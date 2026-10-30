//! Protected resources and lifecycle endpoints: userinfo, introspection,
//! revocation, RP-initiated logout, dynamic registration and key rotation.

use crate::db::{self, Client};
use crate::error::{ApiResult, OauthError};
use crate::jose;
use crate::oidc;
use crate::util::*;
use crate::AppState;
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use crate::db::{params, OptionalExt};
use serde_json::{json, Value};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Access token validation
// ---------------------------------------------------------------------------

/// Split an `Authorization` header into a lowercased scheme and the token.
fn bearer_token(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = raw.splitn(2, ' ');
    let scheme = parts.next()?.to_ascii_lowercase();
    let token = parts.next()?.trim();
    if matches!(scheme.as_str(), "bearer" | "dpop") && !token.is_empty() {
        Some((scheme, token.to_string()))
    } else {
        None
    }
}

pub fn verify_access_token(st: &AppState, token: &str) -> ApiResult<Value> {
    let jwks = st
        .keys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .jwks();
    let (_header, claims) = jose::verify_with_jwks(&jwks, token, Some("at+jwt"))
        .map_err(|_| OauthError::unauthorized("invalid access token"))?;

    if claims.get("iss").and_then(Value::as_str) != Some(st.cfg.issuer.as_str()) {
        return Err(OauthError::unauthorized("access token issuer mismatch"));
    }
    let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
    if exp < now() {
        return Err(OauthError::unauthorized("access token expired"));
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .ok_or_else(|| OauthError::unauthorized("access token has no jti"))?;

    let revoked: Option<i64> = st.db.with(|c| {
        Ok(c.query_row(
            "SELECT revoked FROM access_tokens WHERE jti = ?1 AND expires_at > ?2",
            params![jti, now()],
            |r| r.get(0),
        )
        .optional()?)
    })?;
    match revoked {
        Some(0) => {}
        _ => return Err(OauthError::unauthorized("access token is not active")),
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

pub async fn userinfo(
    State(st): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    match userinfo_inner(&st, &method, &headers) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn userinfo_inner(st: &AppState, method: &Method, headers: &HeaderMap) -> ApiResult<Response> {
    const BEARER: &str = "Bearer realm=\"kagi\"";
    const DPOP: &str = "DPoP algs=\"ES256\"";

    let (scheme, token) = bearer_token(headers)
        .ok_or_else(|| OauthError::unauthorized("an access token is required").with_challenge(BEARER))?;
    let claims = verify_access_token(st, &token).map_err(|e| e.with_challenge(BEARER))?;

    let bound_jkt = claims
        .get("cnf")
        .and_then(|c| c.get("jkt"))
        .and_then(Value::as_str)
        .map(str::to_string);

    match (scheme.as_str(), bound_jkt) {
        // RFC 9449 §7.1: a DPoP-bound token needs a matching proof.
        ("dpop", Some(jkt)) => {
            let proof = crate::dpop::require(
                st.cfg.as_ref(),
                &st.db,
                headers,
                method.as_str(),
                "/userinfo",
                Some(token.as_str()),
            )
            .map_err(|e| {
                e.with_status(StatusCode::UNAUTHORIZED).with_challenge(DPOP)
            })?;
            if proof.jkt != jkt {
                return Err(OauthError::unauthorized("DPoP key does not match the token")
                    .with_challenge(DPOP));
            }
        }
        ("dpop", None) => {
            return Err(OauthError::unauthorized(
                "DPoP scheme used with a token that is not DPoP-bound",
            )
            .with_challenge(BEARER));
        }
        // RFC 9449 §7.1: a DPoP-bound token must not be accepted as a bearer token.
        ("bearer", Some(_)) => {
            return Err(OauthError::unauthorized(
                "access token is DPoP-bound and must be presented with the DPoP scheme",
            )
            .with_challenge(DPOP));
        }
        _ => {}
    }

    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| OauthError::unauthorized("access token has no sub"))?;
    let scope = claims.get("scope").and_then(Value::as_str).unwrap_or("");
    let user = st
        .db
        .with(|c| db::load_user(c, sub))?
        .ok_or_else(|| OauthError::unauthorized("unknown subject"))?;

    let mut out = json!({ "sub": user.id });
    if oidc::scope_contains(scope, "profile") {
        out["name"] = json!(user.display_name);
        out["preferred_username"] = json!(user.username);
    }
    if oidc::scope_contains(scope, "email") {
        out["email"] = json!(user.email);
        out["email_verified"] = json!(user.email_verified);
    }
    if let Some(sid) = claims.get("sid").and_then(Value::as_str) {
        out["sid"] = json!(sid);
    }

    let mut res = Json(out).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

// ---------------------------------------------------------------------------
// Introspection (RFC 7662)
// ---------------------------------------------------------------------------

pub async fn introspect(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match introspect_inner(&st, &headers, &form) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn introspect_inner(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    let client = oidc::authenticate_client(st, headers, form)?;
    let token = form
        .get("token")
        .ok_or_else(|| OauthError::invalid_request("token is required"))?;

    // Try an access token first (a JWT), then an opaque refresh token.
    if let Ok(claims) = verify_access_token(st, token) {
        let token_client = claims.get("client_id").and_then(Value::as_str).unwrap_or("");
        if token_client != client.id {
            return Ok(Json(json!({ "active": false })).into_response());
        }
        let mut body = json!({
            "active": true,
            "token_type": if claims.get("cnf").is_some() { "DPoP" } else { "Bearer" },
            "scope": claims.get("scope"),
            "sub": claims.get("sub"),
            "iss": st.cfg.issuer,
            "aud": claims.get("aud"),
            "client_id": claims.get("client_id"),
            "iat": claims.get("iat"),
            "exp": claims.get("exp"),
            "jti": claims.get("jti"),
        });
        if let Some(sid) = claims.get("sid") {
            body["sid"] = sid.clone();
        }
        if let Some(cnf) = claims.get("cnf") {
            body["cnf"] = cnf.clone();
        }
        let mut res = Json(body).into_response();
        res.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return Ok(res);
    }

    let hash = sha256_hex(token);
    if let Some(row) = st.db.with(|c| db::load_refresh(c, &hash))? {
        if row.client_id != client.id || row.revoked || row.expires_at < now() {
            return Ok(Json(json!({ "active": false })).into_response());
        }
        let body = json!({
            "active": true,
            "token_type": "refresh_token",
            "scope": row.scope,
            "sub": row.user_id,
            "iss": st.cfg.issuer,
            "aud": client.id,
            "client_id": row.client_id,
            "iat": row.issued_at,
            "exp": row.expires_at,
        });
        return Ok(Json(body).into_response());
    }

    Ok(Json(json!({ "active": false })).into_response())
}

// ---------------------------------------------------------------------------
// Revocation (RFC 7009)
// ---------------------------------------------------------------------------

pub async fn revoke(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match revoke_inner(&st, &headers, &form) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

fn revoke_inner(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<()> {
    let client = oidc::authenticate_client(st, headers, form)?;
    let token = form
        .get("token")
        .ok_or_else(|| OauthError::invalid_request("token is required"))?;

    if let Ok((_header, claims, _input, _sig)) = jose::decode_segments(token) {
        if let Some(jti) = claims.get("jti").and_then(Value::as_str) {
            st.db.with(|c| {
                c.execute(
                    "UPDATE access_tokens SET revoked = 1 WHERE jti = ?1 AND client_id = ?2",
                    params![jti, client.id],
                )?;
                Ok(())
            })?;
            return Ok(());
        }
    }

    let hash = sha256_hex(token);
    if let Some(row) = st.db.with(|c| db::load_refresh(c, &hash))? {
        if row.client_id == client.id {
            oidc::revoke_family(st, &row.family_id)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RP-initiated logout
// ---------------------------------------------------------------------------

pub async fn end_session_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    end_session(&st, &headers, &q)
}

pub async fn end_session_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    end_session(&st, &headers, &form)
}

fn end_session(st: &AppState, headers: &HeaderMap, params: &HashMap<String, String>) -> Response {
    let mut client: Option<Client> = None;

    if let Some(hint) = params.get("id_token_hint") {
        let jwks = st.keys.read().unwrap_or_else(|e| e.into_inner()).jwks();
        if let Ok((_h, claims)) = jose::verify_with_jwks(&jwks, hint, Some("JWT")) {
            if let Some(aud) = claims.get("aud").and_then(Value::as_str) {
                if let Ok(Some(c)) = st.db.with(|c| db::load_client(c, aud)) {
                    client = Some(c);
                }
            }
        }
    }
    if client.is_none() {
        if let Some(cid) = params.get("client_id") {
            if let Ok(Some(c)) = st.db.with(|c| db::load_client(c, cid)) {
                client = Some(c);
            }
        }
    }

    let mut redirect_to: Option<String> = None;
    if let (Some(target), Some(client)) = (params.get("post_logout_redirect_uri"), client.as_ref()) {
        if client.post_logout_redirect_uris.iter().any(|u| u == target) {
            let mut url = target.clone();
            if let Some(state) = params.get("state") {
                url = build_url(&url, &[("state", state.clone())]);
            }
            redirect_to = Some(url);
        } else {
            return (StatusCode::BAD_REQUEST, "post_logout_redirect_uri is not registered")
                .into_response();
        }
    }

    let cookie = crate::auth::end_local_session(st, headers);

    let mut res = match redirect_to {
        Some(url) => oidc::redirect_302(&url),
        None => {
            let body = r#"<!doctype html><meta charset="utf-8"><title>Signed out</title>
<link rel="stylesheet" href="/static/style.css">
<body class="signed-out"><section class="card narrow">
<div class="brand"><span class="mark"><span></span></span><span>kagi</span></div>
<h1>サインアウトしました</h1>
<p class="muted">このタブは閉じてかまいません。</p>
<p class="foot"><a href="/login">もう一度サインイン</a></p>
</section></body>"#
                .to_string();
            ([(header::CACHE_CONTROL, "no-store")], Html(body)).into_response()
        }
    };
    if let Some(value) = cookie {
        res.headers_mut().append(header::SET_COOKIE, value);
    }
    res
}

// ---------------------------------------------------------------------------
// Dynamic client registration (RFC 7591)
// ---------------------------------------------------------------------------

pub async fn register_client(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    match register_client_inner(&st, &headers, &body) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn register_client_inner(
    st: &AppState,
    headers: &HeaderMap,
    body: &Value,
) -> ApiResult<Response> {
    if let Some(expected) = &st.cfg.registration_token {
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();
        if !ct_eq(provided.trim(), expected) {
            return Err(OauthError::unauthorized(
                "an initial access token is required to register a client",
            ));
        }
    }

    let redirect_uris: Vec<String> = body
        .get("redirect_uris")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if redirect_uris.is_empty() {
        return Err(OauthError::invalid_request("redirect_uris is required"));
    }
    for uri in &redirect_uris {
        let ok = uri.starts_with("https://")
            || uri.starts_with("http://localhost")
            || uri.starts_with("http://127.0.0.1");
        if !ok || uri.contains('#') {
            return Err(OauthError::invalid_request(format!(
                "redirect_uri {uri} must use https (or localhost) and must not contain a fragment"
            )));
        }
    }

    let auth_method = body
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .unwrap_or("client_secret_basic")
        .to_string();
    if !matches!(
        auth_method.as_str(),
        "none" | "client_secret_basic" | "client_secret_post" | "private_key_jwt"
    ) {
        return Err(OauthError::invalid_request("unsupported token_endpoint_auth_method"));
    }
    if auth_method == "private_key_jwt" && body.get("jwks").is_none() && body.get("jwks_uri").is_some() {
        return Err(OauthError::invalid_request(
            "jwks_uri is not supported; supply jwks inline",
        ));
    }

    let grant_types: Vec<String> = body
        .get("grant_types")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    let response_types: Vec<String> = body
        .get("response_types")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["code".into()]);
    if response_types.iter().any(|r| r != "code") {
        return Err(OauthError::invalid_request("only response_type=code is supported"));
    }
    if grant_types.iter().any(|g| {
        !matches!(
            g.as_str(),
            "authorization_code" | "refresh_token" | "client_credentials"
        )
    }) {
        return Err(OauthError::invalid_request("unsupported grant type"));
    }

    let scopes: Vec<String> = body
        .get("scope")
        .and_then(Value::as_str)
        .map(|s| oidc::split_scope(s))
        .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]);
    if !scopes.iter().any(|s| s == "openid") {
        return Err(OauthError::invalid_scope("openid is required"));
    }

    let client_id = format!("kagi_{}", random_token(12));
    let secret = if auth_method.starts_with("client_secret") {
        Some(random_token(32))
    } else {
        None
    };
    let secret_hash = secret.as_deref().map(sha256_hex);
    let name = body
        .get("client_name")
        .and_then(Value::as_str)
        .unwrap_or("dynamic client")
        .to_string();

    let post_logout: Vec<String> = body
        .get("post_logout_redirect_uris")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    st.db.with(|c| {
        c.execute(
            "INSERT INTO clients
                (id, name, secret_hash, redirect_uris, post_logout_redirect_uris, grant_types,
                 scopes, auth_method, jwks, require_dpop, require_par, id_token_alg, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'ES256', ?12)",
            params![
                client_id,
                name,
                secret_hash,
                serde_json::to_string(&redirect_uris).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&post_logout).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&grant_types).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&scopes).unwrap_or_else(|_| "[]".into()),
                auth_method,
                body.get("jwks").map(|j| j.to_string()),
                body.get("require_dpop").and_then(Value::as_bool).unwrap_or(false) as i64,
                body.get("require_pushed_authorization_requests")
                    .and_then(Value::as_bool)
                    .unwrap_or(false) as i64,
                now(),
            ],
        )?;
        Ok(())
    })?;

    let mut response = json!({
        "client_id": client_id,
        "client_id_issued_at": now(),
        "client_name": name,
        "redirect_uris": redirect_uris,
        "post_logout_redirect_uris": post_logout,
        "grant_types": grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": auth_method,
        "scope": scopes.join(" "),
        "require_pushed_authorization_requests": body
            .get("require_pushed_authorization_requests")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    });
    if let Some(secret) = secret {
        response["client_secret"] = json!(secret);
        response["client_secret_expires_at"] = json!(0);
    }

    let mut res = (StatusCode::CREATED, Json(response)).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

pub async fn rotate_keys(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(expected) = &st.cfg.admin_token else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !ct_eq(provided.trim(), expected) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut ring = st.keys.write().unwrap_or_else(|e| e.into_inner());
    match ring.rotate(&st.db) {
        Ok(kid) => Json(json!({ "kid": kid, "keys": ring.key_ids() })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

pub async fn health(State(st): State<AppState>) -> Response {
    let ready = st.db.with(|conn| {
        let _: i64 = conn.query_row("SELECT COUNT(*) FROM rate_limits", params![], |row| row.get(0))?;
        let _: i64 = conn.query_row("SELECT COUNT(*) FROM signing_keys", params![], |row| row.get(0))?;
        Ok(())
    }).is_ok();

    if ready {
        Json(json!({ "status": "ok", "ready": true })).into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
            "status": "unavailable",
            "ready": false,
            "error": "database unavailable"
        }))).into_response()
    }
}
