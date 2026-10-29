//! OIDC / OAuth 2.1 core: discovery, PAR, authorize, token issuance.

use crate::db::{self, Client, Flow, Session, User};
use crate::dpop;
use crate::error::{ApiResult, OauthError};
use crate::jose;
use crate::util::*;
use crate::AppState;
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use crate::db::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Authorization request parameters
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuthzParams {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub response_type: String,
    #[serde(default)]
    pub response_mode: Option<String>,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub max_age: Option<i64>,
    #[serde(default)]
    pub login_hint: Option<String>,
    #[serde(default)]
    pub acr_values: Option<String>,
    #[serde(default)]
    pub claims: Option<String>,
    #[serde(default)]
    pub dpop_jkt: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

impl AuthzParams {
    pub fn from_map(m: &HashMap<String, String>) -> Self {
        let get = |k: &str| m.get(k).cloned().filter(|v| !v.is_empty());
        Self {
            client_id: get("client_id").unwrap_or_default(),
            redirect_uri: get("redirect_uri").unwrap_or_default(),
            response_type: get("response_type").unwrap_or_default(),
            response_mode: get("response_mode"),
            scope: get("scope").unwrap_or_default(),
            state: get("state"),
            nonce: get("nonce"),
            code_challenge: get("code_challenge").unwrap_or_default(),
            code_challenge_method: get("code_challenge_method"),
            prompt: get("prompt"),
            max_age: get("max_age").and_then(|v| v.parse().ok()),
            login_hint: get("login_hint"),
            acr_values: get("acr_values"),
            claims: get("claims"),
            dpop_jkt: get("dpop_jkt"),
            resource: get("resource"),
        }
    }

    pub fn prompt_set(&self) -> Vec<&str> {
        self.prompt
            .as_deref()
            .map(|p| p.split(' ').filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    }

    pub fn wants(&self, value: &str) -> bool {
        self.prompt_set().contains(&value)
    }

    pub fn response_mode(&self) -> &str {
        self.response_mode.as_deref().unwrap_or("query")
    }
}

pub fn split_scope(scope: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in scope.split_whitespace() {
        if !out.iter().any(|x| x == s) {
            out.push(s.to_string());
        }
    }
    out
}

pub fn scope_contains(scope: &str, name: &str) -> bool {
    split_scope(scope).iter().any(|s| s == name)
}

fn scope_subset(requested: &str, allowed: &str) -> bool {
    let allowed = split_scope(allowed);
    split_scope(requested).iter().all(|s| allowed.iter().any(|a| a == s))
}

// ---------------------------------------------------------------------------
// Static endpoints
// ---------------------------------------------------------------------------

pub async fn discovery(State(st): State<AppState>) -> Response {
    let cfg = &st.cfg;
    let doc = json!({
        "issuer": cfg.issuer,
        "authorization_endpoint": cfg.endpoint("/authorize"),
        "token_endpoint": cfg.endpoint("/token"),
        "userinfo_endpoint": cfg.endpoint("/userinfo"),
        "jwks_uri": cfg.endpoint("/jwks.json"),
        "registration_endpoint": cfg.endpoint("/register"),
        "pushed_authorization_request_endpoint": cfg.endpoint("/par"),
        "introspection_endpoint": cfg.endpoint("/introspect"),
        "revocation_endpoint": cfg.endpoint("/revoke"),
        "end_session_endpoint": cfg.endpoint("/logout"),
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment", "jwt", "query.jwt", "fragment.jwt", "form_post"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "userinfo_signing_alg_values_supported": ["none"],
        "token_endpoint_auth_methods_supported": [
            "none", "client_secret_basic", "client_secret_post", "private_key_jwt"
        ],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256", "EdDSA", "RS256", "PS256"],
        "revocation_endpoint_auth_methods_supported": [
            "none", "client_secret_basic", "client_secret_post", "private_key_jwt"
        ],
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post", "private_key_jwt"
        ],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "sid",
            "name", "preferred_username", "email", "email_verified"
        ],
        "claims_parameter_supported": true,
        "code_challenge_methods_supported": ["S256"],
        "request_parameter_supported": true,
        "request_uri_parameter_supported": true,
        "require_request_uri_registration": false,
        "authorization_response_iss_parameter_supported": true,
        "request_object_signing_alg_values_supported": ["ES256", "EdDSA", "RS256", "PS256"],
        "authorization_signing_alg_values_supported": ["ES256"],
        "authorization_encryption_alg_values_supported": [],
        "dpop_signing_alg_values_supported": ["ES256", "EdDSA", "RS256", "PS256"],
        "prompt_values_supported": ["none", "login", "consent"],
        "require_pushed_authorization_requests": cfg.require_par,
        "tls_client_certificate_bound_access_tokens": false,
        "backchannel_logout_supported": false,
        "frontchannel_logout_supported": false,
    });
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(doc),
    )
        .into_response()
}

pub async fn jwks(State(st): State<AppState>) -> Response {
    let jwks = st.keys.read().unwrap_or_else(|e| e.into_inner()).jwks();
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json(jwks),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// PAR (RFC 9126)
// ---------------------------------------------------------------------------

pub async fn par(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match par_inner(&st, &headers, &form) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn par_inner(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    let client = authenticate_client(st, headers, form)?;
    let mut params = AuthzParams::from_map(form);
    params.client_id = client.id.clone();

    validate_authorization_params(st, &params)?;

    if params.code_challenge.is_empty() {
        return Err(OauthError::invalid_request("PKCE is required"));
    }

    // DPoP at the PAR endpoint binds the whole authorization request to a key.
    if let Some(proof) = dpop::inspect(st.cfg.as_ref(), &st.db, headers, "POST", "/par", None)? {
        params.dpop_jkt = Some(proof.jkt);
    }
    if (st.cfg.require_dpop || client.require_dpop) && params.dpop_jkt.is_none() {
        return Err(OauthError::invalid_dpop_proof("DPoP proof required"));
    }

    let id = random_token(24);
    let payload = serde_json::to_string(&params)
        .map_err(|_| OauthError::server_error("could not serialise request"))?;
    let expires_at = now() + st.cfg.par_ttl;
    st.db.with(|c| {
        c.execute(
            "INSERT INTO flows (id, kind, user_id, client_id, payload, challenge, csrf, expires_at, created_at, consumed)
             VALUES (?1, 'par', NULL, ?2, ?3, NULL, NULL, ?4, ?5, 0)",
            params![id, client.id, payload, expires_at, now()],
        )?;
        Ok(())
    })?;

    let body = json!({
        "request_uri": format!("urn:ietf:params:oauth:request_uri:{id}"),
        "expires_in": st.cfg.par_ttl,
    });
    let mut res = Json(body).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

pub async fn authorize(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    authorize_inner(&st, &headers, query)
}

fn authorize_inner(st: &AppState, headers: &HeaderMap, query: HashMap<String, String>) -> Response {
    let (params, via_par) = match resolve_authorization_request(st, &query) {
        Ok(v) => v,
        Err(e) => return authz_fail(st, None, e.code, &e.description),
    };

    let client = match validate_authorization_params(st, &params) {
        Ok(c) => c,
        Err(e) => return authz_fail(st, Some(&params), e.code, &e.description),
    };

    if !via_par && (st.cfg.require_par || client.require_par) {
        return authz_fail(
            st,
            Some(&params),
            "invalid_request",
            "pushed authorization requests are required for this client",
        );
    }

    let session = crate::auth::session_from_headers(st, headers);
    let prompt = params.prompt_set();

    let max_age_exceeded = match (&session, params.max_age) {
        (Some(s), Some(max)) => s.auth_time + max < now(),
        _ => false,
    };
    let needs_login = session.is_none() || prompt.contains(&"login") || max_age_exceeded;

    if prompt.contains(&"none") {
        if needs_login {
            return authz_fail(st, Some(&params), "login_required", "no active session");
        }
        let s = session.unwrap();
        let user = match st.db.with(|c| db::load_user(c, &s.user_id)) {
            Ok(Some(u)) => u,
            _ => return authz_fail(st, Some(&params), "login_required", "unknown session user"),
        };
        let consented = st
            .db
            .with(|c| db::consent_covers(c, &user.id, &client.id, &params.scope))
            .unwrap_or(false);
        if !consented {
            return authz_fail(
                st,
                Some(&params),
                "consent_required",
                "the user has not consented to this client yet",
            );
        }
        let flow = match create_authorize_flow(st, &params) {
            Ok(f) => f,
            Err(e) => return authz_fail(st, Some(&params), "server_error", &e.description),
        };
        return complete_authorization(st, &flow, &user, &s, true);
    }

    let flow = match create_authorize_flow(st, &params) {
        Ok(f) => f,
        Err(e) => return authz_fail(st, Some(&params), "server_error", &e.description),
    };

    if needs_login {
        return redirect_303(&format!("/login?rid={}", urlenc(&flow.id)));
    }
    redirect_303(&format!("/consent?rid={}", urlenc(&flow.id)))
}

fn resolve_authorization_request(
    st: &AppState,
    query: &HashMap<String, String>,
) -> ApiResult<(AuthzParams, bool)> {
    let has_request = query.get("request").is_some();
    let has_request_uri = query.get("request_uri").is_some();
    if has_request && has_request_uri {
        return Err(OauthError::invalid_request(
            "request and request_uri are mutually exclusive",
        ));
    }

    if let Some(uri) = query.get("request_uri") {
        let Some(id) = uri.strip_prefix("urn:ietf:params:oauth:request_uri:") else {
            return Err(OauthError::invalid_request(
                "only urn:ietf:params:oauth:request_uri values are supported",
            ));
        };
        let flow = st
            .db
            .with(|c| db::load_flow(c, id))?
            .ok_or_else(|| OauthError::invalid_request("unknown or expired request_uri"))?;
        if flow.kind != "par" {
            return Err(OauthError::invalid_request("request_uri is not a PAR handle"));
        }
        // Single use.
        let used = st.db.with(|c| {
            Ok(c.execute(
                "UPDATE flows SET consumed = 1 WHERE id = ?1 AND consumed = 0",
                params![id],
            )?)
        })?;
        if used != 1 {
            return Err(OauthError::invalid_request("request_uri already used"));
        }
        let params: AuthzParams = serde_json::from_value(flow.payload)
            .map_err(|_| OauthError::invalid_request("stored request is corrupt"))?;
        return Ok((params, true));
    }

    if let Some(request) = query.get("request") {
        let params = resolve_request_object(st, query, request)?;
        return Ok((params, false));
    }

    Ok((AuthzParams::from_map(query), false))
}

fn resolve_request_object(
    st: &AppState,
    query: &HashMap<String, String>,
    request: &str,
) -> ApiResult<AuthzParams> {
    let client_id = query
        .get("client_id")
        .cloned()
        .ok_or_else(|| OauthError::invalid_request("client_id is required with request"))?;
    let client = st
        .db
        .with(|c| db::load_client(c, &client_id))?
        .ok_or_else(|| OauthError::invalid_request("unknown client"))?;
    let jwks = client
        .jwks
        .as_ref()
        .ok_or_else(|| OauthError::invalid_request("client has no registered jwks"))?;

    let (_header, claims) = jose::verify_with_jwks(jwks, request, Some("oauth-authz-req+jwt"))
        .map_err(|e| OauthError::invalid_request(format!("invalid request object: {e}")))?;

    if claims.get("iss").and_then(Value::as_str) != Some(client.id.as_str()) {
        return Err(OauthError::invalid_request(
            "request object iss must equal client_id",
        ));
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(s)) => s == &st.cfg.issuer,
        Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(st.cfg.issuer.as_str())),
        _ => false,
    };
    if !aud_ok {
        return Err(OauthError::invalid_request(
            "request object aud must contain the issuer",
        ));
    }
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64) {
        if exp < now() {
            return Err(OauthError::invalid_request("request object has expired"));
        }
    } else {
        return Err(OauthError::invalid_request("request object has no exp"));
    }
    if claims.get("request").is_some() || claims.get("request_uri").is_some() {
        return Err(OauthError::invalid_request(
            "request objects must not nest request or request_uri",
        ));
    }

    let mut map = HashMap::new();
    if let Some(obj) = claims.as_object() {
        for (k, v) in obj {
            match v {
                Value::String(s) => {
                    map.insert(k.clone(), s.clone());
                }
                Value::Number(n) => {
                    map.insert(k.clone(), n.to_string());
                }
                Value::Bool(b) => {
                    map.insert(k.clone(), b.to_string());
                }
                _ => {}
            }
        }
    }
    // Parameters outside the request object must not override it.
    map.entry("client_id".to_string()).or_insert(client.id.clone());
    Ok(AuthzParams::from_map(&map))
}

fn validate_authorization_params(st: &AppState, p: &AuthzParams) -> ApiResult<Client> {
    if p.client_id.is_empty() {
        return Err(OauthError::invalid_request("client_id is required"));
    }
    let client = st
        .db
        .with(|c| db::load_client(c, &p.client_id))?
        .ok_or_else(|| OauthError::invalid_request("unknown client_id"))?;

    if p.redirect_uri.is_empty() || !client.redirect_uris.iter().any(|u| u == &p.redirect_uri) {
        return Err(OauthError::invalid_request(
            "redirect_uri is not registered for this client",
        ));
    }
    if p.response_type != "code" {
        return Err(OauthError::invalid_request(
            "only response_type=code is supported",
        ));
    }
    let scopes = split_scope(&p.scope);
    if !scopes.iter().any(|s| s == "openid") {
        return Err(OauthError::invalid_scope("openid scope is required"));
    }
    if let Some(bad) = scopes.iter().find(|s| !client.scopes.iter().any(|a| a == *s)) {
        return Err(OauthError::invalid_scope(format!(
            "scope {bad} is not registered for this client"
        )));
    }
    if p.code_challenge.is_empty() {
        return Err(OauthError::invalid_request(
            "PKCE (code_challenge) is required",
        ));
    }
    if p.code_challenge.len() < 43 || p.code_challenge.len() > 128 {
        return Err(OauthError::invalid_request("code_challenge has an invalid length"));
    }
    if p.code_challenge_method.as_deref() != Some("S256") {
        return Err(OauthError::invalid_request(
            "code_challenge_method must be S256",
        ));
    }
    if !matches!(
        p.response_mode(),
        "query" | "fragment" | "form_post" | "jwt" | "query.jwt" | "fragment.jwt"
    ) {
        return Err(OauthError::invalid_request("unsupported response_mode"));
    }
    for value in p.prompt_set() {
        if !matches!(value, "none" | "login" | "consent" | "select_account") {
            return Err(OauthError::invalid_request(format!(
                "unsupported prompt value {value}"
            )));
        }
    }
    if p.wants("none") && p.prompt_set().len() > 1 {
        return Err(OauthError::invalid_request(
            "prompt=none cannot be combined with other values",
        ));
    }
    if let Some(max_age) = p.max_age {
        if max_age < 0 {
            return Err(OauthError::invalid_request("max_age must be non-negative"));
        }
    }
    Ok(client)
}

fn create_authorize_flow(st: &AppState, params: &AuthzParams) -> ApiResult<Flow> {
    let id = new_id();
    let csrf = random_token(18);
    let payload = serde_json::to_string(params)
        .map_err(|_| OauthError::server_error("could not serialise request"))?;
    let expires_at = now() + 600;
    st.db.with(|c| {
        c.execute(
            "INSERT INTO flows (id, kind, user_id, client_id, payload, challenge, csrf, expires_at, created_at, consumed)
             VALUES (?1, 'authorize', NULL, ?2, ?3, NULL, ?4, ?5, ?6, 0)",
            params![id, params.client_id, payload, csrf, expires_at, now()],
        )?;
        Ok(())
    })?;
    Ok(Flow {
        id,
        kind: "authorize".to_string(),
        user_id: None,
        client_id: Some(params.client_id.clone()),
        payload: serde_json::to_value(params).unwrap_or(Value::Null),
        challenge: None,
        csrf: Some(csrf),
        expires_at,
        consumed: false,
    })
}

fn authz_fail(st: &AppState, params: Option<&AuthzParams>, code: &str, description: &str) -> Response {
    if let Some(p) = params {
        if let Ok(Some(client)) = st.db.with(|c| db::load_client(c, &p.client_id)) {
            if client.redirect_uris.iter().any(|u| u == &p.redirect_uri) {
                return authorization_error_redirect(st, &client, p, code, description);
            }
        }
    }
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Authorization error</title>\
         <h1>認可リクエストを処理できません</h1><p><code>{}</code>: {}</p>",
        esc(code),
        esc(description)
    );
    (StatusCode::BAD_REQUEST, Html(body)).into_response()
}

fn authorization_error_redirect(
    st: &AppState,
    client: &Client,
    p: &AuthzParams,
    code: &str,
    description: &str,
) -> Response {
    let mode = p.response_mode();
    let mut params: Vec<(&str, String)> = vec![("error", code.to_string())];
    if !description.is_empty() {
        params.push(("error_description", description.to_string()));
    }
    if let Some(state) = &p.state {
        params.push(("state", state.clone()));
    }
    params.push(("iss", st.cfg.issuer.clone()));

    if mode.ends_with("jwt") {
        let claims = json!({
            "iss": st.cfg.issuer,
            "aud": client.id,
            "iat": now(),
            "exp": now() + 120,
            "error": code,
            "error_description": description,
            "state": p.state,
        });
        let signed = match st.keys.read().unwrap_or_else(|e| e.into_inner()).current().sign(Some("JWT"), &claims) {
            Ok(t) => t,
            Err(_) => String::new(),
        };
        let target = if mode.starts_with("fragment") {
            build_fragment(&p.redirect_uri, &[("response", signed)])
        } else {
            build_url(&p.redirect_uri, &[("response", signed)])
        };
        return redirect_303(&target);
    }

    let target = build_url(&p.redirect_uri, &params);
    redirect_303(&target)
}

/// Issue the authorization code and send the user back to the RP.
pub fn complete_authorization(
    st: &AppState,
    flow: &Flow,
    user: &User,
    session: &Session,
    approve: bool,
) -> Response {
    let params: AuthzParams = match serde_json::from_value(flow.payload.clone()) {
        Ok(p) => p,
        Err(_) => return authz_fail(st, None, "server_error", "stored request is corrupt"),
    };
    let client = match st.db.with(|c| db::load_client(c, &params.client_id)) {
        Ok(Some(c)) => c,
        _ => return authz_fail(st, Some(&params), "invalid_request", "unknown client"),
    };

    if !approve {
        let _ = st.db.with(|c| {
            Ok(c.execute("UPDATE flows SET consumed = 1 WHERE id = ?1", params![flow.id])?)
        });
        return authorization_error_redirect(
            st,
            &client,
            &params,
            "access_denied",
            "the user denied the request",
        );
    }

    let code = random_token(32);
    let code_hash = sha256_hex(&code);
    let amr = serde_json::to_string(&session.amr).unwrap_or_else(|_| "[]".to_string());
    let inserted = st.db.with(|c| {
        c.execute(
            "INSERT INTO auth_codes
                (code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge,
                 auth_time, amr, acr, dpop_jkt, session_id, expires_at, created_at, consumed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 0)",
            params![
                code_hash,
                client.id,
                user.id,
                params.redirect_uri,
                params.scope,
                params.nonce,
                params.code_challenge,
                session.auth_time,
                amr,
                session.acr,
                params.dpop_jkt,
                session.id,
                now() + st.cfg.code_ttl,
                now(),
            ],
        )?;
        Ok(())
    });
    if inserted.is_err() {
        return authz_fail(st, Some(&params), "server_error", "could not store the code");
    }
    let _ = st.db.with(|c| {
        Ok(c.execute("UPDATE flows SET consumed = 1 WHERE id = ?1", params![flow.id])?)
    });

    authorization_success(st, &client, &params, &code, session)
}

fn authorization_success(
    st: &AppState,
    client: &Client,
    p: &AuthzParams,
    code: &str,
    session: &Session,
) -> Response {
    let mode = p.response_mode().to_string();

    if mode.ends_with("jwt") {
        let claims = json!({
            "iss": st.cfg.issuer,
            "aud": client.id,
            "iat": now(),
            "exp": now() + 120,
            "code": code,
            "state": p.state,
            "auth_time": session.auth_time,
            "amr": session.amr,
            "acr": session.acr,
            "sub": session.user_id,
        });
        let signed = match st.keys.read().unwrap_or_else(|e| e.into_inner()).current().sign(Some("JWT"), &claims) {
            Ok(t) => t,
            Err(_) => return authz_fail(st, Some(p), "server_error", "signing failed"),
        };
        let target = if mode.starts_with("fragment") {
            build_fragment(&p.redirect_uri, &[("response", signed)])
        } else {
            build_url(&p.redirect_uri, &[("response", signed)])
        };
        return redirect_303(&target);
    }

    let mut params: Vec<(&str, String)> = vec![("code", code.to_string())];
    if let Some(state) = &p.state {
        params.push(("state", state.clone()));
    }
    params.push(("iss", st.cfg.issuer.clone()));

    if mode == "form_post" {
        let inputs: String = params
            .iter()
            .map(|(k, v)| {
                format!(
                    "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                    esc(k),
                    esc(v)
                )
            })
            .collect();
        let body = format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Redirecting…</title>\
             <form id=\"f\" method=\"post\" action=\"{}\">{inputs}\
             <noscript><button type=\"submit\">Continue</button></noscript></form>\
             <script>document.getElementById('f').submit()</script>",
            esc(&p.redirect_uri)
        );
        return ([(header::CACHE_CONTROL, "no-store")], Html(body)).into_response();
    }

    let target = if mode == "fragment" {
        build_fragment(&p.redirect_uri, &params)
    } else {
        build_url(&p.redirect_uri, &params)
    };
    redirect_303(&target)
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

pub async fn token(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match token_inner(&st, &headers, &form) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn token_inner(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    let client = authenticate_client(st, headers, form)?;
    let grant_type = form
        .get("grant_type")
        .ok_or_else(|| OauthError::invalid_request("grant_type is required"))?
        .clone();

    let proof = dpop::inspect(st.cfg.as_ref(), &st.db, headers, "POST", "/token", None)?;
    let jkt = proof.map(|p| p.jkt);
    if (st.cfg.require_dpop || client.require_dpop) && jkt.is_none() {
        return Err(OauthError::invalid_dpop_proof("DPoP proof required"));
    }

    match grant_type.as_str() {
        "authorization_code" => {
            exchange_code(st, &client, form, jkt.as_deref())
        }
        "refresh_token" => refresh(st, &client, form, jkt.as_deref()),
        "client_credentials" => client_credentials(st, &client, form, jkt.as_deref()),
        other => Err(OauthError::unsupported(format!(
            "unsupported grant_type {other}"
        ))),
    }
}

fn exchange_code(
    st: &AppState,
    client: &Client,
    form: &HashMap<String, String>,
    jkt: Option<&str>,
) -> ApiResult<Response> {
    let code = form
        .get("code")
        .ok_or_else(|| OauthError::invalid_request("code is required"))?;
    let verifier = form
        .get("code_verifier")
        .ok_or_else(|| OauthError::invalid_request("code_verifier is required"))?;
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err(OauthError::invalid_grant("code_verifier has an invalid length"));
    }

    let code_hash = sha256_hex(code);
    let row = st
        .db
        .with(|c| db::load_code(c, &code_hash))?
        .ok_or_else(|| OauthError::invalid_grant("unknown authorization code"))?;

    if row.consumed {
        return Err(OauthError::invalid_grant("authorization code already used"));
    }
    if row.expires_at < now() {
        return Err(OauthError::invalid_grant("authorization code expired"));
    }
    if row.client_id != client.id {
        return Err(OauthError::invalid_grant(
            "authorization code was issued to another client",
        ));
    }
    let redirect_uri = form
        .get("redirect_uri")
        .ok_or_else(|| OauthError::invalid_request("redirect_uri is required"))?;
    if &row.redirect_uri != redirect_uri {
        return Err(OauthError::invalid_grant("redirect_uri mismatch"));
    }

    let computed = b64(&sha256(verifier.as_bytes()));
    if !ct_eq(&computed, &row.code_challenge) {
        return Err(OauthError::invalid_grant("PKCE verification failed"));
    }

    match (&row.dpop_jkt, jkt) {
        (Some(bound), Some(present)) if bound.as_str() == present => {}
        (Some(_), _) => {
            return Err(OauthError::invalid_grant(
                "authorization code is bound to a different DPoP key",
            ))
        }
        (None, _) => {}
    }

    let changed = st.db.with(|c| {
        Ok(c.execute(
            "UPDATE auth_codes SET consumed = 1 WHERE code_hash = ?1 AND consumed = 0",
            params![code_hash],
        )?)
    })?;
    if changed != 1 {
        return Err(OauthError::invalid_grant("authorization code already used"));
    }

    let user = st
        .db
        .with(|c| db::load_user(c, &row.user_id))?
        .ok_or_else(|| OauthError::invalid_grant("user no longer exists"))?;

    let (access_token, expires_in) = mint_access_token(
        st,
        &user.id,
        &client.id,
        &row.scope,
        jkt,
        row.session_id.as_deref(),
    )?;

    let id_token = mint_id_token(
        st,
        &user,
        &client.id,
        row.nonce.as_deref(),
        row.auth_time,
        &row.amr,
        &row.acr,
        &access_token,
        row.session_id.as_deref(),
        jkt,
    )?;

    let refresh_token = if scope_contains(&row.scope, "offline_access") {
        Some(mint_refresh_token(
            st,
            &user.id,
            &client.id,
            &row.scope,
            row.auth_time,
            &row.amr,
            &row.acr,
            jkt,
            row.session_id.as_deref(),
            None,
        )?)
    } else {
        None
    };

    Ok(token_response(
        access_token,
        expires_in,
        &row.scope,
        refresh_token,
        Some(id_token),
        jkt.is_some(),
    ))
}

fn refresh(
    st: &AppState,
    client: &Client,
    form: &HashMap<String, String>,
    jkt: Option<&str>,
) -> ApiResult<Response> {
    let token = form
        .get("refresh_token")
        .ok_or_else(|| OauthError::invalid_request("refresh_token is required"))?;
    let hash = sha256_hex(token);
    let row = st
        .db
        .with(|c| db::load_refresh(c, &hash))?
        .ok_or_else(|| OauthError::invalid_grant("unknown refresh token"))?;

    if row.client_id != client.id {
        return Err(OauthError::invalid_grant(
            "refresh token was issued to another client",
        ));
    }
    if row.revoked || row.rotated_to.is_some() {
        // Reuse detection: kill the whole token family.
        revoke_family(st, &row.family_id)?;
        return Err(OauthError::invalid_grant(
            "refresh token reuse detected; the token family has been revoked",
        ));
    }
    if row.expires_at < now() {
        return Err(OauthError::invalid_grant("refresh token expired"));
    }
    match (&row.dpop_jkt, jkt) {
        (Some(bound), Some(present)) if bound.as_str() == present => {}
        (Some(_), _) => {
            return Err(OauthError::invalid_grant(
                "refresh token is bound to a different DPoP key",
            ))
        }
        (None, _) => {}
    }

    let scope = match form.get("scope") {
        Some(requested) if !requested.trim().is_empty() => {
            if !scope_subset(requested, &row.scope) {
                return Err(OauthError::invalid_scope(
                    "requested scope exceeds the original grant",
                ));
            }
            requested.clone()
        }
        _ => row.scope.clone(),
    };

    let new_token = random_token(32);
    let new_hash = sha256_hex(&new_token);
    let rotated = st.db.tx(|tx| {
        // A compare-and-swap is required: two concurrent requests may both
        // have loaded the same active token before either transaction starts.
        let changed = tx.execute(
            "UPDATE refresh_tokens SET revoked = 1, rotated_to = ?1 \
             WHERE token_hash = ?2 AND client_id = ?3 AND revoked = 0 \
               AND rotated_to IS NULL AND expires_at > ?4",
            params![new_hash, hash, client.id, now()],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO refresh_tokens
                (token_hash, family_id, user_id, client_id, scope, auth_time, amr, acr,
                 dpop_jkt, session_id, issued_at, expires_at, rotated_to, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, 0)",
            params![
                new_hash,
                row.family_id,
                row.user_id,
                row.client_id,
                scope,
                row.auth_time,
                serde_json::to_string(&row.amr).unwrap_or_else(|_| "[]".into()),
                row.acr,
                row.dpop_jkt,
                row.session_id,
                now(),
                now() + st.cfg.refresh_ttl,
            ],
        )?;
        Ok(true)
    })?;
    if !rotated {
        // Treat a lost compare-and-swap as concurrent reuse and revoke every
        // token in the family, rather than issuing a second descendant token.
        revoke_family(st, &row.family_id)?;
        return Err(OauthError::invalid_grant(
            "refresh token reuse detected; the token family has been revoked",
        ));
    }

    let (access_token, expires_in) =
        mint_access_token(st, &row.user_id, &client.id, &scope, jkt, row.session_id.as_deref())?;

    let id_token = if scope_contains(&scope, "openid") {
        let user = st
            .db
            .with(|c| db::load_user(c, &row.user_id))?
            .ok_or_else(|| OauthError::invalid_grant("user no longer exists"))?;
        Some(mint_id_token(
            st,
            &user,
            &client.id,
            None,
            row.auth_time,
            &row.amr,
            &row.acr,
            &access_token,
            row.session_id.as_deref(),
            jkt,
        )?)
    } else {
        None
    };

    Ok(token_response(
        access_token,
        expires_in,
        &scope,
        Some(new_token),
        id_token,
        jkt.is_some(),
    ))
}

fn client_credentials(
    st: &AppState,
    client: &Client,
    form: &HashMap<String, String>,
    jkt: Option<&str>,
) -> ApiResult<Response> {
    if client.auth_method == "none" {
        return Err(OauthError::invalid_client(
            "client_credentials requires a confidential client",
        ));
    }
    if !client.grant_types.iter().any(|g| g == "client_credentials") {
        return Err(OauthError::invalid_request(
            "client is not allowed to use client_credentials",
        ));
    }

    let scope = match form.get("scope") {
        Some(s) if !s.trim().is_empty() => {
            if !scope_subset(s, &client.scopes.join(" ")) {
                return Err(OauthError::invalid_scope("scope exceeds client registration"));
            }
            s.clone()
        }
        _ => client.scopes.join(" "),
    };

    let (access_token, expires_in) =
        mint_access_token(st, &client.id, &client.id, &scope, jkt, None)?;

    Ok(token_response(
        access_token,
        expires_in,
        &scope,
        None,
        None,
        jkt.is_some(),
    ))
}

fn token_response(
    access_token: String,
    expires_in: i64,
    scope: &str,
    refresh_token: Option<String>,
    id_token: Option<String>,
    dpop: bool,
) -> Response {
    let mut body = json!({
        "access_token": access_token,
        "token_type": if dpop { "DPoP" } else { "Bearer" },
        "expires_in": expires_in,
        "scope": scope,
    });
    if let Some(rt) = refresh_token {
        body["refresh_token"] = json!(rt);
    }
    if let Some(idt) = id_token {
        body["id_token"] = json!(idt);
    }
    let mut res = Json(body).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    res
}

// ---------------------------------------------------------------------------
// Token minting
// ---------------------------------------------------------------------------

fn mint_access_token(
    st: &AppState,
    subject: &str,
    client_id: &str,
    scope: &str,
    jkt: Option<&str>,
    session_id: Option<&str>,
) -> ApiResult<(String, i64)> {
    let issued_at = now();
    let expires_at = issued_at + st.cfg.access_ttl;
    let jti = random_token(16);

    let mut claims = json!({
        "iss": st.cfg.issuer,
        "sub": subject,
        "aud": st.cfg.issuer,
        "client_id": client_id,
        "scope": scope,
        "iat": issued_at,
        "exp": expires_at,
        "jti": jti,
    });
    if let Some(jkt) = jkt {
        claims["cnf"] = json!({ "jkt": jkt });
    }
    if let Some(sid) = session_id {
        claims["sid"] = json!(sid);
    }

    let token = st
        .keys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .current()
        .sign(Some("at+jwt"), &claims)
        .map_err(|e| OauthError::server_error(format!("signing failed: {e}")))?;

    st.db.with(|c| {
        c.execute(
            "INSERT INTO access_tokens
                (jti, user_id, client_id, scope, audience, dpop_jkt, subject, issued_at, expires_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
            params![
                jti,
                subject,
                client_id,
                scope,
                st.cfg.issuer,
                jkt,
                subject,
                issued_at,
                expires_at,
            ],
        )?;
        Ok(())
    })?;

    Ok((token, st.cfg.access_ttl))
}

fn mint_refresh_token(
    st: &AppState,
    user_id: &str,
    client_id: &str,
    scope: &str,
    auth_time: i64,
    amr: &[String],
    acr: &str,
    jkt: Option<&str>,
    session_id: Option<&str>,
    family_id: Option<&str>,
) -> ApiResult<String> {
    let token = random_token(32);
    let hash = sha256_hex(&token);
    let family = family_id.map(|s| s.to_string()).unwrap_or_else(new_id);
    st.db.with(|c| {
        c.execute(
            "INSERT INTO refresh_tokens
                (token_hash, family_id, user_id, client_id, scope, auth_time, amr, acr,
                 dpop_jkt, session_id, issued_at, expires_at, rotated_to, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, 0)",
            params![
                hash,
                family,
                user_id,
                client_id,
                scope,
                auth_time,
                serde_json::to_string(amr).unwrap_or_else(|_| "[]".into()),
                acr,
                jkt,
                session_id,
                now(),
                now() + st.cfg.refresh_ttl,
            ],
        )?;
        Ok(())
    })?;
    Ok(token)
}

fn mint_id_token(
    st: &AppState,
    user: &User,
    client_id: &str,
    nonce: Option<&str>,
    auth_time: i64,
    amr: &[String],
    acr: &str,
    access_token: &str,
    session_id: Option<&str>,
    dpop_jkt: Option<&str>,
) -> ApiResult<String> {
    let hash = sha256(access_token.as_bytes());
    let at_hash = b64(&hash[..16]);
    let mut claims = json!({
        "iss": st.cfg.issuer,
        "sub": user.id,
        "aud": client_id,
        "azp": client_id,
        "iat": now(),
        "exp": now() + st.cfg.id_ttl,
        "auth_time": auth_time,
        "amr": amr,
        "acr": acr,
        "at_hash": at_hash,
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    if let Some(sid) = session_id {
        claims["sid"] = json!(sid);
    }
    // RFC 9449 §10: bind the ID token to the DPoP key as well.
    if let Some(jkt) = dpop_jkt {
        claims["cnf"] = json!({ "jkt": jkt });
    }
    st.keys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .current()
        .sign(Some("JWT"), &claims)
        .map_err(|e| OauthError::server_error(format!("signing failed: {e}")))
}

pub fn revoke_family(st: &AppState, family_id: &str) -> ApiResult<()> {
    st.db.with(|c| {
        c.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?1",
            params![family_id],
        )?;
        Ok(())
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Client authentication
// ---------------------------------------------------------------------------

pub fn authenticate_client(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Client> {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| STANDARD.decode(b.trim()).ok());
    if let Some(raw) = basic {
        let raw = String::from_utf8(raw)
            .map_err(|_| OauthError::invalid_client("basic credentials are not UTF-8"))?;
        let (id, secret) = raw
            .split_once(':')
            .ok_or_else(|| OauthError::invalid_client("malformed basic credentials"))?;
        let client = load_client_required(st, id)?;
        if client.auth_method != "client_secret_basic" {
            return Err(OauthError::invalid_client(
                "client is not registered for client_secret_basic",
            ));
        }
        verify_secret(&client, secret)?;
        return Ok(client);
    }

    if let Some(assertion) = form.get("client_assertion") {
        let assertion_type = form
            .get("client_assertion_type")
            .map(String::as_str)
            .unwrap_or_default();
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err(OauthError::invalid_client(
                "unsupported client_assertion_type",
            ));
        }
        let client_id = form
            .get("client_id")
            .ok_or_else(|| OauthError::invalid_client("client_id is required"))?
            .clone();
        let client = load_client_required(st, &client_id)?;
        if client.auth_method != "private_key_jwt" {
            return Err(OauthError::invalid_client(
                "client is not registered for private_key_jwt",
            ));
        }
        verify_client_assertion(st, &client, assertion)?;
        return Ok(client);
    }

    let client_id = form
        .get("client_id")
        .ok_or_else(|| OauthError::invalid_client("client_id is required"))?;
    let client = load_client_required(st, client_id)?;

    if let Some(secret) = form.get("client_secret") {
        if client.auth_method != "client_secret_post" {
            return Err(OauthError::invalid_client(
                "client is not registered for client_secret_post",
            ));
        }
        verify_secret(&client, secret)?;
        return Ok(client);
    }

    if client.auth_method != "none" {
        return Err(OauthError::invalid_client(
            "client authentication is required",
        ));
    }
    Ok(client)
}

fn load_client_required(st: &AppState, id: &str) -> ApiResult<Client> {
    st.db
        .with(|c| db::load_client(c, id))?
        .ok_or_else(|| OauthError::invalid_client("unknown client"))
}

fn verify_secret(client: &Client, secret: &str) -> ApiResult<()> {
    let Some(expected) = client.secret_hash.as_deref() else {
        return Err(OauthError::invalid_client("client has no secret"));
    };
    if !ct_eq(&sha256_hex(secret), expected) {
        return Err(OauthError::invalid_client("invalid client secret"));
    }
    Ok(())
}

fn verify_client_assertion(st: &AppState, client: &Client, assertion: &str) -> ApiResult<()> {
    let jwks = client
        .jwks
        .as_ref()
        .ok_or_else(|| OauthError::invalid_client("client has no registered jwks"))?;
    let (header, claims) = jose::verify_with_jwks(jwks, assertion, Some("JWT"))
        .map_err(|e| OauthError::invalid_client(format!("bad client assertion: {e}")))?;
    if header.get("alg").and_then(Value::as_str) == Some("none") {
        return Err(OauthError::invalid_client("alg=none is not allowed"));
    }
    if claims.get("iss").and_then(Value::as_str) != Some(client.id.as_str())
        || claims.get("sub").and_then(Value::as_str) != Some(client.id.as_str())
    {
        return Err(OauthError::invalid_client(
            "assertion iss/sub must equal client_id",
        ));
    }
    let token_endpoint = st.cfg.endpoint("/token");
    let aud_ok = match claims.get("aud") {
        Some(Value::String(s)) => s == &token_endpoint || s == &st.cfg.issuer,
        Some(Value::Array(a)) => a
            .iter()
            .any(|v| v.as_str() == Some(token_endpoint.as_str()) || v.as_str() == Some(st.cfg.issuer.as_str())),
        _ => false,
    };
    if !aud_ok {
        return Err(OauthError::invalid_client("assertion aud is not this OP"));
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| OauthError::invalid_client("assertion has no exp"))?;
    if exp < now() {
        return Err(OauthError::invalid_client("assertion expired"));
    }
    if let Some(iat) = claims.get("iat").and_then(Value::as_i64) {
        if (now() - iat).abs() > 300 {
            return Err(OauthError::invalid_client("assertion iat is out of range"));
        }
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .ok_or_else(|| OauthError::invalid_client("assertion has no jti"))?;
    let inserted = st.db.with(|c| {
        Ok(c.execute(
            "INSERT OR IGNORE INTO assertion_replay (jti, expires_at) VALUES (?1, ?2)",
            params![jti, exp.max(now()) + 60],
        )?)
    })?;
    if inserted == 0 {
        return Err(OauthError::invalid_client("assertion replayed"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Redirect helpers
// ---------------------------------------------------------------------------

pub fn redirect_303(url: &str) -> Response {
    redirect_with(StatusCode::SEE_OTHER, url)
}

pub fn redirect_302(url: &str) -> Response {
    redirect_with(StatusCode::FOUND, url)
}

fn redirect_with(status: StatusCode, url: &str) -> Response {
    let mut res = status.into_response();
    match HeaderValue::from_str(url) {
        Ok(value) => {
            res.headers_mut().insert(header::LOCATION, value);
            res.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid redirect target").into_response();
        }
    }
    res
}

fn build_fragment(base: &str, params: &[(&str, String)]) -> String {
    let mut out = String::from(base);
    out.push('#');
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(&urlenc(k));
        out.push('=');
        out.push_str(&urlenc(v));
    }
    out
}
