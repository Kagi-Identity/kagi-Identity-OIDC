//! Browser-facing authentication: passkey sign-in/up, consent and the account
//! console. The session is an opaque cookie whose SHA-256 is stored server side.

use crate::db::{self, Flow, Session, User};
use crate::error::OauthError;
use crate::oidc;
use crate::ui;
use crate::util::*;
use crate::webauthn;
use crate::AppState;
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use crate::db::params;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

pub const COOKIE_NAME: &str = "kagi_sid";
pub const ACR_PASSKEY: &str = "urn:kagi:acr:passkey";

fn session_expired(session: &Session, now: i64, idle_ttl: i64) -> bool {
    let last_seen_at = if session.last_seen_at > 0 {
        session.last_seen_at
    } else {
        session.created_at
    };
    session.expires_at <= now
        || (idle_ttl > 0 && now.saturating_sub(last_seen_at) > idle_ttl)
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

pub fn session_from_headers(st: &AppState, headers: &HeaderMap) -> Option<Session> {
    let cookies = parse_cookies(headers);
    let sid = cookies.get(COOKIE_NAME)?;
    let hash = sha256_hex(sid);
    let now = now();

    st.db
        .with(|c| {
            let Some(session) = db::load_session(c, &hash)? else {
                return Ok(None);
            };

            // Older databases may contain last_seen_at = 0; the helper falls
            // back to created_at and enforces both absolute and idle expiry.
            if session_expired(&session, now, st.cfg.session_idle_ttl) {
                db::revoke_session_tokens(c, &session.id)?;
                db::delete_session(c, &session.id, &session.user_id)?;
                return Ok(None);
            }

            db::touch_session(c, &session.id, now)?;
            Ok(Some(session))
        })
        .ok()
        .flatten()
}

fn create_session(
    st: &AppState,
    user_id: &str,
    amr: Vec<String>,
) -> anyhow::Result<(String, Session)> {
    let sid = random_token(32);
    let id = sha256_hex(&sid);
    let auth_time = now();
    let expires_at = auth_time + st.cfg.session_ttl;
    st.db.with(|c| {
        c.execute(
            "INSERT INTO sessions (id, user_id, auth_time, amr, acr, expires_at, created_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                user_id,
                auth_time,
                serde_json::to_string(&amr).unwrap_or_else(|_| "[]".into()),
                ACR_PASSKEY,
                expires_at,
                auth_time,
                auth_time,
            ],
        )?;
        Ok(())
    })?;
    Ok((
        sid,
        Session {
            id,
            user_id: user_id.to_string(),
            auth_time,
            amr,
            acr: ACR_PASSKEY.into(),
            expires_at,
            created_at: auth_time,
            last_seen_at: auth_time,
            user_agent: None,
            ip: None,
        },
    ))
}

fn session_cookie(st: &AppState, sid: &str) -> HeaderValue {
    let mut value = format!(
        "{COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        st.cfg.session_ttl
    );
    if st.cfg.cookie_secure {
        value.push_str("; Secure");
    }
    HeaderValue::from_str(&value).expect("cookie value is valid ASCII")
}

fn cleared_cookie(st: &AppState) -> HeaderValue {
    let mut value = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if st.cfg.cookie_secure {
        value.push_str("; Secure");
    }
    HeaderValue::from_str(&value).expect("cookie value is valid ASCII")
}

/// Delete the server-side session and return a Set-Cookie that clears it.
pub fn end_local_session(st: &AppState, headers: &HeaderMap) -> Option<HeaderValue> {
    let cookies = parse_cookies(headers);
    if let Some(sid) = cookies.get(COOKIE_NAME) {
        let hash = sha256_hex(sid);
        // Logout must revoke server-tracked JWTs as well as deleting the browser
        // session. Otherwise a copied access token could remain active until exp.
        let _ = st.db.tx(|tx| {
            db::revoke_session_tokens(tx, &hash)?;
            tx.execute("DELETE FROM sessions WHERE id = ?1", params![hash])?;
            Ok(())
        });
    }
    Some(cleared_cookie(st))
}

fn attach_cookie(mut res: Response, cookie: HeaderValue) -> Response {
    res.headers_mut().append(header::SET_COOKIE, cookie);
    res
}

// ---------------------------------------------------------------------------
// Flow helpers
// ---------------------------------------------------------------------------

fn insert_flow(
    st: &AppState,
    kind: &str,
    user_id: Option<&str>,
    client_id: Option<&str>,
    payload: &Value,
    csrf: Option<&str>,
    ttl: i64,
) -> anyhow::Result<Flow> {
    let id = new_id();
    let expires_at = now() + ttl;
    st.db.with(|c| {
        c.execute(
            "INSERT INTO flows (id, kind, user_id, client_id, payload, challenge, csrf, expires_at, created_at, consumed)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, 0)",
            params![
                id,
                kind,
                user_id,
                client_id,
                serde_json::to_string(payload)?,
                csrf,
                expires_at,
                now()
            ],
        )?;
        Ok(())
    })?;
    Ok(Flow {
        id,
        kind: kind.to_string(),
        user_id: user_id.map(String::from),
        client_id: client_id.map(String::from),
        payload: payload.clone(),
        challenge: None,
        csrf: csrf.map(String::from),
        expires_at,
        consumed: false,
    })
}

fn set_challenge(st: &AppState, rid: &str, challenge: &str) -> anyhow::Result<()> {
    st.db.with(|c| {
        let changed = c.execute(
            "UPDATE flows SET challenge = ?1 WHERE id = ?2 AND consumed = 0 AND expires_at > ?3",
            params![challenge, rid, now()],
        )?;
        anyhow::ensure!(changed == 1, "flow is consumed or expired");
        Ok(())
    })?;
    Ok(())
}

fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, Html(ui::error_page("400", message))).into_response()
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

pub async fn login_page(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let rid = match q.get("rid") {
        Some(rid) => rid.clone(),
        None => match insert_flow(&st, "session", None, None, &json!({}), Some(random_token(18).as_str()), 600) {
            Ok(flow) => return oidc::redirect_302(&format!("/login?rid={}", urlenc(&flow.id))),
            Err(_) => return bad_request("ログイン画面を初期化できませんでした"),
        },
    };

    let flow = match st.db.with(|c| db::load_flow(c, &rid)) {
        Ok(Some(f)) => f,
        _ => return bad_request("このログインリンクは期限切れです。もう一度お試しください。"),
    };
    if !matches!(flow.kind.as_str(), "authorize" | "session") {
        return bad_request("不正なログイン要求です");
    }

    Html(ui::login_page(&flow.id, flow.csrf.as_deref().unwrap_or(""))).into_response()
}

#[derive(Deserialize)]
pub struct RidRequest {
    pub rid: String,
}

#[derive(Deserialize)]
pub struct CredentialRequest {
    pub rid: String,
    pub credential: Value,
}

pub async fn login_options(
    State(st): State<AppState>,
    Json(req): Json<RidRequest>,
) -> Response {
    let flow = match st.db.with(|c| db::load_flow(c, &req.rid)) {
        Ok(Some(f)) if matches!(f.kind.as_str(), "authorize" | "session") => f,
        _ => return OauthError::invalid_request("ログイン要求が無効か期限切れです").into_response(),
    };

    let (public_key, challenge) = webauthn::authentication_options(&st.cfg, &[]);
    if set_challenge(&st, &flow.id, &challenge).is_err() {
        return OauthError::server_error("チャレンジを保存できませんでした").into_response();
    }
    Json(json!({ "publicKey": public_key })).into_response()
}

pub async fn login_verify(
    State(st): State<AppState>,
    Json(req): Json<CredentialRequest>,
) -> Response {
    match login_verify_inner(&st, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn login_verify_inner(st: &AppState, req: CredentialRequest) -> Result<Response, OauthError> {
    let flow = st
        .db
        .with(|c| db::load_flow(c, &req.rid))?
        .ok_or_else(|| OauthError::invalid_request("ログイン要求が無効か期限切れです"))?;
    if !matches!(flow.kind.as_str(), "authorize" | "session") {
        return Err(OauthError::invalid_request("不正なログイン要求です"));
    }
    let challenge = flow
        .challenge
        .clone()
        .ok_or_else(|| OauthError::invalid_request("チャレンジがありません"))?;

    let cred_id = req
        .credential
        .get("rawId")
        .or_else(|| req.credential.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| OauthError::invalid_request("credential id がありません"))?
        .to_string();

    let credential = st
        .db
        .with(|c| db::load_credential(c, &cred_id))?
        .ok_or_else(|| OauthError::invalid_request("このパスキーは登録されていません"))?;

    let outcome = webauthn::verify_authentication(&st.cfg, &challenge, &req.credential, &credential)
        .map_err(|e| OauthError::invalid_request(format!("認証に失敗しました: {e}")))?;

    // Consume the challenge and update the credential counter in one transaction.
    // The conditional update makes the ceremony single-use even when two valid
    // verification requests arrive concurrently.
    let consumed = st.db.tx(|tx| {
        let changed = tx.execute(
            "UPDATE flows SET challenge = '' WHERE id = ?1 AND kind IN ('authorize', 'session') AND challenge = ?2 AND consumed = 0 AND expires_at > ?3",
            params![flow.id, challenge, now()],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        let credential_updated = tx.execute(
            "UPDATE credentials SET sign_count = ?1, backup_state = ?2, last_used_at = ?3 WHERE id = ?4 AND sign_count = ?5",
            params![
                outcome.sign_count,
                outcome.backup_state as i64,
                now(),
                credential.id,
                credential.sign_count,
            ],
        )?;
        Ok(credential_updated == 1)
    })?;
    if !consumed {
        return Err(OauthError::invalid_request(
            "ログイン要求は既に使用済みか期限切れです",
        ));
    }

    let user = st
        .db
        .with(|c| db::load_user(c, &outcome.user_id))?
        .ok_or_else(|| OauthError::invalid_request("ユーザーが見つかりません"))?;

    let amr = if credential.backup_eligible {
        vec!["pop".to_string(), "swk".to_string()]
    } else {
        vec!["pop".to_string(), "hwk".to_string()]
    };
    let (sid, _session) = create_session(st, &user.id, amr).map_err(|e| OauthError::server_error(e.to_string()))?;

    let next = if flow.kind == "authorize" {
        format!("/consent?rid={}", urlenc(&flow.id))
    } else {
        "/".to_string()
    };

    let res = Json(json!({ "ok": true, "next": next })).into_response();
    Ok(attach_cookie(res, session_cookie(st, &sid)))
}

// ---------------------------------------------------------------------------
// Sign-up
// ---------------------------------------------------------------------------

pub async fn signup_page(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !st.cfg.allow_signup {
        return (StatusCode::FORBIDDEN, Html(ui::error_page("403", "新規登録は無効になっています"))).into_response();
    }
    Html(ui::signup_page(q.get("rid").map(String::as_str))).into_response()
}

#[derive(Deserialize)]
pub struct SignupStart {
    pub username: String,
    pub display_name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub rid: Option<String>,
}

pub async fn signup_options(
    State(st): State<AppState>,
    Json(req): Json<SignupStart>,
) -> Response {
    match signup_options_inner(&st, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn signup_options_inner(st: &AppState, req: SignupStart) -> Result<Response, OauthError> {
    if !st.cfg.allow_signup {
        return Err(OauthError::invalid_request("新規登録は無効になっています"));
    }
    let username = req.username.trim().to_ascii_lowercase();
    if username.len() < 3 || username.len() > 64 {
        return Err(OauthError::invalid_request("ユーザー名は3〜64文字で入力してください"));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(OauthError::invalid_request(
            "ユーザー名は英数字と . _ - のみ使用できます",
        ));
    }
    let display_name = req.display_name.trim().to_string();
    if display_name.is_empty() || display_name.chars().count() > 80 {
        return Err(OauthError::invalid_request("表示名を入力してください"));
    }
    let email = req
        .email
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(email) = &email {
        if !email.contains('@') || email.len() > 254 {
            return Err(OauthError::invalid_request("メールアドレスの形式が不正です"));
        }
    }
    if st.db.with(|c| db::load_user_by_name(c, &username))?.is_some() {
        return Err(OauthError::invalid_request("このユーザー名は既に使われています"));
    }

    let user_id = new_id();
    let user = User {
        id: user_id.clone(),
        username: username.clone(),
        display_name: display_name.clone(),
        email: email.clone(),
        email_verified: false,
        created_at: now(),
    };
    let (public_key, challenge) = webauthn::registration_options(&st.cfg, &user, &[]);
    let payload = json!({
        "user_id": user_id,
        "username": username,
        "display_name": display_name,
        "email": email,
        "return_rid": req.rid,
    });
    let flow = insert_flow(&st, "signup", Some(user_id.as_str()), None, &payload, None, 600)
        .map_err(|e| OauthError::server_error(e.to_string()))?;
    set_challenge(st, &flow.id, &challenge).map_err(|e| OauthError::server_error(e.to_string()))?;

    Ok(Json(json!({
        "rid": flow.id,
        "publicKey": public_key,
    }))
    .into_response())
}

pub async fn signup_verify(
    State(st): State<AppState>,
    Json(req): Json<CredentialRequest>,
) -> Response {
    match signup_verify_inner(&st, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn signup_verify_inner(st: &AppState, req: CredentialRequest) -> Result<Response, OauthError> {
    let flow = st
        .db
        .with(|c| db::load_flow(c, &req.rid))?
        .ok_or_else(|| OauthError::invalid_request("登録セッションが期限切れです"))?;
    if flow.kind != "signup" {
        return Err(OauthError::invalid_request("不正な登録要求です"));
    }
    let challenge = flow
        .challenge
        .clone()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| OauthError::invalid_request("チャレンジがありません"))?;

    let payload = &flow.payload;
    let user = User {
        id: payload["user_id"].as_str().unwrap_or_default().to_string(),
        username: payload["username"].as_str().unwrap_or_default().to_string(),
        display_name: payload["display_name"].as_str().unwrap_or_default().to_string(),
        email: payload["email"].as_str().map(String::from),
        email_verified: false,
        created_at: now(),
    };
    if user.id.is_empty() || user.username.is_empty() {
        return Err(OauthError::server_error("登録データが壊れています"));
    }

    let new = webauthn::verify_registration(&st.cfg, &challenge, &user, &req.credential)
        .map_err(|e| OauthError::invalid_request(format!("パスキーの登録に失敗しました: {e}")))?;

    st.db.tx(|tx| {
        // Claim the registration ceremony before creating any account data.
        // The conditional update makes the flow single-use under concurrency.
        let claimed = tx.execute(
            "UPDATE flows SET consumed = 1, challenge = '' \
             WHERE id = ?1 AND kind = 'signup' AND challenge = ?2 \
               AND consumed = 0 AND expires_at > ?3",
            params![flow.id, challenge, now()],
        )?;
        anyhow::ensure!(claimed == 1, "registration flow already consumed or expired");

        tx.execute(
            "INSERT INTO users (id, username, display_name, email, email_verified, created_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5)",
            params![user.id, user.username, user.display_name, user.email, now()],
        )?;
        tx.execute(
            "INSERT INTO credentials
                (id, user_id, public_key, key_type, sign_count, transports, aaguid,
                 backup_eligible, backup_state, nickname, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)",
            params![
                new.id,
                user.id,
                new.cose,
                new.alg_name,
                new.sign_count,
                serde_json::to_string(&new.transports).unwrap_or_else(|_| "[]".into()),
                new.aaguid,
                new.backup_eligible as i64,
                new.backup_state as i64,
                "最初のパスキー",
                now(),
            ],
        )?;
        Ok(())
    })
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            OauthError::invalid_request("このユーザー名は既に使われています")
        } else {
            OauthError::server_error(format!("登録を保存できませんでした: {e}"))
        }
    })?;

    let amr = if new.backup_eligible {
        vec!["pop".to_string(), "swk".to_string()]
    } else {
        vec!["pop".to_string(), "hwk".to_string()]
    };
    let (sid, _) = create_session(st, &user.id, amr).map_err(|e| OauthError::server_error(e.to_string()))?;

    let next = match payload["return_rid"].as_str() {
        Some(rid) if !rid.is_empty() => {
            let still_valid = st.db.with(|c| db::load_flow(c, rid)).ok().flatten().is_some();
            if still_valid {
                format!("/consent?rid={}", urlenc(rid))
            } else {
                "/".to_string()
            }
        }
        _ => "/".to_string(),
    };

    let res = Json(json!({ "ok": true, "next": next })).into_response();
    Ok(attach_cookie(res, session_cookie(st, &sid)))
}

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

pub async fn consent_page(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let rid = match q.get("rid") {
        Some(r) => r.clone(),
        None => return bad_request("認可リクエストが指定されていません"),
    };
    let Some(session) = session_from_headers(&st, &headers) else {
        return oidc::redirect_302(&format!("/login?rid={}", urlenc(&rid)));
    };
    let flow = match st.db.with(|c| db::load_flow(c, &rid)) {
        Ok(Some(f)) if f.kind == "authorize" => f,
        _ => return bad_request("この認可リクエストは期限切れです"),
    };
    let params: oidc::AuthzParams = match serde_json::from_value(flow.payload.clone()) {
        Ok(p) => p,
        Err(_) => return bad_request("認可リクエストが壊れています"),
    };
    let client = match st.db.with(|c| db::load_client(c, &params.client_id)) {
        Ok(Some(c)) => c,
        _ => return bad_request("クライアントが見つかりません"),
    };
    let user = match st.db.with(|c| db::load_user(c, &session.user_id)) {
        Ok(Some(u)) => u,
        _ => return bad_request("ユーザーが見つかりません"),
    };

    let redirect_host = params
        .redirect_uri
        .split("://")
        .nth(1)
        .unwrap_or(&params.redirect_uri)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    Html(ui::consent_page(
        &flow.id,
        flow.csrf.as_deref().unwrap_or(""),
        &client.name,
        &user.username,
        &params.scope,
        &redirect_host,
    ))
    .into_response()
}

pub async fn consent_submit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let Some(session) = session_from_headers(&st, &headers) else {
        return oidc::redirect_302("/login");
    };
    let Some(rid) = form.get("rid") else {
        return bad_request("認可リクエストがありません");
    };
    let flow = match st.db.with(|c| db::load_flow(c, rid)) {
        Ok(Some(f)) if f.kind == "authorize" => f,
        _ => return bad_request("この認可リクエストは期限切れです"),
    };
    let csrf_ok = match (&flow.csrf, form.get("csrf")) {
        (Some(expected), Some(provided)) => ct_eq(expected, provided),
        _ => false,
    };
    if !csrf_ok {
        return bad_request("CSRF トークンが一致しません");
    }
    let user = match st.db.with(|c| db::load_user(c, &session.user_id)) {
        Ok(Some(u)) => u,
        _ => return bad_request("ユーザーが見つかりません"),
    };
    let approve = form.get("decision").map(|d| d == "allow").unwrap_or(false);
    if approve {
        if let Ok(params) =
            serde_json::from_value::<oidc::AuthzParams>(flow.payload.clone())
        {
            let _ = st
                .db
                .with(|c| db::record_consent(c, &user.id, &params.client_id, &params.scope));
        }
    }
    oidc::complete_authorization(&st, &flow, &user, &session, approve)
}

// ---------------------------------------------------------------------------
// Account console
// ---------------------------------------------------------------------------

pub async fn account(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = session_from_headers(&st, &headers) else {
        return oidc::redirect_302("/login");
    };
    let user = match st.db.with(|c| db::load_user(c, &session.user_id)) {
        Ok(Some(u)) => u,
        _ => return oidc::redirect_302("/login"),
    };
    let creds = st
        .db
        .with(|c| db::credentials_for_user(c, &user.id))
        .unwrap_or_default();
    Html(ui::account_page(&user, &creds)).into_response()
}

pub async fn account_logout(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let cookie = end_local_session(&st, &headers);
    let mut res = oidc::redirect_302("/login");
    if let Some(c) = cookie {
        res.headers_mut().append(header::SET_COOKIE, c);
    }
    res
}

// ---------------------------------------------------------------------------
// Adding another passkey
// ---------------------------------------------------------------------------

pub async fn add_passkey_options(State(st): State<AppState>, headers: HeaderMap) -> Response {
    match add_passkey_options_inner(&st, &headers) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn add_passkey_options_inner(st: &AppState, headers: &HeaderMap) -> Result<Response, OauthError> {
    let session = session_from_headers(st, headers)
        .ok_or_else(|| OauthError::unauthorized("サインインが必要です"))?;
    let user = st
        .db
        .with(|c| db::load_user(c, &session.user_id))?
        .ok_or_else(|| OauthError::unauthorized("ユーザーが見つかりません"))?;
    let existing = st.db.with(|c| db::credentials_for_user(c, &user.id))?;

    let (public_key, challenge) = webauthn::registration_options(&st.cfg, &user, &existing);
    let flow = insert_flow(st, "addpasskey", Some(user.id.as_str()), None, &json!({}), None, 600)
        .map_err(|e| OauthError::server_error(e.to_string()))?;
    set_challenge(st, &flow.id, &challenge).map_err(|e| OauthError::server_error(e.to_string()))?;

    Ok(Json(json!({ "rid": flow.id, "publicKey": public_key })).into_response())
}

pub async fn add_passkey_verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialRequest>,
) -> Response {
    match add_passkey_verify_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn add_passkey_verify_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: CredentialRequest,
) -> Result<Response, OauthError> {
    let session = session_from_headers(st, headers)
        .ok_or_else(|| OauthError::unauthorized("サインインが必要です"))?;
    let flow = st
        .db
        .with(|c| db::load_flow(c, &req.rid))?
        .ok_or_else(|| OauthError::invalid_request("登録セッションが期限切れです"))?;
    if flow.kind != "addpasskey" || flow.user_id.as_deref() != Some(session.user_id.as_str()) {
        return Err(OauthError::invalid_request("不正な登録要求です"));
    }
    let challenge = flow
        .challenge
        .clone()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| OauthError::invalid_request("チャレンジがありません"))?;
    let user = st
        .db
        .with(|c| db::load_user(c, &session.user_id))?
        .ok_or_else(|| OauthError::unauthorized("ユーザーが見つかりません"))?;

    let new = webauthn::verify_registration(&st.cfg, &challenge, &user, &req.credential)
        .map_err(|e| OauthError::invalid_request(format!("パスキーの登録に失敗しました: {e}")))?;

    st.db.tx(|tx| {
        // Claim the passkey-registration ceremony before inserting the key.
        let claimed = tx.execute(
            "UPDATE flows SET consumed = 1, challenge = '' \
             WHERE id = ?1 AND kind = 'addpasskey' AND user_id = ?2 \
               AND challenge = ?3 AND consumed = 0 AND expires_at > ?4",
            params![flow.id, user.id, challenge, now()],
        )?;
        anyhow::ensure!(claimed == 1, "passkey flow already consumed or expired");

        tx.execute(
            "INSERT INTO credentials
                (id, user_id, public_key, key_type, sign_count, transports, aaguid,
                 backup_eligible, backup_state, nickname, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)",
            params![
                new.id,
                user.id,
                new.cose,
                new.alg_name,
                new.sign_count,
                serde_json::to_string(&new.transports).unwrap_or_else(|_| "[]".into()),
                new.aaguid,
                new.backup_eligible as i64,
                new.backup_state as i64,
                "追加したパスキー",
                now(),
            ],
        )?;
        Ok(())
    })
    .map_err(|e| OauthError::server_error(format!("登録を保存できませんでした: {e}")))?;

    Ok(Json(json!({ "ok": true })).into_response())
}

#[cfg(test)]
mod session_expiry_tests {
    use super::*;

    fn sample_session() -> Session {
        Session {
            id: "session-hash".into(),
            user_id: "user-1".into(),
            auth_time: 100,
            amr: vec!["passkey".into()],
            acr: ACR_PASSKEY.into(),
            expires_at: 200,
            created_at: 100,
            last_seen_at: 190,
            user_agent: None,
            ip: None,
        }
    }

    #[test]
    fn absolute_expiry_is_enforced_even_when_recently_active() {
        let mut session = sample_session();
        session.last_seen_at = 199;
        assert!(session_expired(&session, 200, 180));
    }

    #[test]
    fn idle_expiry_is_enforced_before_absolute_expiry() {
        let session = sample_session();
        assert!(session_expired(&session, 195, 4));
    }

    #[test]
    fn zero_idle_timeout_disables_only_the_idle_check() {
        let mut session = sample_session();
        session.expires_at = 500;
        session.last_seen_at = 100;
        assert!(!session_expired(&session, 200, 0));
    }
}
