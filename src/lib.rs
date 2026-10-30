mod auth;
mod config;
mod db;
mod dpop;
mod error;
mod jose;
mod keys;
mod oidc;
mod resource;
mod ui;
mod util;
mod webauthn;

use axum::extract::{Request, State};
use axum::http::{header, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use config::Config;
use db::Db;
use keys::KeyRing;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: Arc<Db>,
    pub keys: Arc<RwLock<KeyRing>>,
}

/// Initialize state once per process/function instance. All durable state,
/// including signing keys, sessions and OAuth artifacts, lives in PostgreSQL.
pub fn build_state() -> anyhow::Result<AppState> {
    let cfg = Arc::new(Config::from_env()?);
    if std::env::var("VERCEL").as_deref() == Ok("1") {
        anyhow::ensure!(
            cfg.database_url.as_deref().is_some_and(|u| u.starts_with("postgres://") || u.starts_with("postgresql://")),
            "Vercel production requires KAGI_DATABASE_URL (PostgreSQL); ephemeral SQLite is not supported"
        );
        anyhow::ensure!(cfg.issuer.starts_with("https://"), "Vercel requires an HTTPS KAGI_ISSUER");
        anyhow::ensure!(cfg.origin == cfg.issuer, "KAGI_ORIGIN must exactly match KAGI_ISSUER for this deployment");
        anyhow::ensure!(cfg.cookie_secure, "KAGI_COOKIE_SECURE=1 is required on Vercel");
        anyhow::ensure!(cfg.hsts, "KAGI_HSTS=1 is required on Vercel");
        anyhow::ensure!(!cfg.seed_demo, "KAGI_SEED_DEMO must be disabled on Vercel");
        anyhow::ensure!(cfg.require_par, "KAGI_REQUIRE_PAR=1 is required on Vercel");
        anyhow::ensure!(
            cfg.admin_token.as_ref().is_some_and(|v| v.len() >= 32),
            "KAGI_ADMIN_TOKEN must be a randomly generated secret of at least 32 characters"
        );
        anyhow::ensure!(
            cfg.registration_token.as_ref().is_some_and(|v| v.len() >= 32),
            "KAGI_REGISTRATION_TOKEN must be a randomly generated secret of at least 32 characters"
        );
    }

    let db = Arc::new(Db::open(cfg.database_url.as_deref(), &cfg.db_path)?);
    if cfg.seed_demo {
        anyhow::ensure!(cfg.is_local(), "demo client seeding is only allowed for localhost");
        db.with(|c| db::seed_demo_client(c))?;
    }

    let ring = KeyRing::load(&db)?;
    Ok(AppState {
        cfg,
        db,
        keys: Arc::new(RwLock::new(ring)),
    })
}

/// Build the complete Axum router around durable application state.
pub fn routes(state: AppState) -> Router {
    routes_and_security(state)
}

fn routes_and_security(state: AppState) -> Router {
    Router::new()
    Router::new()
        .route("/", get(auth::account))
        .route("/login", get(auth::login_page))
        .route("/signup", get(auth::signup_page))
        .route("/consent", get(auth::consent_page).post(auth::consent_submit))
        .route("/account/logout", post(auth::account_logout))
        .route("/api/webauthn/login/options", post(auth::login_options))
        .route("/api/webauthn/login/verify", post(auth::login_verify))
        .route("/api/webauthn/signup/options", post(auth::signup_options))
        .route("/api/webauthn/signup/verify", post(auth::signup_verify))
        .route("/api/webauthn/passkey/options", post(auth::add_passkey_options))
        .route("/api/webauthn/passkey/verify", post(auth::add_passkey_verify))
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route("/.well-known/oauth-authorization-server", get(oidc::discovery))
        .route("/jwks.json", get(oidc::jwks))
        .route("/authorize", get(oidc::authorize))
        .route("/par", post(oidc::par))
        .route("/token", post(oidc::token))
        .route("/userinfo", get(resource::userinfo).post(resource::userinfo))
        .route("/introspect", post(resource::introspect))
        .route("/revoke", post(resource::revoke))
        .route(
            "/logout",
            get(resource::end_session_get).post(resource::end_session_post),
        )
        .route("/register", post(resource::register_client))
        .route("/admin/keys/rotate", post(resource::rotate_keys))
        .route("/healthz", get(resource::health))
        .route("/demo", get(demo_page))
        .route("/demo/callback", get(demo_page))
        .route("/static/app.js", get(app_js))
        .route("/static/kagi.js", get(kagi_js))
        .route("/static/style.css", get(style_css))
        .fallback(not_found)
        .with_state(state)
}

fn api_path(path: &str) -> bool {
    path.starts_with("/.well-known/")
        || matches!(
            path,
            "/jwks.json"
                | "/par"
                | "/token"
                | "/userinfo"
                | "/introspect"
                | "/revoke"
                | "/register"
                | "/healthz"
        )
}

async fn harden(req: Request, next: Next) -> Response {
    let is_api = api_path(req.uri().path());
    let preflight = req.method() == Method::OPTIONS && is_api;

    if preflight {
        return (
            StatusCode::NO_CONTENT,
            [
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
                (
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    "authorization, content-type, dpop",
                ),
                (header::ACCESS_CONTROL_MAX_AGE, "600"),
            ],
        )
            .into_response();
    }

    let mut res = next.run(req).await;
    let headers = res.headers_mut();

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; \
             frame-ancestors 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if is_api {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
    }
    res
}

async fn app_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../static/app.js"),
    )
        .into_response()
}

async fn kagi_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../static/kagi.js"),
    )
        .into_response()
}

async fn demo_page(State(st): State<AppState>) -> Response {
    axum::response::Html(ui::demo_page(&st.cfg.issuer, st.cfg.seed_demo)).into_response()
}

async fn style_css() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../static/style.css"),
    )
        .into_response()
}

async fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::response::Html(ui::error_page("404", "ページが見つかりません")),
    )
        .into_response()
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    println!("\n[kagi] shutting down");
}

}

pub async fn run_local() -> anyhow::Result<()> {
    let cfg = Arc::new(Config::from_env()?);
    let db = Arc::new(Db::open(cfg.database_url.as_deref(), &cfg.db_path)?);
    if cfg.seed_demo {
        anyhow::ensure!(cfg.is_local(), "demo client seeding is only allowed for localhost");
        db.with(|c| db::seed_demo_client(c))?;
    }
    let ring = KeyRing::load(&db)?;
    let state = AppState { cfg: cfg.clone(), db: db.clone(), keys: Arc::new(RwLock::new(ring)) };
    let app = routes(state);
    let listener = TcpListener::bind(&cfg.bind).await?;
    println!("[kagi] issuer   {}", cfg.issuer);
    println!("[kagi] bind     http://{}", cfg.bind);
    println!("[kagi] database {}", db.backend());
    for warning in cfg.warnings() { eprintln!("[kagi] SECURITY WARNING: {warning}"); }
    axum::serve(listener, app).await?;
    Ok(())
}
