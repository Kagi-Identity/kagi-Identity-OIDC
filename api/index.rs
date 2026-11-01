use std::sync::OnceLock;

use axum::http::StatusCode;
use axum::Router;
use tower::ServiceBuilder;
use vercel_runtime::axum::VercelLayer;
use vercel_runtime::{Error, run};

static STATE: OnceLock<Result<kagi::AppState, String>> = OnceLock::new();

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Vercel may reuse a function instance across requests. Reuse only the
    // process-local handles; all identity/session/token state is persisted in
    // PostgreSQL and must never depend on this cache surviving.
    let app = match STATE.get_or_init(|| kagi::build_state().map_err(|e| format!("{e:#}"))) {
        Ok(state) => kagi::routes(state.clone()),
        Err(message) => {
            // Keep a configuration failure from becoming a platform-level
            // FUNCTION_INVOCATION_FAILED (500). The detailed cause stays in
            // server-side logs; clients receive only a generic 503 and no
            // internal configuration or secret material is disclosed.
            eprintln!("[kagi] startup configuration failed: {message}");
            Router::new().fallback(|| async {
                (StatusCode::SERVICE_UNAVAILABLE, "service temporarily unavailable")
            })
        }
    };

    let service = ServiceBuilder::new()
        .layer(VercelLayer::new())
        .service(app);

    run(service).await
}
