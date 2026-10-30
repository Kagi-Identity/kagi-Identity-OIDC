use std::sync::OnceLock;

use tower::ServiceBuilder;
use vercel_runtime::axum::VercelLayer;
use vercel_runtime::{Error, run};

static STATE: OnceLock<Result<kagi::AppState, String>> = OnceLock::new();

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Vercel may reuse a function instance across requests. Reuse only the
    // process-local handles; all identity/session/token state is persisted in
    // PostgreSQL and must never depend on this cache surviving.
    let state = match STATE.get_or_init(|| kagi::build_state().map_err(|e| format!("{e:#}"))) {
        Ok(state) => state.clone(),
        Err(message) => {
            eprintln!("[kagi] startup configuration failed: {message}");
            return Err(std::io::Error::other("Kagi Identity startup failed").into());
        }
    };

    let app = kagi::routes(state);
    let service = ServiceBuilder::new()
        .layer(VercelLayer::new())
        .service(app);

    run(service).await
}
