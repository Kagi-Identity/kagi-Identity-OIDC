#[tokio::main]
async fn main() -> anyhow::Result<()> {
    kagi::run_local().await
}
