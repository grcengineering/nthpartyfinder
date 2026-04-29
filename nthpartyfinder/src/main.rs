use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    nthpartyfinder::app::run().await
}
