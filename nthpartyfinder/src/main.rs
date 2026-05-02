#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use anyhow::Result;

#[tokio::main]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn main() -> Result<()> {
    nthpartyfinder::app::run().await
}
