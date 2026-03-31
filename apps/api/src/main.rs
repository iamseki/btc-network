use btc_network_api::run;
use btc_network_observability::init_tracing;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    run().await
}
