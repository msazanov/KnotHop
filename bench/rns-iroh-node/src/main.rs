use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rns_iroh_node::run(rns_iroh_node::Cli::parse()).await
}
