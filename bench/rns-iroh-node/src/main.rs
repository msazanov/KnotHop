use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // файлы состояния создаются только для владельца (SA-24): часть пишет ядро Leviculum через `File::create` по umask
    unsafe { libc::umask(0o077); }
    rns_iroh_node::run(rns_iroh_node::Cli::parse()).await
}
