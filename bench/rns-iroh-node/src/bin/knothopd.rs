use clap::Parser;

/// Число потоков рантайма. 0 - по доступным CPU с учётом квоты cgroup (systemd CPUQuota, docker --cpus):
/// лишние потоки на одном CPU спорят за блокировку QUIC-соединения и съедают ~40% скорости выхода (журнал, W43).
/// Для узла `workers` из --config тоже учитывается (раньше он читался уже после запуска рантайма и не действовал).
fn workers(cli: &rns_iroh_node::VpnCli) -> usize {
    let w = match &cli.cmd {
        rns_iroh_node::VpnCmd::Node(a) => {
            let from_conf = a.config.as_ref().and_then(|p| std::fs::read(p).ok())
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v["workers"].as_u64())
                .map(|n| n as usize);
            from_conf.unwrap_or(a.workers)
        }
        rns_iroh_node::VpnCmd::Client(a) => a.workers,
        _ => 0,
    };
    if w > 0 {
        return w;
    }
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn main() -> anyhow::Result<()> {
    let cli = rns_iroh_node::VpnCli::parse();
    let mut b = tokio::runtime::Builder::new_multi_thread();
    b.enable_all();
    b.worker_threads(workers(&cli));
    b.build()?.block_on(rns_iroh_node::run_vpn(cli))
}
