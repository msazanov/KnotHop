//! Лабораторный драйвер E2E HOST_ACCESS: полноценный `knothopd client` внутри ЭТОГО процесса (как VpnService на телефоне)
//! и локальный Unix-сокет, через который harness вызывает тот же мост, что Java `Native.runCLI` -> `admin_cli_json`.
//!
//! Зачем: `admin-submit` кладёт запрос в живой LXMF-процессор клиента (реестр в памяти процесса), поэтому отдельный
//! процесс `knothopd admin-submit` честно отвечает `unsupported_offline`. Телефонный путь - это вызов моста в процессе VPN.
//!
//! Запуск: lxmf_host_access_e2e_driver SOCK STATE -- client --state STATE [аргументы knothopd client]
//! Протокол сокета: одна строка команды (`admin-view --state x --target ...`), в ответ - одна строка JSON. Сокет 0600.
//! Только лаборатория; секретов не печатает, команды не исполняет через shell. Файл подключается как example симлинком
//! bench/rns-iroh-node/examples/lxmf_host_access_e2e_driver.rs -> ../../tests/lxmf_host_access_e2e_driver.rs.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let sock = args.next().ok_or_else(|| anyhow::anyhow!("usage: driver SOCK STATE -- client ..."))?;
    let state = args.next().ok_or_else(|| anyhow::anyhow!("usage: driver SOCK STATE -- client ..."))?;
    if args.next().as_deref() != Some("--") {
        anyhow::bail!("usage: driver SOCK STATE -- client ...");
    }
    let mut argv = vec!["knothopd".to_string()];
    argv.extend(args);
    let cli = rns_iroh_node::VpnCli::try_parse_from(&argv)?;

    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    std::thread::Builder::new().name("e2e-ctl".into()).spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let state = state.clone();
            std::thread::spawn(move || {
                let mut line = String::new();
                let mut reader = BufReader::new((&conn).take(8192));
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let reply = rns_iroh_node::admin_cli_json(line.trim(), &state);
                let mut conn = &conn;
                let _ = conn.write_all(reply.as_bytes());
                let _ = conn.write_all(b"\n");
            });
        }
    })?;

    let mut b = tokio::runtime::Builder::new_multi_thread();
    b.enable_all();
    b.worker_threads(2);
    b.build()?.block_on(rns_iroh_node::run_vpn(cli))
}
