//! JNI: одна функция `Native.run(args, stateDir)`. Блокирует поток до конца замера.
//! Ход пишется в `<state>/progress.txt`, итог в `<state>/result-c.json`, ошибка в `<state>/error.txt`.
use clap::Parser;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use rns_iroh_node::Cli;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn write_err(state: &str, msg: &str) {
    let _ = std::fs::write(format!("{state}/error.txt"), msg);
}

fn run_impl(env: &mut JNIEnv, args: JString, state: JString) -> jint {
    let args: String = env.get_string(&args).map(|s| s.into()).unwrap_or_default();
    let state: String = env.get_string(&state).map(|s| s.into()).unwrap_or_default();
    let _ = std::fs::remove_file(format!("{state}/error.txt"));
    let st2 = state.clone();
    std::panic::set_hook(Box::new(move |info| write_err(&st2, &format!("panic: {info}"))));
    let argv: Vec<String> = std::iter::once("knothopmeas".to_string()).chain(args.split_whitespace().map(String::from)).collect();
    let res = std::panic::catch_unwind(|| -> anyhow::Result<()> {
        let cli = Cli::try_parse_from(&argv)?;
        let mut b = tokio::runtime::Builder::new_multi_thread();
        b.enable_all();
        if cli.workers > 0 {
            b.worker_threads(cli.workers);
        }
        let rt = b.build()?;
        let r = rt.block_on(rns_iroh_node::run(cli));
        rt.shutdown_background();
        r
    });
    match res {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            write_err(&state, &format!("{e:#}"));
            1
        }
        Err(_) => 2,
    }
}

/// Приложение замеров (com.knothop.meas).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_meas_Native_run<'a>(mut env: JNIEnv<'a>, _c: JClass<'a>, args: JString<'a>, state: JString<'a>) -> jint {
    run_impl(&mut env, args, state)
}

/// VPN-клиент нового образца (knothopd client): аргументы - как у командной строки, `state` - каталог состояния.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_vpn_Native_runVpn<'a>(mut env: JNIEnv<'a>, _c: JClass<'a>, args: JString<'a>, state: JString<'a>) -> jint {
    use clap::Parser as _;
    let args: String = env.get_string(&args).map(|s| s.into()).unwrap_or_default();
    let state: String = env.get_string(&state).map(|s| s.into()).unwrap_or_default();
    let _ = std::fs::remove_file(format!("{state}/error.txt"));
    let st2 = state.clone();
    std::panic::set_hook(Box::new(move |info| write_err(&st2, &format!("panic: {info}"))));
    let argv: Vec<String> = std::iter::once("knothopd".to_string()).chain(args.split_whitespace().map(String::from)).collect();
    let res = std::panic::catch_unwind(|| -> anyhow::Result<()> {
        let cli = rns_iroh_node::VpnCli::try_parse_from(&argv)?;
        let workers = match &cli.cmd {
            rns_iroh_node::VpnCmd::Client(a) => a.workers,
            _ => 0,
        };
        let mut b = tokio::runtime::Builder::new_multi_thread();
        b.enable_all();
        if workers > 0 {
            b.worker_threads(workers);
        }
        let is_client = matches!(&cli.cmd, rns_iroh_node::VpnCmd::Client(_));
        let rt = b.build()?;
        if !is_client {
            let r = rt.block_on(rns_iroh_node::run_vpn(cli));
            rt.shutdown_background();
            return r;
        }
        // Клиент работает до файла `fin`. Корректный выход после него обычно мгновенный, но если какая-то задача его не заметила
        // (долгое ожидание сети, закрытие носителя), приложение не должно оставаться с живым узлом и дубликатом дескриптора TUN
        // (VPN висит после «Отключить»): по истечении срока рантайм снимается принудительно, все задачи и их дескрипторы освобождаются.
        let fin = std::path::PathBuf::from(&state).join("fin");
        let (tx, rx) = std::sync::mpsc::channel();
        rt.spawn(async move {
            let _ = tx.send(rns_iroh_node::run_vpn(cli).await);
        });
        let mut fin_seen: Option<std::time::Instant> = None;
        let r = loop {
            match rx.recv_timeout(std::time::Duration::from_millis(250)) {
                Ok(r) => break r,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break Err(anyhow::anyhow!("клиент завершился аварийно")),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if fin.exists() {
                        let since = *fin_seen.get_or_insert_with(std::time::Instant::now);
                        if since.elapsed() > std::time::Duration::from_secs(5) {
                            break Ok(());
                        }
                    }
                }
            }
        };
        rt.shutdown_background();
        r
    });
    match res {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            write_err(&state, &format!("{e:#}"));
            1
        }
        Err(_) => 2,
    }
}

/// UI visibility is a process-wide hint, independent of runtime lifetime.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_vpn_Native_setUiVisible(_env: JNIEnv, _c: JClass, visible: jboolean) {
    rns_iroh_node::mobile::set_ui_visible(visible != 0);
}

/// Расширенный журнал (флажок «debug» в приложении). Действует сразу, без перезапуска узла; на права и допуск не влияет.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_vpn_Native_setDebug(_env: JNIEnv, _c: JClass, on: jboolean) {
    rns_iroh_node::set_debug(on != 0);
}

/// Подключить (fd >= 0) или снять (fd < 0) TUN у работающего узла без перезапуска. Узел берёт свой дубликат дескриптора.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_vpn_Native_setTun(_env: JNIEnv, _c: JClass, fd: jint) -> jboolean {
    rns_iroh_node::mobile::set_tun_fd(fd) as jboolean
}

/// Просьба пользователя: 0 - внеочередной анонс, 1 - проверка связи со всеми нодами.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_vpn_Native_kick(_env: JNIEnv, _c: JClass, kind: jint) -> jboolean {
    rns_iroh_node::mobile::kick(kind) as jboolean
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_vpn_Native_networkChanged(_env: JNIEnv, _c: JClass) {
    rns_iroh_node::mobile::network_changed();
}

/// Narrow non-shell JSON admin bridge. The command parser accepts only fixed admin verbs/flags;
/// arbitrary OS commands and shell metacharacters are rejected in the Rust backend.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_vpn_Native_runCLI<'a>(mut env: JNIEnv<'a>, _c: JClass<'a>, command: JString<'a>, state: JString<'a>) -> jstring {
    let command: String = match env.get_string(&command) { Ok(s) => s.into(), Err(_) => return std::ptr::null_mut() };
    let state: String = match env.get_string(&state) { Ok(s) => s.into(), Err(_) => return std::ptr::null_mut() };
    let json = rns_iroh_node::admin_cli_json(&command, &state);
    env.new_string(json).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
}
