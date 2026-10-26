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

/// Приложение VPN (com.knothop.vpn).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_vpn_Native_run<'a>(mut env: JNIEnv<'a>, _c: JClass<'a>, args: JString<'a>, state: JString<'a>) -> jint {
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
        let rt = b.build()?;
        let r = rt.block_on(rns_iroh_node::run_vpn(cli));
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_vpn_Native_networkChanged(_env: JNIEnv, _c: JClass) {
    rns_iroh_node::mobile::network_changed();
}

/// Приглашение в каноническую строку kh-… для QR и совместимости; при ошибке - пустая строка.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_knothop_vpn_Native_toBase64<'a>(mut env: JNIEnv<'a>, _c: JClass<'a>, s: JString<'a>) -> jstring {
    let s: String = env.get_string(&s).map(|s| s.into()).unwrap_or_default();
    let out = rns_iroh_node::invite_to_base64(&s).unwrap_or_default();
    env.new_string(out).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
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
