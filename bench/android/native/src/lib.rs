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
    let argv: Vec<String> = std::iter::once("rawgmeas".to_string()).chain(args.split_whitespace().map(String::from)).collect();
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

/// Приложение замеров (com.rawg.meas).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_rawg_meas_Native_run<'a>(mut env: JNIEnv<'a>, _c: JClass<'a>, args: JString<'a>, state: JString<'a>) -> jint {
    run_impl(&mut env, args, state)
}

/// Приложение VPN (com.rawg.vpn).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_rawg_vpn_Native_run<'a>(mut env: JNIEnv<'a>, _c: JClass<'a>, args: JString<'a>, state: JString<'a>) -> jint {
    run_impl(&mut env, args, state)
}

/// VPN-клиент нового образца (rawgd client): аргументы - как у командной строки, `state` - каталог состояния.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_rawg_vpn_Native_runVpn<'a>(mut env: JNIEnv<'a>, _c: JClass<'a>, args: JString<'a>, state: JString<'a>) -> jint {
    use clap::Parser as _;
    let args: String = env.get_string(&args).map(|s| s.into()).unwrap_or_default();
    let state: String = env.get_string(&state).map(|s| s.into()).unwrap_or_default();
    let _ = std::fs::remove_file(format!("{state}/error.txt"));
    let st2 = state.clone();
    std::panic::set_hook(Box::new(move |info| write_err(&st2, &format!("panic: {info}"))));
    let argv: Vec<String> = std::iter::once("rawgd".to_string()).chain(args.split_whitespace().map(String::from)).collect();
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
pub extern "system" fn Java_com_rawg_vpn_Native_setUiVisible(_env: JNIEnv, _c: JClass, visible: jboolean) {
    rns_iroh_node::mobile::set_ui_visible(visible != 0);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_rawg_vpn_Native_networkChanged(_env: JNIEnv, _c: JClass) {
    rns_iroh_node::mobile::network_changed();
}

/// Приглашение в самую короткую текстовую форму (эмодзи). Принимает rawgi-… или эмодзи; при ошибке - пустая строка.
/// Строку в журнал не пишем.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_rawg_vpn_Native_toEmoji<'a>(mut env: JNIEnv<'a>, _c: JClass<'a>, s: JString<'a>) -> jstring {
    let s: String = env.get_string(&s).map(|s| s.into()).unwrap_or_default();
    let out = rns_iroh_node::invite_to_emoji(&s).unwrap_or_default();
    env.new_string(out).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// Приглашение в каноническую строку rawgi-… (для серверов, QR и совместимости). Принимает rawgi-… или эмодзи; при ошибке - пустая строка.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_rawg_vpn_Native_toBase64<'a>(mut env: JNIEnv<'a>, _c: JClass<'a>, s: JString<'a>) -> jstring {
    let s: String = env.get_string(&s).map(|s| s.into()).unwrap_or_default();
    let out = rns_iroh_node::invite_to_base64(&s).unwrap_or_default();
    env.new_string(out).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
}
