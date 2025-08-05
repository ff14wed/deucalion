#![feature(link_llvm_intrinsics)]
#![allow(internal_features)]
#![deny(unused_imports)]

use std::{fs, io::Read, path::PathBuf, sync::Arc, time::SystemTime};

use anyhow::{Context, Result, format_err};
use simplelog::{LevelFilter, WriteLogger};
use w32module::drop_ref_count_to_one;
#[cfg(debug_assertions)]
use winapi::um::{consoleapi, wincon};
#[cfg(windows)]
use winapi::{
    shared::minwindef::*,
    um::{libloaderapi, minwinbase::*, processthreadsapi},
};

mod hook;
mod w32module;

pub mod namedpipe;
pub mod procloader;
pub mod rpc;

mod server;

use log::{error, info};
#[cfg(debug_assertions)]
use simplelog::{CombinedLogger, SimpleLogger};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT_SHA: &str = env!("VERGEN_GIT_SHA");
const COMMIT_DIRTY: &str = env!("VERGEN_GIT_DIRTY");

pub const RECV_SIG: &str = "E8 $ { ' } 4C 8B 4F 10 8B 47 1C 45";
pub const SEND_SIG: &str = "40 53 56 48 83 EC 38 48 8B D9 48 8B F2 8B";
pub const SEND_LOBBY_SIG: &str = "40 53 48 83 EC 20 44 8B 41 28";
/// Overriding with a custom signature for create_target is not supported. If
/// this has changed, it is likely that the hook is broken in a way that just
/// a signature change won't fix.
pub const CREATE_TARGET_SIG: &str = "E8 $ { ' } 41 83 C5 ? 49 8B FC";

fn handle_payload(payload: rpc::Payload, hs: Arc<hook::State>) -> Result<()> {
    let hook_type = match payload.op {
        rpc::MessageOps::Recv => hook::HookType::Recv,
        rpc::MessageOps::Send if payload.ctx == 0 => hook::HookType::SendLobby,
        rpc::MessageOps::Send => hook::HookType::Send,
        _ => return Ok(()),
    };

    let sig_str = String::from_utf8(payload.data).context("Invalid string")?;
    hs.initialize_hook(sig_str, hook_type).map_err(|e| {
        // Errors will be returned to the sender, so we should do the logging here.
        error!("Hook initialization error: {e}");
        format_err!("error initializing hook: {e}")
    })
}

#[rustfmt::skip]
fn initialize_hook_with_sig(hs: &Arc<hook::State>, sig: &str, hook_type: hook::HookType) -> bool {
    hs.initialize_hook(sig.into(), hook_type).map_err(|e| {
        error!("Could not auto-initialize the {hook_type} hook: {e}");
    }).is_ok()
}

/// Automatically initialize all the hooks, but do not fatally exit if any
/// fail to initialize.
/// Returns initialization status for Recv, Send, SendLobby hook types
fn auto_initialize_hooks(hs: &Arc<hook::State>) -> (bool, bool, bool, bool) {
    let r = initialize_hook_with_sig(hs, RECV_SIG, hook::HookType::Recv);
    let s = initialize_hook_with_sig(hs, SEND_SIG, hook::HookType::Send);
    let sl = initialize_hook_with_sig(hs, SEND_LOBBY_SIG, hook::HookType::SendLobby);
    let ct = initialize_hook_with_sig(hs, CREATE_TARGET_SIG, hook::HookType::CreateTarget);
    (r, s, sl, ct)
}

#[tokio::main]
async fn main_with_result() -> Result<()> {
    let dirty = if COMMIT_DIRTY == "true" { "(dirty)" } else { "" };
    info!("Starting Deucalion v{VERSION}-{COMMIT_SHA}{dirty}",);
    let hs = Arc::new(hook::State::new().context("error setting up the hook")?);
    let deucalion_server = server::Server::new();
    info!("Attempting to auto-initialize the hooks");
    let (r, s, sl, ct) = auto_initialize_hooks(&hs);
    deucalion_server.set_hook_status(r, s, sl, ct).await;
    info!("Hooks initialized.");

    // Clone references to hook state and server state so that they can
    // be moved into an async task
    let hs_clone = hs.clone();
    let deucalion_server_clone = deucalion_server.clone();

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Message loop that forwards messages from the hooks to the server task
    let msg_loop_handle = tokio::spawn(async move {
        let mut broadcast_rx = hs_clone.broadcast_rx.lock().await;
        loop {
            tokio::select! {
                Some(payload) = broadcast_rx.recv() => {
                    deucalion_server_clone.broadcast(payload).await;
                },
                _ = &mut shutdown_rx => {
                    hs_clone.shutdown();
                    return;
                }
            }
        }
    });

    let pid = unsafe { processthreadsapi::GetCurrentProcessId() };
    let pipe_name = format!(r"\\.\pipe\deucalion-{pid}");

    info!("Starting server on {pipe_name}");
    // Block on server loop
    let hs_clone = hs.clone();
    if let Err(e) = deucalion_server
        .run(pipe_name, true, move |payload: rpc::Payload| {
            handle_payload(payload, hs_clone.clone())
        })
        .await
    {
        error!("Server encountered error running: {e}")
    }

    // Signal the msg loop to exit and shut down the hook
    drop(shutdown_tx);
    info!("Shutting down broadcast loop...");
    msg_loop_handle.await?;
    info!("Shutting down...");
    Ok(())
}

const DLL_PROCESS_ATTACH: u32 = 1;

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(hModule: HINSTANCE, reason: u32, _: u32) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            processthreadsapi::CreateThread(
                0 as LPSECURITY_ATTRIBUTES,
                0,
                Some(main),
                hModule as LPVOID,
                0,
                0 as LPDWORD,
            );
        }
    }
    TRUE
}

fn pause() {
    println!("Press enter to exit...");
    let _ = std::io::stdin().read(&mut [0u8]).unwrap();
}

fn logging_setup() -> Result<()> {
    let secs_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();

    let mut log_path = PathBuf::new();
    log_path.push(dirs::data_dir().context("Data dir not found")?);
    log_path.push("deucalion");
    fs::create_dir_all(log_path.as_path())?;

    log_path.push(format!("session-{secs_since_epoch}.log"));

    let log_file = fs::File::create(log_path.as_path())?;

    #[cfg(debug_assertions)]
    {
        CombinedLogger::init(vec![
            SimpleLogger::new(LevelFilter::Debug, simplelog::Config::default()),
            WriteLogger::new(LevelFilter::Debug, simplelog::Config::default(), log_file),
        ])?;
    }
    #[cfg(not(debug_assertions))]
    {
        WriteLogger::init(LevelFilter::Info, simplelog::Config::default(), log_file)?;
    }

    Ok(())
}

unsafe extern "system" fn main(dll_base_addr: LPVOID) -> u32 {
    unsafe {
        #[cfg(debug_assertions)]
        consoleapi::AllocConsole();
    }

    if let Err(e) = logging_setup() {
        println!("Error initializing logger: {e}");
    }

    let result = std::panic::catch_unwind(|| {
        if let Err(e) = main_with_result() {
            error!("Encountered fatal error: {e}");
            pause();
        }
    });
    if let Err(cause) = result {
        error!("Panic happened: {cause:?}");
        pause();
    }
    if let Err(e) = unsafe { drop_ref_count_to_one(dll_base_addr as HMODULE) } {
        error!("Could not drop ref count to one: {e}")
    }
    info!("Shut down!");
    unsafe {
        #[cfg(debug_assertions)]
        wincon::FreeConsole();
        libloaderapi::FreeLibraryAndExitThread(dll_base_addr as HMODULE, 0);
    }
    // Exit should happen before here
    0
}
