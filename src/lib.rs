use std::fs::{self, File};
use std::io::{self, Read};
use std::panic;
use std::path::PathBuf;
use std::time::SystemTime;

use simplelog::{self, LevelFilter, WriteLogger};
#[cfg(windows)]
use winapi::shared::minwindef::*;
use winapi::um::libloaderapi;
use winapi::um::minwinbase::*;
use winapi::um::processthreadsapi;

#[cfg(debug_assertions)]
use winapi::um::consoleapi;
#[cfg(debug_assertions)]
use winapi::um::wincon;

use std::sync::Arc;

use anyhow::{format_err, Context, Result};

use tokio::select;
use tokio::sync::{mpsc, oneshot, Mutex};

use dirs;

mod hook;

pub mod namedpipe;
pub mod procloader;
pub mod rpc;

mod server;

use log::{error, info};

#[cfg(debug_assertions)]
use simplelog::{CombinedLogger, SimpleLogger};

const RECV_HOOK_SIG: &str = "E8 $ { ' } 4C 8B 43 10 41 8B 40 18";
const SEND_HOOK_SIG: &str = "E8 $ { ' } 8B 53 2C 48 8D 8B";

fn handle_payload(payload: rpc::Payload, hs: Arc<hook::State>) -> Result<()> {
    info!("Received payload from subscriber: {:?}", payload);
    if payload.op == rpc::MessageOps::Recv || payload.op == rpc::MessageOps::Send {
        let direction = match payload.op {
            rpc::MessageOps::Recv => hook::Direction::Recv,
            rpc::MessageOps::Send => hook::Direction::Send,
            _ => panic!("This case shouldn't be possible"),
        };
        if let Err(e) = parse_sig_and_initialize_hook(hs, payload.data, direction) {
            let err = format_err!("error initializing hook: {:?}", e);
            error!("{:?}", err);
            return Err(err);
        }
    }
    Ok(())
}

fn parse_sig_and_initialize_hook(
    hs: Arc<hook::State>,
    data: Vec<u8>,
    direction: hook::Direction,
) -> Result<()> {
    let sig_str = String::from_utf8(data).context("Invalid string")?;
    hs.initialize_hook(sig_str, direction)
}

#[tokio::main]
async fn main_with_result() -> Result<()> {
    let hs = Arc::new(hook::State::new().context("error setting up the hook")?);

    let (signal_tx, signal_rx) = mpsc::channel(1);
    let state = Arc::new(Mutex::new(server::Shared::new(signal_tx)));

    info!("Attempting to auto-initialize the hooks");

    let initialized_recv = {
        if let Err(e) = hs.initialize_hook(RECV_HOOK_SIG.into(), hook::Direction::Recv) {
            error!("Could not auto-initialize the recv hook: {}", e);
            false
        } else {
            true
        }
    };

    let initialized_send = {
        if let Err(e) = hs.initialize_hook(SEND_HOOK_SIG.into(), hook::Direction::Send) {
            error!("Could not auto-initialize the send hook: {}", e);
            false
        } else {
            true
        }
    };

    {
        let mut s = state.lock().await;
        s.set_recv_state(initialized_recv);
        s.set_send_state(initialized_send);
    }

    info!("Hooks initialized.");

    // Message loop that forwards messages from the hooks to the server task
    let hs_clone = hs.clone();
    let state_clone = state.clone();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let msg_loop_handle = tokio::spawn(async move {
        loop {
            let mut broadcast_rx = hs_clone.broadcast_rx.lock().await;
            select! {
                res = broadcast_rx.recv() => {
                    if let Some(payload) = res {
                        state_clone.lock().await.broadcast(payload).await;
                    }
                },
                _ = &mut shutdown_rx => {
                    hs_clone.shutdown();
                    return ();
                }
            }
        }
    });

    let pid = unsafe { processthreadsapi::GetCurrentProcessId() };
    let pipe_name = format!(r"\\.\pipe\deucalion-{}", pid as u32);

    info!("Starting server on {}", pipe_name);
    // Block on server loop
    let hs_clone = hs.clone();
    if let Err(e) = server::run(pipe_name, state, signal_rx, move |payload: rpc::Payload| {
        handle_payload(payload, hs_clone.clone())
    })
    .await
    {
        error!("Server encountered error running: {:?}", e)
    }

    // Signal the msg loop to exit and shut down the hook
    drop(shutdown_tx);
    info!("Hook shutdown initiated...");
    msg_loop_handle.await?;
    info!("Shut down!");
    Ok(())
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(hModule: HINSTANCE, reason: u32, _: u32) -> BOOL {
    if reason == 1 {
        processthreadsapi::CreateThread(
            0 as LPSECURITY_ATTRIBUTES,
            0,
            Some(main),
            hModule as LPVOID,
            0,
            0 as LPDWORD,
        );
    }
    TRUE
}

fn pause() {
    println!("Press enter to exit...");
    let _ = io::stdin().read(&mut [0u8]).unwrap();
}

fn logging_setup() -> Result<()> {
    let secs_since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let mut log_path = PathBuf::new();
    log_path.push(dirs::data_dir().context("Data dir not found")?);
    log_path.push("deucalion");
    fs::create_dir_all(log_path.as_path())?;

    log_path.push(format!("session-{}.log", secs_since_epoch));

    let log_file = File::create(log_path.as_path())?;

    #[cfg(debug_assertions)]
    {
        let _ = CombinedLogger::init(vec![
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
    #[cfg(debug_assertions)]
    consoleapi::AllocConsole();

    if let Err(e) = logging_setup() {
        println!("Error initializing logger: {:?}", e);
    }

    let result = panic::catch_unwind(|| {
        if let Err(e) = main_with_result() {
            error!("Encountered fatal error: {:?}", e);
            pause();
        }
    });
    if let Err(cause) = result {
        error!("Panic happened: {:?}", cause);
        pause();
    }
    #[cfg(debug_assertions)]
    wincon::FreeConsole();
    libloaderapi::FreeLibraryAndExitThread(dll_base_addr as HMODULE, 0);
    // Exit should happen before here
    return 0;
}
