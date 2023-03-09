use std::io::{self, Read};
use std::panic;

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

mod hook;
mod namedpipe;
mod rpc;
mod server;

pub mod procloader;

use log::{debug, error, info};
use simplelog::{self, LevelFilter, SimpleLogger};

const RECV_HOOK_SIG: &str = "E8 $ { ' } 4C 8B 43 10 41 8B 40 18";

fn handle_payload(payload: rpc::Payload, hs: Arc<hook::State>) -> Result<()> {
    debug!("Received payload: {:?}", payload);
    match payload.op {
        rpc::MessageOps::Debug => {
            debug!("{:?}", payload);
        }
        rpc::MessageOps::Recv => {
            if let Err(e) = parse_sig_and_initialize_hook(hs, payload.data) {
                let err = format_err!("error initializing hook: {:?}", e);
                debug!("{:?}", err);
                return Err(err);
            }
        }
        _ => {}
    };
    Ok(())
}

fn parse_sig_and_initialize_hook(hs: Arc<hook::State>, data: Vec<u8>) -> Result<()> {
    let sig_str = String::from_utf8(data).context("Invalid string")?;
    hs.initialize_recv_hook(sig_str)
}

#[tokio::main]
async fn main_with_result() -> Result<()> {
    let hs = Arc::new(hook::State::new().context("error setting up the hook")?);

    let (signal_tx, signal_rx) = mpsc::channel(1);
    let state = Arc::new(Mutex::new(server::Shared::new(signal_tx)));

    // Asynchronously attempt to initialize the hooks
    let hs_clone = hs.clone();
    let state_clone = state.clone();
    tokio::spawn(async move {
        let initialized_recv = {
            if let Err(e) = hs_clone.initialize_recv_hook(RECV_HOOK_SIG.into()) {
                debug!("Could not auto-initialize the recv hook: {}", e);
                false
            } else {
                true
            }
        };

        let mut s = state_clone.lock().await;
        s.set_recv_state(initialized_recv);
        s.set_send_state(false);
    });

    // Message loop that forwards messages from the hooks to the server task
    let hs_clone = hs.clone();
    let state_clone = state.clone();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let msg_loop_future = tokio::spawn(async move {
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
    msg_loop_future.await?;

    info!("Hook shutdown initiated...");
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

unsafe extern "system" fn main(dll_base_addr: LPVOID) -> u32 {
    #[cfg(debug_assertions)]
    {
        consoleapi::AllocConsole();
        if let Err(e) = SimpleLogger::init(LevelFilter::Debug, simplelog::Config::default()) {
            println!("Error initializing logger: {:?}", e);
        }
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
