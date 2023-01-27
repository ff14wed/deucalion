use std::io::{self, Read};
use std::panic;

use channel::select;
use crossbeam_channel as channel;

#[cfg(windows)]
use winapi::shared::minwindef::*;
use winapi::um::libloaderapi;
use winapi::um::minwinbase::*;
use winapi::um::processthreadsapi;

#[cfg(debug_assertions)]
use winapi::um::consoleapi;
#[cfg(debug_assertions)]
use winapi::um::wincon;

use failure::{Error, ResultExt};

use std::sync::Arc;
use std::thread;

use tokio::runtime;
use tokio::sync::{mpsc, Mutex};

mod hook;
mod procloader;
mod rpc;
mod server;

use log::{debug, error, info};
use simplelog::{self, LevelFilter, SimpleLogger};

fn handle_payload(payload: rpc::Payload) {
    debug!("Received payload: {:?}", payload);
    match payload.op {
        rpc::MessageOps::Debug => {
            debug!("{:?}", payload);
        }
        _ => {}
    };
}

fn main_with_result() -> Result<(), Error> {
    let pid = unsafe { processthreadsapi::GetCurrentProcessId() };
    let pipe_name = format!(r"\\.\pipe\deucalion-{}", pid as u32);

    let (signal_tx, signal_rx) = mpsc::channel(1);
    let state = Arc::new(Mutex::new(server::Shared::new(signal_tx)));
    let mut rt = runtime::Runtime::new()?;

    let msg_loop_state = state.clone();

    info!("Installing hook...");
    let hs = hook::State::new().context("Error setting up the hook")?;
    info!("Installed hook");

    let (shutdown_tx, shutdown_rx) = channel::bounded::<()>(0);
    let msg_thread_handle = thread::spawn(move || {
        match runtime::Builder::new().basic_scheduler().build() {
            Ok(mut msg_loop_rt) => msg_loop_rt.block_on(async {
                loop {
                    select! {
                        recv(hs.broadcast_rx) -> res => {
                            if let Ok(payload) = res {
                                msg_loop_state.lock().await.broadcast(payload).await;
                            }
                        },
                        recv(shutdown_rx) -> _ => {
                            hs.shutdown();
                            return ();
                        }
                    }
                }
            }),
            Err(e) => error!("Error spawning tokio runtime: {:?}", e),
        };
        ()
    });

    rt.block_on(server::run(
        pipe_name,
        state,
        signal_rx,
        move |payload: rpc::Payload| {
            handle_payload(payload);
        },
    ))?;

    drop(shutdown_tx);
    msg_thread_handle.join().unwrap();

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
