use anyhow::{Result, format_err};
use clap::Parser;
use deucalion::rpc::MessageOps;
use deucalion_client::{
    packet::print_deucalion_segment,
    process,
    subscriber::{BroadcastFilter, Subscriber},
};
use log::{error, info};
use simplelog::{LevelFilter, SimpleLogger};
use tokio::runtime::Runtime;

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    #[arg(default_value = "deucalion.dll", help = "Path to Deucalion DLL")]
    payload: String,

    #[arg(
        short,
        long,
        help = "Specify a different target exe to inject into. e.g. notepad.exe"
    )]
    target_exe: Option<String>,

    #[arg(
        short,
        long,
        help = "Call LoadLibrary even if the target is already injected."
    )]
    force: bool,

    #[arg(
        short,
        long,
        help = "Attempt to eject Deucalion from the target process. MAY CRASH GAME IF DEUCALION IS STILL RUNNING."
    )]
    eject: bool,
}

fn main() -> Result<()> {
    SimpleLogger::init(LevelFilter::Debug, simplelog::Config::default())?;

    let args = Args::parse();

    let payload_path = std::path::Path::new(&args.payload);

    let target_name = match args.target_exe {
        Some(target) => target,
        None => "ffxiv_dx11.exe".into(),
    };

    let pids = process::find_all_pids_by_name(&target_name);
    let pid = match pids.len() {
        0 => return Err(format_err!("Cannot find instance of FFXIV")),
        1 => pids[0],
        _ => {
            info!("Found multiple instances of FFXIV: {pids:?}. Selecting first one.");
            pids[0]
        }
    };

    info!("Selecting pid {pid}");

    if args.eject {
        info!("Ejecting Deucalion from {pid}");
        process::eject_dll(pid, payload_path)?;
        return Ok(());
    }

    info!("Injecting Deucalion into {pid}");

    if !payload_path.exists() {
        return Err(format_err!("Payload {} not found!", &args.payload));
    }

    process::copy_current_process_dacl_to_target(pid)?;
    process::inject_dll(pid, payload_path, args.force)?;

    let subscriber = Subscriber::new();

    let pipe_name = format!(r"\\.\pipe\deucalion-{}", pid as u32);

    let rt = Runtime::new()?;

    rt.block_on(async move {
        if let Err(e) = subscriber
            .listen_forever(
                &pipe_name,
                BroadcastFilter::AllowZoneRecv as u32 | BroadcastFilter::AllowZoneSend as u32,
                move |payload: deucalion::rpc::Payload| {
                    info!("Received payload: {:?} {}", payload.op, payload.ctx);
                    match payload.op {
                        MessageOps::Recv | MessageOps::Send => {
                            if let Err(e) = print_deucalion_segment(&payload.data) {
                                error!("Failed to print Deucalion segment: {e}");
                            }
                        }
                        _ => {
                            info!("Data: {:X?}", payload.data);
                        }
                    }
                    Ok(())
                },
            )
            .await
        {
            error!("Error connecting to Deucalion: {e}");
        }
    });

    Ok(())
}
