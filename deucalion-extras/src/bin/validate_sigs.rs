use std::{env, time::Instant};

use anyhow::{Context, Result, format_err};
use deucalion::{CREATE_TARGET_SIG, RECV_SIG, SEND_LOBBY_SIG, SEND_SIG, procloader};
use log::info;
use pelite::{ImageMap, pattern, pe64::PeView};
use simplelog::{LevelFilter, SimpleLogger};

fn main() {
    SimpleLogger::init(LevelFilter::Debug, simplelog::Config::default()).unwrap();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Missing argument: exe path. Usage: validate_sigs <path_to_ffxiv_exe>");
    }

    let target_exe_path = &args[1];
    let image_map = ImageMap::open(target_exe_path).unwrap();
    for sig in [RECV_SIG, SEND_SIG, SEND_LOBBY_SIG, CREATE_TARGET_SIG] {
        info!("===== Searching for sig {sig} in file {target_exe_path} =====");
        let addrs = scan_sigs(image_map.as_ref(), sig).unwrap();
        if addrs.is_empty() {
            panic!("No matches found for signature {sig} in file {target_exe_path}");
        }
        info!("Found addresses:");
        for addr in addrs {
            info!("{addr:x}");
        }
    }
}

fn scan_sigs(image: &[u8], sig_str: &str) -> Result<Vec<usize>> {
    let start = Instant::now();
    let file = PeView::from_bytes(image)?;
    info!("File load took {:?}", start.elapsed());

    let start = Instant::now();
    let pat = pattern::parse(sig_str).context(format!("Invalid signature: \"{sig_str}\""))?;
    let sig: &[pattern::Atom] = &pat;

    let rvas = procloader::find_pattern_matches("", sig, file, true)
        .map_err(|e| format_err!("{}: {}", e, sig_str))?;

    info!("Pattern search took {:?}", start.elapsed());

    Ok(rvas)
}
