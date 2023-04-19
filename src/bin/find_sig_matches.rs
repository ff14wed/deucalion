use deucalion::procloader;
use pelite::pe64::PeView;
use pelite::{pattern, ImageMap};
use std::{env, time::Instant};

use anyhow::{format_err, Context, Result};

use log::info;
use simplelog::{self, LevelFilter, SimpleLogger};

fn main() {
    SimpleLogger::init(LevelFilter::Debug, simplelog::Config::default()).unwrap();

    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("2 positional args are required. See usage in the README.")
    }

    let target_exe_path = &args[1];
    let sig = &args[2];
    info!("Searching for sig {sig} in file {target_exe_path}");

    let image_map = ImageMap::open(target_exe_path).unwrap();
    let addrs = scan_sigs(image_map.as_ref(), sig).unwrap();
    info!("Found addresses:");
    for addr in addrs {
        info!("{addr:x}");
    }
}

fn scan_sigs(image: &[u8], sig_str: &str) -> Result<Vec<usize>> {
    let start = Instant::now();
    let file = PeView::from_bytes(image)?;
    info!("File load took {:?}", start.elapsed());

    let start = Instant::now();
    let pat = pattern::parse(sig_str).context(format!("Invalid signature: \"{sig_str}\""))?;
    let sig: &[pattern::Atom] = &pat;

    let rvas = procloader::find_pattern_matches("", sig, file)
        .map_err(|e| format_err!("{}: {}", e, sig_str))?;

    info!("Pattern search took {:?}", start.elapsed());

    Ok(rvas)
}
