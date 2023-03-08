use deucalion::procloader;
use pelite::pe64::PeView;
use pelite::{pattern, ImageMap};
use std::{env, time::Instant};

use anyhow::{format_err, Context, Result};

fn main() {
    let args: Vec<String> = env::args().collect();
    let target_exe_path = &args[1];
    let sig = &args[2];
    println!("Searching for sig {} in file {}", sig, target_exe_path);

    let image_map = ImageMap::open(target_exe_path).unwrap();
    let addrs = scan_sigs(image_map.as_ref(), &sig).unwrap();
    println!("Found addresses:");
    for addr in addrs {
        println!("{:x}", addr);
    }
}

fn scan_sigs(image: &[u8], sig_str: &String) -> Result<Vec<usize>> {
    let start = Instant::now();
    let file = PeView::from_bytes(image)?;
    println!("File load took {:?}", start.elapsed());

    let start = Instant::now();
    let pat = pattern::parse(sig_str).context(format!("Invalid signature: \"{}\"", sig_str))?;
    let sig: &[pattern::Atom] = &pat;

    let rvas = procloader::find_pattern_matches("", sig, file)
        .map_err(|e| format_err!("{}: {}", e, sig_str))?;

    println!("Pattern search took {:?}", start.elapsed());

    Ok(rvas)
}
