use std::fmt::Display;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{format_err, Context, Result};
use thiserror::Error;

use tokio::sync::{mpsc, Mutex};

use pelite::{pattern, pe::PeView, ImageMap};

use log::info;

use crate::procloader::{find_pattern_matches, get_ffxiv_filepath};
use crate::rpc;

mod packet;
mod recv;
mod send;
mod waitgroup;

pub struct State {
    recv_hook: recv::Hook,
    send_hook: send::Hook,
    wg: waitgroup::WaitGroup,
    pub broadcast_rx: Arc<Mutex<mpsc::UnboundedReceiver<rpc::Payload>>>,
}

pub enum Direction {
    Recv,
    Send,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub(self) enum Channel {
    Lobby,
    Zone,
    Chat,
}

impl Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        match *self {
            Channel::Lobby => f.write_str("lobby"),
            Channel::Zone => f.write_str("zone"),
            Channel::Chat => f.write_str("chat"),
        }
    }
}

#[derive(Debug, Error)]
pub(self) enum HookError {
    #[error("failed to set up {0} hook")]
    SetupFailed(Channel),
    #[error("number of signature matches is incorrect: {0} != {1}")]
    SignatureMatchFailed(usize, usize),
}

impl State {
    pub fn new() -> Result<State> {
        let (broadcast_tx, broadcast_rx) = mpsc::unbounded_channel::<rpc::Payload>();

        let wg = waitgroup::WaitGroup::new();
        let hs = State {
            recv_hook: recv::Hook::new(broadcast_tx.clone(), wg.clone())?,
            send_hook: send::Hook::new(broadcast_tx.clone(), wg.clone())?,
            wg,
            broadcast_rx: Arc::new(Mutex::new(broadcast_rx)),
        };
        Ok(hs)
    }

    pub fn initialize_hook(&self, sig_str: String, direction: Direction) -> Result<()> {
        let pat =
            pattern::parse(&sig_str).context(format!("Invalid signature: \"{}\"", sig_str))?;
        let sig: &[pattern::Atom] = &pat;
        let ffxiv_file_path = get_ffxiv_filepath()?;

        let image_map = ImageMap::open(&ffxiv_file_path).unwrap();
        let pe_image = PeView::from_bytes(image_map.as_ref())?;

        let sig_name = match direction {
            Direction::Recv => "RecvPacket",
            Direction::Send => "SendPacket",
        };
        info!("Scanning for {} sig: `{}`", sig_name, sig_str);
        let scan_start = Instant::now();
        let rvas = find_pattern_matches(sig_name, sig, pe_image)
            .map_err(|e| format_err!("{}: {}", e, sig_str))?;
        info!("Sig scan took {:?}", scan_start.elapsed());

        match direction {
            Direction::Recv => self.recv_hook.setup(rvas),
            Direction::Send => self.send_hook.setup(rvas),
        }
    }

    pub fn shutdown(&self) {
        self.recv_hook.shutdown();
        self.send_hook.shutdown();
        // Wait for any hooks to finish what they're doing
        self.wg.wait();
    }
}
