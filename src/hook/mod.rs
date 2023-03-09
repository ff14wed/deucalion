use std::fmt::Display;
use std::sync::Arc;

use anyhow::{format_err, Context, Result};
use thiserror::Error;

use tokio::sync::{mpsc, Mutex};

use crate::procloader::{find_pattern_matches, get_ffxiv_filepath};
use pelite::{pattern, pe::PeView, ImageMap};

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

    pub fn initialize_recv_hook(&self, sig_str: String) -> Result<()> {
        let pat =
            pattern::parse(&sig_str).context(format!("Invalid signature: \"{}\"", sig_str))?;
        let sig: &[pattern::Atom] = &pat;
        let ffxiv_file_path = get_ffxiv_filepath()?;

        let image_map = ImageMap::open(&ffxiv_file_path).unwrap();
        let pe_image = PeView::from_bytes(image_map.as_ref())?;

        let rvas = find_pattern_matches("recv::DecompressPacket", sig, pe_image)
            .map_err(|e| format_err!("{}: {}", e, sig_str))?;

        self.recv_hook.setup(rvas)
    }

    pub fn initialize_send_hook(&self, sig_str: String) -> Result<()> {
        let pat =
            pattern::parse(&sig_str).context(format!("Invalid signature: \"{}\"", sig_str))?;
        let sig: &[pattern::Atom] = &pat;
        let ffxiv_file_path = get_ffxiv_filepath()?;

        let image_map = ImageMap::open(&ffxiv_file_path).unwrap();
        let pe_image = PeView::from_bytes(image_map.as_ref())?;

        let rvas = find_pattern_matches("recv::CompressPacket", sig, pe_image)
            .map_err(|e| format_err!("{}: {}", e, sig_str))?;

        self.send_hook.setup(rvas)
    }

    pub fn shutdown(&self) {
        self.recv_hook.shutdown();
        self.send_hook.shutdown();
        // Wait for any hooks to finish what they're doing
        self.wg.wait();
    }
}
