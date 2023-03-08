use std::fmt::Display;
use std::sync::Arc;

use anyhow::{format_err, Context, Result};
use thiserror::Error;

use tokio::sync::{mpsc, Mutex};

use crate::procloader::{find_pattern_matches, get_ffxiv_handle};
use pelite::pattern;
use pelite::pe::PeView;

use crate::rpc;

mod packet;
mod recv;
mod waitgroup;

pub struct State {
    recv_hook: recv::Hook,
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
}

impl State {
    pub fn new() -> Result<State> {
        let (broadcast_tx, broadcast_rx) = mpsc::unbounded_channel::<rpc::Payload>();

        let wg = waitgroup::WaitGroup::new();
        let hs = State {
            recv_hook: recv::Hook::new(broadcast_tx.clone(), wg.clone())?,
            wg,
            broadcast_rx: Arc::new(Mutex::new(broadcast_rx)),
        };
        Ok(hs)
    }

    pub fn initialize_recv_hook(&self, sig_str: String) -> Result<()> {
        let pat =
            pattern::parse(&sig_str).context(format!("Invalid signature: \"{}\"", sig_str))?;
        let sig: &[pattern::Atom] = &pat;
        let handle_ffxiv = get_ffxiv_handle()?;
        let pe_view = unsafe { PeView::module(handle_ffxiv) };

        let decompresspacket_rvas = find_pattern_matches("recv::DecompressPacket", sig, pe_view)
            .map_err(|e| format_err!("{}: {}", e, sig_str))?;

        self.recv_hook.setup(decompresspacket_rvas)
    }

    pub fn shutdown(&self) {
        self.recv_hook.shutdown();
        // Wait for any hooks to finish what they're doing
        self.wg.wait();
    }
}
