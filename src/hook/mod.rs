use std::sync::Arc;

use anyhow::{format_err, Context, Result};

use tokio::sync::{mpsc, Mutex};

use crate::procloader::{get_ffxiv_handle, sig_scan_helper};
use pelite::pattern;
use pelite::pe::PeView;

use crate::rpc;

mod recvzonepacket;
mod waitgroup;

pub struct State {
    rzp_hook: recvzonepacket::Hook,
    wg: waitgroup::WaitGroup,
    pub broadcast_rx: Arc<Mutex<mpsc::UnboundedReceiver<rpc::Payload>>>,
}

impl State {
    pub fn new() -> Result<State> {
        let (broadcast_tx, broadcast_rx) = mpsc::unbounded_channel::<rpc::Payload>();

        let wg = waitgroup::WaitGroup::new();
        let hs = State {
            rzp_hook: recvzonepacket::Hook::new(broadcast_tx.clone(), wg.clone())?,
            wg,
            broadcast_rx: Arc::new(Mutex::new(broadcast_rx)),
        };
        Ok(hs)
    }

    pub fn initialize_recv_zone_hook(&self, sig_str: String) -> Result<()> {
        let pat =
            pattern::parse(&sig_str).context(format!("Invalid signature: \"{}\"", sig_str))?;
        let sig: &[pattern::Atom] = &pat;
        let handle_ffxiv = get_ffxiv_handle()?;
        let pe_view = unsafe { PeView::module(handle_ffxiv) };

        let recvzonepacket_rva = sig_scan_helper("RecvZonePacket", sig, pe_view, 8)
            .map_err(|e| format_err!("{}: {}", e, sig_str))?;

        self.rzp_hook.setup(recvzonepacket_rva)
    }

    pub fn shutdown(&self) {
        self.rzp_hook.shutdown();
        // Wait for any hooks to finish what they're doing
        self.wg.wait();
    }
}
