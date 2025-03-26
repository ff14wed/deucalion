use std::sync::Arc;
use std::time::Instant;

use anyhow::{format_err, Context, Result};
use thiserror::Error;

use tokio::sync::{mpsc, Mutex};

use pelite::{pattern, pe::PeView, ImageMap};

use log::info;
use strum_macros::Display;

use crate::procloader::{find_pattern_matches, get_ffxiv_filepath};
use crate::rpc;

mod packet;
mod recv;
mod send;
mod send_lobby;
mod waitgroup;

pub struct State {
    recv_hook: recv::Hook,
    send_hook: send::Hook,
    send_lobby_hook: send_lobby::Hook,
    wg: waitgroup::WaitGroup,
    pub broadcast_rx: Arc<Mutex<mpsc::UnboundedReceiver<rpc::Payload>>>,
}

#[derive(Display, Clone, Copy)]
pub enum HookType {
    Recv,
    Send,
    SendLobby,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
enum Channel {
    Lobby,
    Zone,
    Chat,
}

#[derive(Debug, Error)]
enum HookError {
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
            send_lobby_hook: send_lobby::Hook::new(broadcast_tx, wg.clone())?,
            wg,
            broadcast_rx: Arc::new(Mutex::new(broadcast_rx)),
        };
        Ok(hs)
    }

    pub fn initialize_hook(&self, sig_str: String, hook_type: HookType) -> Result<()> {
        let pat = pattern::parse(&sig_str).context(format!("Invalid signature: \"{sig_str}\""))?;
        let sig: &[pattern::Atom] = &pat;
        let ffxiv_file_path = get_ffxiv_filepath()?;

        let image_map = ImageMap::open(&ffxiv_file_path).unwrap();
        let pe_image = PeView::from_bytes(image_map.as_ref())?;

        let sig_name = match hook_type {
            HookType::Recv => "RecvPacket",
            HookType::Send => "SendPacket",
            HookType::SendLobby => "SendLobbyPacket",
        };
        info!("Scanning for {sig_name} sig: `{sig_str}`");
        let scan_start = Instant::now();
        let rvas = find_pattern_matches(sig_name, sig, pe_image, true)
            .map_err(|e| format_err!("{}: {}", e, sig_str))?;
        info!("Sig scan took {:?}", scan_start.elapsed());

        match hook_type {
            HookType::Recv => self.recv_hook.setup(rvas),
            HookType::Send => self.send_hook.setup(rvas),
            HookType::SendLobby => self.send_lobby_hook.setup(rvas),
        }
    }

    pub fn shutdown(&self) {
        info!("Shutting down hooks...");
        recv::Hook::shutdown();
        send::Hook::shutdown();
        send_lobby::Hook::shutdown();
        // Wait for any hooks to finish what they're doing
        self.wg.wait();
    }
}
