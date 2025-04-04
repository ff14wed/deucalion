use std::{sync::Arc, time::Instant};

use anyhow::{Context, Result, format_err};
use log::info;
use pelite::{ImageMap, pattern, pe::PeView};
use strum_macros::Display;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};

use crate::{
    procloader::{find_pattern_matches, get_ffxiv_filepath},
    rpc,
};

mod create_target;
mod packet;
mod recv;
mod send;
mod send_lobby;
mod waitgroup;

pub struct State {
    recv_hook: recv::Hook,
    send_hook: send::Hook,
    send_lobby_hook: send_lobby::Hook,
    create_target_hook: create_target::Hook,
    wg: waitgroup::WaitGroup,
    pub broadcast_rx: Arc<Mutex<mpsc::UnboundedReceiver<rpc::Payload>>>,
}

#[derive(Display, Clone, Copy)]
pub enum HookType {
    Recv,
    Send,
    SendLobby,
    CreateTarget,
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
    #[error("enabled detour encountered uninitialized state")]
    NotInitialized,
    #[error("detour already initialized")]
    AlreadyInitialized,
}

impl State {
    pub fn new() -> Result<State> {
        let (broadcast_tx, broadcast_rx) = mpsc::unbounded_channel::<rpc::Payload>();
        let (deobf_queue_tx, deobf_queue_rx) = crossbeam_channel::unbounded::<packet::Packet>();

        let wg = waitgroup::WaitGroup::new();
        let hs = State {
            recv_hook: recv::Hook::new(
                broadcast_tx.clone(),
                deobf_queue_tx,
                deobf_queue_rx.clone(),
                wg.clone(),
            )?,
            send_hook: send::Hook::new(broadcast_tx.clone(), wg.clone())?,
            send_lobby_hook: send_lobby::Hook::new(broadcast_tx.clone(), wg.clone())?,
            create_target_hook: create_target::Hook::new(broadcast_tx, deobf_queue_rx, wg.clone())?,
            wg,
            broadcast_rx: Arc::new(Mutex::new(broadcast_rx)),
        };
        Ok(hs)
    }

    pub fn initialize_hook(&self, sig_str: String, hook_type: HookType) -> Result<()> {
        let pat = pattern::parse(&sig_str).context(format!("Invalid signature: \"{sig_str}\""))?;
        let sig: &[pattern::Atom] = &pat;
        let ffxiv_file_path = get_ffxiv_filepath()?;

        let image_map = ImageMap::open(&ffxiv_file_path)?;
        let pe_image = PeView::from_bytes(image_map.as_ref())?;

        let sig_name = match hook_type {
            HookType::Recv => "RecvPacket",
            HookType::Send => "SendPacket",
            HookType::SendLobby => "SendLobbyPacket",
            HookType::CreateTarget => "CreateTarget",
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
            HookType::CreateTarget => {
                info!("Scanning for {sig_name} caller: `{sig_str}`");
                let scan_start = Instant::now();
                let parent_rvas = find_pattern_matches(sig_name, sig, pe_image, false)
                    .map_err(|e| format_err!("{}: {}", e, sig_str))?;
                if parent_rvas.len() != 1 {
                    return Err(HookError::SignatureMatchFailed(parent_rvas.len(), 1).into());
                }
                info!("Sig scan took {:?}", scan_start.elapsed());
                self.create_target_hook.setup(parent_rvas[0], rvas)?;
                self.recv_hook.set_create_target_hook_enabled(true);
                Ok(())
            }
        }
    }

    pub fn shutdown(&self) {
        info!("Shutting down hooks...");
        recv::Hook::shutdown();
        send::Hook::shutdown();
        send_lobby::Hook::shutdown();
        create_target::Hook::shutdown();
        // Wait for any hooks to finish what they're doing
        self.wg.wait();
    }
}
