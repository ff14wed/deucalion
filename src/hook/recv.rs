use std::mem;
use std::sync::Arc;

use anyhow::Result;

use tokio::sync::mpsc;

use once_cell::sync::OnceCell;

use retour;
use retour::static_detour;

use crate::rpc;

use crate::procloader::get_ffxiv_handle;

use super::packet;
use super::waitgroup;
use super::{Channel, HookError};

use log::error;

type HookedFunction = unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize) -> usize;

static_detour! {
    static DecompressPacketChat: unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize) -> usize;
    static DecompressPacketLobby: unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize) -> usize;
    static DecompressPacketZone: unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize) -> usize;
}

#[derive(Clone)]
pub struct Hook {
    data_tx: mpsc::UnboundedSender<rpc::Payload>,

    chat_hook: Arc<OnceCell<&'static retour::StaticDetour<HookedFunction>>>,
    lobby_hook: Arc<OnceCell<&'static retour::StaticDetour<HookedFunction>>>,
    zone_hook: Arc<OnceCell<&'static retour::StaticDetour<HookedFunction>>>,

    wg: waitgroup::WaitGroup,
}

impl Hook {
    pub fn new(
        data_tx: mpsc::UnboundedSender<rpc::Payload>,
        wg: waitgroup::WaitGroup,
    ) -> Result<Hook> {
        Ok(Hook {
            data_tx,
            chat_hook: Arc::new(OnceCell::new()),
            lobby_hook: Arc::new(OnceCell::new()),
            zone_hook: Arc::new(OnceCell::new()),
            wg,
        })
    }

    pub fn setup(&self, rvas: Vec<usize>) -> Result<()> {
        if rvas.len() != 3 {
            return Err(HookError::SignatureMatchFailed(rvas.len(), 3).into());
        }
        let mut ptrs: Vec<*const u8> = Vec::new();
        for rva in rvas {
            ptrs.push(get_ffxiv_handle()?.wrapping_offset(rva as isize));
        }

        let self_clone = self.clone();
        let chat_hook = unsafe {
            let ptr_fn: HookedFunction = mem::transmute(ptrs[0] as *const ());
            DecompressPacketChat.initialize(ptr_fn, move |a, b, c, d, e| {
                self_clone.recv_packet(Channel::Chat, a, b, c, d, e)
            })?
        };
        if let Err(_) = self.chat_hook.set(chat_hook) {
            return Err(HookError::SetupFailed(Channel::Chat).into());
        }

        let self_clone = self.clone();
        let lobby_hook = unsafe {
            let ptr_fn: HookedFunction = mem::transmute(ptrs[1] as *const ());
            DecompressPacketLobby.initialize(ptr_fn, move |a, b, c, d, e| {
                self_clone.recv_packet(Channel::Lobby, a, b, c, d, e)
            })?
        };
        if let Err(_) = self.lobby_hook.set(lobby_hook) {
            return Err(HookError::SetupFailed(Channel::Lobby).into());
        }

        let self_clone = self.clone();
        let zone_hook = unsafe {
            let ptr_fn: HookedFunction = mem::transmute(ptrs[2] as *const ());
            DecompressPacketZone.initialize(ptr_fn, move |a, b, c, d, e| {
                self_clone.recv_packet(Channel::Zone, a, b, c, d, e)
            })?
        };
        if let Err(_) = self.zone_hook.set(zone_hook) {
            return Err(HookError::SetupFailed(Channel::Zone).into());
        }

        unsafe {
            self.chat_hook.get_unchecked().enable()?;
            self.lobby_hook.get_unchecked().enable()?;
            self.zone_hook.get_unchecked().enable()?;
        }
        Ok(())
    }

    unsafe fn recv_packet(
        &self,
        channel: Channel,
        a1: *const u8,
        a2: *const u8,
        a3: usize,
        a4: usize,
        a5: usize,
    ) -> usize {
        let _guard = self.wg.add();

        const INVALID_MSG: &str = "Hook function was called without a valid hook";
        let hook = match channel {
            Channel::Chat => self.chat_hook.clone(),
            Channel::Lobby => self.lobby_hook.clone(),
            Channel::Zone => self.zone_hook.clone(),
        };
        let ret = hook.get().expect(INVALID_MSG).call(a1, a2, a3, a4, a5);

        let ptr_frame: *const u8 = *(a1.add(16) as *const usize) as *const u8;
        let offset: u32 = *(a1.add(28) as *const u32);
        if offset != 0 {
            return ret;
        }

        match packet::extract_packets_from_frame(ptr_frame) {
            Ok(packets) => {
                for packet in packets {
                    let payload = match packet {
                        packet::Packet::IPC(data) => rpc::Payload {
                            op: rpc::MessageOps::Recv,
                            ctx: channel as u32,
                            data,
                        },
                        packet::Packet::Other(data) => rpc::Payload {
                            op: rpc::MessageOps::RecvOther,
                            ctx: channel as u32,
                            data,
                        },
                    };
                    let _ = self.data_tx.send(payload);
                }
            }
            Err(e) => {
                error!("Could not process packet: {}", e)
            }
        }

        return ret;
    }

    pub fn shutdown(&self) {
        unsafe {
            if let Some(hook) = self.lobby_hook.get() {
                let _ = hook.disable();
            };
            if let Some(hook) = self.chat_hook.get() {
                let _ = hook.disable();
            };
            if let Some(hook) = self.zone_hook.get() {
                let _ = hook.disable();
            };
        }
    }
}
