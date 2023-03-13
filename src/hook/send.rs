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

type HookedFunction =
    unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize, usize) -> usize;

static_detour! {
    static CompressPacketChat: unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize, usize) -> usize;
    static CompressPacketZone: unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize, usize) -> usize;
}

#[derive(Clone)]
pub struct Hook {
    data_tx: mpsc::UnboundedSender<rpc::Payload>,

    chat_hook: Arc<OnceCell<&'static retour::StaticDetour<HookedFunction>>>,
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
            zone_hook: Arc::new(OnceCell::new()),
            wg,
        })
    }

    pub fn setup(&self, rvas: Vec<usize>) -> Result<()> {
        if rvas.len() != 2 {
            return Err(HookError::SignatureMatchFailed(rvas.len(), 2).into());
        }
        let mut ptrs: Vec<*const u8> = Vec::new();
        for rva in rvas {
            ptrs.push(get_ffxiv_handle()?.wrapping_offset(rva as isize));
        }

        let self_clone = self.clone();
        let chat_hook = unsafe {
            let ptr_fn: HookedFunction = mem::transmute(ptrs[0] as *const ());
            CompressPacketChat.initialize(ptr_fn, move |a, b, c, d, e, f| {
                self_clone.compress_packet(Channel::Chat, a, b, c, d, e, f)
            })?
        };
        if let Err(_) = self.chat_hook.set(chat_hook) {
            return Err(HookError::SetupFailed(Channel::Chat).into());
        }

        let self_clone = self.clone();
        let zone_hook = unsafe {
            let ptr_fn: HookedFunction = mem::transmute(ptrs[1] as *const ());
            CompressPacketZone.initialize(ptr_fn, move |a, b, c, d, e, f| {
                self_clone.compress_packet(Channel::Zone, a, b, c, d, e, f)
            })?
        };
        if let Err(_) = self.zone_hook.set(zone_hook) {
            return Err(HookError::SetupFailed(Channel::Zone).into());
        }

        unsafe {
            self.chat_hook.get_unchecked().enable()?;
            self.zone_hook.get_unchecked().enable()?;
        }
        Ok(())
    }

    unsafe fn compress_packet(
        &self,
        channel: Channel,
        a1: *const u8,
        a2: *const u8,
        a3: usize,
        a4: usize,
        a5: usize,
        a6: usize,
    ) -> usize {
        let _guard = self.wg.add();

        let ptr_frame: *const u8 = *(a1.add(16) as *const usize) as *const u8;

        match packet::extract_packets_from_frame(ptr_frame) {
            Ok(packets) => {
                for packet in packets {
                    let payload = match packet {
                        packet::Packet::IPC(data) => rpc::Payload {
                            op: rpc::MessageOps::Send,
                            ctx: channel as u32,
                            data,
                        },
                        packet::Packet::Other(data) => rpc::Payload {
                            op: rpc::MessageOps::SendOther,
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

        const INVALID_MSG: &str = "Hook function was called without a valid hook";
        let hook = match channel {
            Channel::Chat => self.chat_hook.clone(),
            Channel::Lobby => panic!("Not implemented."),
            Channel::Zone => self.zone_hook.clone(),
        };
        return hook.get().expect(INVALID_MSG).call(a1, a2, a3, a4, a5, a6);
    }

    pub fn shutdown(&self) {
        unsafe {
            if let Some(hook) = self.chat_hook.get() {
                let _ = hook.disable();
            };
            if let Some(hook) = self.zone_hook.get() {
                let _ = hook.disable();
            };
        }
    }
}
