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

type HookedFunction = unsafe extern "system" fn(*const u8) -> usize;

static_detour! {
    static SendLobbyPacket: unsafe extern "system" fn(*const u8) -> usize;
}

#[derive(Clone)]
pub struct Hook {
    data_tx: mpsc::UnboundedSender<rpc::Payload>,

    lobby_hook: Arc<OnceCell<&'static retour::StaticDetour<HookedFunction>>>,

    wg: waitgroup::WaitGroup,
}

impl Hook {
    pub fn new(
        data_tx: mpsc::UnboundedSender<rpc::Payload>,
        wg: waitgroup::WaitGroup,
    ) -> Result<Hook> {
        Ok(Hook {
            data_tx,
            lobby_hook: Arc::new(OnceCell::new()),
            wg,
        })
    }

    pub fn setup(&self, rvas: Vec<usize>) -> Result<()> {
        if rvas.len() != 1 {
            return Err(HookError::SignatureMatchFailed(rvas.len(), 1).into());
        }
        let mut ptrs: Vec<*const u8> = Vec::new();
        for rva in rvas {
            ptrs.push(get_ffxiv_handle()?.wrapping_offset(rva as isize));
        }

        let self_clone = self.clone();
        let lobby_hook = unsafe {
            let ptr_fn: HookedFunction = mem::transmute(ptrs[0] as *const ());
            SendLobbyPacket.initialize(ptr_fn, move |a| self_clone.send_lobby_packet(a))?
        };
        if let Err(_) = self.lobby_hook.set(lobby_hook) {
            return Err(HookError::SetupFailed(Channel::Lobby).into());
        }

        unsafe {
            self.lobby_hook.get_unchecked().enable()?;
        }
        Ok(())
    }

    unsafe fn send_lobby_packet(&self, a1: *const u8) -> usize {
        let _guard = self.wg.add();

        let ptr_frame: *const u8 = *(a1.add(32) as *const usize) as *const u8;

        match packet::extract_packets_from_frame(ptr_frame) {
            Ok(packets) => {
                for packet in packets {
                    let _ = self.data_tx.send(rpc::Payload {
                        op: rpc::MessageOps::Send,
                        ctx: Channel::Lobby as u32,
                        data: packet,
                    });
                }
            }
            Err(e) => {
                error!("Could not process packet: {}", e)
            }
        }

        const INVALID_MSG: &str = "Hook function was called without a valid hook";
        return self.lobby_hook.get().expect(INVALID_MSG).call(a1);
    }

    pub fn shutdown(&self) {
        unsafe {
            if let Some(hook) = self.lobby_hook.get() {
                let _ = hook.disable();
            };
        }
    }
}
