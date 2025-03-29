use std::mem;

use anyhow::Result;

use tokio::sync::mpsc;

use retour::{static_detour, StaticDetour};

use crate::rpc;

use crate::procloader::get_ffxiv_handle;

use super::packet;
use super::waitgroup;
use super::{Channel, HookError};

use log::error;

type HookedFunction = unsafe extern "system" fn(*const u8) -> usize;
type StaticHook = StaticDetour<HookedFunction>;

static_detour! {
    static SendLobbyPacket: unsafe extern "system" fn(*const u8) -> usize;
}

#[derive(Clone)]
pub struct Hook {
    data_tx: mpsc::UnboundedSender<rpc::Payload>,
    wg: waitgroup::WaitGroup,
}

impl Hook {
    pub fn new(
        data_tx: mpsc::UnboundedSender<rpc::Payload>,
        wg: waitgroup::WaitGroup,
    ) -> Result<Hook> {
        Ok(Hook { data_tx, wg })
    }

    pub fn setup(&self, rvas: Vec<usize>) -> Result<()> {
        if rvas.len() != 1 {
            return Err(HookError::SignatureMatchFailed(rvas.len(), 1).into());
        }

        let ptr = get_ffxiv_handle()?.wrapping_add(rvas[0]);
        unsafe {
            self.setup_hook(&SendLobbyPacket, ptr)?;
            SendLobbyPacket.enable()?;
        };

        Ok(())
    }

    unsafe fn setup_hook(&self, hook: &StaticHook, rva: *const u8) -> Result<()> {
        let self_clone = self.clone();
        let ptr_fn: HookedFunction = mem::transmute(rva as *const ());
        hook.initialize(ptr_fn, move |a| self_clone.send_lobby_packet(a))?;
        Ok(())
    }

    unsafe fn send_lobby_packet(&self, a1: *const u8) -> usize {
        let _guard = self.wg.add();

        let ptr_frame: *const u8 = *(a1.add(32) as *const usize) as *const u8;

        match packet::extract_packets_from_frame(ptr_frame, false) {
            Ok(packets) => {
                for packet in packets {
                    let payload = match packet {
                        packet::Packet::Ipc(data) => rpc::Payload {
                            op: rpc::MessageOps::Send,
                            ctx: Channel::Lobby as u32,
                            data,
                        },
                        packet::Packet::Other(data) => rpc::Payload {
                            op: rpc::MessageOps::SendOther,
                            ctx: Channel::Lobby as u32,
                            data,
                        },
                        _ => unreachable!("This should never send obfuscated packets"),
                    };
                    let _ = self.data_tx.send(payload);
                }
            }
            Err(e) => {
                error!("Could not process packet: {e}")
            }
        }

        SendLobbyPacket.call(a1)
    }

    pub fn shutdown() {
        if let Err(e) = unsafe { SendLobbyPacket.disable() } {
            error!("Error disabling SendLobby hook: {e}");
        }
    }
}
