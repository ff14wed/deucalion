use std::mem;

use anyhow::Result;

use tokio::sync::mpsc;

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
        let mut ptrs: Vec<*const u8> = Vec::new();
        for rva in rvas {
            ptrs.push(get_ffxiv_handle()?.wrapping_offset(rva as isize));
        }

        let self_clone = self.clone();
        unsafe {
            let ptr_fn: HookedFunction = mem::transmute(ptrs[0] as *const ());
            SendLobbyPacket.initialize(ptr_fn, move |a| self_clone.send_lobby_packet(a))?;
            SendLobbyPacket.enable()?;
        };
        Ok(())
    }

    unsafe fn send_lobby_packet(&self, a1: *const u8) -> usize {
        let _guard = self.wg.add();

        let ptr_frame: *const u8 = *(a1.add(32) as *const usize) as *const u8;

        match packet::extract_packets_from_frame(ptr_frame) {
            Ok(packets) => {
                for packet in packets {
                    let payload = match packet {
                        packet::Packet::IPC(data) => rpc::Payload {
                            op: rpc::MessageOps::Send,
                            ctx: Channel::Lobby as u32,
                            data,
                        },
                        packet::Packet::Other(data) => rpc::Payload {
                            op: rpc::MessageOps::SendOther,
                            ctx: Channel::Lobby as u32,
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

        return SendLobbyPacket.call(a1);
    }

    pub fn shutdown() {
        unsafe {
            if let Err(e) = SendLobbyPacket.disable() {
                error!("Error disabling SendLobby hook: {}", e);
            }
        }
    }
}
