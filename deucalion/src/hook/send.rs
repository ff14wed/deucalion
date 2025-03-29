use std::mem;

use anyhow::Result;
use log::error;
use retour::{StaticDetour, static_detour};
use tokio::sync::mpsc;

use super::{Channel, HookError, packet, waitgroup};
use crate::{procloader::get_ffxiv_handle, rpc};

type HookedFunction = unsafe extern "system" fn(*const u8, usize) -> usize;
type StaticHook = StaticDetour<HookedFunction>;

static_detour! {
    static CompressPacketChat: unsafe extern "system" fn(*const u8, usize) -> usize;
    static CompressPacketZone: unsafe extern "system" fn(*const u8, usize) -> usize;
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
        if rvas.len() != 2 {
            return Err(HookError::SignatureMatchFailed(rvas.len(), 2).into());
        }
        let mut ptrs = Vec::<*const u8>::new();
        for rva in rvas {
            ptrs.push(get_ffxiv_handle()?.wrapping_add(rva));
        }

        unsafe {
            self.setup_hook(&CompressPacketChat, Channel::Chat, ptrs[0])?;
            self.setup_hook(&CompressPacketZone, Channel::Zone, ptrs[1])?;

            CompressPacketChat.enable()?;
            CompressPacketZone.enable()?;
        }
        Ok(())
    }

    unsafe fn setup_hook(&self, hook: &StaticHook, channel: Channel, rva: *const u8) -> Result<()> {
        let self_clone = self.clone();
        let ptr_fn: HookedFunction = mem::transmute(rva as *const ());
        hook.initialize(ptr_fn, move |a, b| {
            self_clone.compress_packet(channel, a, b)
        })?;
        Ok(())
    }

    unsafe fn compress_packet(&self, channel: Channel, a1: *const u8, a2: usize) -> usize {
        let _guard = self.wg.add();

        let ptr_frame: *const u8 = *(a1.add(32) as *const usize) as *const u8;

        match packet::extract_packets_from_frame(ptr_frame, false) {
            Ok(packets) => {
                for packet in packets {
                    let payload = match packet {
                        packet::Packet::Ipc(data) => {
                            rpc::Payload { op: rpc::MessageOps::Send, ctx: channel as u32, data }
                        }
                        packet::Packet::Other(data) => rpc::Payload {
                            op: rpc::MessageOps::SendOther,
                            ctx: channel as u32,
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

        let hook = match channel {
            Channel::Chat => &CompressPacketChat,
            Channel::Lobby => unreachable!("This hook is not implemented for lobby"),
            Channel::Zone => &CompressPacketZone,
        };
        hook.call(a1, a2)
    }

    pub fn shutdown() {
        if let Err(e) = unsafe { CompressPacketChat.disable() } {
            error!("Error disabling SendChat hook: {e}");
        }
        if let Err(e) = unsafe { CompressPacketZone.disable() } {
            error!("Error disabling SendZone hook: {e}");
        }
    }
}
