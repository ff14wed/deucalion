use std::{
    mem,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::Result;

use tokio::sync::mpsc;

use retour::{static_detour, StaticDetour};

use crate::rpc;

use crate::procloader::get_ffxiv_handle;

use super::{packet, waitgroup, Channel, HookError};

use log::error;

type HookedFunction = unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize) -> usize;
type StaticHook = StaticDetour<HookedFunction>;

static_detour! {
    static DecompressPacketChat: unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize) -> usize;
    static DecompressPacketLobby: unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize) -> usize;
    static DecompressPacketZone: unsafe extern "system" fn(*const u8, *const u8, usize, usize, usize) -> usize;
}

#[derive(Clone)]
pub struct Hook {
    data_tx: mpsc::UnboundedSender<rpc::Payload>,
    deobf_queue_tx: crossbeam_channel::Sender<packet::Packet>,
    create_target_hook_enabled: Arc<AtomicBool>,
    wg: waitgroup::WaitGroup,
}

impl Hook {
    pub fn new(
        data_tx: mpsc::UnboundedSender<rpc::Payload>,
        deobf_queue_tx: crossbeam_channel::Sender<packet::Packet>,
        wg: waitgroup::WaitGroup,
    ) -> Result<Hook> {
        Ok(Hook {
            data_tx,
            deobf_queue_tx,
            create_target_hook_enabled: Arc::new(AtomicBool::new(false)),
            wg,
        })
    }

    pub fn set_create_target_hook_enabled(&self, enabled: bool) {
        self.create_target_hook_enabled
            .store(enabled, Ordering::SeqCst);
    }

    pub fn setup(&self, rvas: Vec<usize>) -> Result<()> {
        if rvas.len() != 3 {
            return Err(HookError::SignatureMatchFailed(rvas.len(), 3).into());
        }
        let mut ptrs: Vec<*const u8> = Vec::new();
        for rva in rvas {
            ptrs.push(get_ffxiv_handle()?.wrapping_add(rva));
        }

        unsafe {
            self.setup_hook(&DecompressPacketChat, Channel::Chat, ptrs[0])?;
            self.setup_hook(&DecompressPacketLobby, Channel::Lobby, ptrs[1])?;
            self.setup_hook(&DecompressPacketZone, Channel::Zone, ptrs[2])?;

            DecompressPacketChat.enable()?;
            DecompressPacketLobby.enable()?;
            DecompressPacketZone.enable()?;
        }

        Ok(())
    }

    unsafe fn setup_hook(&self, hook: &StaticHook, channel: Channel, rva: *const u8) -> Result<()> {
        let self_clone = self.clone();
        let ptr_fn: HookedFunction = mem::transmute(rva as *const ());
        hook.initialize(ptr_fn, move |a, b, c, d, e| {
            self_clone.recv_packet(channel, a, b, c, d, e)
        })?;
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

        let hook = match channel {
            Channel::Chat => &DecompressPacketChat,
            Channel::Lobby => &DecompressPacketLobby,
            Channel::Zone => &DecompressPacketZone,
        };
        let ret = hook.call(a1, a2, a3, a4, a5);

        let ptr_frame: *const u8 = *(a1.add(16) as *const usize) as *const u8;
        let offset: u32 = *(a1.add(28) as *const u32);
        if offset != 0 {
            return ret;
        }

        let require_deobfuscation = if let Channel::Zone = channel {
            self.create_target_hook_enabled.load(Ordering::SeqCst)
        } else {
            false
        };

        match packet::extract_packets_from_frame(ptr_frame, require_deobfuscation) {
            Ok(packets) => {
                for packet in packets {
                    match packet {
                        packet::Packet::Ipc(data) => {
                            let _ = self.data_tx.send(rpc::Payload {
                                op: rpc::MessageOps::Recv,
                                ctx: channel as u32,
                                data,
                            });
                        }
                        packet::Packet::ObfuscatedIpc { .. } => {
                            let _ = self.deobf_queue_tx.send(packet);
                        }
                        packet::Packet::Other(data) => {
                            let _ = self.data_tx.send(rpc::Payload {
                                op: rpc::MessageOps::RecvOther,
                                ctx: channel as u32,
                                data,
                            });
                        }
                    };
                }
            }
            Err(e) => {
                error!("Could not process packet: {e}")
            }
        }

        ret
    }

    pub fn shutdown() {
        if let Err(e) = unsafe { DecompressPacketChat.disable() } {
            error!("Error disabling RecvChat hook: {e}");
        };
        if let Err(e) = unsafe { DecompressPacketLobby.disable() } {
            error!("Error disabling RecvLobby hook: {e}");
        };
        if let Err(e) = unsafe { DecompressPacketZone.disable() } {
            error!("Error disabling RecvZone hook: {e}");
        };
    }
}
