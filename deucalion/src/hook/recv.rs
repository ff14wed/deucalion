use std::{
    mem,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Result;
use log::{error, warn};
use retour::{StaticDetour, static_detour};
use tokio::sync::mpsc;

use super::{Channel, HookError, packet, waitgroup};
use crate::{procloader::get_ffxiv_handle, rpc};

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
    deobf_queue_rx: crossbeam_channel::Receiver<packet::Packet>,
    create_target_hook_enabled: Arc<AtomicBool>,
    wg: waitgroup::WaitGroup,
}

impl Hook {
    pub fn new(
        data_tx: mpsc::UnboundedSender<rpc::Payload>,
        deobf_queue_tx: crossbeam_channel::Sender<packet::Packet>,
        deobf_queue_rx: crossbeam_channel::Receiver<packet::Packet>,
        wg: waitgroup::WaitGroup,
    ) -> Result<Hook> {
        Ok(Hook {
            data_tx,
            deobf_queue_tx,
            deobf_queue_rx,
            create_target_hook_enabled: Arc::new(AtomicBool::new(false)),
            wg,
        })
    }

    pub fn set_create_target_hook_enabled(&self, enabled: bool) {
        self.create_target_hook_enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn setup(&self, rvas: Vec<usize>) -> Result<()> {
        if rvas.len() != 3 {
            return Err(HookError::SignatureMatchFailed(rvas.len(), 3).into());
        }
        let mut ptrs = Vec::<*const u8>::new();
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
        let ptr_fn: HookedFunction = unsafe { mem::transmute(rva as *const ()) };
        unsafe {
            hook.initialize(ptr_fn, move |a, b, c, d, e| {
                self_clone.recv_packet(channel, a, b, c, d, e)
            })?;
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

        let hook = match channel {
            Channel::Chat => &DecompressPacketChat,
            Channel::Lobby => &DecompressPacketLobby,
            Channel::Zone => &DecompressPacketZone,
        };
        let ret = unsafe { hook.call(a1, a2, a3, a4, a5) };

        let ptr_frame = unsafe { *(a1.add(16) as *const usize) as *mut u8 };
        let offset: u32 = unsafe { *(a1.add(28) as *const u32) };
        if offset != 0 {
            return ret;
        }

        let require_deobf = if let Channel::Zone = channel {
            self.create_target_hook_enabled.load(Ordering::SeqCst)
        } else {
            false
        };

        if require_deobf && !self.deobf_queue_rx.is_empty() {
            warn!("Packet queue has not been fully read. The queue will be emptied.");
            let _: Vec<_> = self.deobf_queue_rx.try_iter().collect();
        }

        let packets = match unsafe { packet::extract_packets_from_frame(ptr_frame, require_deobf) }
        {
            Ok(packets) => packets,
            Err(e) => {
                error!("Could not process packet: {e}");
                return ret;
            }
        };

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
