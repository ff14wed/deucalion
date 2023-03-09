use core::slice;
use std::mem;
use std::sync::Arc;

use anyhow::Result;

use tokio::sync::mpsc;

use once_cell::sync::OnceCell;

use retour;
use retour::static_detour;

use binary_layout::prelude::*;

use crate::rpc;

use crate::procloader::get_ffxiv_handle;

use super::packet;
use super::waitgroup;
use super::{Channel, HookError};

use log::info;

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

        if ptr_frame.is_null() {
            return ret;
        }

        let frame_header_bytes = slice::from_raw_parts(ptr_frame, 40);
        let frame_header = packet::frame_header::View::new(frame_header_bytes);

        const ERR_PREFIX: &str = "Could not process packet";

        let compression: u8 = frame_header.compression().read();
        if compression != 0 {
            info!(
                "{}: packet is still compressed: {}",
                ERR_PREFIX, compression
            );
            return ret;
        }

        let num_segments: u16 = frame_header.segment_count().read();
        let frame_size: usize = frame_header.size().read() as usize;

        let frame_header_size = packet::frame_header::SIZE.unwrap();

        if frame_size > 0x10000 || frame_size < frame_header_size {
            info!("{}: frame_size is invalid: {}", ERR_PREFIX, frame_size);
            return ret;
        }

        let frame_data = slice::from_raw_parts(
            ptr_frame.add(frame_header_size),
            frame_size - frame_header_size,
        );

        let mut frame_data_offset: usize = 0;

        let mut packets: Vec<Vec<u8>> = Vec::new();
        for _ in 0..num_segments {
            let segment_size = packet::segment_header::size::read(&frame_data[frame_data_offset..]);
            let segment_header_size = packet::segment_header::SIZE.unwrap();

            if segment_size > 0x10000 || (segment_size as usize) < segment_header_size {
                info!("{}: segment_size is invalid: {}", ERR_PREFIX, segment_size);
                return ret;
            }

            let segment = packet::segment::View::new(
                &frame_data[frame_data_offset..frame_data_offset + segment_size as usize],
            );
            frame_data_offset += segment_size as usize;

            // Capture only IPC segment type
            if segment.header().segment_type().read() != 3 {
                continue;
            }
            let segment_header = segment.header();
            let deucalion_header_size = packet::deucalion_segment_header::SIZE.unwrap();
            let payload_len = segment_size as usize - segment_header_size + deucalion_header_size;

            let mut dst = Vec::<u8>::with_capacity(payload_len);
            dst.set_len(payload_len);
            let buf: &mut [u8] = dst.as_mut();
            let mut deucalion_segment = packet::deucalion_segment::View::new(buf);
            let mut dsh = deucalion_segment.header_mut();
            dsh.source_actor_mut()
                .write(segment_header.source_actor().read());
            dsh.target_actor_mut()
                .write(segment_header.target_actor().read());
            dsh.timestamp_mut().write(frame_header.timestamp().read());

            deucalion_segment.data_mut().copy_from_slice(segment.data());

            packets.push(dst);
        }

        for packet in packets {
            let _ = self.data_tx.send(rpc::Payload {
                op: rpc::MessageOps::Recv,
                ctx: channel as u32,
                data: packet,
            });
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
