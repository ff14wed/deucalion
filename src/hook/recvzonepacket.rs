use std::mem;
use std::ptr;

use parking_lot::RwLock;
use std::sync::Arc;

use failure::Error;

use crossbeam_channel as channel;
use detour;
use detour::static_detour;

use crate::hook::waitgroup;
use crate::rpc;

use pelite::pattern as pat;
use pelite::pe64::PeView;

use crate::procloader::{get_ffxiv_handle, sig_scan_helper};

use log::info;

static_detour! {
    static RecvZonePacket: unsafe extern "system" fn(*const u8, *const usize) -> usize;
}

const RECVZONEPACKET_SIG: &[pat::Atom] = pat!("E8 $ { ' } 84 C0 0F 85 ? ? ? ? 44 0F B6 64 24 ?");

#[derive(Clone)]
pub struct Hook {
    call_home_tx: channel::Sender<rpc::Payload>,

    hook: Arc<
        RwLock<
            &'static detour::StaticDetour<
                unsafe extern "system" fn(*const u8, *const usize) -> usize,
            >,
        >,
    >,
    wg: waitgroup::WaitGroup,
}

impl Hook {
    pub fn new(
        call_home_tx: channel::Sender<rpc::Payload>,
        wg: waitgroup::WaitGroup,
    ) -> Result<Hook, Error> {
        let handle_ffxiv = get_ffxiv_handle()?;
        let pe_view = unsafe { PeView::module(handle_ffxiv) };
        let rzp_offset = sig_scan_helper("RecvZonePacket", RECVZONEPACKET_SIG, pe_view, 1)?;
        let ptr_rzp = handle_ffxiv.wrapping_offset(rzp_offset);

        let hook = unsafe {
            let rzp: unsafe extern "system" fn(*const u8, *const usize) -> usize =
                mem::transmute(ptr_rzp as *const ());
            RecvZonePacket.initialize(rzp, |_, _| 0)?
        };
        Ok(Hook {
            call_home_tx: call_home_tx,

            hook: Arc::new(RwLock::new(hook)),
            wg: wg,
        })
    }

    pub fn setup(&self) -> Result<(), Error> {
        unsafe {
            let self_clone = self.clone();
            let hook = self.hook.write();
            hook.set_detour(move |a, b| self_clone.recv_zone_packet(a, b));
            hook.enable()?;
        }
        Ok(())
    }

    unsafe fn recv_zone_packet(&self, this: *const u8, a2: *const usize) -> usize {
        let _guard = self.wg.add();

        let ret = self.hook.read().call(this, a2);

        let ptr_received_packet: *const u8 = *(a2.add(2)) as *const u8;

        if ptr_received_packet.is_null() || ret == 0 {
            return ret;
        }

        let source_actor_id: u32 = *(ptr_received_packet.add(0x20) as *const u32);
        let target_actor_id: u32 = *(ptr_received_packet.add(0x24) as *const u32);
        let data_len: u32 = *(ptr_received_packet.add(0x30) as *const u32);
        let ptr_data: *const u8 = *(ptr_received_packet.add(0x38) as *const *const u8);

        if data_len > 0x10000 {
            info!(
                "Could not process packet: data_len exceeds 65536 bytes: {}",
                data_len
            );
            return ret;
        }

        let payload_len: usize = data_len as usize + 8;

        let mut dst = Vec::<u8>::with_capacity(payload_len);
        dst.set_len(payload_len);
        dst[..4].clone_from_slice(&source_actor_id.to_le_bytes());
        dst[4..8].clone_from_slice(&target_actor_id.to_le_bytes());
        ptr::copy(ptr_data, dst[8..].as_mut_ptr(), data_len as usize);

        let _ = self.call_home_tx.send(rpc::Payload {
            op: rpc::MessageOps::Recv,
            ctx: 0,
            data: dst,
        });
        return ret;
    }

    pub fn shutdown(&self) {
        unsafe {
            let _ = self.hook.write().disable();
        }
    }
}
