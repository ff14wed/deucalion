use std::mem;
use std::ptr;

use once_cell::sync::OnceCell;

use failure::{format_err, Error};

use detour;
use detour::static_detour;
use tokio::sync::mpsc;

use crate::hook::waitgroup;
use crate::rpc;

use crate::procloader::get_ffxiv_handle;

use log::info;

static_detour! {
    static RecvZonePacket: unsafe extern "system" fn(*const u8, *const usize) -> usize;
}

// const RECVZONEPACKET_SIG: &[pat::Atom] = pat!("E8 $ { ' } 84 C0 0F 85 ? ? ? ? 44 0F B6 64 24 ?");

#[derive(Clone)]
pub struct Hook {
    data_tx: mpsc::UnboundedSender<rpc::Payload>,

    hook: OnceCell<
        &'static detour::StaticDetour<unsafe extern "system" fn(*const u8, *const usize) -> usize>,
    >,
    wg: waitgroup::WaitGroup,
}

impl Hook {
    pub fn new(
        data_tx: mpsc::UnboundedSender<rpc::Payload>,
        wg: waitgroup::WaitGroup,
    ) -> Result<Hook, Error> {
        Ok(Hook {
            data_tx: data_tx,

            hook: OnceCell::new(),
            wg: wg,
        })
    }

    pub fn setup(&self, recvzonepacket_rva: isize) -> Result<(), Error> {
        let ptr_rzp = get_ffxiv_handle()?.wrapping_offset(recvzonepacket_rva);

        let self_clone = self.clone();

        let hook = unsafe {
            let rzp: unsafe extern "system" fn(*const u8, *const usize) -> usize =
                mem::transmute(ptr_rzp as *const ());
            RecvZonePacket.initialize(rzp, move |a, b| self_clone.recv_zone_packet(a, b))?
        };
        self.hook
            .set(hook)
            .map_err(|_| format_err!("Failed to set up the hook."))?;
        unsafe {
            self.hook.get_unchecked().enable()?;
        }
        Ok(())
    }

    unsafe fn recv_zone_packet(&self, this: *const u8, a2: *const usize) -> usize {
        let _guard = self.wg.add();

        let ret = self
            .hook
            .get()
            .expect("Hook function was called without a valid hook")
            .call(this, a2);

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

        let _ = self.data_tx.send(rpc::Payload {
            op: rpc::MessageOps::Recv,
            ctx: 0,
            data: dst,
        });
        return ret;
    }

    pub fn shutdown(&self) {
        unsafe {
            if let Some(hook) = self.hook.get() {
                let _ = hook.disable();
            };
        }
    }
}
