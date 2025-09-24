//! It doesn't actually matter what function this is hooking, as long as it's
//! right before the giant switch that processes packets.

use std::{
    arch::asm,
    mem,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicPtr, AtomicUsize, Ordering},
    },
};

use anyhow::{Result, format_err};
use log::{error, warn};
use retour::RawDetour;
use tokio::sync::mpsc;

use super::{
    Channel, HookError,
    packet::{self, DEUCALION_DEFER_IPC},
    waitgroup,
};
use crate::{procloader::get_ffxiv_handle, rpc};

// Once initialized, it's important to keep this in memory so that any
// stray calls to the hook still have a valid trampoline to call.
pub(super) static DETOUR: LazyLock<CustomDetour> = LazyLock::new(CustomDetour::new);

/// Custom static detour designed specifically for CreateTarget. If the
/// signature of the function being hooked changes non-trivially this will
/// need to be updated.
///
/// Implementation mostly borrowed from retour::StaticDetour.
/// Copyright (C) 2017 Elliott Linder.
pub struct CustomDetour {
    /// Closure arguments: (packet_data, original_data, return_addr, source_actor)
    #[allow(clippy::type_complexity)]
    closure: AtomicPtr<Box<dyn Fn(usize, usize, usize, usize) -> usize>>,
    detour: AtomicPtr<RawDetour>,
}

impl CustomDetour {
    fn new() -> Self {
        CustomDetour {
            closure: AtomicPtr::new(std::ptr::null_mut()),
            detour: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    /// Initializes the detour and sets the closure to be called when the detour
    /// is enabled.
    pub unsafe fn initialize<D>(&self, target: *const (), closure: D) -> Result<()>
    where
        D: Fn(usize, usize, usize, usize) -> usize + Send + 'static,
    {
        let mut detour = unsafe { Box::new(RawDetour::new(target, create_target as *const ())?) };
        self.detour
            .compare_exchange(
                std::ptr::null_mut(),
                &mut *detour,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|_| HookError::AlreadyInitialized)?;

        self.closure.store(Box::into_raw(Box::new(Box::new(closure))), Ordering::SeqCst);
        mem::forget(detour);
        Ok(())
    }

    /// Enables the detour.
    pub unsafe fn enable(&self) -> Result<()> {
        unsafe {
            self.detour
                .load(Ordering::SeqCst)
                .as_ref()
                .ok_or(HookError::NotInitialized)?
                .enable()?;
        }
        Ok(())
    }

    /// Disables the detour.
    pub unsafe fn disable(&self) -> Result<()> {
        unsafe {
            self.detour
                .load(Ordering::SeqCst)
                .as_ref()
                .ok_or(HookError::NotInitialized)?
                .disable()?;
        }
        Ok(())
    }

    /// Calls the trampoline for the function being hooked. Tries to preserve
    /// rdi for any downstream consumers.
    unsafe fn call_trampoline(&self, source_actor: usize, packet_data: usize) -> Result<usize> {
        let trampoline: fn(usize) -> usize = unsafe {
            mem::transmute(
                self.detour
                    .load(Ordering::SeqCst)
                    .as_ref()
                    .ok_or(HookError::NotInitialized)?
                    .trampoline(),
            )
        };
        // Custom calling convention for the trampoline: Pass in rcx and rdi
        let result: usize;
        unsafe {
            asm!("
                mov rdi, {0}
                mov rcx, {1}
                call {2}",
                in(reg) packet_data,
                in(reg) source_actor,
                in(reg) trampoline as usize,
                out("rdi") _,
                out("rcx") _,
                out("rax") result,
            );
        }
        Ok(result)
    }

    /// Helper for calling the trampoline with error handling.
    unsafe fn call_original(&self, source_actor: usize, packet_data: usize) -> usize {
        unsafe {
            self.call_trampoline(source_actor, packet_data).unwrap_or_else(|e| {
                error!("{e}");
                0
            })
        }
    }

    /// Calls the closure that was set for the detour.
    unsafe fn call_closure(
        &self,
        packet_data: usize,
        original_data: usize,
        return_addr: usize,
        source_actor: usize,
    ) -> Result<usize> {
        let closure = unsafe {
            self.closure.load(Ordering::SeqCst).as_ref().ok_or(HookError::NotInitialized)?
        };
        Ok(closure(
            packet_data,
            original_data,
            return_addr,
            source_actor,
        ))
    }
}

impl Drop for CustomDetour {
    fn drop(&mut self) {
        let previous = self.closure.swap(std::ptr::null_mut(), Ordering::Relaxed);
        if !previous.is_null() {
            mem::drop(unsafe { Box::from_raw(previous) });
        }

        let previous = self.detour.swap(std::ptr::null_mut(), Ordering::Relaxed);
        if !previous.is_null() {
            unsafe {
                let _ = Box::from_raw(previous);
            };
        }
    }
}

unsafe extern "C" {
    #[link_name = "llvm.returnaddress"]
    unsafe fn return_address(a: i32) -> *const u8;
}

unsafe extern "system" fn create_target(a1: usize) -> usize {
    unsafe {
        let source_actor: usize;
        let packet_data: *const u8;
        let original_data: *const u8;
        asm!("
            # Ensure rdi and r13 are preserved before this section
            mov r10, {0}
            mov {1}, rdi
            mov {2}, r12",
            in(reg) a1,
            out(reg) packet_data,
            out(reg) original_data,
            out("r10") source_actor);

        let return_addr = return_address(0);

        DETOUR
            .call_closure(
                packet_data as usize,
                original_data as usize,
                return_addr as usize,
                source_actor,
            )
            .unwrap_or_else(|e| {
                error!("Error in CreateTarget closure: {e}");
                0
            })
    }
}

#[derive(Clone)]
pub struct Hook {
    data_tx: mpsc::UnboundedSender<rpc::Payload>,
    deobf_queue_rx: crossbeam_channel::Receiver<packet::Packet>,
    wg: waitgroup::WaitGroup,
    parent_ptr: Arc<AtomicUsize>,
}

impl Hook {
    pub fn new(
        data_tx: mpsc::UnboundedSender<rpc::Payload>,
        deobf_queue_rx: crossbeam_channel::Receiver<packet::Packet>,
        wg: waitgroup::WaitGroup,
    ) -> Result<Hook> {
        Ok(Hook {
            data_tx,
            deobf_queue_rx,
            wg,
            parent_ptr: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn setup(&self, parent_rva: usize, rvas: Vec<usize>) -> Result<()> {
        if rvas.len() != 1 {
            return Err(HookError::SignatureMatchFailed(rvas.len(), 1).into());
        }
        let ffxiv_handle = get_ffxiv_handle()?;
        let fn_ptr = ffxiv_handle.wrapping_add(rvas[0]);
        let parent_ptr: usize = ffxiv_handle.wrapping_add(parent_rva) as usize;
        self.parent_ptr
            .compare_exchange(0, parent_ptr, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| format_err!("Could not initialize CreateTarget hook"))?;

        let self_clone = self.clone();
        unsafe {
            DETOUR.initialize(fn_ptr as *const (), move |a, b, c, d| {
                self_clone.hook_handler(a, b, c, d)
            })?;
            DETOUR.enable()?;
        }

        Ok(())
    }

    unsafe fn hook_handler(
        &self,
        packet_data: usize,
        original_data: usize,
        return_addr: usize,
        source_actor: usize,
    ) -> usize {
        let _guard = self.wg.add();
        let return_addr = return_addr as *const u8;
        let parent_ptr = self.parent_ptr.load(Ordering::SeqCst) as *const u8;

        // Ensure the return address is within the range of the packet dispatch
        // function
        unsafe {
            if parent_ptr.offset_from(return_addr).abs() > 0x2000 {
                return DETOUR.call_original(source_actor, packet_data);
            }
        }

        let mut actual_packet_data = packet_data as *mut u8;
        if unsafe { *(actual_packet_data.byte_offset(4) as *const u16) } != DEUCALION_DEFER_IPC {
            // Could not read the packet data normally, so just use the original
            // packet data. We should be guarded against invalid data being
            // sent out since there is an opcode and a source actor check.
            actual_packet_data = original_data as *mut u8
        };

        let mut packet_sent = false;
        for expected_packet in self.deobf_queue_rx.try_iter() {
            match unsafe {
                packet::reconstruct_deobfuscated_packet(
                    expected_packet,
                    source_actor as u32,
                    actual_packet_data,
                )
            } {
                Ok(packet::Packet::Ipc(data)) => {
                    let _ = self.data_tx.send(rpc::Payload {
                        op: rpc::MessageOps::Recv,
                        ctx: Channel::Zone as u32,
                        data,
                    });
                    packet_sent = true;
                    break;
                }
                Ok(_) => unreachable!("Reconstruct should only send Ipc packets"),
                Err(e) => {
                    warn!(
                        "Failed to reconstruct deobfuscated packet. \
                        Skipping to the next packet in the queue: {e}."
                    );
                }
            }
        }
        if !packet_sent {
            // If we went through the entire queue (or if it's empty)
            // without sending a matching, corresponding packet, then
            // give up.
            let opcode: u16 = unsafe { *(actual_packet_data.byte_offset(2) as *const u16) };
            warn!("Processing deobfuscated packet {opcode}, but no packet was expected");
        }

        unsafe { DETOUR.call_original(source_actor, packet_data) }
    }

    pub fn shutdown() {
        if let Err(e) = unsafe { DETOUR.disable() } {
            error!("Error disabling CreateTarget hook: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::arch::asm;

    use crate::hook::create_target::DETOUR;

    const FAKE_PACKET_PTR: usize = 0x12345678;
    const FAKE_ORIGINAL_PTR: usize = 0x12000000;
    const FAKE_SOURCE_ACTOR: u32 = 0x11110000;
    const FAKE_OPCODE: u32 = 0x420;

    fn dummy_create_target(a1: u32) -> u32 {
        let source_actor: u32;
        let packet_data: usize;
        let original_data: usize;
        unsafe {
            asm!(
                "mov {1:e}, {0:e}",
                "mov {2}, rdi",
                "mov {3}, r12",
                in(reg) a1,
                out(reg) source_actor,
                out(reg) packet_data,
                out(reg) original_data,
            );
        }

        source_actor + packet_data as u32 + original_data as u32
    }

    unsafe extern "system" fn parent_fn() {
        let packet_data: usize;
        let original_data: usize;
        let dummy_result: u32;
        let case: u32;

        unsafe {
            asm!(
                "mov r12, {orig_ptr}",
                "mov rdi, {packet_ptr}",
                "mov r14d, {source_actor}",
                "mov r13d, {opcode}",
                "mov edx, r13d",
                "mov ecx, r14d",
                "call {func}",
                "add r13d, 0xFFFFFF9Bh",
                orig_ptr = const FAKE_ORIGINAL_PTR,
                packet_ptr = const FAKE_PACKET_PTR,
                source_actor = const FAKE_SOURCE_ACTOR,
                opcode = const FAKE_OPCODE,
                func = sym dummy_create_target,
                out("rax") dummy_result,
                out("rdi") packet_data,
                out("r12") original_data,
                out("r13d") case,
            );
        }

        assert_eq!(packet_data, FAKE_PACKET_PTR);
        assert_eq!(original_data, FAKE_ORIGINAL_PTR);
        assert_eq!(case, FAKE_OPCODE - 101);
        assert_eq!(
            dummy_result,
            FAKE_SOURCE_ACTOR + FAKE_PACKET_PTR as u32 + FAKE_ORIGINAL_PTR as u32
        );
    }

    #[test]
    fn test_parent_fn() {
        unsafe { parent_fn() };
    }

    #[test]
    fn test_custom_detour() {
        unsafe {
            DETOUR
                .initialize(
                    dummy_create_target as *const (),
                    |packet_data, original_data, return_addr, source_actor| {
                        println!("In detour with {packet_data:x}, {original_data:x}, {return_addr:x}, {source_actor:x}");
                        assert_eq!(packet_data, FAKE_PACKET_PTR);
                        assert_eq!(original_data, FAKE_ORIGINAL_PTR);
                        assert!(return_addr != 0);
                        assert_eq!(source_actor, FAKE_SOURCE_ACTOR as usize);
                        DETOUR.call_original(source_actor, packet_data)
                    },
                )
                .unwrap();
            DETOUR.enable().unwrap();
            parent_fn();
            DETOUR.disable().unwrap();
        }
    }
}
