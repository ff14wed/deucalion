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
static DETOUR: LazyLock<CustomDetour> = LazyLock::new(CustomDetour::new);

/// Non-volatile registers that need to be preserved across the detour call.
type Nonvolatiles = [usize; 7];

/// Custom static detour designed specifically for CreateTarget. If the
/// signature of the function being hooked changes non-trivially this will
/// need to be updated.
///
/// Implementation mostly borrowed from retour::StaticDetour.
/// Copyright (C) 2017 Elliott Linder.
pub struct CustomDetour {
    /// Closure arguments: (source_actor, return_addr, nonvolatile_regs)
    #[allow(clippy::type_complexity)]
    closure: AtomicPtr<Box<dyn Fn(usize, usize, &Nonvolatiles) -> usize>>,
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
        D: Fn(usize, usize, &Nonvolatiles) -> usize + Send + 'static,
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
    /// non-volatile registers for any downstream consumers.
    unsafe fn call_trampoline(
        &self,
        source_actor: usize,
        nonvolatile_regs: &Nonvolatiles,
    ) -> Result<usize> {
        let trampoline: fn(usize) -> usize = unsafe {
            mem::transmute(
                self.detour
                    .load(Ordering::SeqCst)
                    .as_ref()
                    .ok_or(HookError::NotInitialized)?
                    .trampoline(),
            )
        };
        // Custom calling convention for the trampoline: Pass in nonvolatile
        // registers in addition to rcx.
        let result: usize;
        unsafe {
            asm!(
                "# Preserve all non-volatile registers before calling the trampoline",
                "push rbx", "push rdi", "push rsi", "push r12", "push r13", "push r14", "push r15",
                "mov rbx, qword ptr [r10]",
                "mov rdi, qword ptr [r10+8]",
                "mov rsi, qword ptr [r10+16]",
                "mov r12, qword ptr [r10+24]",
                "mov r13, qword ptr [r10+32]",
                "mov r14, qword ptr [r10+40]",
                "mov r15, qword ptr [r10+48]",
                "call rax",
                "pop r15", "pop r14", "pop r13", "pop r12", "pop rsi", "pop rdi", "pop rbx",
                in("rax") trampoline as usize,
                in("rcx") source_actor,
                in("r10") nonvolatile_regs.as_ptr(),
                lateout("rax") result,
            );
        }
        Ok(result)
    }

    /// Helper for calling the trampoline with error handling.
    unsafe fn call_original(&self, source_actor: usize, nonvolatile_regs: &Nonvolatiles) -> usize {
        unsafe {
            self.call_trampoline(source_actor, nonvolatile_regs).unwrap_or_else(|e| {
                error!("{e}");
                0
            })
        }
    }

    /// Calls the closure that was set for the detour.
    unsafe fn call_closure(
        &self,
        source_actor: usize,
        return_addr: usize,
        nonvolatile_regs: &Nonvolatiles,
    ) -> Result<usize> {
        let closure = unsafe {
            self.closure.load(Ordering::SeqCst).as_ref().ok_or(HookError::NotInitialized)?
        };
        Ok(closure(source_actor, return_addr, nonvolatile_regs))
    }

    fn drop_internal(&self) {
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

impl Drop for CustomDetour {
    fn drop(&mut self) {
        self.drop_internal();
    }
}

unsafe extern "C" {
    #[link_name = "llvm.returnaddress"]
    unsafe fn return_address(a: i32) -> *const u8;
}

unsafe extern "system" fn create_target(mut source_actor: usize) -> usize {
    unsafe {
        let mut nonvolatile_regs = [0; 7];
        asm!(
            "# Ensure non-volatile registers are preserved before this section",
            "mov qword ptr [rax], rbx",
            "mov qword ptr [rax+8], rdi",
            "mov qword ptr [rax+16], rsi",
            "mov qword ptr [rax+24], r12",
            "mov qword ptr [rax+32], r13",
            "mov qword ptr [rax+40], r14",
            "mov qword ptr [rax+48], r15",
            in("rax") nonvolatile_regs.as_mut_ptr(),
            inout("rcx") source_actor,
        );

        let return_addr = return_address(0);

        DETOUR
            .call_closure(source_actor, return_addr as usize, &nonvolatile_regs)
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
            DETOUR.initialize(fn_ptr as *const (), move |a, b, c| {
                self_clone.hook_handler(a, b, c)
            })?;
            DETOUR.enable()?;
        }

        Ok(())
    }

    unsafe fn hook_handler(
        &self,
        source_actor: usize,
        return_addr: usize,
        nonvolatile_regs: &Nonvolatiles,
    ) -> usize {
        let packet_data = nonvolatile_regs[1]; // rdi
        let original_data = nonvolatile_regs[3]; // r12
        let _guard = self.wg.add();
        let return_addr = return_addr as *const u8;
        let parent_ptr = self.parent_ptr.load(Ordering::SeqCst) as *const u8;

        // Ensure the return address is within the range of the packet dispatch
        // function
        unsafe {
            if parent_ptr.offset_from(return_addr).abs() > 0x2000 {
                return DETOUR.call_original(source_actor, nonvolatile_regs);
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

        unsafe { DETOUR.call_original(source_actor, nonvolatile_regs) }
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

    use pelite::{pattern, pe::PeView};

    use crate::{
        CREATE_TARGET_SIG,
        hook::create_target::{DETOUR, Nonvolatiles},
        procloader::{find_pattern_matches, get_ffxiv_handle},
    };

    const FAKE_PACKET_PTR: usize = 0x12345678;
    const FAKE_ORIGINAL_PTR: usize = 0x12000000;
    const FAKE_SOURCE_ACTOR: u32 = 0x11110000;
    const FAKE_OPCODE: u32 = 0x420;

    #[inline(never)]
    fn create_target_72x(mut source_actor: u32) -> u32 {
        let packet_data: usize;
        unsafe {
            asm!(
                "mov {0}, rsi",
                out(reg) packet_data,
                inout("rcx") source_actor,
            );
        }

        source_actor + packet_data as u32
    }

    #[inline(never)]
    unsafe extern "system" fn parent_72x() {
        let packet_data: usize;
        let dummy_result: u32;
        let case: u32;

        unsafe {
            asm!(
                "mov rsi, {packet_ptr}",
                "mov edi, {source_actor}",
                "mov r15d, {opcode}",
                "mov edx, r15d",
                "mov ecx, edi",
                "call {func}",
                "add r15d, 0xFFFFFF9Ah",
                "cmp r15d, 381h",
                packet_ptr = const FAKE_PACKET_PTR,
                source_actor = const FAKE_SOURCE_ACTOR,
                opcode = const FAKE_OPCODE,
                func = sym create_target_72x,
                out("rax") dummy_result,
                out("rsi") packet_data,
                out("r15d") case,
            );
        }
        assert_eq!(packet_data, FAKE_PACKET_PTR);
        assert_eq!(case, FAKE_OPCODE - 102);
        assert_eq!(dummy_result, FAKE_SOURCE_ACTOR + FAKE_PACKET_PTR as u32);
    }

    #[inline(never)]
    fn create_target_731(mut source_actor: u32) -> u32 {
        let packet_data: usize;
        let original_data: usize;
        unsafe {
            asm!(
                "mov {0}, rdi",
                "mov {1}, r13",
                out(reg) packet_data,
                out(reg) original_data,
                inout("rcx") source_actor,
            );
        }

        source_actor + packet_data as u32 + original_data as u32
    }

    #[inline(never)]
    unsafe extern "system" fn parent_731() {
        let packet_data: usize;
        let dummy_result: u32;
        let case: u32;

        unsafe {
            asm!(
                "mov r13, {orig_ptr}",
                "mov rdi, {packet_ptr}",
                "mov esi, {source_actor}",
                "mov r15d, {opcode}",
                "mov edx, r15d",
                "mov ecx, esi",
                "call {func}",
                "add r15d, 0xFFFFFF9Ah",
                "mov rdi, r13",
                "cmp r15d, 380h",
                orig_ptr = const FAKE_ORIGINAL_PTR,
                packet_ptr = const FAKE_PACKET_PTR,
                source_actor = const FAKE_SOURCE_ACTOR,
                opcode = const FAKE_OPCODE,
                func = sym create_target_731,
                out("rax") dummy_result,
                out("rdi") packet_data,
                out("r15d") case,
            );
        }
        // Packet ptr was overwritten with the original packet ptr in this case
        assert_eq!(packet_data, FAKE_ORIGINAL_PTR);
        assert_eq!(case, FAKE_OPCODE - 102);
        assert_eq!(
            dummy_result,
            FAKE_SOURCE_ACTOR + FAKE_PACKET_PTR as u32 + FAKE_ORIGINAL_PTR as u32
        );
    }

    #[inline(never)]
    fn create_target_731h(mut source_actor: u32) -> u32 {
        let packet_data: usize;
        let original_data: usize;
        unsafe {
            asm!(
                "mov {0}, rdi",
                "mov {1}, r12",
                out(reg) packet_data,
                out(reg) original_data,
                inout("rcx") source_actor,
            );
        }

        source_actor + packet_data as u32 + original_data as u32
    }

    #[inline(never)]
    unsafe extern "system" fn parent_731h() {
        let packet_data: usize;
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
                "mov rdi, r12",
                "cmp r13d, 380h",
                orig_ptr = const FAKE_ORIGINAL_PTR,
                packet_ptr = const FAKE_PACKET_PTR,
                source_actor = const FAKE_SOURCE_ACTOR,
                opcode = const FAKE_OPCODE,
                func = sym create_target_731h,
                out("rax") dummy_result,
                out("rdi") packet_data,
                out("r13d") case,
            );
        }
        // Packet ptr was overwritten with the original packet ptr in this case
        assert_eq!(packet_data, FAKE_ORIGINAL_PTR);
        assert_eq!(case, FAKE_OPCODE - 101);
        assert_eq!(
            dummy_result,
            FAKE_SOURCE_ACTOR + FAKE_PACKET_PTR as u32 + FAKE_ORIGINAL_PTR as u32
        );
    }

    #[test]
    fn test_parent_72x() {
        unsafe { parent_72x() };
    }

    #[test]
    fn test_parent_731() {
        unsafe { parent_731() };
    }

    #[test]
    fn test_parent_731h() {
        unsafe { parent_731h() };
    }

    #[test]
    fn test_create_target_sig() {
        // It's not actually FFXIV, but it should work in test
        let current_handle = get_ffxiv_handle().unwrap();
        let pe_image = unsafe { PeView::module(current_handle) };
        let pat = pattern::parse(CREATE_TARGET_SIG).unwrap();
        let sig: &[pattern::Atom] = &pat;
        let rvas = find_pattern_matches("create_target", sig, pe_image, false).unwrap();
        assert!(rvas.len() >= 2);

        println!("Testing CreateTarget sig compatibility for patch 7.30h/7.31");
        let addr = current_handle.wrapping_add(rvas[0]);
        let parent_731_ptr = parent_731 as *const u8;
        assert!((parent_731_ptr..parent_731_ptr.wrapping_add(100)).contains(&addr));

        println!("Testing CreateTarget sig compatibility for patch 7.30/7.31h");
        let addr = current_handle.wrapping_add(rvas[1]);
        let parent_731h_ptr = parent_731h as *const u8;
        assert!((parent_731h_ptr..parent_731h_ptr.wrapping_add(100)).contains(&addr));
    }

    fn validate_detour(
        create_target: fn(u32) -> u32,
        parent_fn: unsafe extern "system" fn(),
        nonvolatile_validator: fn(&Nonvolatiles),
    ) {
        DETOUR.drop_internal();
        let closure = move |source_actor, return_addr, nonvolatile_regs: &Nonvolatiles| {
            nonvolatile_validator(nonvolatile_regs);
            assert!(return_addr != 0);
            assert_eq!(source_actor, FAKE_SOURCE_ACTOR as usize);
            unsafe { DETOUR.call_original(source_actor, nonvolatile_regs) }
        };
        unsafe {
            DETOUR.initialize(create_target as *const (), closure).unwrap();
            DETOUR.enable().unwrap();
            parent_fn();
            DETOUR.disable().unwrap();
        }
    }

    #[test]
    fn test_detours() {
        println!("Testing CreateTarget detour for patch 7.2x");
        validate_detour(create_target_72x, parent_72x, |nonvolatile_regs| {
            assert_eq!(nonvolatile_regs[2], FAKE_PACKET_PTR); // rsi
        });

        // The 7.30h case is the same as 7.31
        println!("Testing CreateTarget detour for patch 7.31");
        validate_detour(create_target_731, parent_731, |nonvolatile_regs| {
            assert_eq!(nonvolatile_regs[1], FAKE_PACKET_PTR); // rdi
            assert_eq!(nonvolatile_regs[4], FAKE_ORIGINAL_PTR); // r13
        });
        // The 7.30 case is the same as 7.31h
        println!("Testing CreateTarget detour for patch 7.31h");
        validate_detour(create_target_731h, parent_731h, |nonvolatile_regs| {
            assert_eq!(nonvolatile_regs[1], FAKE_PACKET_PTR); // rdi
            assert_eq!(nonvolatile_regs[3], FAKE_ORIGINAL_PTR); // r12
        });
    }
}
