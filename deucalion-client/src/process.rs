use std::{io, mem::MaybeUninit, path::Path, ptr};

use anyhow::{Result, format_err};
use dll_syringe::{
    Syringe,
    process::{OwnedProcess, Process},
};
use log::debug;
use sysinfo::ProcessesToUpdate;
use winapi::{
    shared::winerror::ERROR_SUCCESS,
    um::{
        accctrl::SE_KERNEL_OBJECT,
        aclapi::{GetSecurityInfo, SetSecurityInfo},
        processthreadsapi::{GetCurrentProcess, OpenProcess},
        securitybaseapi::GetSecurityDescriptorDacl,
        winbase::LocalFree,
        winnt::{
            DACL_SECURITY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PSECURITY_DESCRIPTOR,
            READ_CONTROL, UNPROTECTED_DACL_SECURITY_INFORMATION, WRITE_DAC,
        },
    },
};

pub fn find_all_pids_by_name(target_exe: &str) -> Vec<usize> {
    let mut system = sysinfo::System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system
        .processes()
        .values()
        .filter(move |process| process.exe().is_some_and(|path| path.ends_with(target_exe)))
        .map(|process| process.pid().into())
        .collect()
}

pub fn inject_dll<P: AsRef<Path>>(target_pid: usize, payload_path: P, force: bool) -> Result<()> {
    let target_process = OwnedProcess::from_pid(target_pid as u32)?;
    let syringe = Syringe::for_process(target_process);
    let _injected_payload = if force {
        syringe.inject(payload_path)?
    } else {
        syringe.find_or_inject(payload_path)?
    };
    Ok(())
}

pub fn eject_dll<P: AsRef<Path>>(target_pid: usize, payload_path: P) -> Result<()> {
    let target_process = OwnedProcess::from_pid(target_pid as u32)?;
    let syringe = Syringe::for_process(target_process);
    let payload_name = payload_path
        .as_ref()
        .file_name()
        .ok_or(format_err!("Could not get filename from payload path"))?;
    let module = syringe
        .process()
        .find_module_by_name(payload_name)?
        .ok_or(format_err!("Payload not found in target process"))?;
    syringe.eject(module)?;
    Ok(())
}

struct PSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for PSecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(self.0) };
    }
}
pub fn copy_current_process_dacl_to_target(target_pid: usize) -> Result<()> {
    debug!("Getting security info for current process");
    let current_process = unsafe { GetCurrentProcess() };
    let mut sd = MaybeUninit::uninit();
    let ret = unsafe {
        GetSecurityInfo(
            current_process,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            sd.as_mut_ptr(),
        )
    };
    if ret != ERROR_SUCCESS {
        return Err(format_err!("Error calling GetSecurityInfo: {ret:x}"));
    }
    debug!("Getting security descriptor DACL");
    let psd = PSecurityDescriptor(unsafe { sd.assume_init() });
    let mut dacl_present = MaybeUninit::uninit();
    let mut dacl = MaybeUninit::uninit();
    let mut defaulted = MaybeUninit::uninit();
    let ret = unsafe {
        GetSecurityDescriptorDacl(
            psd.0,
            dacl_present.as_mut_ptr(),
            dacl.as_mut_ptr(),
            defaulted.as_mut_ptr(),
        )
    };
    if ret == 0 {
        return Err(io::Error::last_os_error().into());
    }

    if unsafe { dacl_present.assume_init() } == 0 {
        return Err(format_err!("SecurityInfo.DACL not found"));
    }

    debug!("Opening target process for writing the DACL");
    let dacl = unsafe { dacl.assume_init() };
    if dacl.is_null() {
        return Err(format_err!("SecurityInfo.DACL is null"));
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | WRITE_DAC | READ_CONTROL,
            0,
            target_pid as u32,
        )
    };

    if handle.is_null() {
        return Err(io::Error::last_os_error().into());
    }

    debug!("Setting the security info for the target process");

    let ret = unsafe {
        SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if ret != ERROR_SUCCESS {
        return Err(format_err!("Error calling SetSecurityInfo: 0x{ret:x}"));
    }
    Ok(())
}
