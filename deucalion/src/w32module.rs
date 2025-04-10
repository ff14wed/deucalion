use anyhow::{Result, format_err};
use log::info;
use winapi::{
    shared::{minwindef::HMODULE, ntdef::HANDLE},
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        libloaderapi::FreeLibrary,
        processthreadsapi::GetCurrentProcessId,
        tlhelp32::{
            CreateToolhelp32Snapshot, MODULEENTRY32, Module32First, Module32Next, TH32CS_SNAPMODULE,
        },
    },
};

struct TH32Handle(HANDLE);

impl TH32Handle {
    unsafe fn new(handle: HANDLE) -> Result<Self> {
        if handle.is_null() {
            return Err(format_err!(
                "Failed to call CreateToolhelp32Snapshot: {}",
                unsafe { GetLastError() }
            ));
        }
        Ok(TH32Handle(handle))
    }
}
impl Drop for TH32Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

unsafe fn get_ref_count(hmodule: HMODULE) -> Result<u32> {
    let pid = unsafe { GetCurrentProcessId() };
    let snapshot_handle =
        unsafe { TH32Handle::new(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid))? };

    let mut me32: MODULEENTRY32 = unsafe { core::mem::zeroed() };
    let me32_size = std::mem::size_of::<MODULEENTRY32>() as u32;
    me32.dwSize = me32_size;

    if unsafe { Module32First(snapshot_handle.0, &mut me32) } == 0 {
        return Err(format_err!("Failed to call Module32First: {}", unsafe {
            GetLastError()
        }));
    }

    // Set a hard limit of 65535 modules to iterate through before giving up
    for _ in 0..65535 {
        if std::ptr::eq(hmodule, me32.hModule) {
            if me32.GlblcntUsage == 0xFFFF {
                return Err(format_err!(
                    "Could not get ref count for current module since it is reported as 0xFFFF."
                ));
            }
            return Ok(me32.GlblcntUsage);
        }
        if unsafe { Module32Next(snapshot_handle.0, &mut me32) } == 0 {
            break;
        }
    }
    Err(format_err!("Could not find ref count for current module"))
}

pub unsafe fn drop_ref_count_to_one(hmodule: HMODULE) -> Result<()> {
    let count = unsafe { get_ref_count(hmodule)? };
    if count <= 1 {
        return Ok(());
    }
    info!(
        "Ref count is {count}. Calling FreeLibrary {} extra time(s)...",
        count - 1
    );
    for _ in 0..count - 1 {
        if unsafe { FreeLibrary(hmodule) } == 0 {
            return Err(format_err!("Failed to call FreeLibrary: {}", unsafe {
                GetLastError()
            }));
        };
    }
    Ok(())
}
