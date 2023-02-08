use std::convert::TryInto;
use std::mem;
use std::ptr;

use winapi::shared::minwindef;
use winapi::um::libloaderapi;

use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;

use anyhow::Result;
use thiserror::Error;

use pelite::pattern as pat;
use pelite::pe::image::{Rva, Va};
use pelite::pe::Pe;

use memchr::memmem;

use log::debug;

#[derive(Debug, Error)]
enum ProcLoaderError {
    #[error("cannot find load address for module: {}", name)]
    ModuleNotFound { name: &'static str },
    #[error("cannot load address for proc: {}", name)]
    ProcNotFound { name: &'static str },
    #[error("Signature has no predetermined match length.")]
    BadSignature {},
    #[error("Could not get virtual function: {} is null", name)]
    NullPtr { name: &'static str },
}

#[derive(Debug, Error)]
enum SigScanError {
    #[error("Could not find a signature match for {}", name)]
    MatchNotFound { name: &'static str },
    #[error("Invalid signature match for {}", name)]
    InvalidMatch { name: &'static str },
}

#[allow(dead_code)]
pub fn get_module_handle(mod_name: &'static str) -> Result<minwindef::HMODULE> {
    let str_mod = OsStr::new(mod_name)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect::<Vec<_>>();
    unsafe {
        let handle = libloaderapi::LoadLibraryW(str_mod.as_ptr());
        if handle.is_null() {
            return Err(ProcLoaderError::ModuleNotFound { name: mod_name }.into());
        }
        return Ok(handle);
    }
}

#[allow(dead_code)]
pub fn get_address(
    lib_handle: minwindef::HMODULE,
    fn_name: &'static str,
) -> Result<minwindef::FARPROC> {
    let cstr_fn_name = CString::new(fn_name).unwrap();
    unsafe {
        let ptr_fn = libloaderapi::GetProcAddress(lib_handle, cstr_fn_name.as_ptr() as *const i8);
        if ptr_fn.is_null() {
            return Err(ProcLoaderError::ProcNotFound { name: fn_name }.into());
        }
        return Ok(ptr_fn);
    }
}

pub fn get_ffxiv_handle() -> Result<*const u8> {
    unsafe {
        let handle_ffxiv = libloaderapi::GetModuleHandleW(ptr::null()) as *const u8;
        if handle_ffxiv.is_null() {
            return Err(ProcLoaderError::ModuleNotFound { name: "ffxiv" }.into());
        }
        return Ok(handle_ffxiv);
    }
}

#[allow(dead_code)]
pub fn get_virtual_function_ptr(
    vtable_addr: *const u8,
    vtable_offset: isize,
    count: isize,
) -> Result<*const u8> {
    unsafe {
        if vtable_addr.is_null() {
            return Err(ProcLoaderError::NullPtr {
                name: "vtable_addr",
            }
            .into());
        }
        debug!(
            "vtable_addr with offset {:x?}",
            vtable_addr.wrapping_offset(vtable_offset)
        );
        let vtable_addr_offset = vtable_addr.wrapping_offset(vtable_offset) as *const *const usize;
        let vtable = *(vtable_addr_offset);
        if vtable.is_null() {
            return Err(ProcLoaderError::NullPtr { name: "vtable" }.into());
        }
        debug!("vtable {:x?}", vtable);

        debug!(
            "vtable with virt func offset {:x?}",
            vtable.wrapping_offset(count)
        );
        let virt_func_addr = vtable.wrapping_offset(count) as *const *const u8;
        let func_addr = *(virt_func_addr);
        if func_addr.is_null() {
            return Err(ProcLoaderError::NullPtr { name: "func_addr" }.into());
        }
        debug!("func_addr {:x?}", func_addr);

        Ok(func_addr)
    }
}

pub fn fast_pattern_scan<'a, P: Pe<'a>>(
    pat: &[pat::Atom],
    pe: P,
    save: &mut [Rva],
) -> Result<bool> {
    let pat_len = get_pat_len(pat)?;
    let (excerpt, excerpt_rva) = get_excerpt(pat);
    let image_range = pe.headers().code_range();
    let image = pe.image();
    let pattern_scanner = pe.scanner();

    let mut start = image_range.start as usize + excerpt_rva;
    let end = image_range.end as usize;
    debug!(
        "Using pat len {:?} and excerpt {:x?} with rva {:?}",
        pat_len, excerpt, excerpt_rva,
    );
    let finder = memmem::Finder::new(excerpt.as_slice());

    while start < end {
        match finder.find(&image[start..end]) {
            Some(loc) => {
                let pattern_start = loc + start - excerpt_rva;
                let pattern_start_rva = pattern_start as u32;
                if pattern_scanner.finds(pat, pattern_start_rva..pattern_start_rva + pat_len, save)
                {
                    return Ok(true);
                }
                // If pattern not found, continue
                start = pattern_start as usize + excerpt_rva as usize + excerpt.len();
            }
            None => return Ok(false),
        }
    }
    Ok(false)
}

pub fn sig_scan_helper<'a, P: Pe<'a>>(
    name: &'static str,
    pat: &[pat::Atom],
    pe: P,
    depth: usize,
) -> Result<isize> {
    let mut save = [0; 8];

    let res = fast_pattern_scan(pat, pe, &mut save)?;
    if !res {
        return Err(SigScanError::MatchNotFound { name }.into());
    }

    let mut deepest = 0;
    if depth >= 8 {
        for i in 0..8 {
            if save[i] > 0 {
                deepest = i
            }
        }
    } else {
        deepest = depth;
    }

    if save[deepest] == 0 {
        return Err(SigScanError::InvalidMatch { name }.into());
    }

    let rva: isize = save[deepest].try_into()?;
    debug!("Found {} rva: {:x?}", name, rva);
    Ok(rva)
}

fn get_pat_len(pat: &[pat::Atom]) -> Result<u32> {
    let mut idx = 0;

    let mut len: u32 = 0;

    let mut depth = 0;
    let mut ext_range = 0u32;
    const SKIP_VA: u32 = mem::size_of::<Va>() as u32;

    while let Some(atom) = pat.get(idx).cloned() {
        idx += 1;
        match atom {
            pat::Atom::Byte(_) => {
                if depth == 0 {
                    len += 1;
                }
            }
            pat::Atom::Push(skip) => {
                if depth == 0 {
                    let skip = ext_range + skip as u32;
                    let skip = if skip == 0 { SKIP_VA } else { skip };
                    len = len.wrapping_add(skip);
                    ext_range = 0;
                }
                depth += 1;
            }
            pat::Atom::Pop => {
                depth -= 1;
            }
            pat::Atom::Skip(skip) => {
                if depth == 0 {
                    let skip = ext_range + skip as u32;
                    let skip = if skip == 0 { SKIP_VA } else { skip };
                    len = len.wrapping_add(skip);
                    ext_range = 0;
                }
            }
            pat::Atom::Rangext(ext) => {
                ext_range = ext as u32 * 256;
            }
            pat::Atom::ReadU8(_) | pat::Atom::ReadI8(_) => {
                if depth == 0 {
                    len += 1;
                }
            }
            pat::Atom::ReadU16(_) | pat::Atom::ReadI16(_) => {
                if depth == 0 {
                    len += 2;
                }
            }
            pat::Atom::ReadU32(_) | pat::Atom::ReadI32(_) => {
                if depth == 0 {
                    len += 4;
                }
            }
            pat::Atom::Ptr => {
                if depth == 0 {
                    len += SKIP_VA;
                }
            }
            pat::Atom::Jump1
            | pat::Atom::Jump4
            | pat::Atom::Fuzzy(_)
            | pat::Atom::Save(_)
            | pat::Atom::Pir(_)
            | pat::Atom::Check(_)
            | pat::Atom::Aligned(_)
            | pat::Atom::Zero(_)
            | pat::Atom::Nop => ( /* ignore */ ),

            pat::Atom::VTypeName
            | pat::Atom::Back(_)
            | pat::Atom::Many(_)
            | pat::Atom::Case(_)
            | pat::Atom::Break(_) => return Err(ProcLoaderError::BadSignature {}.into()),
        }
    }
    return Ok(len);
}
// Gets a heuristic excerpt from the pattern to use with fast byte searching
// Only a subset of the pattern syntax is supported. It is assumed it passed
// the "fixed length only" check of the get_pat_len function.
fn get_excerpt(pat: &[pat::Atom]) -> (Vec<u8>, usize) {
    let mut idx = 0;
    let mut staging: Vec<u8> = Vec::new();

    let mut offset: u32 = 0;

    let mut depth = 0;
    let mut ext_range = 0u32;
    const SKIP_VA: u32 = mem::size_of::<Va>() as u32;

    while let Some(atom) = pat.get(idx).cloned() {
        idx += 1;
        match atom {
            pat::Atom::Pop
            | pat::Atom::Jump1
            | pat::Atom::Jump4
            | pat::Atom::Ptr
            | pat::Atom::Push(_)
            | pat::Atom::Skip(_)
            | pat::Atom::Fuzzy(_) => {
                if staging.len() >= 3 {
                    break;
                } else {
                    staging.clear();
                }
            }
            _ => (),
        }
        match atom {
            pat::Atom::Byte(pat_byte) => {
                if depth == 0 {
                    staging.push(pat_byte);
                    offset += 1;
                }
            }
            pat::Atom::Push(skip) => {
                if depth == 0 {
                    let skip = ext_range + skip as u32;
                    let skip = if skip == 0 { SKIP_VA } else { skip };
                    offset = offset.wrapping_add(skip);
                    ext_range = 0;
                }
                depth += 1;
            }
            pat::Atom::Pop => {
                depth -= 1;
            }
            pat::Atom::Skip(skip) => {
                if depth == 0 {
                    let skip = ext_range + skip as u32;
                    let skip = if skip == 0 { SKIP_VA } else { skip };
                    offset = offset.wrapping_add(skip);
                    ext_range = 0;
                }
            }
            pat::Atom::ReadU8(_) | pat::Atom::ReadI8(_) => {
                if depth == 0 {
                    offset += 1;
                }
            }
            pat::Atom::ReadU16(_) | pat::Atom::ReadI16(_) => {
                if depth == 0 {
                    offset += 2;
                }
            }
            pat::Atom::ReadU32(_) | pat::Atom::ReadI32(_) => {
                if depth == 0 {
                    offset += 4;
                }
            }
            pat::Atom::Ptr => {
                if depth == 0 {
                    offset += SKIP_VA;
                }
            }

            pat::Atom::Rangext(ext) => {
                ext_range = ext as u32 * 256;
            }
            pat::Atom::Jump1
            | pat::Atom::Jump4
            | pat::Atom::Fuzzy(_)
            | pat::Atom::Save(_)
            | pat::Atom::Pir(_)
            | pat::Atom::Check(_)
            | pat::Atom::Aligned(_)
            | pat::Atom::Zero(_)
            | pat::Atom::Nop => ( /* ignore */ ),

            pat::Atom::VTypeName
            | pat::Atom::Back(_)
            | pat::Atom::Many(_)
            | pat::Atom::Case(_)
            | pat::Atom::Break(_) => {
                ( /* bad case */ )
            }
        }
    }
    let staging_len = staging.len();
    return (staging, (offset as usize) - staging_len);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SIG: &[pat::Atom] = pat!("E8 $ { 48 39 0D ? FF FE $ { ' } } 8D 4B C4");
    const BAD_SIG: &[pat::Atom] = pat!("E8 (01 02 | 03 04 05) 8D 4B C4");

    #[test]
    fn test_correct_pat_len() {
        match get_pat_len(TEST_SIG) {
            Ok(pat_len) => assert_eq!(pat_len, 8),
            Err(e) => panic!("Got error from pat_len: {:?}", e),
        }
    }

    #[test]
    fn test_incorrect_pat_len() {
        match get_pat_len(BAD_SIG) {
            Ok(_pat_len) => panic!("Bad sig should return error"),
            Err(_e) => (),
        }
    }

    #[test]
    fn test_correct_excerpt() {
        let (excerpt, offset) = get_excerpt(TEST_SIG);

        let expected_excerpt: Vec<u8> = vec![0x8D, 0x4B, 0xC4];
        assert_eq!(excerpt, expected_excerpt);

        assert_eq!(offset, 5)
    }
}
