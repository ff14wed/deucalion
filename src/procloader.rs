use std::{mem, ptr};

use winapi::shared::minwindef;
use winapi::shared::minwindef::MAX_PATH;
use winapi::um::libloaderapi;

use std::ffi::OsString;
use std::os::windows::prelude::OsStringExt;

use anyhow::{Context, Result};
use thiserror::Error;

use pelite::pattern as pat;
use pelite::pe::image::{Rva, Va};
use pelite::pe::Pe;

use memchr::memmem;

use log::{debug, info};

#[derive(Debug, Error)]
enum ProcLoaderError {
    #[error("cannot find load address for module: {}", name)]
    ModuleNotFound { name: &'static str },
}

#[derive(Debug, Error)]
enum SigScanError {
    #[error("Could not find a signature match for {}", name)]
    MatchNotFound { name: &'static str },
    #[error("The signature for {} matched something invalid", name)]
    InvalidMatch { name: &'static str },
    #[error("Signature has no predetermined match length.")]
    BadSignature {},
}

pub fn get_ffxiv_handle() -> Result<*const u8> {
    unsafe {
        let handle_ffxiv = libloaderapi::GetModuleHandleW(ptr::null()) as *const u8;
        if handle_ffxiv.is_null() {
            return Err(ProcLoaderError::ModuleNotFound { name: "ffxiv" }.into());
        }
        Ok(handle_ffxiv)
    }
}

pub fn get_ffxiv_filepath() -> Result<String> {
    let mut file_name_buf = [0u16; MAX_PATH];
    let length_read = unsafe {
        libloaderapi::GetModuleFileNameW(
            0 as minwindef::HMODULE,
            file_name_buf.as_mut_ptr(),
            file_name_buf.len() as _,
        )
    };
    if length_read == 0 {
        return Err(ProcLoaderError::ModuleNotFound { name: "ffxiv" }.into());
    }

    let file_name_str = OsString::from_wide(&file_name_buf);
    Ok(file_name_str
        .to_str()
        .context("could not convert FFXIV file path to UTF-8")?
        .to_string())
}

/// Searches for a pattern using an excerpt finding method. This function
/// returns only one search result.
///
/// # Arguments
/// * `pat` - pattern to match
/// * `pe` - the PE to search through
/// * `save` - each level of the result is saved as additional entries in this
/// array
/// * `search_start_rva` - Optionally specify that the search range starts at a
/// different relative virtual address. Set to 0 for starting at the beginning.
pub fn fast_pattern_scan<'a, P: Pe<'a>>(
    pat: &[pat::Atom],
    pe: P,
    save: &mut [Rva],
    search_start_rva: usize,
) -> Result<bool> {
    let (pat_len, excerpt, excerpt_offset) = get_pat_len_and_excerpt(pat)?;
    let image_range = pe.headers().code_range();
    let image = pe.image();
    let pattern_scanner = pe.scanner();

    let mut start = if search_start_rva == 0 {
        image_range.start as usize
    } else {
        search_start_rva
    };
    start += excerpt_offset;

    let end = image_range.end as usize;
    debug!(
        "Using pat len {pat_len:?} and excerpt {excerpt:x?} with excerpt_offset {excerpt_offset:?}"
    );
    let finder = memmem::Finder::new(excerpt.as_slice());

    while start < end {
        match finder.find(&image[start..end]) {
            Some(loc) => {
                let pattern_start = loc + start - excerpt_offset;
                let pattern_start_rva = pattern_start as u32;
                let pattern_end_rva = (pattern_start + pat_len) as u32;
                if pattern_scanner.finds(pat, pattern_start_rva..pattern_end_rva, save) {
                    return Ok(true);
                }
                // If pattern not found, continue
                start = pattern_start + excerpt_offset + excerpt.len();
            }
            None => return Ok(false),
        }
    }
    Ok(false)
}

/// Returns the addresses that match a given signature.
///
/// This function truncates the match list to at most 100 addresses.
pub fn find_pattern_matches<'a, P: Pe<'a>>(
    name: &'static str,
    pat: &[pat::Atom],
    pe: P,
) -> Result<Vec<usize>> {
    let mut addrs: Vec<usize> = Vec::new();

    let mut start_rva: usize = 0;

    for _ in 0..100 {
        // This loop should usually terminate early because it returns when the
        // pattern can no longer be found or if start_rva goes past the end of
        // the image range.

        let mut save = [0; 8];

        let match_found = fast_pattern_scan(pat, pe, &mut save, start_rva)?;
        if !match_found {
            break;
        }

        let mut deepest_match = 0;
        for m in save {
            if m > 0 {
                deepest_match = m
            }
        }

        if deepest_match == 0 {
            return Err(SigScanError::InvalidMatch { name }.into());
        }

        let rva: usize = deepest_match as usize;
        addrs.push(rva);

        start_rva = save[0] as usize + 1;
    }

    if addrs.is_empty() {
        return Err(SigScanError::MatchNotFound { name }.into());
    }
    info!("Found {name} addr(s): {addrs:x?}");
    Ok(addrs)
}

/// Gets the length of memory that the pattern would match as well as a
/// heuristic excerpt from the pattern to use with fast byte searching. Only a
/// subset of the pattern syntax is supported.
fn get_pat_len_and_excerpt(pat: &[pat::Atom]) -> Result<(usize, Vec<u8>, usize)> {
    let mut idx = 0;
    let mut excerpt: Vec<u8> = Vec::new();

    let mut pat_len: usize = 0;
    let mut offset: usize = 0;

    let mut depth = 0;

    let mut ext_range: usize = 0;
    const SKIP_VA: usize = mem::size_of::<Va>();

    while let Some(atom) = pat.get(idx).cloned() {
        idx += 1;
        // If the excerpt isn't long enough before a jump or fuzzy section then
        // clear it and look for another excerpt
        match atom {
            pat::Atom::Pop
            | pat::Atom::Jump1
            | pat::Atom::Jump4
            | pat::Atom::Ptr
            | pat::Atom::Push(_)
            | pat::Atom::Skip(_)
            | pat::Atom::Fuzzy(_) => {
                if excerpt.len() >= 3 {
                    break;
                } else {
                    excerpt.clear();
                }
            }
            _ => (),
        }
        match atom {
            pat::Atom::Byte(pat_byte) => {
                if depth == 0 {
                    pat_len += 1;

                    excerpt.push(pat_byte);
                    offset += 1;
                }
            }
            pat::Atom::Push(skip) => {
                if depth == 0 {
                    let skip = ext_range + skip as usize;
                    let skip = if skip == 0 { SKIP_VA } else { skip };
                    pat_len = pat_len.wrapping_add(skip);
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
                    let skip = ext_range + skip as usize;
                    let skip = if skip == 0 { SKIP_VA } else { skip };
                    pat_len = pat_len.wrapping_add(skip);
                    offset = offset.wrapping_add(skip);
                    ext_range = 0;
                }
            }
            pat::Atom::Rangext(ext) => {
                ext_range = ext as usize * 256;
            }
            pat::Atom::ReadU8(_) | pat::Atom::ReadI8(_) => {
                if depth == 0 {
                    offset += 1;
                    pat_len += 1;
                }
            }
            pat::Atom::ReadU16(_) | pat::Atom::ReadI16(_) => {
                if depth == 0 {
                    offset += 2;
                    pat_len += 2;
                }
            }
            pat::Atom::ReadU32(_) | pat::Atom::ReadI32(_) => {
                if depth == 0 {
                    offset += 4;
                    pat_len += 4;
                }
            }
            pat::Atom::Ptr => {
                if depth == 0 {
                    offset += SKIP_VA;
                    pat_len += SKIP_VA;
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
            | pat::Atom::Break(_) => return Err(SigScanError::BadSignature {}.into()),
        }
    }
    let excerpt_len = excerpt.len();
    Ok((pat_len, excerpt, offset - excerpt_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SIG: &[pat::Atom] = pat!("E8 $ { 48 39 0D ? FF FE $ { ' } } 8D 4B C4");
    const BAD_SIG: &[pat::Atom] = pat!("E8 (01 02 | 03 04 05) 8D 4B C4");

    #[test]
    fn test_correct_pat_len_and_excerpt() {
        let (pat_len, excerpt, excerpt_offset) = get_pat_len_and_excerpt(TEST_SIG).unwrap();

        assert_eq!(pat_len, 8);
        let expected_excerpt: Vec<u8> = vec![0x8D, 0x4B, 0xC4];
        assert_eq!(excerpt, expected_excerpt);

        assert_eq!(excerpt_offset, 5)
    }

    #[test]
    fn test_incorrect_pat_len() {
        if let Ok(_) = get_pat_len_and_excerpt(BAD_SIG) {
            panic!("Bad sig should return error");
        }
    }
}
