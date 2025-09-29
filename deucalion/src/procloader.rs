use std::{ffi::OsString, mem, os::windows::prelude::OsStringExt, ptr};

use anyhow::{Context, Result};
use log::{debug, info};
use memchr::memmem;
use pelite::{
    pattern as pat,
    pe::{
        Pe,
        image::{Rva, Va},
    },
};
use thiserror::Error;
use winapi::{
    shared::{minwindef, minwindef::MAX_PATH},
    um::libloaderapi,
};

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
    #[error("Complex signature cases are not supported")]
    ComplexSignatureCases {},
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
///   array
/// * `search_start_rva` - Optionally specify that the search range starts at a
///   different relative virtual address. Set to 0 for starting at the beginning.
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
    find_deepest_match: bool,
) -> Result<Vec<usize>> {
    let mut addrs = Vec::<usize>::new();

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

        let mut found_rva = save[0];
        if find_deepest_match {
            for m in save {
                if m > 0 {
                    found_rva = m;
                }
            }
        }

        if found_rva == 0 {
            return Err(SigScanError::InvalidMatch { name }.into());
        }

        addrs.push(found_rva as usize);
        start_rva = save[0] as usize + 1;
    }

    if addrs.is_empty() {
        return Err(SigScanError::MatchNotFound { name }.into());
    }
    info!("Found {name} addr(s): {addrs:x?}");
    Ok(addrs)
}

/// Returns the number of bytes that the case would match, and the index within
/// the pattern after the case block.
fn parse_pattern_case(
    expected_branch_len: u8,
    pat: &[pat::Atom],
    mut idx: usize,
) -> Result<(usize, usize)> {
    let mut last_case_atoms = 0;
    let mut num_bytes = 0;
    let mut allow_case = false;
    while let Some(atom) = pat.get(idx).cloned() {
        idx += 1;
        match atom {
            pat::Atom::Byte(_) if last_case_atoms > 0 => num_bytes += 1,
            pat::Atom::Byte(_) | pat::Atom::Nop => {}
            pat::Atom::Break(break_len) => {
                match pat.get(idx) {
                    Some(pat::Atom::Case(_)) => allow_case = true,
                    None => {
                        // Unexpected end of pattern
                        if break_len != 0 {
                            return Err(SigScanError::BadSignature {}.into());
                        }
                        break;
                    }
                    _ => {
                        // This is the last case branch
                        last_case_atoms = break_len;
                    }
                }
                continue;
            }
            pat::Atom::Case(branch_length) => {
                // Nested cases are not allowed
                // If any case has a the wrong branch length, fail
                if !allow_case || branch_length != expected_branch_len {
                    return Err(SigScanError::BadSignature {}.into());
                }
            }
            // Other atoms are not allowed inside a simple case
            _ => return Err(SigScanError::ComplexSignatureCases {}.into()),
        }
        allow_case = false;
        if last_case_atoms > 0 {
            last_case_atoms -= 1;
            if last_case_atoms == 0 {
                break;
            }
        }
    }

    Ok((num_bytes, idx))
}

/// Gets the length of memory that the pattern would match as well as a
/// heuristic excerpt from the pattern to use with fast byte searching. Only a
/// subset of the pattern syntax is supported.
/// Returns the length of bytes that the pattern would match, the excerpt, and
/// the offset of the excerpt within the bytes that the pattern would match.
fn get_pat_len_and_excerpt(pat: &[pat::Atom]) -> Result<(usize, Vec<u8>, usize)> {
    let mut idx = 0;
    let mut pat_len: usize = 0;
    let mut depth = 0;

    let mut best_excerpt = Vec::<u8>::new();
    let mut best_excerpt_offset = 0;
    let mut excerpt = Vec::<u8>::new();

    let mut ext_range: usize = 0;
    const SKIP_VA: usize = mem::size_of::<Va>();

    while let Some(atom) = pat.get(idx).cloned() {
        idx += 1;
        if depth == 0 {
            match atom {
                pat::Atom::Byte(_) => (),
                pat::Atom::VTypeName | pat::Atom::Back(_) | pat::Atom::Many(_) => {
                    return Err(SigScanError::BadSignature {}.into());
                }
                _ => {
                    // If we found a better excerpt before a jump or fuzzy section,
                    // save it. Otherwise, look for another excerpt.
                    if excerpt.len() >= best_excerpt.len() {
                        best_excerpt_offset = pat_len - excerpt.len();
                        best_excerpt = excerpt.clone();
                    }
                    excerpt.clear();
                }
            }
            match atom {
                pat::Atom::Byte(pat_byte) => {
                    pat_len += 1;
                    excerpt.push(pat_byte);
                }
                pat::Atom::Push(skip) => {
                    let skip = ext_range + skip as usize;
                    let skip = if skip == 0 { SKIP_VA } else { skip };
                    pat_len = pat_len.wrapping_add(skip);
                    ext_range = 0;
                }
                pat::Atom::Skip(skip) => {
                    let skip = ext_range + skip as usize;
                    let skip = if skip == 0 { SKIP_VA } else { skip };
                    pat_len = pat_len.wrapping_add(skip);
                    ext_range = 0;
                }
                pat::Atom::ReadU8(_) | pat::Atom::ReadI8(_) => pat_len += 1,
                pat::Atom::ReadU16(_) | pat::Atom::ReadI16(_) => pat_len += 2,
                pat::Atom::ReadU32(_) | pat::Atom::ReadI32(_) => pat_len += 4,
                pat::Atom::Ptr => pat_len += SKIP_VA,
                pat::Atom::Case(expected_branch_len) => {
                    let (len, new_idx) = parse_pattern_case(expected_branch_len, pat, idx)?;
                    pat_len += len;
                    idx = new_idx;
                    continue; // Continue to next atom after case block
                }
                _ => {}
            }
        }
        match atom {
            pat::Atom::Push(_) => depth += 1,
            pat::Atom::Pop => depth -= 1,
            pat::Atom::Rangext(ext) => ext_range = ext as usize * 256,
            _ => (),
        }
    }
    // Just use whatever bytes we have at the end if we didn't find a good one
    if best_excerpt.is_empty() || excerpt.len() > best_excerpt.len() {
        let offset = pat_len - excerpt.len();
        return Ok((pat_len, excerpt, offset));
    }
    Ok((pat_len, best_excerpt, best_excerpt_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SIG: &[pat::Atom] = pat!("E8 $ { 48 39 0D ? FF FE $ { ' } } 8D 4B C4 ? ? ? 41 81");
    const MULTIPLE_CASE_SIG: &[pat::Atom] = pat!("E8 (01 02 | 03 04 | 05 06 | 07 08) 8D 4B C4");
    const VARIABLE_LENGTH_SIG: &[pat::Atom] = pat!("E8 (01 02 03 | 03 04 05 06 | 07 08) 8D 4B C4");
    const NESTED_CASE_SIG: &[pat::Atom] = pat!("E8 (01 (02 | 03) | 04) 8D 4B C4");

    #[test]
    fn test_correct_pat_len_and_excerpt() {
        let (pat_len, excerpt, excerpt_offset) = get_pat_len_and_excerpt(TEST_SIG).unwrap();

        assert_eq!(pat_len, 13);
        let expected_excerpt: Vec<u8> = vec![0x8D, 0x4B, 0xC4];
        assert_eq!(excerpt, expected_excerpt);

        assert_eq!(excerpt_offset, 5)
    }

    #[test]
    fn test_multiple_case_pat() {
        let (pat_len, excerpt, excerpt_offset) =
            get_pat_len_and_excerpt(MULTIPLE_CASE_SIG).unwrap();

        assert_eq!(pat_len, 6);
        let expected_excerpt: Vec<u8> = vec![0x8D, 0x4B, 0xC4];
        assert_eq!(excerpt, expected_excerpt);

        assert_eq!(excerpt_offset, 3)
    }

    #[test]
    fn test_variable_length_pat() {
        if get_pat_len_and_excerpt(VARIABLE_LENGTH_SIG).is_ok() {
            panic!("Bad sig should return error");
        }
    }

    #[test]
    fn test_nested_case_pat() {
        if get_pat_len_and_excerpt(NESTED_CASE_SIG).is_ok() {
            panic!("Bad sig should return error");
        }
    }
}
