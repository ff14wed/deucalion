use anyhow::{Result, bail};

/// Register enum for the supported registers in mov instruction disassembly
#[repr(usize)]
#[derive(Debug, PartialEq, Eq)]
pub enum Register {
    Rbx = 0,
    Rdi,
    Rsi,
    R12,
    R13,
    R14,
    R15,
}

/// Limited disassembler a 3-byte mov rxx, ryy instruction
///
/// Returns (source_reg, dest_reg) for the instruction.
/// Only supports registers rbx, rsi, rdi, r12-r15.
pub fn disassemble_mov_instruction(bytes: &[u8]) -> Result<(Register, Register)> {
    if bytes.len() != 3 {
        bail!("Expected exactly 3 bytes, got {}", bytes.len());
    }

    let rex = bytes[0];
    let opcode = bytes[1];
    let modrm = bytes[2];

    if !matches!(rex, 0x48 | 0x49 | 0x4C | 0x4D) {
        bail!("Invalid REX prefix: 0x{:02X}", rex);
    }

    if !matches!(opcode, 0x89 | 0x8B) {
        bail!("Invalid opcode: 0x{:02X}", opcode);
    }

    // modrm must indicate register-to-register
    if modrm < 0b1100_0000 {
        bail!("Invalid ModR/M byte: 0x{:02X}", modrm);
    }

    let modrm_offset = modrm - 0b1100_0000;
    let src_code = (modrm_offset >> 3) & 0b111;
    let dest_code = modrm_offset & 0b111;

    let src_reg = map_register_code_with_rex(src_code, rex, true)?;
    let dest_reg = map_register_code_with_rex(dest_code, rex, false)?;

    match opcode {
        0x89 => Ok((src_reg, dest_reg)),
        0x8B => Ok((dest_reg, src_reg)),
        _ => unreachable!(),
    }
}

fn map_register_code_with_rex(code: u8, rex: u8, is_src: bool) -> Result<Register> {
    let rex_bit = if is_src {
        (rex & 0x04) != 0 // REX.R
    } else {
        (rex & 0x01) != 0 // REX.B
    };

    let extended_code = code + if rex_bit { 8 } else { 0 };

    match extended_code {
        3 => Ok(Register::Rbx),
        6 => Ok(Register::Rsi),
        7 => Ok(Register::Rdi),
        12 => Ok(Register::R12),
        13 => Ok(Register::R13),
        14 => Ok(Register::R14),
        15 => Ok(Register::R15),
        _ => bail!(
            "Unsupported register code: {} (extended: {})",
            code,
            extended_code
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mov_instructions() {
        let test_cases = [
            // [rex, opcode, modrm], expected_result
            ([0x48, 0x89, 0xF3], (Register::Rsi, Register::Rbx)), // mov rbx, rsi
            ([0x4D, 0x89, 0xEC], (Register::R13, Register::R12)), // mov r12, r13
            ([0x48, 0x8B, 0xFE], (Register::Rsi, Register::Rdi)), // mov rdi, rsi
            ([0x48, 0x89, 0xFB], (Register::Rdi, Register::Rbx)), // mov rbx, rdi
            ([0x49, 0x89, 0xF4], (Register::Rsi, Register::R12)), // mov r12, rsi
            ([0x4C, 0x89, 0xF7], (Register::R14, Register::Rdi)), // mov rdi, r14
            ([0x4D, 0x89, 0xEF], (Register::R13, Register::R15)), // mov r15, r13
            ([0x49, 0x8B, 0xFC], (Register::R12, Register::Rdi)), // mov rdi, r12
            ([0x49, 0x8B, 0xFD], (Register::R13, Register::Rdi)), // mov rdi, r13
            ([0x4C, 0x89, 0xF3], (Register::R14, Register::Rbx)), // mov rbx, r14
            ([0x49, 0x8B, 0xF7], (Register::R15, Register::Rsi)), // mov rsi, r15
            ([0x49, 0x8B, 0xDE], (Register::R14, Register::Rbx)), // mov rbx, r14
            ([0x4D, 0x89, 0xFC], (Register::R15, Register::R12)), // mov r12, r15
            ([0x4D, 0x89, 0xF5], (Register::R14, Register::R13)), // mov r13, r14
            ([0x48, 0x89, 0xFE], (Register::Rdi, Register::Rsi)), // mov rsi, rdi
            ([0x48, 0x8B, 0xFB], (Register::Rbx, Register::Rdi)), // mov rdi, rbx
            ([0x4D, 0x8B, 0xFE], (Register::R14, Register::R15)), // mov r15, r14
            ([0x49, 0x89, 0xDC], (Register::Rbx, Register::R12)), // mov r12, rbx
        ];

        for (bytes, expected) in test_cases {
            let result = disassemble_mov_instruction(&bytes).unwrap();
            assert_eq!(result, expected, "Failed for bytes: {:02X?}", bytes);
        }
    }

    #[test]
    fn test_invalid_rex() {
        let bytes = [0x47, 0x89, 0xC0]; // Invalid REX
        assert!(disassemble_mov_instruction(&bytes).is_err());
    }

    #[test]
    fn test_invalid_opcode() {
        let bytes = [0x48, 0x88, 0xC0]; // Invalid opcode
        assert!(disassemble_mov_instruction(&bytes).is_err());
    }

    #[test]
    fn test_invalid_modrm() {
        let bytes = [0x48, 0x89, 0xBF]; // ModR/M < 0xC0
        assert!(disassemble_mov_instruction(&bytes).is_err());
    }

    #[test]
    fn test_wrong_byte_count() {
        let bytes = [0x48, 0x89]; // Only 2 bytes
        assert!(disassemble_mov_instruction(&bytes).is_err());
    }
}
