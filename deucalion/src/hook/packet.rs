use core::slice;
use std::mem;

use anyhow::{Result, format_err};
use binary_layout::prelude::*;

binary_layout!(frame_header, LittleEndian, {
  magic: [u8; 16],
  timestamp: u64,
  size: u32,
  connection_type: u16,
  segment_count: u16,
  unknown_20: u8,
  compression: u8,
  unknown_22: u16,
  decompressed_length: u32,
});

binary_layout!(segment_header, LittleEndian, {
  size: u32,
  source_actor: u32,
  target_actor: u32,
  segment_type: u16,
  padding: u16,
});

binary_layout!(segment, LittleEndian, {
  header: segment_header::NestedView,
  data: [u8],
});

binary_layout!(ipc_header, LittleEndian, {
  reserved: u16,
  opcode: u16,
  padding: u16,
  server_id: u16,
  timestamp: u32,
  padding1: u32,
});

binary_layout!(ipc_packet, LittleEndian, {
  header: ipc_header::NestedView,
  data: [u8],
});

binary_layout!(deucalion_segment_header, LittleEndian, {
  source_actor: u32,
  target_actor: u32,
  timestamp: u64,
});

binary_layout!(deucalion_segment, LittleEndian, {
  header: deucalion_segment_header::NestedView,
  data: [u8],
});

pub(super) enum Packet {
    Ipc(Vec<u8>),
    ObfuscatedIpc {
        deucalion_segment_header: Vec<u8>,
        opcode: u16,
        data_len: usize,
    },
    Other(Vec<u8>),
}

/// Extract packets from a pointer to a frame. Ensure ptr_frame is a valid
/// pointer or the process will crash!
pub(super) unsafe fn extract_packets_from_frame(
    ptr_frame: *const u8,
    require_deobfuscation: bool,
) -> Result<Vec<Packet>> {
    if ptr_frame.is_null() {
        return Err(format_err!(
            "hook was called with a null pointer. Skipping."
        ));
    }
    let frame_header_bytes = slice::from_raw_parts(ptr_frame, 40);
    let frame_header = frame_header::View::new(frame_header_bytes);

    let compression: u8 = frame_header.compression().read();
    if compression != 0 {
        return Err(format_err!("packet is still compressed: {}", compression));
    }

    let num_segments: u16 = frame_header.segment_count().read();
    let frame_size: usize = frame_header.size().read() as usize;

    let frame_header_size = frame_header::SIZE.unwrap();

    if frame_size > 0x10000 || frame_size < frame_header_size {
        return Err(format_err!("frame_size is invalid: {}", frame_size));
    }

    let frame_data = slice::from_raw_parts(
        ptr_frame.add(frame_header_size),
        frame_size - frame_header_size,
    );

    let mut frame_data_offset: usize = 0;

    let mut packets = Vec::<Packet>::new();
    for _ in 0..num_segments {
        let segment_size = segment_header::size::read(&frame_data[frame_data_offset..]);
        let segment_header_size = segment_header::SIZE.unwrap();

        if segment_size > 0x10000 || (segment_size as usize) < segment_header_size {
            return Err(format_err!("segment_size is invalid: {}", frame_size));
        }

        let segment_bytes =
            &frame_data[frame_data_offset..frame_data_offset + segment_size as usize];
        let segment = segment::View::new(segment_bytes);
        frame_data_offset += segment_size as usize;

        if segment.header().segment_type().read() == 3 {
            // If IPC segment type, decode it and wrap it with a deucalion_segment
            let segment_header = segment.header();
            let deucalion_header_size = deucalion_segment_header::SIZE.unwrap();

            let payload_len = if require_deobfuscation {
                deucalion_header_size
            } else {
                deucalion_header_size + segment_size as usize - segment_header_size
            };
            let mut dst = Vec::<u8>::with_capacity(payload_len);
            let buf = dst.spare_capacity_mut();
            let buf: &mut [u8] = mem::transmute(buf);
            dst.set_len(payload_len);

            let mut deucalion_segment = deucalion_segment::View::new(buf);
            let mut dsh = deucalion_segment.header_mut();
            dsh.source_actor_mut()
                .write(segment_header.source_actor().read());
            dsh.target_actor_mut()
                .write(segment_header.target_actor().read());
            dsh.timestamp_mut().write(frame_header.timestamp().read());

            if require_deobfuscation {
                let ipc_packet = ipc_packet::View::new(segment.data());
                let opcode = ipc_packet.header().opcode().read();
                let data_len = segment.data().len();
                packets.push(Packet::ObfuscatedIpc {
                    deucalion_segment_header: dst,
                    opcode,
                    data_len,
                });
            } else {
                deucalion_segment.data_mut().copy_from_slice(segment.data());
                packets.push(Packet::Ipc(dst));
            }
        } else {
            // Otherwise just copy the segment as-is
            let dst = Vec::from(segment_bytes);
            packets.push(Packet::Other(dst));
        }
    }
    Ok(packets)
}

pub(super) unsafe fn reconstruct_deobfuscated_packet(
    expected_packet: Packet,
    source_actor: u32,
    data: *const u8,
) -> Result<Packet> {
    if let Packet::ObfuscatedIpc { deucalion_segment_header, opcode, data_len } = expected_packet {
        let header = deucalion_segment_header::View::new(&deucalion_segment_header);
        let expected_source_actor = header.source_actor().read();
        if source_actor != expected_source_actor {
            return Err(format_err!(
                "source_actor mismatch: expected {}, got {}",
                expected_source_actor,
                source_actor
            ));
        }
        let data_slice = slice::from_raw_parts(data, data_len);
        let data = ipc_packet::View::new(data_slice);
        if data.header().opcode().read() != opcode {
            return Err(format_err!(
                "opcode mismatch: expected {}, got {}",
                data.header().opcode().read(),
                opcode
            ));
        }

        let header_len = deucalion_segment_header.len();
        let mut dst = Vec::<u8>::with_capacity(header_len + data_len);
        let buf = dst.spare_capacity_mut();
        let buf: &mut [u8] = mem::transmute(buf);
        buf[..header_len].copy_from_slice(&deucalion_segment_header);
        buf[header_len..].copy_from_slice(data_slice);
        dst.set_len(header_len + data_len);

        return Ok(Packet::Ipc(dst));
    }

    Err(format_err!("packet is not an obfuscated IPC packet"))
}

#[cfg(test)]
mod tests {
    use super::*;
    const DUMMY_FRAME_DATA: [u8; 80] = [
        0x52, 0x52, 0xa0, 0x41, 0xff, 0x5d, 0x46, 0xe2, // magic (part 1)
        0x7f, 0x2a, 0x64, 0x4d, 0x7b, 0x99, 0xc4, 0x75, // magic (part 2)
        0xe6, 0xf6, 0x93, 0xda, 0x59, 0x01, 0x00, 0x00, // timestamp
        0x50, 0x00, 0x00, 0x00, // size
        0x00, 0x00, // connection_type
        0x01, 0x00, // segment_count
        0x01, 0x00, // unknown_20 and compression
        0x00, 0x00, // unknown_22
        0x00, 0x00, 0x00, 0x00, // decompressed_length
        // segment
        0x28, 0x00, 0x00, 0x00, // size
        0x01, 0x02, 0x03, 0x04, // source_actor
        0x05, 0x06, 0x07, 0x08, // target_actor
        0x03, 0x00, // segment_type
        0x00, 0x00, // padding
        // ipc_header
        0x14, 0x00, // reserved
        0x42, 0x01, // opcode
        0x00, 0x00, // padding
        0x22, 0x00, // server_id
        0x00, 0x00, 0x00, 0x00, // timestamp
        0x00, 0x00, 0x00, 0x00, // padding1
        0x15, 0xCD, 0x5B, 0x07, 0x42, 0xe0, 0x89, 0x58, // ipc_packet->data
    ];

    #[test]
    fn test_extract_packets_from_frame_without_obfuscation() {
        let packets =
            unsafe { extract_packets_from_frame(DUMMY_FRAME_DATA.as_ptr(), false).unwrap() };
        assert_eq!(packets.len(), 1);
        if let Packet::Ipc(data) = &packets[0] {
            let segment = deucalion_segment::View::new(data);
            assert_eq!(segment.header().source_actor().read(), 0x04030201);
            assert_eq!(segment.header().target_actor().read(), 0x08070605);
            // Ensure the timestamp matches the frame timestamp
            assert_eq!(segment.header().timestamp().read(), 0x159da93f6e6);
            let ipc = ipc_packet::View::new(segment.data());
            assert_eq!(ipc.header().opcode().read(), 0x142);
            assert_eq!(ipc.header().server_id().read(), 34);
            assert_eq!(ipc.data().len(), 8);
        } else {
            panic!("expected an Ipc Packet");
        }
    }

    #[test]
    fn test_extract_packets_from_frame_with_obfuscation() {
        let packets =
            unsafe { extract_packets_from_frame(DUMMY_FRAME_DATA.as_ptr(), true).unwrap() };
        assert_eq!(packets.len(), 1);
        if let Packet::ObfuscatedIpc { deucalion_segment_header, opcode, data_len } = &packets[0] {
            let header = deucalion_segment_header::View::new(deucalion_segment_header);
            assert_eq!(header.source_actor().read(), 0x04030201);
            assert_eq!(header.target_actor().read(), 0x08070605);
            // Ensure the timestamp matches the frame timestamp
            assert_eq!(header.timestamp().read(), 0x159da93f6e6);
            assert_eq!(*opcode, 0x142);
            assert_eq!(*data_len, 24);
        } else {
            panic!("expected an ObfuscatedIpc Packet");
        }
    }

    #[test]
    fn test_reconstruct_deobfuscated_packet() {
        let packet = Packet::ObfuscatedIpc {
            deucalion_segment_header: vec![
                0x01, 0x02, 0x03, 0x04, // source_actor
                0x05, 0x06, 0x07, 0x08, // target_actor
                0xe6, 0xf6, 0x93, 0xda, 0x59, 0x01, 0x00, 0x00, // timestamp
            ],
            opcode: 0x142,
            data_len: 24,
        };

        let reconstructed = unsafe {
            reconstruct_deobfuscated_packet(packet, 0x04030201, DUMMY_FRAME_DATA[56..].as_ptr())
                .unwrap()
        };

        if let Packet::Ipc(data) = reconstructed {
            let segment = deucalion_segment::View::new(data);
            assert_eq!(segment.header().source_actor().read(), 0x04030201);
            assert_eq!(segment.header().target_actor().read(), 0x08070605);
            // Ensure the timestamp matches the frame timestamp
            assert_eq!(segment.header().timestamp().read(), 0x159da93f6e6);
            let ipc = ipc_packet::View::new(segment.data());
            assert_eq!(ipc.header().opcode().read(), 0x142);
            assert_eq!(ipc.header().server_id().read(), 34);
            assert_eq!(ipc.data().len(), 8);
        } else {
            panic!("expected an Ipc Packet");
        }
    }
}
