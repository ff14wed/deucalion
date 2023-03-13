use core::slice;

use anyhow::{format_err, Result};
use binary_layout::prelude::*;

define_layout!(frame_header, LittleEndian, {
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

define_layout!(segment_header, LittleEndian, {
  size: u32,
  source_actor: u32,
  target_actor: u32,
  segment_type: u16,
  padding: u16,
});

define_layout!(segment, LittleEndian, {
  header: segment_header::NestedView,
  data: [u8],
});

define_layout!(ipc_header, LittleEndian, {
  reserved: u16,
  opcode: u16,
  padding: u16,
  server_id: u16,
  timestamp: u32,
  padding1: u32,
});

define_layout!(ipc_packet, LittleEndian, {
  header: ipc_header::NestedView,
  data: [u8],
});

define_layout!(deucalion_segment_header, LittleEndian, {
  source_actor: u32,
  target_actor: u32,
  timestamp: u64,
});

define_layout!(deucalion_segment, LittleEndian, {
  header: deucalion_segment_header::NestedView,
  data: [u8],
});

pub(super) enum Packet {
    IPC(Vec<u8>),
    Other(Vec<u8>),
}

/// Extract packets from a pointer to a frame. Ensure ptr_frame is a valid
/// pointer or the process will crash!
pub(super) unsafe fn extract_packets_from_frame(ptr_frame: *const u8) -> Result<Vec<Packet>> {
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

    let mut packets: Vec<Packet> = Vec::new();
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
            let payload_len = segment_size as usize - segment_header_size + deucalion_header_size;

            let mut dst = Vec::<u8>::with_capacity(payload_len);
            dst.set_len(payload_len);
            let buf: &mut [u8] = dst.as_mut();
            let mut deucalion_segment = deucalion_segment::View::new(buf);
            let mut dsh = deucalion_segment.header_mut();
            dsh.source_actor_mut()
                .write(segment_header.source_actor().read());
            dsh.target_actor_mut()
                .write(segment_header.target_actor().read());
            dsh.timestamp_mut().write(frame_header.timestamp().read());

            deucalion_segment.data_mut().copy_from_slice(segment.data());

            packets.push(Packet::IPC(dst));
        } else {
            // Otherwise just copy the segment as-is
            let mut dst = Vec::<u8>::with_capacity(segment_bytes.len());
            dst.set_len(segment_bytes.len());
            dst.copy_from_slice(segment_bytes);

            packets.push(Packet::Other(dst));
        }
    }
    return Ok(packets);
}
