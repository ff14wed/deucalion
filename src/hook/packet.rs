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
