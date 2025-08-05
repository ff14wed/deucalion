use anyhow::Result;
use binary_layout::prelude::*;
use log::info;

binary_layout!(deucalion_segment, LittleEndian, {
    source_actor: u32,
    target_actor: u32,
    timestamp: u64,
    header: ipc_header::NestedView,
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

binary_layout!(ffxiv_segment_header, LittleEndian, {
    reserved: u16,
    opcode: u16,
    padding: u16,
    server_id: u16,
    timestamp: u32,
});

binary_layout!(ffxiv_segment, LittleEndian, {
    header: ffxiv_segment_header::NestedView,
    data: [u8],
});

pub fn print_deucalion_segment(data: &[u8]) -> Result<()> {
    let segment = deucalion_segment::View::new(data);
    if data.len() < ipc_header::SIZE.unwrap() + 16 {
        return Err(anyhow::anyhow!("Not enough data to parse segment"));
    }
    let source_actor = segment.source_actor().read();
    let target_actor = segment.target_actor().read();
    let timestamp = segment.timestamp().read();
    let opcode = segment.header().opcode().read();
    let data = segment.data().to_vec();
    info!("S: {source_actor} T: {target_actor} TS: {timestamp} O: {opcode:#x}, Data: {data:X?}",);

    Ok(())
}
