use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

#[repr(u8)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum MessageOps {
    Debug,
    Ping,
    Exit,
    Recv,
    Send,
    Option,
    RecvOther,
    SendOther,
}

impl From<u8> for MessageOps {
    fn from(val: u8) -> MessageOps {
        match val {
            0 => MessageOps::Debug,
            1 => MessageOps::Ping,
            2 => MessageOps::Exit,
            3 => MessageOps::Recv,
            4 => MessageOps::Send,
            5 => MessageOps::Option,
            6 => MessageOps::RecvOther,
            7 => MessageOps::SendOther,
            _ => MessageOps::Debug,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Payload {
    pub op: MessageOps,
    pub ctx: u32,
    pub data: Vec<u8>,
}

impl From<Bytes> for Payload {
    fn from(data: Bytes) -> Self {
        let mut b = data;
        Self {
            op: b.get_u8().into(),
            ctx: b.get_u32_le(),
            data: b.to_vec(),
        }
    }
}

impl From<Payload> for Bytes {
    fn from(val: Payload) -> Self {
        let mut buf = BytesMut::with_capacity(9 + val.data.len());
        buf.put_u8(val.op as u8);
        buf.put_u32_le(val.ctx);
        buf.put(val.data.as_slice());
        buf.freeze()
    }
}

pub struct PayloadCodec {
    ld_codec: LengthDelimitedCodec,
}
impl PayloadCodec {
    pub fn new() -> Self {
        PayloadCodec {
            ld_codec: LengthDelimitedCodec::builder()
                .little_endian()
                .length_field_offset(0)
                .length_field_length(4)
                .length_adjustment(-4)
                .new_codec(),
        }
    }
}

impl Default for PayloadCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for PayloadCodec {
    type Item = Payload;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Payload>> {
        match self.ld_codec.decode(src)? {
            Some(buf) => Ok(Some(buf.freeze().into())),
            None => Ok(None),
        }
    }
}

impl Encoder<Payload> for PayloadCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Payload, dst: &mut BytesMut) -> Result<(), io::Error> {
        self.ld_codec.encode(data.into(), dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_payloads() -> Vec<Payload> {
        vec![
            Payload {
                op: MessageOps::Debug,
                ctx: 100,
                data: vec![1, 2, 3],
            },
            Payload {
                op: MessageOps::Ping,
                ctx: 100,
                data: vec![1, 2, 3],
            },
            Payload {
                op: MessageOps::Exit,
                ctx: 100,
                data: vec![1, 2, 3],
            },
            Payload {
                op: MessageOps::Recv,
                ctx: 100,
                data: vec![1, 2, 3],
            },
            Payload {
                op: MessageOps::Send,
                ctx: 100,
                data: vec![1, 2, 3],
            },
            Payload {
                op: MessageOps::Option,
                ctx: 100,
                data: vec![1, 2, 3],
            },
            Payload {
                op: MessageOps::RecvOther,
                ctx: 100,
                data: vec![1, 2, 3],
            },
            Payload {
                op: MessageOps::SendOther,
                ctx: 100,
                data: vec![1, 2, 3],
            },
            Payload {
                op: MessageOps::Debug,
                ctx: 100,
                data: vec![1, 2, 3],
            },
        ]
    }

    #[test]
    fn encoder_handles_all_known_ops() {
        let payloads = expected_payloads();
        let mut buf = BytesMut::with_capacity(payloads.len() * 12);
        let mut codec = PayloadCodec::new();
        for payload in payloads {
            let payload_op = payload.op as u8;
            codec.encode(payload, &mut buf).unwrap();
            let expected: &[u8] = &[12, 0, 0, 0, payload_op, 100, 0, 0, 0, 1, 2, 3];
            let dst: &mut [u8] = &mut [0; 12];
            buf.copy_to_slice(dst);
            assert_eq!(dst, expected);
        }
    }
    #[test]
    fn decoder_handles_all_known_ops() {
        let data: &[u8] = &[
            12, 0, 0, 0, 0, 100, 0, 0, 0, 1, 2, 3, // Debug
            12, 0, 0, 0, 1, 100, 0, 0, 0, 1, 2, 3, // Ping
            12, 0, 0, 0, 2, 100, 0, 0, 0, 1, 2, 3, // Exit
            12, 0, 0, 0, 3, 100, 0, 0, 0, 1, 2, 3, // Recv
            12, 0, 0, 0, 4, 100, 0, 0, 0, 1, 2, 3, // Send
            12, 0, 0, 0, 5, 100, 0, 0, 0, 1, 2, 3, // Option
            12, 0, 0, 0, 6, 100, 0, 0, 0, 1, 2, 3, // RecvOther
            12, 0, 0, 0, 7, 100, 0, 0, 0, 1, 2, 3, // SendOther
            12, 0, 0, 0, 8, 100, 0, 0, 0, 1, 2, 3, // Catch-all debug
        ];
        let mut buf = BytesMut::from(data);
        let mut codec = PayloadCodec::new();
        let mut payloads: Vec<Payload> = Vec::new();

        while let Some(payload) = codec.decode(&mut buf).unwrap() {
            payloads.push(payload);
        }

        assert_eq!(payloads, expected_payloads())
    }
    #[test]
    fn decoder_gracefully_handles_partial_buffers() {
        let data: &[u8] = &[
            15, 0, 0, 0, 0, 100, 0, 0, 0, 4, 5, 6, 7, 8, 9, // Payload 1
            16, 0, 0, 0, 1, 101, 0, 0, 0, 4, 5, 6, 7, 8, 9, 10, // Payload 2
            14, 0, 0, 0, 0, // Partial
        ];
        let mut buf = BytesMut::from(data);
        let mut codec = PayloadCodec::new();
        let mut payloads: Vec<Payload> = Vec::new();

        while let Some(payload) = codec.decode(&mut buf).unwrap() {
            payloads.push(payload);
        }
        assert_eq!(
            payloads,
            vec![
                Payload {
                    op: MessageOps::Debug,
                    ctx: 100,
                    data: vec![4, 5, 6, 7, 8, 9],
                },
                Payload {
                    op: MessageOps::Ping,
                    ctx: 101,
                    data: vec![4, 5, 6, 7, 8, 9, 10],
                },
            ]
        );
    }
}
