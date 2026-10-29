//! WISP v1 packets: a type byte, a little-endian stream id, then the payload.

use thiserror::Error;

const CONNECT: u8 = 0x01;
const DATA: u8 = 0x02;
const CONTINUE: u8 = 0x03;
const CLOSE: u8 = 0x04;
const INFO: u8 = 0x05;

const HEADER: usize = 5;

/// What a WISP stream carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    Tcp = 0x01,
    Udp = 0x02,
}

/// Why a stream closed, as the CLOSE packet says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseReason(pub u8);

impl CloseReason {
    pub const UNKNOWN: Self = Self(0x01);
    pub const VOLUNTARY: Self = Self(0x02);
    pub const NETWORK_ERROR: Self = Self(0x03);
    pub const INVALID_INFO: Self = Self(0x41);
    pub const UNREACHABLE_HOST: Self = Self(0x42);
    pub const NO_RESPONSE: Self = Self(0x43);
    pub const CONN_REFUSED: Self = Self(0x44);
    pub const TRANSFER_TIMEOUT: Self = Self(0x47);
    pub const HOST_BLOCKED: Self = Self(0x48);
    pub const CONN_THROTTLED: Self = Self(0x49);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Connect {
        stream: u32,
        kind: StreamKind,
        port: u16,
        host: String,
    },
    Data {
        stream: u32,
        data: Vec<u8>,
    },
    /// How many more DATA packets the server takes on `stream`; on stream 0, what every
    /// stream starts with.
    Continue {
        stream: u32,
        remaining: u32,
    },
    Close {
        stream: u32,
        reason: CloseReason,
    },
    /// WISP v2's handshake, which a v1 client never asks for.
    Info {
        stream: u32,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("a WISP packet of {0} bytes is shorter than its header")]
    Short(usize),
    #[error("a WISP packet of type {kind:#04x} has a {len}-byte payload")]
    Payload { kind: u8, len: usize },
    #[error("unknown WISP packet type {0:#04x}")]
    UnknownType(u8),
    #[error("unknown WISP stream type {0:#04x}")]
    UnknownStream(u8),
    #[error("a WISP CONNECT names a host that is not UTF-8")]
    Host,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let (kind, stream) = match self {
            Self::Connect { stream, .. } => (CONNECT, *stream),
            Self::Data { stream, .. } => (DATA, *stream),
            Self::Continue { stream, .. } => (CONTINUE, *stream),
            Self::Close { stream, .. } => (CLOSE, *stream),
            Self::Info { stream } => (INFO, *stream),
        };
        let mut out = Vec::with_capacity(HEADER + self.payload_len());
        out.push(kind);
        out.extend_from_slice(&stream.to_le_bytes());
        match self {
            Self::Connect {
                kind, port, host, ..
            } => {
                out.push(*kind as u8);
                out.extend_from_slice(&port.to_le_bytes());
                out.extend_from_slice(host.as_bytes());
            }
            Self::Data { data, .. } => out.extend_from_slice(data),
            Self::Continue { remaining, .. } => out.extend_from_slice(&remaining.to_le_bytes()),
            Self::Close { reason, .. } => out.push(reason.0),
            Self::Info { .. } => {}
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let (head, payload) = bytes
            .split_at_checked(HEADER)
            .ok_or(FrameError::Short(bytes.len()))?;
        let kind = head[0];
        let stream = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
        let short = || FrameError::Payload {
            kind,
            len: payload.len(),
        };
        Ok(match kind {
            CONNECT => {
                let [k, lo, hi, host @ ..] = payload else {
                    return Err(short());
                };
                let kind = match *k {
                    0x01 => StreamKind::Tcp,
                    0x02 => StreamKind::Udp,
                    other => return Err(FrameError::UnknownStream(other)),
                };
                let host = std::str::from_utf8(host).map_err(|_| FrameError::Host)?;
                Self::Connect {
                    stream,
                    kind,
                    port: u16::from_le_bytes([*lo, *hi]),
                    host: host.to_owned(),
                }
            }
            DATA => Self::Data {
                stream,
                data: payload.to_vec(),
            },
            CONTINUE => Self::Continue {
                stream,
                remaining: u32::from_le_bytes(payload.try_into().map_err(|_| short())?),
            },
            CLOSE => match payload {
                [reason] => Self::Close {
                    stream,
                    reason: CloseReason(*reason),
                },
                _ => return Err(short()),
            },
            INFO if payload.len() >= 2 => Self::Info { stream },
            INFO => return Err(short()),
            other => return Err(FrameError::UnknownType(other)),
        })
    }

    fn payload_len(&self) -> usize {
        match self {
            Self::Connect { host, .. } => 3 + host.len(),
            Self::Data { data, .. } => data.len(),
            Self::Continue { .. } => 4,
            Self::Close { .. } => 1,
            Self::Info { .. } => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_is_laid_out_as_the_spec_has_it() {
        let frame = Frame::Connect {
            stream: 0x0102_0304,
            kind: StreamKind::Tcp,
            port: 443,
            host: "example.com".into(),
        };
        let bytes = frame.encode();
        assert_eq!(
            &bytes[..8],
            [0x01, 0x04, 0x03, 0x02, 0x01, 0x01, 0xbb, 0x01]
        );
        assert_eq!(&bytes[8..], b"example.com");
        assert_eq!(Frame::decode(&bytes), Ok(frame));
    }

    #[test]
    fn every_client_and_server_frame_round_trips() {
        for frame in [
            Frame::Data {
                stream: 7,
                data: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
            },
            Frame::Data {
                stream: 7,
                data: vec![],
            },
            Frame::Continue {
                stream: 0,
                remaining: 128,
            },
            Frame::Close {
                stream: 9,
                reason: CloseReason::CONN_REFUSED,
            },
            Frame::Connect {
                stream: 2,
                kind: StreamKind::Udp,
                port: 53,
                host: "1.1.1.1".into(),
            },
        ] {
            assert_eq!(Frame::decode(&frame.encode()), Ok(frame));
        }
    }

    #[test]
    fn malformed_packets_are_refused() {
        assert_eq!(Frame::decode(&[0x02, 0, 0]), Err(FrameError::Short(3)));
        assert_eq!(
            Frame::decode(&[0x09, 0, 0, 0, 0]),
            Err(FrameError::UnknownType(0x09))
        );
        assert_eq!(
            Frame::decode(&[0x03, 0, 0, 0, 0, 1, 2]),
            Err(FrameError::Payload { kind: 0x03, len: 2 })
        );
        assert_eq!(
            Frame::decode(&[0x04, 0, 0, 0, 0]),
            Err(FrameError::Payload { kind: 0x04, len: 0 })
        );
        assert_eq!(
            Frame::decode(&[0x01, 0, 0, 0, 0, 0x07, 80, 0]),
            Err(FrameError::UnknownStream(0x07))
        );
        assert_eq!(
            Frame::decode(&[0x01, 0, 0, 0, 0, 0x01, 80, 0, 0xff]),
            Err(FrameError::Host)
        );
    }
}
