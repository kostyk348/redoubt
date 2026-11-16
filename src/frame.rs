//! One frame layout, and a decoder that cannot panic.
//!
//! ```text
//!  0      1      2      3        4..12      12..20     20..22   22..24   24..      24+n+16
//!  ver    flags  unit   fc       session    seq        addr     qty      payload   tag
//!  \_________________ authenticated header (24 bytes) ______________/  \__ AEAD __/
//! ```
//!
//! The header is the associated data, so a modified function code or address fails the tag instead
//! of being trusted. `seq` is inside the associated data as well — the replay window and the AEAD are
//! therefore not two independent opinions about the same frame.
//!
//! `Frame::open` copies at most [`MAX_FRAME`] bytes onto the stack and never allocates: an OT guard
//! that allocates is an OT guard that eventually pauses.

use crate::crypto::{CryptoError, Session, TAG};

/// Version byte. A different version is a different protocol, not a negotiation.
pub const VERSION: u8 = 1;
pub const HEADER: usize = 24;
/// Largest payload: 125 registers (the Modbus limit) × 2 bytes.
pub const MAX_PAYLOAD: usize = 250;
pub const MAX_FRAME: usize = HEADER + MAX_PAYLOAD + TAG;

pub const FLAG_RESPONSE: u8 = 0b0000_0001;
pub const FLAG_CRITICAL: u8 = 0b0000_0010;
pub const FLAG_DUAL: u8 = 0b0000_0100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooShort { got: usize },
    TooLong { got: usize },
    UnknownVersion(u8),
    UnknownFunction(u8),
    PayloadMismatch { fc: u8, qty: u16, payload: usize },
    Crypto(CryptoError),
}

impl From<CryptoError> for FrameError {
    fn from(error: CryptoError) -> Self {
        FrameError::Crypto(error)
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooShort { got } => write!(f, "{got} bytes is shorter than a header"),
            FrameError::TooLong { got } => write!(f, "{got} bytes exceeds the {MAX_FRAME}-byte frame budget"),
            FrameError::UnknownVersion(v) => write!(f, "version {v} is not {VERSION}"),
            FrameError::UnknownFunction(fc) => write!(f, "function {fc} is not one this guard speaks"),
            FrameError::PayloadMismatch { fc, qty, payload } => {
                write!(f, "function {fc} with quantity {qty} cannot carry {payload} bytes")
            }
            FrameError::Crypto(error) => write!(f, "{error}"),
        }
    }
}

/// The operations a guard understands. Anything else is refused by name, never passed through: a
/// protocol that forwards unknown function codes is a protocol that forwards `0x2B` forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// Read holding or input registers (Modbus 3/4).
    ReadRegisters,
    /// Write one register (6) or one coil (5).
    WriteSingle,
    /// Write many registers (16) or coils (15).
    WriteMultiple,
    /// Read discrete inputs or coils (1/2).
    ReadBits,
}

impl Opcode {
    pub fn from_function(fc: u8) -> Result<Self, FrameError> {
        match fc {
            3 | 4 => Ok(Opcode::ReadRegisters),
            1 | 2 => Ok(Opcode::ReadBits),
            5 | 6 => Ok(Opcode::WriteSingle),
            15 | 16 => Ok(Opcode::WriteMultiple),
            other => Err(FrameError::UnknownFunction(other)),
        }
    }

    pub fn writes(&self) -> bool {
        matches!(self, Opcode::WriteSingle | Opcode::WriteMultiple)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub flags: u8,
    pub unit: u8,
    pub fc: u8,
    pub session_id: u64,
    pub seq: u64,
    pub addr: u16,
    pub qty: u16,
}

impl FrameHeader {
    pub fn encode(&self) -> [u8; HEADER] {
        let mut out = [0u8; HEADER];
        out[0] = VERSION;
        out[1] = self.flags;
        out[2] = self.unit;
        out[3] = self.fc;
        out[4..12].copy_from_slice(&self.session_id.to_be_bytes());
        out[12..20].copy_from_slice(&self.seq.to_be_bytes());
        out[20..22].copy_from_slice(&self.addr.to_be_bytes());
        out[22..24].copy_from_slice(&self.qty.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < HEADER {
            return Err(FrameError::TooShort { got: bytes.len() });
        }
        if bytes[0] != VERSION {
            return Err(FrameError::UnknownVersion(bytes[0]));
        }
        let mut session = [0u8; 8];
        session.copy_from_slice(&bytes[4..12]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&bytes[12..20]);
        let mut addr = [0u8; 2];
        addr.copy_from_slice(&bytes[20..22]);
        let mut qty = [0u8; 2];
        qty.copy_from_slice(&bytes[22..24]);
        Ok(Self {
            flags: bytes[1],
            unit: bytes[2],
            fc: bytes[3],
            session_id: u64::from_be_bytes(session),
            seq: u64::from_be_bytes(seq),
            addr: u16::from_be_bytes(addr),
            qty: u16::from_be_bytes(qty),
        })
    }

    pub fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }

    pub fn is_critical(&self) -> bool {
        self.flags & FLAG_CRITICAL != 0
    }

    pub fn wants_dual(&self) -> bool {
        self.flags & FLAG_DUAL != 0
    }
}

/// A frame with its payload copied into a fixed buffer.
#[derive(Clone, Debug)]
pub struct Frame {
    pub header: FrameHeader,
    payload: [u8; MAX_PAYLOAD],
    payload_len: usize,
}

impl Frame {
    pub fn new(header: FrameHeader, payload: &[u8]) -> Result<Self, FrameError> {
        let opcode = Opcode::from_function(header.fc)?;
        let expected = expected_payload(opcode, header.qty, header.wants_dual())?;
        if payload.len() != expected {
            return Err(FrameError::PayloadMismatch { fc: header.fc, qty: header.qty, payload: payload.len() });
        }
        let mut buffer = [0u8; MAX_PAYLOAD];
        buffer[..payload.len()].copy_from_slice(payload);
        Ok(Self { header, payload: buffer, payload_len: payload.len() })
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }

    /// Encrypt into `out`, returning the total length. Nothing is allocated.
    pub fn seal(&self, session: &mut Session, out: &mut [u8; MAX_FRAME]) -> Result<usize, FrameError> {
        let header = self.header.encode();
        out[..HEADER].copy_from_slice(&header);
        out[HEADER..HEADER + self.payload_len].copy_from_slice(self.payload());
        let body = HEADER + self.payload_len + TAG;
        let total = session.seal(&header, &mut out[HEADER..body], self.payload_len)?;
        Ok(HEADER + total)
    }

    /// Verify and decrypt in place. The buffer is consumed: on success it holds the plaintext, on
    /// failure the caller must discard it entirely.
    pub fn open(buffer: &mut [u8], length: usize, session: &mut Session) -> Result<Self, FrameError> {
        if length > MAX_FRAME {
            return Err(FrameError::TooLong { got: length });
        }
        if length < HEADER + TAG {
            return Err(FrameError::TooShort { got: length });
        }
        let mut header_bytes = [0u8; HEADER];
        header_bytes.copy_from_slice(&buffer[..HEADER]);
        let header = FrameHeader::decode(&header_bytes)?;
        let opcode = Opcode::from_function(header.fc)?;
        let plaintext = session.open(&header_bytes, &mut buffer[HEADER..length], length - HEADER)?;
        let expected = expected_payload(opcode, header.qty, header.wants_dual())?;
        if plaintext != expected {
            return Err(FrameError::PayloadMismatch { fc: header.fc, qty: header.qty, payload: plaintext });
        }
        let mut payload = [0u8; MAX_PAYLOAD];
        payload[..plaintext].copy_from_slice(&buffer[HEADER..HEADER + plaintext]);
        Ok(Self { header, payload, payload_len: plaintext })
    }
}

/// How many payload bytes a function code must carry. This is where a protocol earns its keep: a
/// mismatch is refused before the PLC ever sees the request.
///
/// A single write that asks for dual control carries its two signatures after the value: 2 bytes of
/// value, then the operator's 32-byte signature, then the supervisor's. Multi-register writes cannot
/// ask for dual control — a batch of two hundred values is not a decision two people can make.
pub fn expected_payload(opcode: Opcode, qty: u16, dual: bool) -> Result<usize, FrameError> {
    match opcode {
        Opcode::ReadRegisters | Opcode::ReadBits => {
            if qty == 0 || qty > 2000 {
                return Err(FrameError::PayloadMismatch { fc: 0, qty, payload: 0 });
            }
            Ok(0)
        }
        Opcode::WriteSingle => Ok(if dual { 2 + 64 } else { 2 }),
        Opcode::WriteMultiple => {
            if dual {
                return Err(FrameError::PayloadMismatch { fc: 16, qty, payload: 66 });
            }
            let bytes = usize::from(qty) * 2;
            if bytes == 0 || bytes > MAX_PAYLOAD {
                return Err(FrameError::PayloadMismatch { fc: 16, qty, payload: bytes });
            }
            Ok(bytes)
        }
    }
}
