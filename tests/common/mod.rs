//! Shared helpers: a handshake between two in-memory peers, and frame plumbing.

use redoubt::crypto::{Handshake, KeyPair, Session};
use redoubt::frame::{Frame, FrameHeader, MAX_FRAME};

/// Fixed key material so tests are reproducible and never touch the system random source for the
/// long-term keys (the ephemerals are still random, as they must be).
pub fn key_pair(seed: u8) -> KeyPair {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    KeyPair::from_bytes(bytes)
}

pub fn pair(seed_a: u8, seed_b: u8) -> (KeyPair, KeyPair) {
    (key_pair(seed_a), key_pair(seed_b))
}

/// Run the whole handshake and return both sessions, initiator first.
pub fn connect(a: &KeyPair, b: &KeyPair) -> (Session, Session) {
    let prologue = b"plant-7/unit-1";
    let mut initiator = Handshake::initiator(a, b.public_bytes(), prologue);
    let mut responder = Handshake::responder(b, a.public_bytes(), prologue);
    let message_one = initiator.write_message_1().expect("message one");
    responder.read_message_1(&message_one).expect("responder reads one");
    let message_two = responder.write_message_2().expect("message two");
    initiator.read_message_2(&message_two).expect("initiator reads two");
    let client = initiator.finish(0x1234_5678).expect("client session");
    let server = responder.finish(0x1234_5678).expect("server session");
    (client, server)
}

pub fn header(seq: u64, fc: u8, addr: u16, qty: u16, flags: u8) -> FrameHeader {
    FrameHeader { flags, unit: 1, fc, session_id: 0x1234_5678, seq, addr, qty }
}

pub fn seal(frame: &Frame, session: &mut Session) -> ([u8; MAX_FRAME], usize) {
    let mut buffer = [0u8; MAX_FRAME];
    let length = frame.seal(session, &mut buffer).expect("seal");
    (buffer, length)
}
