//! РЕДУТ/1 — a control channel that fails closed.
//!
//! The design has one rule that outranks the rest: **anything that is not provably authorised does
//! not reach the PLC, and what is refused leaves the process in a state it can survive**. Every
//! other decision — the handshake, the frame, the policy language — is arranged to keep that rule
//! true when a component misbehaves, a cable is cut, or a byte is flipped.
//!
//! # What is here
//!
//! - [`crypto`] — the handshake. The **Noise KK** token sequence (`e, es, ss` / `e, ee, se`) with
//!   X25519, HKDF-SHA256 and AES-256-GCM, built on audited crates (`x25519-dalek`, `hkdf`, `sha2`,
//!   `aes-gcm`). Both static public keys must be known before the first byte, so authentication is
//!   mutual by construction and there is no PKI to misconfigure.
//! - [`frame`] — one fixed layout: 24-byte header, bounded payload, 16-byte tag. Decoding never
//!   allocates and never panics; a frame either verifies whole or is refused whole.
//! - [`replay`] — a 64-wide sliding window, plus `engine_boots`, the SNMPv3 USM idea that makes a
//!   PLC reboot unable to rewind the window. The counter is persisted in an append-only, hash-chained
//!   file: rolling it back is detected, and detection means refusal, not a warning.
//! - [`policy`] — deny-overrides, not first-match: a `deny` line wins over every `allow` line
//!   regardless of order, and no matching line means deny. Order-dependent allow-lists are how
//!   people ship holes.
//! - [`audit`] — a hash chain with HMAC-signed checkpoints. A rewritten record is detected; a
//!   truncated log is detected against its checkpoint; if the log cannot be written, the write it
//!   would have described is refused.
//! - [`guard`] — the state machine that ties the above together: verify, replay-check, authorise,
//!   require a second signature for critical outputs, apply reversibly, and fall to the safe state
//!   when the supervisor stops breathing.
//!
//! # What is deliberately absent
//!
//! No learning from traffic, no agents holding credentials, no email. A policy comes from the
//! engineering project (the I/O list), not from observation: observing a process teaches you what
//! an attacker who has been quiet for a month can also teach you.
//!
//! # Honest limits
//!
//! The handshake follows the Noise KK pattern but has **not** been cross-checked against a reference
//! Noise implementation (no `snow` crate was available offline). The primitives are audited; this
//! composition is not yet. Treat it as a design that can be reviewed and tested, not as certified
//! cryptography, and read `SECURITY.md` before putting it near a pump.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod audit;
pub mod crypto;
pub mod frame;
pub mod guard;
pub mod policy;
pub mod replay;
pub mod rtu;

/// Kani harnesses, compiled only under `cargo kani` — proofs over the code, not over the model.
#[cfg(kani)]
mod kani_proofs;

pub use audit::{AuditError, AuditLog};
pub use crypto::{Handshake, KeyPair, Session};
pub use frame::{Frame, FrameError, FrameHeader, Opcode};
pub use guard::{
    dual_signature, Clock, Decision, FixedClock, Guard, PlcMemory, RoleKeys, RECEIVE_BUFFER,
};
pub use policy::{Policy, PolicyError, Request, Role, Verdict};
pub use replay::{CounterStore, ReplayError, ReplayWindow};
pub use rtu::{crc16, parse as parse_rtu, Op as RtuOp, RtuError, MAX_ADU};
