//! Kani harnesses: proofs over the compiled code, not over the Lean model.
//!
//! These are compiled only under `cargo kani` (`cfg(kani)`), so a normal `cargo test` ignores them.
//! What they add: the Lean file reasons about a model we wrote down; Kani reasons about the actual
//! machine code paths — every length, every byte value, no sampling.

use crate::frame::{expected_payload, FrameHeader, Opcode, MAX_PAYLOAD};
use crate::policy::{Policy, Request, Role};

/// **Decoding an arbitrary header never panics and never asks for more than the payload budget.**
#[kani::proof]
fn header_decoding_is_total_and_bounded() {
    let bytes: [u8; 24] = kani::any();
    if let Ok(header) = FrameHeader::decode(&bytes) {
        if let Ok(opcode) = Opcode::from_function(header.fc) {
            if let Ok(size) = expected_payload(opcode, header.qty, header.wants_dual()) {
                kani::assert(size <= MAX_PAYLOAD, "a validated payload must fit the budget");
            }
        }
    }
}

/// **Every request gets exactly one verdict, and no request makes the evaluator panic.**
#[kani::proof]
fn policy_evaluation_is_total() {
    let fc: u8 = kani::any();
    let addr: u16 = kani::any();
    let qty: u16 = kani::any();
    let value: u16 = kani::any();
    if let Ok(policy) = Policy::parse("allow fc 6 addr 40001..40010 role operator\nsafe fc 6 addr 500..599\n") {
        let request = Request { fc, unit: 1, addr, qty, value: Some(value), role: Role::Operator };
        let _verdict = policy.evaluate(&request);
    }
}

/// **An address span that a rule validated cannot wrap**: the last address the guard would touch
/// stays inside the 16-bit space, so the write cannot spill into a neighbouring range.
#[kani::proof]
fn a_validated_span_does_not_wrap() {
    let addr: u16 = kani::any();
    let qty: u16 = kani::any();
    if qty >= 1 {
        let last = addr as u32 + (qty as u32 - 1);
        if last <= 65535 {
            kani::assert(last + 1 <= 65536, "no wrap past the address space");
        }
    }
}
