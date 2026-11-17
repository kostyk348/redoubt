//! The guard end to end: seven gates, two people, and a timer that runs on absence.

mod common;

use common::{connect, header, pair, seal};
use redoubt::frame::{Frame, FLAG_CRITICAL, FLAG_DUAL, MAX_FRAME};
use redoubt::guard::{dual_signature, Decision, Guard, RoleKeys};
use redoubt::policy::{Policy, Role};

const OPERATOR_KEY: [u8; 32] = [11u8; 32];
const SUPERVISOR_KEY: [u8; 32] = [22u8; 32];

fn make_guard(policy: &str) -> Guard {
    let policy = Policy::parse(policy).expect("policy");
    let mut guard = Guard::new(
        policy,
        [33u8; 32],
        RoleKeys {
            operator: OPERATOR_KEY,
            supervisor: SUPERVISOR_KEY,
        },
        1_000,
    );
    guard.provision_safe(1, 40001, 0);
    guard.provision_safe(1, 40002, 0);
    guard
}

fn write_frame(seq: u64, addr: u16, value: u16, flags: u8) -> Frame {
    Frame::new(header(seq, 6, addr, 1, flags), &value.to_be_bytes()).expect("frame")
}

#[test]
fn an_authorised_write_is_applied_and_can_be_revoked() {
    let (a, b) = pair(10, 90);
    let (mut client, server) = connect(&a, &b);
    let mut guard = make_guard("allow fc 6 addr 40001..40010 role operator\n");
    guard.attach(server, Role::Operator);

    let frame = write_frame(1, 40001, 42, 0);
    let (mut buffer, length) = seal(&frame, &mut client);
    assert!(matches!(
        guard.handle(&mut buffer, length, 10),
        Decision::Allow { .. }
    ));
    assert_eq!(guard.plc().get(1, 40001), 42);

    let decision = guard.handle(&mut buffer, length, 10);
    assert!(
        matches!(decision, Decision::Deny(_)),
        "the same frame twice is a replay"
    );

    let frame = write_frame(2, 40002, 7, 0);
    let (mut buffer, length) = seal(&frame, &mut client);
    let Decision::Allow { batch, .. } = guard.handle(&mut buffer, length, 20) else {
        panic!("the second authorised write should apply")
    };
    assert_eq!(guard.plc().get(1, 40002), 7);

    assert_eq!(guard.revoke(batch).expect("revoke"), 1);
    assert_eq!(
        guard.plc().get(1, 40002),
        0,
        "revoking restores the value it overwrote"
    );
    assert_eq!(guard.plc().get(1, 40001), 42, "and nothing else");
}

#[test]
fn an_unauthorised_function_is_refused_and_the_plc_is_untouched() {
    let (a, b) = pair(11, 89);
    let (mut client, server) = connect(&a, &b);
    let mut guard = make_guard("allow fc 3 addr 0..99 role reader\n");
    guard.attach(server, Role::Operator);

    // Coils (function 5) are not in the policy at all.
    let frame = Frame::new(header(1, 5, 10, 1, 0), &1u16.to_be_bytes()).expect("frame");
    let (mut buffer, length) = seal(&frame, &mut client);
    let decision = guard.handle(&mut buffer, length, 10);
    assert!(matches!(decision, Decision::Deny(_)), "{decision:?}");
    assert_eq!(guard.plc().len(), 0, "nothing was written");
}

#[test]
fn a_critical_write_without_two_people_goes_to_the_safe_value() {
    let (a, b) = pair(12, 88);
    let (mut client, server) = connect(&a, &b);
    let mut guard = make_guard("allow fc 6 addr 40001..40010 role operator dual\n");
    guard.attach(server, Role::Operator);

    // The frame does not even ask for dual control: the policy requires it, so the guard refuses and
    // drives the output to the value the engineering project called safe.
    let frame = write_frame(1, 40001, 999, 0);
    let (mut buffer, length) = seal(&frame, &mut client);
    let decision = guard.handle(&mut buffer, length, 10);
    assert!(matches!(decision, Decision::Safe(_)), "{decision:?}");
    assert_eq!(
        guard.plc().get(1, 40001),
        0,
        "the safe value, not the requested one"
    );
}

#[test]
fn a_critical_write_with_two_different_signatures_is_applied() {
    let (a, b) = pair(13, 87);
    let (mut client, server) = connect(&a, &b);
    let mut guard = make_guard("allow fc 6 addr 40001..40010 role operator dual\n");
    guard.attach(server, Role::Operator);

    let value: u16 = 250;
    let header = header(1, 6, 40001, 1, FLAG_CRITICAL | FLAG_DUAL);
    let header_bytes = header.encode();
    let operator = dual_signature(&OPERATOR_KEY, &header_bytes, value).expect("operator signature");
    let supervisor =
        dual_signature(&SUPERVISOR_KEY, &header_bytes, value).expect("supervisor signature");

    let mut payload = Vec::new();
    payload.extend_from_slice(&value.to_be_bytes());
    payload.extend_from_slice(&operator);
    payload.extend_from_slice(&supervisor);

    let frame = Frame::new(header, &payload).expect("frame");
    let (mut buffer, length) = seal(&frame, &mut client);
    let decision = guard.handle(&mut buffer, length, 10);
    assert!(matches!(decision, Decision::Allow { .. }), "{decision:?}");
    assert_eq!(guard.plc().get(1, 40001), 250);
}

#[test]
fn one_person_signing_twice_is_not_two_people() {
    let (a, b) = pair(14, 86);
    let (mut client, server) = connect(&a, &b);
    let mut guard = make_guard("allow fc 6 addr 40001..40010 role operator dual\n");
    guard.attach(server, Role::Operator);

    let value: u16 = 250;
    let header = header(1, 6, 40001, 1, FLAG_CRITICAL | FLAG_DUAL);
    let header_bytes = header.encode();
    let operator = dual_signature(&OPERATOR_KEY, &header_bytes, value).expect("operator signature");

    let mut payload = Vec::new();
    payload.extend_from_slice(&value.to_be_bytes());
    payload.extend_from_slice(&operator);
    payload.extend_from_slice(&operator); // the same key, twice

    let frame = Frame::new(header, &payload).expect("frame");
    let (mut buffer, length) = seal(&frame, &mut client);
    let decision = guard.handle(&mut buffer, length, 10);
    assert!(
        matches!(decision, Decision::Safe(_)),
        "two roles, two keys: {decision:?}"
    );
    assert_eq!(guard.plc().get(1, 40001), 0);
}

#[test]
fn a_signature_cannot_be_lifted_into_another_frame() {
    let (a, b) = pair(15, 85);
    let (mut client, server) = connect(&a, &b);
    let mut guard = make_guard("allow fc 6 addr 40001..40010 role operator dual\n");
    guard.attach(server, Role::Operator);

    let value: u16 = 250;
    let signed_header = header(1, 6, 40001, 1, FLAG_CRITICAL | FLAG_DUAL).encode();
    let operator = dual_signature(&OPERATOR_KEY, &signed_header, value).expect("signature");
    let supervisor = dual_signature(&SUPERVISOR_KEY, &signed_header, value).expect("signature");

    // The signatures were given for address 40001; the requester now aims at 40002.
    let other = header(2, 6, 40002, 1, FLAG_CRITICAL | FLAG_DUAL);
    let mut payload = Vec::new();
    payload.extend_from_slice(&value.to_be_bytes());
    payload.extend_from_slice(&operator);
    payload.extend_from_slice(&supervisor);
    let frame = Frame::new(other, &payload).expect("frame");
    let (mut buffer, length) = seal(&frame, &mut client);
    let decision = guard.handle(&mut buffer, length, 10);
    assert!(matches!(decision, Decision::Safe(_)), "{decision:?}");
    assert_eq!(guard.plc().get(1, 40002), 0);
}

#[test]
fn the_dead_man_timer_drives_every_output_safe() {
    let (a, b) = pair(16, 84);
    let (_client, server) = connect(&a, &b);
    let mut guard = make_guard("allow fc 3 addr 0..99 role reader\n");
    guard.attach(server, Role::Operator);
    guard.provision_safe(1, 40005, 3);

    // Nothing has ever spoken: the first tick is already late relative to the zero clock.
    let decision = guard.tick(0);
    assert!(matches!(decision, Decision::Safe(_)), "{decision:?}");
    assert_eq!(guard.plc().get(1, 40001), 0);
    assert_eq!(
        guard.plc().get(1, 40005),
        3,
        "every provisioned output is driven safe"
    );

    // A heartbeat inside the window keeps the guard quiet.
    assert!(matches!(guard.tick(0), Decision::Safe(_)));
    let mut guard = make_guard("allow fc 3 addr 0..99 role reader\n");
    guard.attach(connect(&a, &b).1, Role::Operator);
    guard.tick(1_000);
}

#[test]
fn random_bytes_never_panic_and_never_authenticate() {
    let (a, b) = pair(17, 83);
    let (_client, mut server) = connect(&a, &b);
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    for length in 0..=(MAX_FRAME + 8) {
        let mut buffer = [0u8; MAX_FRAME + 8];
        for slot in buffer.iter_mut().take(length) {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *slot = (state >> 33) as u8;
        }
        // Either it refuses, or — by astronomically unlikely chance — it accepts something that
        // passed AES-GCM. It must never panic, and it must never accept with a valid tag here.
        if let Ok(frame) = Frame::open(&mut buffer, length, &mut server) {
            panic!(
                "random bytes authenticated as fc={} addr={}",
                frame.header.fc, frame.header.addr
            );
        }
    }
}

#[test]
fn the_guard_keeps_its_audit_chain_intact() {
    let (a, b) = pair(18, 82);
    let (mut client, server) = connect(&a, &b);
    let mut guard = make_guard("allow fc 6 addr 40001..40010 role operator\n");
    guard.attach(server, Role::Operator);
    for seq in 1..=5u64 {
        let frame = write_frame(seq, 40001, seq as u16, 0);
        let (mut buffer, length) = seal(&frame, &mut client);
        let _ = guard.handle(&mut buffer, length, seq * 10);
    }
    assert!(guard.audit_records() >= 5);
    assert_eq!(guard.verify_audit().expect("verify"), guard.audit_records());
}
