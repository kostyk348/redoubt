//! The handshake, the frame, the replay window, the policy and the audit chain — each on its own.

mod common;

use common::{connect, header, pair, seal};
use oplot::audit::AuditLog;
use oplot::crypto::{Handshake, MESSAGE};
use oplot::frame::{Frame, MAX_FRAME};
use oplot::policy::{Policy, Request, Role, Verdict};
use oplot::replay::{CounterStore, ReplayError, ReplayWindow};

#[test]
fn a_handshake_leaves_both_sides_able_to_talk() {
    let (a, b) = pair(1, 99);
    let (mut client, mut server) = connect(&a, &b);

    let frame = Frame::new(header(1, 3, 0, 10, 0), &[]).expect("frame");
    let (mut buffer, length) = seal(&frame, &mut client);
    let opened = Frame::open(&mut buffer, length, &mut server).expect("server opens");
    assert_eq!(opened.header.fc, 3);
    assert_eq!(opened.header.qty, 10);
    assert!(opened.payload().is_empty());
}

#[test]
fn a_modified_handshake_message_is_refused() {
    let (a, b) = pair(2, 98);
    let prologue = b"plant-7/unit-1";
    let mut initiator = Handshake::initiator(&a, b.public_bytes(), prologue);
    let mut responder = Handshake::responder(&b, a.public_bytes(), prologue);
    let mut message_one = initiator.write_message_1().expect("message one");
    message_one[MESSAGE - 1] ^= 0x01;
    assert!(responder.read_message_1(&message_one).is_err(), "a flipped tag bit must not verify");
}

#[test]
fn an_impostor_holding_the_wrong_static_key_cannot_get_in() {
    // The impostor knows the responder's public key (it is public) but not the static key the
    // responder expects; the first message's tag is what exposes that.
    let responder_key = common::key_pair(50);
    let real_client = common::key_pair(51);
    let impostor = common::key_pair(52);
    let prologue = b"plant-7/unit-1";

    let mut responder = Handshake::responder(&responder_key, real_client.public_bytes(), prologue);
    let mut attacker = Handshake::initiator(&impostor, responder_key.public_bytes(), prologue);
    let message_one = attacker.write_message_1().expect("message one");
    let error = responder.read_message_1(&message_one).unwrap_err();
    assert!(error.to_string().contains("authentication"), "{error}");
}

#[test]
fn a_flipped_bit_in_the_header_or_the_payload_is_refused() {
    let (a, b) = pair(3, 97);
    let (mut client, mut server) = connect(&a, &b);

    let frame = Frame::new(header(1, 6, 40001, 1, 0), &7u16.to_be_bytes()).expect("frame");

    // Payload byte.
    let (mut buffer, length) = seal(&frame, &mut client);
    buffer[26] ^= 0x01;
    assert!(Frame::open(&mut buffer, length, &mut server).is_err(), "payload bit flip");

    // Header byte: the function code is part of the associated data.
    let (mut buffer, length) = seal(&frame, &mut client);
    buffer[3] = 16;
    assert!(Frame::open(&mut buffer, length, &mut server).is_err(), "header bit flip");
}

#[test]
fn truncated_and_oversized_frames_are_refused_without_panicking() {
    let (a, b) = pair(4, 96);
    let (mut client, mut server) = connect(&a, &b);
    let frame = Frame::new(header(1, 5, 10, 1, 0), &1u16.to_be_bytes()).expect("frame");
    let (mut buffer, length) = seal(&frame, &mut client);

    assert!(Frame::open(&mut buffer, 10, &mut server).is_err(), "shorter than a header");
    let mut huge = [0u8; MAX_FRAME + 1];
    assert!(Frame::open(&mut huge, MAX_FRAME + 1, &mut server).is_err(), "over the budget");
    assert!(Frame::open(&mut buffer, length - 1, &mut server).is_err(), "one byte short");
}

#[test]
fn unknown_function_codes_are_refused_by_name() {
    let error = Frame::new(header(1, 43, 0, 1, 0), &[]).unwrap_err();
    assert!(error.to_string().contains("function 43"), "{error}");
}

#[test]
fn the_replay_window_accepts_fresh_out_of_order_and_refuses_the_rest() {
    let mut window = ReplayWindow::new();
    for seq in 1..=5 {
        assert!(window.check_and_update(seq).is_ok(), "frame {seq} is fresh");
    }
    assert_eq!(window.check_and_update(3), Err(ReplayError::Duplicate(3)));
    assert!(window.check_and_update(7).is_ok(), "a jump forward is fine");
    assert!(window.check_and_update(6).is_ok(), "and the gap can be filled");
    assert_eq!(window.check_and_update(0), Err(ReplayError::Zero));
    for _ in 0..100 {
        let _ = window.check_and_update(window.highest() + 1);
    }
    assert!(matches!(window.check_and_update(2), Err(ReplayError::TooOld(_))));
}

#[test]
fn after_a_restart_nothing_at_or_below_the_floor_is_fresh() {
    let mut window = ReplayWindow::from_highest(500);
    assert!(window.check_and_update(501).is_ok());
    assert!(window.check_and_update(500).is_err(), "the floor itself must not be accepted");
}

#[test]
fn the_counter_file_notices_edits_and_rollback() {
    let dir = std::env::temp_dir().join("oplot-counter-test");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("counter-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key = [7u8; 32];

    let mut store = CounterStore::open(&path, key).expect("open");
    assert_eq!(store.boots(), 0);
    assert_eq!(store.bump().expect("bump"), 1);
    assert_eq!(store.bump().expect("bump"), 2);
    drop(store);

    // Reopening verifies the chain and continues from where it stopped.
    let mut store = CounterStore::open(&path, key).expect("reopen");
    assert_eq!(store.boots(), 2);
    assert_eq!(store.records(), 2);

    // A supervisor that has seen a higher boots value exposes a replaced file.
    assert!(matches!(store.verify_against(5), Err(ReplayError::Rollback { .. })));
    assert!(store.verify_against(2).is_ok());

    // Editing a record breaks it.
    let text = std::fs::read_to_string(&path).expect("read");
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if let Some(first) = lines.first_mut() {
        *first = first.replace('1', "9");
    }
    std::fs::write(&path, lines.join("\n") + "\n").expect("write");
    assert!(CounterStore::open(&path, key).is_err(), "an edited record must not load");

    // A wrong key is a different chain.
    let _ = std::fs::remove_file(&path);
    let mut store = CounterStore::open(&path, key).expect("open");
    store.bump().expect("bump");
    assert!(CounterStore::open(&path, [8u8; 32]).is_err(), "the MAC key is part of the chain");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn deny_overrides_allow_whatever_the_order() {
    // The allow comes first, and the deny still wins: order-dependent allow-lists ship holes.
    let policy = Policy::parse(
        "allow fc 6 addr 40001..40010 role operator\n\
         deny  fc 6 addr 40005\n",
    )
    .expect("policy");
    let request = Request { fc: 6, unit: 1, addr: 40005, qty: 1, value: Some(10), role: Role::Operator };
    assert!(matches!(policy.evaluate(&request), Verdict::Deny(_)));
    let allowed = Request { fc: 6, unit: 1, addr: 40001, qty: 1, value: Some(10), role: Role::Operator };
    assert_eq!(policy.evaluate(&allowed), Verdict::Allow { dual: false });
}

#[test]
fn nothing_matches_means_nothing_is_allowed() {
    let policy = Policy::parse("allow fc 3 addr 0..499 role reader\n").expect("policy");
    let request = Request { fc: 16, unit: 1, addr: 40001, qty: 1, value: Some(1), role: Role::Supervisor };
    assert!(matches!(policy.evaluate(&request), Verdict::Deny(_)));
}

#[test]
fn a_rule_covers_the_whole_span_or_nothing() {
    // A rule for ten registers must not authorise a write that runs past the tenth.
    let policy = Policy::parse("allow fc 16 addr 40001..40010 role operator\n").expect("policy");
    let inside = Request { fc: 16, unit: 1, addr: 40001, qty: 10, value: None, role: Role::Operator };
    let past = Request { fc: 16, unit: 1, addr: 40001, qty: 11, value: None, role: Role::Operator };
    assert!(matches!(policy.evaluate(&inside), Verdict::Allow { .. }));
    assert!(matches!(policy.evaluate(&past), Verdict::Deny(_)));
}

#[test]
fn a_role_is_a_floor_not_an_equality() {
    let policy = Policy::parse("allow fc 6 addr 0..9 role operator\n").expect("policy");
    let as_reader = Request { fc: 6, unit: 1, addr: 1, qty: 1, value: Some(1), role: Role::Reader };
    let as_supervisor = Request { fc: 6, unit: 1, addr: 1, qty: 1, value: Some(1), role: Role::Supervisor };
    assert!(matches!(policy.evaluate(&as_reader), Verdict::Deny(_)));
    assert!(matches!(policy.evaluate(&as_supervisor), Verdict::Allow { .. }));
}

#[test]
fn the_policy_refuses_to_load_something_that_would_allow_everything() {
    assert!(Policy::parse("allow addr 0..10\n").is_err(), "a rule without fc matches every function");
    assert!(Policy::parse("allow fc 6 addr 10..1\n").is_err(), "a backwards range");
    assert!(Policy::parse("").is_err(), "an empty policy allows nothing, which is a configuration error");
}

#[test]
fn the_audit_chain_notices_an_edited_record() {
    let mut log = AuditLog::new([3u8; 32]).with_checkpoint_every(4);
    for index in 0..10 {
        log.append(&format!("entry {index}")).expect("append");
    }
    assert_eq!(log.verify().expect("verify"), 10);

    assert!(log.replace_for_test(4, "entry 4 (edited)"));
    assert!(log.verify().is_err(), "an edited record breaks every hash after it");
}

#[test]
fn truncation_is_caught_by_a_head_kept_elsewhere() {
    let mut log = AuditLog::new([4u8; 32]).with_checkpoint_every(4);
    for index in 0..10 {
        log.append(&format!("entry {index}")).expect("append");
    }
    let head_before = log.head();
    log.truncate_for_test(5);
    // The chain that remains is internally consistent — this is the honest limit of a log that
    // lives on the same disk as its attacker. What catches it is a head kept somewhere else.
    assert_eq!(log.verify().expect("the remainder still verifies"), 5);
    assert_ne!(log.head(), head_before, "the head moved, and the supervisor's copy says so");
}
