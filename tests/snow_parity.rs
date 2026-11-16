//! Parity with a reference implementation of Noise.
//!
//! The claim this file tests is the one an auditor would ask about first: *is this actually Noise
//! KK, or something that looks like it?* One side of the handshake here is `snow` (the reference
//! Noise implementation in Rust), the other side is ours. If the two can complete a handshake and
//! then exchange transport messages, our transcript, key schedule, nonce layout and AEAD usage are
//! the ones the specification defines.
//!
//! Why it matters: a hand-rolled key schedule that is self-consistent will pass every test we write
//! against ourselves, and still not interoperate with anything.

use redoubt::crypto::Handshake;
use redoubt::{KeyPair, Session};
use snow::params::NoiseParams;
use snow::Builder;

const PROLOGUE: &[u8] = b"REDOUBT/1";

fn seed(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = value.wrapping_mul(17).wrapping_add(index as u8);
    }
    bytes
}

#[test]
fn a_reference_noise_peer_completes_a_handshake_with_us() {
    // Long-term keys: the same bytes on both sides, so the static DHs are the same.
    let station_secret = seed(3);
    let device_secret = seed(9);
    let station = KeyPair::from_bytes(station_secret);
    let device = KeyPair::from_bytes(device_secret);

    // Our initiator.
    let mut ours = Handshake::initiator(&station, device.public_bytes(), &[]);

    // `snow` as the responder, with the same static keys and the same prologue.
    let params: NoiseParams = "Noise_KK_25519_AESGCM_SHA256".parse().expect("params");
    let mut reference = Builder::new(params)
        .local_private_key(&device_secret)
        .remote_public_key(&station.public_bytes())
        .prologue(PROLOGUE)
        .build_responder()
        .expect("responder");

    // Message one: ours → the reference.
    let message_one = ours.write_message_1().expect("our message one");
    let mut payload = [0u8; 64];
    let read = reference.read_message(&message_one, &mut payload).expect("the reference accepts our message one");
    assert_eq!(read, 0, "no handshake payload");

    // Message two: the reference → ours.
    let mut message_two = [0u8; 96];
    let length = reference.write_message(&[], &mut message_two).expect("reference message two");
    ours.read_message_2(&message_two[..length]).expect("we accept the reference's message two");

    // Sessions on both sides. Session id zero keeps our transport nonce byte-for-byte the Noise one.
    let mut our_session = ours.finish(0).expect("our session");
    let mut reference = reference.into_transport_mode().expect("reference transport");

    // The reference sends, we receive.
    let mut frame = [0u8; 64];
    let written = reference.write_message(b"open the valve", &mut frame).expect("reference writes");
    let opened = our_session.open(&[], &mut frame, written).expect("we decrypt the reference's message");
    assert_eq!(&frame[..opened], b"open the valve");

    // We send, the reference receives.
    let mut ours_out = [0u8; 64];
    let plaintext = b"valve opened";
    ours_out[..plaintext.len()].copy_from_slice(plaintext);
    let sealed = our_session.seal(&[], &mut ours_out, plaintext.len()).expect("we seal");
    let mut received = [0u8; 64];
    let read = reference.read_message(&ours_out[..sealed], &mut received).expect("the reference decrypts our message");
    assert_eq!(&received[..read], plaintext);
}

#[test]
fn the_reference_refuses_a_modified_message_of_ours() {
    // Same setup, but the first message is altered: the reference must not accept it.
    let station_secret = seed(4);
    let device_secret = seed(10);
    let station = KeyPair::from_bytes(station_secret);
    let params: NoiseParams = "Noise_KK_25519_AESGCM_SHA256".parse().expect("params");
    let mut reference = Builder::new(params)
        .local_private_key(&device_secret)
        .remote_public_key(&station.public_bytes())
        .prologue(PROLOGUE)
        .build_responder()
        .expect("responder");

    let mut ours = Handshake::initiator(&station, KeyPair::from_bytes(device_secret).public_bytes(), &[]);
    let mut message_one = ours.write_message_1().expect("message one");
    let last = message_one.len() - 1;
    message_one[last] ^= 0x01;
    let mut payload = [0u8; 64];
    assert!(reference.read_message(&message_one, &mut payload).is_err(), "a flipped bit must not verify");
}

#[test]
fn the_reference_keys_differ_when_the_static_key_is_wrong() {
    // If the responder holds a different static key than the initiator thinks, the handshake must not
    // complete: this is the property that makes provisioning errors loud instead of silent.
    let station_secret = seed(5);
    let station = KeyPair::from_bytes(station_secret);
    let wrong_device = seed(11);
    let params: NoiseParams = "Noise_KK_25519_AESGCM_SHA256".parse().expect("params");
    let mut reference = Builder::new(params)
        .local_private_key(&wrong_device)
        .remote_public_key(&station.public_bytes())
        .prologue(PROLOGUE)
        .build_responder()
        .expect("responder");

    let mut ours = Handshake::initiator(&station, KeyPair::from_bytes(seed(21)).public_bytes(), &[]);
    let message_one = ours.write_message_1().expect("message one");
    let mut payload = [0u8; 64];
    assert!(reference.read_message(&message_one, &mut payload).is_err(), "wrong static key must fail");
}

/// Keep the unused import honest: `Session` is used in the type annotation above.
#[allow(dead_code)]
fn _session_is_used(_: Session) {}
