# Redoubt/1 — a fail-closed control channel for PLCs

**English** · [Русский](README.ru.md)

[![CI](https://github.com/kostyk348/redoubt/actions/workflows/ci.yml/badge.svg)](https://github.com/kostyk348/redoubt/actions/workflows/ci.yml)
![tests](https://img.shields.io/badge/tests-48-brightgreen)
![clippy](https://img.shields.io/badge/clippy-warnings%20are%20errors-brightgreen)
![lean](https://img.shields.io/badge/lean-25%20theorems-blueviolet)
![noise](https://img.shields.io/badge/noise-parity%20with%20snow-informational)
[![rust](https://img.shields.io/badge/rust-1.80%2B-orange)](Cargo.toml)
![licence](https://img.shields.io/badge/licence-MIT-blue)

A **redoubt** is a small fort you hold from the inside. This repository is a protocol and a library
that stand between a control network and a PLC, and decide **per operation**, not per connection,
whether a request may reach the controller. The controller is not modified: plain Modbus/TCP on the
south side, Redoubt/1 on the north side.

## Why

Modbus has no authentication, no authorisation and no replay protection. The TLS-based Modbus
Security profile protects the **channel**, but an authenticated client may still invoke any function
code — including the one that writes to the register holding a pump. FrostyGoop (2024) spoke
Modbus/TCP directly to a district-heating process; advisory AA26-097A (2026) described attacks on
internet-facing PLCs through malicious project files and manipulated HMI data.

## Seven gates

Every request passes these in order, and a failure at any gate stops it:

1. **frame** — authenticates and parses as exactly one known operation (AEAD over a 24-byte header);
2. **session** — the frame belongs to the open session;
3. **replay** — the frame number is fresh, given a 64-wide window and a **boot counter that survives a power cut**;
4. **policy** — deny-overrides, deny-by-default: function, address span, unit, role;
5. **dual control** — for critical outputs, two signatures from two different keys;
6. **audit** — if the decision cannot be written to the hash chain, the operation **does not happen**;
7. **apply** — the write is journalled with the values it overwrote, so the batch can be revoked.

An eighth gate runs on a clock: if the supervisor stops sending heartbeats, every output with a
provisioned safe value is driven to it, and the event is recorded.

## What is verified

| check | result |
|---|---|
| `cargo test` | **48 tests** (guard, protocol, handshake parity) |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `lean lean/Redoubt.lean` | exit 0, **25 theorems**, axioms `propext`/`choice`/`Quot.sound`, no `sorryAx` |
| parity with `snow` (reference Noise) | handshake completes, transport decrypts both ways |
| `cargo kani` (in CI) | three harnesses: total decoding, total policy evaluation, no address wrap |

The parity check earned its keep: it found **two real bugs** — the prologue was hashed in two pieces
instead of one, and the pre-message public keys were never folded into the transcript. Both are fixed,
and `tests/snow_parity.rs` keeps them fixed.

## RS-485 / Modbus RTU: the south side

Real plants are RS-485 lines, not only IP. `src/rtu.rs` speaks Modbus RTU south of the guard:
one ADU in, exactly one operation out — and the **same** policy engine judges it (no second
authorisation language for the second transport). The decoder refuses rather than guesses:
trailing bytes (`TrailingBytes` — the link layer splits on silence, not on a second CRC),
unit 0 (`BroadcastUnit` — "everyone" is not an authorisation subject), coil writes that are
neither `0x0000` nor `0xFF00` (`BadValue`), spans that cross `0xFFFF` (`AddressWrap`), and
anything longer than 256 bytes (`TooLong` — refused, never truncated).

The model side gains five theorems: a CRC failure never becomes an operation, a wrapped span
never decodes, the broadcast address never decodes, decoding is the inverse of encoding, and
a success pins the frame to exactly one ADU of its function code's shape. Reference frames
from the Modbus over serial line specification (`01 03 00 00 00 01 84 0A`,
`11 03 00 6B 00 03 76 87`) are unit tests.

The link layer itself lives in `src/serial.rs`: T3.5 timing by the book (3.5 × 11-bit
"
       "characters, fixed 1.75 ms above 19200 baud), a `Port` trait so the default build stays
"
       "dependency-free and tests run on a virtual port with a virtual clock, and
"
       "`SerialLink::transact` — a valid request out, the answer read up to the silence gap,
"
       "decoded by the response-shaped parser, refused by name when a *different* unit answers.
"
       "The OS adapter (`serialport`) sits behind the `serial` feature. The north side stays
"
       "Redoubt/1 over IP: at 9600 baud a single ~100-byte frame costs about a second of line
"
       "time, which is the wrong budget for the heartbeat gate.

## Quick start

```sh
cargo test             # 48 tests
ci/run.sh              # everything CI runs: fmt, clippy, tests, lean
```

```rust
use redoubt::frame::{Frame, FrameHeader};
use redoubt::guard::{Decision, Guard, RoleKeys};
use redoubt::policy::{Policy, Role};
use redoubt::{Handshake, KeyPair};

let station = KeyPair::generate()?;
let device = KeyPair::generate()?;
let mut initiator = Handshake::initiator(&station, device.public_bytes(), b"plant-7/unit-1");
let mut responder = Handshake::responder(&device, station.public_bytes(), b"plant-7/unit-1");
let one = initiator.write_message_1()?;
responder.read_message_1(&one)?;
let two = responder.write_message_2()?;
initiator.read_message_2(&two)?;
let mut client = initiator.finish(0x1234)?;
let server = responder.finish(0x1234)?;

let policy = Policy::parse("allow fc 6 addr 40001..40010 role operator\n")?;
let mut guard = Guard::new(policy, [7u8; 32], RoleKeys { operator: [11u8; 32], supervisor: [22u8; 32] }, 1_000);
guard.provision_safe(1, 40001, 0);
guard.attach(server, Role::Operator);

let header = FrameHeader { flags: 0, unit: 1, fc: 6, session_id: 0x1234, seq: 1, addr: 40001, qty: 1 };
let frame = Frame::new(header, &42u16.to_be_bytes())?;
let mut buffer = [0u8; redoubt::RECEIVE_BUFFER];
let length = frame.seal(&mut client, &mut buffer)?;
assert!(matches!(guard.handle(&mut buffer, length, 1_000), Decision::Allow { .. }));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Policy

A policy is a text file of rule lines; `policy.example` is a working starting point.

```plumb
allow fc in {3,4} addr 0..499 role reader          # telemetry
allow fc 6 addr 40001..40010 role operator value in 0..1000
allow fc in {5,15} addr 100..199 role supervisor dual
deny  fc in {5,6,15,16} addr 0..99                 # emergency-stop wiring
safe  fc 6 addr 500..599                           # drive safe on refusal
```

A `deny` line wins over every `allow` line regardless of order, and no matching line is a denial.
Order-dependent allow-lists are how people ship holes.

## Repository layout

```text
src/crypto.rs       Noise KK handshake, session keys, AEAD seal/open
src/frame.rs        one frame layout, decoder that cannot panic, no allocations
src/replay.rs       sliding window + hash-chained engineBoots file
src/policy.rs       deny-overrides parser and evaluator, three verdicts
src/audit.rs        hash chain with HMAC checkpoints
src/guard.rs        the seven gates, dual control, revocation, dead-man timer
src/kani_proofs.rs  Kani harnesses (cfg(kani)), run in CI on Linux
lean/Redoubt.lean   25 theorems about the decision model (incl. the RTU south side)
tests/              48 tests, no mocks, no network
draft/              draft-kostyk-redoubt-00.txt — the Internet-Draft
ci/                 the same checks CI runs, for a local commit
```

## Documents

- [Internet-Draft](draft/draft-kostyk-redoubt-00.xml) — published as `draft-kostyk-redoubt-00` (https://www.ietf.org/archive/id/draft-kostyk-redoubt-00.txt)
- [Outreach](outreach/outreach.md) — ready-to-send texts: IOTOPS list, the Modbus serial-link authors, Modbus Organization, arXiv metadata
- [SECURITY.md](SECURITY.md) — threat model, what is proved and what is not, how to report a problem
- [lean/Redoubt.lean](lean/Redoubt.lean) — the proofs, with their axiom footprint

## What this is not

It does not replace network segmentation, does not save you from a project file an engineer signed
itself, does not promise confidentiality on a 9600 bit/s serial line, does not defend against a
compromised PLC firmware, and does not replace key management. The guard is a single point of failure
by construction: deploy two, and require them to agree. `SECURITY.md` lists every limit.

## Licence

MIT. Protocol name: Redoubt/1. Maintainer: Konstantin Parashchuk <lain90269@gmail.com>.
