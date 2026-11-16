# РЕДУТ/1 — защищённый канал управления для ПЛК

**По-русски коротко.** Протокол и библиотека для управления ПЛК так, чтобы «правильный» с точки
зрения Modbus клиент не мог сделать что угодно: рукопожатие на Noise KK (X25519 + AES-256-GCM),
кадр с аутентификацией заголовка, окно повторов, которое не сбрасывается перезагрузкой, политика
«запрет побеждает разрешение», двойная подпись для опасных записей, обратимая запись и журнал-
цепочка. Отдельно — файл `lean/Redoubt.lean`: одиннадцать доказанных в Lean 4 утверждений о модели
решений (политика, окно, границы, счётчик загрузок, таймер безопасности, двойное управление).

Решения не «доверяй сканеру трафика»: политика пишется из проекта автоматизации (список I/O), а не
выучивается наблюдением. Агентов и почты в проекте нет — их предложили убрать, и это правильно:
чем меньше компонентов держат ключи, тем меньше поверхностей.

> Название протокола рабочее (РЕДУТ/1, `redoubt`). Переименуем, когда конструкция устоится.

## What this is

A guard that sits between a control network and a PLC, and a protocol for talking to it:

```text
 HMI / SCADA            РЕДУТ/1 channel                 guard                  PLC
 ───────────  ────────────────────────────────  ──────────────────────  ─────────────────
  request  ─▶  Noise KK handshake, then AEAD  ─▶  seven gates, in order  ─▶  plain Modbus/TCP
               frames with a replay window        (see below)               (unchanged)
```

The PLC is not modified: the guard is a bump-in-the-wire, with plain Modbus on its south side. Every
request passes seven gates, and a failure at any of them stops it:

1. **frame** — does it authenticate and parse as exactly one known operation?
2. **session** — does the frame belong to the open session?
3. **replay** — is the frame number fresh, given a 64-wide window and a persisted boot counter?
4. **policy** — deny-overrides, deny-by-default: is this function, span, unit and role allowed?
5. **dual control** — for critical outputs, two valid signatures from two different keys?
6. **audit** — can the decision be written to a hash chain? If not, nothing happens.
7. **apply** — writes are journalled with their previous values, so a batch can be revoked.

An eighth gate runs on a clock instead of a request: if the supervisor stops breathing, the guard
drives every output it knows a safe value for, and records that it did.

## Why it is built this way

- **No invented cryptography.** X25519, HKDF-SHA256, AES-256-GCM and HMAC-SHA256 come from audited
  crates; the composition is the Noise KK pattern (the shape WireGuard uses), not something we made
  up at three in the morning.
- **Deny-overrides, not first-match.** Order-dependent allow-lists are how people ship holes: an
  `allow` inserted above the protecting `deny` silently opens a pump. Here a denial anywhere wins.
- **Replay against reboots.** `engineBoots` is the SNMPv3 USM idea from 1998; a counter in RAM is
  reset by a power cut, a counter in a hash-chained file is not. If the file is edited, refused; if
  it is rolled back relative to a supervisor's copy, refused.
- **Reversibility.** Every applied batch keeps the values it overwrote. `revoke` puts them back, and
  the revocation is in the log. This is the answer to "two days without heating".
- **Fail-closed everywhere.** Unparsable frame, unknown function, missing signature, unwritable log
  — all four refuse; a critical write that cannot be authorised drives the output to its safe value
  rather than leaving it where it was.

## Quick start

```sh
cargo test          # 25 tests: handshake, frame, replay, policy, audit, guard end to end
cargo build --release
```

```rust
use redoubt::frame::{Frame, FrameHeader};
use redoubt::guard::{Decision, Guard, RoleKeys};
use redoubt::policy::{Policy, Role};
use redoubt::{Handshake, KeyPair};

// Provisioning: both sides know each other's static public key before the first byte.
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

let frame = Frame::new(FrameHeader { flags: 0, unit: 1, fc: 6, session_id: 0x1234, seq: 1, addr: 40001, qty: 1 }, &42u16.to_be_bytes())?;
let mut buffer = [0u8; redoubt::RECEIVE_BUFFER];
let length = frame.seal(&mut client, &mut buffer)?;
assert!(matches!(guard.handle(&mut buffer, length, 1_000), Decision::Allow { .. }));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## The policy file

```plumb
allow fc in {3,4} addr 0..499 role reader      # telemetry: read-only, everywhere in the shop
allow fc 6 addr 40001..40010 role operator    # setpoints: an operator, inside the working range
allow fc in {5,15} addr 0..99 role supervisor dual
deny  fc in {5,6} addr 0..99                  # emergency-stop wiring: never by wire
safe  fc 6 addr 500..599                      # on refusal, drive this range to its safe value
```

## Formal verification

`lean/Redoubt.lean` proves, in Lean 4 (no Mathlib), fifteen statements about the decision model. They
check with `lean lean/Redoubt.lean` (Lean 4.35.0, exit 0, no output) and their axiom footprint is
`[propext, choice, Quot.sound]` — the ordinary classical axioms, and **no `sorryAx`**, which is how a
"proof" with a hole would betray itself.

| # | theorem | what it says |
|---|---|---|
| 1 | `deny_overrides` | one matching `deny` beats every `allow`, in any order |
| 2 | `no_allow_no_allowance` | with no allow rule matching, the verdict is `safe` or `denied` |
| 3 | `allow_requires_a_rule` | an allow verdict exists only because an allow rule matched |
| 4 | `dual_needs_a_dual_rule` | allow-with-dual exists only because a dual rule matched |
| 5 | `no_double_accept` | a frame number accepted once is refused the second time |
| 6 | `window_bounded` | the replay window never remembers more than 65 numbers |
| 7 | `last_address_inside` | a validated address span cannot wrap past 65535 (`omega`) |
| 8 | `payload_bounded` | a validated write cannot exceed 125 registers / 250 bytes |
| 9 | `boots_monotone`, `boots_never_decrease` | the persisted boot counter strictly increases |
| 10 | `dead_man_fires`, `dead_man_quiet`, `dead_man_fires_late` | a guard that never heard its supervisor fails safe on the first tick; one inside the window does not; one silent too long does |
| 11 | `dual_keys_distinct` | one key cannot produce the two signatures dual control requires |

To check: `lean lean/Redoubt.lean` — it typechecks or it does not.

**What this is not.** These proofs are about a *model*, not about the compiled Rust, and not about
AES-GCM or X25519 (those are assumptions). "No overflow in the address span" is proved in `Nat`
arithmetic; the Rust side uses `saturating_add` and is tested, not proved. A proof is a reason to
trust the design, not a certificate that the binary is unhackable — read `SECURITY.md`.

## Repository layout

```text
src/crypto.rs     Noise KK handshake, session keys, AEAD seal/open
src/frame.rs      one frame layout, decoder that cannot panic, no allocations
src/replay.rs     sliding window + hash-chained engineBoots file
src/policy.rs     deny-overrides parser and evaluator, three verdicts
src/audit.rs      hash chain with HMAC checkpoints
src/guard.rs      the seven gates, dual control, revocation, dead-man timer
lean/Redoubt.lean   eleven theorems about the decision model
tests/            25 tests, no mocks, no network
```

## Licence

MIT OR Apache-2.0.
