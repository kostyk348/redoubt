# Security policy and honest scope

## What this project claims

1. **The decision core refuses by default.** Unauthenticated, replayed, unauthorised, unsigned and
   unloggable requests do not reach the PLC. This is tested (25 tests) and, for the model, proved in
   Lean (`lean/Redoubt.lean`, 11 theorems).
2. **The cryptography is standard and borrowed.** X25519 (`x25519-dalek`), HKDF-SHA256 (`hkdf`,
   `sha2`), AES-256-GCM (`aes-gcm`), HMAC-SHA256 (`hmac`), constant-time comparison (`subtle`). The
   handshake follows the **Noise KK** token sequence.
3. **The window survives reboots.** `engine_boots` lives in an append-only, HMAC-chained file; a
   rollback against a supervisor's copy is refused.

## What this project does **not** claim

- **Not "unhackable", and not certified.** No third-party audit, no Common Criteria, no IEC 62443
  certification. A cryptographic composition of audited primitives is not itself audited.
- **The Lean proofs are about a model, not the binary.** They say the policy engine, the replay
  window, the arithmetic bounds, the boot counter, the dead-man timer and dual control behave as
  described. They do **not** say the compiled Rust is free of bugs, and they do not model AES-GCM or
  X25519 — those are assumptions.
- **The handshake has not been cross-checked against a reference Noise implementation.** The `snow`
  crate was not available offline when this was written. Before production use: run the
  `snow`-based cross-check (see the roadmap below) or replace our handshake with `snow` directly.
- **No timing side-channel analysis.** Tag comparisons use constant-time equality; the higher-level
  code does not claim constant-time behaviour.
- **Nothing about the PLC itself.** A PLC that accepts unauthenticated writes from a directly
  connected laptop is still that PLC. The guard protects the path it sits on, and it is itself a
  single point of failure — deploy two, and require agreement.
- **No key management.** Provisioning static keys, revoking them, and rotating them is out of scope
  here and is where most real deployments fail.

## Roadmap to stronger assurance

1. Cross-check the handshake against `snow` (Noise reference) with matching test vectors, or delete
   ours and use `snow`.
2. Symbolic verification of the handshake with **Tamarin** or **ProVerif**: mutual authentication,
   forward secrecy, resistance to key-compromise impersonation.
3. **Kani** harnesses over the Rust decision core, so the proofs cover the code and not only the
   model: no panics, no arithmetic overflow, refusal reachable only through the seven gates.
4. Cross-check the Lean model against the Rust implementation with a shared test vector file
   (same policy file, same requests, same verdicts) in CI.
5. External review by someone paid to break it.

## Reporting a problem

- **This project**: use GitHub's private vulnerability reporting ("Report a vulnerability" on the
  repository's Security tab). Please do not open a public issue for a security bug.
- **A bug in someone else's product found while using this**: report it to the vendor and to the
  coordination centre that covers it — in the United States, CISA (report@cisa.gov, 24/7 Operations
  Center); in the EU, the relevant national CSIRT; for ICS specifically, CISA's ICS programme
  publishes advisories and coordinates with vendors. Their coordinated-disclosure timelines apply,
  not ours.
- **About the protocol design itself**: this is a proposal, not a deployed standard. Critique is
  welcome as an ordinary issue; a design flaw is not a CVE.

## Note on reaching out to CISA (or IEC, or IETF) with this

Sending a protocol proposal to CISA is not a vulnerability report, and CISA does not "approve"
protocols. The realistic paths, in order of usefulness:

1. **IETF** — publish the frame and policy as an Internet-Draft (informational). That is how RFC 6588
   (ucode) and the Modbus serial-link security draft exist at all: as drafts, publicly, with a
   comment period.
2. **Modbus Organization** — the body that owns the Modbus Security specification (TLS profile on
   port 802). Our guard is complementary: it authorises operations, not just channels.
3. **IEC TC 65/SC 65A WG 15** — the group behind IEC 62351. Their profiles cover authentication for
   MMS/ICCP, not per-operation authorisation for Modbus.
4. **CISA / ICSJWG** — as a stakeholder contribution or a talk, not as a submission for approval.
5. **A peer-reviewed venue** (ACSAC, RAID, or an ICS workshop) — where a Lean-verified decision core
   for ICS is actually an argument, because the proofs are checkable.

What makes any of these conversations worth having: a working implementation, tests, a proof
artifact, and an honest list of what is *not* covered — which is what this file is.
