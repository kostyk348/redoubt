# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions follow [SemVer](https://semver.org/).

Entries come from `git log`; each item links its commit. Merge commits are not
listed. The repository has no tags yet, so the whole history is one `0.1.0`
section — the number matches `Cargo.toml` and the published Internet-Draft.

## [Unreleased]

Empty: no changes since the last release commit.

## [0.1.0] — 2026-11-16

First release: a fail-closed control channel for Modbus-era PLCs — protocol,
library, formal model and Internet-Draft.

### Added

- Protocol and library: Noise KK handshake, AEAD frames, replay window with a
  boot counter that survives a power cut, deny-overrides policy, dual control,
  reversible writes, hash-chained audit log; 25 tests at that point
  ([a6ab314](https://github.com/kostyk348/redoubt/commit/a6ab314)).
- Lean model: the whole decision path proved, 20 theorems, axioms limited to
  `propext`/`choice`/`Quot.sound`
  ([b052d5e](https://github.com/kostyk348/redoubt/commit/b052d5e),
  [603949d](https://github.com/kostyk348/redoubt/commit/603949d)).
- Internet-Draft `draft-kostyk-redoubt-00`: frame, handshake, replay window,
  policy language, dual control, reversible batches, audit chain, formal
  verification, limits
  ([4acba20](https://github.com/kostyk348/redoubt/commit/4acba20));
  RFCXML v3 for submission to the datatracker
  ([2a64729](https://github.com/kostyk348/redoubt/commit/2a64729)).
- Outreach: four ready-to-send texts — the IOTOPS list, a letter to the Modbus
  serial-link authors, the Modbus Organization technical committee, arXiv
  metadata (cs.CR)
  ([6489301](https://github.com/kostyk348/redoubt/commit/6489301)).
- CI: build, clippy, tests, Kani harnesses, Lean and snow parity
  ([66f8c2a](https://github.com/kostyk348/redoubt/commit/66f8c2a)).
- Bilingual README, badges, repository topics, MIT licence, `cfg(kani)` for
  clippy ([ec98c0a](https://github.com/kostyk348/redoubt/commit/ec98c0a)).
- `SECURITY.md` with the threat model and every limit of the design
  ([ec98c0a](https://github.com/kostyk348/redoubt/commit/ec98c0a)).

### Changed

- Project name fixed as **Redoubt/1**; the working name ОПЛОТ is retired
  ([f4f7e49](https://github.com/kostyk348/redoubt/commit/f4f7e49),
  [5686956](https://github.com/kostyk348/redoubt/commit/5686956)).
- README rewritten in English without the Russian block; the draft carries the
  real author address
  ([9f17939](https://github.com/kostyk348/redoubt/commit/9f17939)).
- `cargo fmt` applied across the tree; `lean-toolchain` pinned
  ([6a27a02](https://github.com/kostyk348/redoubt/commit/6a27a02)).

### Fixed

- snow parity found two real bugs — the prologue was hashed in two pieces and
  the pre-message public keys were never folded into the transcript
  ([fc44172](https://github.com/kostyk348/redoubt/commit/fc44172)).
- clippy `-D warnings` clean (unused `mut`, loop counter)
  ([e91db2f](https://github.com/kostyk348/redoubt/commit/e91db2f)).
- Lean job: install Lean through elan instead of `lean-action` — the repository
  is not a Lake package
  ([c433bd7](https://github.com/kostyk348/redoubt/commit/c433bd7)).
- Kani job: explicit harness list and a 25-minute wall instead of a six-hour
  hang ([20a3d3f](https://github.com/kostyk348/redoubt/commit/20a3d3f));
  `policy_evaluation_is_total` back in CI with bounded inputs
  ([31cb2e1](https://github.com/kostyk348/redoubt/commit/31cb2e1)),
  a narrowed search space ([e4abbc7](https://github.com/kostyk348/redoubt/commit/e4abbc7)),
  and policy built without parsing a string
  ([f15c5a3](https://github.com/kostyk348/redoubt/commit/f15c5a3)).
- Kani: `Kind` and `Rule` made visible to the harness (`pub(crate)`)
  ([8f787f4](https://github.com/kostyk348/redoubt/commit/8f787f4)).

[Unreleased]: https://github.com/kostyk348/redoubt/commits/main
[0.1.0]: https://github.com/kostyk348/redoubt/releases/tag/v0.1.0
