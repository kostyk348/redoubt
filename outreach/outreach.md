# Outreach: ready-to-send texts

Four texts, one per destination. Replace `[...]` placeholders, send from `lain90269@gmail.com`
(subscribe to the list first, or the message is held for moderation), and keep the draft link in
every one of them: <https://datatracker.ietf.org/doc/draft-kostyk-redoubt-00/>.

Repository: <https://github.com/kostyk348/redoubt> — the implementation, 28 tests, the Lean proofs.

---

## 1. IETF IOTOPS list — `iotops@ietf.org`

Subscribe at <https://www.ietf.org/mailman/listinfo/iotops> and confirm before sending.

> Subject: New individual draft: draft-kostyk-redoubt-00 (authorised control for Modbus-era PLCs)
>
> Hello,
>
> I published an individual draft that may be relevant to this group's work on Modbus security:
> https://datatracker.ietf.org/doc/draft-kostyk-redoubt-00/
>
> It proposes a guard in front of Modbus/TCP that decides per operation rather than per connection:
> an AEAD frame with the header as associated data, a Noise KK handshake, a replay window backed by
> a boot counter that survives a power cut, a deny-overrides policy over function / address span /
> role, dual control for critical outputs, reversible batches, and an audit chain that fails closed.
> The decision core is modelled in Lean 4 with twenty machine-checked properties, and there is a
> working Rust implementation with a parity test against the `snow` reference Noise implementation
> (https://github.com/kostyk348/redoubt).
>
> It is an individual draft, not a WG item, and I am not asking for adoption. I would value review
> of two things in particular: the handshake and prologue construction (Section 5), and whether the
> policy language (Section 7) is expressive enough for real installations.
>
> Konstantin Parashchuk

---

## 2. Personal note to the authors of the Modbus serial-link draft

Find the authors' addresses from the datatracker page of
`draft-liu-iotops-modbus-seriallink-sec-spec-02`. Keep it to five sentences: this is a person, not a
list.

> Subject: Your Modbus serial-link security draft and a per-operation authorisation proposal
>
> Hello,
>
> I read draft-liu-iotops-modbus-seriallink-sec-spec-02 and agree with its framing: the TLS profile
> covers Modbus/TCP and leaves serial links with nothing. The gap I keep running into is one step
> higher: even on a protected channel, an authenticated client may invoke any function code,
> including the write that stops a pump.
>
> I published an individual draft that adds the missing decision per operation on top of a protected
> channel, rather than a new transport: https://datatracker.ietf.org/doc/draft-kostyk-redoubt-00/
> It uses a Noise KK handshake (parity-tested against `snow`), a replay window that survives a
> reboot, a deny-overrides policy, dual control and reversible batches; the decision model is
> machine-checked in Lean 4.
>
> If serial-link integrity is your focus, the part that may be useful to you is the replay and boot
> counter design (Section 6): it solves the "device rebooted, so the recorded frame is fresh again"
> problem that a plain MAC does not.
>
> Would you be open to a short exchange about whether these two drafts should reference each other?
>
> Konstantin Parashchuk

---

## 3. Modbus Organization — technical contact

Route: <https://modbus.org> contact page → technical committee. Ask first, send the draft second:
this is a standards body that owns the specification, not a mailing list.

> Subject: Proposal: per-operation authorisation for Modbus/TCP, complementary to Modbus Security
>
> Dear Modbus Organization,
>
> I am writing about the Modbus Security Protocol specification (TLS profile, 2018). It closes an
> important gap: the channel. It does not close the next one, which the incidents of the last two
> years made visible — an authenticated client can still invoke any function code, including a write
> to a register that controls physical equipment. FrostyGoop (2024) and advisory AA26-097A (2026)
> are the public examples.
>
> I have written an individual Internet-Draft that adds that decision as a guard in front of a
> controller, without changing the controller and without changing Modbus on the wire between the
> guard and the PLC: https://datatracker.ietf.org/doc/draft-kostyk-redoubt-00/
>
> In short: an AEAD frame carrying the Modbus function and address span, a deny-overrides policy
> (function / span / unit / role), dual control for critical outputs, a replay window that survives
> a controller reboot, reversible write batches, and an audit chain that fails closed. There is a
> working implementation with tests and a machine-checked decision model
> (https://github.com/kostyk348/redoubt).
>
> I am not asking the organization to adopt anything. I would like to know whether the technical
> committee considers per-operation authorisation in scope, and whether a short presentation would be
> welcome.
>
> Konstantin Parashchuk
> lain90269@gmail.com

---

## 4. arXiv submission — `cs.CR`

Submit at <https://arxiv.org/submit>. Write the paper from the draft plus the proof artefacts; the
abstract below is the submission metadata.

**Title:** Redoubt/1: A Fail-Closed Guard for Modbus-Era PLCs, with a Machine-Checked Decision Core

**Authors:** Konstantin Parashchuk

**Abstract:**

> Modbus has no authentication, no authorisation and no replay protection. The TLS-based Modbus
> Security profile protects the channel, but an authenticated client may still invoke any function
> code, including writes to registers that control physical equipment; FrostyGoop (2024) and the
> 2026 advisory AA26-097A are public examples of what that costs. We present Redoubt/1, a guard that
> sits in front of a controller and decides per operation rather than per connection. The design has
> three unusual commitments. First, every request passes seven ordered gates — frame authentication,
> session binding, replay freshness, policy, dual control, auditability, and journalled application
> — and a failure at any gate stops it. Second, refusal is not the only negative answer: a third
> verdict drives affected outputs to provisioned safe values, because leaving an output where the
> last authorised write left it is not safety. Third, the replay window is backed by a boot counter
> in an append-only hash-chained file, so a power cut raises the floor instead of resetting it. The
> decision core is modelled in Lean 4 and twenty properties are machine-checked, including that an
> allow verdict implies every gate was passed and that no write occurs on any other verdict; the
> handshake is a Noise KK composition whose interoperability is verified against the `snow`
> reference implementation, a check that found two real transcript bugs. We report the design, the
> proofs, the implementation, and the limits of all three.

**Comments:** 10 pages, 1 figure. Implementation and Lean proofs: https://github.com/kostyk348/redoubt

**Categories:** cs.CR (primary), cs.SE (cross-list)

---

## Что писать не надо

- В `ietf@ietf.org` — общий список, индивидуальные драфты там раздражают.
- В CISA «проверьте наш протокол» — они не сертифицируют и не одобряют. CISA нужна только для
  уязвимости в чужом продукте (`report@cisa.gov`) или как площадка ICSJWG для доклада.
- Никому не писать «наша система невзламываема». Формулировка, которая работает: «fail-closed by
  construction; вот 20 доказанных инвариантов; вот что не покрыто».
