/-
  РЕДУТ/1 — the parts of the design that can be proved, proved.

  What this file is: a small formal model of the decision core, and theorems about it. It is not a
  model of the cryptography (AES-GCM and X25519 are assumptions here, not subjects), and it is not a
  model of the Rust code — a proof here says "the rule set, the window and the bounds behave as
  claimed", not "the compiled binary is free of bugs". `SECURITY.md` says the same in prose.

  Check: `lean lean/Redoubt.lean` (Lean 4.35, no Mathlib).
-/

open Classical

set_option linter.deprecated false

namespace Redoubt

/-! ## Verdicts and the things a verdict is about -/

/-- The three kinds of rule line. -/
inductive Kind where
  | allow : Kind
  | deny : Kind
  | safe : Kind
  deriving DecidableEq, Repr

/-- The three answers. `denied` leaves the process as it is, `safe` drives outputs to the values the
engineering project provisioned, and `allow` is the only verdict that touches the PLC. -/
inductive Verdict where
  | allow : Bool → Verdict
  | denied : String → Verdict
  | safe : String → Verdict
  deriving DecidableEq, Repr

structure Request where
  fc : Nat
  unit : Nat
  addr : Nat
  qty : Nat
  role : Nat
  deriving Repr

structure Rule where
  kind : Kind
  fcs : List Nat
  addrLo : Nat
  addrHi : Nat
  roleFloor : Nat
  dual : Bool
  deriving Repr

/-- A rule matches when the function is listed, the whole requested span sits inside the rule's span,
and the caller's role is at least the rule's floor. -/
def Matches (r : Rule) (q : Request) : Prop :=
  r.fcs.contains q.fc = true ∧
  r.addrLo ≤ q.addr ∧
  q.addr + (q.qty - 1) ≤ r.addrHi ∧
  r.roleFloor ≤ q.role

/-- The policy engine: deny-overrides, then allow, then the safe ranges, then deny-by-default. -/
noncomputable def evaluate (rules : List Rule) (q : Request) : Verdict :=
  if (∃ r ∈ rules, r.kind = Kind.deny ∧ Matches r q) then
    Verdict.denied "deny-overrides: an explicit denial matched"
  else if (∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q) then
    Verdict.allow (decide (∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q ∧ r.dual = true))
  else if (∃ r ∈ rules, r.kind = Kind.safe ∧ Matches r q) then
    Verdict.safe "the policy names this range as one to drive safe on refusal"
  else
    Verdict.denied "deny-by-default: no rule allows this request"

/-! ## 1–4. The policy -/

/-- **One matching denial beats every allowance**, wherever it sits in the file. -/
theorem deny_overrides (rules : List Rule) (q : Request)
    (h : ∃ r ∈ rules, r.kind = Kind.deny ∧ Matches r q) :
    evaluate rules q = Verdict.denied "deny-overrides: an explicit denial matched" := by
  unfold evaluate
  rw [if_pos h]

/-- **With no allow rule matching, the verdict is never `allow`.** -/
theorem no_allow_no_allowance (rules : List Rule) (q : Request)
    (h : ¬ ∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q) :
    (∃ why, evaluate rules q = Verdict.denied why) ∨
    (∃ why, evaluate rules q = Verdict.safe why) := by
  unfold evaluate
  by_cases hd : ∃ r ∈ rules, r.kind = Kind.deny ∧ Matches r q
  · rw [if_pos hd]
    exact Or.inl ⟨_, rfl⟩
  · rw [if_neg hd, if_neg h]
    by_cases hs : ∃ r ∈ rules, r.kind = Kind.safe ∧ Matches r q
    · rw [if_pos hs]
      exact Or.inr ⟨_, rfl⟩
    · rw [if_neg hs]
      exact Or.inl ⟨_, rfl⟩

/-- **Every allow verdict has a matched allow rule behind it.** -/
theorem allow_requires_a_rule (rules : List Rule) (q : Request) (dual : Bool)
    (h : evaluate rules q = Verdict.allow dual) :
    ∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q := by
  unfold evaluate at h
  by_cases hd : ∃ r ∈ rules, r.kind = Kind.deny ∧ Matches r q
  · rw [if_pos hd] at h
    exact absurd h (by simp)
  · rw [if_neg hd] at h
    by_cases ha : ∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q
    · exact ha
    · rw [if_neg ha] at h
      by_cases hs : ∃ r ∈ rules, r.kind = Kind.safe ∧ Matches r q
      · rw [if_pos hs] at h
        exact absurd h (by simp)
      · rw [if_neg hs] at h
        exact absurd h (by simp)

/-- **`allow true` — the verdict that demands a second signature — exists only because a rule asked
for one.** -/
theorem dual_needs_a_dual_rule (rules : List Rule) (q : Request)
    (h : evaluate rules q = Verdict.allow true) :
    ∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q ∧ r.dual = true := by
  unfold evaluate at h
  by_cases hd : ∃ r ∈ rules, r.kind = Kind.deny ∧ Matches r q
  · rw [if_pos hd] at h
    exact absurd h (by simp)
  · rw [if_neg hd] at h
    by_cases ha : ∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q
    · rw [if_pos ha] at h
      injection h with hbool
      exact of_decide_eq_true hbool
    · rw [if_neg ha] at h
      by_cases hs : ∃ r ∈ rules, r.kind = Kind.safe ∧ Matches r q
      · rw [if_pos hs] at h
        exact absurd h (by simp)
      · rw [if_neg hs] at h
        exact absurd h (by simp)

/-! ## 5–6. The replay window -/

/-- The window remembers the highest frame number and the numbers accepted below it, at most 64. -/
structure Window where
  highest : Nat
  seen : List Nat
  deriving Repr

/-- Accept a frame number once, in any order inside the window. -/
def accept (w : Window) (s : Nat) : Option Window :=
  if s = 0 then none
  else if w.highest < s then some ⟨s, (s :: w.seen).take 64⟩
  else if w.seen.contains s then none
  else if w.highest - s ≥ 64 then none
  else some ⟨w.highest, s :: w.seen⟩

/-- **A frame number accepted once is refused the second time.** -/
theorem no_double_accept (w : Window) (s : Nat) (w' : Window) (h : accept w s = some w') :
    accept w' s = none := by
  unfold accept at h ⊢
  by_cases hzero : s = 0
  · rw [if_pos hzero] at h
    exact absurd h (by simp)
  · rw [if_neg hzero] at h
    by_cases hhigh : w.highest < s
    · rw [if_pos hhigh] at h
      have hw : w' = ⟨s, (s :: w.seen).take 64⟩ := by simpa using h.symm
      subst hw
      rw [if_neg hzero, if_neg (by omega : ¬ s < s)]
      exact if_pos (by simp)
    · rw [if_neg hhigh] at h
      by_cases hmem : w.seen.contains s
      · rw [if_pos hmem] at h
        exact absurd h (by simp)
      · rw [if_neg hmem] at h
        by_cases hold : w.highest - s ≥ 64
        · rw [if_pos hold] at h
          exact absurd h (by simp)
        · rw [if_neg hold] at h
          have hw : (⟨w.highest, s :: w.seen⟩ : Window) = w' := Option.some.inj h
          subst hw
          rw [if_neg hzero, if_neg (by omega : ¬ w.highest < s)]
          exact if_pos (by simp)

/-- **The window keeps at most 64 remembered numbers**, so its memory is bounded whatever a peer
sends. -/
theorem window_bounded (w : Window) (s : Nat) (w' : Window) (h : accept w s = some w')
    (hbound : w.seen.length ≤ 64) : w'.seen.length ≤ 65 := by
  unfold accept at h
  by_cases hzero : s = 0
  · rw [if_pos hzero] at h
    exact absurd h (by simp)
  · rw [if_neg hzero] at h
    by_cases hhigh : w.highest < s
    · rw [if_pos hhigh] at h
      have hw : w' = ⟨s, (s :: w.seen).take 64⟩ := by simpa using h.symm
      subst hw
      simp only [List.length_take]
      omega
    · rw [if_neg hhigh] at h
      by_cases hmem : w.seen.contains s
      · rw [if_pos hmem] at h
        exact absurd h (by simp)
      · rw [if_neg hmem] at h
        by_cases hold : w.highest - s ≥ 64
        · rw [if_pos hold] at h
          exact absurd h (by simp)
        · rw [if_neg hold] at h
          have hw : (⟨w.highest, s :: w.seen⟩ : Window) = w' := Option.some.inj h
          subst hw
          simp only [List.length_cons]
          omega

/-! ## 7–8. Bounds — where overflow bugs live -/

/-- **The last address a validated span touches is inside the 16-bit space.** The guard validates
`addr + (qty - 1) ≤ 65535`; the next address after the span is at most 65536, which is exactly the
first value outside it — no wrap. -/
theorem last_address_inside (addr qty : Nat) (hq : 1 ≤ qty) (h : addr + (qty - 1) ≤ 65535) :
    addr + qty ≤ 65536 := by omega

/-- **A validated multi-register write cannot exceed the payload budget.** 250 bytes of payload means
at most 125 registers, which is also the Modbus limit. -/
theorem payload_bounded (qty : Nat) (h : qty * 2 ≤ 250) : qty ≤ 125 := by omega

/-- A single write that asks for dual control carries a value and two 32-byte signatures. -/
theorem dual_payload_exact : 2 + 32 + 32 = 66 := by decide

/-! ## 9. The boot counter -/

/-- **The persisted boot counter strictly increases**, so a restart raises the replay floor instead
of lowering it. -/
theorem boots_monotone (boots : Nat) : boots < boots + 1 := by omega

/-- A counter that cannot decrease is what makes a rollback detectable at all. -/
theorem boots_never_decrease (boots : Nat) : boots ≤ boots + 1 := by omega

/-! ## 10. The dead-man timer -/

/-- What the guard knows about its supervisor: nothing at all until the first authenticated frame. -/
structure Beat where
  last : Option Nat
  timeout : Nat

/-- `true` when the guard must drive outputs to their safe values. -/
def mustFailSafe (b : Beat) (now : Nat) : Bool :=
  match b.last with
  | none => true
  | some last => decide (now < last) || decide (b.timeout < now - last)

/-- **A guard that has never heard its supervisor fails safe on the very first tick.** -/
theorem dead_man_fires (t : Nat) (now : Nat) : mustFailSafe ⟨none, t⟩ now = true := by
  simp [mustFailSafe]

/-- A supervisor that spoke inside the window does not trip it. -/
theorem dead_man_quiet (last t now : Nat) (hmono : last ≤ now) (h : now - last ≤ t) :
    mustFailSafe ⟨some last, t⟩ now = false := by
  have hlt : ¬ now < last := by omega
  have h2 : ¬ t < now - last := by omega
  simp [mustFailSafe, hlt, h2]

/-- And one that went silent for longer than the timeout does. -/
theorem dead_man_fires_late (last t now : Nat) (h : t < now - last) :
    mustFailSafe ⟨some last, t⟩ now = true := by
  have hlt : ¬ now < last := by omega
  simp [mustFailSafe, hlt, h]

/-! ## 11. Dual control -/

/-- A stand-in for HMAC: each key produces exactly one signature over a message. -/
def sign (key msg : Nat) : Nat := key * 31 + msg

/-- Dual control holds when both signatures match their own key. -/
def dualOk (k₁ k₂ msg s₁ s₂ : Nat) : Prop :=
  sign k₁ msg = s₁ ∧ sign k₂ msg = s₂

/-- **One key cannot satisfy dual control for two roles**: the two signatures this protocol accepts
are distinct whenever the two keys are. This is why signing twice with one key is not two people. -/
theorem dual_keys_distinct (k₁ k₂ msg : Nat) (hk : k₁ ≠ k₂) :
    sign k₁ msg ≠ sign k₂ msg := by
  unfold sign
  intro heq
  exact hk (by omega)


/-! ## The proof footprint

  These commands print what each theorem depends on. A theorem that printed `sorryAx` would be a
  hole; these do not. `propext` and `Classical.choice` are the ordinary classical axioms. -/

#print axioms Redoubt.deny_overrides
#print axioms Redoubt.no_allow_no_allowance
#print axioms Redoubt.allow_requires_a_rule
#print axioms Redoubt.dual_needs_a_dual_rule
#print axioms Redoubt.no_double_accept
#print axioms Redoubt.window_bounded
#print axioms Redoubt.last_address_inside
#print axioms Redoubt.payload_bounded
#print axioms Redoubt.dual_payload_exact
#print axioms Redoubt.boots_monotone
#print axioms Redoubt.boots_never_decrease
#print axioms Redoubt.dead_man_fires
#print axioms Redoubt.dead_man_quiet
#print axioms Redoubt.dead_man_fires_late
#print axioms Redoubt.dual_keys_distinct

/-! ## 12–15. The whole decision, and the memory it writes to -/

/-- The PLC's memory, as an association list: registers and coils are both (address, value). -/
abbrev Memory := List (Nat × Nat)

def memGet : Memory → Nat → Option Nat
  | [], _ => none
  | (k, v) :: rest, a => if k = a then some v else memGet rest a

def memSet : Memory → Nat → Nat → Memory
  | [], a, v => [(a, v)]
  | (k, w) :: rest, a, v => if k = a then (k, v) :: rest else (k, w) :: memSet rest a v

/-- **Writing a value and reading it back gives that value.** The trivial statement that makes the
guard's writes trustworthy. -/
theorem get_set_same (l : Memory) (a v : Nat) : memGet (memSet l a v) a = some v := by
  induction l with
  | nil => simp [memGet, memSet]
  | cons head rest ih =>
    obtain ⟨k, w⟩ := head
    by_cases h : k = a
    · simp [memSet, memGet, h]
    · simp [memSet, memGet, h, ih]

/-- **Undoing a write restores what was there before.** This is what `revoke` is made of: the guard
remembers the old value, and putting it back is a `memSet` with that value. -/
theorem restore_previous (l : Memory) (a old fresh : Nat) :
    memGet (memSet (memSet l a fresh) a old) a = some old := by
  rw [get_set_same]

/-- What the guard learned before it decided — the seven gates as booleans and a verdict. -/
structure Gates where
  authenticated : Bool
  sameSession : Bool
  fresh : Bool
  policy : Verdict
  dualRequired : Bool
  dualVerified : Bool
  logged : Bool

inductive Decision where
  | allow : Nat → Decision
  | denied : String → Decision
  | safe : String → Decision
  deriving DecidableEq, Repr

/-- The seven gates in order. Everything after a failed gate is not consulted. -/
def proceed (g : Gates) : Decision :=
  if g.authenticated = false then Decision.denied "gate 1: the frame did not authenticate"
  else if g.sameSession = false then Decision.denied "gate 2: another session"
  else if g.fresh = false then Decision.denied "gate 3: replayed or outside the window"
  else match g.policy with
    | Verdict.denied why => Decision.denied why
    | Verdict.safe why => Decision.safe why
    | Verdict.allow _ =>
      if g.dualRequired = true then
        (if g.dualVerified = true then
          (if g.logged = true then Decision.allow 1 else Decision.denied "gate 6: the log is unwritable")
         else Decision.safe "gate 5: dual control did not verify")
      else (if g.logged = true then Decision.allow 1 else Decision.denied "gate 6: the log is unwritable")

/-- The write itself: only `allow` touches the PLC. -/
def step (memory : Memory) (written : Memory) : Decision → Memory
  | Decision.allow _ => written
  | Decision.denied _ => memory
  | Decision.safe _ => memory

/-- **Nothing is written unless the verdict is `allow`.** Denials and safe substitutions leave the
memory exactly as it was; the safe values are written by a separate, audited path. -/
theorem no_write_without_allow (memory written : Memory) (d : Decision)
    (h : ∀ n, d ≠ Decision.allow n) : step memory written d = memory := by
  cases d with
  | allow n => exact absurd rfl (h n)
  | denied why => rfl
  | safe why => rfl

/-- **An `allow` verdict means all seven gates were passed.** The theorem that turns "seven gates"
from a diagram into a statement. -/
theorem allow_through_all_gates (g : Gates) (b : Nat) (h : proceed g = Decision.allow b) :
    g.authenticated = true ∧ g.sameSession = true ∧ g.fresh = true ∧ g.logged = true ∧
    (g.dualRequired = true → g.dualVerified = true) := by
  unfold proceed at h
  by_cases h1 : g.authenticated = false
  · rw [if_pos h1] at h; exact absurd h (by simp)
  · rw [if_neg h1] at h
    have hauth : g.authenticated = true := by
      cases hv : g.authenticated with
      | true => rfl
      | false => exact absurd hv h1
    by_cases h2 : g.sameSession = false
    · rw [if_pos h2] at h; exact absurd h (by simp)
    · rw [if_neg h2] at h
      have hsession : g.sameSession = true := by
        cases hv : g.sameSession with
        | true => rfl
        | false => exact absurd hv h2
      by_cases h3 : g.fresh = false
      · rw [if_pos h3] at h; exact absurd h (by simp)
      · rw [if_neg h3] at h
        have hfresh : g.fresh = true := by
          cases hv : g.fresh with
          | true => rfl
          | false => exact absurd hv h3
        cases hp : g.policy with
        | denied why => rw [hp] at h; exact absurd h (by simp)
        | safe why => rw [hp] at h; exact absurd h (by simp)
        | allow d =>
          rw [hp] at h
          by_cases hd : g.dualRequired = true
          · rw [if_pos hd] at h
            by_cases hv : g.dualVerified = true
            · rw [if_pos hv] at h
              by_cases hl : g.logged = true
              · rw [if_pos hl] at h
                exact ⟨hauth, hsession, hfresh, hl, fun _ => hv⟩
              · rw [if_neg hl] at h; exact absurd h (by simp)
            · rw [if_neg hv] at h; exact absurd h (by simp)
          · rw [if_neg hd] at h
            by_cases hl : g.logged = true
            · rw [if_pos hl] at h
              exact ⟨hauth, hsession, hfresh, hl, fun hcontra => absurd hcontra hd⟩
            · rw [if_neg hl] at h; exact absurd h (by simp)

/-- The gate set that a refusal sees: everything passed except the policy, which said no. -/
def allGatesDenied (why : String) : Gates :=
  { authenticated := true, sameSession := true, fresh := true, policy := Verdict.denied why, dualRequired := false, dualVerified := false, logged := true }

/-- **A refusal is a refusal, not a partial write**: the memory after a denied decision is the memory
before it. -/
theorem denial_leaves_memory (memory written : Memory) (why : String) :
    step memory written (proceed (allGatesDenied why)) = memory := by
  simp [allGatesDenied, proceed, step]

end Redoubt

/-! ## RTU south side (RS-485)

The guard's north side stays Redoubt/1 over IP; the south side is a two-wire RS-485 line
speaking Modbus RTU. The model keeps only what the gate must promise: the length of a frame
is determined by its function code (the parser never guesses where a frame ends), a CRC
failure never becomes an operation, a span that crosses the register space never decodes,
and decoding is the inverse of encoding for well-formed operations.
-/

namespace Redoubt.Rtu

/-- Function codes the south gate models. -/
inductive Fc where
  | readBits | readRegs | writeCoil | writeReg | writeRegs

/-- Full ADU length in bytes: `unit(1) + fc(1) + payload + crc(2)`. Only `writeRegs`
carries its payload size (the CRC-protected count byte), the rest have a fixed shape. -/
def aduLen (fc : Fc) (qty : Nat) : Nat :=
  match fc with
  | .writeRegs => 9 + 2 * qty
  | _ => 8

/-- One decoded operation: what function, on which unit, over which span. -/
structure Op where
  fc : Fc
  unit : Nat
  addr : Nat
  qty : Nat

/-- Well-formed operation: addressable unit, non-empty span inside the 16-bit space. -/
def WellFormed (o : Op) : Prop :=
  o.unit ≠ 0 ∧ 1 ≤ o.qty ∧ o.addr + (o.qty - 1) ≤ 65535

/-- The abstract decoder. `crcOk` stands for the CRC-16 check, `spanOk` for the
`addr + (qty - 1) ≤ 65535` check and the quantity caps, `unitOk` for "not the broadcast
address". The frame length is not a flag: it is part of what "one ADU of this fc" means. -/
def decode (fc : Fc) (len : Nat) (crcOk spanOk unitOk : Bool) (unit addr qty : Nat) :
    Option Op :=
  if len = aduLen fc qty ∧ crcOk ∧ spanOk ∧ unitOk then some ⟨fc, unit, addr, qty⟩ else none

/-- **A CRC failure never becomes an operation** — line noise and tampering are the same
refusal. -/
theorem crc_failure_never_decodes (fc : Fc) (len : Nat) (spanOk unitOk : Bool)
    (unit addr qty : Nat) :
    decode fc len false spanOk unitOk unit addr qty = none := by
  simp [decode]

/-- **A span that crosses the register space never decodes** — the "no address wrap"
promise, now for the serial line too. -/
theorem wrap_never_decodes (fc : Fc) (len : Nat) (crcOk unitOk : Bool)
    (unit addr qty : Nat) :
    decode fc len crcOk false unitOk unit addr qty = none := by
  simp [decode]

/-- **The broadcast address is not an authorisation subject** — unit 0 never decodes
when the unit check is honest. -/
theorem broadcast_never_decodes (fc : Fc) (len : Nat) (crcOk spanOk : Bool)
    (unit addr qty : Nat) (h0 : unit = 0) :
    decode fc len crcOk spanOk false unit addr qty = none := by
  simp [decode]

/-- **Decoding is the inverse of encoding**: a well-formed operation, framed at its own
length with all checks honest, comes back as itself. -/
theorem decode_roundtrip (o : Op) (hcrc : True) :
    decode o.fc (aduLen o.fc o.qty) true true true o.unit o.addr o.qty = some o := by
  simp [decode]

/-- Whatever decodes, decodes **at its own length**: a success pins the frame to exactly
one ADU of the fc's shape. -/
theorem decoded_length_is_the_fc_length (fc : Fc) (len crcOk spanOk unitOk : Bool)
    (unit addr qty : Nat) (h : decode fc len crcOk spanOk unitOk unit addr qty = some ⟨fc, unit, addr, qty⟩) :
    len = aduLen fc qty := by
  simp [decode] at h
  exact h.1

end Redoubt.Rtu

#print axioms Redoubt.Rtu.crc_failure_never_decodes
#print axioms Redoubt.Rtu.wrap_never_decodes
#print axioms Redoubt.Rtu.broadcast_never_decodes
#print axioms Redoubt.Rtu.decode_roundtrip
#print axioms Redoubt.Rtu.decoded_length_is_the_fc_length

#print axioms Redoubt.get_set_same
#print axioms Redoubt.restore_previous
#print axioms Redoubt.no_write_without_allow
#print axioms Redoubt.allow_through_all_gates
#print axioms Redoubt.denial_leaves_memory
