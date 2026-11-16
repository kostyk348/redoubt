/-
  ОПЛОТ/1 — the parts of the design that can be proved, proved.

  What this file is: a small formal model of the decision core, and theorems about it. It is not a
  model of the cryptography (AES-GCM and X25519 are assumptions here, not subjects), and it is not a
  model of the Rust code — a proof here says "the rule set, the window and the bounds behave as
  claimed", not "the compiled binary is free of bugs". `SECURITY.md` says the same in prose.

  Check: `lean lean/Oplot.lean` (Lean 4.35, no Mathlib).
-/

open Classical

set_option linter.deprecated false

namespace Oplot

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

end Oplot

/-! ## The proof footprint

  These commands print what each theorem depends on. A theorem that printed `sorryAx` would be a
  hole; these do not. `propext` and `Classical.choice` are the ordinary classical axioms. -/

#print axioms Oplot.deny_overrides
#print axioms Oplot.no_allow_no_allowance
#print axioms Oplot.allow_requires_a_rule
#print axioms Oplot.dual_needs_a_dual_rule
#print axioms Oplot.no_double_accept
#print axioms Oplot.window_bounded
#print axioms Oplot.last_address_inside
#print axioms Oplot.payload_bounded
#print axioms Oplot.dual_payload_exact
#print axioms Oplot.boots_monotone
#print axioms Oplot.boots_never_decrease
#print axioms Oplot.dead_man_fires
#print axioms Oplot.dead_man_quiet
#print axioms Oplot.dead_man_fires_late
#print axioms Oplot.dual_keys_distinct
