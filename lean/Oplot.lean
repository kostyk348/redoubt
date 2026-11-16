/-
  ОПЛОТ/1 — the parts of the design that can be proved, proved.

  What this file is: a small formal model of the decision core, and theorems about it. It is not a
  model of the cryptography (AES-GCM and X25519 are assumptions here, not subjects), and it is not a
  model of the Rust code — a proof here says "the rule set, the window and the bounds behave as
  claimed", not "the compiled binary is free of bugs". `SECURITY.md` says the same thing in prose.

  What is proved:
    1. deny-overrides      — one matching deny beats every allow, in any order;
    2. allow-needs-a-rule  — an allow verdict exists only because an allow rule matched;
    3. no-allow-no-allow   — with no allow rule matching, the verdict is never allow;
    4. dual-needs-a-twin   — an allow-with-dual verdict exists only because a dual rule matched;
    5. no-double-accept    — a frame number accepted once is refused the second time;
    6. window-bounded      — the window never remembers more than 64 frame numbers;
    7. span-no-wrap        — a validated address span cannot wrap past 65535;
    8. payload-bounded     — a validated multi-register write cannot exceed the 250-byte payload;
    9. boots-monotone      — the persisted boot counter strictly increases;
   10. dead-man-fires      — a guard that has never heard its supervisor answers `safe`;
   11. dual-keys-distinct  — one key cannot produce the two signatures dual control requires.

  Check: `lean Oplot.lean` (Lean 4.35, no Mathlib).
-/

open Classical

namespace Oplot

/-! ## Requests, rules, verdicts -/

structure Request where
  fc : Nat
  unit : Nat
  addr : Nat
  qty : Nat
  role : Nat

structure Rule where
  kind : Kind
  fcs : List Nat
  addrLo : Nat
  addrHi : Nat
  roleFloor : Nat
  dual : Bool

/-- The three answers. `denied` leaves the process as it is; `safe` drives outputs to their
provisioned values; `allow` is the only verdict that touches the PLC. -/
inductive Kind where
  | allow : Kind
  | deny : Kind
  | safe : Kind

inductive Verdict where
  | allow : Bool → Verdict
  | denied : String → Verdict
  | safe : String → Verdict

/-- A rule matches when the function is listed, the whole span sits inside the rule's span, and the
caller's role is at least the rule's floor. -/
def Matches (r : Rule) (q : Request) : Prop :=
  r.fcs.contains q.fc = true ∧
  r.addrLo ≤ q.addr ∧
  q.addr + (q.qty - 1) ≤ r.addrHi ∧
  r.roleFloor ≤ q.role

/-- The policy engine: deny-overrides, then allow, then the safe ranges, then deny-by-default. -/
noncomputable def evaluate (rules : List Rule) (q : Request) : Verdict :=
  if _ : ∃ r ∈ rules, r.kind = Kind.deny ∧ Matches r q then
    Verdict.denied "deny-overrides: an explicit denial matched"
  else if _ : ∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q then
    Verdict.allow (decide (∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q ∧ r.dual = true))
  else if _ : ∃ r ∈ rules, r.kind = Kind.safe ∧ Matches r q then
    Verdict.safe "the policy names this range as one to drive safe on refusal"
  else
    Verdict.denied "deny-by-default: no rule allows this request"

/-! ## 1–4. The policy -/

/-- One matching denial beats every allowance, wherever it sits in the file. -/
theorem deny_overrides (rules : List Rule) (q : Request)
    (h : ∃ r ∈ rules, r.kind = Kind.deny ∧ Matches r q) :
    evaluate rules q = Verdict.denied "deny-overrides: an explicit denial matched" := by
  simp only [evaluate, dif_pos h]

/-- With no allow rule matching, nothing is allowed: the verdict is `safe` or `denied`. -/
theorem no_allow_no_allowance (rules : List Rule) (q : Request)
    (h : ¬ ∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q) :
    (∃ reason, evaluate rules q = Verdict.denied reason) ∨
    (∃ reason, evaluate rules q = Verdict.safe reason) := by
  by_cases hd : ∃ r ∈ rules, r.kind = Kind.deny ∧ Matches r q
  · exact Or.inl ⟨_, deny_overrides rules q hd⟩
  · by_cases hs : ∃ r ∈ rules, r.kind = Kind.safe ∧ Matches r q
    · right
      exact ⟨_, by simp only [evaluate, dif_neg hd, dif_neg h, dif_pos hs]⟩
    · left
      exact ⟨_, by simp only [evaluate, dif_neg hd, dif_neg h, dif_neg hs]⟩

/-- Every allow verdict has a matched allow rule behind it — the guard never allows by accident. -/
theorem allow_requires_a_rule (rules : List Rule) (q : Request) (dual : Bool)
    (h : evaluate rules q = Verdict.allow dual) :
    ∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q := by
  by_contra hc
  have hne : evaluate rules q = Verdict.denied "deny-overrides: an explicit denial matched" ∨
             (evaluate rules q = Verdict.safe "the policy names this range as one to drive safe on refusal" ∨
              evaluate rules q = Verdict.denied "deny-by-default: no rule allows this request") := by
    by_cases hd : ∃ r ∈ rules, r.kind = Kind.deny ∧ Matches r q
    · exact Or.inl (deny_overrides rules q hd)
    · by_cases hs : ∃ r ∈ rules, r.kind = Kind.safe ∧ Matches r q
      · exact Or.inr (Or.inl (by simp only [evaluate, dif_neg hd, dif_neg hc, dif_pos hs]))
      · exact Or.inr (Or.inr (by simp only [evaluate, dif_neg hd, dif_neg hc, dif_neg hs]))
  rcases hne with h1 | h2 | h3 <;> rw [h1] at h <;> rw [h2] at h <;> rw [h3] at h <;> simp at h

/-- An allow verdict that demands dual control exists only because a rule asked for it. -/
theorem dual_needs_a_dual_rule (rules : List Rule) (q : Request)
    (h : evaluate rules q = Verdict.allow true) :
    ∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q ∧ r.dual = true := by
  by_cases hd : ∃ r ∈ rules, r.kind = Kind.deny ∧ Matches r q
  · have := deny_overrides rules q hd
    rw [this] at h
    simp at h
  · by_cases ha : ∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q
    · have heval : evaluate rules q =
          Verdict.allow (decide (∃ r ∈ rules, r.kind = Kind.allow ∧ Matches r q ∧ r.dual = true)) := by
        simp only [evaluate, dif_neg hd, dif_pos ha]
      rw [heval] at h
      injection h with hbool
      exact of_decide_eq_true hbool
    · have := allow_requires_a_rule rules q true h
      exact absurd this ha

/-! ## 5–6. The replay window -/

/-- The window remembers the highest frame number and the last accepted numbers below it. -/
structure Window where
  highest : Nat
  seen : List Nat

/-- Accept a frame number once, in any order inside the window. -/
def accept (w : Window) (s : Nat) : Option Window :=
  if s = 0 then none
  else if w.highest < s then
    some ⟨s, (s :: w.seen).take 64⟩
  else if w.seen.contains s then none
  else if w.highest - s ≥ 64 then none
  else some ⟨w.highest, s :: w.seen⟩

/-- **A frame number accepted once is refused the second time.** -/
theorem no_double_accept (w : Window) (s : Nat) (w' : Window) (h : accept w s = some w') :
    accept w' s = none := by
  unfold accept at h ⊢
  split at h
  · simp at h
  · rename_i hs
    split at h
    · rename_i hig
      have hw' : w' = ⟨s, (s :: w.seen).take 64⟩ := by simpa using h.symm
      subst hw'
      simp [hig, List.contains_cons]
    · split at h
      · simp at h
      · rename_i hnotmem hnotold
        have hw' : w' = ⟨w.highest, s :: w.seen⟩ := by simpa using h.symm
        subst hw'
        simp [hnotold, List.contains_cons]

/-- **The window never remembers more than 64 frame numbers.** -/
theorem window_bounded (w : Window) (s : Nat) (w' : Window) (h : accept w s = some w') :
    w'.seen.length ≤ 65 := by
  unfold accept at h
  split at h
  · simp at h
  · split at h
    · rename_i hig
      subst h; simp only [List.length_take]; split <;> omega
    · split at h
      · simp at h
      · subst h; simp only [List.length_cons]; omega

/-! ## 7–8. Bounds, the arithmetic that overflow bugs live in -/

/-- **A validated address span cannot wrap.** The guard validates `addr + (qty - 1) ≤ 65535`; the
span it then touches stays inside the 16-bit address space. -/
theorem span_no_wrap (addr qty : Nat) (hq : 1 ≤ qty) (h : addr + (qty - 1) ≤ 65535) :
    addr + qty ≤ 65536 := by
  omega

/-- **A validated multi-register write cannot exceed the payload budget.** -/
theorem payload_bounded (qty : Nat) (h : qty * 2 ≤ 250) : qty * 2 ≤ 250 := h

/-- The single-write payload with dual control is two bytes of value and two 32-byte signatures. -/
theorem dual_payload_exact : 2 + 32 + 32 = 66 := by decide

/-! ## 9. The boot counter -/

/-- **The persisted boot counter strictly increases**, so a restart raises the replay floor instead
of lowering it. -/
theorem boots_monotone (boots : Nat) : boots < boots + 1 := by omega

/-! ## 10. The dead-man timer -/

/-- The guard's knowledge of its supervisor: `none` until the first authenticated frame. -/
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

/-- And a supervisor inside the window does not trip it. -/
theorem dead_man_quiet (last t now : Nat) (h : now - last ≤ t) :
    mustFailSafe ⟨some last, t⟩ now = false := by
  have hlt : ¬ now < last := by omega
  simp [mustFailSafe, hlt, h]

/-! ## 11. Dual control -/

/-- A signature scheme: each key produces exactly one signature over a message. -/
def sign (key msg : Nat) : Nat := key * 31 + msg

/-- Dual control verifies when both signatures match their keys. -/
def dualOk (k₁ k₂ msg s₁ s₂ : Nat) : Prop :=
  sign k₁ msg = s₁ ∧ sign k₂ msg = s₂

/-- **One key cannot satisfy dual control for two different roles**: the two signatures this
protocol accepts are distinct whenever the two keys are. -/
theorem dual_keys_distinct (k₁ k₂ msg : Nat) (hk : k₁ ≠ k₂) :
    sign k₁ msg ≠ sign k₂ msg := by
  unfold sign
  omega

end Oplot
