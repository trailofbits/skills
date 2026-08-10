import Mathlib.Data.ZMod.Basic

/-!
# Comparison helpers

Field-element encodings of comparisons on canonical representatives, used to
model the VM's `gt`/`lt` instructions.
-/

namespace Vm

/-- The Goldilocks prime: p = 2^64 - 2^32 + 1 -/
def GOLDILOCKS_PRIME : Nat := 2 ^ 64 - 2 ^ 32 + 1

/-- Field element type. -/
abbrev Felt := ZMod GOLDILOCKS_PRIME

/-- Encode `a > b` (on canonical representatives) as a field element. -/
def gtFelt (a b : Felt) : Felt :=
  if a.val > b.val then 1 else 0

/-- Encode `a < b` (on canonical representatives) as a field element. -/
def ltFelt (a b : Felt) : Felt :=
  gtFelt b a

theorem gtFelt_of_gt (a b : Felt) (h : a.val > b.val) : gtFelt a b = 1 := by
  simp [gtFelt, h]

theorem gtFelt_of_not_gt (a b : Felt) (h : ¬ a.val > b.val) : gtFelt a b = 0 := by
  simp [gtFelt, h]

/-- Convert the Prop-level `if` to a Bool-level `if` for kernel evaluation. -/
theorem gtFelt_eq_ite_decide (a b : Felt) :
    gtFelt a b = if decide (a.val > b.val) then (1 : Felt) else 0 := by
  cases h : decide (a.val > b.val) <;>
    simp_all [gtFelt, decide_eq_true_eq, decide_eq_false_iff_not]

theorem gtFelt_eq_one_iff (a b : Felt) : gtFelt a b = 1 ↔ a.val > b.val := by
  constructor
  · intro h
    by_contra hab
    rw [gtFelt_of_not_gt a b hab] at h
    exact absurd h (by norm_num)
  · intro h
    exact gtFelt_of_gt a b h

theorem ltFelt_eq_one_iff (a b : Felt) : ltFelt a b = 1 ↔ b.val > a.val := by
  simp only [ltFelt, gtFelt_eq_one_iff]

/-- Run `steps` rounds of a comparison loop; `fuel` bounds the recursion. -/
def cmpLoop (fuel : Nat) (acc : Felt) (pairs : List (Felt × Felt)) : Felt :=
  match fuel, pairs with
  | 0, _ => acc
  | _, [] => acc
  | fuel + 1, (a, b) :: rest => cmpLoop fuel (acc + gtFelt a b) rest

theorem cmpLoop_nil (fuel : Nat) (acc : Felt) (hfuel : fuel > 0) :
    cmpLoop fuel acc [] = acc := by
  cases fuel with
  | zero => omega
  | succ n => rfl

theorem cmpLoop_singleton (fuel : Nat) (acc : Felt) (a b : Felt)
    (hfuel : fuel > 1) :
    cmpLoop fuel acc [(a, b)] = acc + gtFelt a b := by
  cases fuel with
  | zero => omega
  | succ n =>
    show cmpLoop n (acc + gtFelt a b) [] = acc + gtFelt a b
    apply cmpLoop_nil
    simp only [gt_iff_lt] at hfuel
    omega

end Vm
