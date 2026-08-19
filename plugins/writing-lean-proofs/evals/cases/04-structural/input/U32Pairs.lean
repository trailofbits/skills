import Mathlib.Tactic

set_option pp.all true
set_option maxHeartbeats 1000000

/-!
# u32 pairs

Predicates and lemmas for pairs of naturals within u32 bounds, used when
splitting a u64 value into limbs.
-/

namespace Vm

/-- Two naturals forming a valid u32 pair. -/
def U32Pair (a b : Nat) : Prop := a < 2 ^ 32 ∧ b < 2 ^ 32

/-- The carry bit of a u32 addition. -/
def carry (a b : Nat) : Nat := (a + b) / 2 ^ 32

theorem u32Pair_mod (a b : Nat) : U32Pair (a % 2 ^ 32) (b % 2 ^ 32) := by
  show a % 2 ^ 32 < 2 ^ 32 ∧ b % 2 ^ 32 < 2 ^ 32
  constructor
  apply Nat.mod_lt
  norm_num
  apply Nat.mod_lt
  norm_num

theorem u32Pair_swap (a b : Nat) (h : U32Pair a b) : U32Pair b a := by
  obtain ⟨ha, hb⟩ := h
  exact ⟨hb, ha⟩

theorem carry_le_one (a b : Nat) (h : U32Pair a b) : carry a b ≤ 1 := by
  obtain ⟨ha, hb⟩ := h
  simp only [carry, Nat.div_le_iff_le_mul_add_pred, Nat.lt_iff_add_one_le,
    Nat.reducePow, Nat.mul_one, Nat.add_sub_cancel, Nat.pos_iff_ne_zero,
    ne_eq, OfNat.ofNat_ne_zero, not_false_eq_true, Nat.lt_add_one_iff]

theorem mod_add_carry_mul (a b : Nat) :
    (a + b) % 2 ^ 32 + 2 ^ 32 * carry a b = a + b := by
  simp [carry]
  omega

end Vm
