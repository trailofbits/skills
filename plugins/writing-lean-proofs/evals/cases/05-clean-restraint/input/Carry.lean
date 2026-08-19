import Mathlib.Tactic

/-!
# Carries of u32 addition

The carry bit of a truncated 32-bit addition, with its basic API.
-/

namespace Vm

/-- The carry bit of a u32 addition. -/
def carry (a b : Nat) : Nat := (a + b) / 2 ^ 32

theorem carry_def (a b : Nat) : carry a b = (a + b) / 2 ^ 32 := rfl

@[simp] theorem carry_zero_left (b : Nat) (hb : b < 2 ^ 32) : carry 0 b = 0 := by
  simp [carry_def, Nat.div_eq_of_lt hb]

@[simp] theorem carry_zero_right (a : Nat) (ha : a < 2 ^ 32) : carry a 0 = 0 := by
  simp [carry_def, Nat.div_eq_of_lt ha]

theorem carry_comm (a b : Nat) : carry a b = carry b a := by
  simp [carry_def, Nat.add_comm]

theorem carry_le_one (a b : Nat) (ha : a < 2 ^ 32) (hb : b < 2 ^ 32) :
    carry a b ≤ 1 := by
  rw [carry_def]
  have h : (a + b) / 2 ^ 32 < 2 := Nat.div_lt_of_lt_mul (by omega)
  omega

theorem carry_lt_u32 (a b : Nat) (ha : a < 2 ^ 32) (hb : b < 2 ^ 32) :
    carry a b < 2 ^ 32 :=
  calc carry a b ≤ 1 := carry_le_one a b ha hb
    _ < 2 ^ 32 := by norm_num

/-- The truncated sum and the carry together reconstruct the exact sum,
and the carry is a single bit. -/
theorem addWithCarry_spec (a b : Nat) (ha : a < 2 ^ 32) (hb : b < 2 ^ 32) :
    (a + b) % 2 ^ 32 + 2 ^ 32 * carry a b = a + b ∧ carry a b ≤ 1 := by
  constructor
  · show (a + b) % 2 ^ 32 + 2 ^ 32 * carry a b = a + b
    rw [carry_def]
    exact Nat.mod_add_div (a + b) (2 ^ 32)
  · show carry a b ≤ 1
    exact carry_le_one a b ha hb

/-- Chained carries vanish: adding a carry bit to a u32 value cannot carry
again unless the value is at the boundary. -/
theorem carry_carry_eq_zero (a b c : Nat)
    (ha : a < 2 ^ 32) (hb : b < 2 ^ 32) (hc : c < 2 ^ 32 - 1) :
    carry c (carry a b) = 0 := by
  have h1 : carry a b ≤ 1 := carry_le_one a b ha hb
  have h2 : c + carry a b < 2 ^ 32 := by omega
  rw [carry_def]
  exact Nat.div_eq_of_lt h2

end Vm
