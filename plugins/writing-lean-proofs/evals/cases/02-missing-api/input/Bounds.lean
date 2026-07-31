import Mathlib.Data.ZMod.Basic

/-!
# Bound lemmas

Bounds on canonical representatives, used to discharge side conditions when
lifting u32 arithmetic into the field.
-/

namespace Vm

/-- The Goldilocks prime: p = 2^64 - 2^32 + 1 -/
def GOLDILOCKS_PRIME : Nat := 2 ^ 64 - 2 ^ 32 + 1

/-- Field element type. -/
abbrev Felt := ZMod GOLDILOCKS_PRIME

/-- A VM state: an operand stack and word-addressable memory. -/
structure State where
  stack : List Felt
  memory : Nat → Felt

/-- Replace the operand stack, keeping memory. -/
def State.withStack (s : State) (stk : List Felt) : State :=
  { s with stack := stk }

@[simp] theorem State.withStack_stack (s : State) (stk : List Felt) :
    (s.withStack stk).stack = stk := rfl

@[simp] theorem State.withStack_memory (s : State) (stk : List Felt) :
    (s.withStack stk).memory = s.memory := rfl

@[simp] theorem State.withStack_withStack (s : State) (stk1 stk2 : List Felt) :
    (s.withStack stk1).withStack stk2 = s.withStack stk2 := rfl

instance : NeZero GOLDILOCKS_PRIME := ⟨by norm_num [GOLDILOCKS_PRIME]⟩

/-- Every canonical representative is below the prime. -/
theorem felt_val_lt_prime (a : Felt) : a.val < GOLDILOCKS_PRIME :=
  ZMod.val_lt a

/-- Values below 2^32 are below the prime. -/
theorem u32_lt_prime (n : Nat) (h : n < 2 ^ 32) : n < GOLDILOCKS_PRIME := by
  unfold GOLDILOCKS_PRIME
  omega

/-- Truncation to 32 bits lands below the prime. -/
theorem u32_mod_lt_prime (n : Nat) : n % 2 ^ 32 < GOLDILOCKS_PRIME := by
  unfold GOLDILOCKS_PRIME
  omega

/-- The carry of a felt-valued addition is below the prime. -/
theorem sum_div_lt_prime (a b : Felt) :
    (a.val + b.val) / 2 ^ 32 < GOLDILOCKS_PRIME := by
  have ha := felt_val_lt_prime a
  have hb := felt_val_lt_prime b
  unfold GOLDILOCKS_PRIME at *
  omega

/-- Small powers of two stay below the prime. -/
theorem pow2_lt_prime (n : Nat) (h : n < 64) : 2 ^ n < GOLDILOCKS_PRIME := by
  have h1 : 2 ^ n ≤ 2 ^ 63 := Nat.pow_le_pow_right (by omega) (by omega)
  unfold GOLDILOCKS_PRIME
  omega

/-- A product of u32 values divided by 2^32 is below the prime. -/
theorem u32_prod_div_lt_prime (a b : Nat) (ha : a < 2 ^ 32) (hb : b < 2 ^ 32) :
    a * b / 2 ^ 32 < GOLDILOCKS_PRIME := by
  have h : a * b / 2 ^ 32 < 2 ^ 32 :=
    Nat.div_lt_of_lt_mul (Nat.mul_lt_mul_of_lt_of_lt ha hb)
  unfold GOLDILOCKS_PRIME at *
  omega

end Vm
