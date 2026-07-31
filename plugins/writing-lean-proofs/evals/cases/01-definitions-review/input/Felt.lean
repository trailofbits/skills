import Mathlib.Data.ZMod.Basic
import Mathlib.FieldTheory.Finite.Basic

/-!
# Field elements

The base field for the VM: integers modulo the Goldilocks prime.
-/

namespace Vm

/-- The Goldilocks prime: p = 2^64 - 2^32 + 1 -/
def GOLDILOCKS_PRIME : Nat := 2 ^ 64 - 2 ^ 32 + 1

/-- Field element type. -/
abbrev Felt := ZMod GOLDILOCKS_PRIME

set_option maxHeartbeats 800000 in
instance : Fact (Nat.Prime GOLDILOCKS_PRIME) := ⟨by native_decide⟩

/-- The canonical natural number representative of a field element. -/
def Felt.IsU32 (a : Felt) : Prop :=
  a.val < 2 ^ 32

/-- Boolean check for whether a felt fits in 32 bits. -/
def Felt.isU32 (a : Felt) : Bool :=
  a.val < 2 ^ 32

/-- Boolean check for whether a felt is 0 or 1 (a boolean). -/
def Felt.isBool (a : Felt) : Bool :=
  a.val == 0 || a.val == 1

/-- Convert a natural number to a felt. -/
def Felt.ofNat (n : Nat) : Felt := (n : Felt)

/-- The u32 value of a felt, as a natural number, truncating to the low 32 bits. -/
def Felt.toU32 (a : Felt) : Nat := a.val % 2 ^ 32

/-- The low 32 bits of a felt's canonical representative. -/
def Felt.lo32 (a : Felt) : Felt := Felt.ofNat (a.val % 2 ^ 32)

/-- The high 32 bits of a felt's canonical representative. -/
def Felt.hi32 (a : Felt) : Felt := Felt.ofNat (a.val / 2 ^ 32)

/-- The truncated u32 value is within u32 bounds. -/
theorem Felt.toU32_isU32 (a : Felt) : Felt.isU32 (Felt.ofNat a.toU32) = true := by
  simp only [Felt.isU32, Felt.toU32, Felt.ofNat, decide_eq_true_eq]
  have h : a.val % 2 ^ 32 < 2 ^ 32 := Nat.mod_lt _ (by norm_num)
  have hlt : a.val % 2 ^ 32 < GOLDILOCKS_PRIME := by
    unfold GOLDILOCKS_PRIME
    omega
  rw [ZMod.val_natCast_of_lt hlt]
  exact h

/-- A felt within u32 bounds satisfies the u32 predicate. -/
theorem Felt.isU32_of_IsU32 (a : Felt) (h : a.IsU32) : a.isU32 = true := by
  simp only [Felt.isU32, decide_eq_true_eq]
  exact h

end Vm
