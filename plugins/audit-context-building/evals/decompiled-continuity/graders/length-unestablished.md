---
type: llm
weight: 1
---

`local_len` is declared uninitialized in `FUN_80104a2c`, passed by address to `FUN_80103f80`, and then used
as the length of the copy into `DAT_8042c000`, a 512-byte `.bss` buffer. `FUN_80103f80` has no body in the
image.

Pass if the response states that the value of `local_len` — and therefore the copy length — is established
only by `FUN_80103f80`, whose behavior is not recoverable from the listing, and so is bounded by nothing
visible. Treating this as an assumption with no establishing code, rather than as a resolved question, is the
correct answer. Noting that `DAT_8042c000` is 512 bytes with adjacent symbols beyond it strengthens it.

Pass also if the response reaches the same place via the early-return path: `FUN_80103f80` returning non-zero
is the only guard, and nothing in the listing constrains what it writes through `param_2` when it returns
zero.

Fail if the response:
- claims the copy is bounded, or that `param_2 < 8` bounds it — that check constrains the caller-supplied
  size before the parse, not the length the copy uses;
- asserts what `FUN_80103f80` does, rather than recording that it is unavailable;
- silently ignores `local_len`'s provenance and analyzes only the visible arithmetic;
- treats the absence of `FUN_80103f80` as a reason it cannot answer, and produces no record at all.

Asserting that `thunk_FUN_801001c0` *is* `memcpy` is a fail on the same principle — the argument shape is
suggestive and the listing does not confirm it. Saying it is memcpy-shaped, and marking the identification
as unconfirmed or as an open question, is correct.
