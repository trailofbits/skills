---
name: recursive-drop-stack-overflow-finder
description: Detects recursive types whose implicit Drop walks the structure recursively, causing an uncatchable stack overflow when the type is built from untrusted input
---

**Finding ID Prefix:** `RECURSEDROP`.

**Gates:**

1. Type `T` is in `rec_map` from Phase A — recursive via `Box<Self>`, `Option<Box<Self>>`, `Vec<Self>`, `HashMap<_, Self>`, or equivalent. Recursive *enums* with a `Box<Self>` variant (linked-list / cons-cell / AST shape) are the canonical case.
2. `T` does **not** have a hand-written `impl Drop` that performs **iterative** teardown of the recursive chain. The default derived/elided `Drop` recurses one frame per node.
3. `T` is reachable from an untrusted source (Phase B) — direct deserialization, programmatic construction in a loop fed by request data, or accumulation across requests.
4. The path producing `T` does not itself cap depth before storage (e.g., parser-side depth limit applies on insert).

**Why it matters:** dropping a `Box<Node>`-chained list of depth `N` consumes `N` stack frames *after* the function returns. The overflow happens at `}` — frequently at the end of a request handler, far from any visible recursion in source. Stack overflow is **not** catchable: `catch_unwind` does not trap it, and `panic = "unwind"` does not help. A single oversized request — even one that was rejected and returned an error — can crash the process during cleanup. This is the canonical Rust footgun (`rust-lang/rust#58068`, "Recursive Drop causes stack overflow even for object trees", still open).

**FPs (reject):**

- `T` has a manual `impl Drop` that converts the recursive chain into an iterative walk (typical pattern: take ownership of children into a `Vec` worklist, drop in a loop). Verify by reading the body.
- `T` is bounded at construction by a depth cap that is enforced on **every** path that builds `T` (not just the parser). Note: caps on `serde_json::Value` deserialization (128) do **not** translate to caps on user types built from `Value`.
- Recursion is "wide but shallow" by construction (e.g., a `Vec<Self>` where vector length is large but nesting depth is statically `O(1)`).
- The type is only constructed in `#[cfg(test)]`.

**Patch:**

Implement `Drop` manually with iterative teardown. For a linked list:

```rust
impl Drop for List {
    fn drop(&mut self) {
        let mut cur = self.head.take();
        while let Some(mut node) = cur {
            cur = node.next.take();
            // node drops here at depth 1
        }
    }
}
```

For tree/AST shapes, drain children into a `Vec` worklist and pop in a loop. Cap input depth at the trust boundary as a defense-in-depth measure even when iterative `Drop` is in place.
