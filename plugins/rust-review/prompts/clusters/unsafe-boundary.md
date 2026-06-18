---
name: cluster-unsafe-boundary
kind: cluster
consolidated: true
covers:
  - unsafe-reaching-api  # URAPI
  - transmute-misuse     # TRANS
  - raw-pointer-arith    # RAWPTR
  - repr-c-layout        # REPRC
  - safety-doc           # SAFETYDOC
  - debug-assert-safety  # DEBUGSAFETY
  - pointer-cast         # PTRCAST
  - enum-discriminant    # ENUMUB
---

# Cluster: Unsafe boundary

Rust's safety guarantees end at `unsafe` blocks. This cluster maps the **attack surface** — every public, safe entry point that can transitively reach an `unsafe` operation — and audits each safe→unsafe transition for soundness.

ID prefixes: `URAPI`, `TRANS`, `RAWPTR`, `PTRCAST`, `REPRC`, `ENUMUB`, `SAFETYDOC`, `DEBUGSAFETY`.

---

## Phase A — Build the unsafe-reachability map (ONCE per run)

Run these scans and keep results as `unsafe_map` for all eight passes:

```
Grep: pattern="\bunsafe\s*\{"                          # Unsafe blocks (UB)
Grep: pattern="\bunsafe\s+fn\s"                        # Unsafe functions (UF)
Grep: pattern="\bunsafe\s+impl\s"                      # Unsafe trait impls
Grep: pattern="\bextern\s+\"(C|system|stdcall|cdecl|win64|sysv64|aapcs|fastcall|thiscall|vectorcall|efiapi)(-unwind)?\""  # FFI entry points (any non-Rust ABI)
Grep: pattern="#\[repr\(C\)\]"                         # FFI-safe layouts
Grep: pattern="\btransmute(_copy)?\s*[:<(]"             # mem::transmute usage
Grep: pattern="(\*mut|\*const)\s+\w"                  # Raw pointer types
Grep: pattern="\.(as_ptr|as_mut_ptr|into_raw|from_raw)\(" # Raw pointer extraction
Grep: pattern="\b(get_unchecked(_mut)?|copy_nonoverlapping|ptr::(write|read|offset|add|sub))\s*\("
Grep: pattern="\bas\s+\*(const|mut)\s+\w"              # ptr-type reinterpretation via `as`
Grep: pattern="\bas\s+(usize|isize)\b"                 # ptr↔int candidates (Read confirms ptr side)
Grep: pattern="\btransmute(_copy)?\s*::\s*<\s*u8\s*,\s*bool"   # transmute<u8, bool>
Grep: pattern="\benum\s+\w+\s*\{"                              # candidate enums (cross with #[repr(...)])
Grep: pattern="Option<\s*(NonZero|&|Box<|NonNull|fn\()"        # niche-optimized fields
```

For each unsafe block, identify its **Unsafe Encapsulating Function (UEF)** — the smallest `fn` (safe or unsafe) lexically containing it. Then walk callers via `Grep` for the UEF name to find every **Unsafe Reaching API (URAPI)** — a `pub fn` whose body, directly or transitively, dispatches into the UEF. Record `unsafe_map[UB] = { uef, urapis[], inputs_flowing_in }`.

Do NOT file findings during Phase A.

---

## Phase B — Run these passes in order, reusing `unsafe_map`

### 1. `URAPI` — Unsafe Reaching API exposure

For each `pub fn` in `urapis[]`: confirm there is **either** a documented invariant the caller must uphold (in the rustdoc `/// # Safety` block) **or** a runtime check that proves it. If the public function takes untrusted input (network, file, IPC, user CLI) and that input flows into the unsafe block without validation, file `URAPI` finding.

### 2. `TRANS` — `mem::transmute` misuse

Every `transmute` site: confirm source and destination types have identical layout (size, alignment, validity invariants). Flag transmutes between references and raw pointers, transmutes that fabricate `&mut T` from non-mut sources, transmutes across `#[repr(Rust)]` types whose layout is unspecified, and `transmute_copy` of partially-initialized values.

### 3. `RAWPTR` — Raw pointer arithmetic and provenance

For every `.offset()`, `.add()`, `.sub()`, `ptr::write`, `ptr::read`, `copy_nonoverlapping`: confirm the pointer is derived from a live allocation, bounded within that allocation, and properly aligned for the target type. Pointer arithmetic exceeding allocation bounds is UB even before dereference.

### 3a. `PTRCAST` — Pointer cast hazards via `as`

`mem::transmute` is grepped by Phase A, but the `as` operator can perform the same reinterpretation invisibly. Four sub-patterns:

**Pointer → integer** (`ptr as usize`): strips provenance. Sound only if the integer is consumed for logging, hashing, or comparison and never cast back to a pointer. Flag any value that flows from `ptr as usize` into a subsequent `as *mut T` / `as *const T` in the same function.

**Integer → pointer** (`usize as *mut T`, `0xDEAD_BEEF as *const T`): fabricates a pointer with no provenance. Sound only when the integer was previously obtained from `ptr.expose_provenance()` (or an equivalent exposing cast) of a live pointer. Bare casts from constants, FFI integers, or arithmetic results are UB on dereference.

**Fat → thin pointer** (`&[T] as *const [T] as *const T` — slice-length truncation; `(b as *const dyn Trait).cast::<()>()` or `Box::into_raw(b) as *mut ()` for trait objects; `<*const [T]>::as_ptr`): silently discards the vtable or length metadata. The resulting thin pointer cannot reconstruct the original; any read/write past one element via the thin pointer is UB. Note you **cannot** `as`-cast a fat reference straight to a thin raw pointer in one step — rustc rejects `&[T] as *const T` and `&dyn Trait as *const ()` with E0606 — so the truncation always appears as a two-step `as *const [T] as *const T`, an `.as_ptr()` on the slice/`dyn`, or a `ptr::from_raw_parts` / metadata drop; the Phase A `\bas\s+\*(const|mut)` grep only catches the thin *destination*, so Read the surrounding line for the multi-step source. Particularly insidious because the code compiles cleanly.

**Pointer-type reinterpretation** (`*const T as *const U` between layout-incompatible types): functionally equivalent to `transmute` but bypasses the Phase A `\btransmute(_copy)?` grep. Read the surrounding code to determine `T` and `U`; if their layouts differ in size, alignment, or validity invariants, file `PTRCAST`.

**FPs to reject:**

- Same-type const↔mut casts (`*const T as *mut T`) — aliasing soundness is covered by the unsafe block's broader contract.
- `ptr as usize` whose value is only consumed by logging, hashing, or `Debug` formatting with no subsequent `as *const T` / `as *mut T` reverse cast in the function.
- Numeric `as` casts not involving any pointer type — that is `LOSSYFROM` / `ARITHOFL` territory.
- Casts inside `bytemuck`, `zerocopy`, `cast_slice*` and similar zero-copy helpers whose trait bounds (`Pod`, `AnyBitPattern`, `FromBytes`) prove the layout contract.

**Patch:** prefer `.cast::<U>()` for typed pointer casts (still unsafe but searchable as a clear keyword); use `ptr.addr()` and `ptr::with_exposed_provenance` for the int↔ptr round-trip under Strict Provenance; preserve metadata via `<*const [T]>::len()` / `ptr::metadata` / `ptr::from_raw_parts` instead of fat→thin truncation.

### 4. `REPRC` — Layout guarantees at the unsafe boundary

Structs passed to/from FFI, transmuted, or accessed via raw pointer reads must be `#[repr(C)]` (or `#[repr(transparent)]` / `#[repr(packed)]` with care). Default `#[repr(Rust)]` allows field reordering between compiler versions. Flag any struct used at an unsafe boundary without explicit `repr`.

### 4a. `ENUMUB` — Enum discriminant and niche validity

Constructing a Rust enum value whose bit pattern does not correspond to a declared discriminant is instant UB — regardless of whether the value is ever read. Four sub-patterns:

**Integer → fieldless enum** (`transmute::<u32, MyEnum>(x)`, `*ptr.cast::<MyEnum>()` reads, `ptr::read::<MyEnum>(p)` from raw bytes): UB unless the source bytes are provably one of the enum's declared discriminants. Particularly common in FFI deserialization and binary parsers.

**`transmute::<u8, bool>(byte)`** and equivalents: `bool` has exactly two valid bit patterns (`0` and `1`); any other byte is UB. Decode `bool` from C buffers via `byte != 0`, not via transmute.

**Niche writes** through a raw pointer or FFI buffer into a field of type `Option<&T>`, `Option<&mut T>`, `Option<Box<T>>`, `Option<NonNull<T>>`, or `Option<fn(...)>`: the all-zeros pattern is `None`; any other pattern must be a valid `Some(T)`. Writing untrusted bytes into such a slot can violate `T`'s validity invariant. Severity depends on `T`: `Option<&T>` / `Option<&mut T>` / `Option<Box<T>>` reconstituted with an unaligned or non-dereferenceable address is **instant UB** on construction — references **and `Box`** carry the same alignment + dereferenceability validity invariants beyond non-null — and `Option<fn(...)>` with a non-function bit pattern is instant UB. For `Option<NonNull<T>>` the inner type's only validity invariant is non-null, so an attacker-supplied non-zero pattern survives construction — but every later dereference is UB on a wild pointer. (Note: `Option<NonZero*>` has the same niche layout but no validity hazard at all, because every non-zero bit pattern is a valid `NonZeroN`; writes there are only a *logic* hazard, not a UB hazard.)

**`#[repr(Rust)]` enum at FFI boundary** — discriminant width is implementation-defined and field layout is unspecified. Passing such an enum by value through `extern "C"`, storing it in a `#[repr(C)]` struct that crosses FFI, or reading it from a foreign-written buffer is unsound.

**FPs to reject:**

- `transmute` or cast preceded by an `assert!`, `if`, or exhaustive `match` validating the integer against the declared discriminants on the same code path.
- Niche-slot writes where the writer demonstrably zeros via `MaybeUninit::zeroed()` (yielding `None`) and then constructs the `Some` value through a safe constructor.
- Enums declared with `#[repr(u8)]`, `#[repr(u32)]`, `#[repr(C)]`, `#[repr(C, u32)]`, or other primitive/C reprs at FFI boundaries — discriminant width is fixed and field layout is specified for these variants. Only `#[repr(Rust)]` is unsound at FFI.
- `#[non_exhaustive]` enums whose construction sites are all internal and audited.

**Patch:** define a `TryFrom<u32>` (or the source integer type) returning `Err` for unknown discriminants and replace the transmute with the checked conversion; decode `bool` via `match byte { 0 => false, 1 => true, _ => return Err(...) }`; give FFI-exposed enums a primitive `#[repr(...)]` and validate the discriminant at the boundary; introduce a typed wrapper that owns the niche-write invariant.

### 5. `SAFETYDOC` — `// SAFETY:` documentation rules

Every `unsafe { ... }` block in safe code MUST have an adjacent `// SAFETY: <reasoning>` comment explaining why the operation is sound. Every `unsafe fn` MUST have a rustdoc `# Safety` section listing invariants the caller upholds. Flag missing or pro-forma docs (e.g., `// SAFETY: trust me`).

### 6. `DEBUGSAFETY` — Safety invariant guarded only by `debug_assert!`

`debug_assert!` / `debug_assert_eq!` / `debug_assert_ne!` are **compiled out in release builds** (unless the crate explicitly sets `debug-assertions = true` for the release profile). Using them to guard a precondition of an `unsafe` operation produces release-build UB: the invariant is checked in tests, silently elided in production.

For each `debug_assert*!(...)` lexically adjacent (within ~5 lines, no intervening branch) to an `unsafe { ... }` block whose soundness depends on the asserted predicate, file `DEBUGSAFETY`. Also flag patterns like:

```rust
debug_assert!(idx < self.len);
unsafe { *self.ptr.add(idx) }
```

— the bounds check evaporates in release.

**FPs to reject:**

- The same predicate is *also* enforced by a regular `assert!`, a `match` arm, or by the type system (e.g., `NonZeroUsize`).
- The crate's release profile sets `debug-assertions = true` in `Cargo.toml` (`[profile.release] debug-assertions = true`) — confirm by reading the manifest.
- The `debug_assert!` documents a redundant sanity check whose precondition is established by the *function's safety contract* (`/// # Safety`) — the contract, not the assert, is the guarantee.

**Patch:** promote to `assert!` (compiled in all profiles), or replace with a checked operation (`self.ptr.add(idx)` → bounds-checked indexing), or remove if redundant with a safety contract.

---

## Deconfliction

Report only one finding per `(path, line)`. Priority (higher wins):

1. `URAPI` > `TRANS` > `PTRCAST` > `RAWPTR` (URAPI captures the public-API attack chain; flag the entry point, not the internal mechanic. When the same site triggers both `TRANS` and `PTRCAST` greps — e.g., `transmute::<_, *const u8>(v) as usize` — file `TRANS` because the transmute is the root UB; `PTRCAST` otherwise outranks `RAWPTR` because it names the bug more precisely).
2. `ENUMUB` > `TRANS` when the unsoundness is specifically an invalid-discriminant problem rather than a generic layout mismatch — `ENUMUB` names the bug more precisely. By the same logic, `ENUMUB` > `PTRCAST` when the cast's destination type is an enum (e.g., `*ptr.cast::<MyEnum>()` is filed as `ENUMUB`, not `PTRCAST`). `URAPI` still tops `ENUMUB` when the unsafe is reachable from a public API — file the entry point, not the discriminant read.
3. `REPRC` and `SAFETYDOC` are orthogonal and independent — never collapse with the above.
4. `DEBUGSAFETY` is independent of `SAFETYDOC`: a `// SAFETY:` comment may exist and still be unsound if the only enforcer is `debug_assert!`. Report both when applicable.

---

## Token-economy reminder

All eight passes operate on the same `unsafe_map`. Build it ONCE; do not re-`Grep` raw-pointer, transmute, `as`-cast, or enum patterns per pass. Reuse the URAPI set across UAF, double-free, invalid-free, and BOF in the **memory-safety** cluster too — those finders may `Read` `unsafe_map` notes via the worker's scratch findings, but the **memory-safety** cluster runs in a different worker, so it must rebuild its own map (cluster isolation is intentional).
