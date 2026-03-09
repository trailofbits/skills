# Rust Zeroization Patterns Reference

This reference documents vulnerability pattern detected by the zeroize-audit tooling for Rust code.
Each entry includes: what the flaw is, which tool detects it, severity, category, a minimal Rust snippet showing the bug, and a recommended fix.

---

## Section A — Semantic Patterns (`semantic_audit.py`, rustdoc JSON-based)

These patterns are detectable from rustdoc JSON without executing the compiler. `semantic_audit.py` processes trait impls, derives, and field types from the rustdoc index.

---

### A1 — `#[derive(Copy)]` on Sensitive Type

**Category**: `SECRET_COPY` | **Severity**: critical

**Why it's dangerous**: `Copy` types are bitwise-duplicated on every assignment, function call, and return. No `Drop` ever runs — the type cannot implement `Drop`. Every copy is a silent, untracked duplicate that will never be zeroed.

```rust
// BAD: every assignment silently duplicates the secret
#[derive(Copy, Clone)]
pub struct CopySecret {
    data: [u8; 32],
}

fn use_key(key: CopySecret) {  // <-- full copy here
    // original still on stack, unzeroed
}
```

**Fix**: Remove `Copy`. Use `Clone` explicitly where needed and ensure all clones are tracked and zeroed.

---

### A2 — No `Zeroize`, `ZeroizeOnDrop`, or `Drop`

**Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: high

**Why it's dangerous**: When the type goes out of scope, Rust calls `drop_in_place` which simply frees the memory without zeroing it. The secret bytes remain in the freed heap or on the stack until overwritten by future allocations.

```rust
// BAD: no cleanup whatsoever
pub struct UnprotectedKey {
    bytes: Vec<u8>,
}

fn example() {
    let key = UnprotectedKey { bytes: vec![0x42; 32] };
    // key drops here — heap bytes never zeroed
}
```

**Fix**: Add `#[derive(ZeroizeOnDrop)]` (with `zeroize` crate) or implement `Drop` calling `.zeroize()` on all fields.

---

### A3 — `Zeroize` Impl Without Auto-Trigger

**Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: high

**Why it's dangerous**: The `Zeroize` trait provides a `.zeroize()` method, but it requires explicit invocation. If no `Drop` or `ZeroizeOnDrop` calls it, the zeroing never happens automatically when the value goes out of scope.

```rust
use zeroize::Zeroize;

// BAD: Zeroize is implemented but never called on drop
pub struct ManualZeroizeToken {
    bytes: Vec<u8>,
}

impl Zeroize for ManualZeroizeToken {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

fn example() {
    let token = ManualZeroizeToken { bytes: vec![0x42; 32] };
    // token drops here — zeroize() is NEVER called
}
```

**Fix**: Add `#[derive(ZeroizeOnDrop)]` alongside `Zeroize`, or add an explicit `Drop` impl that calls `self.zeroize()`.

---

### A4 — `Drop` Impl Missing Secret Fields

**Category**: `PARTIAL_WIPE` | **Severity**: high

**Why it's dangerous**: The struct has multiple sensitive fields, but the `Drop` impl only zeroes some of them. The unzeroed fields remain in memory after the struct is freed.

```rust
// BAD: Drop impl zeroes `secret` but forgets `token`
pub struct ApiSecret {
    secret: Vec<u8>,
    token: Vec<u8>,  // <-- never zeroed
}

impl Drop for ApiSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
        // self.token is NOT zeroed
    }
}
```

**Fix**: Ensure `Drop` calls `.zeroize()` on every sensitive field, or use `#[derive(ZeroizeOnDrop)]` to zero all fields automatically.

---

### A5 — `ZeroizeOnDrop` on Struct with Heap Fields

**Category**: `PARTIAL_WIPE` | **Severity**: medium

**Why it's dangerous**: `ZeroizeOnDrop` zeros all fields via the `Zeroize` implementation, but `Vec<T>` zeroes only `len` bytes, not the full allocated `capacity`. Excess capacity bytes remain readable until the allocator reclaims them.

```rust
use zeroize::ZeroizeOnDrop;

// BAD: ZeroizeOnDrop zeros len bytes but capacity tail is untouched
#[derive(ZeroizeOnDrop)]
pub struct SessionKey {
    data: Vec<u8>,
}

fn example() {
    let mut key = SessionKey { data: Vec::with_capacity(64) };
    key.data.extend_from_slice(&[0x42; 32]);
    // capacity[32..64] bytes never zeroed
}
```

**Fix**: Use `Zeroizing<Vec<u8>>` which uses `zeroize_and_drop` for the full buffer, or manually `self.data.zeroize(); self.data.shrink_to_fit()` in `Drop`.

---

### A6 — `ManuallyDrop<T>` Struct Field

**Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: critical

**Why it's dangerous**: `ManuallyDrop<T>` inhibits automatic drop for the wrapped value. Rust will never call `Drop` on a `ManuallyDrop<T>` field unless `ManuallyDrop::drop()` is called explicitly. If the containing struct's `Drop` impl does not explicitly drop and zero the field, the secret bytes are never wiped.

```rust
use std::mem::ManuallyDrop;

// BAD: Drop is never called on `key` field automatically
pub struct SecretHolder {
    key: ManuallyDrop<Vec<u8>>,
}

// When SecretHolder drops, `key` is NOT zeroed — bytes stay in heap
```

**Fix**: Implement `Drop` for `SecretHolder` that explicitly calls `self.key.zeroize()` (if `Vec<u8>` implements `Zeroize`) and then `unsafe { ManuallyDrop::drop(&mut self.key) }`.

---

### A7 — `#[derive(Clone)]` on Zeroizing Type

**Category**: `SECRET_COPY` | **Severity**: medium

**Why it's dangerous**: Each `clone()` call creates an independent heap allocation containing the same secret bytes. The clone must be independently zeroed. If callers pass clones to functions that don't zero them on return, the secret escapes the zeroing lifecycle.

```rust
// BAD: clone() creates an untracked duplicate that may not be zeroed
#[derive(Clone)]
pub struct CloneableKey {
    bytes: Vec<u8>,
}

impl Drop for CloneableKey {
    fn drop(&mut self) { self.bytes.zeroize(); }
}

fn bad_caller(key: &CloneableKey) {
    let copy = key.clone(); // a new heap allocation
    do_something_with(copy); // copy may not be zeroed on return from do_something_with
}
```

**Fix**: Remove `Clone` if not needed. If cloning is required, document that all clones must implement the same zeroization lifecycle.

---

### A8 — `From<T>` / `Into<T>` to Non-Zeroizing Type

**Category**: `SECRET_COPY` | **Severity**: medium

**Why it's dangerous**: A `From`/`Into` conversion transfers the secret bytes into a type that does not implement `ZeroizeOnDrop` or `Drop`. The original may be zeroed but the converted value escapes without zeroization guarantees.

```rust
type RawBytes = Vec<u8>;  // type alias — does NOT implement ZeroizeOnDrop

pub struct ApiSecret {
    secret: Vec<u8>,
    token: RawBytes,
}

// BAD: From<RawBytes> converts secret into a plain Vec with no zeroing
impl From<RawBytes> for ApiSecret {
    fn from(token: RawBytes) -> Self {
        ApiSecret { secret: vec![], token }
    }
}
// The returned ApiSecret has no Drop/Zeroize impl
```

**Fix**: Ensure the target type of `From`/`Into` also implements `ZeroizeOnDrop`, or wrap in `Zeroizing<T>`.

---

### A9 — `ptr::write_bytes` Without `compiler_fence`

**Category**: `OPTIMIZED_AWAY_ZEROIZE` | **Severity**: medium

**Why it's dangerous**: `ptr::write_bytes` is a non-volatile memory write. If the compiler determines the memory is never read afterwards (classic dead-store elimination), it may remove the write entirely. Unlike `volatile_set_memory`, there is no compiler barrier to prevent this.

```rust
use std::ptr;

pub struct WriteBytesSecret {
    data: [u8; 32],
}

fn wipe_insecure(s: &mut WriteBytesSecret) {
    // BAD: compiler may eliminate this as a dead store
    unsafe {
        ptr::write_bytes(s as *mut WriteBytesSecret, 0, 1);
    }
}
// No compiler_fence — wipe is DSE-vulnerable
```

**Fix**: Add `std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst)` after the write, or use `zeroize::Zeroize` which is DSE-resistant by design.

---

### A10 — `#[cfg(feature)]` Wrapping `Drop` or `Zeroize` Impl

**Category**: `NOT_ON_ALL_PATHS` | **Severity**: medium

**Why it's dangerous**: When the controlling feature flag is disabled, the cleanup impl is compiled out entirely. Code built without the feature silently loses all zeroization, with no compile error or warning.

```rust
pub struct CfgGuardedKey {
    secret: Vec<u8>,
}

// BAD: when feature "zeroize" is off, this impl does not exist
#[cfg(feature = "zeroize")]
impl Drop for CfgGuardedKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
```

**Fix**: Make zeroization unconditional. If the `zeroize` crate is optional, gate the crate import but always zero memory manually in `Drop` using a volatile write loop as the fallback.

---

### A11 — `#[derive(Debug)]` on Sensitive Type

**Category**: `SECRET_COPY` | **Severity**: low

**Why it's dangerous**: The `Debug` trait formats all fields into a string. Any logging framework, panic handler, or `dbg!()` call will print the secret bytes in plaintext. This is a common source of credential leaks in logs.

```rust
// BAD: {key:?} or panic prints the raw bytes
#[derive(Debug)]
pub struct DebugSecret {
    secret: Vec<u8>,
}
```

**Fix**: Remove `#[derive(Debug)]`. Implement `Debug` manually to show a redacted placeholder: `write!(f, "DebugSecret([REDACTED])")`.

---

### A12 — `#[derive(Serialize)]` on Sensitive Type

**Category**: `SECRET_COPY` | **Severity**: low

**Why it's dangerous**: Serialization creates a representation of the secret in the serialization output (JSON, msgpack, etc.). If the output buffer is not itself zeroed after use, the secret bytes leak into the serialized payload.

```rust
use serde::Serialize;

// BAD: serde may write secret bytes to an uncontrolled buffer
#[derive(Serialize)]
pub struct SerializableSecret {
    secret: Vec<u8>,
}
```

**Fix**: Remove `Serialize`. If serialization is required, implement it manually to skip or encrypt sensitive fields, and ensure the output buffer is zeroed after use.

---

## Section B — Dangerous API Patterns (`find_dangerous_apis.py`, source grep-based)

These patterns are detected by scanning Rust source files for calls to APIs that prevent or bypass zeroization. Detection confidence is `"likely"` when the call appears within ±15 lines of a sensitive name, `"needs_review"` otherwise.

---

### B1 — `mem::forget(secret)`

**Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: critical

**Why it's dangerous**: `mem::forget` leaks the value without running its destructor. If the type has a `Drop` impl that calls `zeroize`, `mem::forget` bypasses it entirely. The heap allocation is leaked and never zeroed.

```rust
use std::mem;

struct SecretKey(Vec<u8>);
impl Drop for SecretKey { fn drop(&mut self) { self.0.zeroize(); } }

fn bad(key: SecretKey) {
    // BAD: Drop is never called — bytes leak forever
    mem::forget(key);
}
```

**Fix**: Never call `mem::forget` on values containing secrets. Use explicit zeroing before consuming the value if early release is needed.

---

### B2 — `ManuallyDrop::new(secret)` Call

**Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: critical

**Why it's dangerous**: Wrapping a value in `ManuallyDrop` suppresses its destructor. The secret bytes will not be zeroed when the `ManuallyDrop` wrapper is dropped unless `ManuallyDrop::drop()` is called explicitly.

```rust
use std::mem::ManuallyDrop;

struct SecretKey(Vec<u8>);
impl Drop for SecretKey { fn drop(&mut self) { self.0.zeroize(); } }

fn bad(key: SecretKey) {
    // BAD: Drop never runs for the inner SecretKey
    let _md = ManuallyDrop::new(key);
}
```

**Fix**: If `ManuallyDrop` is required for FFI or unsafe code, explicitly call `key.zeroize()` before passing into `ManuallyDrop::new`, or ensure the surrounding code calls `ManuallyDrop::drop()`.

---

### B3 — `Box::leak(secret)`

**Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: critical

**Why it's dangerous**: `Box::leak` produces a `'static` reference by preventing the `Box` from ever being dropped. The secret allocation persists for the entire program lifetime and is never zeroed.

```rust
struct SecretKey(Vec<u8>);

fn bad(key: SecretKey) -> &'static SecretKey {
    // BAD: key is never dropped or zeroed
    Box::leak(Box::new(key))
}
```

**Fix**: Avoid `Box::leak` for secrets. Use `Arc<SecretKey>` with proper `Drop` if shared ownership is needed, ensuring the last reference is dropped before program exit.

---

### B4 — `mem::uninitialized()`

**Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: critical

**Why it's dangerous**: `mem::uninitialized` returns memory with undefined contents — which in practice means prior stack or heap bytes are exposed as the return value. It is unsound (deprecated since Rust 1.39) and may expose sensitive data from prior use of that memory region.

```rust
use std::mem;

struct SecretKey([u8; 32]);

unsafe fn bad() -> SecretKey {
    // BAD: may return bytes from prior sensitive allocations
    mem::uninitialized()
}
```

**Fix**: Use `MaybeUninit<T>::zeroed().assume_init()` for zero-initialized memory, or `MaybeUninit::uninit()` only when you will fully initialize before reading.

---

### B5 — `Box::into_raw(secret)`

**Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: high

**Why it's dangerous**: `Box::into_raw` consumes the `Box` and returns a raw pointer, preventing the destructor from running. The caller is responsible for zeroing and deallocating, but this is often forgotten.

```rust
struct SecretKey(Vec<u8>);
impl Drop for SecretKey { fn drop(&mut self) { self.0.zeroize(); } }

fn bad(key: SecretKey) -> *mut SecretKey {
    // BAD: Drop is suppressed; raw pointer escapes
    Box::into_raw(Box::new(key))
}
```

**Fix**: If raw pointer access is required for FFI, zero the value before converting: call `key.zeroize()` (if applicable), then use `Box::into_raw`. Document the requirement for the caller to `Box::from_raw` and drop the value.

---

### B6 — `ptr::write_bytes` Without Volatile

**Category**: `OPTIMIZED_AWAY_ZEROIZE` | **Severity**: high

**Why it's dangerous**: `ptr::write_bytes` is a non-volatile write. The compiler's dead-store elimination pass can and will remove it if the memory is not read afterwards. Use of this function as a zeroization primitive is unreliable at optimization levels O1 and above.

```rust
use std::ptr;

struct SecretKey([u8; 32]);

fn wipe(key: &mut SecretKey) {
    // BAD: may be eliminated by DSE at -O1/-O2
    unsafe { ptr::write_bytes(key as *mut SecretKey, 0, 1); }
}
```

**Fix**: Use `zeroize::Zeroize` (which uses volatile writes internally) or add `std::sync::atomic::compiler_fence(Ordering::SeqCst)` after the write.

---

### B7 — `mem::transmute::<SensitiveType, _>`

**Category**: `SECRET_COPY` | **Severity**: high

**Why it's dangerous**: `mem::transmute` performs a bitwise copy of the value into the target type. If the target type does not implement `ZeroizeOnDrop`, the transmuted copy is a secret that will never be zeroed.

```rust
use std::mem;

struct SecretKey([u8; 32]);
impl Drop for SecretKey { fn drop(&mut self) { /* zeroize */ } }

fn bad(key: SecretKey) -> [u8; 32] {
    // BAD: bytes escape into a plain array with no zeroing
    unsafe { mem::transmute::<SecretKey, [u8; 32]>(key) }
}
```

**Fix**: Avoid transmuting sensitive types. If raw byte access is needed, use `as_ref()` or slice operations that keep the secret in a `Zeroizing<>` wrapper.

---

### B8 — `mem::take(&mut sensitive)`

**Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: medium

**Why it's dangerous**: `mem::take` replaces the target with `Default::default()`, which for `Vec<u8>` is an empty `Vec` — not a zeroed one. The taken value is returned to the caller, which may not zero it. The original location now contains the default value without evidence of the prior secret.

```rust
use std::mem;

struct SecretKey(Vec<u8>);

fn bad(key: &mut SecretKey) -> Vec<u8> {
    // BAD: original bytes copied out; neither location is zeroed
    mem::take(&mut key.0)
}
```

**Fix**: Call `self.key.zeroize()` before using `mem::take`, or use a wrapper that zeroes on `Default`. Ensure the returned value is also properly zeroed after use.

---

### B9 — `slice::from_raw_parts` Over Secret Buffer

**Category**: `SECRET_COPY` | **Severity**: medium

**Why it's dangerous**: Creating a slice alias over a secret buffer using raw pointers bypasses Rust's ownership and lifetime tracking. The resulting slice can be passed to functions that copy the bytes or retain a reference beyond the owning struct's lifetime.

```rust
struct SecretKey([u8; 32]);

fn bad(key: &SecretKey) -> &[u8] {
    // BAD: aliased reference — bytes may escape or be copied by caller
    unsafe { std::slice::from_raw_parts(key.0.as_ptr(), 32) }
}
```

**Fix**: Use safe slice references (`key.0.as_ref()` or `&key.0[..]`) which are subject to normal lifetime rules. Avoid unsafe aliasing of secret memory.

---

### B10 — `async fn` with Secret Local Across `.await`

**Category**: `NOT_ON_ALL_PATHS` | **Severity**: high

**Why it's dangerous**: Rust async functions compile to state machines. Any local variable live across an `.await` point is stored in the generated `Future` struct, which resides in heap memory. If the `Future` is cancelled (dropped mid-poll), the state machine drops without running the normal destructor sequence, leaving the secret in heap memory.

```rust
async fn bad() {
    let secret_key = SecretKey([0u8; 32]);  // stored in Future state machine
    some_async_op().await;  // secret_key is live here
    drop(secret_key);       // may never reach here if Future is cancelled
}
```

**Fix**: Zero the secret before every `.await` point: call `secret_key.zeroize()` before `.await`, or use `Zeroizing<>` wrapper (which zeroes on drop). Alternatively, place the secret in a separate non-async function scope.

---

## Section C — Compiler-Level Patterns

These patterns are **invisible to source and rustdoc analysis** but are detected by `check_mir_patterns.py`, `check_llvm_patterns.py`, and `check_rust_asm.py`. Each entry explains why source inspection is blind to it and what compiler artifact reveals the flaw.

---

### C-MIR1 — Closure Captures Sensitive Local by Value

**Tool**: `check_mir_patterns.py` | **Category**: `SECRET_COPY` | **Severity**: high

**Why source is blind**: At the source level, `let f = || use(secret)` looks identical whether `secret` is captured by reference or by move. Only MIR makes the distinction explicit: the closure struct gets a field `_captured = move _secret`.

```rust
fn bad(secret: Vec<u8>) {
    // Source looks fine — is it a move or borrow?
    let f = move || process(&secret);
    // MIR shows: closure struct receives `_captured_secret = move _secret`
    // The copy is now in the closure's heap allocation, not the original binding
    f();
    // `secret` is gone — but closure may outlive intended scope
}
```

**Detection**: MIR shows `closure_body: _captured_field = move _local` where the local matches a sensitive name pattern.

---

### C-MIR2 — Secret Live Across Generator Yield on Error Path

**Tool**: `check_mir_patterns.py` | **Category**: `NOT_ON_ALL_PATHS` | **Severity**: high

**Why source is blind**: Source analysis can find `.await` points but cannot determine which locals are live at each yield, or whether an error exit path skips a `StorageDead` for the secret. MIR encodes exact liveness: each suspend point lists live locals, and each `Err`/early-return basic block shows whether `StorageDead(_secret)` precedes the yield.

```rust
async fn bad() -> Result<(), Error> {
    let secret_key = SecretKey::new();
    let result = risky_op().await?;  // Err path: secret_key may be live at yield
    // If risky_op() returns Err, the ? operator returns early.
    // In MIR: basic block for Err path may lack StorageDead(_secret_key)
    drop(secret_key);
    Ok(result)
}
```

**Detection**: MIR Err-path basic block has no `StorageDead` for the sensitive local before the `yield`/`GeneratorDrop` terminator.

---

### C-MIR3 — `drop_in_place` for Sensitive Type Has No Zeroize Call

**Tool**: `check_mir_patterns.py` | **Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: medium

**Why source is blind**: When `Drop` is implemented in a separate crate or via blanket impl, source analysis cannot read the drop body. MIR drop-glue functions are generated per-type and show every call inside the drop sequence.

```rust
// The Drop impl may be in an external crate:
impl Drop for ThirdPartySecret {
    fn drop(&mut self) {
        // Does this call zeroize? Source analysis cannot verify.
        self.inner.clear(); // <-- NOT zeroize — MIR reveals no zeroize call
    }
}
```

**Detection**: MIR function `drop_in_place::<SensitiveType>` contains no call to `zeroize`, `volatile_set_memory`, or `memset`.

---

### C-IR1 — DSE Eliminates Correct `zeroize()` Call

**Tool**: `check_llvm_patterns.py` | **Category**: `OPTIMIZED_AWAY_ZEROIZE` | **Severity**: high

**Why source is blind**: The source correctly calls `.zeroize()`. The bug exists only in the optimized IR: LLVM's dead-store elimination pass removes the volatile stores as "dead" before the function returns. Source shows a correct call; IR at O2 shows zero volatile stores.

```rust
fn wipe(key: &mut SecretKey) {
    self.key.zeroize();  // Source looks correct!
    // At O0: 32 volatile stores in IR
    // At O2: 0 volatile stores — DSE eliminated them as "dead before return"
}
```

**Detection**: `volatile store` count drops from N (O0) to 0 (O2) targeting the same buffer.

---

### C-IR2 — Non-Volatile `llvm.memset` on Secret-Sized Range

**Tool**: `check_llvm_patterns.py` | **Category**: `OPTIMIZED_AWAY_ZEROIZE` | **Severity**: high

**Why source is blind**: A `memset` call looks correct in source. IR reveals whether the `llvm.memset` intrinsic has the `volatile` flag set. Without it, LLVM is free to remove the call as a dead store.

```c
// Source: memset(secret, 0, 32); — looks fine
// IR at O0: call void @llvm.memset.p0.i64(ptr %secret, i8 0, i64 32, i1 false)
//                                                                        ^^^^^
//                                                                 volatile=false — removable!
```

**Detection**: `llvm.memset` intrinsic on a buffer matching a sensitive size (16/32/64 bytes) with `volatile=false` flag.

---

### C-IR3 — Secret `alloca` Has `lifetime.end` Without Prior Volatile Store

**Tool**: `check_llvm_patterns.py` | **Category**: `STACK_RETENTION` | **Severity**: high

**Why source is blind**: The local simply goes out of scope in source. IR shows the stack slot's lifetime: if `@llvm.lifetime.end` is reached without any preceding `store volatile`, the slot is released with secret bytes intact.

```rust
fn bad() {
    let mut key = [0u8; 32];
    fill_key(&mut key);
    // key goes out of scope — source shows nothing
    // IR: llvm.lifetime.end(32, %key) with no volatile store before it
    // Stack bytes remain until overwritten
}
```

**Detection**: `@llvm.lifetime.end` on a sensitive `alloca` with no `store volatile` in the dominating path.

---

### C-IR4 — Secret `alloca` Promoted to Registers by SROA/mem2reg

**Tool**: `check_llvm_patterns.py` | **Category**: `OPTIMIZED_AWAY_ZEROIZE` | **Severity**: high

**Why source is blind**: The `alloca` disappears entirely at O2 — LLVM's SROA and mem2reg passes promote it to SSA registers. Any volatile stores targeting that `alloca` are also removed since the `alloca` no longer exists.

```rust
fn bad() {
    let mut key = SecretKey::new();
    // O0 IR: %key = alloca [32 x i8] + volatile stores on drop
    // O2 IR: %key promoted to SSA registers — no alloca, no volatile stores
    use_key(&key);
    // Drop: no volatile stores remain
}
```

**Detection**: `alloca` present at O0 with volatile stores disappears entirely at O2.

---

### C-IR5 — Secret Value in Argument Registers at Call Site

**Tool**: `check_llvm_patterns.py` | **Category**: `REGISTER_SPILL` | **Severity**: medium

**Why source is blind**: Source shows a function call with a sensitive argument. IR shows the calling convention: the value is loaded from memory into argument registers (`%rdi`, `%rsi`, …) before the `call` instruction. The callee may spill those registers to its own stack frame without zeroing them.

```rust
fn bad(key: &SecretKey) {
    callee(key.data);  // Source: pass by value
    // IR: %key_val = load i256, ptr %key; call @callee(i256 %key_val)
    // Callee may spill %rdi/%rsi to its stack frame
}
```

**Detection**: IR shows sensitive `alloca` loaded into argument registers immediately before a `call` instruction.

---

### C-ASM1 — Stack Frame Allocated, No Zero-Stores Before `ret`

**Tool**: `check_rust_asm.py` | **Category**: `STACK_RETENTION` | **Severity**: high

**Why source is blind**: Source shows the function body with no evidence of stack frame contents. Assembly reveals the frame size and whether any zero-store instructions (`movq $0, [rsp+N]` / `str xzr, [sp, #N]`) appear before the `retq`/`ret` instruction.

```asm
; x86-64 example — no zero stores before retq
SecretKey_process:
    subq $64, %rsp      ; allocates 64-byte frame (possibly holds secret)
    ; ... use frame ...
    retq                ; returns without zeroing frame
```

**Detection**: Function with sensitive name allocates stack frame and returns without any zero-store instructions targeting the frame slots.

---

### C-ASM2 — Callee-Saved Register Spilled in Sensitive Function

**Tool**: `check_rust_asm.py` | **Category**: `REGISTER_SPILL` | **Severity**: high

**Why source is blind**: Register allocation decisions are invisible in source or IR. Assembly shows the spill instructions: `movq %r12, [rsp+N]` (x86-64) or `str x19, [sp, #N]` (AArch64). Callee-saved registers (`%r12`–`%r15`/`rbx` on x86-64; `x19`–`x28` on AArch64) are preserved across calls — if they held secret values, the spill creates an unzeroed copy.

```asm
; AArch64 example — x19 (callee-saved) spilled
SecretKey_wipe:
    str x19, [sp, #-16]!   ; spill x19 — may hold secret bytes
    ; ... wipe logic ...
    ldr x19, [sp], #16     ; restore — but spill slot not zeroed
    ret
```

**Detection**: Callee-saved register spill instruction inside a function matching a sensitive name pattern.

---

### C-ASM3 — Caller-Saved Register Spilled in Sensitive Function

**Tool**: `check_rust_asm.py` | **Category**: `REGISTER_SPILL` | **Severity**: medium

**Why source is blind**: Same as C-ASM2 but for caller-saved registers (`%rax`, `%rcx`, etc. / `x0`–`x17` on AArch64). These are not preserved by callees, so the current function is responsible for any secret bytes spilled to the stack.

**Detection**: Caller-saved register spill instruction inside a sensitive function body.

---

### C-ASM4 — `drop_in_place` in Assembly Has No Zeroize/Memset Call

**Tool**: `check_rust_asm.py` | **Category**: `MISSING_SOURCE_ZEROIZE` | **Severity**: medium

**Why source is blind**: Corroborates the MIR-level finding (C-MIR3) with concrete machine code. The emitted assembly for `drop_in_place::<SensitiveType>` contains no `call` to a zeroing function — confirming that the missing zeroize is not merely a MIR-level artifact but reaches the final binary.

**Detection**: `drop_in_place::<SensitiveName>` assembly function contains no `call @zeroize`, `call @volatile_set_memory`, or `call @memset`.

---

## Section D — Undetectable Patterns (TODO)

These patterns are **not detected by any current tool** (`semantic_audit.py`, `find_dangerous_apis.py`, `check_mir_patterns.py`, `check_llvm_patterns.py`, `check_rust_asm.py`). Each entry explains why all current approaches are insufficient and what new capability would be required.

---

### D1 — `Arc<SensitiveType>` / `Rc<SensitiveType>` Deferred Drop

**Category**: `NOT_ON_ALL_PATHS` | **Gap type**: inter-procedural alias/ownership analysis

**Why it's dangerous**: `Drop`/`ZeroizeOnDrop` only runs when the *last* reference is dropped. Any clone of an `Arc<SecretKey>` holds the bytes alive and unzeroed until the reference count reaches zero. If an Arc clone escapes a security boundary (e.g., is passed to a background task), the secret persists until that task completes.

```rust
use std::sync::Arc;

let key = Arc::new(SecretKey::new());  // ZeroizeOnDrop
let clone = Arc::clone(&key);         // reference count = 2
pass_to_background_task(clone);       // may live arbitrarily long
drop(key);                            // count = 1, NOT dropped here
// secret stays in heap until background task finishes
```

**Why undetectable**: `semantic_audit.py` only inspects struct definitions, not call sites. `find_dangerous_apis.py` has no `Arc::clone` pattern — adding one would produce massive false positives without knowing the wrapped type. MIR/IR/ASM tools can detect the drop-glue but cannot statically verify that all Arc clones are dropped before a given boundary.

**Requires**: Inter-procedural ownership/alias tracking (e.g., Polonius dataflow or a custom MIR analysis that tracks Arc reference count propagation across function boundaries).

---

### D2 — `#[repr(C)]` Struct Padding Bytes Not Zeroed

**Category**: `PARTIAL_WIPE` | **Gap type**: struct layout analysis

**Why it's dangerous**: `zeroize()` on a `#[repr(C)]` struct zeros all *declared* fields, but the Rust compiler may insert alignment padding between or after fields. `Zeroize` does not touch padding bytes. An attacker with heap inspection capabilities may recover the secret from pad regions.

```rust
#[repr(C)]
struct MixedSecret {
    flag: u8,      // 1 byte
    // 7 bytes padding here (for alignment of `key`)
    key: [u8; 32],
}
// zeroize() zeros flag and key but NOT the 7 padding bytes
```

**Why undetectable**: `check_rust_asm.py` fires `STACK_RETENTION` only if NO zeroing occurs — it does not detect partial zeroing that skips padding. `check_llvm_patterns.py` counts volatile stores but does not compare bytes-zeroed vs. total struct size.

**Requires**: Struct layout analysis via `rustc -Z print-type-sizes` combined with IR analysis comparing zeroed byte ranges against total struct size.

---

### D3 — `static` / `LazyLock<SensitiveType>` Secret Never Dropped

**Category**: `MISSING_SOURCE_ZEROIZE` | **Gap type**: static item analysis

**Why it's dangerous**: Rust does not call `Drop` on `static` variables at program exit. A `static KEY: LazyLock<ApiKey>` or `static mut SEED: [u8; 32]` is never zeroed, regardless of any `ZeroizeOnDrop` impl.

```rust
use std::sync::LazyLock;

static GLOBAL_KEY: LazyLock<ApiKey> = LazyLock::new(|| ApiKey::generate());
// Drop is never called at program exit — bytes remain in memory until OS reclaim
```

**Why undetectable**: `semantic_audit.py` only processes `kind = "struct"` and `"enum"` items — `kind = "static"` items are silently skipped. `find_dangerous_apis.py` has no `static` binding pattern. Compiler-level tools do not produce zeroing evidence for globals in `.data`/`.bss` sections.

**Requires**: Extend `semantic_audit.py` to process `"static"` kind items from rustdoc JSON, or add a grep in `find_dangerous_apis.py` for `static .* SensitiveName`.

---

### D4 — `async fn` Future Cancellation: State-Machine `Drop` Lacks `ZeroizeOnDrop`

**Category**: `NOT_ON_ALL_PATHS` | **Gap type**: coroutine MIR analysis

**Why it's dangerous**: `find_dangerous_apis.py` and `check_mir_patterns.py` detect secret locals live across `.await` / yield points. The remaining gap is *cancellation safety*: when a `Future` is dropped mid-poll (e.g., by `tokio::select!` dropping the losing branch), any secrets stored in the compiler-generated state-machine struct are freed without zeroing. The generated struct type is anonymous — not written in source.

```rust
async fn process_secret() {
    let key = SecretKey::new();     // stored in coroutine state machine
    phase_one().await;              // suspension point
    phase_two().await;              // another suspension point
    drop(key);
}

// If the Future is cancelled at phase_one().await:
//   - The coroutine struct is dropped
//   - The compiler-generated Drop for the coroutine does NOT zero `key`
//   - Unless the coroutine struct's Drop impl explicitly zeroes captured fields
```

**Why undetectable**: The compiler-generated coroutine struct type is not in the rustdoc index. Its `Drop` impl is generated drop-glue, not user code. `check_mir_patterns.py` detects secrets live at yield points but does not verify that the *coroutine struct's generated Drop glue* calls `zeroize` on each captured field.

**Requires**: `check_mir_patterns.py` extension to identify coroutine/generator MIR bodies, enumerate their captured locals matching sensitive name patterns, and verify presence of `zeroize` calls in the generated Drop glue for the coroutine state machine type.

---

### D5 — `Cow<'_, [u8]>` or `Cow<'_, str>` Silently Cloning a Secret

**Category**: `SECRET_COPY` | **Gap type**: type-taint tracking

**Why it's dangerous**: `Cow::to_owned()`, `Cow::into_owned()`, and `Cow::Owned(...)` allocate an owned copy of the bytes with no tracking. The clone does not inherit any `ZeroizeOnDrop` guarantee. Since `Cow` can hold a reference or an owned value, and conversion between the two is implicit, secrets can be silently promoted to owned allocations.

```rust
use std::borrow::Cow;

fn process(data: Cow<'_, [u8]>) {
    let owned: Vec<u8> = data.into_owned(); // secret bytes in plain Vec
    // owned has no ZeroizeOnDrop — never zeroed
}
```

**Why undetectable**: A source grep on `Cow` alone has unacceptably high false-positive rate without knowing whether the held type is sensitive. `find_dangerous_apis.py` cannot distinguish `Cow<'_, [u8]>` holding secrets from `Cow<'_, str>` holding log messages. MIR/IR would show the allocation but correlation back to "this Cow holds sensitive data" requires type-level taint tracking that current regex-based tools do not perform.

**Requires**: Inter-procedural type taint analysis to track whether the `Cow` inner type originates from a sensitive allocation.

---

### D6 — `mem::swap` Moving Secret Bytes to Non-Zeroizing Location

**Category**: `SECRET_COPY` | **Gap type**: type-aware MIR operand analysis

**Why it's dangerous**: `mem::swap(&mut secret_key, &mut output_buf)` moves the secret bytes bitwise into `output_buf`, which likely does not implement `ZeroizeOnDrop`. The original location is overwritten with `output_buf`'s prior content. The secret now lives in `output_buf` with no zeroing guarantee, while the original location no longer contains the secret (so its Drop impl zeroes the wrong data).

```rust
fn bad(key: &mut SecretKey, output: &mut Vec<u8>) {
    // BAD: key bytes moved into output (plain Vec, no ZeroizeOnDrop)
    unsafe {
        let key_bytes: &mut Vec<u8> = std::mem::transmute(key);
        std::mem::swap(key_bytes, output);
    }
    // key is now "empty" — key.drop() zeroes nothing meaningful
    // output holds the secret bytes with no zeroing guarantee
}
```

**Why undetectable**: `find_dangerous_apis.py` has no `mem::swap` pattern; adding one without type awareness would flag every `swap` call in the codebase. In MIR, `mem::swap` is represented as a pair of assignments — detectable if the checker verifies the types of both operands, but this is not currently implemented.

**Requires**: Type-aware MIR analysis of swap operands to detect when a sensitive type is swapped into a non-zeroizing container.
