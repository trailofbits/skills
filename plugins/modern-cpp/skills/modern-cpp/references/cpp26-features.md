# C++26 Features

C++26 was finalized in March 2026 — the most significant release since C++11. This reference covers the features worth knowing about, ranked by practical impact.

## Reflection (Game-Changer)

Static reflection is the single most impactful C++26 feature. It lets programs inspect types, members, and functions at compile time and generate code with zero runtime overhead.

### What It Eliminates

- Per-struct serialization functions (JSON, protobuf, XML)
- Code generators (protobuf codegen, Qt MOC, flatbuffers)
- Macro-based registration systems (enum-to-string, type registries)
- Verbose template metaprogramming with `std::tuple` tricks

### Core Syntax

The `^^` operator ("reflection operator") reflects a construct into a `std::meta::info` value:

```cpp
#include <meta>

constexpr auto type_info = ^^int;  // reflect the type 'int'
constexpr auto member_info = ^^MyStruct::field;  // reflect a member
```

Key `std::meta::` functions:
- `nonstatic_data_members_of(^^T)` — enumerate struct members
- `identifier_of(member)` — get member name as string
- `type_of(member)` — get member type
- `enumerators_of(^^E)` — enumerate enum values

The splice operator `[:expr:]` converts a reflection back into code.

### Before / After

```cpp
// BEFORE: write this for EVERY struct, update when fields change
json to_json(const Player& p) {
    return {{"name", p.name}, {"health", p.health},
            {"x", p.x}, {"y", p.y}, {"score", p.score}};
}

// AFTER: one function, works for ANY struct, never needs updating
template <typename T>
json to_json(const T& obj) {
    json result;
    template for (constexpr auto member :
                  std::meta::nonstatic_data_members_of(^^T)) {
        result[std::meta::identifier_of(member)] = obj.[:member:];
    }
    return result;
}
```

### Enum-to-String (Classic Pain Point)

```cpp
// BEFORE: manual mapping, breaks when you add values
const char* to_string(Color c) {
    switch (c) {
        case Color::Red: return "Red";
        case Color::Green: return "Green";
        case Color::Blue: return "Blue";
    }
}

// AFTER: works for any enum, automatically
template <typename E>
    requires std::is_enum_v<E>
std::string to_string(E value) {
    template for (constexpr auto e : std::meta::enumerators_of(^^E)) {
        if (value == [:e:])
            return std::string(std::meta::identifier_of(e));
    }
    return "<unknown>";
}
```

### Compiler Support

- **GCC 16** (April 2026): Reflection merged in trunk
- **Clang**: Bloomberg experimental fork ([github.com/bloomberg/clang-p2996](https://github.com/bloomberg/clang-p2996)), mainline catching up
- **MSVC**: Not yet

### When to Use / Not Use

- **Use for**: Serialization, deserialization, ORM mapping, debug printing, enum conversion, logging, plugin systems
- **Don't use for**: Simple code where templates or concepts suffice; reflection adds compile-time complexity

## Contracts

Language-level preconditions, postconditions, and assertions.

### Syntax

```cpp
// Precondition — checked before function body executes
void transfer(Account& from, Account& to, int amount)
    pre (amount > 0)
    pre (from.balance >= amount)
    post (from.balance >= 0)
{
    from.balance -= amount;
    to.balance += amount;
}

// In-body assertion
void process(std::span<int> data) {
    contract_assert(!data.empty());
    // ...
}
```

### Enforcement Modes

| Mode | Behavior |
|------|----------|
| `enforce` | Check, call violation handler, terminate if it returns |
| `observe` | Check, call violation handler, continue execution |
| `ignore` | Skip the check entirely |
| `quick_enforce` | Check, terminate immediately (no handler) |

Mode is selected at build time, not per-contract.

### Before / After

```cpp
// BEFORE: preconditions buried in body, invisible to callers
int divide(int a, int b) {
    assert(b != 0);  // only in debug builds, invisible to IDE
    return a / b;
}

// AFTER: preconditions on declaration, visible to callers and tools
int divide(int a, int b)
    pre (b != 0);
```

### Honest Limitations

- **No virtual function contracts** — deferred to a future standard
- **Controversial design** — Bjarne Stroustrup has publicly criticized the design
- **Compiler support is experimental** — GCC trunk has it, not production-ready
- **Side effects in contract expressions are unspecified**

### Recommendation

Adopt cautiously. Use for new API boundaries where preconditions should be visible. Don't rewrite existing assert() usage wholesale until compilers mature.

## Memory Safety Improvements

### Erroneous Behavior for Uninitialized Reads

Uninitialized local variable reads are no longer undefined behavior. They become "erroneous behavior" — well-defined (the variable holds a valid but unspecified value) but diagnosable.

**Practical impact:** Compilers can no longer use "this read is UB, so I can optimize away your null check" reasoning. Just recompiling as C++26 gives you this protection.

**Opt-out:** `[[indeterminate]]` attribute for performance-critical code where you can prove the variable is written before read.

### Hardened Standard Library

Bounds-checking preconditions added to `operator[]`, `front()`, `back()`, etc. on `std::vector`, `std::span`, `std::string`, `std::string_view`, `std::array`, `std::optional`, `std::expected`.

**Google's deployment results:**
- Deployed across Chrome and entire server fleet
- ~0.3% average performance overhead
- 1000+ previously undetected bugs found
- 30% reduction in production segfault rate

**Enable today** (no need to wait for C++26):
```
-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST
```

See [compiler-hardening.md](./compiler-hardening.md) for details.

## Smaller Wins

### #embed

Embed binary data at compile time without external tools:
```cpp
// BEFORE: xxd -i data.bin > data.h (slow, 70+ seconds for 40MB)
static const unsigned char data[] = { 0x89, 0x50, 0x4E, ... };

// AFTER: instant, handled by compiler
static constexpr unsigned char data[] = {
    #embed "data.bin"
};
```

GCC 15+ and Clang 19+ support `#embed`.

### std::inplace_vector<T, N>

Fixed-capacity, dynamically-resizable vector with no heap allocation. Replaces `boost::static_vector`.

```cpp
std::inplace_vector<int, 64> small_buf;  // max 64 elements, stack-allocated
small_buf.push_back(42);  // works like vector
// small_buf.push_back() when full: throws (or use try_push_back for fallible API)
```

### std::function_ref

Non-owning, non-allocating callable wrapper. The `std::string_view` of callables.

```cpp
// BEFORE: std::function allocates, type-erases, is nullable
void for_each(std::span<int> data, std::function<void(int)> fn);

// AFTER: zero allocation, passable in registers
void for_each(std::span<int> data, std::function_ref<void(int)> fn);
```

### std::indirect<T> and std::polymorphic<T>

Value-semantic wrappers for heap-allocated objects:
- `std::indirect<T>` — like `unique_ptr` but copyable (deep copies)
- `std::polymorphic<T>` — adds virtual dispatch with value semantics

### Placeholder Variables

```cpp
auto [x, _, _] = get_triple();     // ignore second and third
std::lock_guard _(mutex);          // unnamed RAII guard
for (auto _ : std::views::iota(0, 5)) { /* repeat 5 times */ }
```

### Other Notable Additions

- **Pack indexing** `T...[N]` — direct variadic pack access
- **Saturation arithmetic** — `std::add_sat`, `std::sub_sat`, `std::mul_sat`
- **`= delete("reason")`** — document why an overload is deleted
- **`std::hive`** — bucket container with stable pointers and O(1) insert/erase
- **`<simd>`** — data-parallel SIMD types
- **`<linalg>`** — BLAS-based linear algebra
