# Safe C++ Idioms

Security patterns organized by vulnerability class. Each section explains what exploitable bugs the pattern prevents and what modern C++ features eliminate them.

## Memory Safety

### Ownership: Smart Pointers

Use smart pointers for all owning relationships. Raw pointers are only for non-owning observation.

```cpp
// Unique ownership (default choice)
auto widget = std::make_unique<Widget>(args...);
process(*widget);  // borrow via reference

// Shared ownership (only when genuinely shared)
auto shared = std::make_shared<Config>(args...);
auto copy = shared;  // reference count incremented

// Non-owning observation
Widget* observer = widget.get();  // does NOT own, must not delete
std::weak_ptr<Config> watcher = shared;  // non-owning, expires safely
```

**Selection guide:**
- `std::unique_ptr` — default. Zero overhead vs raw pointer. Use for exclusive ownership.
- `std::shared_ptr` — only when multiple owners genuinely need to extend lifetime. Has overhead (refcount, control block).
- `std::weak_ptr` — observe shared objects without preventing destruction. Use to break cycles.
- Raw `T*` / `T&` — non-owning only. Never `delete` a raw pointer you didn't `new`.

### Non-Owning Views

```cpp
// DANGEROUS: pointer + length — no size information
void process(const char* data, size_t len);

// SAFE: carries size, bounds-checkable
void process(std::span<const char> data);

// DANGEROUS: null-terminated assumption
void log(const char* message);

// SAFE: carries length, works with string and string_view
void log(std::string_view message);
```

**Rules:**
- Function parameters: `std::span<T>` for arrays, `std::string_view` for strings
- Return values: return owned types (`std::vector`, `std::string`), not views
- Never return a `span` or `string_view` to a local

### Optional vs Nullable Pointers

```cpp
// DANGEROUS: null pointer used as "no value"
Widget* find(int id);  // caller might forget to check

// SAFE: explicit optionality
std::optional<Widget> find(int id);  // caller must unwrap

// Check before use
if (auto w = find(42)) {
    use(w.value());  // or *w
}
```

### Value Semantics by Default

Prefer value types over heap-allocated pointer indirection. C++26 adds `std::indirect<T>` and `std::polymorphic<T>` for cases where heap allocation is needed but value semantics are desired.

## Type Safety

### Variant Over Union

```cpp
// DANGEROUS: union — accessing wrong member is UB
union Value { int i; double d; std::string s; };  // UB: string in union

// SAFE: variant — type-checked access
std::variant<int, double, std::string> value;
value = "hello";

// Visit pattern — compiler ensures all types handled
std::visit([](auto&& v) { std::println("{}", v); }, value);

// Throws std::bad_variant_access if wrong type
auto& s = std::get<std::string>(value);
```

### Safe Type Punning

```cpp
// DANGEROUS: reinterpret_cast — undefined behavior for most types
float f = 3.14f;
int bits = *reinterpret_cast<int*>(&f);  // UB!

// SAFE: bit_cast — defined behavior, constexpr-compatible
int bits = std::bit_cast<int>(f);  // OK, well-defined
```

### Enum Class

```cpp
// DANGEROUS: plain enum — implicit int conversion, leaks names
enum Color { Red, Green, Blue };
int x = Red;  // compiles silently
if (Red == 0)  // compiles silently

// SAFE: enum class — scoped, no implicit conversion
enum class Color : uint8_t { Red, Green, Blue };
// int x = Color::Red;     // compile error
// if (Color::Red == 0)    // compile error
auto c = Color::Red;       // must use scope
```

### Preventing Misuse

```cpp
// Mark functions where ignoring the return is likely a bug
[[nodiscard]] std::expected<Data, Error> load(const Path& p);

// Prevent implicit conversions
class UserId {
public:
    explicit UserId(int64_t id) : id_(id) {}
    // UserId u = 42;  // compile error — must be explicit
private:
    int64_t id_;
};

// Document why an overload is forbidden (C++26)
void process(std::string_view s);
void process(std::nullptr_t) = delete("passing nullptr is a bug — use empty string");
```

## Integer Safety

### Narrowing Detection

```cpp
#include <utility>

void safe_convert(int64_t big_value) {
    // CHECK: is the value representable in the target type?
    if (std::in_range<int32_t>(big_value)) {
        int32_t small = static_cast<int32_t>(big_value);
        use(small);
    } else {
        handle_overflow();
    }
}
```

### Saturation Arithmetic (C++26)

```cpp
#include <numeric>

// For signal processing, image manipulation, counters
uint8_t pixel = std::add_sat<uint8_t>(200, 100);  // 255, not 44

// Useful for counters that should not wrap
size_t count = std::add_sat(count, increment);
```

### Compiler Warnings

Enable `-Wconversion` and `-Wsign-conversion` to catch implicit narrowing at compile time. These flags alone prevent a significant class of integer bugs.

## Concurrency Safety

### Lock Management

```cpp
// DANGEROUS: manual lock/unlock — exception-unsafe, easy to forget
std::mutex mtx;
mtx.lock();
do_work();      // if this throws, mutex is never unlocked
mtx.unlock();

// SAFE: scoped_lock — exception-safe, supports multiple mutexes
{
    std::scoped_lock lock(mtx);
    do_work();  // mutex released when lock goes out of scope
}

// Multiple mutexes — deadlock-free (sorted lock acquisition)
std::scoped_lock lock(mutex_a, mutex_b);
```

### Thread Management

```cpp
// DANGEROUS: std::thread — forgetting join() calls std::terminate
std::thread t(work);
// if exception before join → crash

// SAFE: jthread — auto-joins, supports cooperative cancellation
std::jthread t([](std::stop_token stoken) {
    while (!stoken.stop_requested()) {
        do_work();
    }
});
// destructor calls request_stop() then join()
```

### Atomics

```cpp
// DANGEROUS: volatile does NOT provide atomicity or ordering
volatile int counter = 0;  // data race in multi-threaded code

// SAFE: atomic with explicit memory ordering
std::atomic<int> counter{0};
counter.fetch_add(1, std::memory_order_relaxed);  // specify ordering
```

## Initialization Safety

### constexpr / consteval

Computation at compile time is UB-free by design — the compiler rejects any undefined behavior in constant expressions.

```cpp
constexpr int factorial(int n) {
    // If this has UB (e.g., signed overflow), it's a compile error
    int result = 1;
    for (int i = 2; i <= n; ++i) result *= i;
    return result;
}

consteval int must_be_compile_time(int n) {
    return factorial(n);  // guaranteed compile-time evaluation
}
```

### Always Initialize

```cpp
// DANGEROUS: uninitialized variable
int x;           // indeterminate value (erroneous behavior in C++26)
use(x);          // bug

// SAFE: initialize at declaration
int x = 0;
int y{};         // value-initialized (zero for scalars)
auto z = compute_value();
```

Enable `-ftrivial-auto-var-init=zero` to catch cases you miss.

### Rule of Five / Zero

```cpp
// Rule of Zero: prefer this — let the compiler generate everything
struct Config {
    std::string name;
    std::vector<int> values;
    // No destructor, copy/move constructors, or assignment needed
    // Compiler-generated versions do the right thing
};

// Rule of Five: if you must manage a resource manually
class FileHandle {
    int fd_;
public:
    ~FileHandle();
    FileHandle(const FileHandle&);
    FileHandle& operator=(const FileHandle&);
    FileHandle(FileHandle&&) noexcept;
    FileHandle& operator=(FileHandle&&) noexcept;
};
// But prefer RAII wrappers (unique_ptr with custom deleter) over this
```

## Iterator Safety

### Prefer Algorithms Over Raw Loops

```cpp
// RISKY: off-by-one, iterator invalidation
for (auto it = vec.begin(); it != vec.end(); ++it) {
    if (should_remove(*it)) {
        vec.erase(it);  // BUG: invalidates iterator
    }
}

// SAFE: erase-remove idiom
std::erase_if(vec, should_remove);  // C++20

// SAFE: range-based algorithms
auto results = data
    | std::views::filter(is_valid)
    | std::views::transform(process);
```

### Iterator Invalidation Awareness

Know which operations invalidate iterators on which containers. When in doubt, use indices or rebuild the container. Trail of Bits' [Itergator](https://github.com/trailofbits/itergator) tool detects iterator invalidation bugs via CodeQL.
