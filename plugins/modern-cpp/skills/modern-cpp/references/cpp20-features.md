# C++20 Features (Default Practice)

These features are mature, well-supported (GCC 12+, Clang 14+, MSVC 17.0+), and should be the default way to write C++.

## Concepts

Constrain templates with readable, declarative requirements.

### What They Replace

SFINAE and `std::enable_if` — the arcane template tricks that produced unreadable error messages.

### Standard Concepts

Use concepts from `<concepts>` before writing custom ones:

```cpp
#include <concepts>

template <std::integral T>
T gcd(T a, T b) { return b == 0 ? a : gcd(b, a % b); }

template <std::invocable<int> F>
void apply(F&& fn, int value) { fn(value); }
```

Key standard concepts: `std::integral`, `std::floating_point`, `std::invocable`, `std::copyable`, `std::movable`, `std::regular`, `std::predicate`, `std::ranges::range`.

### Custom Concepts

```cpp
template <typename T>
concept Serializable = requires(T obj, std::ostream& os) {
    { obj.serialize(os) } -> std::same_as<void>;
    { T::deserialize(os) } -> std::same_as<T>;
};

void save(const Serializable auto& obj, std::ostream& os) {
    obj.serialize(os);
}
```

### requires Clauses vs concept Keyword

- **`concept`**: reusable, named constraint — define when used in 2+ places
- **`requires`**: inline, one-off constraint

```cpp
// One-off: use requires
template <typename T>
    requires (sizeof(T) <= 16)
void small_copy(T value);

// Reusable: define a concept
template <typename T>
concept SmallType = sizeof(T) <= 16;
```

### Before / After

```cpp
// BEFORE: SFINAE — cryptic, fragile
template <typename T,
          typename = std::enable_if_t<std::is_arithmetic_v<T>>>
T square(T x) { return x * x; }
// Error: "no matching function for call to 'square'" + 50 lines of template noise

// AFTER: concepts — readable, clear errors
template <typename T>
    requires std::is_arithmetic_v<T>
T square(T x) { return x * x; }
// Error: "constraint 'is_arithmetic_v<string>' not satisfied"
```

## Ranges

Composable, lazy algorithms that operate on range objects instead of iterator pairs.

### Key Patterns

```cpp
#include <ranges>
#include <algorithm>

std::vector<int> data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

// View pipeline — lazy, no intermediate allocations
auto result = data
    | std::views::filter([](int x) { return x % 2 == 0; })
    | std::views::transform([](int x) { return x * x; });

// Range algorithms — accept ranges directly
std::ranges::sort(data);
auto it = std::ranges::find(data, 42);
auto [mn, mx] = std::ranges::minmax(data);
```

To materialize a lazy view into a concrete container, use `std::ranges::to<>()` from C++23 — see [cpp23-features.md](./cpp23-features.md).

### Useful Views

| View | Purpose |
|------|---------|
| `views::filter` | Keep elements matching predicate |
| `views::transform` | Apply function to each element |
| `views::take(n)` | First n elements |
| `views::drop(n)` | Skip first n elements |
| `views::split(delim)` | Split range on delimiter |
| `views::join` | Flatten nested ranges |
| `views::enumerate` | Pairs of (index, element) — C++23 |
| `views::zip` | Zip multiple ranges — C++23 |
| `views::chunk(n)` | Group into chunks of n — C++23 |
| `views::concat` | Concatenate ranges — C++26 |

## std::span<T>

Non-owning view over contiguous memory. Replaces pointer + length pairs.

```cpp
#include <span>

// BEFORE: dangerous — no size information
void process(int* data, size_t len);

// AFTER: carries size, bounds-checkable
void process(std::span<int> data) {
    for (auto& val : data) { /* safe iteration */ }
    data[0];    // unchecked (fast)
    data.at(0); // bounds-checked with hardened libc++
}

// Works with any contiguous container
std::vector<int> vec = {1, 2, 3};
std::array<int, 3> arr = {4, 5, 6};
int c_arr[] = {7, 8, 9};

process(vec);    // implicit conversion
process(arr);    // implicit conversion
process(c_arr);  // implicit conversion
```

Use `std::span<const T>` for read-only views.

## std::format

Type-safe string formatting, replacing `sprintf` and iostream chains.

```cpp
#include <format>

std::string s = std::format("Hello, {}!", name);
std::string t = std::format("{:>10.2f}", 3.14159);   // right-aligned, 2 decimal
std::string u = std::format("{:#x}", 255);            // 0xff
std::string v = std::format("{:%Y-%m-%d}", std::chrono::system_clock::now());
```

### Custom Formatters

```cpp
template <>
struct std::formatter<Point> {
    constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }
    auto format(const Point& p, format_context& ctx) const {
        return std::format_to(ctx.out(), "({}, {})", p.x, p.y);
    }
};

// Now works:
std::println("Position: {}", my_point);
```

## Three-Way Comparison (<=>)

Generate all comparison operators from one declaration.

```cpp
#include <compare>

struct Point {
    int x, y;
    auto operator<=>(const Point&) const = default;
    // Generates: ==, !=, <, >, <=, >=
};
```

For custom ordering:
```cpp
struct Version {
    int major, minor, patch;
    std::strong_ordering operator<=>(const Version& other) const {
        if (auto cmp = major <=> other.major; cmp != 0) return cmp;
        if (auto cmp = minor <=> other.minor; cmp != 0) return cmp;
        return patch <=> other.patch;
    }
    bool operator==(const Version&) const = default;
};
```

## Designated Initializers

Named field initialization for aggregates.

```cpp
struct Config {
    int port = 8080;
    bool verbose = false;
    int max_connections = 100;
};

// Clear which fields are being set
Config cfg = {.port = 3000, .verbose = true};
// .max_connections gets its default value (100)
```

## std::jthread

Thread with automatic joining and cooperative cancellation.

```cpp
#include <thread>

// BEFORE: forgetting to join causes std::terminate
std::thread t(work);
// ... if exception thrown here, t.join() never called → crash

// AFTER: auto-joins on destruction
std::jthread t(work);
// destructor calls request_stop() then join() — always safe

// Cooperative cancellation via stop token
std::jthread worker([](std::stop_token stoken) {
    while (!stoken.stop_requested()) {
        do_work();
    }
});
worker.request_stop();  // signal the thread to exit
// destructor waits for thread to finish
```

## Coroutines

Suspendable functions for lazy computation and async I/O.

### When to Use

- I/O-bound async work (network, file system)
- Lazy sequence generation (use `std::generator` from C++23)
- State machines that would otherwise be complex

### When NOT to Use

- CPU-bound parallel work (coroutines cooperate, they don't parallelize)
- Simple synchronous code (unnecessary complexity)
- Reimplementing coroutine types (`generator`, `task`) that libraries already provide
- Custom awaiters are fine when adapting async libraries to coroutines — that's often the only way to bridge callback-based APIs

### With std::generator (C++23)

```cpp
std::generator<int> range(int start, int end) {
    for (int i = start; i < end; ++i)
        co_yield i;
}

for (auto val : range(0, 10)) {
    std::println("{}", val);
}
```
