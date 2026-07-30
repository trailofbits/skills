# C++23 Features (Usable Today)

These features have solid compiler support (GCC 13+, Clang 17+, MSVC 17.4+) and deliver immediate value. Adopt them now.

## std::expected<T, E>

Type-safe error handling with monadic chaining. The most impactful C++23 feature for everyday code.

### What It Replaces

Error codes + output parameters, nullable returns, exceptions at API boundaries where failure is expected (not exceptional).

### Basic Usage

```cpp
#include <expected>

enum class ParseError { empty_input, invalid_format, overflow };

std::expected<int, ParseError> parse_int(std::string_view s) {
    if (s.empty())
        return std::unexpected(ParseError::empty_input);
    // ... parsing logic ...
    return 42;
}

// Caller must handle both paths
auto result = parse_int("123");
if (result) {
    use(*result);  // or result.value()
} else {
    handle(result.error());
}
```

### Monadic Chaining

Chain operations without nested if-checks:

```cpp
std::expected<Config, Error> load_config(const Path& p) {
    return read_file(p)                    // expected<string, Error>
        .and_then(parse_toml)              // expected<TomlValue, Error>
        .and_then(validate_config)         // expected<Config, Error>
        .transform(apply_defaults);        // expected<Config, Error>
}
```

- `.and_then(f)` — if value, call `f(value)` which returns a new `expected`
- `.transform(f)` — if value, call `f(value)` and wrap result in `expected`
- `.or_else(f)` — if error, call `f(error)` which returns a new `expected`
- `.transform_error(f)` — if error, call `f(error)` and wrap result

### When to Use vs Exceptions

- **Use `std::expected`**: expected failures (file not found, parse error, validation failure), performance-critical paths, codebases that ban exceptions
- **Use exceptions**: truly exceptional conditions (out of memory, programmer error), deep call stacks where propagation cost matters

### Compiler Support

GCC 13+, Clang 17+, MSVC 17.4+

## std::print / std::println

Type-safe formatted output. Essentially `fmt::print` standardized.

### Basic Usage

```cpp
#include <print>

std::println("Hello, {}!", name);              // with newline
std::print("x = {}, y = {}\n", x, y);         // without auto-newline
std::println("{:>10.2f}", 3.14159);            // format spec: right-aligned, 2 decimal
std::println("{0} is {0}", value);             // reuse argument by index
```

### What It Replaces

```cpp
// BEFORE: printf (type-unsafe, format string vulnerabilities)
printf("Name: %s, Age: %d\n", name.c_str(), age);

// BEFORE: iostream (verbose, stateful, slow)
std::cout << "Name: " << name << ", Age: " << age << std::endl;

// AFTER: type-safe, readable, fast
std::println("Name: {}, Age: {}", name, age);
```

### Relationship to {fmt}

`std::print` IS the `{fmt}` library adopted into the standard, by the same author (Victor Zverovich). If you already use `{fmt}`, switching to `std::print` removes one dependency. `{fmt}` still has extras `std::print` lacks (color output, named arguments).

### Compiler Support

GCC 14+, Clang 18+, MSVC 17.4+

## Deducing this

Eliminates const/non-const overload duplication and simplifies CRTP.

### The Problem It Solves

```cpp
// BEFORE: duplicated logic for const and non-const
class Buffer {
    std::vector<char> data_;
public:
    char& operator[](size_t i) { return data_[i]; }
    const char& operator[](size_t i) const { return data_[i]; }
    // Often 4 overloads: const/non-const x lvalue/rvalue
};

// AFTER: one function handles all qualifications
class Buffer {
    std::vector<char> data_;
public:
    template <typename Self>
    auto&& operator[](this Self&& self, size_t i) {
        return std::forward<Self>(self).data_[i];
    }
};
```

### Simplified CRTP

```cpp
// BEFORE: arcane template pattern
template <typename Derived>
struct Base {
    void interface() {
        static_cast<Derived*>(this)->implementation();
    }
};

// AFTER: no template parameter needed
struct Base {
    void interface(this auto&& self) {
        self.implementation();
    }
};
```

### Recursive Lambdas

```cpp
// BEFORE: std::function or Y-combinator
std::function<int(int)> fib = [&](int n) {
    return n <= 1 ? n : fib(n-1) + fib(n-2);
};

// AFTER: direct recursion
auto fib = [](this auto&& self, int n) -> int {
    return n <= 1 ? n : self(n-1) + self(n-2);
};
```

### Compiler Support

GCC 14+, Clang 18+, MSVC 19.32+

## std::ranges::to (Materializing Views)

Converts lazy range views into concrete containers. The missing piece from C++20 ranges.

```cpp
#include <ranges>

auto vec = data
    | std::views::filter(is_valid)
    | std::views::transform(process)
    | std::ranges::to<std::vector>();  // materialize into a vector

// Works with any container
auto set = data
    | std::views::transform(normalize)
    | std::ranges::to<std::set>();
```

Without `std::ranges::to`, you had to manually construct containers from view iterators — awkward and error-prone. This completes the C++20 ranges story.

### Compiler Support

GCC 14+, Clang 17+, MSVC 17.4+

## std::flat_map / std::flat_set

Cache-friendly sorted containers backed by contiguous storage.

### When to Prefer Over std::map

- **Read-heavy workloads** — lookup is 8-17x faster than `std::map` for small-medium sizes
- **Small-to-medium maps** (up to ~1000 elements)
- **Cache-sensitive code** — contiguous memory vs node-based tree

### When NOT to Use

- **Insert-heavy workloads** — insertion is O(n) due to shifting elements
- **Large maps with frequent mutations** — `std::map`'s O(log n) insert wins
- **Iterator stability required** — flat containers invalidate iterators on insert

### Usage

```cpp
#include <flat_map>

std::flat_map<std::string, int> scores;
scores["alice"] = 100;
scores["bob"] = 85;

auto it = scores.find("alice");  // fast binary search on sorted vector
```

### Compiler Support

GCC 15+, Clang 18+, MSVC 17.6+

## std::generator<T>

Lazy coroutine generators for producing sequences on demand.

### Usage

```cpp
#include <generator>

std::generator<int> fibonacci() {
    int a = 0, b = 1;
    while (true) {
        co_yield a;
        auto next = a + b;
        a = b;
        b = next;
    }
}

// Lazy — only computes as many values as consumed
for (auto val : fibonacci() | std::views::take(10)) {
    std::println("{}", val);
}
```

### Compiler Support

MSVC 17.4+, GCC 14+ (partial), Clang catching up. Wait for broader support before relying on it.

## import std

Import the entire standard library as a module.

```cpp
import std;  // replaces ALL #include <...> for standard headers

int main() {
    std::println("Hello from modules!");
}
```

### Caveats

- Build system support varies (CMake 3.28+ with some generators)
- Third-party libraries are mostly not module-ready
- Mixing headers and modules requires care
- Best for new projects; migration of existing code is nontrivial

### Compiler Support

GCC 15+, Clang 18+ (partial), MSVC 17.5+
