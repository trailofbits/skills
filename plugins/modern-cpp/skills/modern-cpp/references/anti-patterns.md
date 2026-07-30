# Anti-Patterns: Legacy to Modern C++

Comprehensive reference of legacy C++ patterns and their modern replacements. Each entry explains WHY the modern version is better — not just that it exists.

## Memory Management

| Avoid | Use Instead | Standard | Why |
|-------|-------------|----------|-----|
| `new T` / `delete p` | `std::make_unique<T>()` | C++14 | Eliminates memory leaks, double-free; exception-safe construction |
| `new T[]` / `delete[] p` | `std::vector<T>` or `std::make_unique<T[]>(n)` | C++14 | Automatic sizing, bounds-aware with `.at()` |
| Raw owning `T*` | `std::unique_ptr<T>` | C++11 | RAII ownership; zero overhead vs raw pointer |
| Raw shared `T*` | `std::shared_ptr<T>` via `std::make_shared` | C++11 | Reference-counted lifetime; thread-safe refcount |
| C arrays `int arr[N]` | `std::array<int, N>` | C++11 | Value semantics, `.size()`, no decay to pointer |
| `malloc`/`free` | Containers or smart pointers | C++11 | Type-safe, exception-safe, RAII |
| `memcpy(dst, src, n)` | `std::copy(src, src+n, dst)` or container assignment | C++11 | Type-safe, works with non-trivial types |
| `memset(buf, 0, n)` | Value initialization or `std::fill` | C++11 | No risk of zeroing non-trivially-constructible types |
| Pointer + length parameter pairs | `std::span<T>` | C++20 | Carries size, bounds-checkable with hardened mode |
| `const char*` for non-owning strings | `std::string_view` | C++17 | Carries length, no null-terminator assumption |
| Nullable `T*` for optional values | `std::optional<T>` | C++17 | Explicit intent, no null dereference risk |

## Type Safety

| Avoid | Use Instead | Standard | Why |
|-------|-------------|----------|-----|
| C-style cast `(int)x` | `static_cast<int>(x)` | C++11 | Explicit intent, greppable, won't silently reinterpret |
| `reinterpret_cast` for type punning | `std::bit_cast<T>(x)` | C++20 | Defined behavior, `constexpr`-compatible |
| `union` for variants | `std::variant<A, B, C>` | C++17 | Type-safe access via `std::visit`, no silent UB |
| `void*` type erasure | `std::any`, `std::variant`, or templates | C++17 | Type-safe, no manual casting |
| Plain `enum` | `enum class` | C++11 | Scoped, no implicit int conversion |
| `NULL` or `0` | `nullptr` | C++11 | Unambiguous null pointer, no overload confusion |
| Implicit single-arg constructors | Mark `explicit` | C++11 | Prevents surprising implicit conversions |
| Unchecked return values | `[[nodiscard]]` | C++17 | Compiler warns when return value is ignored |
| `= delete` without message | `= delete("reason")` | C++26 | Documents why the overload is forbidden |

## Error Handling

| Avoid | Use Instead | Standard | Why |
|-------|-------------|----------|-----|
| Error codes + out-params | `std::expected<T, E>` | C++23 | Composable with `.and_then()`, `.transform()`, `.or_else()` |
| `assert()` macro | `contract_assert` | C++26 | Visible to tooling, configurable enforcement modes |
| Unchecked `errno` | `std::expected` or exceptions | C++23 | Forces caller to handle the error path |
| Throwing in constructor for expected failures | Factory returning `std::expected` | C++23 | No exception overhead for expected failure paths |

## I/O and Formatting

| Avoid | Use Instead | Standard | Why |
|-------|-------------|----------|-----|
| `printf` / `sprintf` | `std::format` / `std::print` | C++20/23 | Type-safe, no format string vulnerabilities |
| `snprintf` for string building | `std::format` | C++20 | Returns `std::string`, no buffer management |
| `std::cout << a << b << c` | `std::println("{} {} {}", a, b, c)` | C++23 | Readable, no stream state issues, faster |

## Concurrency

| Avoid | Use Instead | Standard | Why |
|-------|-------------|----------|-----|
| `mutex.lock()` / `mutex.unlock()` | `std::scoped_lock` | C++17 | Exception-safe, supports multiple mutexes (no deadlock) |
| `std::thread` + manual `.join()` | `std::jthread` | C++20 | Auto-joins on destruction, supports stop tokens |
| `volatile` for thread sync | `std::atomic<T>` | C++11 | Actually guarantees atomic operations and memory ordering |
| Manual condition variable notify | `std::latch`, `std::barrier` | C++20 | Higher-level, less error-prone synchronization |
| Hand-rolled atomic CAS loops | `std::atomic::fetch_max/fetch_min` | C++26 | Standard, correct, optimized |

## Metaprogramming

| Avoid | Use Instead | Standard | Why |
|-------|-------------|----------|-----|
| `std::enable_if` / SFINAE | Concepts + `requires` | C++20 | Readable constraints, clear error messages |
| CRTP for static polymorphism | Deducing `this` | C++23 | No template boilerplate, works with lambdas |
| Macros for code generation | Static reflection | C++26 | Zero-overhead, composable, type-safe |
| `std::tuple_element` for pack access | Pack indexing `T...[N]` | C++26 | Direct access, no recursive template machinery |
| `std::function` for non-owning callbacks | `std::function_ref` | C++26 | No allocation, passable in registers |

## Containers

| Avoid | Use Instead | Standard | Why |
|-------|-------------|----------|-----|
| `std::map` for read-heavy lookups | `std::flat_map` | C++23 | Cache-friendly, 8-17x faster lookup for small-medium maps |
| `boost::static_vector` | `std::inplace_vector` | C++26 | Standard, no Boost dependency, fallible API |
| `std::function` (when non-owning) | `std::function_ref` | C++26 | Zero allocation overhead |
| Raw pointer polymorphism | `std::indirect<T>`, `std::polymorphic<T>` | C++26 | Value semantics, copyable, no manual lifetime management |
| Manual iterator loops | `std::ranges::` algorithms + views | C++20 | Composable, lazy, no off-by-one |
