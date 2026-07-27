# C/C++ Release Practices

## Build system

Use modern CMake. For new projects,
[cmake-init](https://github.com/friendlyanon/cmake-init) generates a
well-structured project with presets, warnings, and packaging support:

```sh
git init && cmake-init <project-name>
```

Plain GNU Make is acceptable for small projects; anything intended for
downstream packaging (vcpkg, distro packages) should use CMake.

## Language standard and portability

- Use **C++17 as the minimum** for new code; prefer C++20 or newer where the
  supported toolchains allow.
- Write standard C++, not compiler-specific dialects. Limit extensions to
  those with broad support across Clang, GCC, and (if targeted) MSVC, and
  build in CI with more than one compiler to keep the code honest.

## Testing and quality engineering

- **Unit tests:** [GoogleTest](https://github.com/google/googletest), run
  through CTest for build-system integration.
- **Sanitizers in CI:** build and run the test suite under ASan and UBSan at
  minimum; add TSan for concurrent code. Sanitizer CI jobs catch memory bugs
  reviewers miss.
- **Valgrind** remains useful for leak detection where sanitizers cannot run.
- **Fuzzing:** for code that parses untrusted input, add libFuzzer or AFL++
  harnesses, and consider [OSS-Fuzz](https://github.com/google/oss-fuzz)
  enrollment once public.
- Enable a strict warning baseline (`-Wall -Wextra`, warnings-as-errors in
  CI).

## Formatting and linting

Use the latest stable **clang-format** and **clang-tidy**, each enforced in
CI. Defaults are fine; a repository may commit its own `.clang-format` and
`.clang-tidy` configurations. Examples:
[pe-parse](https://github.com/trailofbits/pe-parse/blob/master/.clang-format),
[winchecksec](https://github.com/trailofbits/winchecksec/blob/master/.clang-format).

## Documentation

[Doxygen](https://www.doxygen.nl/) for API documentation, published to GitHub
Pages from CI.

## Packaging and distribution

- **vcpkg** is the most common route for distributing C++ libraries; Conan is
  a reasonable alternative if the audience already uses it.
- For tools, attach prebuilt binaries to GitHub Releases from CI, and
  consider a container image. Keep images small: multi-stage builds with a
  minimal base (alpine, distroless).
- See [pe-parse's release workflow](https://github.com/trailofbits/pe-parse/blob/master/.github/workflows/release.yml)
  for an example of CI-managed release packaging.
