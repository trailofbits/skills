# Language-Specific Guidance

Commands below assume `$DB_NAME` and `$CODEQL_LANG` from the build-database workflow. They
are written as `"$DB_NAME"` rather than a literal path on purpose: everything a run
produces belongs under `$OUTPUT_DIR`, and a database in the working directory is invisible
to the discovery step that looks there next time.

## No Build Required

### Python

```bash
codeql database create "$DB_NAME" --language=python --source-root=.
```

**Framework Support:**
- Django, Flask, FastAPI: Built-in models
- Tornado, Pyramid: Partial support
- Custom frameworks: May need data extensions

**Common Issues:**
| Issue | Fix |
|-------|-----|
| Missing Django models | Ensure `settings.py` is at expected location |
| Virtual env included | Use `paths-ignore` in config |
| Type stubs missing | Install `types-*` packages before extraction |

### JavaScript/TypeScript

```bash
codeql database create "$DB_NAME" --language=javascript --source-root=.
```

**Framework Support:**
- React, Vue, Angular: Built-in models
- Express, Koa, Fastify: HTTP source/sink models
- Next.js, Nuxt: Partial SSR support

**Common Issues:**
| Issue | Fix |
|-------|-----|
| node_modules bloat | Already excluded by default |
| TypeScript not parsed | Ensure `tsconfig.json` is valid |
| Monorepo issues | Use `--source-root` for specific package |

### Ruby

```bash
codeql database create "$DB_NAME" --language=ruby --source-root=.
```

**Framework Support:**
- Rails: Full support (controllers, models, views)
- Sinatra: Built-in support
- Hanami: Partial support

**Common Issues:**
| Issue | Fix |
|-------|-----|
| Bundler issues | Run `bundle install` first |
| Rails engines | May need multiple database passes |

## Build Required

### Go

Compiled, and **rejects `--build-mode=none`** — autobuild or a manual command only. The
command below looks build-free but runs autobuild, which invokes the Go toolchain; it
fails if Go is absent or the module does not build, and there is no no-build fallback.

```bash
codeql database create "$DB_NAME" --language=go --source-root=.
```

**Framework Support:**
- net/http, Gin, Echo, Chi: Built-in models
- gRPC: Partial support
- Custom routers: May need data extensions

**Common Issues:**
| Issue | Fix |
|-------|-----|
| Missing dependencies | Run `go mod download` first |
| Vendor directory | CodeQL handles automatically |
| CGO code | Requires `--command='go build'` with CGO enabled |
| Build fails | Fix it. `--build-mode=none` is rejected for Go, so there is no fallback |

### C/C++

```bash
# Make
codeql database create "$DB_NAME" --language=cpp --command='make -j8'

# CMake
codeql database create "$DB_NAME" --language=cpp \
  --source-root=/path/to/src \
  --command='cmake --build build'

# Ninja
codeql database create "$DB_NAME" --language=cpp \
  --command='ninja -C build'
```

**Build System Tips:**
| Build System | Command |
|--------------|---------|
| Make | `make clean && make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"` |
| CMake | `cmake -B build && cmake --build build` |
| Meson | `meson setup build && ninja -C build` |
| Bazel | `bazel build //...` |

**Common Issues:**
| Issue | Fix |
|-------|-----|
| Partial extraction | Ensure `make clean` before CodeQL build |
| Header-only libraries | Use `--extractor-option cpp_trap_headers=true` |
| Cross-compilation | Set `CODEQL_EXTRACTOR_CPP_TARGET_ARCH` |

### Java/Kotlin

```bash
# Gradle
codeql database create "$DB_NAME" --language=java --command='./gradlew build -x test'

# Maven
codeql database create "$DB_NAME" --language=java --command='mvn compile -DskipTests'
```

**Framework Support:**
- Spring Boot: Full support
- Jakarta EE: Built-in models
- Android: Requires Android SDK

**Common Issues:**
| Issue | Fix |
|-------|-----|
| Missing dependencies | Run `./gradlew dependencies` first |
| Kotlin mixed projects | Use `--language=java` (covers both) |
| Annotation processors | Ensure they run during CodeQL build |

### Rust

```bash
codeql database create "$DB_NAME" --language=rust --command='cargo build'
```

**Common Issues:**
| Issue | Fix |
|-------|-----|
| Proc macros | May require special handling |
| Workspace projects | Use `--source-root` for specific crate |
| Build script failures | Ensure native dependencies are available |

### C#

```bash
# .NET Core
codeql database create "$DB_NAME" --language=csharp --command='dotnet build'

# MSBuild
codeql database create "$DB_NAME" --language=csharp --command='msbuild /t:rebuild'
```

**Framework Support:**
- ASP.NET Core: Full support
- Entity Framework: Database query models
- Blazor: Partial support

**Common Issues:**
| Issue | Fix |
|-------|-----|
| NuGet restore | Run `dotnet restore` first |
| Multiple solutions | Specify solution file in command |

### Swift

```bash
# Xcode project
codeql database create "$DB_NAME" --language=swift \
  --command='xcodebuild -project MyApp.xcodeproj -scheme MyApp build'

# Swift Package Manager
codeql database create "$DB_NAME" --language=swift --command='swift build'
```

**Requirements:**
- macOS only
- Xcode Command Line Tools

**Common Issues:**
| Issue | Fix |
|-------|-----|
| Code signing | Add `CODE_SIGN_IDENTITY=- CODE_SIGNING_REQUIRED=NO` |
| Simulator target | Add `-sdk iphonesimulator` |

## Extractor Options

Set via environment variables: `CODEQL_EXTRACTOR_<LANG>_OPTION_<NAME>=<VALUE>`

### C/C++ Options

| Option | Description |
|--------|-------------|
| `trap_headers=true` | Include header file analysis |
| `target_arch=x86_64` | Target architecture |

### Java Options

| Option | Description |
|--------|-------------|
| `jdk_version=17` | JDK version for analysis |

### Python Options

| Option | Description |
|--------|-------------|
| `python_executable=/path/to/python` | Specific Python interpreter |
