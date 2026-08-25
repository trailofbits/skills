# Build Fixes

Fixes to apply when a CodeQL database build method fails. Try these in order, then retry the current build method. **Log each fix attempt.**

Every block sources `build_log.sh` for itself. A helper defined in an earlier Bash call is
gone by the next one, and `log_step` then exits 127, which the ladder reads as a failed method.

## 1. Clean existing state

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "Applying fix: clean existing state"
rm -rf "$DB_NAME"
log_result "Removed $DB_NAME"
```

## 2. Clean build cache

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "Applying fix: clean build cache"
CLEANED=""
make clean 2>/dev/null && CLEANED="$CLEANED make"
rm -rf build CMakeCache.txt CMakeFiles 2>/dev/null && CLEANED="$CLEANED cmake-artifacts"
./gradlew clean 2>/dev/null && CLEANED="$CLEANED gradle"
mvn clean 2>/dev/null && CLEANED="$CLEANED maven"
cargo clean 2>/dev/null && CLEANED="$CLEANED cargo"
log_result "Cleaned: $CLEANED"
```

## 3. Install missing dependencies

> **Note:** The commands below install the *target project's* dependencies so CodeQL can trace the build. Use whatever package manager the target project expects (`pip`, `npm`, `go mod`, etc.) — these are not the skill's own tooling preferences.

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

log_step "Applying fix: install dependencies"
FAILED_INSTALLS=()

# Python — use target project's package manager (pip/uv/poetry)
# allow-legacy-python: installs the analysed project's own deps; forcing uv could change its build.
if [ -f requirements.txt ]; then
  run_logged pip install -r requirements.txt || FAILED_INSTALLS+=("pip install -r requirements.txt")
fi
if [ -f setup.py ] || [ -f pyproject.toml ]; then
  run_logged pip install -e . || FAILED_INSTALLS+=("pip install -e .")
fi

# Node
if [ -f package.json ]; then
  run_logged npm install || FAILED_INSTALLS+=("npm install")
fi

# Go
if [ -f go.mod ]; then
  run_logged go mod download || FAILED_INSTALLS+=("go mod download")
fi

# Java
if [ -f build.gradle ] || [ -f build.gradle.kts ]; then
  run_logged ./gradlew dependencies --refresh-dependencies || FAILED_INSTALLS+=("gradlew dependencies")
fi
if [ -f pom.xml ]; then
  run_logged mvn dependency:resolve || FAILED_INSTALLS+=("mvn dependency:resolve")
fi

# Rust
if [ -f Cargo.toml ]; then
  run_logged cargo fetch || FAILED_INSTALLS+=("cargo fetch")
fi

if [ ${#FAILED_INSTALLS[@]} -gt 0 ]; then
  log_result "Dependency installation FAILED: ${FAILED_INSTALLS[*]}"
  echo "WARNING: ${#FAILED_INSTALLS[@]} dependency step(s) failed — a retry will likely" \
       "fail the same way. Report which, rather than retrying blind." >&2
else
  log_result "Dependencies installed"
fi
```

## 4. Handle private registries

If dependencies require authentication, ask user:
```
AskUserQuestion: "Build requires private registry access. Options:"
  1. "I'll configure auth and retry"
  2. "Skip these dependencies"
  3. "Show me what's needed"
```

```bash
. "{baseDir}/scripts/build_log.sh" || exit 1

# Log authentication setup if performed
log_step "Private registry authentication configured"
log_result "Registry: <REGISTRY_URL>, Method: <AUTH_METHOD>"
```

**After fixes:** Retry current build method. If still fails, move to next method.
