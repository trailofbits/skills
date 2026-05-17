## Day 5: Crash Deduplication and Corpus Minimization

- **Goal**: Learn to efficiently deduplicate crashes and minimize test cases for easier analysis.
- **Activities**:
  - _Reading_:
    - "Fuzzing for Software Security Testing and Quality Assurance" by Ari Takanen - Chapter 9: Fuzzing Case Studies
    - [AFL++ Corpus Minimization](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md)
  - _Online Resources_:
    - [Test Case Reduction Strategies](https://lcamtuf.coredump.cx/afl/technical_details.txt)
    - [Delta Debugging Algorithm](https://www.st.cs.uni-saarland.de/papers/tse2002/tse2002.pdf)
  - _Tool Setup_:
    - afl-tmin (test case minimizer)
    - afl-cmin (corpus minimizer)
    - creduce / llvm-reduce (for source code)
  - _Exercise_:
    - Deduplicate and minimize crashes from vulnerable_suite
    - Reduce crash input to minimal reproducer

### Lab Setup: Building AFL-Instrumented Binary

For coverage-based deduplication and AFL tools (afl-tmin, afl-cmin), you need an AFL-instrumented build:

```bash
cd ~/crash_analysis_lab/src

# Build AFL-instrumented version (requires AFL++ installed)
afl-clang-fast -g -o ../vuln_afl vulnerable_suite.c

# Verify instrumentation
afl-showmap -o /dev/null -- ../vuln_afl 1 "test"
# Should show output similar to:
# [+] Hash of coverage map: cfa0609563552e5b
# [+] Captured 2 tuples (map size 26, highest value 1, total values 2) in '/dev/null'.
```

> [!NOTE] If you don't have AFL++ installed, you can skip the coverage-based methods and use stack-hash or CASR-based deduplication instead.

### Why Deduplication and Minimization Matter

**The Problem**:

- Fuzzing generates thousands of crashes
- Many are duplicates (same bug, different input)
- Large inputs make analysis difficult
- Need efficient prioritization

**Benefits of Deduplication**:

- Focus on unique bugs, not symptoms
- Reduce analysis time from days to hours
- Better resource allocation
- Clear bug count for tracking

**Benefits of Minimization**:

- Smaller inputs easier to understand
- Faster crash reproduction
- Clearer root cause identification
- Simpler exploit development

### Crash Deduplication Strategies

#### Method 1: Stack Trace Hashing

**Concept**: Hash the call stack to identify unique crashes

**Pros**:

- Fast and simple
- Deterministic
- No special tools needed

**Cons**:

- Different stacks can be same bug
- Non-deterministic bugs may vary
- Address randomization affects hashing

**Implementation**:

```bash
#!/bin/bash
# dedupe_by_stack.sh
cd ~/crash_analysis_lab

for crash in crashes/*; do
    # Get stack trace
    stack=$(gdb -batch \
        -ex "run < $crash" \
        -ex "bt" \
        -ex "quit" \
        ./vuln_no_protect 2>&1 | grep "^#")

    # Hash stack (ignore addresses)
    hash=$(echo "$stack" | \
        sed 's/0x[0-9a-f]\{8,16\}//g' | \
        md5sum | cut -d' ' -f1)

    # Create directory for this hash
    mkdir -p deduped/$hash

    # Copy first crash with this hash
    if [ ! -f deduped/$hash/crash ]; then
        cp $crash deduped/$hash/crash
        echo "$crash -> $hash"
    fi
done

echo "Unique crashes: $(ls -1 deduped/ | wc -l)"
```

#### Method 2: Coverage-Based Deduplication

**Concept**: Hash the code coverage path

**Pros**:

- More accurate than stack traces
- Captures execution flow
- Works with non-deterministic crashes

**Cons**:

- Requires instrumentation
- Slower than stack hashing
- May over-deduplicate

**Implementation**:

```bash
#!/bin/bash
# dedupe_by_coverage.sh
cd ~/crash_analysis_lab

mkdir -p deduped

for crash in crashes/*; do
    name=$(basename "$crash")

    # Get a stable coverage signature from afl-showmap output.
    # -q: quiet
    # -e: edges only (ignore hit counts)
    # -o: output file
    # -H: file that replaces @@ (file-input targets)
    # Note: Requires AFL-instrumented build (afl-clang-fast)
    afl-showmap -q -e -o "/tmp/${name}.cov" -H "$crash" -- ./vuln_afl @@ >/dev/null 2>&1 || true

    hash=$(md5sum "/tmp/${name}.cov" | cut -d' ' -f1)
    mkdir -p "deduped/$hash"

    if [ ! -f "deduped/$hash/crash" ]; then
        cp "$crash" "deduped/$hash/crash"
    fi
done
```

#### Method 3: CASR-Based Deduplication (Recommended)

**Concept**: Use CASR's semantic crash classification

**Pros**:

- Semantically meaningful (23 severity types)
- Built-in clustering algorithm
- Modern, actively maintained
- Considers crash type, location, and severity

**Cons**:

- Requires ASAN build for best results
- Some setup required

**Implementation**:

```bash
#!/bin/bash
# dedupe_by_casr.sh
cd ~/crash_analysis_lab

# Generate CASR reports for each crash
for crash in crashes/*; do
    name=$(basename $crash)
    casr-san -o casrep/${name}.casrep -- ./vuln_asan < $crash 2>/dev/null
done

# Use CASR's built-in clustering
casr-cluster -c casrep/ deduped/

# Review clusters
echo "Unique crash clusters:"
for cluster in deduped/cl*; do
    count=$(ls -1 $cluster/*.casrep 2>/dev/null | wc -l)
    # Get representative crash type
    type=$(jq -r '.CrashSeverity.ShortDescription' $cluster/*.casrep 2>/dev/null | head -1)
    echo "  $(basename $cluster): $count crashes - $type"
done

# Expected output (example):
# Number of clusters: 8
# Unique crash clusters:
#   cl1: 1 crashes - double-free
#   cl2: 1 crashes - AbortSignal
#   cl3: 1 crashes - heap-buffer-overflow(write)
#   cl4: 1 crashes - DestAvNearNull
#   cl5: 1 crashes - DestAvNearNull
#   cl6: 1 crashes - stack-buffer-overflow(write)
#   cl7: 1 crashes - heap-use-after-free(read)
#   cl8: 3 crashes - ReturnAv
#   clerr: 2 crashes - AbortSignal
```

> [!NOTE] The `clerr` cluster contains crashes that CASR couldn't fully classify
> (e.g., AbortSignal from ASAN reports without clear memory corruption).
> The DestAvNearNull clusters indicate potential NULL pointer dereferences.

**Alternative: Pwndbg-Based Analysis** (Interactive):

> [!WARNING] The crash files in this lab contain test numbers and inputs formatted for the ASAN build. For GDB analysis, you need to pass arguments directly rather than via stdin.

```bash
#!/bin/bash
# For manual interactive analysis with proper argument passing
cd ~/crash_analysis_lab

# Generate overflow payloads
STACK_PAYLOAD=$(python3 -c "print('A'*100)")
HEAP_PAYLOAD=$(python3 -c "print('B'*60)")

echo "=== Stack Overflow Analysis ==="
gdb -batch \
    -ex "run 1 $STACK_PAYLOAD" \
    -ex "bt" \
    -ex "checksec" \
    -ex "quit" \
    ./vuln_no_protect

echo "=== Heap Overflow Analysis ==="
gdb -batch \
    -ex "run 2 $HEAP_PAYLOAD" \
    -ex "bt" \
    -ex "checksec" \
    -ex "quit" \
    ./vuln_no_protect

# Note: Heap overflow may not crash immediately without ASAN!
# Use ASAN build to detect: ./vuln_asan 2 "$HEAP_PAYLOAD"

echo "=== Use-After-Free Analysis ==="
gdb -batch \
    -ex "run 3" \
    -ex "bt" \
    -ex "checksec" \
    -ex "quit" \
    ./vuln_no_protect

echo "=== Double-Free Analysis ==="
gdb -batch \
    -ex "run 4" \
    -ex "bt" \
    -ex "checksec" \
    -ex "quit" \
    ./vuln_no_protect
```

**Expected Output (Stack Overflow)**:

```text
=== Stack Overflow Analysis ===
[*] Copying input to 64-byte buffer...
[*] Buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401225 in stack_overflow (input=0x7fffffffe491 'A' <repeats 100 times>) at vulnerable_suite.c:11
#0  0x0000000000401225 in stack_overflow (input=...) at vulnerable_suite.c:11
#1  0x4141414141414141 in ?? ()
#2  0x4141414141414141 in ?? ()
#3  0x4141414141414141 in ?? ()
Backtrace stopped: Cannot access memory at address 0x4141414141414149

File:     /home/dev/crash_analysis_lab/vuln_no_protect
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
Stack:      Executable
RWX:        Has RWX segments
```

> [!TIP] **Analysis Notes**:
>
> - Return address overwritten with `0x4141414141414141` ('AAAA...' in hex) = **RIP control achieved**
> - No stack canary + Executable stack + No PIE = **Highly exploitable**
> - The crash at `vulnerable_suite.c:11` indicates the function epilogue (`ret` instruction)

**Expected Output (Heap Overflow - No Crash)**:

```text
=== Heap Overflow Analysis ===
[*] Allocated 32 bytes at 0x4052a0
[*] Buffer: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
[Inferior 1 (process 2116) exited normally]
No stack.
```

> [!WARNING] **Why No Crash?**
> Heap overflows often don't cause immediate crashes without sanitizers:
>
> - The overflow corrupts adjacent heap metadata/data **silently**
> - Crash may only occur later during `free()` or when corrupted data is accessed
> - Use ASAN build to detect: `./vuln_asan 2 "$HEAP_PAYLOAD"` will report `heap-buffer-overflow`
> - This demonstrates why **sanitizers are essential** for finding heap corruption bugs

**Expected Output (Use-After-Free - No Crash)**:

```text
=== Use-After-Free Analysis ===
[*] Allocated at 0x4052a0: Hello, World!
[*] Freed, now accessing...
[*] UAF read:
[Inferior 1 (process 2131) exited normally]
No stack.
```

> [!WARNING] **Why No Crash?**
> Use-after-free bugs are often silent without sanitizers:
>
> - The freed memory is accessed but returns **garbage/stale data** (notice empty UAF read)
> - Memory may still be mapped, just marked as "free" in the allocator
> - A crash only occurs if the page is unmapped or memory is reused with different data
> - Use ASAN build to detect: `./vuln_asan 3` will report `heap-use-after-free`
> - **UAF bugs are highly exploitable** - attacker can control what replaces the freed object

**Expected Output (Double-Free - Crashes!)**:

```text
=== Double-Free Analysis ===
[*] Allocated at 0x4052a0
[*] First free done
free(): double free detected in tcache 2

Program received signal SIGABRT, Aborted.
__pthread_kill_implementation (no_tid=0, signo=6, threadid=<optimized out>) at ./nptl/pthread_kill.c:44
#0  __pthread_kill_implementation (...) at ./nptl/pthread_kill.c:44
#1  __pthread_kill_internal (signo=6, ...) at ./nptl/pthread_kill.c:78
#2  __GI___pthread_kill (...) at ./nptl/pthread_kill.c:89
#3  0x00007ffff7c4527e in __GI_raise (sig=6) at ../sysdeps/posix/raise.c:26
#4  0x00007ffff7c288ff in __GI_abort () at ./stdlib/abort.c:79
#5  0x00007ffff7c297b6 in __libc_message_impl (...) at ../sysdeps/posix/libc_fatal.c:134
#6  0x00007ffff7ca8ff5 in malloc_printerr (str=0x7ffff7dd1bf0 "free(): double free detected in tcache 2")
#7  0x00007ffff7cab55f in _int_free (...) at ./malloc/malloc.c:4541
#8  0x00007ffff7caddae in __GI___libc_free (mem=0x4052a0) at ./malloc/malloc.c:3398
#9  0x0000000000401390 in double_free () at vulnerable_suite.c:39
#10 0x0000000000401558 in main (argc=2, argv=0x7fffffffe228) at vulnerable_suite.c:68
```

> [!TIP] **Analysis Notes (Double-Free)**:
>
> - **glibc tcache detection triggered**: Modern glibc (2.26+) includes tcache double-free mitigation
> - Stack trace shows: `double_free()` → `__libc_free()` → `_int_free()` → `malloc_printerr()` → `abort()`
> - The error message `"free(): double free detected in tcache 2"` is the tcache key check
> - **SIGABRT** (signal 6) = program called `abort()` due to detected corruption
> - This mitigation can be bypassed in exploitation scenarios (e.g., filling tcache first)

#### Method 4: Combined Approach

```bash
#!/bin/bash
# dedupe_combined.sh
cd ~/crash_analysis_lab

for crash in crashes/*; do
    # 1. Get stack hash
    stack=$(gdb -batch \
        -ex "run < $crash" \
        -ex "bt" \
        -ex "quit" \
        ./vuln_no_protect 2>&1 | grep "^#")

    stack_hash=$(echo "$stack" | \
        sed 's/0x[0-9a-f]\{8,16\}//g' | \
        md5sum | cut -d' ' -f1)

    # 2. Get CASR severity hash
    casr_hash=$(casr-san -- ./vuln_asan < $crash 2>&1 | \
        grep -E "ShortDescription|CrashLine" | md5sum | cut -d' ' -f1)

    # Combined hash
    combined=$(echo "$stack_hash $casr_hash" | md5sum | cut -d' ' -f1)

    mkdir -p deduped/$combined
    if [ ! -f deduped/$combined/crash ]; then
        cp $crash deduped/$combined/crash
        echo "$stack_hash,$casr_hash" > deduped/$combined/hashes.txt
    fi
done
```

### Differential Crash Analysis

**Concept**: Compare similar crashes to understand root cause variations and identify distinct bugs that appear similar.

**When to Use**:

- Multiple crashes in same function but different behaviors
- Crashes that look similar but have different exploitability
- Understanding crash variants from the same bug class

**Differential Analysis Workflow (for .casrep files)**:

```bash
#!/bin/bash
# diff_casrep.sh - Compare two existing CASR report files
# Usage: ./diff_casrep.sh <crash_a.casrep> <crash_b.casrep>

REPORT_A="$1"
REPORT_B="$2"

echo "=== Differential Crash Analysis (CASREP) ==="

# Compare severity
echo -e "\n[1] Severity Comparison:"
echo "Crash A: $(jq -r '.CrashSeverity.ShortDescription' "$REPORT_A")"
echo "Crash B: $(jq -r '.CrashSeverity.ShortDescription' "$REPORT_B")"

# Compare crash locations
echo -e "\n[2] Crash Location:"
echo "Crash A: $(jq -r '.CrashLine' "$REPORT_A")"
echo "Crash B: $(jq -r '.CrashLine' "$REPORT_B")"

# Compare stack traces (first 5 frames)
echo -e "\n[3] Stack Trace Comparison:"
echo "Crash A top frames:"
jq -r '.Stacktrace[:5][]' "$REPORT_A" 2>/dev/null || jq -r '.StackTrace[:5][]' "$REPORT_A" 2>/dev/null
echo "---"
echo "Crash B top frames:"
jq -r '.Stacktrace[:5][]' "$REPORT_B" 2>/dev/null || jq -r '.StackTrace[:5][]' "$REPORT_B" 2>/dev/null

# Compare ASAN description if available
echo -e "\n[4] ASAN Description:"
echo "Crash A: $(jq -r '.AsanReport // "N/A"' "$REPORT_A" | head -3)"
echo "Crash B: $(jq -r '.AsanReport // "N/A"' "$REPORT_B" | head -3)"

# Determine if same bug
echo -e "\n[5] Same Bug Assessment:"
line_a=$(jq -r '.CrashLine' "$REPORT_A")
line_b=$(jq -r '.CrashLine' "$REPORT_B")
if [ "$line_a" == "$line_b" ]; then
    echo "LIKELY SAME BUG - Same crash line: $line_a"
else
    echo "POSSIBLY DIFFERENT BUGS"
    echo "  Crash A: $line_a"
    echo "  Crash B: $line_b"
fi
```

**Usage Examples**:

```bash
cd ~/crash_analysis_lab

# Compare two CASR clusters (DestAvNearNull variants)
./diff_casrep.sh deduped/cl4/*.casrep deduped/cl5/*.casrep

# Compare stack overflow vs heap overflow
./diff_casrep.sh deduped/stack_overflow.casrep deduped/heap_overflow.casrep
```

**Alternative: Generate and Compare from Raw Inputs**:

```bash
#!/bin/bash
# diff_crash_analysis.sh - Compare two crashes from raw inputs
# Usage: ./diff_crash_analysis.sh <test_num_a> <input_a> <test_num_b> <input_b>
cd ~/crash_analysis_lab

TEST_A="$1"
INPUT_A="$2"
TEST_B="$3"
INPUT_B="$4"

echo "=== Differential Crash Analysis ==="

# Generate CASR reports
casr-san -o /tmp/crash_a.casrep -- ./vuln_asan "$TEST_A" "$INPUT_A" 2>/dev/null
casr-san -o /tmp/crash_b.casrep -- ./vuln_asan "$TEST_B" "$INPUT_B" 2>/dev/null

# Compare severity
echo -e "\n[1] Severity Comparison:"
echo "Crash A: $(jq -r '.CrashSeverity.ShortDescription' /tmp/crash_a.casrep)"
echo "Crash B: $(jq -r '.CrashSeverity.ShortDescription' /tmp/crash_b.casrep)"

# Compare crash locations
echo -e "\n[2] Crash Location:"
echo "Crash A: $(jq -r '.CrashLine' /tmp/crash_a.casrep)"
echo "Crash B: $(jq -r '.CrashLine' /tmp/crash_b.casrep)"

# Compare stack traces (first 5 frames)
echo -e "\n[3] Stack Trace Comparison:"
echo "Crash A top frames:"
jq -r '.Stacktrace[:5][]' /tmp/crash_a.casrep 2>/dev/null
echo "---"
echo "Crash B top frames:"
jq -r '.Stacktrace[:5][]' /tmp/crash_b.casrep 2>/dev/null

# Determine if same bug
echo -e "\n[4] Same Bug Assessment:"
if [ "$(jq -r '.CrashLine' /tmp/crash_a.casrep)" == "$(jq -r '.CrashLine' /tmp/crash_b.casrep)" ]; then
    echo "LIKELY SAME BUG - Same crash line"
else
    echo "POSSIBLY DIFFERENT BUGS - Different crash lines"
fi
```

**Usage**:

```bash
# Compare stack overflow vs UAF
PAYLOAD=$(python3 -c "print('A'*100)")
./diff_crash_analysis.sh 1 "$PAYLOAD" 3 ""

# Compare stack overflow vs heap overflow
./diff_crash_analysis.sh 1 "$PAYLOAD" 2 "$(python3 -c "print('B'*60)")"
```

**Expected Output (Stack Overflow vs Heap Overflow)**:

```text
=== Differential Crash Analysis ===

[1] Severity Comparison:
Crash A: stack-buffer-overflow(write)
Crash B: heap-buffer-overflow(write)

[2] Crash Location:
Crash A: /home/dev/crash_analysis_lab/src/vulnerable_suite.c:9:5
Crash B: /home/dev/crash_analysis_lab/src/vulnerable_suite.c:17:5

[3] Stack Trace Comparison:
Crash A top frames:
    #0 0x555555602d73 in strcpy (vuln_asan)
    #1 0x555555659c75 in stack_overflow vulnerable_suite.c:9:5
    #2 0x555555659c75 in main vulnerable_suite.c:65:39
---
Crash B top frames:
    #0 0x555555602d73 in strcpy (vuln_asan)
    #1 0x555555659e38 in heap_overflow vulnerable_suite.c:17:5
    #2 0x555555659e38 in main vulnerable_suite.c:66:39

[4] Same Bug Assessment:
POSSIBLY DIFFERENT BUGS - Different crash lines
```

> [!TIP] **Analysis Insight**:
> Both crashes have `strcpy` at frame #0 (same dangerous function), but different vulnerability functions (`stack_overflow` vs `heap_overflow`).
> Same root cause pattern (unbounded copy), different memory corruption targets.

### Crash Variant Discovery

**Concept**: Given a crash, find related crashes by mutating the input to explore the bug's attack surface.

**Why Find Variants?**:

- Original crash might be DoS-only, variant might be RCE
- Different variants may bypass different mitigations
- Helps understand full scope of vulnerability
- Variants with different severity may have different priority

**Mutation-Based Variant Discovery**:

```python
#!/usr/bin/env python3
"""
crash_variant_finder.py - Find crash variants by mutating input

Usage: python3 crash_variant_finder.py ./vuln_no_protect crashes/stack_150.txt variants/

This script mutates a known crash input to discover:
- Different crash locations (new bugs)
- Different crash severities
- Smaller reproducers
- Inputs that trigger the same bug differently
"""
import subprocess
import random
import hashlib
import os
from pathlib import Path

def mutate_input(data, mutation_rate=0.05):
    """Apply random mutations to crash input

    Mutation strategies:
    - flip: XOR random byte with random value
    - insert: Add new byte at random position
    - delete: Remove random byte
    - replace: Replace byte with random value
    """
    data = bytearray(data)
    num_mutations = max(1, int(len(data) * mutation_rate))

    for _ in range(num_mutations):
        mutation_type = random.choice(['flip', 'insert', 'delete', 'replace'])
        pos = random.randint(0, len(data) - 1) if data else 0

        if mutation_type == 'flip' and data:
            data[pos] ^= random.randint(1, 255)
        elif mutation_type == 'insert':
            data.insert(pos, random.randint(0, 255))
        elif mutation_type == 'delete' and len(data) > 1:
            del data[pos]
        elif mutation_type == 'replace' and data:
            data[pos] = random.randint(0, 255)

    return bytes(data)

def test_crash(target, input_data, test_case="1", timeout=2):
    """Test if input causes crash using vulnerable_suite test case

    Note: For vulnerable_suite, format is: ./vuln <test_num> <payload>
    """
    try:
        result = subprocess.run(
            [target, test_case, input_data.decode('latin-1')],
            timeout=timeout,
            capture_output=True
        )
        return result.returncode < 0  # Negative = signal (crash)
    except subprocess.TimeoutExpired:
        return False  # Hang, not crash
    except Exception:
        return False

def get_crash_signature(target_asan, input_data, test_case="1"):
    """Get crash signature using ASAN output

    Returns normalized crash signature (addresses stripped for ASLR).
    This ensures the same crash location is identified regardless of
    memory layout randomization.
    """
    import re
    try:
        result = subprocess.run(
            [target_asan, test_case, input_data.decode('latin-1')],
            timeout=5,
            capture_output=True,
            text=True
        )
        # Extract crash location from ASAN output
        for line in result.stderr.split('\n'):
            if '#0' in line and ' in ' in line:
                # Strip addresses to normalize for ASLR
                # Before: "#0 0x56eef1918d73 in strcpy (/path/vuln+0xaed73)"
                # After:  "#0 in strcpy (/path/vuln)"
                normalized = re.sub(r'0x[0-9a-f]+', '', line)
                normalized = re.sub(r'\+0x[0-9a-f]+', '', normalized)
                normalized = re.sub(r'\s+', ' ', normalized).strip()
                return normalized
    except:
        pass
    return "unknown"

def find_variants(target, original_crash, output_dir, num_iterations=1000):
    """Find crash variants by mutating original input"""

    # Derive ASAN binary name
    target_asan = target.replace('vuln_no_protect', 'vuln_asan')

    with open(original_crash, 'rb') as f:
        original_data = f.read().strip()

    original_sig = get_crash_signature(target_asan, original_data)
    print(f"[*] Original crash signature: {original_sig}")

    variants = {}
    Path(output_dir).mkdir(exist_ok=True)

    for i in range(num_iterations):
        mutated = mutate_input(original_data)

        if test_crash(target, mutated):
            sig = get_crash_signature(target_asan, mutated)

            if sig not in variants:
                variants[sig] = mutated
                variant_hash = hashlib.md5(mutated).hexdigest()[:8]
                variant_path = f"{output_dir}/variant_{variant_hash}"

                with open(variant_path, 'wb') as f:
                    f.write(mutated)

                print(f"[+] New variant ({len(variants)}): {sig[:60]}...")

        if i % 100 == 0:
            print(f"[*] Progress: {i}/{num_iterations}, found {len(variants)} variants")

    print(f"\n[*] Found {len(variants)} unique crash variants")
    return variants

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target> <crash_input> <output_dir>")
        print(f"Example: {sys.argv[0]} ./vuln_no_protect crashes/stack_150.txt variants/")
        sys.exit(1)

    find_variants(sys.argv[1], sys.argv[2], sys.argv[3])
```

> [!NOTE] **Why Only 1 Variant?**
> The simple stack overflow always crashes at the same `strcpy` location regardless of payload content.
> To find _different_ crash variants, you need inputs that trigger different code paths.
> The script above is useful when fuzzing complex parsers where mutations might reach different vulnerable functions.

**Alternative: Multi-Vulnerability Variant Finder**

For `vulnerable_suite`, use this version that explores different test cases:

```python
#!/usr/bin/env python3
"""
multi_vuln_variant_finder.py - Find variants across different vulnerability types

Usage: python3 multi_vuln_variant_finder.py ./vuln_no_protect variants/
"""
import subprocess
import random
import hashlib
import re
from pathlib import Path

# Test cases and their required payloads
VULN_TESTS = {
    "1": lambda: "A" * random.randint(65, 200),   # Stack overflow
    "2": lambda: "B" * random.randint(33, 100),   # Heap overflow
    "3": lambda: "",                               # Use-after-free
    "4": lambda: "",                               # Double-free
    "5": lambda: random.choice(["0", "1"]),       # NULL deref
}

def test_crash(target, test_num, payload, timeout=2):
    """Test if input causes crash"""
    try:
        args = [target, test_num]
        if payload:
            args.append(payload)
        result = subprocess.run(args, timeout=timeout, capture_output=True)
        return result.returncode < 0
    except:
        return False

def get_crash_signature(target_asan, test_num, payload):
    """Get ASLR-normalized crash signature"""
    try:
        args = [target_asan, test_num]
        if payload:
            args.append(payload)
        result = subprocess.run(args, timeout=5, capture_output=True, text=True)

        for line in result.stderr.split('\n'):
            if '#0' in line and ' in ' in line:
                normalized = re.sub(r'0x[0-9a-f]+', '', line)
                normalized = re.sub(r'\+0x[0-9a-f]+', '', normalized)
                normalized = re.sub(r'\s+', ' ', normalized).strip()
                return normalized
    except:
        pass
    return "unknown"

def find_all_variants(target, output_dir, iterations_per_test=200):
    """Find crash variants across all vulnerability types"""

    target_asan = target.replace('vuln_no_protect', 'vuln_asan')
    variants = {}
    Path(output_dir).mkdir(exist_ok=True)

    for test_num, payload_gen in VULN_TESTS.items():
        print(f"\n[*] Testing vulnerability type {test_num}...")

        for i in range(iterations_per_test):
            payload = payload_gen()

            if test_crash(target, test_num, payload):
                sig = get_crash_signature(target_asan, test_num, payload)

                if sig and sig != "unknown" and sig not in variants:
                    variants[sig] = (test_num, payload)

                    variant_hash = hashlib.md5(f"{test_num}{payload}".encode()).hexdigest()[:8]
                    variant_path = f"{output_dir}/variant_{test_num}_{variant_hash}"

                    with open(variant_path, 'w') as f:
                        f.write(f"{test_num} {payload}")

                    print(f"[+] New variant ({len(variants)}): test={test_num}, {sig[:50]}...")

    print(f"\n[*] Found {len(variants)} unique crash variants across all tests")
    return variants

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target> <output_dir>")
        sys.exit(1)

    find_all_variants(sys.argv[1], sys.argv[2])
```

**Running the Multi-Vulnerability Finder**:

```bash
cd ~/crash_analysis_lab

# Find variants across ALL vulnerability types
python3 multi_vuln_variant_finder.py ./vuln_no_protect variants/

# Expected output:
# [*] Testing vulnerability type 1...
# [+] New variant (1): test=1, #0 in strcpy (/home/dev/crash_analysis_lab/vuln_as...
#
# [*] Testing vulnerability type 2...
# (no crash - heap overflow is silent without ASAN)
#
# [*] Testing vulnerability type 3...
# (no crash - UAF is silent without ASAN)
#
# [*] Testing vulnerability type 4...
# [+] New variant (2): test=4, #0 in free (/home/dev/crash_analysis_lab/vuln_asan...
#
# [*] Testing vulnerability type 5...
# [+] New variant (3): test=5, #0 in null_deref /home/dev/crash_analysis_lab/src/...
#
# [*] Found 3 unique crash variants across all tests

ls -la variants/
# variant_1_*  (stack overflow - strcpy)
# variant_4_*  (double-free - glibc tcache detection)
# variant_5_*  (null deref - SIGSEGV)
```

**Running the Variant Finder**:

```bash
cd ~/crash_analysis_lab

# Create crash input files for different vulnerability types
echo "1 $(python3 -c "print('A'*150)")" > crashes/stack_150.txt
echo "2 $(python3 -c "print('B'*80)")" > crashes/heap_80.txt

# Run the variant finder
python3 crash_variant_finder.py ./vuln_no_protect crashes/stack_150.txt variants/

# Expected output:
# [*] Original crash signature: #0 0x... in stack_overflow ...
# [*] Progress: 0/1000, found 0 variants
# [+] New variant (1): #0 0x555555659c75 in stack_overflow /home/dev/...
# [*] Progress: 100/1000, found 2 variants
# ...
# [*] Found X unique crash variants

# Check results
ls -la variants/
# variant_3a8f2c1d  variant_7bc912ef  ...

# Analyze each variant with CASR
for v in variants/*; do
    echo "=== $(basename $v) ==="
    casr-san -o /tmp/v.casrep -- ./vuln_asan $(cat $v) 2>/dev/null
    jq -r '.CrashSeverity.ShortDescription' /tmp/v.casrep
done
```

**Targeted Variant Discovery**:

```bash
cd ~/tools

# Install radamsa
git clone --depth 1 https://gitlab.com/akihe/radamsa.git
cd radamsa
make
sudo make install
radamsa --help

cd ~/crash_analysis_lab

echo "1 $(python3 -c "print('A'*100)")" > crash_input.txt

# Generate variants with ASLR-normalized deduplication
mkdir -p radamsa_variants
declare -A seen_sigs

for i in {1..100}; do
    radamsa crash_input.txt > /tmp/variant.txt

    # Get ASAN output and normalize
    output=$(./vuln_asan $(cat /tmp/variant.txt) 2>&1)
    if echo "$output" | grep -qE "ERROR.*Sanitizer"; then
        # Extract and normalize signature (strip addresses for ASLR)
        sig=$(echo "$output" | grep "#0" | head -1 | sed 's/0x[0-9a-f]\+//g')

        if [[ -z "${seen_sigs[$sig]}" ]]; then
            seen_sigs[$sig]=1
            cp /tmp/variant.txt radamsa_variants/variant_$i.txt
            echo "[+] Unique variant $i: $(echo "$output" | grep -oE 'stack-buffer|heap-buffer|use-after|double-free' | head -1)"
        fi
    fi
done

echo "Found ${#seen_sigs[@]} unique crash signatures"

# Expected output:
# [+] Unique variant 3: stack-buffer
# [+] Unique variant 28: use-after
# Found 2 unique crash signatures
```

> [!TIP] **Why deduplication matters:**
> Without deduplication, you might see 30+ "crashes" that are all the same bug. With proper ASLR-normalized signatures, radamsa found **2 truly unique** crash types:
>
> - **stack-buffer**: Original overflow from test case 1
> - **use-after**: Radamsa mutated the test number ("1" -> "3"), discovering UAF!
>
> This demonstrates radamsa's power to explore beyond the original crash input.

```bash
# Method 3: Focused byte-range mutation
# Useful when you know which input region triggers the bug
python3 << 'EOF'
import random
import subprocess
import re

seen_sigs = set()

# Focus mutations on BOTH test number and payload
for i in range(20):
    # Mutate test number (1-5 are valid, but let's explore)
    test_num = str(random.randint(1, 6))

    # Generate payload with mutations
    payload = bytearray(b"A" * random.randint(50, 150))
    for _ in range(random.randint(3, 8)):
        pos = random.randint(0, len(payload) - 1)
        payload[pos] = random.randint(0, 255)

    try:
        result = subprocess.run(
            ["./vuln_asan", test_num, payload.decode('latin-1')],
            capture_output=True, timeout=5
        )

        if b"ERROR" in result.stderr:
            # Normalize signature (strip ASLR addresses)
            stderr = result.stderr.decode('latin-1', errors='ignore')
            sig_match = re.search(r'#0.*?in (\w+)', stderr)
            sig = sig_match.group(1) if sig_match else "unknown"

            if sig not in seen_sigs:
                seen_sigs.add(sig)
                err_type = stderr.split('ERROR')[1][:60] if 'ERROR' in stderr else ''
                print(f"[+] New crash (test={test_num}): {sig} - {err_type.strip()}")
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

print(f"\nFound {len(seen_sigs)} unique crash signatures")
EOF

# Expected output:
# [+] New crash (test=5): null_deref - : AddressSanitizer: SEGV on unknown address
# [+] New crash (test=4): free - : AddressSanitizer: attempting double-free
# [+] New crash (test=3): printf_common - : AddressSanitizer: heap-use-after-free
# [+] New crash (test=2): strcpy - : AddressSanitizer: heap-buffer-overflow
# [+] New crash (test=1): strcpy - : AddressSanitizer: stack-buffer-overflow
#
# Found 4-5 unique crash signatures (varies by random selection)
```

### Test Case Minimization with afl-tmin

**What Is afl-tmin?**:

- AFL++ tool for minimizing crash inputs
- Uses delta debugging algorithm
- Removes bytes while preserving crash
- Produces minimal reproducer

> [!WARNING] **Important for vulnerable_suite:**
> `afl-tmin` with `@@` passes a **filename** to the target, but `vulnerable_suite` expects **command-line arguments** (`./vuln 1 AAAA`).
> For this lab, use the Python-based minimizer below or CASR's `casr-afl` for minimization.

**Basic Usage (for file-input targets)**:

```bash
cd ~/crash_analysis_lab

# For targets that read from file (@@):
#afl-tmin -i crash_input -o crash_minimized -- ./target @@

# Options:
# -i: Input file
# -o: Output file
# -m: Memory limit (MB), use 'none' to disable
# -t: Timeout (ms)
# -e: Solve for edge coverage only (faster)
```

**Python-Based Minimizer (for command-line argument targets)**:

```python
#!/usr/bin/env python3
"""
minimize_crash.py - Delta debugging minimizer for command-line argument targets

Usage: python3 minimize_crash.py ./vuln_asan 1 "$(cat crash_input.txt)"
"""
import subprocess
import sys

def crashes(target, test_num, payload, timeout=5):
    """Check if input still crashes"""
    try:
        result = subprocess.run(
            [target, test_num, payload],
            capture_output=True, timeout=timeout
        )
        return result.returncode < 0 or b"ERROR" in result.stderr
    except subprocess.TimeoutExpired:
        return False
    except:
        return False

def minimize(target, test_num, payload):
    """Delta debugging minimization"""
    print(f"[*] Original size: {len(payload)} bytes")

    # Phase 1: Block deletion (binary search)
    block_size = len(payload) // 2
    while block_size >= 1:
        i = 0
        while i < len(payload):
            # Try removing block
            candidate = payload[:i] + payload[i + block_size:]
            if crashes(target, test_num, candidate):
                payload = candidate
                print(f"    Block {block_size}: {len(payload)} bytes")
            else:
                i += block_size
        block_size //= 2

    # Phase 2: Byte-by-byte removal
    i = 0
    while i < len(payload):
        candidate = payload[:i] + payload[i + 1:]
        if crashes(target, test_num, candidate):
            payload = candidate
        else:
            i += 1

    print(f"[+] Minimized size: {len(payload)} bytes")
    return payload

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target> <test_num> <payload>")
        sys.exit(1)

    result = minimize(sys.argv[1], sys.argv[2], sys.argv[3])
    print(f"[+] Minimal payload: {repr(result)}")
```

**Running the Minimizer**:

```bash
cd ~/crash_analysis_lab

# Create crash input (150 A's triggers stack overflow)
PAYLOAD=$(python3 -c "print('A'*150)")

# Minimize it
python3 minimize_crash.py ./vuln_asan 1 "$PAYLOAD"

# Expected output:
# [*] Original size: 150 bytes
#     Block 75: 75 bytes
#     Block 37: 74 bytes
#     Block 18: 72 bytes
#     Block 4: 68 bytes
#     Block 4: 64 bytes
# [+] Minimized size: 64 bytes
# [+] Minimal payload: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
```

> [!TIP] The minimizer found that **64 bytes** is the minimum payload to trigger the stack overflow.
> Why? The buffer is `char buffer[64]`, and `strcpy` adds a null terminator (`\0`), so 64 chars + 1 null = 65 bytes written, overflowing by exactly 1 byte!

**What Minimization Does**:

```text
Original crash: 150 bytes ("A" * 150)
Pass 1: Block-level deletion (75-byte blocks)
  → 75 bytes (still crashes)
Pass 2: Smaller blocks (37 bytes)
  → 74 bytes
Pass 3: Even smaller (18 bytes)
  → 72 bytes
Pass 4: 4-byte blocks
  → 68 bytes → 64 bytes
Pass 5: Byte-level deletion
  → 64 bytes (minimal crash - no further reduction possible)

Result: 64 chars + null terminator = 65 bytes written to buffer[64]
```

**Batch Minimization (Simple Approach)**:

```bash
cd ~/crash_analysis_lab
mkdir -p minimized

# Minimize each variant using the Python script
for crash in variants/variant_*; do
    name=$(basename "$crash")
    content=$(cat "$crash")
    test_num=$(echo "$content" | cut -d' ' -f1)
    payload=$(echo "$content" | cut -d' ' -f2-)

    echo "Minimizing $name (test=$test_num, ${#payload} bytes)..."

    # Use the minimize_crash.py script (much faster with block deletion)
    result=$(python3 minimize_crash.py ./vuln_asan "$test_num" "$payload" 2>&1 | tail -1)
    min_payload=$(echo "$result" | sed "s/.*Minimal payload: '//;s/'$//")

    echo "$test_num $min_payload" > "minimized/${name}_min"
done

# Expected output:
# Minimizing variant_1_b2f710bc (test=1, 123 bytes)...
# Minimizing variant_4_a87ff679 (test=4, 0 bytes)...
# Minimizing variant_4ddd9d03 (test=1, 149 bytes)...
# Minimizing variant_5_c0c7c76d (test=5, 1 bytes)...

ls -la minimized/
# variant_1_b2f710bc_min  67 bytes  (1 + space + 64 A's = minimal stack overflow)
# variant_4_a87ff679_min   3 bytes  (just "4 " - double-free needs no payload)
# variant_4ddd9d03_min    67 bytes  (same stack overflow)
# variant_5_c0c7c76d_min   3 bytes  (just "5 0" - null deref minimal trigger)
```

> [!TIP] **Minimization Results Analysis:**
>
> - **Stack overflow (test 1)**: Reduced to 64-byte payload (exact buffer size)
> - **Double-free (test 4)**: Reduced to 0-byte payload (crash is payload-independent)
> - **NULL deref (test 5)**: Reduced to "0" (just needs trigger flag)

**Tips for Effective Minimization**:

1. **Use block deletion first**: Much faster than byte-by-byte (O(n log n) vs O(n²))
2. **Set Appropriate Timeout**: ASAN is slow, use 5+ seconds
3. **Verify After Minimization**: Ensure crash still reproduces
4. **Know payload-independent crashes**: UAF/double-free don't need payload minimization

### Corpus Minimization with afl-cmin

**What Is afl-cmin?**:

- Minimizes corpus while preserving coverage
- Keeps smallest inputs that cover all edges
- Essential for efficient continuous fuzzing

> [!WARNING] **Important for vulnerable_suite:**
> Like `afl-tmin`, `afl-cmin` with `@@` passes a **filename**, but `vulnerable_suite` expects command-line arguments.
> For this lab, we demonstrate the concept but note this requires file-input targets in practice.

**Usage (for file-input targets)**:

```bash
# For targets that read from file (@@):
afl-cmin -i corpus_dir -o corpus_min -- ./target @@

# Options:
# -i: Input corpus directory
# -o: Output minimized corpus
# -m: Memory limit (use 'none' to disable)
# -t: Timeout in ms
# -T: Use multiple cores (e.g., -T all)
```

**Python-Based Corpus Minimization (for CLI argument targets)**:

```python
#!/usr/bin/env python3
"""
corpus_minimize.py - Coverage-based corpus minimization for CLI targets

Usage: python3 corpus_minimize.py ./vuln_asan corpus_dir/ corpus_min/
"""
import subprocess
import os
import sys
import re
from pathlib import Path

def get_coverage_signature(target, test_num, payload, timeout=5):
    """Get normalized coverage signature from ASAN output"""
    try:
        result = subprocess.run(
            [target, test_num, payload],
            capture_output=True, timeout=timeout
        )
        # Use stack trace as coverage proxy
        stderr = result.stderr.decode('latin-1', errors='ignore')
        # Extract function names from stack trace
        funcs = re.findall(r'in (\w+)', stderr)
        return tuple(funcs[:5]) if funcs else None
    except:
        return None

def minimize_corpus(target, input_dir, output_dir):
    """Keep smallest input for each unique coverage signature"""
    Path(output_dir).mkdir(exist_ok=True)

    # Group inputs by coverage
    coverage_map = {}  # signature -> (size, path, content)

    for crash_file in Path(input_dir).glob("*"):
        if crash_file.is_dir():
            continue

        # Read as binary to handle non-UTF8 data
        raw = crash_file.read_bytes()
        content = raw.decode('latin-1', errors='ignore').strip()
        parts = content.split(' ', 1)
        test_num = parts[0] if parts else "1"
        payload = parts[1] if len(parts) > 1 else ""

        sig = get_coverage_signature(target, test_num, payload)
        if sig is None:
            continue

        size = len(raw)
        if sig not in coverage_map or size < coverage_map[sig][0]:
            coverage_map[sig] = (size, crash_file.name, raw)

    # Write minimized corpus
    for i, (sig, (size, name, raw)) in enumerate(coverage_map.items()):
        out_path = Path(output_dir) / f"min_{i:04d}_{name}"
        out_path.write_bytes(raw)
        print(f"[+] {name} -> {out_path.name} ({size} bytes)")

    print(f"\n[*] Minimized: {len(list(Path(input_dir).glob('*')))} -> {len(coverage_map)} files")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target> <input_dir> <output_dir>")
        sys.exit(1)
    minimize_corpus(sys.argv[1], sys.argv[2], sys.argv[3])
```

**Running Corpus Minimization**:

```bash
cd ~/crash_analysis_lab

# Minimize the variants directory
python3 corpus_minimize.py ./vuln_asan variants/ corpus_min/

# Expected output:
# [+] variant_5_c0c7c76d -> min_0000_variant_5_c0c7c76d (3 bytes)
# [+] variant_4_a87ff679 -> min_0001_variant_4_a87ff679 (2 bytes)
# [+] variant_1_b2f710bc -> min_0002_variant_1_b2f710bc (125 bytes)
#
# [*] Minimized: 4 -> 3 files

ls -la corpus_min/
```

### Practical Exercise

**Task**: Deduplicate and minimize crashes from the vulnerable_suite test cases

**Setup**:

```bash
cd ~/crash_analysis_lab

# Generate ~25 crash inputs (varying payloads for each vuln type)
mkdir -p crashes

# Stack overflow (test 1) - varying lengths
for i in {100..200..20}; do
    echo "1 $(python3 -c "print('A'*$i)")" > crashes/stack_$i.txt
done

# Heap overflow (test 2), UAF (test 3), Double-free (test 4), NULL deref (test 5)
# TODO: Generate 5 variants each with different payloads

ls crashes/ | wc -l
```

**Challenge 1: Stack Hash Deduplication**

Write a script that:

1. Runs each crash through `./vuln_no_protect` with GDB
2. Extracts the backtrace (`bt` command)
3. Normalizes addresses (remove `0x...` to handle ASLR)
4. Computes MD5 hash of normalized stack
5. Groups crashes by unique hash

**Hints**:

- Use `gdb -batch -ex "run ..." -ex "bt" -ex "quit"`
- `sed 's/0x[0-9a-f]\+//g'` removes hex addresses
- Expected result: ~4-5 unique hashes (one per vulnerability type)

**Challenge 2: CASR Classification**

For each unique crash from Challenge 1:

1. Run through `casr-san` with the ASAN build
2. Extract `CrashSeverity.Type` from the JSON report
3. Note which bugs CASR classifies as EXPLOITABLE

**Hints**:

- `casr-san -o output.casrep -- ./vuln_asan <args>`
- `jq -r '.CrashSeverity.Type' output.casrep`
- Some vuln types (heap overflow, UAF) need ASAN to detect!

**Challenge 3: Crash Minimization**

Write a Python minimizer that:

1. Takes a crash file and binary target as input
2. Iteratively removes bytes while crash still reproduces
3. Outputs the minimal crash that still triggers the bug

**Hints**:

- Stack overflow should minimize to ~64 bytes (buffer size)
- Double-free/NULL-deref are already minimal (just the test number)
- Check `subprocess.run()` return code or ASAN output for crash detection
- Binary search is faster than linear removal

**Challenge 4: Variant Discovery**

Find additional crash variants by:

1. Mutating existing crashes with radamsa
2. Running variants through your deduplication pipeline
3. Identifying any new unique stack signatures

**Success Criteria**:

- [ ] Stack hash deduplication script working
- [ ] CASR reports generated for unique crashes
- [ ] At least one crash minimized (stack overflow: 200+ → ~64 bytes)
- [ ] Understand why heap/UAF bugs need ASAN to detect
- [ ] Document each unique bug with trigger command

### Key Takeaways

1. **Deduplication is essential**: Analyzing 100 duplicates wastes time
2. **Multiple methods improve accuracy**: Stack + coverage + CASR severity
3. **Minimization clarifies bugs**: 42 bytes easier than 8KB to understand
4. **Automation enables scale**: Manual triage doesn't scale past dozens of crashes
5. **Verification is critical**: Always confirm minimized crash reproduces bug

### Discussion Questions

1. When might stack-based deduplication give false duplicates (different bugs, same stack)?
2. How does ASLR affect crash deduplication strategies, and how does CASR handle this?
3. What are the risks of over-aggressive test case minimization with afl-tmin (e.g., losing the root cause trigger)?
4. When should you use afl-cmin (corpus minimization) vs afl-tmin (single test case minimization)?

