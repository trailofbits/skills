export const meta = {
  name: 'c-review',
  description:
    'C/C++ security review: location-partitioned reading over a generated unit list, a per-unit x per-question ledger, a shared-state invariant audit, a bounded class sweep, and deterministic artifacts',
  whenToUse:
    'Auditing a C or C++ codebase for memory corruption, integer overflow, races, or platform-specific vulnerabilities',
  phases: [
    { title: 'Detect', detail: 'platform and context from real API usage, plus the generated unit list' },
    { title: 'Review', detail: 'one agent per contiguous slice of the unit list' },
    { title: 'Sweep', detail: 'the class axis: silent bug classes, and the shared-state invariant audit' },
    { title: 'Dedup', detail: 'one agent, only for collisions the assembler cannot merge deterministically' },
    { title: 'Assemble', detail: 'one fixed command; ledger gate, merge and artifacts, no agent retypes findings' },
  ],
}

// ============================================================================
// Design, in three rules. The measurements behind them are in
// tools/c-review-bench/MEASUREMENTS.md; they are not repeated here because a
// number copied into a comment goes stale and no test catches it.
//
//   1. LOCATION is the partition. Every line has exactly one owner, generated
//      from a parse. The bug-class catalogue is a bounded completeness sweep
//      over classes nothing reported, never the fan-out.
//   2. No agent ever transcribes another agent's work. Each writes only its own
//      part file; a deterministic assembler joins them.
//   3. No false-positive judge. Severity is the reviewer's own, and the report
//      must say so next to the findings.
// ============================================================================

// --------------------------------------------------------------------- inputs

const REQUIRED_ARGS = ['outputDir', 'pluginRoot', 'threatModel', 'severityFilter']

// `args` arrives as a JSON-encoded STRING often enough to matter: the caller is a model
// emitting a tool call, and serialising the object one extra time is a coin-flip it loses
// some fraction of the time. The Workflow tool's own documentation warns about it. Refusing
// that call wastes the entire run — a bench cell is ~2.5M tokens and ~45 minutes, and the
// failure surfaces as "no args" long after the operator has stopped watching, which is
// exactly how the first containerised cell was lost. Parse it instead; a string that does
// not parse, or parses to something that is not an object, still throws below.
let args_ = args
if (typeof args_ === 'string') {
  try {
    args_ = JSON.parse(args_)
  } catch (err) {
    throw new Error(
      'c-review: args arrived as a string and is not valid JSON (' + err.message + '). ' +
        'Pass {outputDir, pluginRoot, threatModel, severityFilter, ...} as an object.'
    )
  }
}
if (!args_ || typeof args_ !== 'object' || Array.isArray(args_)) {
  throw new Error(
    'c-review: no args. The skill must pass {outputDir, pluginRoot, threatModel, severityFilter, findingScopeRoot, contextRoots, workerModel}.'
  )
}
// Read everything below through ARGS, never the injected `args` global: the global may be a
// read-only binding, so assigning the parsed object back onto it can throw in strict mode.
const ARGS = args_
for (const key of REQUIRED_ARGS) {
  if (!ARGS[key]) throw new Error('c-review: args.' + key + ' is required')
}

const OUTPUT_DIR = String(ARGS.outputDir)
const PLUGIN_ROOT = String(ARGS.pluginRoot)
const THREAT_MODEL = String(ARGS.threatModel).toUpperCase()
const SEVERITY_FILTER = String(ARGS.severityFilter).toLowerCase()
const SCOPE = String(ARGS.findingScopeRoot || '.')
const CONTEXT_ROOTS = String(ARGS.contextRoots || '.')
const WORKER_MODEL =
  ARGS.workerModel && String(ARGS.workerModel) !== 'inherit' ? String(ARGS.workerModel) : null

if (!['REMOTE', 'LOCAL_UNPRIVILEGED', 'BOTH'].includes(THREAT_MODEL)) {
  throw new Error('c-review: threatModel must be REMOTE, LOCAL_UNPRIVILEGED or BOTH')
}
if (!['all', 'medium', 'high'].includes(SEVERITY_FILTER)) {
  throw new Error('c-review: severityFilter must be all, medium or high')
}

// 628 lines with four bugs, and no configuration ever found all four in eight
// attempts. A unit larger than this reproduces exactly the saturation the
// location partition exists to remove, so the cap is not a tuning knob.
const MAX_UNIT_LINES =
  Number.isFinite(ARGS.maxUnitLines) && ARGS.maxUnitLines >= 40 ? Math.floor(ARGS.maxUnitLines) : 150

// Left unset, enumerate_units.py derives the count from the line total. Set it to
// pin the fan-out for a measured comparison.
const REVIEW_AGENTS =
  Number.isFinite(ARGS.reviewAgents) && ARGS.reviewAgents >= 1 ? Math.floor(ARGS.reviewAgents) : null

// Lines of source per review agent. Neighbouring units share callers and buffers, so a
// larger slice reads as code rather than as a sample and costs less in re-established
// context. Note `--agent-min` floors the derived count, so on a small tree lowering this
// changes nothing; use `reviewAgents` to pin the fan-out.
const LINES_PER_AGENT =
  Number.isFinite(ARGS.linesPerAgent) && ARGS.linesPerAgent >= 200
    ? Math.floor(ARGS.linesPerAgent)
    : 1500

// The class axis is exactly two agents: one completeness sweep over classes with no
// entry anywhere, and one shared-state invariant audit. Both earn their place from
// measurement — the class sweep uniquely found four bugs no location reader did, and
// the invariant audit is the only thing aimed at the five bugs that wore five
// different labels and were one mechanism. Neither is capped, so neither can silently
// drop work.

// One dedup agent, and only for what the assembler could not merge on its own.
// Under a location partition cross-reviewer duplication is near zero by
// construction, so this phase is usually skipped entirely.
const DEDUP_MAX_PAIRS = 40

// Must equal NEARBY_LINES in assemble_findings.py. Two findings in one function this
// close are the same bug described twice; the assembler merges them for the artifact
// and this side merges them to keep the pair out of the dedup agent's prompt. If the
// two numbers drift the agent is asked about pairs the artifact has already merged.
const NEARBY_LINES = 3

// Mirrors REQUIRED_FINDING_FIELDS in assemble_findings.py. Used only to decide whether a
// part's RETURNED findings were complete, which is what lets the assembler distinguish a
// stale part file from a genuinely thin one.
const REQUIRED_PART_FIELDS = ['title', 'file', 'line', 'description', 'impact', 'recommendation']

// Must equal CROSS_CLASS_NEARBY_LINES in assemble_findings.py, where the measurement
// behind it is recorded. Cross-class pairs merge deterministically only on the same line;
// one to three lines apart they go to the dedup agent instead.
const CROSS_CLASS_NEARBY_LINES = 0

const PARTS_DIR = OUTPUT_DIR + '/parts'
const SCRIPTS = PLUGIN_ROOT + '/scripts'

function workerOpts(extra) {
  const opts = Object.assign({}, extra)
  if (WORKER_MODEL) opts.model = WORKER_MODEL
  return opts
}

// ------------------------------------------------------------------- catalog
//
// `brief` carries only what a strong model does not already have: surprising library
// semantics, the specific invariant, what makes a sighting a false positive. Generic
// restatement ("check bounds before memcpy") is deliberately absent — it costs tokens and
// anchors the search on a checklist instead of on the code.
//
// `posix` gates a class on the codebase using POSIX APIs; `skipRemote` drops classes an
// off-box attacker cannot reach; `evidence` is the grep detect runs to decide whether the
// class has a candidate site at all.

const CLASSES = {
  'buffer-overflow': {
    prefix: 'BOF',
    title: 'Out-of-bounds write',
    brief:
      'Spatial safety at any write: index arithmetic, loop bounds, size computations that reach a fixed or heap buffer. The high-yield shape is a size that is computed correctly for one buffer and used against another, or a bound that is re-derived rather than reused. Not a finding when the index is provably constrained at every caller; say where.',
  },
  'oob-read': {
    prefix: 'OOBREAD',
    title: 'Out-of-bounds read',
    brief:
      'A read past either end of an allocation, which `buffer-overflow` does not cover — that class is explicitly the out-of-bounds *write*. The shapes: an index validated against the wrong buffer\'s length, a loop that reads one element past its bound, a length taken from the data rather than from the allocation, and back-references or window offsets in a decompressor that point behind the start of the buffer. Impact is disclosure or a crash, so it is a real vulnerability even where nothing is written.',
  },
  'memcpy-size': {
    prefix: 'MEMCPYSZ',
    title: 'Bad size argument to a memory primitive',
    brief:
      'The third argument to memcpy/memmove/memset/bcopy. Signed subtraction that can go negative then converts to a huge size_t; a syscall return used without an error check; unsigned subtraction that wraps. sizeof on a pointer rather than the pointee is the classic silent one.',
  },
  'overlapping-buffers': {
    prefix: 'OVERLAP',
    title: 'Overlapping source and destination',
    brief:
      'memcpy, strcpy, sprintf and the str*cat family are undefined when the regions overlap; only memmove is defined. Aliasing usually arrives through two pointers into the same allocation (buf and buf+k), not through a literally identical argument.',
    evidence: 'memcpy or strcpy with two pointers derived from one allocation',
  },
  'flexible-array': {
    prefix: 'FLEX',
    title: 'Flexible-array / struct-hack sizing',
    brief:
      'A trailing data[0] or data[1] member sized with sizeof(struct) rather than offsetof(struct, data) allocates one element too few or too many. The [1] form is the dangerous one: sizeof already counts the element, so the arithmetic silently disagrees with the C99 data[] form other code assumes.',
    evidence: 'a struct whose last member is an array of length 0 or 1',
  },

  'string-bounds-and-termination': {
    prefix: 'STRBOUND',
    title: 'String bounds and NUL termination',
    brief:
      'The three classic C string sizing errors, which are one bug with three faces. malloc(strlen(s)) followed by strcpy writes one byte past the allocation — only a bug when the destination is later used as a C string, since a raw copy of exactly strlen bytes is fine. strncpy does not NUL-terminate when the source is at least n bytes, so look for the missing buf[n-1] = 0 and for that assignment existing on only one branch. strncat\'s third argument is how many bytes to APPEND, not the destination size, and it always writes one more byte for the NUL, so sizeof(dst) is wrong by strlen(dst)+1; that one is almost always a real overflow when it appears.',
    evidence: 'a call to strcpy, strncpy, strncat, or an allocation sized from strlen',
  },
  'string-issues': {
    prefix: 'STR',
    title: 'Encoding, locale and multibyte handling',
    brief:
      'Byte length confused with character length across a conversion boundary; locale-dependent case folding used for a security comparison (Turkish dotless i is the standing example); missing UTF-8/UTF-16 validation where downstream code assumes well-formed input; surrogate-pair and overlong-encoding handling. Encoding-invariant violations are a real vulnerability class in parsers, not a cosmetic issue.',
    evidence: 'multibyte, wide-character, locale or encoding-validation code',
  },

  'format-string': {
    prefix: 'FMT',
    title: 'Format-string control',
    brief:
      'A non-literal format argument anywhere in the printf/syslog family, %n as a write primitive, and argument/specifier type mismatches. Also variadic wrappers that forward to v*printf without __attribute__((format)), which turns off every compiler check at every call site.',
    evidence: 'a printf/syslog-family call, or a variadic wrapper forwarding to v*printf',
  },
  'snprintf-retval': {
    prefix: 'SNPRINTF',
    title: 'snprintf return value is the would-have-been length',
    brief:
      'snprintf returns the length the output WOULD have had, which can exceed the buffer size; it is not the number of bytes written. So buf[n] = 0 with n from the return can write out of bounds, ptr += snprintf(...) can run the pointer past the end, and remaining = size - snprintf(...) can go negative. asprintf returns -1 and leaves the pointer indeterminate on failure.',
    evidence: 'a call to snprintf, vsnprintf or asprintf whose return value is used',
  },
  'scanf-uninit': {
    prefix: 'SCANFUNINIT',
    title: 'scanf family leaves targets uninitialized',
    brief:
      'On a partial or failed match the *scanf family leaves later targets untouched, so an uninitialized local is read as if parsed. The return value is the number of items assigned; ignoring it is what makes this exploitable. %s with no field width is a separate unbounded write.',
    evidence: 'a call to scanf, sscanf or fscanf',
  },
  'banned-api-with-attacker-data': {
    prefix: 'BANNEDAPI',
    title: 'Banned or discouraged API reached by attacker data',
    brief:
      'gets, strcpy, strcat, sprintf, vsprintf, tmpnam, tempnam, mktemp, strtok, alloca, putenv, rand for security purposes, width-less %s conversions, stpcpy, atoi and friends with no error channel. THE EVIDENCE BAR IS A FLOW, NOT A NAME: report one of these as a vulnerability only when you can trace attacker-influenced data or an attacker-influenced size to it, and state the source, the sink and what validates between them. A call whose inputs are provably bounded internal constants is a hardening observation, not a vulnerability — you may still report it, but say so plainly in the impact so the judge can rate it accordingly. Check for a project-local macro or wrapper shadowing the libc name before concluding anything. (The previous catalogue said of a bare banned call that "the presence is the bug, no data-flow trace needed" and wired it to a judge forbidden from rejecting it. That is an unrejectable-finding pump; it never fired on the measured corpora because neither uses strcpy, and it would have fired on the first legacy target.)',
    evidence: 'a call to one of the banned functions named in this brief',
  },

  'uninitialized-data': {
    prefix: 'UNINIT',
    title: 'Use or disclosure of uninitialized memory',
    brief:
      'Locals read on a path that skips their assignment, structs serialized with padding bytes intact, arrays partially filled then used at full length. The disclosure half matters as much as the use half: struct padding and tail bytes leaked over a socket or into a file are an information leak even when nothing misbehaves.',
  },
  'null-deref': {
    prefix: 'NULL',
    title: 'Null pointer dereference',
    brief:
      'Unchecked allocation returns and unchecked lookup failures. The subtle variant is a check placed after a dereference: the compiler is entitled to delete the check because the earlier dereference already proved the pointer non-null, so the guard you can see is not the guard that runs.',
    evidence: 'an allocation or lookup whose result is dereferenced',
  },
  'use-after-free': {
    prefix: 'UAF',
    title: 'Use after free, double free, dangling pointer',
    brief:
      'A pointer that survives its allocation: freed on an error path and used by the caller, freed twice through two owners, or invalidated by a realloc whose old value some other variable still holds. Realloc aliasing is the one most often missed — every copy of the old pointer is dangling after a successful realloc.',
  },
  'memory-leak': {
    prefix: 'LEAK',
    title: 'Memory and resource leak',
    brief:
      'Leaks matter here when the leaking path is attacker-repeatable — an error branch reachable from untrusted input is a remote memory-exhaustion primitive. A leak only reachable once at startup is not. File descriptors, sockets and locks count as resources. Cold error paths are where these live, and cold error paths are the ground an attacker-reachability prior deprioritises, so read them deliberately.',
  },
  'state-field-invariant': {
    prefix: 'STATEINV',
    title: 'Invariant on a field of a shared state struct',
    brief:
      'A field or flag of a long-lived struct carries a rule that must hold across every reset, allocation, refill and free path, and one path breaks it. C-specific by construction: malloc does not zero, lifetime is manual, and the struct is threaded through a state machine where no single function owns the field. This is the mechanism behind five bugs in the measured corpus that wore five different labels — buffer-overflow, unsigned overflow, uninitialised use, encoding invariant, double free — and that every configuration missed, including the ones whose class DID cover the symptom. THIS IS NOT A LABEL TO GREP FOR. It is the output of the invariant audit: enumerate the fields, find every writer and every reader, and prove the field\'s rule at each. Used as a search term it will reproduce the failure it was created to describe.',
  },

  'integer-overflow': {
    prefix: 'INT',
    title: 'Integer overflow, truncation and signedness',
    brief:
      'Size and length arithmetic is the payload: n * sizeof(T) with no overflow check, a + b compared against a bound after the addition already wrapped, a 64-bit length truncated into an int, a signed value that goes negative and then converts to a huge size_t. Signed overflow is undefined, so a post-hoc check like if (a + b < a) may be deleted by the compiler — that is a bug even where the wrap would have been benign. Growth patterns that double a size, or add a header to a body length, are where this reaches memory corruption. Unsigned subtraction is the quiet one: `a - b` where b can exceed a wraps to a near-SIZE_MAX value that passes every upper-bound check written for the non-wrapping case.',
  },
  'oob-comparison': {
    prefix: 'OOBCMP',
    title: 'Comparison reads past the shorter buffer',
    brief:
      'memcmp/strncmp/bcmp with a length taken from the longer operand, and the three-iterator std::equal, which reads from the second range without knowing its end. Also: memcmp is not constant-time, so using it on a secret is a separate timing problem worth noting.',
    evidence: 'a call to memcmp, strncmp, bcmp or std::equal',
  },
  'operator-precedence': {
    prefix: 'PREC',
    title: 'Operator precedence and associativity',
    brief:
      'Shift binds looser than addition; bitwise and/or bind looser than comparison; the ternary binds looser than assignment. The security-relevant shapes are a mask test written without parentheses and a size expression whose intended grouping differs from the parsed one.',
  },
  'type-confusion': {
    prefix: 'TYPE',
    title: 'Type confusion, unsafe casts and null/zero conversions',
    brief:
      'A buffer cast to a struct larger than the allocation is the memory-corrupting form — look for numbered or "extended" struct variants where the choice of variant comes from the data. Also: union members read under the wrong tag, void* callback payloads cast back to the wrong type, and C++ downcasts done with static_cast where the dynamic type is attacker-influenced. In a variadic (or K&R) call the compiler cannot convert 0 to a null pointer, so execl(path, arg, 0) passes an int where a char* terminator is required, and on LP64 that is 32 bits of zero followed by whatever is next; 0 in a prototyped pointer parameter is fine.',
  },
  'undefined-behavior': {
    prefix: 'UB',
    title: 'Undefined behavior the optimizer can weaponize',
    brief:
      'Shifts by a negative amount or by at least the promoted width; misaligned loads via a cast; strict-aliasing violations that are not char*, memcpy or a union; unsequenced modification of the same object. What makes these security bugs rather than pedantry is that the optimizer is allowed to assume they never happen and delete the surrounding check — so the consequences belong here too: memset of a secret before the object dies is dead-store-eliminated unless explicit_bzero, memset_s, SecureZeroMemory or a volatile access is used; security checks inside assert() vanish under NDEBUG; a null check placed after a dereference is removable; and constant-time code written in plain C is not constant-time after optimization.',
  },

  'error-handling': {
    prefix: 'ERR',
    title: 'Unchecked, mis-compared or mis-propagated return values',
    brief:
      'Ignoring the return of an allocation, an open, a crypto verify, or a write. Comparing against the wrong success convention — a function that returns 1 on success tested with != 0, or -1 on error tested with != 1. A failure that is logged but not propagated leaves the caller acting on invalid state. Three specific shapes travel with this class. NEGATIVE RETURNS: read/write/recv/send/snprintf return negative on error, and assigned into a size_t, -1 becomes SIZE_MAX, after which n == -1 against an unsigned type is never true — the check reads as present but never fires. ERRNO: it is only meaningful after a call that failed, functions with a legitimate sentinel (strtol returning 0 or LONG_MAX, getpwnam returning NULL) need errno = 0 before the call, and errno is clobbered by intervening library calls including the logging call in the error branch itself. EINTR: blocking syscalls must be retried unless SA_RESTART covers every installed handler, close() is the exception because on Linux the descriptor is already released when it returns EINTR so retrying can close an unrelated descriptor, and a retry loop that restarts a partial read from the beginning is also wrong.',
  },

  'open-issues': {
    prefix: 'FILEOP',
    title: 'Unsafe file open and path resolution',
    posix: true,
    brief:
      'access() then open() is a symlink race whenever the directory is attacker-writable, and access() answers for the real uid, not the effective one. O_NOFOLLOW only refuses a symlink as the final component — every directory in the path is still followed; openat2 with RESOLVE_NO_SYMLINKS or component-by-component openat is the real fix. Missing O_CLOEXEC leaks descriptors across exec.',
    evidence: 'a call to open, openat, creat or access',
  },
  'filesystem-issues': {
    prefix: 'FS',
    title: 'Symlink, temp file and path-normalization issues',
    brief:
      'Predictable temp names (tmpnam/tempnam/mktemp, or a PID-derived name) in a shared directory; a path prefix check that a "..", a symlink, a trailing slash, or a case-insensitive filesystem can defeat; Unicode normalization applied after the check rather than before. A prefix test that compares strings rather than resolved paths is the recurring bug.',
    evidence: 'temp-file creation, or a path prefix or traversal check',
  },
  'socket-state': {
    prefix: 'SOCKSTATE',
    title: 'Socket association and half-closed state',
    posix: true,
    brief:
      'Calling connect() with sa_family set to AF_UNSPEC dissolves an already-connected socket, after which it can be reconnected elsewhere; if any part of a sockaddr reaching connect() is attacker-influenced, the association a sandbox or a peer identity relies on can be dropped, and this has been used for sandbox escapes. Separately, shutdown(fd, SHUT_WR) leaves the socket readable and SHUT_RD leaves it writable, so a state machine that treats "peer closed" as "connection over" keeps processing data that arrives in the half-closed window, or frees per-connection state a subsequent read still touches — and a peer that half-closes rather than closing can hold a connection slot open indefinitely.',
    evidence: 'a call to connect, shutdown or a per-connection state machine',
  },

  'race-condition': {
    prefix: 'RACE',
    title: 'TOCTOU and unsynchronized shared state',
    brief:
      'Check-then-act on anything another actor can change between the two steps: a filesystem path, a shared counter, a cached pointer. Double-fetch is the memory version — reading an attacker-writable location twice and assuming the two reads agree, so the validated value is not the used value. Also lock scope that ends before the compound operation does.',
    evidence: 'threads, shared mutable globals, or a check-then-act on the filesystem',
  },
  'thread-safety': {
    prefix: 'THREAD',
    title: 'Non-reentrant calls and uninitialized lock primitives',
    posix: true,
    brief:
      'gethostbyname, inet_ntoa, strtok, strerror, localtime, gmtime, ctime, asctime, getpwnam, getgrnam and readdir return pointers to static storage that the next call from any thread overwrites; the bug is not the call, it is the window between the call and the consumption of the result. pthread_spinlock_t has no static initializer, so a spinlock reached on a path that skipped pthread_spin_init — or whose init return was ignored — is used uninitialized, and the same shape applies to a mutex whose pthread_mutex_init failed unchecked. Only relevant if the process actually creates threads.',
    evidence: 'pthread_create or another thread-creation API',
  },
  'signal-handler': {
    prefix: 'SIGNAL',
    title: 'Async-signal-unsafe handler',
    posix: true,
    brief:
      'A handler may call only async-signal-safe functions. malloc/free reentered from a handler corrupts the allocator; stdio reentered from a handler corrupts its lock and buffers; longjmp out of a handler leaves everything indeterminate. A handler must also save and restore errno. The safe shapes are: set a volatile sig_atomic_t flag, or write() one byte to a self-pipe.',
    evidence: 'a call to signal() or sigaction()',
  },

  'access-control': {
    prefix: 'ACCESS',
    title: 'Missing or misplaced authorization',
    brief:
      'An operation that changes state or returns data on behalf of a principal, with no check that the principal is entitled to it — or a check performed on a different value than the one used. Includes capability and descriptor leaks across a privilege boundary.',
  },
  'privilege-drop': {
    prefix: 'PRIVDROP',
    title: 'Incomplete or unchecked privilege drop',
    posix: true,
    skipRemote: true,
    brief:
      'setuid() from a non-root effective uid can fail while returning a value nobody checks, leaving the process privileged. seteuid() alone leaves the saved-set-uid, so privileges can be regained; setresuid(uid,uid,uid) is the complete form. Groups must be dropped before the user, and setgroups() must be called to clear the supplementary set. Verify the drop by reading back the ids.',
    evidence: 'a call to setuid, seteuid, setresuid, setgid or setgroups',
  },
  envvar: {
    prefix: 'ENVVAR',
    title: 'Environment variable trust',
    posix: true,
    skipRemote: true,
    brief:
      'Under LOCAL_UNPRIVILEGED the environment is attacker data. Relevant shapes: a privileged process trusting a variable for a path or a library location; a secret placed in the environment where any process that can read /proc/<pid>/environ sees it; setenv leaving the previous value reachable; a child inheriting an environment that was never sanitized.',
    evidence: 'a call to getenv, setenv or putenv',
  },
  'time-issues': {
    prefix: 'TIME',
    title: 'Clock and time-arithmetic assumptions',
    brief:
      'Wall-clock time used to measure a duration (an expiry or a rate limit that the clock stepping backwards defeats); 32-bit time_t overflow; comparisons that assume 86400-second days across a DST or leap-second boundary. Only report where the wrong answer has a security consequence.',
    evidence: 'a time(), gettimeofday() or clock call used for expiry or rate limiting',
  },
  dos: {
    prefix: 'DOS',
    title: 'Attacker-controlled resource consumption',
    brief:
      'Unbounded allocation, unbounded recursion, and superlinear algorithms driven by input size. Recursion depth is the highest-yield one in parsers: look for a depth counter that exists but is never compared against a limit, a limit that only counts one of several recursive paths, or an amplification guard that a linear chain slips under. Hash-table collision floods and regex backtracking belong here too. A countable population — enumerate EVERY recursive construct before writing this class off; one run filed a single stack-exhaustion bug, declared the class covered, and never looked at the second recursion in the same file.',
  },

  'exploit-mitigations': {
    prefix: 'MITIGATION',
    title: 'Missing or silently misspelled hardening flags',
    brief:
      'Read the actual build files. The interesting failure is not an absent flag but a misspelled one — _FORTIFY_SORUCE, -fstack-protector-stong, _GLIBCXX_ASSERTONS — because a typo in a -D or a -f flag is accepted silently and the mitigation is simply off while the build looks hardened. Also check that the flag reaches the target, not only a sample or test build.',
    evidence: 'a Makefile, CMakeLists.txt, configure script or meson.build in the tree',
  },

  qsort: {
    prefix: 'QSORT',
    title: 'Non-transitive comparator drives qsort out of bounds',
    posix: true,
    brief:
      'glibc qsort trusted its comparator to be a valid ordering; an inconsistent one walks the merge past the array (CVE-2023-6246 family, Qualys 2024). Inconsistency sources: subtracting ints, which overflows; comparing only a prefix or one field of a record; floating point where NaN makes every comparison false; and a multi-key comparator that returns 0 for distinct records. The safe form is (a > b) - (a < b).',
    evidence: 'a call to qsort, bsearch or another comparator-taking function',
  },
  'regex-issues': {
    prefix: 'REGEX',
    title: 'Regex denial of service and matching bypasses',
    brief:
      'Backtracking blowup from nested or overlapping quantifiers on attacker input. Bypasses: an unanchored pattern used as if it were a whole-string test, and POSIX regexec matching per line unless REG_NEWLINE semantics are considered, so an embedded newline can hide the rest of the input from a check.',
    evidence: 'a call to regcomp, regexec or another regex API',
  },
  'va-start-end': {
    prefix: 'VAARG',
    title: 'va_list lifecycle',
    brief:
      'Every va_start and every va_copy needs a matching va_end before the function returns, including on early-error paths. Reusing a va_list after it has been consumed by one v*printf call is undefined — a second consumer needs va_copy.',
    evidence: 'a va_start, va_copy or variadic function definition',
  },

  'logic-flaw': {
    prefix: 'LOGIC',
    title: 'Security logic, protocol and state-machine flaws',
    brief:
      'Everything memory-safety taxonomies do not name, and the single most productive class in the measured runs — 30 filed, 28 credited, more than any specific label. Namespace or delimiter injection, where a separator character the format reserves is accepted inside a value and re-emitted so the two parse differently on the way back. Protocol state machines that accept a message in a state that skips authentication or size negotiation, or that return success on a path meant to signal "need more input". Deserialization that lets input choose a type or a size. Off-by-one in an index-to-identity mapping. Two named patterns worth hunting explicitly, because both were found here without a class of their own: VALIDATED-VALUE SUBSTITUTION, where one value is checked and a different, unchecked one reaches the sink — validation applied to a normalized copy while the raw value is used downstream is the same shape; and CALL-SITE INVARIANT, where a shared macro or helper enforces a well-formedness rule at some expansion sites and not all, so one path admits input the others reject. Also: a value read out of a header or a length field and stored into state without being checked against the bound the rest of the code assumes. These are found by reading what a value is ALLOWED to be and then asking what the code does with a value one step outside that.',
  },
  'crypto-misuse': {
    prefix: 'CRYPTO',
    title: 'Cryptographic misuse',
    brief:
      'Correct primitives assembled wrongly. A nonce or IV reused across two messages under one key, or derived from a counter that resets when the process does. One key serving two purposes, or a long-term key used where an ephemeral one belongs. Secrets, MACs or tags compared with memcmp or strcmp, which returns early and leaks position. Ciphertext decrypted before its tag is checked, or a tag never checked. ECB, or any unauthenticated mode where the plaintext is attacker-influenced. Keys or salts from rand/srand, time, a PID, or a hardcoded constant instead of a CSPRNG. A KDF with no salt or a trivial iteration count. Padding or signature verification whose failure path returns the same value as success. Judge the construction against what the primitive requires of its caller, not against whether the primitive itself is sound.',
    evidence: 'a cryptographic primitive, key, nonce, MAC or random-number call',
  },

  'smart-pointer': {
    prefix: 'SPTR',
    title: 'C++ smart pointer ownership',
    brief:
      'Two independent shared_ptr control blocks built from one raw pointer (double free); a raw pointer or reference handed out of a unique_ptr and outliving it; shared_ptr cycles; weak_ptr::lock() result used without checking.',
  },
  'move-semantics': {
    prefix: 'MOVE',
    title: 'Use of a moved-from object',
    brief:
      'A moved-from object is valid but unspecified. The security-relevant shape is a buffer or key moved out and then read as if it still held the data, and a std::move inside a loop that moves the same object on every iteration.',
  },
  'lambda-capture': {
    prefix: 'LAMBDA',
    title: 'Lambda capture outliving its referent',
    brief:
      'A lambda stored in a callback, a thread, or a coroutine that captured a local by reference, or captured this, and now outlives it. [=] on a member function captures this by value, not the members — a common surprise.',
  },
  'iterator-invalidation': {
    prefix: 'ITER',
    title: 'Iterator, pointer or reference invalidated by a container mutation',
    brief:
      'Any vector or string growth invalidates every iterator, pointer and reference into it, including one held across a function call that appends. Erasing inside a loop without taking the returned iterator. unordered_ containers invalidate iterators on rehash but keep references valid — the asymmetry causes real bugs.',
  },

  'init-order': {
    prefix: 'INIT',
    title: 'Static initialization order',
    brief:
      'A namespace-scope object in one translation unit whose constructor reads one defined in another has no defined order. Member initializers run in declaration order, not in the order they are written in the list. The observable failure is a security check reading a not-yet-initialized table.',
  },
  'virtual-function': {
    prefix: 'VIRT',
    title: 'Virtual dispatch hazards',
    brief:
      'A virtual call in a constructor or destructor dispatches to the class being constructed, not the derived override, so a derived-class invariant check silently does not run. Deleting through a base pointer without a virtual destructor. Object slicing on assignment to a base value.',
  },
  'exception-safety': {
    prefix: 'EXCEPT',
    title: 'Exception paths that leak or leave partial state',
    brief:
      'A resource acquired between a try and the RAII wrapper that would release it; a destructor that can throw (terminate during unwind); a noexcept function whose callee throws. The security shape is a lock or a privilege left held, or a half-updated invariant observed after the handler.',
  },

  createprocess: {
    prefix: 'CREATEPROC',
    title: 'Windows process creation',
    brief:
      'An unquoted lpApplicationName/lpCommandLine path with spaces lets C:\\Program.exe run instead of the intended target. bInheritHandles = TRUE hands every inheritable handle to the child. Also: creating a process with a token or a working directory the caller does not control.',
  },
  'cross-process': {
    prefix: 'CROSSPROC',
    title: 'Cross-process memory and handle access',
    brief:
      'OpenProcess/ReadProcessMemory/WriteProcessMemory against a PID that can be recycled or a handle obtained without verifying the target identity. Duplicating a handle into a lower-privileged process with more access than intended.',
  },
  'token-privilege': {
    prefix: 'TOKPRIV',
    title: 'Token and impersonation handling',
    brief:
      'Impersonation that is not reverted on every path, including error paths. ImpersonateNamedPipeClient without first checking the client is who is expected. Privileges enabled and left enabled. A SECURITY_DESCRIPTOR with a NULL DACL, which grants everyone full control (it is not the same as an empty DACL, which grants no one).',
  },
  'service-security': {
    prefix: 'WINSVC',
    title: 'Windows service configuration',
    brief:
      'A service binary or its directory writable by non-admins; a service whose ACL allows SERVICE_CHANGE_CONFIG to a non-admin (the binary path can then be rewritten); an unquoted ImagePath with spaces.',
  },

  'dll-planting': {
    prefix: 'DLLPLANT',
    title: 'DLL search-order hijacking',
    brief:
      'LoadLibrary with a bare name, or an implicit import of a DLL not present in System32, resolves through a search order that includes the application directory and (without SetDefaultDllDirectories) the current directory. Use a fully qualified path or LOAD_LIBRARY_SEARCH_SYSTEM32.',
  },
  'windows-path': {
    prefix: 'WINPATH',
    title: 'Windows path parsing',
    brief:
      'Path checks defeated by 8.3 short names, alternate data streams, a trailing dot or space that the filesystem strips, the \\\\?\\ prefix that skips normalization, device names such as CON and NUL, and UNC paths reaching a check written for local paths. Case-insensitivity plus Unicode folding defeats string prefix tests.',
  },
  'installer-race': {
    prefix: 'INSTRACE',
    title: 'Installer and updater filesystem race',
    brief:
      'A privileged installer writing to or executing from a directory a normal user can write, or extracting to a temp directory before setting its ACL. The window between create and ACL-set is the bug.',
  },

  'named-pipe': {
    prefix: 'NAMEDPIPE',
    title: 'Named pipe security',
    brief:
      'A server that does not create the pipe with FILE_FLAG_FIRST_PIPE_INSTANCE can be squatted by a client that created the name first. A server that impersonates a client without validating it, or a client that connects without SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, can be impersonated by a malicious server.',
  },
  'windows-crypto': {
    prefix: 'WINCRYPTO',
    title: 'Windows cryptography API misuse',
    brief:
      'Deprecated CryptoAPI with weak algorithms; a static or zero IV; RSA without OAEP; a key derived from a password without a KDF; CryptGenRandom replaced by rand. Also CryptProtectData used for data that crosses a trust boundary it does not protect.',
  },
  'windows-alloc': {
    prefix: 'WINALLOC',
    title: 'Windows allocator misuse',
    brief:
      'Mixing allocator families (HeapAlloc freed with free, LocalAlloc freed with HeapFree, CoTaskMemAlloc freed with delete). Size arithmetic before HeapAlloc that can overflow. HEAP_ZERO_MEMORY assumed but not passed.',
  },
}

// Groups are no longer agent units — location is the partition. They keep three
// jobs: the coarse platform gate, batching the completeness sweep (one agent for
// "nothing in concurrency has an entry" is coherent; four agents for four silent
// classes is not), and the reporting taxonomy. Because they are not agent units
// their sizes no longer matter, which is why two of them are now single-class.
const GROUPS = [
  { id: 'memory-bounds', title: 'Memory bounds', classes: ['buffer-overflow', 'oob-read', 'memcpy-size', 'overlapping-buffers', 'flexible-array'] },
  { id: 'string-handling', title: 'String handling', classes: ['string-bounds-and-termination', 'string-issues'] },
  { id: 'format-and-input-apis', title: 'Format and input APIs', classes: ['format-string', 'snprintf-retval', 'scanf-uninit', 'banned-api-with-attacker-data'] },
  { id: 'object-lifecycle', title: 'Object lifecycle', classes: ['uninitialized-data', 'null-deref', 'use-after-free', 'memory-leak', 'state-field-invariant'] },
  { id: 'integer-safety', title: 'Integer overflow and bounds arithmetic', classes: ['integer-overflow', 'oob-comparison'] },
  { id: 'conversion-and-ub', title: 'Conversions, precedence and undefined behavior', classes: ['operator-precedence', 'type-confusion', 'undefined-behavior'] },
  { id: 'syscall-returns', title: 'Return values and errno', classes: ['error-handling'] },
  { id: 'files-and-sockets', title: 'Files and sockets', classes: ['open-issues', 'filesystem-issues', 'socket-state'] },
  { id: 'concurrency', title: 'Concurrency', classes: ['race-condition', 'thread-safety', 'signal-handler'] },
  { id: 'ambient-and-dos', title: 'Ambient state and DoS', classes: ['access-control', 'privilege-drop', 'envvar', 'time-issues', 'dos'] },
  { id: 'build-hardening', title: 'Build hardening', classes: ['exploit-mitigations'] },
  { id: 'library-api-misuse', title: 'Library API contract misuse', classes: ['qsort', 'regex-issues', 'va-start-end'] },
  { id: 'logic-and-protocol', title: 'Logic, protocol and crypto', classes: ['logic-flaw', 'crypto-misuse'] },
  { id: 'cpp-lifetime', title: 'C++ lifetime', gate: 'is_cpp', classes: ['smart-pointer', 'move-semantics', 'lambda-capture', 'iterator-invalidation'] },
  { id: 'cpp-classes', title: 'C++ class semantics', gate: 'is_cpp', classes: ['init-order', 'virtual-function', 'exception-safety'] },
  { id: 'windows-process', title: 'Windows processes', gate: 'is_windows', classes: ['createprocess', 'cross-process', 'token-privilege', 'service-security'] },
  { id: 'windows-fs-path', title: 'Windows filesystem and paths', gate: 'is_windows', classes: ['dll-planting', 'windows-path', 'installer-race'] },
  { id: 'windows-ipc-crypto', title: 'Windows IPC and crypto', gate: 'is_windows', classes: ['named-pipe', 'windows-crypto', 'windows-alloc'] },
]

// -------------------------------------------------------------------- schemas

const DETECT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: [
    'is_cpp', 'is_posix', 'is_windows', 'platform_evidence', 'purpose', 'entry_points',
    'trust_boundaries', 'existing_hardening', 'state_structs', 'class_evidence',
    'units_ok', 'units_summary',
  ],
  properties: {
    is_cpp: { type: 'boolean', description: 'C++ translation units are compiled, not merely C headers guarded by extern "C"' },
    is_posix: { type: 'boolean', description: 'the code actually calls POSIX APIs on the build path being audited' },
    is_windows: { type: 'boolean', description: 'the code actually calls Win32 APIs on the build path being audited' },
    platform_evidence: { type: 'string', description: 'one line per flag set true, each citing a path:line that shows real API usage' },
    purpose: { type: 'string' },
    entry_points: { type: 'array', items: { type: 'string' }, description: 'where untrusted data enters, as path:line plus one phrase' },
    trust_boundaries: { type: 'array', items: { type: 'string' } },
    existing_hardening: { type: 'array', items: { type: 'string' }, description: 'fuzzers, sanitizers, assertions, privilege separation actually present in the tree' },
    state_structs: {
      type: 'array',
      description:
        'long-lived mutable structs threaded through the code whose fields carry rules across function boundaries. One entry per struct as "path:line StructName — what it is for". Empty is a valid answer for code with no such struct.',
      items: { type: 'string' },
    },
    class_evidence: {
      type: 'array',
      description: 'one entry per bug class you were asked about',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['bug_class', 'has_candidates', 'citation'],
        properties: {
          bug_class: { type: 'string' },
          has_candidates: { type: 'boolean', description: 'true only if you can cite a real candidate site in the source' },
          citation: { type: 'string', description: 'path:line of one candidate site, or the concrete reason there is none' },
        },
      },
    },
    units_ok: { type: 'boolean', description: 'enumerate_units.py exited 0 and wrote units.json' },
    units_summary: { type: 'string', description: 'the totals block the script printed, or its error text' },
    assignment_ids: { type: 'array', items: { type: 'string' }, description: 'the assignment ids the script produced, e.g. unit-01' },
  },
}

const LEDGER_ROW = {
  type: 'object',
  additionalProperties: false,
  required: ['unit_id', 'question', 'verdict', 'sites_accounted', 'evidence'],
  properties: {
    unit_id: { type: 'string', description: 'copied exactly from your assignment file' },
    question: { type: 'string', description: 'one of the question ids listed for that unit' },
    verdict: {
      type: 'string',
      enum: ['clean', 'finding', 'needs-human', 'not-applicable'],
      description:
        'clean means you accounted for every counted site and none is a bug. finding means at least one is, AND you still accounted for the rest. not-applicable is only valid when the counted population is empty.',
    },
    sites_accounted: {
      type: 'array',
      items: { type: 'integer' },
      description:
        'the line numbers from this question\'s site list in your assignment file that you actually looked at. A clean or finding verdict must list ALL of them — a gate compares this against the parse, not against your description of what you did.',
    },
    evidence: { type: 'string', description: 'what you found at those sites, including at the ones you did not file' },
  },
}

const FINDING_PROPERTIES = {
  bug_class: { type: 'string', description: 'one of the class ids listed in the prompt, or the closest one if the bug is outside them' },
  title: { type: 'string' },
  file: { type: 'string', description: 'repo-relative path, no markdown link, no absolute path' },
  line: { type: 'integer', minimum: 1 },
  function: { type: 'string', description: 'the single enclosing function, or (file-level)' },
  unit_id: { type: 'string', description: 'the unit id this bug sits in, copied from your assignment file; empty if it is outside your units' },
  confidence: { type: 'string', enum: ['High', 'Medium', 'Low'] },
  description: { type: 'string', description: 'the broken invariant and what the attacker controls' },
  code: { type: 'string', description: 'the real snippet, copied not paraphrased' },
  data_flow: { type: 'string', description: 'source, sink and what validation exists between them; N/A for a file-level finding' },
  reachability: { type: 'string', description: 'call chain from an entry point, or the honest limit of what you traced' },
  impact: { type: 'string' },
  mitigations_checked: { type: 'string', description: 'each mitigation you looked for, with the path:line where you found it or the statement that it is absent' },
  recommendation: { type: 'string' },
  outside_assigned_classes: { type: 'boolean', description: 'true when this bug is outside the units or classes you were assigned' },
  // Severity is the reporter's job now. There is no judge downstream to assign it,
  // so an omitted severity becomes MEDIUM by default rather than being reviewed.
  severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], description: 'against the table in your prompt, relative to this threat model' },
  attack_vector: { type: 'string', enum: ['Remote', 'Local', 'Both'] },
  exploitability: { type: 'string', enum: ['Reliable', 'Difficult', 'Theoretical'] },
  severity_rationale: { type: 'string', description: 'one line: what makes it this level and not the one above or below' },
}

const FINDING_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['bug_class', 'title', 'file', 'line', 'function', 'confidence', 'description', 'code', 'impact', 'recommendation'],
  properties: FINDING_PROPERTIES,
}

const REVIEW_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['part_written', 'findings', 'ledger', 'external_sources_consulted', 'external_sources_detail'],
  properties: {
    part_written: { type: 'boolean', description: 'true once you have written your part file to the path given in the prompt' },
    findings: { type: 'array', items: FINDING_SCHEMA },
    ledger: { type: 'array', items: LEDGER_ROW },
    external_sources_consulted: {
      type: 'boolean',
      description:
        'true if you read anything outside this repository while working — upstream sources, a git history, a changelog, an advisory, a CVE record, a search result. Declaring it is expected and carries no penalty; it exists so benchmark runs can be scored honestly.',
    },
    external_sources_detail: { type: 'string', description: 'what you consulted and why, or the single word "none"' },
    pointers: {
      type: 'array',
      description:
        'bugs you noticed OUTSIDE your assigned units. One line each, no write-up: the owner of those lines will do that. Promoted to a finding only if the owner files nothing there.',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['file', 'line', 'note'],
        properties: {
          file: { type: 'string', description: 'repo-relative' },
          line: { type: 'integer', minimum: 1 },
          note: { type: 'string', description: 'one sentence: what looks wrong' },
        },
      },
    },
    notes: { type: 'string', description: 'anything a human should know: units you could not finish, files you could not read, areas that need a person' },
  },
}

const DEDUP_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['merges'],
  properties: {
    merges: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['primary', 'duplicates', 'rationale'],
        properties: {
          primary: { type: 'string', description: 'the candidate key that survives' },
          duplicates: { type: 'array', items: { type: 'string' } },
          rationale: { type: 'string', description: 'one phrase naming the single shared source construct' },
        },
      },
    },
  },
}

const ASSEMBLE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['ok'],
  properties: {
    ok: { type: 'boolean' },
    reported: { type: 'integer' },
    raw_findings: { type: 'integer' },
    // The assembler runs the ledger gate in-process now, so these come back from it
    // rather than from a gate agent of their own.
    checks_required: { type: 'integer' },
    checks_completed: { type: 'integer' },
    checks_satisfied: { type: 'integer', description: 'answered AND accepted by the gate' },
    error: { type: 'string' },
  },
}

// -------------------------------------------------------------------- prompts

const EVIDENCE_RULE = [
  'EVIDENCE RULE — the most important instruction here.',
  '',
  'Every negative conclusion you reach rests on the code in front of you. You may not clear a',
  'candidate, and you may not conclude that a bug class is absent, on the basis of what you recall',
  'about this project: its identity, its version, its release history, or its published',
  'vulnerabilities. Recalled knowledge that "the fix for this is already upstream" is not evidence,',
  'and asserting it has previously caused this pipeline to suppress real, present bugs that a plain',
  'reading of the file would have found.',
  '',
  'If you claim a guard, a bounds check, a cast, or any other mitigation exists, cite the path:line',
  'where it is written, so a reader can open that line and see it. If you cannot cite it, it is not',
  'there. Nothing outside this repository substitutes for that citation: an upstream diff, a',
  'changelog or an advisory may tell you where to look, but only the code in front of you can clear',
  'a candidate.',
].join('\n')

const EXTERNAL_SOURCE_DECLARATION = [
  'DECLARE EXTERNAL SOURCES.',
  '',
  'Set external_sources_consulted true if you read anything outside this repository while working —',
  'an upstream release or tarball, a git history, a changelog, an advisory, a CVE record, a search',
  'result, a vendored copy elsewhere on the machine. Otherwise set it false. Put what you used in',
  'external_sources_detail, or the single word "none".',
  '',
  'Declaring true costs you nothing. Nothing is dropped, downgraded or re-reviewed because of it,',
  'and in a real audit comparing against upstream is legitimate and often the fastest route to a',
  'bug. The flag exists for one reason: this pipeline is also measured against corpora whose bugs',
  'are already public, and a run where a reviewer read the answer off an upstream fix measures',
  'diffing rather than review, so the score has to know which findings came from where. The only',
  'thing that does damage is an undeclared consultation.',
].join('\n')

// The escape hatch, rewritten for a LOCATION partition. The original text told every
// agent "report anything you find, no one else is guaranteed to be looking for it" — true
// when work was split by bug class, because classes had gaps. Under a location partition
// every line has exactly one owner, so the claim is false and the sentence buys duplicate
// work — measured, it drove one line being written up by five of six agents.
//
// The safety net is kept and made cheap: out-of-class but IN your slice is still a full
// finding; out of your slice is a one-line pointer, promoted only if the owner never filed
// there. Nothing is lost and nothing is written twice.
const REVIEW_ESCAPE_HATCH = [
  'REPORT WHAT YOU FIND — BUT ONLY WRITE UP WHAT IS YOURS.',
  '',
  'Inside your assigned units the questions and classes are where to start, not a fence. Any',
  'security bug of any kind — authorization gap, protocol state-machine error, injection through a',
  'reserved delimiter, deserialization flaw, broken encoding invariant, nonce reuse, path traversal',
  '— is a full finding, with outside_assigned_classes set to true.',
  '',
  'OUTSIDE your units, do not write a finding. Every line has exactly one owner and the owner is',
  'reading them now with more context than you have. Put it in `pointers`: file, line, one sentence,',
  'nothing else. If the owner files it your pointer is dropped; if the owner misses it, it is',
  'promoted and the bug still reaches the report.',
  '',
  'Do not drop a bug because you doubt it matters. You assign severity yourself and there is no',
  'judge downstream, so a finding you leave out is not filtered — it is never seen.',
].join('\n')

const ESCAPE_HATCH = [
  'REPORT WHAT YOU FIND.',
  '',
  'The questions and classes below are where to start, not a fence. If you find a security bug of',
  'any kind while reading — an authorization gap, a protocol state-machine error, an injection',
  'through a reserved delimiter, a deserialization flaw, a broken encoding invariant, a nonce reuse,',
  'a path traversal — report it and set outside_assigned_classes to true. No one else is guaranteed',
  'to be looking for it, and the least specific class in this catalogue is also its most productive.',
  '',
  'Do not drop a bug because you doubt it matters. You assign its severity yourself and there is',
  'no judge downstream, so a finding you leave out is not filtered — it is simply never seen.',
].join('\n')

// The class sweep's escape hatch. Its "assigned" is a list of bug CLASSES computed AFTER
// every location reviewer returned — exactly the classes with zero findings anywhere in this
// run. So for any class NOT on the list, "someone already filed in this class" is true by
// construction rather than a guess. Out-of-class sightings become pointers, not silence: a
// measured run's only sweep-found ground-truth bug sat in an already-covered class.
const CLASS_SWEEP_ESCAPE_HATCH = [
  'REPORT WHAT YOU FIND — BUT ONLY WRITE UP YOUR ASSIGNED CLASSES.',
  '',
  'A bug whose class is one of yours above is a full finding.',
  '',
  'A bug whose class is NOT one of yours: put it in `pointers`, not a finding. Your class list is',
  'exactly the classes with zero findings anywhere in this run, computed after every location',
  'reviewer finished — so any class you were not given already has a finding from someone who read',
  'those lines with more context. That is checked against this run\'s output, not assumed.',
  '',
  'A pointer is file, line, and one sentence naming the mechanism — not "looks suspicious". Make it',
  'earn its place: if no finding lands within 12 lines, the assembler promotes it and your sentence',
  'becomes the description verbatim, with no one downstream to expand it.',
  '',
  'None of this narrows what you read: cover the whole tree and notice every class. It only changes',
  'how an out-of-class bug is written up. Do not drop a bug because you doubt it matters or because',
  'it is outside your classes — there is no judge downstream, so what you leave out is never seen.',
].join('\n')

// The part file is what the deterministic assembler reads. No agent is ever asked to
// transcribe another's findings — a previous design did, and destroyed the evidence fields
// of nearly every finding once the run got large.
function partBlock(partPath) {
  return [
    'WRITE YOUR RESULT TO ' + partPath,
    '',
    'Write a single JSON object there with exactly the keys of the structured value you return.',
    'Use the Write tool; if it is blocked, use a Bash heredoc with a quoted delimiter:',
    '',
    "  cat > '" + partPath + "' <<'C_REVIEW_PART_EOF'",
    '  { ...your JSON... }',
    '  C_REVIEW_PART_EOF',
    '',
    'The file is the artifact — a deterministic assembler builds the report from files, not from',
    'what you return. So the two must agree. Write every field of every finding, `description`',
    'above all; a finding that reaches the report without one states a location and no defect.',
    '',
    'IF YOUR STRUCTURED ANSWER IS REJECTED AND YOU SEND IT AGAIN, REWRITE THIS FILE TOO. Writing',
    'the file and then fixing only the retried answer leaves the rejected draft on disk, and every',
    'other check still passes. Make the file match the answer you actually return, last.',
  ].join('\n')
}

function contextBlock(detect) {
  return [
    '<codebase>',
    'Purpose: ' + detect.purpose,
    'Language/platform: is_cpp=' + detect.is_cpp + ', is_posix=' + detect.is_posix + ', is_windows=' + detect.is_windows,
    'Platform evidence: ' + detect.platform_evidence,
    'Entry points for untrusted data:',
    (detect.entry_points || []).map((e) => '  - ' + e).join('\n'),
    'Trust boundaries:',
    (detect.trust_boundaries || []).map((e) => '  - ' + e).join('\n'),
    'Existing hardening:',
    (detect.existing_hardening || []).map((e) => '  - ' + e).join('\n'),
    'Long-lived mutable state structs:',
    (detect.state_structs || []).map((e) => '  - ' + e).join('\n'),
    '</codebase>',
  ].join('\n')
}

function scopeBlock() {
  return [
    '<scope>',
    'Finding scope root: ' + SCOPE + '  (a finding must live inside this subtree)',
    'Context roots: ' + CONTEXT_ROOTS + '  (read these freely to establish callers, build flags and reachability; do not file findings here)',
    'Threat model: ' + THREAT_MODEL,
    '</scope>',
  ].join('\n')
}

function classList(ids) {
  return ids
    .map((id) => {
      const c = CLASSES[id]
      return '### ' + id + ' — ' + c.title + '\n' + c.brief
    })
    .join('\n\n')
}

function detectPrompt(gateableClasses) {
  const cmd =
    'uv run ' + JSON.stringify(SCRIPTS + '/enumerate_units.py') +
    ' --root ' + JSON.stringify(SCOPE) +
    ' --out-dir ' + JSON.stringify(OUTPUT_DIR) +
    ' --max-unit-lines ' + MAX_UNIT_LINES +
    ' --lines-per-agent ' + LINES_PER_AGENT +
    (REVIEW_AGENTS ? ' --agents ' + REVIEW_AGENTS : '')

  return [
    'You are opening a C/C++ codebase for a security review. You have four jobs. Read the build',
    'system and the sources; do not guess.',
    '',
    '1. GENERATE THE UNIT LIST. Run exactly this command:',
    '',
    '     ' + cmd,
    '',
    '   It parses the tree and writes units.json plus one assignment file per reviewer. It exits',
    '   non-zero if it finds no source files or produces no units — if that happens, report',
    '   units_ok=false and put the error text in units_summary rather than working around it. Put',
    '   the "totals" block it prints into units_summary, and the assignment ids into assignment_ids.',
    '',
    '2. PLATFORM AND LANGUAGE, from real API usage rather than from a single include.',
    '',
    '   A portable library commonly carries a compatibility header that includes <windows.h> so that',
    '   one typedef resolves; that is not a Windows codebase, and gating Windows work on it once',
    '   burned 27% of a review on a portable XML parser. Set is_windows only if the code calls Win32',
    '   APIs — processes, handles, registry, services, named pipes, CryptoAPI, Win32 file or path',
    '   functions. Set is_posix only if the code calls POSIX APIs — sockets, fork/exec, signals,',
    '   pthreads, file descriptors, uid/gid. A library that only uses ISO C is neither, and that is a',
    '   valid answer. Set is_cpp only if C++ translation units are compiled; a C library with a C++',
    '   test harness or an extern "C" guard is not C++. Cite a path:line per flag you set true.',
    '',
    '3. THE SHARED STATE STRUCTS. Find the long-lived mutable structs that are threaded through the',
    '   code — the ones a state machine carries across calls, holding sizes, offsets, window',
    '   pointers, flags and mode. These are the subject of a dedicated audit later. Name each with a',
    '   path:line. If the code genuinely has none, return an empty list; do not invent one.',
    '',
    '4. CLASS EVIDENCE. For each bug class below, decide whether the source contains any candidate',
    '   site at all, and cite one path:line if it does. grep is the right tool. This gates a later',
    '   completeness sweep: a class with no candidate site costs an agent that finds nothing, and a',
    '   decompression library has no sockets, signals or regex. Answer honestly in both directions —',
    '   has_candidates=false on a class that IS present hides it from the only pass that would have',
    '   looked for it.',
    '',
    gateableClasses.map((id) => '   - ' + id + ': ' + (CLASSES[id].evidence || CLASSES[id].title)).join('\n'),
    '',
    'Also return the context a reviewer needs: what the code is for, where untrusted data enters',
    '(with path:line), the trust boundaries, and the hardening already in the tree (fuzz targets,',
    'sanitizer configuration, assertions, privilege separation).',
    '',
    'Finally, write your whole structured answer as JSON to ' + OUTPUT_DIR + '/detect.json.',
    '',
    scopeBlock(),
  ].join('\n')
}

function reviewPrompt(assignment, detect) {
  const partPath = PARTS_DIR + '/review-' + assignment.id + '.json'
  return [
    'You are reviewing an assigned slice of a C/C++ codebase for security bugs.',
    '',
    'Read your assignment file first — it is the authoritative statement of what you own:',
    '  ' + assignment.path,
    '',
    'It lists every unit you own — file, line range, name, parameters, the line numbers of every',
    'countable site, and the question ids that unit owes an answer to. Those line numbers came from',
    'a parse, not a model, and a gate diffs your ledger against them.',
    '',
    EVIDENCE_RULE,
    '',
    EXTERNAL_SOURCE_DECLARATION,
    '',
    REVIEW_ESCAPE_HATCH,
    '',
    '## How to work',
    '',
    'Read your units properly — open the file and read around them for the callers, types and',
    'buffers they touch. You have few enough lines to do that. The bugs this finds are the ones that',
    'need a model of what the code is TRYING to do, which skimming for a pattern does not produce.',
    '',
    'For every (unit, question) pair in your assignment, return one ledger row.',
    '',
    '- `sites_accounted` must list every line number from that question\'s site list — all of them, not',
    '  just the ones you filed at. A gate diffs this against the parse. `evidence` says what you found',
    '  at them, including the ones you did not file: "12 write sites, all indexed by `i` bounded at',
    '  411, except 418 which uses `n` from the header — filed" is a real row.',
    '- Verdict `finding` does NOT close the unit or the question. A bug found is a reason to look',
    '  harder here, not to move on: the densest function measured was also the one with the most',
    '  missed bugs.',
    '- `not-applicable` is only honest when the counted population is empty.',
    '- `needs-human` is a legitimate answer and is better than a false clean. Say what you could not',
    '  resolve.',
    '',
    'The questions, and what each is asking:',
    '',
    Object.entries(QUESTION_TEXT).map(([id, text]) => '- **' + id + '** — ' + text).join('\n'),
    '',
    'C semantics are the substance of these questions, not the labels. Integer promotion, signedness',
    'and truncation; what `malloc` does and does not initialise; that a size computed for one buffer',
    'is not a bound for another; that a macro is textual, unscoped and untypechecked so its',
    'assumptions are invisible where it is used; that manual lifetime means every pointer copy',
    'outlives the free unless something stops it.',
    '',
    'One finding per distinct site. `file` must be repo-relative, `line` the vulnerable line, and',
    '`unit_id` the unit it sits in, copied from your assignment file.',
    '',
    severityBlock(),
    '',
    '## bug_class — pick from this list',
    '',
    'The question ids above are NOT bug classes — a run that files under them loses its taxonomy to',
    '`logic-flaw`. Choose the id that names the defect; if none fits, use `logic-flaw` and say so.',
    '',
    Object.keys(CLASSES).map((id) => '- ' + id + ' — ' + CLASSES[id].title).join('\n'),
    '',
    partBlock(partPath),
    '',
    scopeBlock(),
    '',
    contextBlock(detect),
  ].join('\n')
}

function invariantSweepPrompt(structs, detect) {
  const partPath = PARTS_DIR + '/sweep-invariants.json'
  const targets = structs.length
    ? structs.map((s) => '  - ' + s).join('\n')
    : '  - No struct was nominated. Find the module-level mutable state instead: file-scope\n' +
      '    statics, globals, and any struct passed by pointer through more than two functions.\n' +
      '    If there genuinely is none, say so in notes and return no findings rather than\n' +
      '    inventing a target.'

  return [
    'You are auditing invariants on the fields of the long-lived mutable state in a C/C++',
    'codebase. Your targets:',
    '',
    targets,
    '',
    'THIS IS THE FRONTIER. In the measured corpus, five bugs no partition reliably reached wore five',
    'different class labels — out-of-bounds write, unsigned integer overflow, uninitialised use, a',
    'broken encoding invariant, and a double free — and were ONE mechanism: a rule on a field of the',
    'shared state struct that one path breaks. Classes already existed for the symptoms of two of',
    'them and still did not catch them, because a label you grep for finds sites, and this needs a',
    'proof across sites.',
    '',
    'The task is concrete and enumerable, so do it exhaustively rather than by sampling:',
    '',
    '1. List every field. Include the ones that look boring.',
    '2. State each field\'s invariant in one sentence — the rule the rest of the code assumes.',
    '   "wnext is an offset strictly inside the window, so wnext < wsize." "size is non-zero exactly',
    '   when the i/o buffers are allocated." A field whose rule you cannot state is a finding waiting',
    '   to happen; give it a needs-human row.',
    '3. Find EVERY writer and EVERY reader. grep the field name across the tree. Do not stop at the',
    '   obvious function.',
    '4. Prove the invariant holds at each writer, and that each reader is entitled to assume it. The',
    '   paths that break it are: reset and re-init paths that clear some fields and not others, error',
    '   paths that return before restoring a field, allocation paths where the field says "allocated"',
    '   before the allocation succeeded, and free paths that release the memory without clearing the',
    '   field that says it exists. `malloc` does not zero, so a field holds whatever the previous',
    '   owner of that memory left there until someone writes it.',
    '5. Where the invariant can be broken, that is a finding. Class it `state-field-invariant` unless',
    '   a more specific class describes the consequence better, and name the field and the path.',
    '',
    'Emit a ledger row per field you audited: `unit_id` is the struct-qualified field name, e.g.',
    '`state.wnext`; `question` is `state-field-invariant`; `sites_accounted` is the writer and reader',
    'lines you checked; `evidence` is the invariant and where it holds or breaks. These rows sit',
    'outside the generated unit list, so the coverage gate records them without requiring them.',
    '',
    EVIDENCE_RULE,
    '',
    EXTERNAL_SOURCE_DECLARATION,
    '',
    ESCAPE_HATCH,
    '',
    severityBlock(),
    '',
    partBlock(partPath),
    '',
    scopeBlock(),
    '',
    contextBlock(detect),
  ].join('\n')
}
function classSweepPrompt(groups, detect, evidenceById) {
  const partPath = PARTS_DIR + '/sweep-classes.json'
  const classIds = groups.flatMap((g) => g.classIds)
  return [
    'You are running a completeness sweep across the WHOLE codebase. This is not the main review —',
    'that partitioned the tree by location and has already read every line. You are here for the',
    'classes below, each of which has NO entry anywhere in the review output and each of which the',
    'detect phase could cite a real candidate site for.',
    '',
    'Grouped for reading, not for scoping — all of them are yours:',
    '',
    groups.map((g) => '  ' + g.group.title + ': ' + g.classIds.join(', ')).join('\n'),
    '',
    'This pass earns its keep on scattered single-site slips — a missing free on one error path, a',
    '(void) cast hiding an unchecked return, one clamp done at the wrong width, one state that',
    'returns success where it should return "need more input". Those are exactly the bugs a reader',
    'working through a region in order tends to walk past, and in the measurement they were found by',
    'a class sweep and by nothing else. Three of the four lived in cold error-handling paths.',
    '',
    'Cited candidate sites from the detect phase:',
    '',
    classIds.map((id) => '  - ' + id + ': ' + (evidenceById.get(id) || 'no citation recorded')).join('\n'),
    '',
    '## Your classes',
    '',
    classList(classIds),
    '',
    '## How to work',
    '',
    'Enumerate the population for each class before you judge it — every call site, every recursive',
    'construct, every error path — and then account for all of it. Filing one finding closes that',
    'finding, not the class. Writing "reported" over an uncountable population ("all constructs',
    'reachable from untrusted input") on the strength of one instance is how a second bug in the same',
    'class goes unlooked-at; that happened, and the missed one was a real CVE.',
    '',
    'Work the classes in the order given and stop cleanly if you run short — a class you did not',
    'reach with an honest not-searched row is worth more than nine skimmed ones.',
    '',
    'Return one ledger row per class: `unit_id` is the literal string `(sweep)`, `question` is the',
    'class id, `sites_accounted` is empty (your population is not from the unit parse), and',
    '`evidence` is the population you enumerated and what you found across it.',
    '',
    EVIDENCE_RULE,
    '',
    EXTERNAL_SOURCE_DECLARATION,
    '',
    CLASS_SWEEP_ESCAPE_HATCH,
    '',
    severityBlock(),
    '',
    partBlock(partPath),
    '',
    scopeBlock(),
    '',
    contextBlock(detect),
  ].join('\n')
}

const DEDUP_RULES = [
  'Merge only when the findings point at one call expression, one statement, or one small block —',
  'the same sink token, normally within about five lines, or the cause and consequence sites of one',
  'data-flow chain. Different constructs in one function are different bugs even when the impact',
  'overlaps and even when one class is a more general name for the other. Two findings fixed by the',
  'same edit are related, not duplicate.',
  '',
  'Merging across bug classes is allowed here, and only here, when the disagreement is about what to',
  'call one defect. You must be able to say in one phrase why both labels name the same bug.',
  '',
  'Expect few merges: reviewers had disjoint slices, so cross-reviewer duplication is near zero by',
  'construction. When in doubt, do not merge — a wrong merge silently drops a real bug, a wrong',
  'split costs one paragraph.',
].join('\n')

function dedupPrompt(buckets) {
  const partPath = PARTS_DIR + '/dedup-agent.json'
  // Every finding carries its group index in the payload. The workflow discards a merge
  // whose members are not all from one group, and so does nothing downstream — the group
  // is in front of the agent so the constraint is checkable rather than merely stated.
  const groups = buckets.map((bucket, i) => bucket.map((f) => Object.assign({ group: i }, f)))
  return [
    'Independent reviewers collided in ' + buckets.length + ' place(s). Decide, WITHIN each group',
    'separately, which findings describe the same defect and should be merged.',
    '',
    DEDUP_RULES,
    '',
    'Never merge across two groups. Every key in one merge must carry the same `group` value, and',
    'any merge that does not is discarded.',
    '',
    'Groups (JSON):',
    JSON.stringify(groups, null, 2),
    '',
    'Return every merge you are confident in, across all groups, in one merges array. `primary` is',
    'the key that survives; prefer the higher confidence, then the lexicographically smallest key.',
    'Return an empty merges array if none apply — that is a normal outcome here, not a failure.',
    '',
    'WRITE YOUR RESULT TO ' + partPath,
    '',
    'Before you return, write a single JSON object to that path shaped exactly like the value you',
    'return: {"part_id": "dedup-agent", "merges": [ ... ]}. Use the Write tool; if the harness blocks',
    'it, use a Bash heredoc with a quoted delimiter. The final report is assembled from the part',
    'files, so a merge that is only in your reply and not in the file does not happen.',
  ].join('\n')
}

// Several collisions in one file go to one agent. The buckets stay separate in the
// prompt and a merge that crosses two of them is discarded in code, so batching
// cannot merge unrelated findings — it only saves the agent that would otherwise
// re-read the same file for each bucket.
const SEVERITY_TABLES = [
  '### REMOTE',
  '',
  '- CRITICAL — remote code execution, authentication bypass, remotely reachable memory corruption with reliable exploitation',
  '- HIGH — reliable remote denial of service, disclosure of sensitive data, SSRF into internal services',
  '- MEDIUM — difficult remote denial of service, limited information disclosure, bugs needing unusual network conditions',
  '- LOW — theoretical issues, defense-in-depth gaps, remotely reachable issues with negligible impact',
  '',
  '### LOCAL_UNPRIVILEGED',
  '',
  '- CRITICAL — privilege escalation to root, sandbox or container escape',
  '- HIGH — access to other users data, arbitrary file read or write as a privileged user',
  '- MEDIUM — local denial of service, system data disclosure, limited privilege-boundary crossing',
  '- LOW — a privilege-boundary crossing with minimal impact',
  '',
  '### BOTH',
  '',
  'Score remote-triggerable bugs against the remote table and local-only bugs against the local table.',
  'If a bug is triggerable either way, take the higher severity.',
  '',
  '### Adjustments',
  '',
  '- A mitigation that is present and effective at this site: reduce one level. A mitigation that is a known bypass target (ASLR, canaries): no change.',
  '- Requires winning a race, or requires a non-default configuration: reduce one level.',
  '- Affects authentication or cryptography, or sits on a widely reachable entry point: raise one level.',
].join('\n')

// Severity is assigned by whoever found the bug. There is no judge downstream to
// re-derive it, so the tables have to travel with the reviewer rather than sitting in
// a separate agent's prompt. The scoping rules come with them: a finding the threat
// model puts out of scope should not be filed at all, which is where roughly half of
// the deleted judge's rejections went.
function severityBlock() {
  return [
    '## Severity — you assign it, nobody re-checks it',
    '',
    'There is no separate judge in this pipeline. The severity you write is the severity the user',
    'reads, so spend a moment on it. Severity is relative to the threat model, not absolute.',
    '',
    SEVERITY_TABLES,
    '',
    '### Scope — do not file what this threat model excludes',
    '',
    'Under REMOTE, a bug only triggerable through local configuration, CLI arguments, environment or',
    'an existing shell is out of scope: do not file it. Under LOCAL_UNPRIVILEGED, a bug that crosses',
    'no privilege boundary is out of scope, and so is one that requires root. If it is close to the',
    'line, file it and say so in the impact — a borderline finding a reader can dismiss is cheaper',
    'than a real bug nobody looked at.',
    '',
    'A finding whose impact is hardening rather than exploitation — a banned API with no',
    'attacker-controlled data reaching it, a missing compiler flag — is worth reporting at LOW. Say',
    'plainly in the impact that it is a hardening gap, so it is not read as an exploitable bug.',
  ].join('\n')
}
function assemblePrompt(expected, complete, groupsAttempted, groupsFailed, failures) {
  const parts = [
    'uv run ' + JSON.stringify(SCRIPTS + '/assemble_findings.py'),
    '--run-dir ' + JSON.stringify(OUTPUT_DIR),
    '--threat-model ' + JSON.stringify(THREAT_MODEL),
    '--severity-filter ' + JSON.stringify(SEVERITY_FILTER),
    '--scope ' + JSON.stringify(SCOPE),
    '--context-roots ' + JSON.stringify(CONTEXT_ROOTS),
    '--worker-model ' + JSON.stringify(WORKER_MODEL || 'inherit'),
    '--groups-attempted ' + JSON.stringify(groupsAttempted.join(',')),
    '--groups-failed ' + JSON.stringify(groupsFailed.join(',')),
    '--no-judge',
  ]
  for (const e of expected) parts.push('--expect ' + JSON.stringify(e))
  for (const c of complete) parts.push('--expect-complete ' + JSON.stringify(c))
  for (const f of failures) parts.push('--agent-failure ' + JSON.stringify(f))

  return [
    'Mechanical step. Run exactly this command and report its result. Do not analyse the content, do',
    'not edit any file, and do not write any artifact yourself.',
    '',
    '  ' + parts.join(' \\\n    '),
    '',
    'It reads the part files each agent wrote, assembles findings.json deterministically, and',
    'generates REPORT.md and REPORT.sarif from it. It exits non-zero and prints the reason if a part',
    'file is missing, unreadable, or if there are no part files at all.',
    '',
    'If it fails, return ok=false with the stderr text in `error`. Do not hand-write the outputs and',
    'do not retry with different arguments — a previous design had an agent transcribe this document',
    'by hand and it silently summarised 86 findings down to 23 with every evidence field stripped.',
    '',
    'It also runs the coverage gate in-process and writes ledger-gate.json, so there is no separate',
    'gate step. On success, copy the counts from the JSON it printed into the matching fields,',
    'including checks_required, checks_completed and checks_satisfied.',
  ].join('\n')
}

// ---------------------------------------------------------------- plain logic

const QUESTION_TEXT = {
  bounds:
    'Spatial safety at every write: what bounds each destination, and can the index or length reach past it? The high-yield shape is a size computed for one buffer and applied to another.',
  integer:
    'Width, signedness and wrap at every conversion and at every arithmetic expression that becomes a size or an index. Unsigned subtraction that can go below zero is the quiet one — it wraps to a value that passes every upper-bound check.',
  'alloc-lifetime':
    'Allocation and release pairing: single owner, freed once, never used after, no surviving copy of a reallocated pointer, and released on every error path.',
  'sizeof-arith':
    'Every sizeof in a size computation: is it the pointee rather than the pointer, and can the surrounding arithmetic overflow before it reaches the allocator?',
  'nul-termination':
    'Every string produced or consumed here: NUL-terminated on every path, and is byte length being confused with character length?',
  'return-values':
    'Every call whose failure matters: is the result checked, and against the convention that function actually uses? A negative return assigned into an unsigned type makes the check that follows unreachable.',
  'caller-contract':
    'What this unit assumes its caller guarantees about each parameter, and whether every caller actually guarantees it. Check the callers; do not assume.',
  'banned-api':
    'Each banned or deprecated API here: name the source of the data and the size that reaches it, and what validates between them. A bounded internal constant reaching one is a hardening note, not a vulnerability — say which.',
  'macro-contract':
    'Each function-like macro: what it assumes of its arguments, and whether that is enforced at every expansion site. A macro is textual, unscoped and untypechecked, so an invariant it relies on is invisible where it is used and can hold at four call sites and not the fifth.',
}

function selectGroups(detect) {
  const selected = []
  for (const group of GROUPS) {
    if (group.gate === 'is_cpp' && !detect.is_cpp) continue
    if (group.gate === 'is_windows' && !detect.is_windows) continue
    const classIds = group.classes.filter((id) => {
      const c = CLASSES[id]
      if (c.posix && !detect.is_posix) return false
      if (c.skipRemote && THREAT_MODEL === 'REMOTE') return false
      return true
    })
    if (classIds.length) selected.push({ group: group, classIds: classIds })
  }
  return selected
}

function normalizePath(p) {
  let s = String(p == null ? '' : p).replace(/\\/g, '/').trim()
  const link = s.match(/^\[([^\]]+)\]\([^)]*\)$/)
  if (link) s = link[1]
  while (s.startsWith('./')) s = s.slice(2)
  while (s.indexOf('//') !== -1) s = s.replace('//', '/')
  return s
}

const CONFIDENCE_RANK = { High: 3, Medium: 2, Low: 1 }

// The key is the finding's identity for the whole run: <part id>#<index in that
// part's findings array>. The assembler recomputes it from the same part file, so
// dedup and judge decisions land on the right finding without either side needing
// the other's numbering. Public ids (BOF-001) are assigned by the assembler alone.
function normalizeFinding(raw, partId, index) {
  const bugClass = CLASSES[raw.bug_class] ? raw.bug_class : 'logic-flaw'
  return {
    key: partId + '#' + index,
    bug_class: bugClass,
    reported_bug_class: String(raw.bug_class || ''),
    title: String(raw.title || 'untitled'),
    file: normalizePath(raw.file),
    line: Number.isFinite(raw.line) && raw.line > 0 ? Math.floor(raw.line) : 1,
    function: String(raw.function || '(file-level)').trim(),
    unit_id: String(raw.unit_id || ''),
    confidence: CONFIDENCE_RANK[raw.confidence] ? raw.confidence : 'Medium',
    description: String(raw.description || ''),
    code: String(raw.code || ''),
    data_flow: String(raw.data_flow || ''),
    reachability: String(raw.reachability || ''),
    impact: String(raw.impact || ''),
    mitigations_checked: String(raw.mitigations_checked || ''),
    recommendation: String(raw.recommendation || ''),
    outside_assigned_classes: raw.outside_assigned_classes === true,
    found_by: partId,
  }
}

function pickPrimary(a, b) {
  const ra = CONFIDENCE_RANK[a.confidence] || 2
  const rb = CONFIDENCE_RANK[b.confidence] || 2
  if (ra !== rb) return ra > rb ? a : b
  return a.key <= b.key ? a : b
}

// Tier 1: identical (file, line, bug_class) is a duplicate by construction, and
// needs no agent. The assembler applies the same rule to the part files, so this
// exists only to keep those pairs out of the dedup agents' buckets.
function tier1(findings) {
  const buckets = new Map()
  for (const f of findings) {
    const key = f.file + ':' + f.line + ':' + f.bug_class
    if (!buckets.has(key)) buckets.set(key, [])
    buckets.get(key).push(f)
  }
  const mergedInto = new Map()
  for (const members of buckets.values()) {
    if (members.length < 2) continue
    let primary = members[0]
    for (const m of members.slice(1)) primary = pickPrimary(primary, m)
    for (const m of members) if (m.key !== primary.key) mergedInto.set(m.key, primary.key)
  }
  return mergedInto
}

// Prose that appears in almost every data_flow description. Without these the
// comparison measures how similarly two reviewers write English rather than whether
// they are describing one chain.
// Tier 1.5, mirroring `assemble_findings.py`. Two findings in one function within
// three lines are the same bug described twice, including across bug classes — the
// case tier 1's exact (file, line, class) match cannot see. Doing it here as well as
// in the assembler is not redundancy: the assembler owns the artifact, and this copy
// is what keeps these pairs out of the dedup agent's prompt. Both sides use the same
// rule and the same window, and the assembler's tests pin it.
function autoMergeNearby(findings, mergedInto) {
  const live = findings.filter((f) => !mergedInto.has(f.key))
  const byFn = new Map()
  for (const f of live) {
    const fn = normFunction(f.function)
    if (!fn) continue
    const key = f.file + '::' + fn
    if (!byFn.has(key)) byFn.set(key, [])
    byFn.get(key).push(f)
  }
  let merged = 0
  for (const members of byFn.values()) {
    members.sort((a, b) => a.line - b.line || (a.key < b.key ? -1 : 1))
    for (let i = 0; i < members.length; i++) {
      for (let j = i + 1; j < members.length; j++) {
        const a = members[i]
        const b = members[j]
        const gap = Math.abs(a.line - b.line)
        if (gap > NEARBY_LINES) break
        // Mirrors CROSS_CLASS_NEARBY_LINES in assemble_findings.py. If this side merged a
        // cross-class pair the assembler now leaves alone, the pair would be dropped from
        // the dedup agent's prompt as "already handled" and then never merged by anyone —
        // the two rules have to agree or a pair falls between them.
        if (gap > CROSS_CLASS_NEARBY_LINES && a.bug_class !== b.bug_class) continue
        if (mergedInto.has(a.key) || mergedInto.has(b.key)) continue
        const primary = pickPrimary(a, b)
        const dup = primary.key === a.key ? b : a
        mergedInto.set(dup.key, primary.key)
        merged++
      }
    }
  }
  return merged
}

const FLOW_STOPWORDS = new Set([
  'the', 'and', 'from', 'into', 'with', 'this', 'that', 'then', 'than', 'when', 'where',
  'which', 'value', 'values', 'data', 'input', 'source', 'sink', 'size', 'length', 'len',
  'buffer', 'buf', 'pointer', 'ptr', 'user', 'attacker', 'controlled', 'validation',
  'validated', 'check', 'checked', 'none', 'null', 'call', 'caller', 'function', 'via',
  'passed', 'reaches', 'reach', 'between', 'them', 'for', 'not', 'are', 'its', 'it',
  'chain', 'flow', 'unchecked', 'bound', 'bounds', 'bounded', 'field', 'struct', 'line',
  'lines', 'code', 'file', 'path', 'unit', 'review', 'here', 'there', 'both', 'each',
  'reachable', 'reachability', 'entry', 'point', 'write', 'read', 'copy', 'copied',
])

// Identifier-ish tokens out of a data_flow description. Case-folded, because one
// reviewer writes `state->wnext` and another writes `wnext`.
function flowTokens(text) {
  const out = new Set()
  for (const raw of String(text || '').split(/[^A-Za-z0-9_]+/)) {
    const t = raw.toLowerCase()
    if (t.length < 3 || FLOW_STOPWORDS.has(t) || /^\d+$/.test(t)) continue
    out.add(t)
  }
  return out
}

// Deliberately hard to trigger. Two findings describing one chain name the same
// specific identifiers — the variable, the field, the callee — so a genuine match has
// several distinctive tokens in common. A loose threshold instead measures prose
// similarity: at three tokens and 34% overlap, two unrelated findings fifty lines
// apart bucketed together purely because both descriptions were short. Every false
// collision costs a dedup agent, and the phase is supposed to be near-empty under a
// location partition.
function flowsIntersect(a, b) {
  const ta = flowTokens(a.data_flow)
  const tb = flowTokens(b.data_flow)
  if (ta.size < 4 || tb.size < 4) return false
  let shared = 0
  for (const t of ta) if (tb.has(t)) shared++
  if (shared < 3) return false
  return shared / Math.min(ta.size, tb.size) >= 0.5
}

const NO_FUNCTION = new Set(['', '-', 'none', 'n/a', 'na', 'file-level', '(file-level)', 'filelevel', 'file level'])

function normFunction(name) {
  const fn = String(name || '').toLowerCase().replace(/[()]/g, '').replace(/[-_\s]+/g, ' ').trim()
  return NO_FUNCTION.has(fn) ? '' : fn
}

// Under a location partition, "same file" is far too coarse: one file may be one
// reviewer's entire slice. Two findings collide when they are in the same file AND
// point at the same construct — the same function, lines within a short window, or
// two descriptions of one data-flow chain (its cause site and its consequence site,
// which is the duplication that actually survives this pipeline).
function collisionBuckets(findings, mergedInto) {
  const live = findings.filter((f) => !mergedInto.has(f.key))
  const byFile = new Map()
  for (const f of live) {
    if (!byFile.has(f.file)) byFile.set(f.file, [])
    byFile.get(f.file).push(f)
  }

  const buckets = []
  for (const members of byFile.values()) {
    members.sort((a, b) => a.line - b.line || (a.key < b.key ? -1 : 1))
    const parent = new Map(members.map((f) => [f.key, f.key]))
    const find = (k) => {
      while (parent.get(k) !== k) {
        parent.set(k, parent.get(parent.get(k)))
        k = parent.get(k)
      }
      return k
    }
    const union = (a, b) => {
      const ra = find(a)
      const rb = find(b)
      if (ra !== rb) parent.set(ra, rb)
    }
    for (let i = 0; i < members.length; i++) {
      for (let j = i + 1; j < members.length; j++) {
        const a = members[i]
        const b = members[j]
        const sameFn = normFunction(a.function) && normFunction(a.function) === normFunction(b.function)
        const nearby = Math.abs(a.line - b.line) <= 8
        if (sameFn || nearby || flowsIntersect(a, b)) union(a.key, b.key)
      }
    }
    const groups = new Map()
    for (const f of members) {
      const root = find(f.key)
      if (!groups.has(root)) groups.set(root, [])
      groups.get(root).push(f)
    }
    for (const g of groups.values()) if (g.length > 1) buckets.push(g)
  }
  return buckets
}

// ---------------------------------------------------------------------- run

const partsExpected = []
const partsComplete = []
const agentFailures = []

// One command creates every directory the agents write into, so no agent has to
// think about mkdir and no write fails on a missing parent.
phase('Detect')
const gateableClasses = Object.keys(CLASSES).filter((id) => CLASSES[id].evidence)
const detect = await agent(
  'First run this, exactly, and report nothing about it unless it fails:\n\n  mkdir -p ' +
    JSON.stringify(PARTS_DIR) + '\n\nThen do the following.\n\n' + detectPrompt(gateableClasses),
  workerOpts({ label: 'detect', phase: 'Detect', schema: DETECT_SCHEMA })
)
if (!detect) {
  throw new Error('c-review: detection agent returned nothing; there is no unit list to review')
}
if (!detect.units_ok) {
  throw new Error(
    'c-review: enumerate_units.py did not produce a unit list, so there is nothing to partition. ' +
      'It reported: ' + String(detect.units_summary || '(no detail)')
  )
}
log(
  'platform: is_cpp=' + detect.is_cpp + ' is_posix=' + detect.is_posix + ' is_windows=' + detect.is_windows
)
log('units: ' + String(detect.units_summary || '').replace(/\s+/g, ' ').slice(0, 300))

const assignmentIds = (detect.assignment_ids || []).map(String).filter(Boolean)
if (!assignmentIds.length) {
  throw new Error(
    'c-review: the detect agent produced no assignment ids. units.json exists but nothing can be ' +
      'dispatched against it; re-run rather than reviewing an unpartitioned tree.'
  )
}
const assignments = assignmentIds.map((id) => ({
  id: id,
  path: OUTPUT_DIR + '/assignments/' + id + '.json',
  // Deliberately nothing else. The unit count, line total and file list live in the
  // assignment file, which the workflow cannot read; a previous version carried them
  // as zero-valued "display hints" and every review prompt opened with the literal
  // "Your slice is 0 unit(s), 0 line(s), in: ." The run only survived it because the
  // prompt also says to read the assignment file first.
}))

const evidenceById = new Map()
for (const e of detect.class_evidence || []) {
  if (e && e.bug_class && e.has_candidates) evidenceById.set(String(e.bug_class), String(e.citation || ''))
}
const selected = selectGroups(detect)
log(
  assignments.length + ' review assignment(s); ' + selected.length + ' live group(s); ' +
    evidenceById.size + ' class(es) with a cited candidate site'
)

// ------------------------------------------------------------------- review
//
// The barrier is deliberate. Every later phase is a function of the whole ledger:
// the gate diffs it, the second pass is dispatched from it, and the sweep is chosen
// by what has no entry in it. Pipelining here would mean dispatching a second pass
// before knowing whether another reviewer already covered the unit.

phase('Review')
const reviewResults = await parallel(
  assignments.map((a) => () =>
    agent(
      reviewPrompt(a, detect),
      workerOpts({ label: 'review:' + a.id, phase: 'Review', schema: REVIEW_SCHEMA })
    ).then((r) => ({ partId: 'review-' + a.id, result: r }))
  )
)

// -------------------------------------------------------------------- sweep
//
// The class axis, in two agents. It is not the partition — location is — but it is
// not decoration either: in the measurement it was the only thing that found four
// bugs, a missing free on an open() failure path, a (void) cast hiding an unchecked
// return, a 64-bit clamp done at the wrong width, and a state returning success
// where it should have asked for more input. Three of the four are in cold error
// paths, which is exactly the ground a reader working a region in order walks past.

phase('Sweep')
const classesWithFindings = new Set()
for (const entry of reviewResults) {
  if (!entry || !entry.result) continue
  for (const f of entry.result.findings || []) classesWithFindings.add(String(f.bug_class || ''))
}

// Every silent class with a cited candidate site goes to ONE agent, grouped for
// readability rather than split across agents. v3 spent up to three agents here and
// still capped, which meant reporting a cap AND paying for the fan-out.
const silentByGroup = []
for (const sel of selected) {
  const silent = sel.classIds.filter((id) => !classesWithFindings.has(id) && evidenceById.has(id))
  if (silent.length) silentByGroup.push({ group: sel.group, classIds: silent })
}

// The invariant audit is OFF by default: where it has been measured it cost ~9% of the run
// for no credited hit. It is kept rather than deleted because the shared-state-struct bugs
// it targets have never been measured on a valid cell — unknown, not disproven. Turn it on
// for state-machine-heavy targets.
const INVARIANT_AUDIT = ARGS.invariantAudit === true

const sweepThunks = []
if (silentByGroup.length) {
  const total = silentByGroup.reduce((n, g) => n + g.classIds.length, 0)
  log(
    'class sweep: ' + total + ' silent class(es) with a cited candidate site across ' +
      silentByGroup.length + ' group(s)'
  )
  sweepThunks.push(() =>
    agent(
      classSweepPrompt(silentByGroup, detect, evidenceById),
      workerOpts({ label: 'sweep:classes', phase: 'Sweep', schema: REVIEW_SCHEMA })
    ).then((r) => ({ partId: 'sweep-classes', result: r }))
  )
} else if (!evidenceById.size) {
  // These two are very different coverage stories and must not share a message: one
  // says the sweep had nothing left to do, the other says the gate that feeds it
  // never fired, so no class sweep happened at all.
  log(
    'WARNING: the detect phase cited no candidate site for any gateable class, so no ' +
      'class sweep ran. Expected on a small ISO-C target, suspicious on anything larger.'
  )
} else {
  log('every live class with a cited candidate site already has an entry; class sweep skipped')
}

const structs = (detect.state_structs || []).map(String).filter(Boolean)
if (INVARIANT_AUDIT) {
  sweepThunks.push(() =>
    agent(
      invariantSweepPrompt(structs, detect),
      workerOpts({ label: 'sweep:invariants', phase: 'Sweep', schema: REVIEW_SCHEMA, effort: 'high' })
    ).then((r) => ({ partId: 'sweep-invariants', result: r }))
  )
  log(
    'invariant audit over ' +
      (structs.length ? structs.length + ' nominated struct(s)' : 'module-level state')
  )
} else if (structs.length) {
  log(
    'invariant audit NOT run (pass invariantAudit: true to enable). ' + structs.length +
      ' state struct(s) were nominated and their field invariants are unaudited: ' +
      structs.join(' | ')
  )
}

const sweepResults = await parallel(sweepThunks)
// ---------------------------------------------------- collect the producers

const producers = [...reviewResults, ...sweepResults]
const rawFindings = []
const notes = []
for (const entry of producers) {
  if (!entry) continue
  if (!entry.result) {
    agentFailures.push(entry.partId + ': returned nothing')
    log('WARNING: ' + entry.partId + ' returned nothing; its units and classes are UNCOVERED')
    continue
  }
  const findings = entry.result.findings || []
  findings.forEach((f, i) => rawFindings.push(normalizeFinding(f, entry.partId, i)))
  if (entry.result.part_written === false) {
    agentFailures.push(entry.partId + ': did not write its part file')
    log(
      'WARNING: ' + entry.partId + ' says it did not write its part file. Its ' + findings.length +
        ' finding(s) will be missing from the artifacts; the assembler will fail on the expectation.'
    )
  }
  partsExpected.push(entry.partId + '=' + findings.length)
  // The workflow's copy of these findings came back through the schema, so it is complete
  // by construction. Tell the assembler that, and it can tell a part file that is merely
  // thin (the agent genuinely had nothing to say) from one that is STALE — written before
  // a rejected structured answer was retried, and never rewritten. Measured on the
  // 2026-08-07 container cell: the sweep agent's file held 7 findings with no
  // `description` while its accepted return carried all 7.
  if (findings.length && findings.every((f) => REQUIRED_PART_FIELDS.every((k) => f && f[k]))) {
    partsComplete.push(entry.partId)
  }
  if (entry.result.notes) notes.push(entry.partId + ': ' + entry.result.notes)
}

const byKey = new Map(rawFindings.map((f) => [f.key, f]))
log(rawFindings.length + ' raw finding(s) from ' + producers.filter((e) => e && e.result).length + ' agent(s)')

// -------------------------------------------------------------------- dedup
//
// Deterministic first, agent only for what is left. `assemble_findings.py` merges
// identical (file, line, class) and same-function-within-three-lines pairs on its
// own, without an agent and without a prompt. What reaches an agent is the residue:
// pairs that collide on a data-flow chain or a nearby line but are not obviously one
// construct. Under a location partition that residue is usually empty, so this phase
// most often costs nothing at all.

phase('Dedup')
const mergedInto = tier1(rawFindings)
const autoMerged = autoMergeNearby(rawFindings, mergedInto)
const buckets = collisionBuckets(rawFindings, mergedInto)
// bucketOf keeps the single agent honest: a merge whose two members never collided
// is discarded, so holding every bucket at once cannot invent a cross-bucket merge.
const bucketOf = new Map()
for (let b = 0; b < buckets.length; b++) {
  for (const f of buckets[b]) bucketOf.set(f.key, b)
}

let dedupAgents = 0
if (buckets.length) {
  const pairs = buckets.reduce((n, b) => n + b.length, 0)
  let sent = buckets
  if (pairs > DEDUP_MAX_PAIRS) {
    // One agent is the budget, so the cap is on what fits in its prompt rather than
    // on how many agents run. Say what was dropped: unmerged duplicates are visible
    // in the report as two findings, which is the safe direction, but it is still a
    // thing the reader should know happened.
    let running = 0
    sent = buckets.filter((b) => (running += b.length) <= DEDUP_MAX_PAIRS)
    log(
      'CAP: ' + pairs + ' colliding finding(s) exceed the ' + DEDUP_MAX_PAIRS + '-finding dedup ' +
        'prompt budget; ' + (pairs - sent.reduce((n, b) => n + b.length, 0)) + ' left unmerged ' +
        'and reported separately'
    )
  }
  // A single bucket bigger than the whole budget leaves nothing to send. Splitting it
  // would hide the very pair that formed it, so it is dropped wholesale — but dropping
  // it must not also cost an agent that is then handed an empty group list.
  if (!sent.length) {
    log('dedup agent skipped: every collision group exceeded the prompt budget on its own')
  } else {
    dedupAgents = 1
    log(
      sent.length + ' collision group(s) to one agent, ' + autoMerged +
        ' pair(s) already merged deterministically'
    )
    const res = await agent(
      dedupPrompt(sent),
      workerOpts({ label: 'dedup', phase: 'Dedup', schema: DEDUP_SCHEMA, effort: 'low' })
    )
    for (const merge of (res && res.merges) || []) {
      if (!byKey.has(merge.primary) || mergedInto.has(merge.primary)) continue
      for (const dup of merge.duplicates || []) {
        if (dup === merge.primary || !byKey.has(dup) || mergedInto.has(dup)) continue
        if (bucketOf.get(dup) !== bucketOf.get(merge.primary)) {
          log('rejected cross-bucket merge ' + dup + ' -> ' + merge.primary)
          continue
        }
        mergedInto.set(dup, merge.primary)
      }
    }
  }
} else {
  log(
    'no collisions beyond the ' + autoMerged + ' pair(s) merged deterministically; dedup agent skipped'
  )
}

const primaries = rawFindings.filter((f) => !mergedInto.has(f.key))
log(primaries.length + ' primaries after dedup (' + mergedInto.size + ' merged)')
// ----------------------------------------------------------------- assemble

phase('Assemble')
const groupsAttempted = selected.map((s) => s.group.id)
const groupsFailed = producers.filter((e) => e && !e.result).map((e) => e.partId)
const assembled = await agent(
  assemblePrompt(partsExpected, partsComplete, groupsAttempted, groupsFailed, agentFailures),
  workerOpts({ label: 'assemble', phase: 'Assemble', schema: ASSEMBLE_SCHEMA, effort: 'low' })
)
if (!assembled || !assembled.ok) {
  log(
    'WARNING: artifacts were not written: ' +
      ((assembled && assembled.error) || 'assemble agent returned nothing') +
      '. The part files are intact under ' + PARTS_DIR + '; re-run assemble_findings.py by hand.'
  )
}

return {
  outputDir: OUTPUT_DIR,
  artifactsWritten: !!(assembled && assembled.ok),
  artifactError: assembled && assembled.ok ? null : (assembled && assembled.error) || 'assemble agent returned nothing',
  findingsJson: OUTPUT_DIR + '/findings.json',
  reportMd: OUTPUT_DIR + '/REPORT.md',
  reportSarif: OUTPUT_DIR + '/REPORT.sarif',
  unitsJson: OUTPUT_DIR + '/units.json',
  ledgerGateJson: OUTPUT_DIR + '/ledger-gate.json',
  // No judge ran. Severity on every finding is the reviewer's own and nothing
  // rejected anything, so the skill has to say so next to the findings.
  judgeRan: false,
  stats: {
    agents_total: 1 + assignments.length + sweepThunks.length + dedupAgents + 1,
    review_agents: assignments.length,
    sweep_agents: sweepThunks.length,
    dedup_agents: dedupAgents,
    auto_merged: autoMerged,
    raw_findings: rawFindings.length,
    merged: mergedInto.size,
    primaries: primaries.length,
    reported: assembled && Number.isFinite(assembled.reported) ? assembled.reported : null,
  },
  // Populated by the assembler, which now runs the ledger gate in-process; read
  // ledger-gate.json for the per-row detail.
  // `satisfied` is the honest number: a row the gate rejected was answered but is not
  // coverage. Reporting only `completed` is how a run with live violations printed 100%.
  coverage: assembled && assembled.checks_required
    ? {
        checksRequired: assembled.checks_required,
        checksCompleted: assembled.checks_completed,
        checksSatisfied: Number.isFinite(assembled.checks_satisfied) ? assembled.checks_satisfied : null,
      }
    : null,
  groupsAttempted: groupsAttempted,
  groupsFailed: groupsFailed,
  agentFailures: agentFailures,
  notes: notes,
  silentClasses: silentByGroup.flatMap((g) => g.classIds),
}
