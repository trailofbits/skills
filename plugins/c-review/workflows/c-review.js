export const meta = {
  // NOT 'c-review': the skill is already `/c-review:c-review`, and a workflow with the
  // same meta.name claims the identical command — whichever loses resolution becomes
  // unreachable, and the workflow run bare has no args and throws. SKILL.md dispatches
  // this file by scriptPath, so the name here is only the marketplace command.
  name: 'audit',
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
// Design, in three rules (measured in the internal c-review benchmark harness,
// which does not ship with this plugin):
//
//   1. LOCATION is the partition. Every line has exactly one owner, generated
//      from a parse. The bug-class catalogue is a bounded completeness sweep
//      over classes nothing reported, never the fan-out.
//   2. No agent ever transcribes another agent's work. Each writes only its own
//      part file; a deterministic assembler joins them.
//   3. No false-positive judge. Severity is the reviewer's own, and the report
//      must say so next to the findings.
//
// File layout: inputs -> catalog -> schemas -> prompts -> utilities -> phase
// functions -> main. The main algorithm is the top-level code at the bottom.
// ============================================================================

// -------------------------------------------------------------------- inputs
//
// Every wrong shape throws a named error instead of defaulting or coercing: a
// silently defaulted argument changes what a measured run measures. The one
// leniency is `args` arriving JSON-encoded a second time — the caller is a
// model, refusing that shape wastes the whole run.

const REQUIRED_ARGS = ['outputDir', 'pluginRoot', 'threatModel', 'severityFilter']

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
// Read everything below through ARGS, never the injected `args` global — it may be a
// read-only binding, so assigning the parsed object back onto it can throw.
const ARGS = args_
for (const key of REQUIRED_ARGS) {
  if (!ARGS[key]) throw new Error('c-review: args.' + key + ' is required')
}

// Optional args: absent takes the default, present with a wrong TYPE throws.
function optional(key, type) {
  const value = ARGS[key]
  if (value === undefined || value === null) return undefined
  const ok = type === 'number' ? Number.isFinite(value) : typeof value === type
  if (!ok) {
    throw new Error(
      'c-review: args.' + key + ' must be a ' + type + ', got ' + JSON.stringify(value) +
        '. It is not defaulted: a wrong type here changes what the run measures.'
    )
  }
  return value
}

// Range check on top of `optional`: present and out of range throws rather than
// silently becoming the derived default.
function bounded(key, min, max) {
  const value = optional(key, 'number')
  if (value === undefined) return null
  if (value < min || (max !== undefined && value > max)) {
    throw new Error(
      'c-review: args.' + key + ' must be ' +
        (max === undefined ? 'at least ' + min : 'between ' + min + ' and ' + max) +
        ', got ' + value +
        '. It is not defaulted: a wrong value here changes what the run measures.'
    )
  }
  return Math.floor(value)
}

// Strings only, no coercion: every one of these becomes a path or a command operand.
function text(key, fallback) {
  const value = ARGS[key]
  if ((value === undefined || value === null || value === '') && fallback !== undefined) {
    return fallback
  }
  if (typeof value !== 'string') {
    throw new Error(
      'c-review: args.' + key + ' must be a string, got ' + JSON.stringify(value) +
        '. It is not coerced: every one of these becomes a path or a command operand.'
    )
  }
  return value
}

const OUTPUT_DIR = text('outputDir')
const PLUGIN_ROOT = text('pluginRoot')
const THREAT_MODEL = text('threatModel').toUpperCase()
const SEVERITY_FILTER = text('severityFilter').toLowerCase()
const SCOPE = text('findingScopeRoot', '.')
// The scope root spelled absolutely, resolved by SKILL.md with Bash — a Workflow script
// has no filesystem APIs. `normalizePath` here and the assembler must strip the SAME
// roots, or the two sides disagree about which findings merged. Empty means "no absolute
// root known", and the assembler is told that explicitly rather than left to guess.
const SCOPE_ABS = optional('findingScopeRootAbs', 'string') || ''
const CONTEXT_ROOTS = text('contextRoots', '.')
const WORKER_MODEL_ARG = optional('workerModel', 'string')
const WORKER_MODEL =
  WORKER_MODEL_ARG && WORKER_MODEL_ARG !== 'inherit' ? WORKER_MODEL_ARG : null

if (!['REMOTE', 'LOCAL_UNPRIVILEGED', 'BOTH'].includes(THREAT_MODEL)) {
  throw new Error('c-review: threatModel must be REMOTE, LOCAL_UNPRIVILEGED or BOTH')
}
if (!['all', 'medium', 'high'].includes(SEVERITY_FILTER)) {
  throw new Error('c-review: severityFilter must be all, medium or high')
}

// A unit larger than this reproduces the reviewer saturation the location partition
// exists to remove; bounded above because the value is string-concatenated into the
// detect command and argparse rejects `1e+21`.
const MAX_UNIT_LINES = bounded('maxUnitLines', 40, 100000) || 150

// Pins the review fan-out for a measured comparison. Left unset, enumerate_units.py
// derives the count from the line total.
const REVIEW_AGENTS = bounded('reviewAgents', 1, 64)

// Lines of source per review agent. Neighbouring units share callers and buffers, so a
// larger slice reads as code rather than as a sample. `--agent-min` floors the derived
// count on a small tree; use `reviewAgents` to pin the fan-out.
const LINES_PER_AGENT = bounded('linesPerAgent', 200, 1000000) || 1500

// Benchmark instrumentation, off in a real audit: adds the external-source declaration to
// every producing prompt plus two required schema fields, and changes no finding.
const BENCHMARK_MODE = optional('benchmarkMode', 'boolean') === true

// The shared-state invariant audit, off by default: a whole extra agent whose value is
// unknown, not disproven. Turn it on for state-machine-heavy targets. Resolved here so a
// wrong type is a startup error and not a surprise 40 minutes in.
const INVARIANT_AUDIT = optional('invariantAudit', 'boolean') === true

// Cap on the model-controlled review fan-out (`detect.assignment_ids` decides the
// dispatch count). Also passed to enumerate_units.py as --agent-max, so a pinned
// `reviewAgents` above 14 is not clamped away by the enumerator's default.
const AGENT_MAX = Math.max(14, REVIEW_AGENTS || 0)

// Paths the enumerator skips, each becoming a repeated `--exclude`. The enumerator
// aborts naming `--exclude` as the remedy — a symlink resolving outside the scope root,
// an unreadable directory — so the remedy must be reachable from here, not only by
// running the enumerator by hand.
const EXCLUDE = ARGS.exclude === undefined || ARGS.exclude === null ? [] : ARGS.exclude
if (!Array.isArray(EXCLUDE) || EXCLUDE.some((e) => typeof e !== 'string' || e === '')) {
  throw new Error(
    'c-review: args.exclude must be an array of non-empty strings, got ' +
      JSON.stringify(ARGS.exclude) + '. Each entry becomes an --exclude operand.'
  )
}

const PARTS_DIR = OUTPUT_DIR + '/parts'
const SCRIPTS = PLUGIN_ROOT + '/scripts'

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
      'gets, strcpy, strcat, sprintf, vsprintf, tmpnam, tempnam, mktemp, strtok, alloca, putenv, rand for security purposes, width-less %s conversions, stpcpy, atoi and friends with no error channel. THE EVIDENCE BAR IS A FLOW, NOT A NAME: report one of these as a vulnerability only when you can trace attacker-influenced data or an attacker-influenced size to it, and state the source, the sink and what validates between them. A call whose inputs are provably bounded internal constants is a hardening observation, not a vulnerability — you may still report it, but say so plainly in the impact so the judge can rate it accordingly. Check for a project-local macro or wrapper shadowing the libc name before concluding anything.',
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
      'A field or flag of a long-lived struct carries a rule that must hold across every reset, allocation, refill and free path, and one path breaks it. C-specific by construction: malloc does not zero, lifetime is manual, and the struct is threaded through a state machine where no single function owns the field. A broken invariant here can present under any symptom label, so a class label you grep for will not surface it. THIS IS NOT A LABEL TO GREP FOR. It is the output of the invariant audit: enumerate the fields, find every writer and every reader, and prove the field\'s rule at each. Used as a search term it will reproduce the failure it was created to describe.',
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
    // `signal()` and `sig_atomic_t` are ISO C; only `sigaction` is POSIX.
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
    // `getenv` is ISO C. `skipRemote` still applies: it is the threat model that puts
    // this out of scope, not the platform.
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
      'Unbounded allocation, unbounded recursion, and superlinear algorithms driven by input size. Recursion depth is the highest-yield one in parsers: look for a depth counter that exists but is never compared against a limit, a limit that only counts one of several recursive paths, or an amplification guard that a linear chain slips under. Hash-table collision floods and regex backtracking belong here too. A countable population — enumerate EVERY recursive construct before writing this class off; filing one stack-exhaustion bug does not cover the class: the same file can hold other recursive constructs.',
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
    // No `posix: true`: qsort and bsearch are ISO C <stdlib.h>. Gating this on is_posix
    // makes the CVE-2023-6246 comparator shape structurally absent from every pure-libc
    // review, in no artifact and in no coverage list.
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
      'Everything memory-safety taxonomies do not name, and often the highest-yield class, because it catches logic bugs that fit no specific label below. Namespace or delimiter injection, where a separator character the format reserves is accepted inside a value and re-emitted so the two parse differently on the way back. Protocol state machines that accept a message in a state that skips authentication or size negotiation, or that return success on a path meant to signal "need more input". Deserialization that lets input choose a type or a size. Off-by-one in an index-to-identity mapping. Two named patterns worth hunting explicitly, because both were found here without a class of their own: VALIDATED-VALUE SUBSTITUTION, where one value is checked and a different, unchecked one reaches the sink — validation applied to a normalized copy while the raw value is used downstream is the same shape; and CALL-SITE INVARIANT, where a shared macro or helper enforces a well-formedness rule at some expansion sites and not all, so one path admits input the others reject. Also: a value read out of a header or a length field and stored into state without being checked against the bound the rest of the code assumes. These are found by reading what a value is ALLOWED to be and then asking what the code does with a value one step outside that.',
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

// Groups do three jobs: the coarse platform gate, batching the completeness sweep
// (one agent for "nothing in concurrency has an entry" is coherent; four agents for
// four silent classes is not), and the reporting taxonomy. They are not agent units,
// so their sizes do not matter and a single-class group is fine.
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

// What each review question is asking; ids must cover check_ledger.QUESTION_SITE_KINDS.
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
  initialisation:
    'Every field of every caller-provided out-parameter, and every local this unit returns through: is it written on every path before anything reads it? `malloc` does not zero and neither does the stack, so an early return through an error path leaves the caller reading whatever the previous owner of that memory left there.',
  'macro-contract':
    'Each function-like macro: what it assumes of its arguments, and whether that is enforced at every expansion site. A macro is textual, unscoped and untypechecked, so an invariant it relies on is invisible where it is used and can hold at four call sites and not the fifth.',
}

// -------------------------------------------------------------------- schemas

const DETECT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: [
    'is_cpp', 'is_posix', 'is_windows', 'platform_evidence', 'purpose', 'entry_points',
    'trust_boundaries', 'existing_hardening', 'state_structs', 'class_evidence',
    'units_ok', 'units_summary', 'assignment_ids',
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
        'the line numbers of this question\'s sites in this unit, as you found them by reading the source. They are deliberately NOT in your assignment file, which gives only the count. Every verdict except not-applicable must list ALL of them, needs-human included — a gate compares this against the parse, not against your description of what you did.',
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
  // Severity is the reporter's job. There is no judge downstream to assign it,
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
  required: ['part_written', 'findings', 'ledger'].concat(
    BENCHMARK_MODE ? ['external_sources_consulted', 'external_sources_detail'] : []
  ),
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
  // `artifacts_written` is REQUIRED and answered from the DIRECTORY, not the exit code:
  // optional, a gate-rejection return would read as "artifacts were not written" over a
  // complete report.
  required: ['ok', 'artifacts_written'],
  properties: {
    ok: { type: 'boolean', description: 'the script exited 0' },
    artifacts_written: {
      type: 'boolean',
      description:
        'true only if findings.json, REPORT.md and REPORT.sarif are all present in the output directory after the command ran. List the directory; do not infer it from the exit code.',
    },
    reported: { type: 'integer' },
    raw_findings: { type: 'integer' },
    // The assembler runs the ledger gate in-process, so these come back from it directly.
    checks_required: { type: 'integer' },
    checks_completed: { type: 'integer' },
    checks_satisfied: { type: 'integer', description: 'answered AND accepted by the gate' },
    // Part files no assembler rule reads — each is an agent's whole output dropped on
    // the floor, usually a misnamed stem.
    unrecognised_parts: { type: 'integer' },
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
  'and asserting it suppresses real, present bugs that a plain reading of the file would find.',
  '',
  'If you claim a guard, a bounds check, a cast, or any other mitigation exists, cite the path:line',
  'where it is written, so a reader can open that line and see it. If you cannot cite it, it is not',
  'there. Nothing outside this repository substitutes for that citation: an upstream diff, a',
  'changelog or an advisory may tell you where to look, but only the code in front of you can clear',
  'a candidate.',
  '',
  'The same rule covers this run\'s OWN generated files. The output directory holds the unit list,',
  'the assignment files and, once the run finishes, the gate report — none of them are the source,',
  'and none of them are evidence about the code. Read the file the unit names, not the tooling',
  'around it.',
  // Deliberately nothing here names the derivation it denies: anti-cheat text that
  // describes the cheat is worse than none. The control is the tool scope (WORKER_AGENT).
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

// The location-partition escape hatch, distinct from ESCAPE_HATCH below: under a location
// partition every line has one owner, so "report anything, no one else is looking" buys
// duplicate work (measured: one line written up by five of six agents). Out-of-slice bugs
// become one-line pointers, promoted only if the owner never files there.
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
// construction rather than a guess. Out-of-class sightings become pointers, not silence.
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
// transcribe another's findings; each writes only its own part file.
function partBlock(partPath) {
  return [
    'WRITE YOUR RESULT TO ' + partPath,
    '',
    'Write a single JSON object there with exactly the keys of the structured value you return.',
    // Write, and only Write: a shell-fallback sentence here would point a shell-less
    // agent (see WORKER_AGENT) at the very tool the scope removes.
    'Use the Write tool. You have no shell in this configuration; there is no fallback.',
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

// Every list off `detect` goes through `asArray`: the detect return is model output, and
// a non-iterable would throw away the agent already paid for.
function contextBlock(detect) {
  return [
    '<codebase>',
    'Purpose: ' + detect.purpose,
    'Language/platform: is_cpp=' + detect.is_cpp + ', is_posix=' + detect.is_posix + ', is_windows=' + detect.is_windows,
    'Platform evidence: ' + detect.platform_evidence,
    'Entry points for untrusted data:',
    asArray(detect.entry_points).map((e) => '  - ' + e).join('\n'),
    'Trust boundaries:',
    asArray(detect.trust_boundaries).map((e) => '  - ' + e).join('\n'),
    'Existing hardening:',
    asArray(detect.existing_hardening).map((e) => '  - ' + e).join('\n'),
    'Long-lived mutable state structs:',
    asArray(detect.state_structs).map((e) => '  - ' + e).join('\n'),
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

function detectPrompt(gateableClasses) {
  const cmd =
    // `--no-project`: the cwd is the AUDITED tree, and a C library with Python bindings
    // commonly carries a pyproject.toml — without the flag uv installs that project
    // first, and its resolution failure aborts Detect. PEP 723 inline deps still install.
    'uv run --no-project ' + shq(SCRIPTS + '/enumerate_units.py') +
    ' --root ' + shq(SCOPE) +
    ' --out-dir ' + shq(OUTPUT_DIR) +
    ' --max-unit-lines ' + MAX_UNIT_LINES +
    ' --lines-per-agent ' + LINES_PER_AGENT +
    ' --agent-max ' + AGENT_MAX +
    EXCLUDE_FLAGS +
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
    '   one typedef resolves; that is not a Windows codebase, and gating Windows work on it spends',
    '   the fan-out on a platform axis that does not apply. Set is_windows only if the code calls Win32',
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
    'It lists every unit you own — file, line range, name, parameters, the question ids that unit',
    'owes an answer to, and under `site_counts` HOW MANY sites of each question a parse counted in',
    'it. The lines themselves are in no file. You find them by reading the unit; the count is how',
    'you know when you have them all.',
    '',
    EVIDENCE_RULE,
    '',
    ...(BENCHMARK_MODE ? [EXTERNAL_SOURCE_DECLARATION, ''] : []),
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
    '- `sites_accounted` is the line numbers you FOUND by reading the unit — all of them, not just',
    '  the ones you filed at. `site_counts` tells you how many the parse counted for that question,',
    '  so you know when you have them all; the lines themselves are not in your assignment file and',
    '  a gate diffs yours against the parse. `evidence` says what you found at them, including the',
    '  ones you did not file: "12 write sites, all indexed by `i` bounded at 411, except 418 which',
    '  uses `n` from the header — filed" is a real row.',
    '- `site_counts` is what the parse counted, so it tells you when to keep looking, not what to',
    '  write down. List what you actually found. Do not pad with lines that are related but are not',
    '  that question\'s own construct — a `bounds` site is the write itself, not the bound check',
    '  above it or the call that reached it — and do NOT delete a site you found to make the',
    '  numbers agree. A count you cannot reconcile is information: say so in `evidence` and leave',
    '  the extra line in. Trimming to the number is how a real thirteenth write site stops being',
    '  examined, and it is the one thing the gate exists to measure independently.',
    '- The two PARAMETER questions are the exception, and they are counted differently on purpose:',
    '  for `caller-contract` and `initialisation` the population is EVERY line that mentions the',
    '  parameter — the NULL check, the length comparison and the write alike — because what those',
    '  questions ask about is the whole use of the value, not one construct.',
    '- Verdict `finding` does NOT close the unit or the question. A bug found is a reason to look',
    '  harder here, not to move on: a function with one bug found is likely to hold more.',
    '- `not-applicable` is only honest when the counted population is empty.',
    '- `needs-human` is a legitimate answer and is better than a false clean, but it is not a cheaper',
    '  one: still list every counted site in `sites_accounted` and say what you could not resolve.',
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
    ...(BENCHMARK_MODE ? [EXTERNAL_SOURCE_DECLARATION, ''] : []),
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
    'classes below, each of which has NO entry anywhere in the review output and none of which the',
    'detect phase ruled out.',
    '',
    'Grouped for reading, not for scoping — all of them are yours:',
    '',
    groups.map((g) => '  ' + g.group.title + ': ' + g.classIds.join(', ')).join('\n'),
    '',
    'This pass earns its keep on scattered single-site slips — a missing free on one error path, a',
    '(void) cast hiding an unchecked return, one clamp done at the wrong width, one state that',
    'returns success where it should return "need more input". Those are exactly the bugs a reader',
    'working through a region in order tends to walk past. Check cold error-handling paths',
    'deliberately.',
    '',
    'Cited candidate sites from the detect phase (a class with no citation was never put to that',
    'phase — no grep decides it, so enumerate its population yourself):',
    '',
    classIds.map((id) => '  - ' + id + ': ' + (evidenceById.get(id) || 'not gated, no citation')).join('\n'),
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
    'class goes unlooked-at.',
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
    ...(BENCHMARK_MODE ? [EXTERNAL_SOURCE_DECLARATION, ''] : []),
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
  // Each finding carries its group index so the no-cross-group constraint is checkable
  // in the prompt; the workflow discards any merge that violates it.
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
    'return: {"part_id": "dedup-agent", "merges": [ ... ]}. Use the Write tool. You have no shell',
    'in this configuration; there is no fallback. The final report is assembled from the part',
    'files, so a merge that is only in your reply and not in the file does not happen.',
  ].join('\n')
}

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
// model puts out of scope should not be filed at all.
function severityBlock() {
  return [
    '## Severity — you assign it, nobody re-checks it',
    '',
    'There is no separate judge in this pipeline. The severity you write is the severity the user',
    'reads, so spend a moment on it. Severity is relative to the threat model, not absolute.',
    '',
    SEVERITY_TABLES,
    '',
    '### Scope — file everything, and say what the threat model does to it',
    '',
    'Under REMOTE, a bug only triggerable through local configuration, CLI arguments, environment or',
    'an existing shell scores LOW. Under LOCAL_UNPRIVILEGED, so does a bug that crosses no privilege',
    'boundary, or one that requires root. File it either way, and say in the impact that the threat',
    'model puts it out of scope. Do NOT decide not to file it: nothing downstream re-reads your',
    'units, so a bug you judge out of scope is a bug nobody ever looks at again, and the pipeline',
    'already filters deterministically by severity after the fact.',
    '',
    'A finding whose impact is hardening rather than exploitation — a banned API with no',
    'attacker-controlled data reaching it, a missing compiler flag — is worth reporting at LOW. Say',
    'plainly in the impact that it is a hardening gap, so it is not read as an exploitable bug.',
  ].join('\n')
}
function assemblePrompt(expected, complete, external, groupsAttempted, groupsFailed, failures) {
  const parts = [
    // `--no-project` for the same reason as the detect command: the cwd is the audited
    // tree, whose own pyproject.toml must not be installed before the assembler runs.
    'uv run --no-project ' + shq(SCRIPTS + '/assemble_findings.py'),
    '--run-dir ' + shq(OUTPUT_DIR),
    '--threat-model ' + shq(THREAT_MODEL),
    '--severity-filter ' + shq(SEVERITY_FILTER),
    '--scope ' + shq(SCOPE),
    // Always passed, empty included: omitting it lets the assembler resolve `--scope`
    // against its own cwd and strip a root `normalizePath` above never saw.
    '--scope-abs ' + shq(SCOPE_ABS),
    '--context-roots ' + shq(CONTEXT_ROOTS),
    '--worker-model ' + shq(WORKER_MODEL || 'inherit'),
    // The declaration is only asked for in benchmark mode, so only benchmark mode may
    // record it as asked. Inferring it from the part file lets a model that volunteers the
    // optional property make an unasked cell look like a cleared one.
    ...(BENCHMARK_MODE ? ['--benchmark-mode'] : []),
    '--groups-attempted ' + shq(groupsAttempted.join(',')),
    '--groups-failed ' + shq(groupsFailed.join(',')),
    '--no-judge',
  ]
  for (const e of expected) parts.push('--expect ' + shq(e))
  for (const c of complete) parts.push('--expect-complete ' + shq(c))
  // The declaration the agent gave through the SCHEMA. Without it the assembler only ever
  // sees the part file, which can be an earlier draft than the accepted return — the same
  // staleness `--expect-complete` exists for — so an honest `true` could be dropped.
  for (const x of external) parts.push('--external-source ' + shq(x))
  for (const f of failures) parts.push('--agent-failure ' + shq(f))

  return [
    'Mechanical step. Run exactly this command and report its result. Do not analyse the content, do',
    'not edit any file, and do not write any artifact yourself.',
    '',
    '  ' + parts.join(' \\\n    '),
    '',
    'It reads the part files each agent wrote, assembles findings.json deterministically, and',
    'generates REPORT.md and REPORT.sarif from it.',
    '',
    'Three exit codes, and they mean different things:',
    '',
'- 0 — everything written and the coverage gate accepted the ledger. Return ok=true.',
    '- 1 — everything WAS written, but the coverage gate could not run or rejected the ledger. The',
    '  review is assembled and unverified, and all three artifacts say so. Return ok=false and the',
    '  stderr text in `error`.',
    '- 2 — no artifact was written (a part file missing or unreadable, none at all, or a malformed',
    '  part the assembler could not read). Return ok=false and the stderr text in `error`.',
    '',
    'Then LIST ' + shq(OUTPUT_DIR) + ' and set artifacts_written from what is actually there —',
    'true only if findings.json, REPORT.md and REPORT.sarif are all present. Do not infer it from',
    'the exit code: the code tells you what the script believes, and the directory is the fact.',
    '',
    'Never re-run it and never hand-write the outputs: it is deterministic, so a second run cannot',
    'produce a different answer, and hand-transcribing this document silently drops findings and',
    'strips evidence fields.',
    '',
    'It also runs the coverage gate in-process and writes ledger-gate.json, so there is no separate',
    'gate step. Copy the counts from the JSON it printed into the matching fields WHATEVER the exit',
    'code was — checks_required, checks_completed, checks_satisfied and unrecognised_parts. The',
    'script prints that JSON before it returns 1, so those numbers exist on a rejection too, and a',
    'rejection is exactly when coverage matters: omitting them makes the skill report 400 of 445',
    'satisfied as "coverage UNMEASURED". Copy unrecognised_parts even when it is 0 — an omitted',
    'count is reported as UNCHECKED, not as none.',
  ].join('\n')
}

// ----------------------------------------------------------------- utilities

// POSIX single-quoting for every value interpolated into a command an agent is told to
// run EXACTLY. `JSON.stringify` is a JSON encoder, not a shell quoter: inside bash double
// quotes `$` and backticks stay live — and part ids are model output, so a hand-rolled
// quote falls to `unit-01'; echo PWNED; #`.
function shq(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'"
}

// Pre-quoted `--exclude` flags for the detect command, built here — after `shq` — because
// the command builder splices this string verbatim and every element must already be
// quoted. test_workflow_args.py scans the command regions for unquoted operands and
// allowlists this name on the strength of the `shq` below.
const EXCLUDE_FLAGS = EXCLUDE.map((e) => ' --exclude ' + shq(e)).join('')

// An assignment id becomes a shell word, an `--expect ID=COUNT` operand and a part-file
// stem: an `=` mis-splits the expectation, a `/` or `..` escapes the parts directory.
const ASSIGNMENT_ID = /^[a-z0-9][a-z0-9-]*$/

function workerOpts(extra) {
  const opts = Object.assign({}, extra)
  if (WORKER_MODEL) opts.model = WORKER_MODEL
  return opts
}

// The tool scope for every PRODUCING agent. `agents/c-review-worker.md` grants Read,
// Grep, Glob and Write — and no Bash, which is the only control that closes the two
// documented ledger-gate bypasses (both need code execution over this run's own generated
// files). The detect and assemble agents each exist to run a command, so they are
// TRUSTED, not controlled — README.md and AGENTS.md say so where the reader is.
const WORKER_AGENT = 'c-review:c-review-worker'

// The control goes LAST so a caller's explicit `agentType: undefined` cannot win: the
// CLI's dispatch skips the scoping block for a null-ish agentType and the subagent then
// inherits every tool, Bash included. This control fails OPEN when it fails.
function producingOpts(extra) {
  return workerOpts(Object.assign({}, extra, { agentType: WORKER_AGENT }))
}

// Every dispatch is caught so one rejection cannot take down `parallel` and discard every
// completed slice — and the reason is logged, because `agent type '…' not found` means
// the tool scope above is broken, which N bare "returned nothing" warnings would hide.
function died(label) {
  return (err) => {
    log('WARNING: ' + label + ' failed: ' + ((err && err.message) || String(err)))
    return null
  }
}

// One dedup agent, only for collisions the assembler cannot merge deterministically; the
// cap bounds its prompt size, not an agent count.
const DEDUP_MAX_PAIRS = 40

// The next three must equal NEARBY_LINES, CROSS_CLASS_NEARBY_LINES and COLLISION_LINES in
// assemble_findings.py, which owns the artifact. If they drift, a pair this side counts
// as already merged is left for an agent there (or the reverse) and the pair falls
// between the two rules. Tests pin the equality.
const NEARBY_LINES = 3
const CROSS_CLASS_NEARBY_LINES = 0
const COLLISION_LINES = 8

// Mirrors REQUIRED_FINDING_FIELDS in assemble_findings.py. Decides whether a part's
// RETURNED findings were complete, which lets the assembler tell a stale part file from a
// genuinely thin one.
const REQUIRED_PART_FIELDS = ['title', 'file', 'line', 'description', 'impact', 'recommendation']

// `hasOwnProperty`, not `CLASSES[id]`: `constructor` and `__proto__` resolve through the
// prototype chain and would pass as real bug classes here while assemble_findings.py maps
// them to `logic-flaw`.
function knownClass(id) {
  return Object.prototype.hasOwnProperty.call(CLASSES, id)
}

// Every agent-returned list goes through this: a truthy non-iterable like `findings:
// {a: 1}` would otherwise throw out of the module after every agent has been paid for.
// Mirrors `_seq` on the Python side.
function asArray(value) {
  return Array.isArray(value) ? value : []
}

// Folds model spellings (`format_string`, `Buffer Overflow`) onto catalogue ids; '' when
// nothing matches. NOT used for a finding's own `bug_class`, which must stay byte-exact
// with assemble_findings.py.
function normClassId(value) {
  const raw = String(value == null ? '' : value).trim()
  if (!raw) return ''
  if (knownClass(raw)) return raw
  const slug = raw.toLowerCase().replace(/[\s_]+/g, '-').replace(/-+/g, '-')
  return knownClass(slug) ? slug : ''
}

function classList(ids) {
  return ids
    .map((id) => {
      const c = CLASSES[id]
      return '### ' + id + ' — ' + c.title + '\n' + c.brief
    })
    .join('\n\n')
}

// Returns {selected, dropped}: a class the platform or threat model removed appears in
// no other coverage story, so `dropped` must be returned rather than skipped.
function selectGroups(detect) {
  const selected = []
  const dropped = []
  for (const group of GROUPS) {
    // Recorded, not just skipped: a bare `continue` would drop the group's classes from
    // `selected` AND `dropped`, leaving them in no coverage story.
    const gateFailed = (group.gate === 'is_cpp' && !detect.is_cpp) ? 'not a C++ target'
      : (group.gate === 'is_windows' && !detect.is_windows) ? 'not a Windows target'
      : null
    if (gateFailed) {
      for (const id of group.classes) dropped.push(id + ' (' + gateFailed + ')')
      continue
    }
    const classIds = group.classes.filter((id) => {
      const c = CLASSES[id]
      const why = c.posix && !detect.is_posix ? 'not a POSIX target'
        : c.skipRemote && THREAT_MODEL === 'REMOTE' ? 'out of scope under REMOTE'
        : null
      if (why) dropped.push(id + ' (' + why + ')')
      return !why
    })
    if (classIds.length) selected.push({ group: group, classIds: classIds })
  }
  return { selected: selected, dropped: dropped }
}

// Port of `normalize_path` in assemble_findings.py, including the scope-root stripping
// and the `.`/`..` folding: any rule short of the assembler's sees `src/parse.c` and
// `/proj/src/parse.c` as two files, and the pair never reaches the dedup agent.
function normalizePath(p) {
  let s = String(p == null ? '' : p).replace(/\\/g, '/').trim()
  const link = s.match(/^\[([^\]]+)\]\([^)]*\)$/)
  if (link) s = link[1]
  while (s.indexOf('//') !== -1) s = s.replace('//', '/')
  // Fold `.`/`..` BEFORE stripping the roots (absolute spelling first), exactly as the
  // assembler orders it: stripping first leaves `./src/parse.c` unmatched against `src`.
  s = foldSegments(s)
  for (const candidate of [SCOPE_ABS, SCOPE]) {
    const root = foldSegments(String(candidate || '').replace(/\\/g, '/').replace(/\/+$/, ''))
    if (root && s.startsWith(root + '/')) {
      s = s.slice(root.length + 1)
      break
    }
  }
  return s
}

function foldSegments(s) {
  const parts = []
  for (const segment of s.split('/')) {
    if (segment === '.' || (segment === '' && parts.length)) continue
    if (segment === '..' && parts.length && parts[parts.length - 1] !== '' && parts[parts.length - 1] !== '..') {
      parts.pop()
      continue
    }
    parts.push(segment)
  }
  return parts.join('/')
}

const CONFIDENCE_RANK = { High: 3, Medium: 2, Low: 1 }

// The key is the finding's identity for the whole run: <part id>#<index in that
// part's findings array>. The assembler recomputes it from the same part file, so
// dedup and judge decisions land on the right finding without either side needing
// the other's numbering. Public ids (BOF-001) are assigned by the assembler alone.
function normalizeFinding(raw, partId, index) {
  const bugClass = knownClass(raw.bug_class) ? raw.bug_class : 'logic-flaw'
  return {
    key: partId + '#' + index,
    bug_class: bugClass,
    reported_bug_class: String(raw.bug_class || ''),
    title: String(raw.title || 'untitled'),
    file: normalizePath(raw.file),
    line: Number.isFinite(raw.line) && raw.line > 0 ? Math.floor(raw.line) : 1,
    function: String(raw.function || '(file-level)').trim(),
    unit_id: String(raw.unit_id || ''),
    confidence: CONFIDENCE_RANK[raw.confidence] > 0 ? raw.confidence : 'Medium',
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

// Must match `_election_key` in assemble_findings.py, which owns the artifact. Location
// PRECISION first — a named function beats `(file-level)` — then confidence, then key.
function precisionRank(f) {
  return normFunction(f.function) ? 1 : 0
}

function pickPrimary(a, b) {
  const pa = precisionRank(a)
  const pb = precisionRank(b)
  if (pa !== pb) return pa > pb ? a : b
  // `> 0`, not truthiness: `CONFIDENCE_RANK['constructor']` is a Function off the
  // prototype chain, which is truthy and compares as neither greater nor less.
  const ra = CONFIDENCE_RANK[a.confidence] > 0 ? CONFIDENCE_RANK[a.confidence] : 2
  const rb = CONFIDENCE_RANK[b.confidence] > 0 ? CONFIDENCE_RANK[b.confidence] : 2
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

// Does this component hold a cross-class pair further apart than the cap allows?
// Port of `_cross_class_too_far` in assemble_findings.py.
function crossClassTooFar(component) {
  for (let i = 0; i < component.length; i++) {
    for (let j = i + 1; j < component.length; j++) {
      const a = component[i]
      const b = component[j]
      if (a.bug_class === b.bug_class) continue
      if (Math.abs(a.line - b.line) > CROSS_CLASS_NEARBY_LINES) return true
    }
  }
  return false
}

// Tier 1.5, mirroring `assemble_findings.py`: two findings in one function within three
// lines are the same bug described twice. The assembler owns the artifact; this copy is
// what keeps such pairs out of the dedup agent's prompt.
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
    if (members.length < 2) continue
    members.sort((a, b) => a.line - b.line || (a.key < b.key ? -1 : 1))
    // Connected components, not pairs, exactly as tier1_5 does it: findings at 100, 102
    // and 104 are one group even though the outer two are four lines apart.
    const parent = new Map(members.map((f) => [f.key, f.key]))
    const find = (k) => {
      while (parent.get(k) !== k) {
        parent.set(k, parent.get(parent.get(k)))
        k = parent.get(k)
      }
      return k
    }
    for (let i = 0; i < members.length; i++) {
      for (let j = i + 1; j < members.length; j++) {
        const a = members[i]
        const b = members[j]
        const gap = b.line - a.line
        if (gap > NEARBY_LINES) break
        // Cross-class pairs merge only on the same line, exactly as the assembler rules.
        if (gap > CROSS_CLASS_NEARBY_LINES && a.bug_class !== b.bug_class) continue
        const ra = find(a.key)
        const rb = find(b.key)
        if (ra !== rb) parent.set(ra, rb)
      }
    }
    const components = new Map()
    for (const f of members) {
      const root = find(f.key)
      if (!components.has(root)) components.set(root, [])
      components.get(root).push(f)
    }
    for (const component of components.values()) {
      if (component.length < 2) continue
      // The cap is pairwise but the merge is by component, so a cross-class pair can meet
      // through a third finding: reject the WHOLE component, as `_cross_class_too_far`
      // does in assemble_findings.py.
      if (crossClassTooFar(component)) continue
      let primary = component[0]
      for (const m of component.slice(1)) primary = pickPrimary(primary, m)
      const demoted = new Set(component.filter((f) => f.key !== primary.key).map((f) => f.key))
      for (const key of demoted) {
        mergedInto.set(key, primary.key)
        merged++
      }
      // A demoted tier-1 primary drags everything folded into it along, or mergedInto
      // holds a chain. Not counted: they were merged already.
      for (const [dup, target] of [...mergedInto]) {
        if (demoted.has(target) && !demoted.has(dup)) mergedInto.set(dup, primary.key)
      }
    }
  }
  return merged
}

// Prose that appears in almost every data_flow description. Without these the comparison
// measures how similarly two reviewers write English rather than whether they are
// describing one chain.
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

// Deliberately hard to trigger: a genuine match shares several distinctive identifiers.
// A looser threshold measures prose similarity instead, and every false collision costs
// a dedup agent.
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
        const nearby = Math.abs(a.line - b.line) <= COLLISION_LINES
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

// ----------------------------------------------------------------- run state
//
// Accumulated across phases and handed to assemble_findings.py as operands: which part
// files to expect (and with how many findings), which returns were complete, each
// agent's external-source declaration, and every agent failure.
const partsExpected = []
const partsComplete = []
const partsExternal = []
const agentFailures = []

// Classes the detect phase cited a candidate site for, by catalogue id. A class carrying
// an `evidence` grep is sweep-eligible only with a citation; a class without one was
// never put to detect, so it is ALWAYS a candidate — gating those on a citation would
// make 32 of the 56 classes structurally unreachable by the sweep.
const evidenceById = new Map()
const sweepCandidate = (id) => evidenceById.has(id) || !CLASSES[id].evidence

function recordClassEvidence(detect) {
  for (const e of asArray(detect.class_evidence)) {
    if (!e || !e.bug_class || !e.has_candidates) continue
    // Normalized: `format_string` and `Buffer Overflow` are routine model spellings, and
    // an unrecognised id silently removes the class from the only pass that looks for it.
    const id = normClassId(e.bug_class)
    if (id) evidenceById.set(id, String(e.citation || ''))
  }
}

// ----------------------------------------------------------- phase functions

// Detect: platform and context from real API usage, plus the generated unit list.
// enumerate_units.py — run inside the prompt's command — creates parts/ and clears any
// previous run's part files, so a stale part can never be assembled into this run.
async function runDetect() {
  const gateableClasses = Object.keys(CLASSES).filter((id) => CLASSES[id].evidence)
  const detect = await agent(
    detectPrompt(gateableClasses),
    workerOpts({ label: 'detect', phase: 'Detect', schema: DETECT_SCHEMA })
  ).catch(died('detect'))
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
  return detect
}

// The assignment ids are model output that becomes shell words, `--expect` operands and
// part-file paths, so every check here throws before any review agent is paid for.
function toAssignments(detect) {
  const assignmentIds = asArray(detect.assignment_ids).map(String).filter(Boolean)
  if (!assignmentIds.length) {
    throw new Error(
      'c-review: the detect agent produced no assignment ids. units.json exists but nothing can be ' +
        'dispatched against it; re-run rather than reviewing an unpartitioned tree.'
    )
  }
  const malformedIds = assignmentIds.filter((id) => !ASSIGNMENT_ID.test(id))
  if (malformedIds.length) {
    throw new Error(
      'c-review: assignment id(s) ' + malformedIds.join(', ') + ' are not ' + ASSIGNMENT_ID +
        '. `enumerate_units.py` emits `unit-NN`, so these were not copied from it; they reach a ' +
        'shell command, an --expect operand and a part-file path.'
    )
  }
  // Two agents handed one id are told to write the same part path, so one agent's whole
  // output is overwritten before anything reads it.
  if (new Set(assignmentIds).size !== assignmentIds.length) {
    throw new Error(
      'c-review: the detect agent returned duplicate assignment id(s) in ' +
        assignmentIds.join(', ') + '. Each id is a part-file path; two agents sharing one means ' +
        'one agent\'s whole output is overwritten before anything reads it.'
    )
  }
  if (assignmentIds.length > AGENT_MAX) {
    throw new Error(
      'c-review: the detect agent returned ' + assignmentIds.length + ' assignment ids and ' +
        'enumerate_units.py cannot emit more than ' + AGENT_MAX + '. These were not copied from ' +
        'units.json, and each one costs an agent.'
    )
  }
  // Deliberately nothing beyond id and path: the unit details live in the assignment
  // file, which the prompt tells the reviewer to read first.
  const assignments = assignmentIds.map((id) => ({
    id: id,
    path: OUTPUT_DIR + '/assignments/' + id + '.json',
  }))
  return assignments
}

// Review: one agent per contiguous slice of the unit list. This is the partition — every
// line has exactly one owner.
async function runReview(assignments, detect) {
  return parallel(
    assignments.map((a) => () =>
      agent(
        reviewPrompt(a, detect),
        producingOpts({ label: 'review:' + a.id, phase: 'Review', schema: REVIEW_SCHEMA })
      )
        .catch(died('review-' + a.id))
        .then((r) => ({ partId: 'review-' + a.id, result: r }))
    )
  )
}

// Sweep: the class axis. One agent covers every class that has no finding anywhere in
// the review output and that detect did not rule out, plus — with `invariantAudit: true`
// — the shared-state invariant audit. Not the partition, but not decoration either: in
// the measurement it alone found four bugs, three of them in cold error paths.
async function runSweep(detect, selected, reviewResults) {
  const classesWithFindings = new Set()
  // The class each finding will actually be FILED under — normalizeFinding's exact-match
  // rule, not a slug-folded guess — or a covered-looking class ships no finding in any
  // artifact and appears in no coverage story. A part that was never written contributes
  // nothing to any artifact, so its classes are still silent.
  function recordClasses(entries) {
    for (const entry of entries) {
      if (!entry || !entry.result) continue
      if (entry.result.part_written === false) continue
      for (const f of asArray(entry.result.findings)) {
        classesWithFindings.add(knownClass(f && f.bug_class) ? f.bug_class : 'logic-flaw')
      }
    }
  }
  recordClasses(reviewResults)

  const silentByGroup = []
  for (const sel of selected) {
    const silent = sel.classIds.filter((id) => !classesWithFindings.has(id) && sweepCandidate(id))
    if (silent.length) silentByGroup.push({ group: sel.group, classIds: silent })
  }
  // Silent but ruled out by detect, logged separately: "no candidate site" and "swept and
  // found nothing" are different coverage stories.
  const ruledOut = selected.flatMap((sel) =>
    sel.classIds.filter((id) => !classesWithFindings.has(id) && !sweepCandidate(id))
  )
  if (!evidenceById.size) {
    log(
      'WARNING: the detect phase cited no candidate site for any gateable class, so every ' +
        'grep-gated class is out of the sweep. Expected on a small ISO-C target, suspicious on anything larger.'
    )
  }
  if (ruledOut.length) {
    log(ruledOut.length + ' silent class(es) NOT swept — detect cited no candidate site: ' + ruledOut.join(', '))
  }

  const sweepThunks = []
  if (silentByGroup.length) {
    const total = silentByGroup.reduce((n, g) => n + g.classIds.length, 0)
    log(
      'class sweep: ' + total + ' silent class(es) across ' + silentByGroup.length + ' group(s)'
    )
    sweepThunks.push(() =>
      agent(
        classSweepPrompt(silentByGroup, detect, evidenceById),
        producingOpts({ label: 'sweep:classes', phase: 'Sweep', schema: REVIEW_SCHEMA })
      ).catch(died('sweep-classes')).then((r) => ({ partId: 'sweep-classes', result: r }))
    )
  } else {
    log('every live class already has an entry or was ruled out by detect; class sweep skipped')
  }

  const structs = asArray(detect.state_structs).map(String).filter(Boolean)
  if (INVARIANT_AUDIT) {
    sweepThunks.push(() =>
      agent(
        invariantSweepPrompt(structs, detect),
        producingOpts({ label: 'sweep:invariants', phase: 'Sweep', schema: REVIEW_SCHEMA, effort: 'high' })
      ).catch(died('sweep-invariants')).then((r) => ({ partId: 'sweep-invariants', result: r }))
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
  // Recomputed over every producer: a silent class is one with no finding ANYWHERE, so
  // the set computed before the sweep ran cannot be the answer.
  recordClasses(sweepResults)
  const stillSilent = silentByGroup.flatMap((g) => g.classIds).filter((id) => !classesWithFindings.has(id))
  return {
    sweepResults: sweepResults,
    silentByGroup: silentByGroup,
    ruledOut: ruledOut,
    stillSilent: stillSilent,
  }
}

// Collect every producer's schema-returned findings and build the assembler's operands.
function collectProducers(reviewResults, sweepResults) {
  const producers = [...reviewResults, ...sweepResults]
  const rawFindings = []
  const notes = []
  for (const entry of producers) {
    if (!entry) continue
    if (!entry.result) {
      agentFailures.push(entry.partId + ': returned nothing')
      log('WARNING: ' + entry.partId + ' returned nothing; its units and classes are UNCOVERED')
      // The stem WITHOUT a count: `--expect` is an allowlist as well as an assertion, and
      // a worker whose structured answer was rejected may still have written an honest
      // part file. The matching `--agent-failure` keeps a genuinely absent file non-fatal.
      partsExpected.push(entry.partId)
      continue
    }
    const findings = asArray(entry.result.findings)
    findings.forEach((f, i) => rawFindings.push(normalizeFinding(f, entry.partId, i)))
    if (entry.result.part_written === false) {
      agentFailures.push(entry.partId + ': did not write its part file')
      log(
        'WARNING: ' + entry.partId + ' says it did not write its part file. Its ' + findings.length +
          ' finding(s) are missing from the artifacts, and this run is short by that much.'
      )
    }
    // Pushed either way: skipping it would make `part_written: false` an agent-controlled
    // switch that disables the only check on a part file the assembler still reads in full.
    partsExpected.push(entry.partId + '=' + findings.length)
    // Complete by construction — it came back through the schema. Lets the assembler tell
    // a stale part file from a genuinely thin one.
    if (findings.length && findings.every((f) => REQUIRED_PART_FIELDS.every((k) => f && f[k]))) {
      partsComplete.push(entry.partId)
    }
    // Only benchmark mode asks the question, so only a return that carried the key counts
    // as an answer — the part file can be an earlier draft than the accepted return.
    if (BENCHMARK_MODE && 'external_sources_consulted' in entry.result) {
      partsExternal.push(entry.partId + '=' + (entry.result.external_sources_consulted ? 1 : 0))
    }
    if (entry.result.notes) notes.push(entry.partId + ': ' + entry.result.notes)
  }
  const byKey = new Map(rawFindings.map((f) => [f.key, f]))
  log(rawFindings.length + ' raw finding(s) from ' + producers.filter((e) => e && e.result).length + ' agent(s)')
  return { producers: producers, rawFindings: rawFindings, notes: notes, byKey: byKey }
}

// Dedup residue: one agent, only for the collisions `tier1` and `autoMergeNearby` (both
// already applied to `mergedInto`) could not merge deterministically. Under a location
// partition that residue is usually empty. Returns how many dedup agents came BACK.
async function runDedup(rawFindings, byKey, mergedInto, autoMerged) {
  const buckets = collisionBuckets(rawFindings, mergedInto)
  // Keys are `<partId>#<index>` and so are guessable: a merge over findings the agent was
  // never SHOWN must be rejected, or a hallucinated merge drops a real finding with the
  // assembler agreeing. Populated from `sent` below, NOT from `buckets`.
  const bucketOf = new Map()
  let dedupAgents = 0
  if (buckets.length) {
    const pairs = buckets.reduce((n, b) => n + b.length, 0)
    let sent = buckets
    if (pairs > DEDUP_MAX_PAIRS) {
      // A bucket only counts toward the budget when kept, so one oversized bucket cannot
      // poison the total for every bucket after it. Unmerged duplicates ship as two
      // findings, which is the safe direction, but the reader should know it happened.
      let running = 0
      sent = buckets.filter((b) => {
        if (running + b.length > DEDUP_MAX_PAIRS) return false
        running += b.length
        return true
      })
      log(
        'CAP: ' + pairs + ' colliding finding(s) exceed the ' + DEDUP_MAX_PAIRS + '-finding dedup ' +
          'prompt budget; ' + (pairs - sent.reduce((n, b) => n + b.length, 0)) + ' left unmerged ' +
          'and reported separately'
      )
    }
    if (!sent.length) {
      log('dedup agent skipped: every collision group exceeded the prompt budget on its own')
    } else {
      for (let b = 0; b < sent.length; b++) {
        for (const f of sent[b]) bucketOf.set(f.key, b)
      }
      log(
        sent.length + ' collision group(s) to one agent, ' + autoMerged +
          ' pair(s) already merged deterministically'
      )
      const res = await agent(
        dedupPrompt(sent),
        producingOpts({ label: 'dedup', phase: 'Dedup', schema: DEDUP_SCHEMA, effort: 'low' })
      ).catch(died('dedup-agent'))
      // No `--expect` for the dedup part in either branch: DEDUP_SCHEMA has no
      // `part_written`, so an unmet expectation would fail the assembler with exit 2 and
      // NO artifacts — for the most skippable phase in the pipeline. A merge that never
      // reached disk is visible as two findings.
      if (!res) {
        agentFailures.push('dedup-agent: returned nothing')
        log('WARNING: the dedup agent returned nothing; colliding findings stay unmerged')
      }
      if (res) dedupAgents = 1
      for (const merge of asArray(res && res.merges)) {
        const stated = merge && merge.primary
        if (!byKey.has(stated) || mergedInto.has(stated)) continue
        const live = []
        for (const dup of asArray(merge && merge.duplicates)) {
          if (dup === stated || !byKey.has(dup) || mergedInto.has(dup)) continue
          // `has` first: two findings that are each in no bucket both read `undefined`,
          // which compares equal, and the merge would be accepted unshown.
          if (!bucketOf.has(dup) || bucketOf.get(dup) !== bucketOf.get(stated)) {
            log('rejected cross-bucket merge ' + dup + ' -> ' + stated)
            continue
          }
          live.push(dup)
        }
        if (!live.length) continue
        // RE-ELECT exactly as `apply_agent_merges` does rather than trusting the agent's
        // nomination, or the run log and findings.json disagree about which finding
        // survived.
        let primary = byKey.get(stated)
        for (const dup of live) primary = pickPrimary(primary, byKey.get(dup))
        for (const key of [stated, ...live]) {
          if (key !== primary.key) mergedInto.set(key, primary.key)
        }
      }
    }
  } else {
    log(
      'no collisions beyond the ' + autoMerged + ' pair(s) merged deterministically; dedup agent skipped'
    )
  }
  return dedupAgents
}

// ------------------------------------------------------------------------ main
//
// The whole workflow, phase by phase. Each phase is a function above; this top-level
// code is the entry point and reads as the algorithm.

phase('Detect')
const detect = await runDetect()
const assignments = toAssignments(detect)
recordClassEvidence(detect)
const { selected, dropped: platformDropped } = selectGroups(detect)
log(
  assignments.length + ' review assignment(s); ' + selected.length + ' live group(s); ' +
    evidenceById.size + ' class(es) with a cited candidate site'
)
if (platformDropped.length) {
  log(
    platformDropped.length + ' class(es) dropped before anything looked, by the platform ' +
      'flags or the threat model: ' + platformDropped.join(', ')
  )
}

// The barrier after review is deliberate: the gate diffs the whole ledger and the sweep
// is chosen by what has no entry in it.
phase('Review')
const reviewResults = await runReview(assignments, detect)

phase('Sweep')
const { sweepResults, silentByGroup, ruledOut, stillSilent } = await runSweep(
  detect,
  selected,
  reviewResults
)
const { producers, rawFindings, notes, byKey } = collectProducers(reviewResults, sweepResults)

phase('Dedup')
const mergedInto = tier1(rawFindings)
const autoMerged = autoMergeNearby(rawFindings, mergedInto)
const dedupAgents = await runDedup(rawFindings, byKey, mergedInto, autoMerged)
const primaries = rawFindings.filter((f) => !mergedInto.has(f.key))
log(primaries.length + ' primaries after dedup (' + mergedInto.size + ' merged)')

phase('Assemble')
const groupsAttempted = selected.map((s) => s.group.id)
// Bug-class group ids, NOT part ids: only the class sweep can lose CLASSES — a failed
// location reviewer loses lines, reported through `agentFailures`. A sweep whose part
// file was never written counts as died, exactly as `recordClasses` treats it.
const sweepDied = producers.some(
  (e) => e && e.partId === 'sweep-classes' && (!e.result || e.result.part_written === false)
)
// Only the groups the sweep was actually GIVEN, or the report prints "their classes are
// uncovered" for classes that produced findings.
const groupsFailed = sweepDied ? silentByGroup.map((g) => g.group.id) : []
const assembled = await agent(
  assemblePrompt(
    partsExpected,
    partsComplete,
    partsExternal,
    groupsAttempted,
    groupsFailed,
    agentFailures
  ),
  workerOpts({ label: 'assemble', phase: 'Assemble', schema: ASSEMBLE_SCHEMA, effort: 'low' })
).catch(died('assemble'))

// Everything below distinguishes ABSENT from zero or false: `assembled` is one agent's
// transcription of an exit code, and a count nobody copied is a measurement nobody took.
// An agent that never came back is UNKNOWN, not a lost report.
const artifactsWritten = assembled ? assembled.artifacts_written === true : null
if (!assembled) {
  log(
    'WARNING: the assemble agent returned nothing, so whether findings.json, REPORT.md and ' +
      'REPORT.sarif were written is UNKNOWN — the command may have completed and only its ' +
      'structured answer failed. List ' + OUTPUT_DIR + ' before re-running anything; the part ' +
      'files are intact under ' + PARTS_DIR + '.'
  )
} else if (!assembled.ok || !artifactsWritten) {
  // `{ok: true, artifacts_written: false}` — exit 0 with no artifacts on disk — must not
  // be the quietest return in the block.
  log(
    'WARNING: ' +
      (artifactsWritten
        ? 'the artifacts were written but the coverage gate REJECTED this run: '
        : 'artifacts were not written: ') +
      (assembled.error ||
        (assembled.ok
          ? 'the assemble agent reported the script exited 0 and the artifacts are NOT in ' +
            OUTPUT_DIR
          : 'no reason given')) +
      '. The part files are intact under ' + PARTS_DIR + '; re-run assemble_findings.py by hand.'
  )
}
// null when the agent did not transcribe a count: defaulting to 0 turns "nobody looked"
// into "there were none".
const unrecognisedParts = (assembled && Number.isFinite(assembled.unrecognised_parts)) ? assembled.unrecognised_parts : null
// `coverage: null` means unmeasured, not zero; the branches below log which of its three
// causes applied.
const checksRequired = (assembled && Number.isFinite(assembled.checks_required)) ? assembled.checks_required : null
const checksSatisfied =
  assembled && Number.isFinite(assembled.checks_satisfied) ? assembled.checks_satisfied : null
if (checksRequired === null) {
  log(
    'WARNING: no coverage number came back, so ledger coverage is UNMEASURED, not complete. ' +
      'Either the assembler did not run, or units.json is not in ' + OUTPUT_DIR + ', or the ' +
      'assemble agent did not copy checks_required. Read ' + OUTPUT_DIR + '/ledger-gate.json.'
  )
} else if (checksRequired === 0) {
  log('WARNING: the ledger gate required 0 checks; nothing was verified against the unit parse.')
} else if (checksSatisfied !== checksRequired) {
  // The agent reported `ok`, the artifacts are on disk, and only the counts disagree —
  // the one rejection shape no branch above reaches.
  log(
    'WARNING: the coverage gate REJECTED this run — ' + checksSatisfied + ' of ' +
      checksRequired + ' required check(s) satisfied. The part files are intact under ' +
      PARTS_DIR + '; re-run assemble_findings.py by hand.'
  )
}
if (unrecognisedParts === null) {
  log(
    'WARNING: the assembler did not return an unrecognised-part count, so whether any part file ' +
      'under ' + PARTS_DIR + ' matched no assembler rule is UNCHECKED, not none. Read the ' +
      'assemble_findings.py output, or list ' + PARTS_DIR + ' against the dispatched part ids.'
  )
} else if (unrecognisedParts) {
  log(
    'WARNING: ' + unrecognisedParts + ' part file(s) under ' + PARTS_DIR + ' match no assembler ' +
      'rule, so their findings are in NO artifact. A misnamed stem is one agent\'s whole output ' +
      'dropped; check the names against the dispatched part ids.'
  )
}

// `ok` is an unverified transcription, so the gate is accepted only when the numbers in
// the same return agree with it: artifacts on disk, a non-empty measurement
// (`checksRequired > 0` — a gate that measured NOTHING is not a gate that passed), and
// every required check satisfied.
const gateAccepted = !!(
  assembled &&
  assembled.ok &&
  artifactsWritten &&
  checksRequired !== null &&
  checksRequired > 0 &&
  checksSatisfied === checksRequired
)
// `artifactError` carries a reason for every failure the checks above can reach; deriving
// it from `ok` alone would return a failure with no reason in it.
const gateError = !assembled
  ? 'assemble agent returned nothing'
  : assembled.error ||
    (!artifactsWritten
      ? 'the assemble agent reported the script exited 0 and findings.json, REPORT.md and ' +
        'REPORT.sarif are not all in ' + OUTPUT_DIR
      : checksRequired === null
        ? 'the assemble agent returned no coverage numbers, so the gate is unmeasured'
        : checksRequired === 0
          ? 'the assemble agent reported ok with 0 required checks, so nothing was ' +
            'verified against the unit parse'
        : checksSatisfied !== checksRequired
          ? 'the assemble agent reported ok with ' + checksSatisfied + ' of ' + checksRequired +
            ' required check(s) satisfied, which is a gate rejection'
          : // `error` is optional in ASSEMBLE_SCHEMA, so `ok: false` alone must still
            // come back with a reason attached.
            'the assemble agent reported that assemble_findings.py did not exit 0, ' +
            'without saying why')

return {
  outputDir: OUTPUT_DIR,
  artifactsWritten: artifactsWritten,
  gateAccepted: gateAccepted,
  artifactError: gateAccepted ? null : gateError,
  findingsJson: OUTPUT_DIR + '/findings.json',
  reportMd: OUTPUT_DIR + '/REPORT.md',
  reportSarif: OUTPUT_DIR + '/REPORT.sarif',
  unitsJson: OUTPUT_DIR + '/units.json',
  ledgerGateJson: OUTPUT_DIR + '/ledger-gate.json',
  // No judge ran. Severity on every finding is the reviewer's own and nothing
  // rejected anything, so the skill has to say so next to the findings.
  judgeRan: false,
  // Agents that came BACK, not agents that were dispatched; the failures are in
  // `agentFailures`.
  stats: {
    agents_total:
      1 +
      reviewResults.filter((e) => e && e.result).length +
      sweepResults.filter((e) => e && e.result).length +
      dedupAgents +
      (assembled ? 1 : 0),
    review_agents: reviewResults.filter((e) => e && e.result).length,
    review_agents_dispatched: assignments.length,
    sweep_agents: sweepResults.filter((e) => e && e.result).length,
    dedup_agents: dedupAgents,
    auto_merged: autoMerged,
    raw_findings: rawFindings.length,
    merged: mergedInto.size,
    primaries: primaries.length,
    reported: assembled && Number.isFinite(assembled.reported) ? assembled.reported : null,
  },
  // From the in-process ledger gate (per-row detail in ledger-gate.json). `satisfied` is
  // the honest number: a rejected row was answered but is not coverage.
  coverage: checksRequired === null
    ? null
    : {
        checksRequired: checksRequired,
        checksCompleted: Number.isFinite(assembled.checks_completed) ? assembled.checks_completed : null,
        checksSatisfied: Number.isFinite(assembled.checks_satisfied) ? assembled.checks_satisfied : null,
      },
  groupsAttempted: groupsAttempted,
  groupsFailed: groupsFailed,
  agentFailures: agentFailures,
  unrecognisedParts: unrecognisedParts,
  notes: notes,
  // Three coverage stories: swept and still silent; silent and never swept (detect cited
  // no candidate site); dropped by platform or threat model before anything looked.
  silentClasses: stillSilent,
  ruledOutClasses: ruledOut,
  platformDroppedClasses: platformDropped,
}
