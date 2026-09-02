# Recovery Mechanisms

Lookup table for Stage 1d (recovery) and Stage 3 challenge 2. **Many "crash"
findings are error responses.** Answer one question: at the panic/exception site,
does anything in the call stack catch it, and what impact actually survives?

Do not assume recovery is absent because you did not find it. A process-crash
claim needs positive evidence that nothing recovers.

---

## Summary table

The fastest path to an answer. Everything below this table is elaboration.

| Runtime / framework | Default behavior on panic or uncaught exception | Surviving impact | How to confirm |
|---|---|---|---|
| Go `net/http` | **Per-connection `recover()` in `conn.serve`** | That one connection is closed. **No status is written** — not a 500 | Handler panic does not stop the server; the client sees a dropped connection |
| Go Gin | Recovery middleware, included in `gin.Default()` | 500 | Check whether `gin.New()` was used instead |
| Go, general | No recovery unless `defer`/`recover` | Process crash | `grep -rn 'defer func' \| grep -A3 recover` |
| Rust, general | No recovery unless `catch_unwind` — and none at all under `panic = "abort"` | Panicking thread dies. That is the **process** only if it is `main` or the profile aborts; another thread's death is one thread | `grep -rn catch_unwind`, plus `panic =` in `Cargo.toml`, plus which thread the panic is on |
| Rust Actix-web | **No default panic recovery, and no 500** | That worker thread dies mid-request; the client sees a dropped connection and the process survives | Whether the server log shows a worker being replaced — do not assume either way |
| Node.js Express | **A synchronous throw IS caught** by the built-in error handler, with or without a custom one | 500 | Whether the handler is `async`: see the row below |
| Node.js Express, async handler | Express 4 does **not** catch a rejected promise; Express 5 forwards it to the error handler | Express 4: unhandled rejection, which on Node ≥15 exits the process. Express 5: 500 | The Express major version, and whether the route `await`s without a `try` |
| Node.js, general | Uncaught exception terminates unless a handler exists | Process exit | `grep -rn uncaughtException`, and `unhandledRejection` for the async case |
| Python Flask | Built-in error handler | 500 | Default behavior |
| Python Django | Middleware catches exceptions | 500 | Default behavior |
| Python, general | Uncaught exception unwinds to the interpreter and exits | Process exit | The absence of `try` is not the question — find the outermost frame |
| Python `asyncio` | **A task that raises dies alone.** The loop keeps running and logs "Task exception was never retrieved" — often only at GC | One task lost, silently | `grep -n 'create_task\|ensure_future'` and check who awaits the result |
| Python `threading` | An exception in a thread kills that thread only | One thread lost | `threading.excepthook`, and whether the thread was doing the only copy of the work |
| Java Spring Boot | Handled by the framework whether or not you register anything: `@ExceptionHandler` / `@ControllerAdvice` if present, otherwise `BasicErrorController` | 500 (the whitelabel error page, absent an advice class) | An advice class changes the *body*, not whether it is caught |
| Java, general | Uncaught exception kills the thread, not the JVM | One thread lost | `Thread.setDefaultUncaughtExceptionHandler` |
| C# / ASP.NET | Exception filter pipeline | 500 | Built-in middleware |
| Ruby on Rails | `ShowExceptions` middleware, on by default | 500 | Production serves the static error page; development renders the `DebugExceptions` diagnostic page (still a 500). The generated **test** env is the one that re-raises |
| PHP-FPM | Fatal error ends that request; the pool worker is reused or respawned | 500, pool survives | `max_children`, and whether the fatal leaks state |
| Erlang / Elixir | **Supervisor restarts the process by design** | Restart, state lost | The supervision tree, and the restart strategy and intensity |
| Rust `tokio` | A panicking task is captured in its `JoinHandle`; the runtime survives | One task lost | Whether anything inspects the `JoinError` |
| Go, `errgroup` / `WaitGroup` | Neither recovers — a panic in a member goroutine still takes the process | Process crash | `recover()` inside each goroutine, not around the group |
| WebAssembly | Trapped at the VM boundary | Call fails, host survives | Cannot escape the VM |
| Docker container | Container exits; the restart policy decides and **defaults to `no`** | Without `--restart`, the container stays down — not a blip | `docker inspect -f '{{.HostConfig.RestartPolicy.Name}}'`, or the Compose `restart:` key |
| Kubernetes pod | `restartPolicy: Always` by default, with exponential backoff | Restart; **`CrashLoopBackOff` if repeatable** | The liveness probe, and whether a crash loop is itself the DoS |
| systemd unit | `Restart=` decides, and defaults to `no` | Depends entirely on the unit file | `systemctl cat`, and `StartLimitBurst` |
| Subprocess | Child exits, parent observes | Isolated failure | Parent's `subprocess` handling |
| Serverless (Lambda etc.) | The invocation fails; the platform retries per its own policy | One invocation, possibly retried | Whether a retry re-triggers the bug, and whether the effect is idempotent |

---

## The two facts that most often flip a Critical to a Low

**Go's `net/http` recovers per connection.** A panic inside an HTTP handler is
caught by the deferred `recover()` in `conn.serve`, which logs the stack and
**closes that connection**. A finding written up as "remote attacker crashes the
server" is, in almost every `net/http` service, one dropped connection while the
server keeps accepting and answering everything else.

Be precise about what the client sees: `conn.serve` writes **no HTTP status**.
Saying it "returns a 500" is a plausible-sounding error, and an eval grader in
this plugin's own history demanded it — scoring six correct answers as failures
before anyone re-read the grader. Flask and Django *do* return a 500; `net/http`
does not.

**`recover()` does not cross goroutine boundaries.** The inverse of the above,
and the reason the same codebase can contain both a Low and a Critical. A panic
inside `go func() { ... }()` with no `recover()` *in that goroutine* takes down
the process, no matter what the enclosing handler does.

---

## Patterns that are usually false positives

- **"Panic in a Go HTTP handler crashes the server."** `net/http` catches it.
  Request error, not server crash.
- **"An exception in a Flask view crashes the server."** Flask's error handler
  catches it. 500, not a crash.
- **"A Rust panic always crashes."** Only without `catch_unwind`, and only on a
  thread whose death is the process's. Check both.
- **"An exception in an Express route crashes the server."** A synchronous throw
  is caught and answered 500 without any middleware of your own. The async
  rejection is the case worth checking.

## Patterns that are usually real crashes

- **Go panic in an unrecovered goroutine** — `recover()` does not reach it.
- **Rust panic on `main` with no `catch_unwind`** — unwinds out and the process
  exits 101. Under `panic = "abort"` any thread's panic aborts the process.
- **Node.js uncaught exception with no `uncaughtException` handler** — and, since
  Node 15, an unhandled promise rejection with no `unhandledRejection` handler,
  which terminates by default rather than warning.
- **Panic in `init()` or startup** — recovery is not installed yet. And this is
  the case where a restart policy makes things *worse*, not better: a crash in
  startup restarts into the same crash, which is a `CrashLoopBackOff` and an
  outage rather than a blip.
- **C/C++ segfault** — a signal, not an exception; nothing catches it by default.

## The third answer: recovered, and still a finding

The question is not binary. Recovery can exist and the impact survive anyway, and
these are the shapes that get written up as "recovered, therefore Low" when they
are not:

- **The restart is the denial of service.** A crash that is cheap to trigger and
  restarts in 100ms is a Low; the same crash under a Kubernetes backoff, reachable
  by an unauthenticated request, is an availability finding — the pod spends its
  life in `CrashLoopBackOff`. Ask how fast the attacker can re-trigger it relative
  to the restart, not just whether a restart happens.
- **State does not come back.** Erlang supervisors and container restarts both
  restore the *process*, not what it was holding: in-flight requests, unflushed
  buffers, an incomplete multi-step write. A recovered crash mid-transaction can
  leave inconsistency that outlives the recovery.
- **The recovery swallows the evidence.** A framework handler that turns every
  exception into a 500 also turns a detectable attack into ordinary error-rate
  noise. That does not raise severity by itself, but it belongs in the report,
  because it is why nobody noticed.
- **One lost task is not one lost request.** An `asyncio` task or a `tokio` task
  that dies alone is contained — unless it was the only thing draining a queue,
  renewing a lease, or expiring sessions. Check what the task was *for* before
  calling its loss contained.

Record the impact that survives, not the fact that something caught it.

---

## Verification checklist before claiming "process crash"

- [ ] Panic location identified (file:line)
- [ ] Execution path traced from entry point to the panic
- [ ] Call stack searched for recovery code
- [ ] Framework defaults checked against the table above
- [ ] Confirmed not inside a handler that the framework recovers
- [ ] Process isolation considered (container, subprocess, worker)
- [ ] Goroutine boundaries checked, if Go
- [ ] Crash actually observed in a dev environment

**If any of these is uncertain, do not claim a process crash.** There is no
"uncertain" value to return — the schema asks for a boolean `recoveryExists`, and
`false` is rendered downstream as the affirmative "no recovery found". So put the
unchecked item in `evidence` in as many words, and set `effectiveImpact` to the
impact you can actually evidence, not to the crash you could not rule in.

---

## When the runtime is not in the table

1. Identify the runtime and the web framework, including version.
2. Search for the recovery primitive by name — `recover`, `catch_unwind`,
   `uncaughtException`, `errorhandler`, `ControllerAdvice`. Search for the
   primitive, not for generic `try`/`except`, which matches everything and
   tells you nothing.
3. Read the framework's request-dispatch path: recovery, when it exists, is
   almost always installed there rather than in application code.
4. Confirm empirically. Trigger the condition in a dev environment and observe
   whether the process is still serving afterwards.

Add a row to the table when you resolve a runtime it does not cover.
