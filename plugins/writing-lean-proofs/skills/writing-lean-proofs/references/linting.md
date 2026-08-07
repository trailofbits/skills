# Linting: gates in CI early, custom linters for your own constructs

## Contents

- [The sorry gate: ask the kernel, not grep](#the-sorry-gate-ask-the-kernel-not-grep)
- [Choose a project-specific linter profile](#choose-a-project-specific-linter-profile)
- [Adopting a linter that is not yet clean](#adopting-a-linter-that-is-not-yet-clean)
- [Custom linters](#custom-linters-every-project-convention-worth-having-is-worth-one)
- [Prove every check can fail](#prove-every-check-can-fail-before-trusting-that-it-passes)

**Set up an appropriate linter set, gated in CI, at the start of the project — and
write a custom linter for every project-specific convention.** Bugs and
unidiomatic proof patterns propagate by copy-paste: the first bad `simp` call
becomes the template for the next fifty, and a linter adopted late meets a
backlog instead of a single bad line (measured in one project: one deferred
linter had accumulated 438 warnings across 25 files; adopted on day one it
would have flagged one). Review does not substitute — the first simp-normal-
form linter found 100+ redundant simp lemmas in Mathlib that had all passed
expert maintainer review. This matters doubly when a model writes the Lean:
models follow a convention *almost* everywhere and forget the step with no
visible symptom; only a linter reliably catches "the attribute is missing on
29 of 30 declarations".

## The sorry gate: ask the kernel, not grep

Gate unproved obligations with axiom collection, never `grep sorry`. Grep is
wrong in both directions: it matches the word in comments and docstrings, and
it misses a theorem whose own text is clean but which applies an unproved
helper. `Lean.collectAxioms` catches exactly the real cases:

```lean
-- Save as scripts/AxiomCheck.lean in YOUR project; CI runs:
--   lake env lean scripts/AxiomCheck.lean
import MyProject
open Lean

/-- Axioms the library is known and intended to depend on. Anything else —
    a new `sorry`, a stray `native_decide` — fails loudly. -/
def expectedAxioms : List Name := [``propext, ``Classical.choice, ``Quot.sound]

/-- Is this declaration defined in one of our own modules (not Mathlib etc.)? -/
def isOurs (env : Environment) (n : Name) : Bool :=
  match env.getModuleIdxFor? n with
  | none => false          -- defined in the current file, not the library
  | some idx =>
      match env.header.moduleNames[idx.toNat]? with
      | some m => (`MyProject).isPrefixOf m
      | none => false

run_cmd Elab.Command.liftCoreM do
  let env ← getEnv
  let mut checked := 0
  for (n, _) in env.constants.toList do
    unless isOurs env n && !n.isInternal && !n.hasMacroScopes do continue
    checked := checked + 1
    let axs ← collectAxioms n
    if axs.contains ``sorryAx then throwError "unproved: {n}"
    let bad := axs.filter (!expectedAxioms.contains ·)
    unless bad.isEmpty do throwError "unexpected axioms on {n}: {bad.toList}"
  if checked == 0 then
    throwError "module filter matched nothing — the check is vacuous"
```

Assert the **whole footprint**, not just `sorryAx`: listing the expected
axioms turns "we think nothing else crept in" into a checked claim, so a new
trust assumption (someone adding `native_decide`) fails instead of landing
silently. And note the final line — see "Prove every check can fail" below.

## Choose a project-specific linter profile

Do **not** enable `linter.mathlibStandardSet` wholesale just because a project
depends on Mathlib. At Mathlib commit
[`50a1a360`](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Init.lean),
the set contains 26 lints with four different jobs:

- proof robustness and debugging;
- reusable public-API design;
- optional source-formatting conventions; and
- Mathlib's own repository policy.

Those are appropriate defaults for Mathlib, not one indivisible policy for
every downstream package. Select individual options according to who will
consume the code, and re-audit the list when updating the pinned Mathlib
revision.

### Recommended profile: self-contained project or proof

For a finished proof, executable specification, verification artifact, or
application whose declarations are not a downstream API, start with the
checks that prevent fragile proof scripts and leftover debugging state:

```lean
leanOptions := #[
  ⟨`weak.linter.auxLemma, true⟩,
  ⟨`weak.linter.style.maxHeartbeats, true⟩,
  ⟨`weak.linter.style.multiGoal, true⟩,
  ⟨`weak.linter.style.setOption, true⟩,
  ⟨`weak.linter.style.show, true⟩
]
```

Add `linter.flexible` if the artifact will be maintained across dependency
updates; it makes intermediate broad automation such as bare `simp` more
explicit, but can impose substantial cleanup on a short-lived proof. Add
the deprecated-syntax checks only when the project deliberately follows
Mathlib's tactic style. Do not enable public-API or documentation lints
merely to make the profile resemble Mathlib.

### Recommended profile: reusable library

For a library intended to be imported by other projects, also protect API
generality, module structure, and upgrade resilience:

```lean
leanOptions := #[
  ⟨`weak.linter.auxLemma, true⟩,
  ⟨`weak.linter.flexible, true⟩,
  ⟨`weak.linter.style.maxHeartbeats, true⟩,
  ⟨`weak.linter.style.missingEnd, true⟩,
  ⟨`weak.linter.style.multiGoal, true⟩,
  ⟨`weak.linter.style.openClassical, true⟩,
  ⟨`weak.linter.style.setOption, true⟩,
  ⟨`weak.linter.style.show, true⟩,
  ⟨`weak.linter.unusedDecidableInType, true⟩,
  ⟨`weak.linter.unusedFintypeInType, true⟩
]
```

This is a starting profile, not another aggregate to copy blindly. A library
with intentionally broad automation may omit `linter.flexible`; a package
whose modules are generated may omit structural style checks.
`linter.style.nameCheck` is not a member of `mathlibStandardSet`; it defaults
to `true` and catches double underscores, not the whole Mathlib naming
convention. A library adopting that convention should also run Batteries'
`#lint defsWithUnderscore` and use review for the rules no linter covers.

Apply the classification per target or module, not merely per repository. A
reusable library commonly includes terminal examples, tests, and regression
fixtures for which its public-source policy is inappropriate.

### Audit of every standard-set member

`Enable` means it belongs in the profile above. `Consider` means its value
depends on expected maintenance or local conventions. `Policy` requires an
explicit trust or repository decision. `Avoid` means that enabling it without
narrow scoping is likely to reject legitimate downstream code.

| Lint | What it protects | Reusable library | Self-contained project / proof |
|------|------------------|------------------|--------------------------------|
| `linter.auxLemma` | Avoids references to generated names such as `_proof_1` that can change after unrelated edits | Enable | Enable |
| `linter.flexible` | Makes non-terminal broad tactics such as bare `simp` explicit, reducing dependence on a changing environment | Enable for maintained libraries | Consider when upgrades matter |
| `linter.hashCommand` | Flags silent `#` commands, and all `#` commands under `warningAsError` | Consider only in production modules that forbid such probes | Usually omit: `#guard` may be an intentional assertion |
| `linter.oldObtain` | Replaces a Lean 3-style `obtain` form with an explicit proof block | Consider as readability style | Consider as readability style |
| `linter.privateModule` | Flags nonempty modules that expose only private declarations | Consider for modules meant to be imported; omit terminal and test modules | Avoid for terminal test and proof modules |
| `linter.style.cases` | Rejects Mathlib's discouraged `cases'` syntax | Consider when adopting Mathlib tactic style | Consider when adopting Mathlib tactic style |
| `linter.style.induction` | Rejects Mathlib's discouraged `induction'` syntax | Consider when adopting Mathlib tactic style | Consider when adopting Mathlib tactic style |
| `linter.style.refine` | Rejects Mathlib's discouraged `refine'` syntax | Consider when adopting Mathlib tactic style | Consider when adopting Mathlib tactic style |
| `linter.style.cdot` | Enforces Mathlib's spelling of the centered dot | Project style | Project style |
| `linter.style.docString` | Enforces Mathlib docstring formatting, not documentation coverage | Consider when adopting Mathlib documentation style | Usually omit |
| `linter.style.dollarSyntax` | Prefers `<|` over `$` | Project style | Project style |
| `linter.style.emptyLine` | Rejects blank lines within declarations | Project style; can be noisy | Project style; can be noisy |
| `linter.style.header` | Enforces Mathlib's license header, module docstring, and import restrictions | Avoid unless deliberately matching the exact Mathlib repository policy | Avoid |
| `linter.style.lambdaSyntax` | Prefers `fun` over `λ` | Project style | Project style |
| `linter.style.longLine` | Enforces a configurable line-length limit | Project style | Project style |
| `linter.style.longFile` | Enforces a chosen file-length limit; this option is a number, not a Boolean | Consider only with a locally chosen limit | Usually omit; generated artifacts may be long |
| `linter.style.multiGoal` | Prevents tactics from depending silently on the order of several active goals | Enable | Enable for finished, maintainable proofs |
| `linter.style.nativeDecide` | Warns about compiler-backed `native_decide` and `decide +native` | Policy: enable if the trust model forbids them | Policy: choose explicitly |
| `linter.style.openClassical` | Discourages global classical scope that can hide unnecessarily strong theorem assumptions | Enable for public APIs | Consider when theorem statements are reused |
| `linter.style.maxHeartbeats` | Requires an explanation next to scoped heartbeat overrides | Enable | Consider when budgets are allowed |
| `linter.style.missingEnd` | Makes namespace and section boundaries explicit | Enable | Consider for multi-section files |
| `linter.style.setOption` | Catches leftover traces, profilers, pretty-printer flags, and unscoped sensitive options | Enable outside dedicated fixtures | Enable outside dedicated fixtures |
| `linter.style.show` | Prevents `show` from silently changing the target; requires honest `change` | Enable | Enable |
| `linter.style.whitespace` | Enforces Mathlib declaration spacing | Project style | Project style |
| `linter.unusedDecidableInType` | Removes an unnecessary `Decidable` assumption from a theorem's public type | Enable | Consider only when statements are reused |
| `linter.unusedFintypeInType` | Removes or weakens an unnecessary `Fintype` assumption in a theorem's public type | Enable | Consider only when statements are reused |

The behavior classifications above come from the corresponding current
Mathlib implementations: [auxiliary names](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/AuxLemma.lean),
[flexible tactics](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/FlexibleLinter.lean),
[`#` commands](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/HashCommandLinter.lean),
[legacy `obtain`](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/OldObtain.lean),
[private modules](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/PrivateModule.lean),
[deprecated syntax](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/DeprecatedSyntaxLinter.lean),
[general style](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/Style.lean),
[docstrings](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/DocString.lean),
[empty lines](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/EmptyLine.lean),
[headers](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/Header.lean),
[multiple goals](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/Multigoal.lean),
[whitespace](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/Whitespace.lean),
and [unused instances](https://github.com/leanprover-community/mathlib4/blob/50a1a3609f97d1a965d8eaba5088d846dab11dce/Mathlib/Tactic/Linter/UnusedInstancesInType.lean).

### Make the selected profile an actual gate

Most standard-set members are **off by default in dependent projects**. Five
mechanics matter:

- **`leanOptions` reach every module, and `-D` on an unregistered option is a
  hard error** — a Mathlib-provided `linter.style.*` option breaks any module
  in your package that imports only core Lean. The `weak.` prefix is the
  escape hatch: `⟨`weak.linter.style.multiGoal, true⟩` sets the option where
  it is registered and ignores it where it is not.
- **Use fully qualified individual option names.** Note that
  `linter.flexible` and the two `linter.unused*InType` options are not under
  `linter.style`. Reconfirm every name against the project's pinned Mathlib
  revision. Then add a known-trigger fixture for every option: the `weak.`
  prefix deliberately ignores unknown options, so a typo otherwise produces
  a green build with no linter running.
- **A linter is only a gate if warnings fail the build.** Check what you are
  *already* passing before adopting anything new: ~30 linters can be on and
  clean while nothing protects that compliance. Locking in what you already
  satisfy is cheaper and higher-value than any new adoption. Mechanically,
  warnings-as-errors is a CI step:

  ```sh
  set -o pipefail                        # or the build failure vanishes into tee
  lake build MyProject 2>&1 | tee build.log
  # Vacuity anchor: Lake caches per-module artifacts and linter warnings are
  # emitted only when a module is *recompiled*. On a restored cache with
  # nothing to rebuild, build.log is empty, the grep below matches nothing,
  # and the gate reports clean over live warnings and sorries. Prove the
  # sweep reached something before trusting its silence.
  grep -qE "^(info: )?\[[0-9]+/[0-9]+\]" build.log \
    || { echo "gate is vacuous: lake compiled no module" >&2; exit 1; }
  ! grep -n "warning:" build.log         # any warning (linter or sorry) fails CI
  ```

  The anchor is what makes this a gate rather than a report; the alternative
  is to build the gating job from a cold cache. This is the same discipline
  the `checked == 0` guard enforces in `AxiomCheck.lean` above, and the same
  one the sweep-counting rule below states in general — a check that cannot
  observe its own reach cannot fail.
- **Anything outside the default build target rots silently.** A test or
  regression file that nothing builds stops compiling and nobody notices.
  Give such files their own `lean_lib` target in the lakefile and build that
  target explicitly in CI.
- **Run declaration-level linters too.** The `leanOptions` profiles above
  activate syntax and command linters; they do not replace Batteries'
  `#lint`, whose checks include `simpNF`. Give the linter file a build target
  and execute it explicitly in CI.

When policy enables a lint, exempt a sanctioned violation **locally, never
globally**: `set_option linter.style.nativeDecide false in` immediately above
the one permitted use, with a comment saying why. The linter stays on
library-wide, so a *new* violation still fails, and the exemption is visible
exactly where a reviewer needs it.

## Adopting a linter that is not yet clean

- **A gate that fails is not a gate.** Enable a linter only once it reports
  zero; until then run it advisory with the *measured* backlog recorded next
  to it, and promote it when it reaches zero. Writing the count down is what
  keeps the backlog actionable and stops a later reader assuming the linter
  was rejected on principle.
- **Counts from a failed build are meaningless.** Modules that never compiled
  were never linted; a partial build reports a partial count that reads
  exactly like a clean result. Confirm the build reached the end first.
- **Reported counts can be lower bounds.** `linter.flexible` propagates a
  "stain" that stops at the first fix, so pinning one flagged `simp` unmasks
  the next in the same ladder (measured undercounts of 3×). When a file has a
  repeated idiom, fix *every* occurrence in one pass.
- **Never paste a linter's own `Try this:` suggestion.** The flexible
  linter's suggested `simp only [...]` list comes from re-running a *default*
  `simp`, dropping the arguments the original call passed. Run `simp?` in
  place instead. A tool's suggested fix is a hint about the shape of the fix,
  not a patch.
- **Rank the backlog by warnings-per-edit, not warnings.** One line can carry
  37 warnings and cost one token; a copy-pasted six-line idiom can hold a
  third of the total. Sort the work by idiom, most-duplicated first.
- Adopt for **your** consumers: Mathlib's set is calibrated for a
  million-line library with thousands of downstream users. A verification
  project with a small team should weight correctness- and trust-protecting
  linters up and house-style linters down (e.g. `hashCommand` is wrong for a
  test suite whose `#guard`s *are* the assertions).

## Custom linters: every project convention worth having is worth one

Any new construct your project introduces — a simp-set discipline, a naming
scheme for summary lemmas, an attribute that downstream automation consumes —
will be misused, because nothing enforces it. Defining a linter is genuinely
easy; write one alongside the construct, not after the first regression.

The declaration-level kind (what Batteries' `#lint` runs) is one structure:

```lean
@[env_linter] def mySummaryTagged : Batteries.Tactic.Lint.Linter where
  noErrorsFound := "all execution summaries are tagged"
  errorsFound := "summaries missing @[my_summary]:"
  test n := do
    -- full MetaM access: inspect the type, attributes, docstring, environment
    ...return (some msg) to flag, none to pass
```

`@[nolint mySummaryTagged]` gives per-declaration exemptions for free. (The
other kind — a syntax-level linter à la `linter.style.*` — needs a
`register_option`, a `Linter where run`, and an `initialize addLinter`; the
extra boilerplate buys file-local `set_option … false in` opt-outs. Reach for
it when exemptions must be positional rather than per-declaration.) The
highest-value checks are **coverage invariants** no generic linter can
express — "every constructor the executor handles has a corresponding
soundness lemma" — where the failure mode (extend the executor, forget the
lemma) compiles cleanly and leaves no trace. Implement those as a
declaration-level linter that does its work anchored on one declaration and
returns `none` for everything else.

Engineering rules, each learned the hard way:

- **Prefer a linter over a script that greps source.** Anything checked by
  scraping text (attributes, naming, doc comments) is checkable against the
  *declaration*, where comments, formatting, and renames cannot fool it —
  the same argument that makes `collectAxioms` beat `grep sorry`.
- **Test the shape of a declaration, not its name.** A suffix-keyed linter
  flags look-alikes and misses restatements; match the actual conclusion.
- **Know which side you are checking.** A rewrite's LHS must match the goal;
  its RHS may deliberately use a different spelling that downstream lemmas
  expect. Any statement-syntax check must distinguish the two.
- **Private declarations are not where you think:** `private theorem foo`
  lives at `_private.<module>.0.foo`, so `env.contains ``foo`` ` reports it
  missing. Use `mkPrivateNameCore` per candidate module.
- **Do no expensive per-constant work while iterating `env.constants`.**
  Real work per foreign constant will not finish against a Mathlib-sized
  environment (a string-processing probe over it timed out at 400 s). A cheap
  module-membership filter per constant is fine — the axiom audit above does
  exactly that — but anything heavier belongs behind targeted `env.find?`
  lookups, so cost is O(things you care about), not O(everything Mathlib
  defines).
- **Self-police allowlists:** report entries that no longer exist and entries
  that now satisfy the rule, or the list quietly outlives its justification.
- **Budget the check itself.** A linter can exhaust a module's heartbeat
  budget normalizing a 110-equation match — turning a green module red. Prefer
  a documented local opt-out over abandoning the gate everywhere.
- **Say what the linter does *not* protect**, in its docstring, so a future
  reader does not over-trust it.

## Prove every check can fail before trusting that it passes

A check that silently never fires is indistinguishable from a clean codebase.
For every new gate — linter, sweep, axiom audit:

- Introduce a deliberate violation *and* a near-miss control; confirm the
  first is flagged and the second is not. This regularly finds vacuous
  linters (e.g. a normalization step that never matches, so every candidate
  "passes").
- **Build the vacuity check in permanently**: anchor a sanity assertion on
  one known declaration ("this attribute must exist", "checked > 0"), so the
  gate fails loudly rather than reporting a codebase it never examined.
- Watch the plumbing: plain `lean -Dname=value` rejects an unknown option,
  while `lean -Dweak.name=value` intentionally ignores one so packages can
  span modules with different imports. Verify a weak option in a module that
  imports its linter and include a known violation, or a typo can report zero
  findings. A `#lint` run piped through `tee` without `pipefail` exits 0 even
  when Lean crashed; `git ls-files
  'Proj/**/*.lean'` silently excludes top-level files (`*` in a git pathspec
  matches `/`; `**/` requires an intervening directory — the more
  explicit-looking spelling is the narrower one). Print and assert the number
  of files each sweep reached.
