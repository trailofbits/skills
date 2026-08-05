# Reference toolchains

Reference is the one quadrant that must not be hand-written prose. It describes the machinery, so it has to be generated *from* the machinery — anything else drifts within a release and then actively misleads, which is worse than being absent.

This file is for the reference agent: pick a generator, scaffold it, write the doc comments, wire the build.

## Pick the generator

Prefer the language's native, conventional generator over whatever is technically nicer. The value is that a future contributor recognizes it and keeps it working.

| Language | Generator | Config to create | Comment syntax | Build command |
|----------|-----------|------------------|----------------|---------------|
| C / C++ | Doxygen | `Doxyfile` | `/** … */` with `@param`, `@return`, `@brief` | `doxygen Doxyfile` |
| Python | Sphinx + `autodoc` | `docs/conf.py`, `docs/index.rst` | Docstrings, Google or NumPy style via `napoleon` | `sphinx-build -b html docs docs/_build` |
| Python (MkDocs sites) | `mkdocstrings` | `mkdocs.yml` | Same docstrings | `mkdocs build` |
| Rust | rustdoc | none — built in | `///` and `//!`, with `# Examples` doctests | `cargo doc --no-deps` |
| Go | pkgsite / `go doc` | none — built in | Comment directly above the declaration, starting with the identifier name | `go doc ./...` |
| TypeScript / JavaScript | TypeDoc | `typedoc.json` | TSDoc `/** … */` | `npx typedoc` |
| Java | Javadoc | usually already in the build file | `/** … */` with `@param`, `@return`, `@throws` | `./gradlew javadoc` or `mvn javadoc:javadoc` |
| Ruby | YARD | `.yardopts` | `# @param`, `# @return` | `yard doc` |
| Solidity | NatSpec + `forge doc` | `foundry.toml` `[doc]` section | `/// @notice`, `/// @param`, `/// @dev` | `forge doc` |
| C# | DocFX or built-in XML docs | `docfx.json` | `/// <summary>` | `docfx build` |
| Swift | DocC | `Package.swift` target | `///` | `swift package generate-documentation` |

**Choosing in a polyglot repo.** Do not scaffold four generators. Pick by *public surface*, not by line count: the language a consumer of this project actually calls into. A Rust core with a Python binding and a shell test harness gets rustdoc plus Sphinx for the binding — the shell scripts get a how-to, not a reference. If two languages genuinely both present public API, scaffold both and give `docs/reference/index.md` a section per language.

**If a generator is already configured, use it.** Extend the existing config; do not replace it with a preferred one. Report in the manifest that you adopted an existing toolchain.

## Doc comments are the actual deliverable

The config is ten minutes of work. The reference quality comes entirely from the comments in the source, and this is where the agent spends its effort.

Cover the **public surface first and completely** before improving anything internal: exported functions, types, methods, constants, CLI commands and flags, configuration keys, environment variables, error types. A reference with 100% coverage of the public API and nothing else beats one with 40% coverage spread evenly.

For each symbol, write what a reader looking it up needs:

- What it is, in one sentence that does not restate the name. `// GetUser gets a user` is noise; delete-and-rewrite it rather than leave it.
- Every parameter: meaning, units, valid range, what happens at the boundaries.
- The return value, including what is returned on the empty or degenerate case.
- Errors and exceptions raised, and the condition for each.
- Anything a caller cannot infer from the signature: mutation of arguments, thread-safety, blocking behavior, ordering guarantees, resource ownership, whether the result aliases an input.

That last group is the highest-value writing in the whole run. A signature already tells the reader the types; it never tells them that the returned slice aliases internal state.

Keep it austere. No rationale (that's explanation), no recommendations (that's how-to), no scenarios. One minimal example per symbol is acceptable where form is non-obvious — a doctest in Rust or Python earns its place because it is also a test.

## Hard constraints when editing source

The reference agent modifies source files. These are not negotiable:

- **Comments and documentation only.** Never change a statement, a signature, a name, or a default. If a doc comment is impossible to write because the behavior is genuinely unclear, say so in the manifest — do not "clarify" the code.
- **Do not delete or rewrite an existing accurate comment.** Extend it. If an existing comment is *wrong*, fix it and list it in the manifest under `correctedComments` so a human reviews that specific change.
- **Match the file's existing style.** If the file uses NumPy docstrings, do not introduce Google style. If it wraps at 80, wrap at 80.
- **Do not reformat.** No touching indentation, import order, or line wrapping outside the comment you are writing. It buries the real change in diff noise.

## Wire it up so it stays alive

Generated reference that nobody builds rots as fast as hand-written reference. Before finishing:

1. Write `docs/reference/index.md` explaining what is generated, the exact build command, and where output lands.
2. Add the build command to whatever the project already uses — a `Makefile` target, a `just` recipe, a `package.json` script, a `tox`/`nox` environment. Follow the project's convention; do not introduce a new runner.
3. Add generated output directories to `.gitignore` (`docs/_build/`, `target/doc/`, `docs/api/`). Generated artifacts do not belong in version control. Include what the *build itself* leaves behind, not just its output — Sphinx autodoc imports the package and drops `__pycache__/`, TypeDoc leaves `.tsbuildinfo`. Run the build once and check `git status`; anything new that you did not intend to commit belongs in the ignore list.
4. Note in the manifest whether CI builds the docs. If it does not, say so — recommending a CI step is a legitimate finding, but adding one is outside this run's remit unless the project already has a docs job.

## Reporting

The manifest returned by the reference agent must include, at minimum: the generator chosen and why, whether it was adopted or newly scaffolded, the count of public symbols found versus documented, the files whose source was edited, any comments corrected, and any public symbol left undocumented with the reason. An agent that documented zero symbols is a failed run, not a clean one.
