# Mutation Testing — Campaign Configuration (mewt/muton)

Helps configure [mewt](https://github.com/trailofbits/mewt) or [muton](https://github.com/trailofbits/muton) mutation testing campaigns — scoping targets, tuning timeouts, and optimizing long-running runs so you can execute `mewt run` or `muton run` with confidence.

> **Note**: muton and mewt share identical interfaces. This plugin uses `mewt` in examples, but all commands work the same with `muton`. File names change accordingly: `mewt.toml` → `muton.toml`, `mewt.sqlite` → `muton.sqlite`.

## What It Does

Walks through a 5-phase configuration workflow:

1. **Initialize and validate targets** — run `mewt init`, review auto-generated config, fix include/ignore patterns
2. **Generate mutants and assess scope** — count mutants, time the test command, estimate campaign duration
3. **Decide on optimization** — choose between full run, targeted components, high/medium severity only, or two-phase campaign
4. **Validate test command and timeout** — verify the command works; set manual timeout for recompilation-heavy languages (Solidity/Foundry, heavy C++)
5. **Final validation checklist** — confirm config, mutant count, target selection, and timeout before running

## When to Use

- Setting up a new mutation testing campaign
- Optimizing a campaign that would take too long to run
- Diagnosing why no mutants are generated or why the test command fails

## Prerequisites

- [mewt](https://github.com/trailofbits/mewt) v3.0.0+ or [muton](https://github.com/trailofbits/muton) v3.0.0+ installed
- A test suite runnable from the command line
- Source code in a supported language (Rust, Solidity, Go, Python, JavaScript, C/C++)

## Example Usage

```
User: "Help me set up mewt for this Solidity project"
User: "Configure muton for this FunC codebase"
User: "My mewt campaign would take 30 hours — how do I optimize it?"
→ Guides through configuration, scope assessment, and optimization
```

## References

- [mewt GitHub Repository](https://github.com/trailofbits/mewt)
- [Use mutation testing to find the bugs your tests don't catch](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/) — Trail of Bits blog post
