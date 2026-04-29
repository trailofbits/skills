# Decision Mode

Use for approach selection, architecture choice, tool selection, strategy debates — any case where the claim is "X is the best way to do Y."

## When to pick decision mode

- "Should we use X or Y?"
- "Is this the right architecture?"
- "Is strategy A better than strategy B?"
- Any comparison between 2+ alternatives
- Any design decision before implementation

If the claim is "this bug is real" or "this vulnerability exists," use [proof-mode.md](proof-mode.md) instead.

## Required inputs before dispatching

1. **The claim** — one sentence, falsifiable, names the preferred option
2. **The alternatives** — explicit list of competing options (2-4 is ideal)
3. **Evaluation dimensions** — 3-5 axes the agents should address
4. **Evidence available** — known facts, prior findings, constraints both agents can cite

## Structure of decision-mode arguments

Each agent should produce arguments organized by dimension:

**Advocate output shape:**
```
## Why {CLAIM} is the best approach

### Dimension 1: {e.g., "Bug-finding effectiveness"}
- Specific claim with evidence
- Specific claim with evidence
- Pre-refutation of obvious counter

### Dimension 2: {e.g., "Implementation effort"}
- ...

### Dimension 3: {e.g., "Speed / throughput"}
- ...

## Summary: why the alternatives fail
- Alternative A fails at ... because ...
- Alternative B fails at ... because ...
```

**Skeptic output shape:**
```
## Why {CLAIM} is wrong

### Structural flaw
- The core reason the claim's logic doesn't hold
- Evidence

### Dimension 1: {e.g., "Oracle problem"}
- Specific objection with evidence
- Pre-refutation of obvious counter

### Dimension 2: {e.g., "False positive rate"}
- ...

## Summary: why one of the alternatives is actually best
- Alternative X wins at ... because ...
```

## Common dimensions to include

Pick 3-5 that fit your claim:

| Dimension | What to argue |
|-----------|---------------|
| **Effectiveness** | Does it actually find/solve the target problem? |
| **Effort / cost** | Time, lines of code, dependencies added |
| **Speed / throughput** | Execution time, iterations per second, latency |
| **False positive / false negative rate** | Signal-to-noise ratio |
| **Maintenance burden** | Who owns it, how brittle |
| **Precedent** | Has it worked before, in what domains, at what scale |
| **Oracle / correctness** | How do you know the answer is right |
| **Composability** | Does it combine well with existing systems |
| **Reversibility** | If wrong, how hard to back out |
| **Risk** | Worst-case outcome |

## Synthesis for decision mode

The verdict table should have one row per dimension. For each dimension, pick which side made the stronger argument and explain why.

Example verdict row:
| Dimension | Advocate says | Skeptic says | Verdict |
|-----------|---------------|--------------|---------|
| Oracle correctness | Native ARM64 compile is a valid reference | Clang can miscompile; need Intel HW to disambiguate | **Skeptic wins** — advocate didn't address the compiler-bug-vs-translator-bug ambiguity. |

The **recommendation** paragraph should:
- State which overall approach wins
- List the 2-3 skeptic points that matter for the winner (qualifications)
- State what the caller should actually do next

## Example: full decision-mode pass

Claim: "Track 2 (persistent harness + comparator fix) is the best next step for the Rosetta 2 differential fuzzer."

Advocate dimensions: speed gain (10x), unblocks semantic bug detection, low effort (days not weeks)

Skeptic dimensions: still no ARM64 execution, still only finds crashes, Track 3 has higher ceiling

Verdict:
| Dimension | Verdict |
|-----------|---------|
| Short-term speed | Advocate wins — 10x is 10x |
| Semantic bug detection | Skeptic wins — Track 2 doesn't add ARM64 execution |
| Long-term ceiling | Skeptic wins — Track 3 is required eventually |
| Effort-to-value ratio | Advocate wins — Track 2 is days, Track 3 is weeks |

Recommendation: Do Track 2 now because speed gain is real and blocking. Plan Track 3 as the next major work item.
