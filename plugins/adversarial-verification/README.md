# adversarial-verification

Stress-test claims, designs, and bug findings by dispatching two isolated sub-agents — one advocate, one skeptic — and synthesizing their arguments into a structured verdict.

## When to Use

- Choosing between competing technical approaches
- Reviewing a design decision before commit
- Any claim you're inclined to agree with by default
- Stress-testing your own reasoning when you suspect it may be one-sided

Deciding whether a security finding is a true or false positive belongs to `fp-check`, which does the data-flow tracing and exploitability analysis this skill does not.

## What It Does

Counters sycophancy and single-agent agreement bias by forcing maximal disagreement before committing. Each sub-agent runs in isolated context — the advocate never sees the skeptic's arguments and vice versa. After both return, the caller synthesizes a verdict table that picks winners per dimension and produces a concrete recommendation.

### Two modes

| Mode | Claim type | Structure |
|------|-----------|-----------|
| **Decision mode** | "X is the best approach" | Free-form arguments organized by evaluation dimensions |
| **Proof mode** | "X is real" — a perf regression, a reproducibility claim, a non-security assertion | N null hypotheses — skeptic proves, advocate refutes |

## Installation

```
/plugin marketplace add trailofbits/skills
/plugin install adversarial-verification
```
