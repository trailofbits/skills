# adversarial-verification

Stress-test claims, designs, and bug findings by dispatching two isolated sub-agents — one advocate, one skeptic — and synthesizing their arguments into a structured verdict.

## When to Use

- Choosing between competing technical approaches
- Verifying a bug finding is real (not a false positive)
- Reviewing a design decision before commit
- Any claim you're inclined to agree with by default
- Stress-testing your own reasoning when you suspect it may be one-sided

## What It Does

Counters sycophancy and single-agent agreement bias by forcing maximal disagreement before committing. Each sub-agent runs in isolated context — the advocate never sees the skeptic's arguments and vice versa. After both return, the caller synthesizes a verdict table that picks winners per dimension and produces a concrete recommendation.

### Two modes

| Mode | Claim type | Structure |
|------|-----------|-----------|
| **Decision mode** | "X is the best approach" | Free-form arguments organized by evaluation dimensions |
| **Proof mode** | "X is a real bug/finding" | N null hypotheses — skeptic proves, advocate refutes |

## Installation

```
/plugin marketplace add trailofbits/skills
/plugin install adversarial-verification
```
