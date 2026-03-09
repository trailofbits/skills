# Evidence Templates

Use these templates when documenting verification evidence for each bug.

## Data Flow Documentation

```
Bug #N Data Flow Analysis
Source: [exact location] — Trust Level: [trusted/untrusted]
Path: Source → Validation1[file:line] → Transform[file:line] → Vulnerability[file:line]
Validation Points:
  - Check1: [condition] at [file:line] — [passes/fails/bypassed]
  - Check2: [condition] at [file:line] — [passes/fails/bypassed]
```

## Mathematical Bounds Proof

```
Bug #N Mathematical Analysis
Claim: Operation X is vulnerable to [overflow/underflow/bounds violation]
Given Constraints: [list all validation conditions]

Algebraic Proof:
1. [first constraint from validation]
2. [constant or known value]
3. [derived inequality]
...
N. Therefore: [vulnerability confirmed/debunked] (Q.E.D.)

Conclusion: [vulnerability is/is not mathematically possible]
```

**Example:**

```
Given: validation ensures (input_size >= MIN_SIZE)
Given: MIN_SIZE = 16, header_size = 8
Prove: (input_size - header_size) cannot underflow

1. input_size >= MIN_SIZE             (from validation)
2. MIN_SIZE = 16                      (constant)
3. header_size = 8                    (constant)
4. input_size >= 16                   (substitution of 1,2)
5. input_size - 8 >= 16 - 8          (subtract header_size from both sides)
6. input_size - header_size >= 8     (simplification)
7. Therefore: underflow impossible    (Q.E.D.)
```

## Attacker Control Analysis

```
Bug #N Attacker Control Analysis
Input Vector: [how attacker provides input]
Control Level: [full/partial/none]
Constraints: [what limits exist on attacker input]
Reachability: [can attacker-controlled data reach vulnerable operation?]
```

## PoC — Pseudocode with Data Flow Diagram

```
PoC for Bug #N: [Brief Description]

Data Flow Diagram:

[External Input] → [Validation Point] → [Processing] → [Vulnerable Operation]
     |                    |                   |                    |
  Attacker           (May be bypassed)    (Transforms data)   (Unsafe operation)
  Controlled              |                   |                    |
     |                    v                   v                    v
  [Malicious Data] → [Insufficient Check] → [Processed Data] → [Impact]

PSEUDOCODE:
function vulnerable_operation(user_data):
    validation_result = weak_validation(user_data)  // Explain why this fails
    processed_data = transform_data(user_data)      // Show transformation
    unsafe_operation(processed_data)               // Show vulnerability trigger
```

## Devil's Advocate Review

```
Bug #N Devil's Advocate Review
Vulnerability Claim: [brief description]

For each of the 13 questions from the devil's advocate review, document your answer:
1-11. [Challenges arguing AGAINST the vulnerability]
12-13. [Challenges arguing FOR the vulnerability — false-negative protection]

Final Assessment: [Vulnerability confirmed/debunked with reasoning]
```
