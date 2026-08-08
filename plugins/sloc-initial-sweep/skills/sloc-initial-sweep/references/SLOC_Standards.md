# SLOC Counting Standards Reference

## Overview

This document defines the Source Lines of Code (SLOC) counting standards used in this skill.

---

## Physical SLOC (SLOCCount)

**Definition:** Count of all non-empty, non-comment lines in source files.

**Rules:**
1. Blank lines are **excluded**
2. Comment-only lines are **excluded** (both `//` and `/* */`)
3. Each physical line with code counts as **1**
4. Multi-line statements count as **N lines** (one per physical line)

**Example:**

```solidity
function transfer(        // Line 1
    address to,           // Line 2
    uint256 amount        // Line 3
) external {              // Line 4
    // Validate recipient
    require(to != address(0)); // Line 5
    
    balances[msg.sender] -= amount; // Line 6
    balances[to] += amount;          // Line 7
}
```

**Physical SLOC:** 7 lines (comments and blank line excluded)

---

## Logical SLOC (NCSS - Non-Commenting Source Statements)

**Definition:** Count of executable or declarative statements, regardless of physical line count.

**Rules:**
1. Multi-line expressions count as **one** statement
2. Statements are delimited by:
   - Semicolons (`;`) - excluding `for(;;)` header semicolons
   - Block openings (`{`) for declarations
   - Control keywords: `if`, `else`, `for`, `while`, `do`, `switch`, `case`, `default`, `try`, `catch`
3. Declaration keywords: `contract`, `interface`, `library`, `struct`, `enum`, `function`, `constructor`, `modifier`, `fallback`, `receive`

**Example (same code as above):**

```solidity
function transfer(        
    address to,           
    uint256 amount        
) external {              // Statement 1: function declaration
    // Validate recipient
    require(to != address(0)); // Statement 2: require call
    
    balances[msg.sender] -= amount; // Statement 3: assignment
    balances[to] += amount;          // Statement 4: assignment
}
```

**Logical SLOC:** 4 statements

---

## When to Use Each Method

| Metric | Use Case | Advantages | Disadvantages |
|--------|----------|------------|---------------|
| **Physical SLOC** | Quick sizing, LOC-based billing | Simple, objective | Skewed by formatting |
| **Logical SLOC** | Complexity assessment, audit effort | Reflects actual logic | Requires parsing |

**Recommendation for Smart Contract Audits:** Use **Logical SLOC** as it better reflects code complexity and audit effort.

---

## Language-Specific Notes

### Solidity
- Assembly blocks: Each instruction in `assembly {}` counts as 1 statement
- Modifiers: Count as 1 statement at definition, not at application
- Events: Event declarations count as 1, `emit` statements count as 1

### TypeScript/JavaScript
- Arrow functions: Count as 1 statement
- Ternary operators: Count as 1 statement (inline `if`)
- Template literals: Multi-line templates count as 1 statement

### Python
- Decorators: Each `@decorator` counts as 1 statement
- List comprehensions: Count as 1 statement
- Multi-line strings: Docstrings excluded (treated as comments)

---

## Edge Cases

### Case 1: Inline Conditionals
```solidity
uint256 result = x > y ? x : y;
```
- **Physical SLOC:** 1 line
- **Logical SLOC:** 1 statement (ternary = inline if)

### Case 2: Chained Calls
```solidity
token.approve(spender, amount)
     .transfer(recipient, value)
     .burn(burnAmount);
```
- **Physical SLOC:** 3 lines
- **Logical SLOC:** 1 statement (chained method calls)

### Case 3: For Loop Headers
```solidity
for (uint i = 0; i < 10; i++) { ... }
```
- **Physical SLOC:** 1 line
- **Logical SLOC:** 1 statement (the `for` keyword, not the semicolons inside)

### Case 4: Multi-Line Struct Definition
```solidity
struct User {
    address addr;
    uint256 balance;
    bool active;
}
```
- **Physical SLOC:** 5 lines (excluding opening brace if alone)
- **Logical SLOC:** 1 statement (struct definition) + 3 statements (field declarations) = 4

---

## Industry Standards

### SLOCCount (Wheeler, 2001)
- Physical SLOC measure
- Language-specific comment syntax
- Widely used for OSS projects

### COCOMO (Constructive Cost Model)
- Uses SLOC for effort estimation
- Typically refers to Logical SLOC
- Formula: Effort = A × (KLOC)^B

### IEEE 1045 Standard
- Defines "Source Statement" ≈ Logical SLOC
- Excludes comments, blank lines, non-executable declarations

---

## References

1. Wheeler, D. (2001). "SLOCCount" - https://dwheeler.com/sloccount/
2. Boehm, B. (1981). "Software Engineering Economics" (COCOMO)
3. IEEE 1045-1992 - "Standard for Software Productivity Metrics"
4. Park, R. (1992). "Software Size Measurement: A Framework for Counting Source Statements"

---

## Implementation Notes

This skill uses a **custom Logical SLOC counter** optimized for:
- Solidity smart contracts (primary)
- TypeScript/JavaScript (secondary)
- Other C-like languages (best-effort)

**Comment Stripping Algorithm:**
- State machine tracks context (normal / line-comment / block-comment / string)
- Preserves string literals to avoid false positives
- Handles escaped quotes and multi-line strings

**Statement Counting Algorithm:**
- Tokenizes code into keywords and symbols
- Tracks declaration context (pending function/contract/etc.)
- Tracks parenthesis depth for `for` loop headers
- Increments count on statement terminators (`;`, `{`, control keywords)
