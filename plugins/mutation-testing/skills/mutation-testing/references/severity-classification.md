# Severity Classification Guide

Severity depends on the impact type of the mutated code, not the mutation operator used. The same operator replacement carries different severity depending on whether it occurs in access control logic or in a logging statement. Always classify based on what the code does, not how it was mutated.

The tiers prioritize testing gaps. They do not establish that the original code contains a vulnerability. State uncertainty about impact instead of automatically raising the tier.

This file covers general severity criteria and examples. Blockchain-specific examples are loaded separately by `SKILL.md` for blockchain projects.

---

## Tier 1: Critical — Security-Sensitive Code

Surviving, non-equivalent mutants in code that enforces security invariants. The tests missed a change to a security property. Exploitability in the original code requires a separate investigation.

### Decision Criteria

The mutated code falls in Tier 1 if it:

- Enforces who can call a function (access control, authorization)
- Verifies identity or credentials (authentication, signature checks)
- Prevents reentrancy or other concurrency attacks
- Validates external input at system boundaries
- Performs cryptographic operations (hashing, signing, verifying)
- Guards privilege escalation paths (admin functions, upgrades)

### Examples

- `assert(caller == admin)` or `require(msg.sender == owner)` — authorization
- Signature verification (`verify_signature`, `ecrecover`, `jwt.verify`)
- Constant-time comparison (`hmac.compare_digest`, `bcrypt.compare`)
- Authentication guards and decorators (`@login_required`, role-check middleware)
- Any `require`, `assert`, `if` guard, or middleware that controls access to sensitive operations

---

## Tier 2: High — Financial/State Integrity Code

Surviving mutants in code that governs value transfers, accounting, or critical state transitions. An uncaught mutation here means the test suite does not verify that funds or state are handled correctly.

### Decision Criteria

The mutated code falls in Tier 2 if it:

- Transfers tokens or native currency
- Computes fees, shares, exchange rates, or interest
- Manages balances or accounting ledgers
- Enforces state machine transitions (order of operations)
- Uses oracle-dependent price calculations
- Enforces slippage or deadline protections
- Handles liquidation or collateral thresholds

### Examples

- `account.balance -= withdrawal` — balance deduction
- `interest = principal * rate * time` or `fee = amount * rate / 100` — financial computation
- Share or token accounting (`total_shares += new_shares`, `pool.update()`)
- Price or threshold guards (`assert(price >= min_price)`, `if (total > limit) throw`)
- Any arithmetic on monetary values, accounting updates, or state transition guards with financial implications

---

## Tier 3: Medium — Business Logic Code

Surviving mutants in code that implements protocol-specific behavior without directly handling value or enforcing security boundaries. An uncaught mutation here means functional correctness is not fully tested.

### Decision Criteria

The mutated code falls in Tier 3 if it:

- Validates configuration or parameters (non-security bounds)
- Manages data structures (arrays, mappings, queues)
- Implements protocol-specific workflow logic (governance, voting, staking rewards)
- Handles integration points with external contracts (callbacks, return values)
- Contains error handling or revert conditions for non-security paths

### Examples

- Data structure operations (`vec.push(item)`, `tasks.filter(...)`, `sorted(items, ...)`)
- Configuration updates and validation (`config.max_retries = value`, `Math.min(value, MAX)`)
- Capacity and retry guards (`if queue.len() > MAX_SIZE`, `if retry_count > MAX_RETRIES`)
- Cache management (`cache.expire(key, ttl=300)`)
- Any non-security, non-financial logic that affects functional behavior

---

## Tier 4: Low — Observability and Informational Code

Surviving mutants in code that does not affect execution logic. These represent the lowest priority but still indicate missing test assertions.

### Decision Criteria

The mutated code falls in Tier 4 if it:

- Emits events or logs
- Returns values from view/pure/getter functions used only for display
- Contains error message strings (not the revert condition itself)
- Updates NatSpec or documentation-reflected constants
- Provides monitoring or debugging output

### Examples

- Logging and tracing (`log::info!(...)`, `logger.debug(...)`, `console.log(...)`)
- Metric emission (`metrics.increment('api.calls')`)
- Getters and display methods (`get_name()`, `__repr__`, `displayName`)
- Any code that does not affect control flow, state, or return values in non-view contexts

---

## Ambiguous Cases

### Configuration Parameters that Affect Security

If a configuration parameter controls a security-sensitive threshold (e.g., maximum number of signers, timeout for timelocks), classify as **Tier 1**, not Tier 3.

### Error Handling in External Calls

If the error handling is on a value-bearing external call (e.g., catching a failed token transfer), classify as **Tier 2**. If the error handling is on a non-value call, classify as **Tier 3**.

### Getter Functions Used in State-Changing Logic

If a getter or read-only function's return value is consumed by a state-changing function (e.g., a pricing lookup used in a transaction, a permission check used in an update), the getter mutation is **Tier 2**, not Tier 4.

### Event or Log Emissions Required by Consumers

If event or log emission is required by downstream consumers (e.g., monitoring systems, indexers, integration contracts, or protocol standards), consider **Tier 3** instead of Tier 4.

### Boundary Between Tier 2 and Tier 3

When unsure whether code is "financial" or "business logic," ask: if this code were wrong in production, would it result in loss of funds or incorrect accounting? If yes, Tier 2. If it would cause incorrect behavior without direct financial impact, Tier 3.
