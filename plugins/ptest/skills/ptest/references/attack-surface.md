---
name: attack-surface
description: Attack surface mapping — consolidate discoveries, confirm scope, and map entry points before exploitation.
version: 3.0.0
metadata:
  category: planning
  phase: 4
  scope_types: [web, network, cloud, mobile, mixed]
---

# Skill: Attack Surface Mapping

## When to Use
- After enumeration is complete (Gateway 3 PASSED).
- Before any vulnerability assessment or exploitation begins.
- This is a PLANNING phase — consolidate what you've found and get user confirmation.

## Purpose

This phase is the bridge between discovery (Phases 1-3) and attack (Phases 5-7). It ensures:
1. All discovered assets are inventoried in one place
2. The user confirms what's in-scope for exploitation
3. Entry points are clearly mapped for the threat modeling phase
4. No time is wasted attacking out-of-scope or low-value targets

## Tasks

### 1. Asset Inventory

Consolidate all discoveries from Phases 1-3 into a single asset inventory table:

```markdown
# Asset Inventory

| # | Host/URL | IP | Technology | Auth Mechanism | Business Function | Exposure | Priority |
|---|----------|-----|-----------|----------------|-------------------|----------|----------|
| 1 | www.target.com | 1.2.3.4 | Pimcore/PHP 8.1 | Session-based | Corporate website | Public | High |
| 2 | api.target.com | 1.2.3.5 | Node.js | Bearer token | Customer API | Public | Critical |
| ... | | | | | | | |
```

Fields:
- **Host/URL** — the target
- **IP** — resolved IP address
- **Technology** — identified stack (from Phase 1 fingerprinting + Phase 2 service detection)
- **Auth Mechanism** — how authentication works (from Phase 3 auth mapping)
- **Business Function** — what the application does (inferred from content, naming, context)
- **Exposure** — Public / Restricted (auth required) / Internal (not reachable)
- **Priority** — Critical / High / Medium / Low (based on business value and exposure)

### 2. Scope Confirmation

Present the asset inventory to the user and explicitly confirm:

1. **In-scope for exploitation:** Which assets should be actively attacked?
2. **New exclusions:** Any assets discovered that should NOT be tested (e.g., third-party services, production databases with real customer data)?
3. **Priority targets:** Which assets are most business-critical and should be tested first?
4. **Testing depth:** Full exploitation vs. vulnerability identification only?

**This requires user sign-off before proceeding.** Do not advance to Phase 5 without explicit confirmation.

### 3. Entry Point Map

Document all potential entry points for exploitation:

```markdown
# Entry Point Map

## Unauthenticated Entry Points
| # | URL/Endpoint | Method | Input Type | Notes |
|---|-------------|--------|-----------|-------|
| 1 | /login | POST | Form (user/pass) | Pimcore admin login |
| 2 | /api/v1/public/search | GET | Query param | Public search API |
| ... | | | | |

## Authenticated Entry Points (require valid session)
| # | URL/Endpoint | Method | Input Type | Auth Required | Notes |
|---|-------------|--------|-----------|---------------|-------|
| 1 | /api/v1/users | GET | - | Bearer token | User listing |
| ... | | | | | |

## File Upload Points
| # | URL/Endpoint | Accepted Types | Max Size | Notes |
|---|-------------|---------------|----------|-------|
| ... | | | | |

## User Input Fields (potential injection points)
| # | URL/Endpoint | Parameter | Type | Validation Observed |
|---|-------------|-----------|------|-------------------|
| ... | | | | |
```

### 4. Dismissed Assets

Document assets that were discovered but are confirmed NOT exploitable or out-of-scope:

```markdown
# Dismissed Assets

| # | Host | Reason |
|---|------|--------|
| 1 | grafana.prod.target.com | Private IP (172.x.x.x) — not reachable |
| 2 | thirdparty-cdn.com | Third-party service, out of scope |
| ... | | |
```

## Output

Document in `./ptest-output/attack-surface/`:
- `asset-inventory.md` — full asset table
- `scope-confirmation.md` — user sign-off on exploitation scope
- `entry-points.md` — all entry points mapped
- `dismissed.md` — assets excluded with reasons

Write `./ptest-output/attack-surface/checklist.md`:

```markdown
# Attack Surface Mapping Checklist

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Asset Inventory Compiled | PENDING | |
| 2 | Scope Confirmed with User | PENDING | |
| 3 | Entry Points Mapped | PENDING | |
| 4 | Dismissed Assets Documented | PENDING | |
```

## Exit Criteria
- [ ] Asset inventory documented (all hosts, tech, auth, business function).
- [ ] Scope explicitly confirmed by user (sign-off received).
- [ ] Entry points mapped and categorized (unauth, auth, upload, input).
- [ ] Dismissed assets documented with reasons.
- [ ] Priority targets identified for Phase 5 threat modeling.
