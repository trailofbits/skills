# Domain Notes

The question never changes. For each requirement: what does it demand of an implementation, where would that be
enforced, is it enforced on every path, and if you cannot find it, have you looked everywhere it could hide.

What changes is what counts as a specification, what enforcement looks like, and where it hides. That is what
this file maps.

| | what specifies behavior | what enforcement looks like | where it hides | what makes `absent` credible |
| --- | --- | --- | --- | --- |
| Smart contracts | whitepaper, protocol spec, NatSpec | `require` / `revert`, modifier, type bound | base contracts, modifiers, libraries, the caller | no modifier, no base-contract check, no caller check, and the vocabulary swept |
| C / C++ | RFC, standard, header comments, design docs | `if`-return, `assert`, length parameter, allocation size | macros, `#ifdef` builds, the caller, a wrapper | checked in every build configuration, not just the one you read |
| Services | API spec, OpenAPI, design docs, README guarantees | middleware, decorator, validation schema, DB constraint | the framework's route registration, not the handler | every route on that path checked, plus the DB schema |
| Firmware / decompiled | datasheet, protocol spec, vendor docs | a compare-and-branch, often unnamed | anywhere; symbol names are absent or wrong | the coverage record says which handlers were read at all |

## Smart contracts

The original target of this plugin. Enforcement is usually a `require` or a custom error, and the trap is that
it delegates: `require(_check(x))` is only enforcement if `_check` compares `x` against the bound the document
names, on the path taken. Follow it.

`unchecked` blocks and assembly suspend guarantees the surrounding code is written as though it still has. A
document requiring that a balance never go below a floor is contradicted by an `unchecked` subtraction even
though a checked one would satisfy it, and the call site looks identical.

Requirements about who may act map to modifiers, `msg.sender` comparisons, and role registries — and to the
constructor and upgrade path, because a document saying the operator cannot reduce a balance is contradicted by
any admin function that can, including one that only moves balances around. Requirements about ordering map to
where state writes sit relative to external calls: "must settle before notifying" is a line-order question.

Watch for arithmetic stated as a percentage and implemented as a numerator. `amountIn * 997 / 1000` satisfies a
0.3% fee and matches nothing you can grep for; verify the arithmetic rather than the wording, and record the
equivalence in the analysis so the next reader does not redo it.

## C and C++

Requirements are usually about bounds, lifetimes, and integer width, and the specification is often an RFC or a
standard rather than a project document — in which case the requirement is normative text with its own section
numbers, and "the code implements RFC 9110 §8.6" is a set of checkable claims rather than one.

The out-parameter is the classic trap: the caller checks the return code and uses the out-parameter, and one
path through the callee returns success without writing it. A requirement that a length is validated is
`partial` if one early return skips the validation.

Check every build configuration. A bound enforced inside `#ifdef DEBUG` is not enforced in the shipped binary,
and a requirement satisfied only under one set of flags should say which. Note the macros — enforcement written
as a macro will not match a search for a function call.

## Services

Authorization and input validation carry most of the requirements, and enforcement usually is not in the handler
body. It is a middleware chain, a decorator, a route registration, or a validation schema declared elsewhere. A
requirement looks `absent` from the handler and is enforced framework-side; a requirement looks satisfied
because one route registers the middleware and three others do not.

So the unit of checking is the route table, not the function. For any requirement about who may call what,
enumerate every registered route on that path and say which ones get the check.

Database constraints are enforcement too. A uniqueness requirement may live in a migration rather than in code,
and a requirement about consistency across two operations is about transactions.

## Firmware and decompiled binaries

Names are absent or wrong, so the rule against inferring behavior from a name is not a caution here — it is the
default condition. Enforcement is a compare-and-branch with no identifier attached to it, and the requirement
has to be recognized from the arithmetic.

Most callees are black boxes and that is normal rather than exceptional. A bound never established in the
visible listing is `absent` with the searches recorded, and that is a complete answer.

Keep a coverage record: which handlers and task entries were read at all. Without it there is no way to
distinguish a requirement that is genuinely unenforced from one enforced in a subsystem nobody opened, and
`absent` cannot be credible.

## When the specification is a standard

RFCs, FIPS documents, and IEEE standards differ from a project whitepaper in two ways that matter.

They are large, so scope the check: name the sections in play and say which were not checked, rather than
implying the whole standard was covered. And they distinguish MUST from SHOULD from MAY deliberately, so the
`force` field carries real weight — a SHOULD the code omits is a documented deviation, not a defect, and
reporting it as one costs credibility on the MUSTs.

They also define terms precisely, and the definition is usually in a different section from the requirement.
Read it before deciding what the requirement demands.
