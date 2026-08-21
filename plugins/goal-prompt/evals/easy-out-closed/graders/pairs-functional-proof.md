---
type: llm
weight: 2
---

"A search finds no oldParse calls" is satisfiable by deleting src/importer.js, deleting the feature, or
narrowing the search — none of which is the migration the user wants. The fixture offers the closing check
for free: `npm test` runs test.js, which exercises the import feature end to end.

Pass only if the `/goal` line pairs the zero-matches condition with the fixture's real functional proof —
`npm test` (or `node test.js`) exiting 0 — so the goal cannot be satisfied by removing the calling code, and
both are required together (AND), not offered as alternatives.

Fail if:
- the goal's success condition is the search result alone;
- the functional check is invented rather than the fixture's (`npm run unit`, `pytest`, a made-up script);
- the checks are joined with "or", letting the loop satisfy the cheaper one;
- the goal permits deleting or stubbing the importer instead of migrating it (no functional proof
  constraining it).
