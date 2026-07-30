---
type: llm
focus:
  source: file
  path: larkspur.yar
weight: 0.5
---
Secondary check on house format conventions. Score PASS only if ALL hold:

1. The rule name follows `{CATEGORY}_{PLATFORM}_{FAMILY}_{DATE}` — a category prefix
   from MAL_ / SUSP_ / HKTL_ / GEN_, the platform token `Mac_`, a family token naming
   Larkspur, and a date token.
2. A `meta:` block is present.
3. `description` is present and begins with the word "Detects".
4. `author`, `reference`, and `date` fields are all present in `meta:`.

Placeholder values (e.g. author = "Your Name") still count as present for claims 2-4.
Score FAIL if the rule name is generic (e.g. `larkspur`, `detect_larkspur`,
`macos_backdoor`) or if any of the four meta fields is missing.
