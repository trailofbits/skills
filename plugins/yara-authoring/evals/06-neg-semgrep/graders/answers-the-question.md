---
type: llm
focus: last_message
weight: 1
---
Score PASS only if the response delivers a usable Semgrep rule for the task asked.
ALL of the following must hold:

1. A Semgrep rule in YAML form is present, under a top-level `rules:` key.
2. The rule has an `id`, a `message`, a `severity`, and `languages` including Python.
3. It contains a `pattern`, `patterns`, or `pattern-either` block that matches assignment
   of a string literal to a secret-looking variable name.
4. It makes some attempt to avoid flagging values read from the environment — e.g. a
   `pattern-not` excluding `os.environ` / `os.getenv`, or a metavariable regex
   constraining the assigned value to literals.

Score FAIL if the response instead produces a YARA rule, reframes the request as malware
detection or threat hunting, or answers with prose only and no rule YAML.
