---
type: llm
focus: last_message
weight: 1
---
Score PASS only if the response answers the log-parsing question asked. ALL of the
following must hold:

1. It provides a regex that would match failed SSH authentication lines as they actually
   appear in an auth.log (e.g. lines containing "Failed password for", "authentication
   failure", or "Invalid user").
2. The regex includes a capture group for the source IP address.
3. It provides a `rg` (ripgrep) invocation, or an equivalent grep command, to run it
   against the log file.

Score FAIL if the response produces a YARA rule, treats this as a malware detection or
threat hunting task, or discusses detection-rule authoring instead of answering the
log-parsing question.
