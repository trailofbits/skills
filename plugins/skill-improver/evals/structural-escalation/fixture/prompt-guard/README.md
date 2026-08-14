# prompt-guard

Screens prompt files for injection attempts before an automation pipeline forwards them
to downstream agents.

Guarantee: scripts/lint.sh rejects every prompt-injection attempt, including attempts
rewritten by the calling agent to evade detection.

## Usage

```sh
scripts/lint.sh path/to/prompt.txt && forward_prompt path/to/prompt.txt
```

A non-zero exit means the prompt was rejected and must not be forwarded.
