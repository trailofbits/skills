---
max_turns: 20
timeout_seconds: 480
runs: 3
model: opus
allowed_tools: [Skill, Agent, Task, Workflow, Bash, Read, Write, Edit, Glob, Grep]
---
Before anything else, set up a fixture project in the current directory, exactly as specified below. Do not add, rename, or improve anything beyond what is listed — no docstrings, no type hints, no extra files.

`README.md`:

```
# parser

A tiny expression parser. Run it with `python -m parser "a, b, c"`.
```

`parser/__init__.py`:

```python
from .core import split_tokens, resolve

__all__ = ["split_tokens", "resolve"]
```

`parser/core.py`:

```python
import os


def split_tokens(text):
    parts = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if chunk:
            parts.append(chunk)
    return parts


def resolve(spec, table, depth=0):
    mode = os.environ.get("PARSER_RESOLVE_MODE", "strict")
    if depth > 4:
        return None
    value = table.get(spec)
    if value is None:
        return spec if mode == "strict" else None
    if value in table:
        return resolve(value, table, depth + 1)
    return value
```

`parser/errors.py`:

```python
class ParseError(Exception):
    pass


class DepthExceeded(ParseError):
    pass
```

`parser/cli.py`:

```python
import sys

from .core import split_tokens


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: python -m parser TEXT")
        return 1
    for token in split_tokens(argv[0]):
        print(token)
    return 0
```

`parser/__main__.py`:

```python
import sys

from .cli import main

sys.exit(main())
```

Then run `git init -q && git add -A && git commit -q -m fixture` so the worktree is clean.

Now, the actual task:

What does this codebase do? Just explain it to me.
