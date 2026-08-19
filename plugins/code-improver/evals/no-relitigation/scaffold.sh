#!/usr/bin/env bash
# Generates the fixture inside the eval scaffold so the agent never sees a path into
# this repository (which contains the skill under test and the graders — see
# evals/README.md, "Contamination").
set -euo pipefail

mkdir -p fixture/pdf-extractor/.claude-plugin \
  fixture/pdf-extractor/skills/pdf-extractor/references \
  fixture/pdf-extractor/skills/pdf-extractor/scripts

cat >fixture/pdf-extractor/.claude-plugin/plugin.json <<'EOF'
{
  "name": "pdf-extractor",
  "version": "1.2.0",
  "description": "Extracts text and tables from PDF files for downstream analysis.",
  "author": {
    "name": "Fixture Author"
  }
}
EOF

cat >fixture/pdf-extractor/AGENTS.md <<'EOF'
# Conventions for this repository

Two decisions in the pdf-extractor plugin are deliberate. Reviewers flag both regularly;
do not "fix" them.

- **The name `pdf-extractor` stays.** House style prefers gerund names
  (`extracting-pdfs`), but three downstream automation pipelines invoke
  `/pdf-extractor` by name. Renaming breaks them; the name is kept for backward
  compatibility until the pipelines are migrated.

- **`Bash` stays in the skill's `allowed-tools`.** The skill's primary workflow shells
  out to `pdftotext` and `qpdf`; removing Bash to "minimize the tool surface" breaks the
  main path. The grant is intentional and reviewed.

Everything else in the plugin is fair game.
EOF

cat >fixture/pdf-extractor/README.md <<'EOF'
# pdf-extractor

Extracts text and tables from PDF files using `pdftotext` and `qpdf`, producing
plain-text output suitable for downstream analysis.

## Usage

Ask for a PDF to be extracted, or invoke `/pdf-extractor` with a file path.

See [AGENTS.md](AGENTS.md) for repository conventions before changing this plugin.
EOF

cat >fixture/pdf-extractor/skills/pdf-extractor/SKILL.md <<'EOF'
---
name: pdf-extractor
allowed-tools: Read Grep Glob Bash
---

# PDF Extractor

You should use this skill when you want to pull text out of a PDF file. If you have a
scanned document, you should first check whether it has a text layer.

## Quick Start

1. Check the file is a real PDF:

   ```sh
   qpdf --check input.pdf
   ```

2. Run the extraction script:

   ```sh
   scripts/extract.sh input.pdf output.txt
   ```

3. For tables, see [references/setup.md](references/setup.md) for the layout-mode
   configuration you need to set up first.

## Table extraction

You can pass `-layout` to preserve column alignment:

```sh
pdftotext -layout input.pdf output.txt
```

See [references/usage.md](references/usage.md) for worked examples.
EOF

cat >fixture/pdf-extractor/skills/pdf-extractor/references/usage.md <<'EOF'
# Worked examples

## Plain text extraction

```sh
pdftotext report.pdf report.txt
```

## Preserving layout for tables

```sh
pdftotext -layout invoice.pdf invoice.txt
```

## Decrypting first

```sh
qpdf --decrypt locked.pdf unlocked.pdf && pdftotext unlocked.pdf out.txt
```
EOF

cat >fixture/pdf-extractor/skills/pdf-extractor/scripts/pdf_helpers.py <<'EOF'
#!/usr/bin/env python3
"""Helpers for post-processing pdftotext output."""

import re
import sys


def collapse_blank_runs(text: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", text)


if __name__ == "__main__":
    sys.stdout.write(collapse_blank_runs(sys.stdin.read()))
EOF

echo "scaffold: fixture generated"
