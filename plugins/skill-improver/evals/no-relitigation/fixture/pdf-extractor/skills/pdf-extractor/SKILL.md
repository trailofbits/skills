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
