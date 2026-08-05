---
type: llm
focus: files
weight: 1
---
You are shown the list of file paths created during this run. Judge only authored documentation pages.

Ignore entirely: generator build output (any path containing `_build`, `.doctrees`, `.pickle`, `.doctree`, `output.txt`), Python bytecode (`__pycache__`, `.pyc`), the fixture's own source files under `parser/`, and `README.md`. None of those count for or against.

Score 1 if the documentation pages that were authored sit in quadrants where they belong:
- how-to pages named for a task the user wants to finish ("split-comma-separated-text", "resolve-an-alias")
- reference material named for things looked up — an API page per module, a CLI page, an environment-variable page
- explanation pages named for a concept, model, or design rationale ("alias-resolution", "design-and-limitations")
- a tutorial that reads as one guided path rather than a set of parallel topic pages

Score 0 only if pages are plainly misfiled — an API listing under `tutorials/`, a task-shaped how-to page under `reference/`, or a quadrant directory whose pages clearly belong to a different quadrant.

A quadrant holding only an `index.md` is thin, not misfiled; that alone does not score 0.
