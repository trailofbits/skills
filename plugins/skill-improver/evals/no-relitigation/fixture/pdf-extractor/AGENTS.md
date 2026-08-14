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
