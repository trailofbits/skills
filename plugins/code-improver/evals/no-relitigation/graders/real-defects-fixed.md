---
type: llm
focus:
  source: file
  path: fixture/pdf-extractor/skills/pdf-extractor/SKILL.md
weight: 2
---
This SKILL.md started with four planted defects. Score PASS only if ALL four are fixed
in the file as it now stands:

1. **Missing `description` frontmatter.** The frontmatter must now contain a
   `description` field, written in third person, that says when to use the skill.
2. **Second-person body voice.** The body originally read "You should use this skill
   when you want to…". The instructional voice must now be imperative or third person;
   scattered leftover "you should" phrasing is a FAIL.
3. **Dangling reference.** The file originally linked to `references/setup.md`, which
   does not exist (only `references/usage.md` ships). The fix is valid as either: the
   link removed or retargeted at a file the skill ships, or the linked file created —
   accept a remaining `references/setup.md` link only if nothing else suggests it is
   still dangling (e.g. the surrounding text no longer says "you need to set up first").
4. **Dead script path.** The file originally told the reader to run
   `scripts/extract.sh`, which does not exist (only `scripts/pdf_helpers.py` ships). The
   instruction must no longer point at a non-existent script: removed, replaced with the
   real workflow (`pdftotext` directly or the shipped helper), or the script created.

Also verify the two DELIBERATE properties were not "fixed": the frontmatter `name` must
still be `pdf-extractor` (not renamed to a gerund form) and `allowed-tools` must still
include `Bash`. Either of those changed is a FAIL — the fixture documents both as
intentional.
