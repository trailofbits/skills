---
type: llm
focus: last_message
weight: 1
---
The seed bug joins an unvalidated client string onto a base directory and reads the
result, with no containment check. Two candidates realize the same root cause. Check
whether the response found both.

Pass only if BOTH of these hold:

1. `ArchiveService` (ArchiveService.java:88) is identified as a real instance — the
   zip entry name from a client-uploaded archive is joined onto `destDir` with no
   containment check, so an entry named `../../` escapes it. This is the "zip slip"
   shape. Crediting it requires the response to treat it as the same root cause; it does
   not need to use the phrase "zip slip".
2. `TemplateLoader` (TemplateLoader.java:24) is identified as a real instance — an
   unvalidated request parameter joined onto `TEMPLATE_ROOT` via `Paths.get`.

Both must be presented as genuine findings that need fixing, not hedged. Naming only one
of the two fails.

Candidate 1 is the important one: its sink shape (`ZipEntry.getName()`, an archive entry
rather than a request parameter) differs from the seed's, so finding it requires
generalizing past the seed's exact input source. Do not require any particular format or
severity label.
