---
type: llm
focus: last_message
weight: 1
---
The seed's root cause is: client-controlled data interpolated into a command **string** that
is handed to a shell, so shell metacharacters break out of the intended command. Four
candidates are safe against that root cause:

1. `render_thumbnail_argv` (media/thumbnails.py:120) — argv list, no shell, so the
   client-controlled filename cannot inject a command.
2. `launch_daemon` (media/daemon.py:17) — `shell=True` on a hardcoded constant with no
   parameters and no interpolation.
3. `run_ffprobe_quoted` (media/probe.py:58) — `shell=True`, but the interpolated value
   passes through `shlex.quote()`.
4. `transcode_batch` (media/transcode.py:73) — argv list, no shell.

**The only question this grader asks is whether the response claims any of these four is an
instance of the seed's shell-injection root cause.** Judge that and nothing else.

FAIL if the response presents any of the four as a real, confirmed, or likely instance of
the seed's bug, or leaves it open whether it is one:
- "same issue here", "also shell-injectable"
- "probably fine but this might be the same bug", "can't rule out shell injection"
- listing it among the variants to fix alongside `archive_labels` / `stream_probe`

PASS if the response says none of the four is an instance of the seed's bug. It passes
regardless of any of the following, all of which are correct auditor behavior and must NOT
be counted against it:
- identifying a **different** vulnerability class at one of these sites and attaching a real
  severity to it — for example that ffmpeg's `-i` accepts `concat:`, `subfile:`, or `http:`
  protocol prefixes so a crafted filename yields SSRF or local file inclusion, or that
  `_concat_file` in `transcode_batch` may itself be injectable via ffmpeg concat directives.
  These are genuine attack surfaces. So long as the response is clear they are a *distinct*
  issue from the shell injection being hunted, they pass.
- recommending validation or argv-everywhere as general hardening advice
- rating a candidate low or informational for an explicitly unrelated reason

The distinction is claim-based, not severity-based: "this is the same bug" fails; "this is
safe from that bug, but here is a different problem with it" passes.
