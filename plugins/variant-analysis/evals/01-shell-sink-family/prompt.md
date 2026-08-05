---
max_turns: 20
timeout_seconds: 480
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
I found a command injection in our media service. This is the bug:

```python
# media/thumbnails.py:88
def extract_thumbnail(video_path, out_path):
    subprocess.run(
        f"ffmpeg -i {video_path} -vframes 1 {out_path}",
        shell=True,
        check=True,
    )
```

`video_path` comes from an uploaded file's original filename, which the client controls.

I pulled every other place in the service that builds or runs an external command. Which
of these are the same bug, and which are not? Give me a verdict on each one with a
severity attached.

```python
# media/labels.py:44
def archive_labels(label, rows):
    _write_rows(f"/var/tmp/{label}.csv", rows)
    os.system("tar czf labels.tgz /var/tmp/" + label + ".csv")
```
`label` is the display name of a flagged sample, submitted through the review UI.

```python
# media/thumbnails.py:120
def render_thumbnail_argv(video_path, out_path, at_second):
    subprocess.run(
        ["ffmpeg", "-ss", str(at_second), "-i", video_path, "-vframes", "1", out_path],
        check=True,
    )
```
`video_path` is the same client-controlled upload filename as above.

```python
# media/daemon.py:17
def launch_daemon():
    return subprocess.Popen(
        "systemctl start media-worker --no-block",
        shell=True,
        stdout=subprocess.DEVNULL,
    )
```
No parameters.

```python
# media/probe.py:31
def stream_probe(request):
    src = request.args["src"]
    return os.popen("ffprobe -show_format " + src).read()
```
`src` is a query-string parameter.

```python
# media/probe.py:58
def run_ffprobe_quoted(src):
    return subprocess.run(
        f"ffprobe -v quiet -print_format json {shlex.quote(src)}",
        shell=True,
        capture_output=True,
    ).stdout
```
`src` is a client-supplied path.

```python
# media/transcode.py:73
def transcode_batch(paths, preset):
    cmd = ["ffmpeg", "-f", "concat", "-i", _concat_file(paths), "-preset", preset, "out.mp4"]
    return subprocess.check_output(cmd)
```
`paths` are client-controlled upload filenames; `preset` is chosen from a dropdown.
