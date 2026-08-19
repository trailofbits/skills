---
max_turns: 20
timeout_seconds: 480
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
ugh, just hit this in our video handler:

```python
# handlers/video.py:52
def convert_upload(fname):
    os.system("convert " + fname + " -resize 320x240 thumb.png")
```

`fname` is whatever the client called the file they uploaded. anything else like it in
here? these are the other spots that touch external tools or build command strings:

```python
# handlers/preview.py:19
def make_preview(clip, start):
    subprocess.run(f"ffmpeg -ss {start} -i {clip} -t 5 preview.mp4", shell=True)
```
`clip` is an uploaded filename, `start` is an integer from a slider.

```python
# handlers/util.py:8
def sanitize_name(raw):
    return "".join(c for c in raw if c.isalnum() or c in "._-")[:64]
```

```python
# handlers/export.py:41
def zip_outputs(src_dir, dest):
    subprocess.run(["zip", "-r", dest, src_dir], check=True)
```
`dest` is derived from a client-supplied export name.

```python
# handlers/hooks.py:12
HOOK_CMD = "/opt/media/hooks/post-process.sh"

def run_hook():
    os.system(HOOK_CMD)
```

```python
# handlers/watermark.py:66
def apply_watermark(img, out):
    wm = current_project.config["watermark_path"]
    return os.popen(f"composite {wm} {img} {out}").read()
```
`watermark_path` is a per-project setting editable by any project member.
