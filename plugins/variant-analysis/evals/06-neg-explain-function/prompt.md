---
max_turns: 8
timeout_seconds: 180
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
What does this function do? Walking a colleague through this file and I want to describe it
accurately.

```python
# media/thumbnails.py:88
def extract_thumbnail(video_path, out_path):
    subprocess.run(
        f"ffmpeg -i {video_path} -vframes 1 {out_path}",
        shell=True,
        check=True,
    )
```
