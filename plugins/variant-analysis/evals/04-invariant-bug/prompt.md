---
max_turns: 20
timeout_seconds: 480
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
Found a TOCTOU race in our file store:

```python
# store/writer.py:31
def write_if_writable(path, data):
    if os.access(path, os.W_OK):
        with open(path, "w") as fh:
            fh.write(data)
```

The store runs as a privileged service and `path` lands in a world-writable staging
directory, so an attacker can swap the path for a symlink between the check and the open.

Here is every other filesystem operation in the store. Which of these are the same bug?
Verdict on each, with a severity.

```python
# store/uploads.py:58
def save_upload(src, dest):
    if not os.path.exists(dest):
        shutil.move(src, dest)
    else:
        raise FileExistsError(dest)
```

```python
# store/logs.py:22
def rotate_log(log_path):
    if os.path.isfile(log_path):
        os.remove(log_path)
    return open(log_path, "w")
```

```python
# store/atomic.py:14
def atomic_write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(data)
```

```python
# store/config.py:9
def read_config(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return DEFAULTS
```

```python
# store/dirs.py:11
def mkdir_job(job_id):
    d = os.path.join(STAGING_DIR, job_id)
    os.mkdir(d, 0o700)
    return d
```
`job_id` is a server-generated UUID, never client-supplied.

```python
# store/staging.py:40
def tempfile_write(data, suffix):
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as fh:
        fh.write(data)
        return fh.name
```

All of these run in the same privileged service, against the same staging directory.
