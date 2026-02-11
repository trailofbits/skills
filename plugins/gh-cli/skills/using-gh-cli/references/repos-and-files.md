# Repos and Files

## Viewing File Contents

The `gh api` command is the primary way to fetch file contents from GitHub.

```bash
# Get file metadata + base64 content
gh api repos/owner/repo/contents/path/to/file.py

# Decode file content (base64)
gh api repos/owner/repo/contents/path/to/file.py --jq '.content' | base64 -d

# Get raw file content directly (skips base64)
gh api repos/owner/repo/contents/path/to/file.py \
  -H "Accept: application/vnd.github.raw+json"

# Get file from a specific branch/ref
gh api repos/owner/repo/contents/path/to/file.py?ref=develop

# List directory contents
gh api repos/owner/repo/contents/src/ --jq '.[].name'
```

## Browsing Repository Structure

```bash
# Get the repo tree recursively
gh api repos/owner/repo/git/trees/main?recursive=1 --jq '.tree[].path'

# Filter tree to specific file types
gh api repos/owner/repo/git/trees/main?recursive=1 \
  --jq '.tree[] | select(.path | endswith(".py")) | .path'
```
