---
name: filesystem-issues-finder
description: Detects symlink attacks and temp file vulnerabilities
---

**Finding ID Prefix:** `FS` (e.g., FS-001, FS-002)

**Bug Patterns to Find:**

1. **Symlink/Softlink Issues**
   - Following symlinks in privileged code
   - Symlink TOCTOU attacks
   - Directory traversal via symlinks

2. **Disk Synchronization Issues**
   - Missing fsync/fdatasync
   - Data corruption on crash
   - Write ordering bugs

3. **Unquoted Path Issues**
   - Paths with spaces not quoted
   - Shell injection via paths

4. **Missing Path Separators**
   - `/path/files` vs `/path/files/` behavior
   - `/path/files` vs `/path/files_sensitive`

5. **Case and Normalization**
   - Case-insensitive filesystem issues
   - Unicode normalization bypasses
   - Path canonicalization bugs

6. **Predictable Temp Files**
   - Using tmpnam/tempnam/mktemp
   - Predictable temp file names
   - Insecure temp directory permissions

**Common False Positives to Avoid:**

- **O_NOFOLLOW used:** Symlink following explicitly prevented
- **Hardcoded trusted paths:** Paths to system files that can't be manipulated
- **User's own directory:** Operations in user's home dir by user's own process
- **Already canonicalized:** Path passed through realpath() or similar
- **Directory fd operations:** openat() with directory fd avoids races
- **Root-only writable directory:** Symlink attacks require write access

**Search Patterns:**
```
open\s*\(|fopen\s*\(|stat\s*\(|lstat\s*\(
readlink\s*\(|symlink\s*\(|realpath\s*\(
tmpnam|tempnam|mktemp|mkstemp|tmpfile
fsync\s*\(|fdatasync\s*\(
O_NOFOLLOW|O_DIRECTORY
```
