---
name: thread-safety-finder
description: Detects thread safety and concurrency bugs
---

**Finding ID Prefix:** `THREAD` (e.g., THREAD-001, THREAD-002)

**Non-Thread-Safe Functions:**

1. **Network Functions**
   - `gethostbyname` - Returns static struct
   - `gethostbyaddr` - Returns static struct
   - `inet_ntoa` - Returns static buffer

2. **String Functions**
   - `strtok` - Uses static state
   - `strerror` - May use static buffer

3. **Time Functions**
   - `localtime` - Returns static struct
   - `gmtime` - Returns static struct
   - `ctime` - Returns static buffer
   - `asctime` - Returns static buffer

4. **User/Group Functions**
   - `getpwnam` / `getpwuid` - Return static struct
   - `getgrnam` / `getgrgid` - Return static struct

5. **Other Dangerous Functions**
   - `readdir` - Returns static struct
   - `getenv` / `setenv` - Not thread-safe (glibc improved recently)

**Thread-Safe Alternatives:**
- `gethostbyname_r`, `inet_ntop`, `strtok_r`
- `localtime_r`, `gmtime_r`, `ctime_r`, `asctime_r`
- `getpwnam_r`, `getpwuid_r`, `getgrnam_r`, `getgrgid_r`
- `readdir_r` (deprecated but thread-safe)

**Common False Positives to Avoid:**

- **Single-threaded code:** Program doesn't use pthreads, std::thread, or fork
- **Result used immediately:** Static result is copied/used before any yield point
- **Thread-local storage:** Function result stored in thread-local variable
- **Mutex protected:** Call is protected by mutex that serializes access
- **_r variant used:** Code actually uses the thread-safe _r variant

**Search Patterns:**
```
pthread_create|std::thread|fork\s*\(\s*\)
gethostbyname\s*\(|inet_ntoa\s*\(|\bstrtok\s*\(
\blocaltime\s*\(|\bgmtime\s*\(|\bctime\s*\(
\bgetpwnam\s*\(|\bgetpwuid\s*\(
getenv\s*\(|setenv\s*\(
```
