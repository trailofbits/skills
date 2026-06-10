---
name: time-issues-finder
description: Identifies time-related bugs and timing attacks
---

**Finding ID Prefix:** `TIME` (e.g., TIME-001, TIME-002)

**Bug Patterns to Find:**

1. **Non-Monotonic Clocks**
   - Using wall clock for duration measurement
   - Time going backward breaking logic
   - Clock skew between systems

2. **Time Zone Issues**
   - Local vs UTC confusion
   - DST transitions breaking logic
   - Midnight crossing issues

3. **Leap Seconds**
   - Assuming 86400 seconds per day
   - Time comparison across leap second

4. **Time Representation**
   - 32-bit time_t (Y2038)
   - Overflow in time calculations
   - Loss of precision in conversion

5. **Timing Assumptions**
   - Assuming operation completes in fixed time
   - Timeout calculation errors
   - Sleep duration assumptions

**Common False Positives to Avoid:**

- **CLOCK_MONOTONIC used:** Proper monotonic clock for duration measurement
- **UTC throughout:** Code consistently uses UTC without local time confusion
- **64-bit time_t:** Modern systems with 64-bit time_t don't have Y2038 issue
- **Non-security time usage:** Logging timestamps, display purposes only
- **Explicit tolerance:** Code handles clock skew with explicit tolerance

**Search Patterns:**
```
time\s*\(|gettimeofday\s*\(|clock_gettime\s*\(
localtime\s*\(|gmtime\s*\(|strftime\s*\(
sleep\s*\(|usleep\s*\(|nanosleep\s*\(
difftime\s*\(|mktime\s*\(
CLOCK_MONOTONIC|CLOCK_REALTIME
```
