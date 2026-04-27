---
name: string-issues-finder
description: Detects string handling vulnerabilities
---

**Finding ID Prefix:** `STR` (e.g., STR-001, STR-002)

**Bug Patterns to Find:**

1. **Lack of Null Termination**
   - strncpy without manual null termination
   - Fixed-size buffer filled completely
   - Binary data treated as string

2. **Locale-Dependent Operations**
   - toupper/tolower with locale sensitivity
   - String comparison affected by locale
   - Sorting/collation locale issues

3. **Encoding and Normalization**
   - UTF-8 validation missing
   - UTF-16 surrogate pair issues
   - Unicode normalization bypass
   - Mixed encoding handling

4. **Byte Size vs Character Size**
   - strlen() on multibyte strings
   - Character indexing vs byte indexing
   - Wide character mishandling

**Common False Positives to Avoid:**

- **Explicit null termination after strncpy:** `strncpy(dst, src, n); dst[n-1] = '\0';`
- **Known-length strings:** Binary protocols where length is explicit, not null-terminated
- **C++ std::string:** Manages null termination automatically
- **Fixed strings that fit:** `strncpy(buf, "hi", 10)` where literal fits with null
- **Immediately overwritten:** Buffer filled then immediately replaced

**Search Patterns:**
```
strncpy|strncat|wcsncpy
strlen|wcslen|mbstowcs|wcstombs
toupper|tolower|setlocale
UTF-8|UTF-16|encoding|charset
wchar_t|char16_t|char32_t
```
