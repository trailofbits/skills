# Fuzz Strategies by Parameter Category

Use this table when generating corpus values for each fuzz target. Match the parameter name
against the "Name signals" column. When a parameter matches multiple categories, generate inputs
for all matching categories — they compound and that's intentional.

When a parameter name doesn't match any category, use the **Unmatched** fallback set at the bottom.

---

## Semantic Category Table

| Category | Name signals | Generated inputs |
|---|---|---|
| **Numeric ID** | `id`, `*_id`, `user_id`, `account_id`, `item_id`, `record_id`, `*Id`, `*ID` | `0`, `-1`, `-2147483648`, `2147483648`, `9999999999`, `1.5`, `null`, `""`, `undefined`, `NaN` |
| **Email address** | `email`, `email_address`, `login`, `username`, `*_email` | `user@`, `@example.com`, `user@@example.com`, `user @example.com`, `a@b.c'--`, `admin@example.com`, `"><script>alert(1)</script>@x.com`, (500-char `a` string + `@x.com`), `user+test@example.com`, `user@bücher.de` |
| **Password / secret** | `password`, `passwd`, `secret`, `pass`, `pwd`, `*_password`, `*_secret` | `""`, `null`, `password`, `admin`, `' OR '1'='1`, `'; DROP TABLE users; --`, (500-char string), `\x00`, `password\nX-Injected: true` |
| **Date / time** | `date`, `*_date`, `*_at`, `created_at`, `updated_at`, `timestamp`, `start`, `end`, `from`, `to`, `expires` | `0`, `-1`, `2038-01-19`, `9999-12-31`, `0000-00-00`, `13/32/2024`, `now`, `yesterday`, `1' OR '1'='1`, `2024-02-30`, `9999999999` (Unix epoch far future), `2024-01-01T00:00:00Z` |
| **Role / permission** | `role`, `roles`, `permission`, `permissions`, `scope`, `access`, `access_level`, `privilege`, `type`, `account_type` | `admin`, `root`, `superuser`, `administrator`, `ADMIN`, `Admin`, `system`, `internal`, `owner`, `god`, `sudo`, `staff`, `moderator`, `super_admin`, `null`, `""` |
| **Filename / path** | `file`, `filename`, `file_name`, `path`, `filepath`, `file_path`, `attachment`, `document`, `resource`, `uri`, `location` | `../../../etc/passwd`, `....//....//etc/passwd`, `/etc/passwd`, `/etc/passwd%00.jpg`, `%2e%2e%2f%2e%2e%2fetc%2fpasswd`, `CON`, `NUL`, `PRN`, `AUX`, `.htaccess`, `index.php`, `web.config`, `app.config`, `null`, `""`, (500-char string) |
| **URL / redirect** | `url`, `redirect`, `redirect_url`, `return_url`, `callback`, `next`, `dest`, `destination`, `ref`, `referrer` | `http://attacker.com`, `//attacker.com`, `/\attacker.com`, `javascript:alert(1)`, `data:text/html,<h1>x</h1>`, `http://localhost/admin`, `http://169.254.169.254/latest/meta-data/`, `""`, `null` |
| **Free text / name** | `name`, `title`, `description`, `comment`, `message`, `content`, `body`, `text`, `label`, `note`, `subject` | `""`, `a`, (1000-char `a` string), (10000-char `a` string), `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `' OR 1=1--`, `\x00`, `\r\nX-Injected: true`, `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` |
| **Token / key / hash** | `token`, `api_key`, `apikey`, `key`, `hash`, `nonce`, `auth`, `jwt`, `bearer`, `access_token`, `refresh_token` | `""`, `null`, `0000000000000000000000000000000000000000`, `aaaa`, (4-char string), (10000-char string), `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.` (JWT with alg:none), `../../../etc/passwd` |
| **Boolean flag** | `enabled`, `active`, `is_admin`, `is_staff`, `verified`, `confirmed`, `flag`, `*_enabled`, `*_active`, `*_flag` | `true`, `false`, `1`, `0`, `"true"`, `"false"`, `"yes"`, `"no"`, `null`, `""`, `2`, `-1` |
| **Amount / quantity** | `amount`, `price`, `quantity`, `count`, `total`, `balance`, `fee`, `cost`, `rate`, `limit`, `offset` | `0`, `-1`, `-0.01`, `0.001`, `2147483647`, `9999999999.99`, `"NaN"`, `"Infinity"`, `"-Infinity"`, `null`, `""`, `1e308` |
| **Age / size / length** | `age`, `size`, `length`, `width`, `height`, `max`, `min`, `duration`, `timeout`, `retry` | `0`, `-1`, `2147483647`, `99999`, `1.5`, `"0"`, `null`, `""`, `"unlimited"` |
| **Search / query** | `query`, `q`, `search`, `filter`, `keyword`, `term`, `s` | `""`, `*`, `%`, `_`, `' OR 1=1--`, `"; DROP TABLE users; --`, `<script>alert(1)</script>`, `{{7*7}}`, (1000-char string), `\x00` |

---

## Unmatched Parameters

When a parameter doesn't match any category above, generate this broad set:

```
(empty string)
null
undefined
true
false
0
-1
2147483648
' OR 1=1--
<script>alert(1)</script>
{{7*7}}
(500-char 'a' string)
../../../etc/passwd
\r\nX-Injected: true
\x00
```

---

## Generation Guidance

**Match on substrings**: `user_id` matches "Numeric ID" even though it's not just `id`.
The `*` wildcard in name signals means "any prefix/suffix".

**Context matters**: Read the current value alongside the name. A field named `type` with value
`"json"` probably controls output format — add `xml`, `html`, `csv`, `yaml`, `../` alongside
the standard role-escalation probes.

**Nested JSON bodies**: If a body param's type is `object` or `array`, include the scalar fuzz
inputs for that top-level key (the fuzzer replaces the entire value). This catches type-confusion
bugs where the server expects an object but receives a string.

**Corpus file format**: Write one value per line to `./corpus/<param-name>.txt`. Blank lines are
ignored by the fuzzer. Values that would be JSON non-strings (numbers, booleans, null) are written
as their raw literal — the fuzzer injects them preserving the original field's JSON type context
unless the original type was a string.

---

## Why semantic fuzzing beats blind mutation

Blind fuzzing sends random garbage and relies on volume. Semantic fuzzing sends values that probe
specific server-side assumptions: "is this field validated as an email?", "does the server
parameterize SQL queries?", "does it restrict which roles a user can assign themselves?".
Fewer requests, higher signal-to-noise ratio — which is exactly what makes the anomaly detection
meaningful rather than overwhelming.
