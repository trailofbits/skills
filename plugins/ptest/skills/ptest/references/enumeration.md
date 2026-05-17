---
name: enumeration
description: Application-layer enumeration — deep discovery of directories, APIs, parameters, and hidden content.
version: 3.0.0
metadata:
  category: enumeration
  phase: 3
  scope_types: [web, network, cloud, mobile, mixed]
---

# Skill: Enumeration

## When to Use
- After active recon is complete (Gateway 2 PASSED).
- When you need to discover application-layer content: directories, files, API endpoints, parameters, and hidden functionality.

## Scope
This phase covers **application-layer discovery**:
- Directory and file brute-forcing
- API endpoint discovery and mapping
- Parameter discovery
- Virtual host enumeration
- CMS-specific enumeration
- JavaScript analysis and source map extraction
- Authentication endpoint mapping

Network-layer discovery (port scanning, service detection) belongs in Phase 2 (Active Recon).

## Techniques & Tools

### 1. Directory & File Brute-Force (MANDATORY: gobuster or feroxbuster)
Discover hidden paths, files, and directories on web targets.
```bash
# gobuster — directory mode
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o ./ptest-output/enumeration/gobuster-dirs.txt -t 50

# gobuster — file mode (common extensions)
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,html,js,json,xml,txt,bak,env,conf -o ./ptest-output/enumeration/gobuster-files.txt

# feroxbuster — recursive
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o ./ptest-output/enumeration/ferox.txt --depth 3

# Targeted wordlists for specific tech stacks
# Pimcore: /admin, /bundles, /var, /bin
# WordPress: /wp-content, /wp-includes, /wp-json
# Laravel: /api, /storage, /vendor
```

**Requirements:**
- Run against ALL confirmed-live web hosts (from Phase 1 domains-live.md)
- Use appropriate wordlists for the identified technology stack
- If gobuster/feroxbuster unavailable, document gap and use alternative (dirsearch, dirb)

### 2. API Endpoint Discovery (MANDATORY: ffuf)
Map API endpoints, methods, and response patterns.
```bash
# ffuf — API endpoint fuzzing
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,401,403,405 -o ./ptest-output/enumeration/ffuf-api.json

# ffuf — versioned API paths
ffuf -u https://target.com/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc all -fc 404

# Check common API documentation endpoints
for path in /swagger /swagger-ui /api-docs /openapi.json /swagger.json /docs /redoc; do
  curl -s --max-time 5 -o /dev/null -w "%{http_code} $path\n" "https://target.com$path"
done

# GraphQL introspection
curl -s -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'
```

### 3. Parameter Discovery
Identify hidden parameters on discovered endpoints.
```bash
# arjun — parameter discovery
arjun -u https://target.com/endpoint -o ./ptest-output/enumeration/arjun-params.json

# Manual parameter fuzzing
ffuf -u "https://target.com/page?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc all -fc 404 -fs <baseline-size>
```

### 4. Virtual Host Enumeration
Discover additional virtual hosts on the same IP.
```bash
# gobuster vhost mode
gobuster vhost -u https://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# ffuf vhost fuzzing
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -fc 404 -fs <baseline-size>
```

### 5. CMS-Specific Enumeration
Run targeted enumeration based on identified CMS/framework.
```bash
# WordPress
wpscan --url https://target.com --enumerate ap,at,u -o ./ptest-output/enumeration/wpscan.txt

# Pimcore
# Check: /admin/login, /bundles/, /js/routing, /_profiler, /_wdt
# Enumerate admin routes via FOS routing bundle if exposed

# Drupal
droopescan scan drupal -u https://target.com

# Joomla
joomscan -u https://target.com
```

### 6. JavaScript Analysis
Extract endpoints, secrets, and functionality from client-side code.
```bash
# linkfinder — extract endpoints from JS files
linkfinder -i https://target.com -o ./ptest-output/enumeration/linkfinder.txt

# Download and analyze JS bundles
curl -s https://target.com/static/js/main.*.js | grep -ioE '(https?://[^\s"]+|/api/[^\s"]+|/v[0-9]/[^\s"]+)' | sort -u

# Check for source maps
curl -sI https://target.com/static/js/main.*.js | grep -i sourcemap
curl -s https://target.com/static/js/main.*.js.map | head -100

# Extract hardcoded secrets/tokens from JS
curl -s https://target.com/static/js/main.*.js | grep -ioE '(api[_-]?key|token|secret|password|auth)["\s]*[:=]["\s]*[^\s",}]+' | sort -u
```

### 7. Authentication Endpoint Mapping
Document all authentication mechanisms and entry points.
```bash
# Identify login pages
for path in /login /signin /auth /admin/login /api/auth /oauth /sso; do
  code=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "https://target.com$path")
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "HTTP $code $path"
  fi
done

# Check auth mechanisms
curl -sI https://target.com/api/protected 2>/dev/null | grep -iE "www-authenticate|x-auth|authorization"

# OAuth/OIDC discovery
curl -s https://target.com/.well-known/openid-configuration | python3 -m json.tool
curl -s https://target.com/.well-known/oauth-authorization-server | python3 -m json.tool
```

## Scope Type Adjustments

- **web/API:** All techniques apply. Focus on techniques 1, 2, 3, 6, 7.
- **network:** Skip web-specific techniques. Focus on service-specific enumeration (SMB shares, SNMP walks, NFS exports).
- **cloud:** Focus on storage bucket enumeration, API gateway discovery, serverless function endpoints.
- **mobile:** Focus on API endpoints the app communicates with (extract from APK/IPA), certificate pinning checks.

## Output

Document findings in `./ptest-output/enumeration/`:
- `summary.md` — consolidated enumeration results
- `directories.md` — discovered paths per host
- `api-endpoints.md` — API endpoints with methods and auth requirements
- `parameters.md` — discovered parameters per endpoint
- `auth-mechanisms.md` — authentication mechanisms per application
- `js-analysis.md` — findings from JavaScript analysis
- `gobuster-*.txt` — raw tool output
- `ffuf-*.json` — raw tool output

Write `./ptest-output/enumeration/checklist.md`:

```markdown
# Enumeration Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 1 | Directory & File Brute-Force (MANDATORY) | PENDING | |
| 2 | API Endpoint Discovery (MANDATORY) | PENDING | |
| 3 | Parameter Discovery | PENDING | |
| 4 | Virtual Host Enumeration | PENDING | |
| 5 | CMS-Specific Enumeration | PENDING | |
| 6 | JavaScript Analysis | PENDING | |
| 7 | Authentication Endpoint Mapping | PENDING | |
```

Mark each technique as `DONE` or `SKIPPED (reason)` after execution.

## Exit Criteria
- [ ] All live web applications have directory/file enumeration completed.
- [ ] API endpoints mapped with methods and parameters.
- [ ] Authentication mechanisms identified per application.
- [ ] Hidden content and functionality discovered.
- [ ] Mandatory tools (gobuster/feroxbuster, ffuf) executed — or gap documented.
- [ ] Checklist shows all applicable techniques executed.
