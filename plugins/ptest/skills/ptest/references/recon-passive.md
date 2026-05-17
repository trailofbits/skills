---
name: recon-passive
description: Passive reconnaissance — gather intelligence without touching the target directly.
version: 3.0.0
metadata:
  category: reconnaissance
  phase: 1
  scope_types: [web, network, cloud, mobile, mixed]
---

# Skill: Passive Reconnaissance

## When to Use
- First phase of any engagement (Gateway 1 is OPEN).
- When you need to map the attack surface without alerting the target.

## Techniques & Tools

### 1. OSINT Gathering
Search public sources for target information.
```bash
# WHOIS lookup
whois target.com

# DNS records
dig target.com ANY
dig +short target.com MX
dig +short target.com TXT
host -t ns target.com

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value' | sort -u

# Google dorks
# site:target.com filetype:pdf
# site:target.com inurl:admin
# site:target.com intitle:"index of"
```

### 2. Subdomain Enumeration
Discover subdomains from passive sources.
```bash
# subfinder
subfinder -d target.com -o subdomains.txt

# amass (passive only)
amass enum -passive -d target.com -o amass-subs.txt

# from certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crt-subs.txt

# Wayback Machine URLs
waybackurls target.com | sort -u > wayback-urls.txt
```

### 3. Technology Fingerprinting
Identify tech stack from public-facing assets.
```bash
# HTTP headers (passive — only reads response headers)
curl -sI https://target.com

# Wappalyzer CLI
wappalyzer https://target.com

# whatweb
whatweb -v https://target.com
```

### 4. Email & Username Discovery
Search for exposed emails and usernames.
```bash
# theHarvester
theHarvester -d target.com -b all -l 500

# hunter.io (requires API key)
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$HUNTER_API_KEY" | jq '.data.emails[].value'

# GitHub search for leaked credentials
# Search: "target.com" password OR secret OR token
```

### 5. Network Mapping
Identify IP ranges and ASN information.
```bash
# ASN lookup
whois -h whois.radb.net -- '-i origin AS12345'

# BGP data
curl -s "https://api.bgpview.io/search?query_term=target.com" | jq .

# Shodan (passive — queries indexed data)
shodan search hostname:target.com
shodan host 1.2.3.4
```

### 6. Asset Validation

**This step is MANDATORY before reporting any subdomain-related findings.**

After enumeration, validate every discovered subdomain for liveness. DNS existence alone is NOT evidence of exposure.

#### Step 1: DNS Resolution Check
```bash
# Batch resolve all enumerated subdomains
while read sub; do
  ip=$(dig +short "$sub" | head -1)
  if [ -n "$ip" ]; then
    echo "RESOLVES|$sub|$ip"
  else
    echo "DEAD|$sub|"
  fi
done < subdomains.txt
```

Categorize results:
- **RESOLVES** — has a DNS A/AAAA record pointing to an IP
- **DEAD** — no DNS resolution (historical/decommissioned, exclude from findings)

#### Step 2: HTTP Probe (for resolving hosts)
```bash
# Probe each resolving subdomain for HTTP/HTTPS response
while read sub; do
  status=$(curl -sI --max-time 5 -o /dev/null -w "%{http_code}" "https://$sub" 2>/dev/null)
  if [ "$status" != "000" ]; then
    echo "LIVE|$sub|https|$status"
  else
    status=$(curl -sI --max-time 5 -o /dev/null -w "%{http_code}" "http://$sub" 2>/dev/null)
    if [ "$status" != "000" ]; then
      echo "LIVE|$sub|http|$status"
    else
      echo "NO_HTTP|$sub||"
    fi
  fi
done < resolving-subs.txt
```

Categorize results:
- **LIVE** — responds to HTTP/HTTPS (confirmed attack surface)
- **NO_HTTP** — resolves but no HTTP response (may have non-HTTP services; pass to active recon for port scanning)

#### Step 3: Classify
| Category | Meaning | Action |
|----------|---------|--------|
| LIVE | Resolves + HTTP response | Confirmed attack surface. Eligible for findings. |
| NO_HTTP | Resolves but no HTTP | Potential target. Pass to active recon for port scan. Do NOT report as finding. |
| DEAD | Does not resolve | Historical/inactive. Informational only. Not a finding. |

**Important:** When the subdomain list is very large (100+), batch the validation. Probe high-value targets first (admin panels, APIs, monitoring tools, databases), then sample the rest. Document the sampling methodology.

---

## Finding Standards

**These rules are mandatory for Phase 1 findings:**

1. **DNS existence is NOT a finding.** A subdomain appearing in CT logs or DNS is informational context for attack surface mapping — it is not a vulnerability.

2. **Only report a finding if ALL of the following are true:**
   - The host is **confirmed accessible** (LIVE status from validation)
   - The accessible service presents a **security concern** (e.g., unauthenticated panel, version disclosure, sensitive data exposure)
   - You have **direct evidence** (HTTP response, screenshot, or response body proving the concern)

3. **Severity guidance for passive recon findings:**
   - **Info:** Technology/version disclosure on confirmed-accessible hosts (e.g., `X-Powered-By` header)
   - **Low:** Confirmed information exposure with minor impact (e.g., directory listing with non-sensitive files)
   - **Medium:** Only if the service is confirmed accessible AND lacks authentication or exposes sensitive data (must be verified with evidence)
   - **High/Critical:** Extremely unlikely in passive recon. Requires confirmed unauthenticated access to sensitive systems with direct evidence.

4. **What to do with unverified potential issues:**
   - Document them in `domains-potential.md` as targets for active recon
   - Do NOT create findings for them
   - Note them in the phase summary as "requires active verification"

---

## Output

Document findings in `./ptest-output/recon-passive/`:
- `summary.md` — consolidated attack surface overview
- `domains-live.md` — confirmed accessible subdomains (resolved + HTTP response), with response codes
- `domains-potential.md` — resolved but not HTTP-accessible (for active recon to port scan)
- `domains-dead.md` — did not resolve (informational/historical only)
- `network.md` — IP ranges and ASNs
- `tech-stack.md` — technology stack per confirmed-live target
- `emails-usernames.md` — potential usernames/emails discovered

Write `./ptest-output/recon-passive/checklist.md`:

```markdown
# Passive Recon Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 1 | OSINT Gathering | PENDING | |
| 2 | Subdomain Enumeration | PENDING | |
| 3 | Technology Fingerprinting | PENDING | |
| 4 | Email & Username Discovery | PENDING | |
| 5 | Network Mapping | PENDING | |
| 6 | Asset Validation (DNS + HTTP probe) | PENDING | |
```

Mark each technique as `DONE` or `SKIPPED (reason)` after execution.

## Exit Criteria
- [ ] Attack surface is mapped (domains, IPs, subdomains).
- [ ] Enumerated subdomains validated for liveness (DNS + HTTP probe).
- [ ] Only confirmed-accessible hosts reported as findings.
- [ ] Technology stack identified on live hosts.
- [ ] Potential entry points listed (verified).
- [ ] Checklist shows all applicable techniques executed.
