---
name: recon-active
description: Active reconnaissance — network-layer discovery through direct probing of targets.
version: 3.0.0
metadata:
  category: reconnaissance
  phase: 2
  scope_types: [web, network, cloud, mobile, mixed]
---

# Skill: Active Reconnaissance

## When to Use
- After passive recon is complete (Gateway 1 PASSED).
- When you need to identify live hosts, open ports, and running services.

## Scope
This phase covers **network-layer discovery only**:
- Port scanning
- Service detection and banner grabbing
- OS fingerprinting
- Network topology mapping

Application-layer enumeration (directories, APIs, parameters) belongs in Phase 3 (Enumeration).

## Techniques & Tools

### 1. Port Scanning (MANDATORY: nmap)
Identify open ports and services on all in-scope hosts.
```bash
# Full TCP scan on primary targets
nmap -sV -sC -p- -oA ./ptest-output/recon-active/nmap-full-tcp target.com

# Fast initial scan (top ports)
nmap -sV --top-ports 1000 -T4 -oA ./ptest-output/recon-active/nmap-top1000 target.com

# UDP top 100
nmap -sU --top-ports 100 -oA ./ptest-output/recon-active/nmap-udp target.com

# Scan multiple IPs from passive recon
nmap -sV --top-ports 1000 -T4 -iL ./ptest-output/recon-passive/live-ips.txt -oA ./ptest-output/recon-active/nmap-all-hosts

# Masscan for speed on large ranges
masscan -p1-65535 --rate=1000 -oL ./ptest-output/recon-active/masscan.txt 10.0.0.0/24
```

**Requirements:**
- Scan ALL unique public IPs discovered in Phase 1 (not just the primary target)
- Document every open port with service version
- If nmap is unavailable, document the gap and use alternative (masscan + banner grab)

### 2. Service Detection & Banner Grabbing
Detailed version fingerprinting on discovered open ports.
```bash
# Intensive version detection
nmap -sV --version-intensity 9 -p <open-ports> target.com

# Manual banner grab
nc -nv target.com 22 <<< ""
curl -sI http://target.com:8080

# SMB enumeration (if port 445 open)
enum4linux -a target.com
smbclient -L //target.com -N

# SNMP (if port 161 open)
snmpwalk -v2c -c public target.com
```

### 3. OS Fingerprinting
```bash
# OS detection
nmap -O target.com

# TTL-based inference
ping -c 1 target.com | grep ttl
```

### 4. Network Topology Mapping
```bash
# Traceroute
traceroute target.com

# Identify shared hosting / CDN
# Compare IPs across subdomains to identify load balancers, CDNs, shared infrastructure
```

## Scope Type Adjustments

- **web/API:** Focus on HTTP/HTTPS ports (80, 443, 8080, 8443, 3000, 5000, 8000). Light UDP scan.
- **network:** Full TCP + UDP scan. All techniques apply.
- **cloud:** Focus on common cloud service ports. Check for metadata endpoints.
- **mobile:** Focus on API backend ports the app communicates with.

## Output

Document findings in `./ptest-output/recon-active/`:
- `summary.md` — consolidated scan results
- `ports-services.md` — open ports and services per host (table format)
- `nmap-*.xml/txt` — raw nmap output files
- `network-map.md` — topology and infrastructure notes

Write `./ptest-output/recon-active/checklist.md`:

```markdown
# Active Recon Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 1 | Port Scanning (nmap — MANDATORY) | PENDING | |
| 2 | Service Detection & Banner Grabbing | PENDING | |
| 3 | OS Fingerprinting | PENDING | |
| 4 | Network Topology Mapping | PENDING | |
```

Mark each technique as `DONE` or `SKIPPED (reason)` after execution.

## Exit Criteria
- [ ] All in-scope public IPs port-scanned (nmap executed).
- [ ] Open ports documented with service versions.
- [ ] Network topology understood (CDN, load balancers, shared infra).
- [ ] Checklist shows all applicable techniques executed.
- [ ] Mandatory tool (nmap) was run — or gap documented with justification.
