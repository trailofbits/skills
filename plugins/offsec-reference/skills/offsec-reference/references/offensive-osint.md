## offensive-osint

> Source: `/Users/ryan-osome-infosec/.claude/skills/offensive-osint//SKILL.md`

---
name: offensive-osint
description: "Operational arsenal for external red-team and bug-bounty reconnaissance. Concrete wordlists (28 Swagger paths, 13 GraphQL paths, 35 high-risk ports, 6 missing-header findings, 15 always-on HTTP checks, 5 SAML paths, cloud bucket permutations, JS guess-paths, vendor product fingerprints for Citrix/F5/Pulse/Fortinet/Cisco/PaloAlto/VMware/Exchange, cloud-native service fingerprints, container/K8s exposure paths, CI/CD platform paths, documentation/wiki leak paths, WHOIS/RDAP, DNS record catalog, Wayback CDX recipes), 43+-pattern secret-regex catalog (incl. modern AI API keys: Anthropic/OpenAI/HuggingFace/Cloudflare/DigitalOcean/npm/PyPI/Docker Hub/Atlassian/DataDog/Sentry/ngrok), 80+ dork corpus across 9 categories, GitHub code-search dorks, copy-paste curl/httpie probes for every check, post-discovery enumeration workflows (AWS/GitHub/Slack/JWT/PMAK/Anthropic/OpenAI), endpoint interest scoring rubric (0–100), mobile app ownership confidence, identity-fabric endpoints (Entra/Okta/ADFS/Google/SAML/M365 Teams+SharePoint+OneDrive+OAuth + user-enum), GraphQL field-suggestion enumeration when introspection disabled, 9 read-only secret validators (Postman/AWS/GitHub/Slack/Anthropic/OpenAI/npm/Atlassian/DataDog), Postman workspace search (verified endpoint), Stack Exchange sweep, public SaaS dorks, email security analysis (SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC), origin-discovery / CDN bypass techniques, TLS deep audit (sslyze/testssl.sh/JA3/JA4), reverse-DNS sweep + IPv6 enum, vulnerability prioritization data sources (NVD/EPSS/CISA KEV/ExploitDB/Metasploit), 27 attack-path hint templates, 80+ severity-matrix examples, LinkedIn employee enumeration, job posting tech-stack analysis, Slack/Discord workspace discovery, package registry leak hunting (npm/PyPI/Docker Hub/Quay/GHCR), sat imagery for physical recon, tooling quick-install one-liners, sector-specific recon notes (healthcare/finance/ICS-SCADA/IoT/government), runnable stdlib-only secret_scan.py helper, plus the existing tool references for username/email/phone/people/social/breach/infrastructure/crypto/media/geospatial/AI/archiving/automation. Use when you need concrete probe paths, regexes, payloads, scoring rules, curl one-liners, and tool URLs for an authorized external recon engagement."
version: 2.1.1
triggers:
  - external recon
  - external red team
  - red team external
  - attack surface management
  - ASM
  - bug bounty recon
  - bug bounty
  - reconnaissance
  - footprinting
  - asset discovery
  - swagger discovery
  - openapi discovery
  - graphql introspection
  - graphql discovery
  - subdomain enumeration
  - subdomain takeover
  - cloud bucket enumeration
  - bucket enum
  - S3 enum
  - GCS enum
  - Azure blob enum
  - identity fabric
  - SSO discovery
  - IdP fingerprinting
  - tenant fingerprinting
  - okta enum
  - entra enum
  - azure AD enum
  - ADFS enum
  - SAML metadata
  - mobile recon
  - APK analysis
  - mobile attack surface
  - secret scanning
  - secret leak
  - leaked credential
  - github dorking
  - google dorking
  - bing dorking
  - DDG dorking
  - postman workspace
  - stack exchange OSINT
  - breach lookup
  - have I been pwned
  - HudsonRock cavalier
  - infostealer
  - dehashed
  - intelx
  - shodan recon
  - censys recon
  - certificate transparency
  - crt.sh
  - JARM
  - favicon mmh3
  - JS endpoint extraction
  - sourcemap leak
  - copy paste probes
  - curl one-liner
  - email security analysis
  - SPF DMARC DKIM
  - origin discovery
  - CDN bypass
  - WAF bypass
  - vendor product fingerprints
  - Citrix Netscaler
  - F5 BIG-IP
  - Pulse Secure
  - FortiGate
  - PaloAlto GlobalProtect
  - Cisco AnyConnect
  - VMware vCenter
  - cloud native fingerprint
  - Lambda function URL
  - Cloud Run
  - kubernetes exposure
  - kubelet
  - etcd
  - CI CD exposure
  - Jenkins recon
  - GitLab self-hosted
  - GitHub Actions secrets
  - documentation leak
  - Notion public
  - Confluence anonymous
  - Trello board
  - WHOIS RDAP
  - DNS record catalog
  - Wayback CDX
  - LinkedIn enumeration
  - job posting tech stack
  - Slack workspace discovery
  - Discord server discovery
  - npm token leak
  - PyPI token leak
  - Docker Hub leak
  - sat imagery physical recon
  - TLS deep audit
  - JA3 JA4
  - reverse DNS sweep
  - IPv6 enumeration
  - CVE prioritization
  - EPSS scoring
  - CISA KEV
  - vulnerability prioritization
  - tooling install
  - sector specific recon
  - healthcare DICOM
  - finance SWIFT
  - ICS SCADA
  - Modbus
  - BACnet
  - post discovery workflow
  - JWT triage
  - AWS key triage
  - GraphQL field suggestion
  - Anthropic API key
  - OpenAI API key
  - Microsoft 365 deep
  - Teams federation
  - SharePoint enum
  - OneDrive enum
---

# Offensive OSINT — External Red-Team Arsenal

> Companion skill: `osint-methodology` (the "how to think" skill). This skill is the "what to reach for." Use them together.

## 0. When to use / When NOT

**Use this skill when:**
- You need concrete probe paths, wordlists, regexes, payloads, scoring rules, or tool URLs.
- You're executing reconnaissance and need the actual technical reference (vs. methodology).
- You're building a recon automation and need specific lists to seed it.

**Do NOT use this skill when:**
- The user is asking for active exploitation, post-exploitation, or anything past reconnaissance.
- The user is asking for defensive / blue-team detections.
- The target's authorization isn't established — see §1.

---

## 1. Authorization & Legal Posture

For assets the operator owns or has written authorization to assess. Soft scope check before acting against an unverified third-party target — see methodology skill §1 for the full posture.

---

## 2. Confidence Levels

- **TENTATIVE** — plausible based on indirect evidence (snippet-only dork match, single-source asset, inferred email pattern).
- **FIRM** — directly observed (subdomain resolves, HEAD-confirmed bucket exists, banner returned).
- **CONFIRMED** — verified via independent corroboration OR direct verification (live PMAK validation, multiple sources agree, listable bucket with object retrieval).

---

## 3. Output Format Conventions

Findings should carry: `id`, `module`, `asset_key`, `category`, `severity` (info/low/medium/high/critical), `confidence`, `title`, `description`, `evidence` (url + UTC timestamp + sha256 + raw ≤ 2 KiB), `references`, `remediation`. UTC timestamps everywhere.

---

## 4. Source Hygiene & Citations

URL + UTC timestamp + SHA-256 + tool version + run_id, every artifact. PNG screenshots, JSONL run logs, raw HTTP captures capped at 2 KiB body.

---

## 5. Do NOT

- Don't paste creds/PII/session tokens into cloud LLMs.
- Don't run destructive probes outside DEEP/`--aggressive`.
- Don't use validated credentials for anything except read-only liveness check.
- Don't single-source attribute.
- Don't assume vendor labels are ground truth.

---

## 6. General OSINT (curated tool refs)

- [OSINT Bookmarks](https://tools.myosint.training/) — comprehensive bookmarks.
- [OSINT Framework](https://osintframework.com/) — tool/resource directory.
- [IntelTechniques Tools](https://inteltechniques.com/tools/) — investigative suite.
- [Bellingcat Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/) — investigative journalism.
- [CyberSudo OSINT Toolkit](https://docs.google.com/spreadsheets/d/1EC0sKA_W9znzsxUt0wye9UYtyATXw5m8) — OSINT websites list.
- [Google Dorks](https://dorksearch.com/) — efficient Google searching.
- [Distributed Denial of Secrets](https://ddosecrets.com/) — leaked datasets.
- [Country-Specific Resources](https://digitaldigging.org/osint/) — country-targeted OSINT.

## 7. Search Engines

| Tool | Notes |
|------|-------|
| [Carrot2](https://search.carrot2.org/#/search/web) | Clusters results by topic |
| [etools](https://www.etools.ch/) | Metasearch |
| [Kagi](https://kagi.com/) | Privacy-first, non-personalized |
| [Brave Search](https://search.brave.com/) | Independent index; Goggles for custom ranking |
| [PDF Search](https://www.pdfsearch.io/) | PDF + table of contents |
| [Google Fact Check Explorer](https://toolbox.google.com/factcheck/explorer) | Cross-site fact-check |

---

## 8. Username & Email Investigation

| Tool | Purpose |
|------|---------|
| [Sherlock](https://github.com/sherlock-project/sherlock) | Username search across social networks |
| [Maigret](https://github.com/soxoj/maigret) | Profile collector by username |
| [What's My Name](https://whatsmyname.app/) | Username search |
| [Holehe](https://github.com/megadose/holehe) | Email registration check |
| [Epieos](https://epieos.com/) | Email pivots and metadata |
| [OSINT Industries](https://osint.industries/) | Email/username/phone lookups |
| [Hunter.io](https://hunter.io/) | Domain → emails |
| [EmailRep](https://emailrep.io/) | Email reputation |
| [Emailable](https://emailable.com/) | Email verification |
| [Mugetsu](https://mugetsu.io/) | X/Twitter username history |
| [RocketReach](https://rocketreach.co/) / [Apollo](https://www.apollo.io/) | Email enrichment + pattern guessing |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | Phone number intelligence |

Browser extensions: [GetProspect](https://chromewebstore.google.com/detail/email-finder-getprospect/bhbcbkonalnjkflmdkdodieehnmmeknp), [SignalHire](https://chrome.google.com/webstore/detail/signalhire-find-email-or/aeidadjdhppdffggfgjpanbafaedankd).

---

## 9. People Search

- [TruePeopleSearch](https://www.truepeoplesearch.com/) — free U.S. people search.
- [WhitePages](https://www.whitepages.com/), [Spokeo](https://www.spokeo.com/), [Webmii](https://webmii.com/), [Pipl](https://pipl.com/) (paid).
- [Clearbit](https://clearbit.com/) — company/individual data enrichment.
- [FaceCheck](https://facecheck.id/) / [FaceSeek](https://faceseek.online/) — reverse face search.

---

## 10. Phone Number OSINT

- [TrueCaller](https://www.truecaller.com/) — caller ID + spam blocking.
- [ThatsThem](https://thatsthem.com/) — reverse phone search.
- [Infobel](https://infobel.com/) — non-USA phone search.
- [FreeCarrierLookup](https://freecarrierlookup.com/) — carrier/type (US).
- [NumlookupAPI](https://numlookupapi.com/) [Freemium] — programmatic carrier checks.
- [CallerIDTest](https://calleridtest.com/), [Advanced Background Checks](https://www.advancedbackgroundchecks.com/).

---

## 11. Email-Pattern Inference (TENTATIVE candidates)

Given a `(first_name, last_name, domain)`, generate these 8 candidate addresses for breach pre-hits, phishing list curation, and downstream enrichment. Mark as **TENTATIVE** confidence until corroborated.

```
{first}.{last}@{domain}        # john.doe@example.com
{first}{last}@{domain}         # johndoe@example.com
{first}@{domain}               # john@example.com
{first[0]}{last}@{domain}      # jdoe@example.com
{first}.{last[0]}@{domain}     # john.d@example.com
{last}@{domain}                # doe@example.com
{first}_{last}@{domain}        # john_doe@example.com
{first}-{last}@{domain}        # john-doe@example.com
```

Lowercase before lookup. Strip diacritics for ASCII fallback. If the org uses a known pattern (e.g., Hunter.io shows `{first}.{last}` is dominant), prioritize that one and mark FIRM.

---

## 12. Email-Harvest Source Stack

Six parallel sources, dedup at the end:

1. **IntelX phonebook API** — 2-step search + poll. Largest single source for breach-era addresses.
2. **Hunter.io** — domain-search endpoint. ~25 free/month. Returns verified emails + roles.
3. **crt.sh** — extract X.509 SAN extensions. Many certs include admin/contact emails.
4. **DuckDuckGo SERP scrape** — HTML scrape of `"@{target-domain}"` results.
5. **Bing SERP scrape** — same query, complementary index.
6. **Wayback CDX** — historic snapshots of the target's homepage / contact / about pages often contain emails removed from the live site.

**Email regex:**
```regex
\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b
```

**Noise filter (reject numeric-only locals):**
```regex
^[0-9]+$
```
(Discards garbage like `12345@example.com` from random tokens.)

---

## 13. Social Media

| Platform | Tool |
|----------|------|
| Instagram | [Picuki](https://www.picuki.com/) — profile view without account |
| X/Twitter | [snscrape](https://github.com/snscrape/snscrape) — preferred CLI scraper; Twint as fallback |
| Facebook | [Graph Search](https://inteltechniques.com/tools/Facebook.html), [sowsearch.info](https://sowsearch.info/), [lookup-id.com](https://lookup-id.com/), [whopostedwhat.com](https://whopostedwhat.com/) |
| Facebook (research) | [Meta Content Library](https://transparency.meta.com/researcher) — CrowdTangle successor (researcher-gated) |
| YouTube/Twitch | [Social Blade](https://socialblade.com/) — analytics |
| TikTok | [Tokboard](https://tokboard.com/) — trends + profile analytics |
| Reddit | [Reveddit](https://www.reveddit.com/) — removed content; [RedTrack.social](https://redtrack.social/) — user history |
| Bluesky | [Firesky](https://firesky.tv/) — real-time firehose; [SkyView](https://bsky.jazco.dev/) — follower graphs |
| Mastodon | [FediSearch](https://fedisearch.skorpil.cz/) — cross-instance search; [Fedifinder](https://fedifinder.glitch.me/) — find Twitter users on Mastodon |
| Faces | [Search4Faces](https://search4faces.com/) |

---

## 14. Public Records & Company Information

- [OpenCorporates](https://opencorporates.com/) — world's largest open company DB.
- [SEC EDGAR](https://www.sec.gov/edgar.shtml) — U.S. company filings.
- [OpenOwnership Register](https://register.openownership.org/) — beneficial ownership.
- [MuckRock](https://www.muckrock.com/) — FOIA repository + request tracking.
- [EU Tenders (TED)](https://ted.europa.eu/) — EU procurement notices.
- [World Bank Projects](https://projects.worldbank.org/) — project + procurement records.
- [UK Companies House](https://find-and-update.company-information.service.gov.uk/) — UK companies + officers + filings.

### 14.1 RU registries

[Rusprofile](https://www.rusprofile.ru/), [Kontur.Focus](https://focus.kontur.ru/) (freemium), [zakupki.gov.ru](https://zakupki.gov.ru/) (procurement), EGRUL/EGRIP (official, captcha-gated).

### 14.2 CN registries + USCC + ICP

- **GSXT** — [gsxt.gov.cn](https://www.gsxt.gov.cn/) National Enterprise Credit Info; cross-check with Tianyancha / Qichacha.
- **USCC (Unified Social Credit Code)** — 18-character entity ID assigned to all CN legal entities. Format: `<region:6><authority:2><type:1><serial:9>`. Useful for joining GSXT records to ICP filings.
- **ICP Beian** — [beian.miit.gov.cn](https://beian.miit.gov.cn/) — every domain serving traffic in mainland CN must register an ICP filing; the filing links the domain to a USCC, which links to the legal entity in GSXT.
- Workflow: `target.cn` domain → ICP lookup → USCC → GSXT → entity name + officers + adjacent registered entities.

### 14.3 Sanctions & Compliance

- [OFAC SDN List](https://sanctionssearch.ofac.treas.gov/), [EU Sanctions Map](https://www.sanctionsmap.eu/).
- [OpenSanctions](https://www.opensanctions.org/) — aggregated.
- [OCCRP Aleph](https://aleph.occrp.org/) — investigative documents, leaks, company records.

---

## 15. Breach & Leak Data

- [Have I Been Pwned](https://haveibeenpwned.com/) — breach lookup; Pwned Passwords API (k-anonymity).
- [Dehashed](https://dehashed.com/) — credential search (paid).
- [IntelX](https://intelx.io/) — data intelligence.
- [LeakCheck](https://leakcheck.io/), [Snusbase](https://snusbase.com/), [BreachDirectory](https://breachdirectory.org/), [Scattered Secrets](https://scatteredsecrets.com/), [Phonebook](https://phonebook.cz/), [LeakPeek](https://leakpeek.com/).
- [Cavalier (Hudson Rock)](https://cavalier.hudsonrock.com/) — **infostealer log lookups; FREE; highest single-source ROI for finding compromised employee credentials in corporate SSO**.

### 15.0.1 HudsonRock Cavalier — direct API recipe

The web UI wraps a **public, unauthenticated JSON API**. Hit it directly:

```bash
# By domain (canonical first call)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=target.com" | jq .

# By email (single-account check)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=alice@target.com" | jq .

# By URL (when target's app is the breach victim)
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-url?url=https://app.target.com" | jq .
```

PowerShell:
```powershell
$hr = Invoke-RestMethod -Uri "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=$D" -TimeoutSec 30
"Employees: $($hr.employees) | Users: $($hr.users) | Third-party: $($hr.third_parties) | Total: $($hr.total)"
$hr.data.employees_urls | Sort-Object -Property occurrence -Descending | Select-Object -First 20
$hr.data.clients_urls   | Sort-Object -Property occurrence -Descending | Select-Object -First 15
```

**Top-level JSON fields:**
- `total` — total stealer entries touching this domain.
- `totalStealers` — global stealer-log corpus size (context only).
- `employees` — count of `<*>@<domain>` accounts found.
- `users` — count of accounts where the domain appeared as a *visited* URL (customers/vendors).
- `third_parties` — accounts touching adjacent domains in the org.
- `data.employees_urls[]` — `{occurrence, type, url}` — internal apps where employees were logging in when stolen. **Subdomain hits here = recon gold.**
- `data.clients_urls[]` — same shape; user-facing apps (often reveals undocumented public portals).
- `data.stealer_families[]` — `{_key, _value}` → which stealer (RedLine / Lumma / StealC / Vidar / Raccoon).
- `data.dates_compromised[]` — `{_key, _value}` → temporal distribution.

**Free-tier caveats (CRITICAL to know):**
- Subdomain hostnames in `data.*_urls[]` past the first few are **redacted with asterisks** (`*****.target.com`). Pivot to paid Cavalier tier or other sources for unredacted.
- Free endpoint returns counts + sample URLs only. Cleartext passwords + emails are **never** in the free response.
- Rate limit ~1 req/sec/IP; 429 on burst. Sleep 1s between calls.
- For unredacted creds + bulk enumeration → paid Cavalier portal.

**Severity mapping (per §15.1 + §15.2):** `employees ≥ 10` → CRITICAL, **regardless of whether the breached service is still online** (legacy Lotus Domino / on-prem mail decommissioned + cloud SSO migration → employees almost always reuse passwords → SSO_EXPOSURE escalates CRITICAL).

### 15.1 Domain-Level Breach Severity Mapping

When you query a breach corpus by domain, map the result to severity like so:

| Stat | Severity |
|---|---|
| ≥ 10 employees compromised | **CRITICAL** |
| 1–9 employees compromised | **HIGH** |
| ≥ 1 end-user (non-employee) compromised | **MEDIUM** |
| Domain seen in breach with 0 named accounts | **INFO** |

**Employees vs end-users distinction:** an employee account is `<anything>@<target-domain>` (the breach victim is the target's own staff). An end-user account is the target's customer who reused a password — useful for credential-stuffing risk awareness but not directly compromising the target's identity fabric.

### 15.2 SSO_EXPOSURE finding

When a discovered SSO tenant (Entra GUID / Okta slug / Google Workspace domain) intersects with the breach corpus on its domain → `SSO_EXPOSURE` finding, severity **CRITICAL**. Evidence: tenant ID + product + employee count + per-account source attribution.

**Legacy-mail-decommissioned pattern (high-value variant):**

If `mail.<domain>` / `webmail.<domain>` returns **NXDOMAIN today** but HudsonRock/HIBP corpus still has historical employee credentials against it AND `autodiscover.<domain>` resolves to Microsoft IPs (M365) or `aspmx.l.google.com` MX (Workspace), the org migrated from on-prem to cloud — and the stolen passwords almost certainly survived the migration via password reuse. **Escalate to CRITICAL `SSO_EXPOSURE`** even when the legacy host is dead.

Concrete triggers (all three together):
1. `Resolve-DnsName mail.<domain> -Type A` → NXDOMAIN (legacy gone)
2. HudsonRock corpus has employee URLs against the *old* host (e.g. `mail.<domain>/names.nsf` for Lotus Domino, `mail.<domain>/owa/` for Exchange, `mail.<domain>/iwaredir.nsf` for iNotes, `mail.<domain>/zimbra/` for Zimbra)
3. Current MX → M365 / Google Workspace / Zoho cloud (DNS confirms migration)

Evidence pack: tenant GUID + breach count + 3+ legacy URLs from corpus + autodiscover Microsoft IPs + current MX. Recommend forced password rotation + MFA audit + Conditional Access review.

---

## 16. Pre-built Wordlists & Probe Paths

Copy-pasteable arsenals, severity-annotated where relevant.

### 16.1 Swagger / OpenAPI discovery — 28 paths

Probe each path on every alive webapp. GET (or HEAD if rate-limited).

```
swagger.json
swagger.yaml
swagger/v1/swagger.json
swagger/v2/swagger.json
swagger-ui.html
swagger-ui/
swagger-resources
api-docs
api-docs.json
api/swagger
api/swagger.json
api/swagger-ui.html
api/v1/swagger.json
api/v2/swagger.json
api/v3/api-docs
v2/api-docs
v3/api-docs
openapi.json
openapi.yaml
openapi/v1
openapi/v3
docs
redoc
rapidoc
api/docs
api/documentation
.well-known/openapi
```

**Severity:**
- Reachable Swagger/OpenAPI spec without auth → **HIGH** `LEAKY_API_SPEC` (full endpoint enumeration leaks; often reveals undocumented internal APIs).
- Behind auth but accessible to any authenticated user → MEDIUM (still discloses internal API surface).

### 16.2 GraphQL discovery — 13 paths

```
graphql
graphiql
api/graphql
v1/graphql
v2/graphql
query
api/query
gql
altair
playground
subscriptions
graphql/console
api/v1/graphql
```

**Standard introspection POST body:**
```json
{
  "operationName": "IntrospectionQuery",
  "query": "query IntrospectionQuery { __schema { types { name kind fields { name type { name kind } } } queryType { name } mutationType { name } subscriptionType { name } } }"
}
```

**Severity:**
- Introspection returns schema without auth → **HIGH** `OPEN_GRAPHQL_API`.
- Field-suggestion enumeration possible (server returns "did you mean" for typo'd field names) → **MEDIUM** (re-derive partial schema even when introspection is disabled).
- `/graphql` accepts batched queries (`[...]` request body) → MEDIUM (rate-limit bypass surface; auth bypass via mixed batches).

UI markers (lower severity but still discoverable):
- HTML response contains `graphiql`, `playground`, `apollo studio`, `altair` → GraphiQL UI exposed (often shipped accidentally on prod).

### 16.3 High-risk ports — 35 services

For each open port, emit a finding with the severity and "why an attacker cares" below. Source for the open-port observation: Shodan InternetDB (free, 1 req/sec) is the recommended starting point.

| Port | Service | Severity | Why it matters |
|---|---|---|---|
| 21 | FTP | HIGH | Anonymous read often enabled; cleartext creds. |
| 22 | SSH | LOW | Banner discloses version; brute-force surface. |
| 23 | Telnet | HIGH | Cleartext protocol; should never be exposed. |
| 25 | SMTP | LOW | Open relay risk; version banner. |
| 53 | DNS | LOW | Recursion = DDoS amplifier; AXFR opportunism. |
| 80 | HTTP | INFO | Standard. |
| 110 | POP3 | LOW | Cleartext if no STARTTLS. |
| 111 | rpcbind | MEDIUM | NFS exports enumeration. |
| 135 | MS RPC | HIGH | Enum via Impacket. |
| 139 | NetBIOS-SSN | HIGH | File/printer enum. |
| 143 | IMAP | LOW | Cleartext if no STARTTLS. |
| 161 | SNMP | HIGH | Community strings often `public`/`private`; full device enum. |
| 389 | LDAP | HIGH | Anonymous bind = full directory dump. |
| 443 | HTTPS | INFO | Standard. |
| 445 | SMB | **CRITICAL** | EternalBlue, SMB relay, anonymous shares. |
| 465 | SMTPS | LOW | Banner. |
| 514 | rsyslog | MEDIUM | Log injection / DoS. |
| 587 | SMTP-MSA | LOW | Banner. |
| 631 | IPP/CUPS | MEDIUM | Print server enum / RCE in old CUPS. |
| 873 | rsync | HIGH | Modules often listable; backup data exposure. |
| 1433 | MSSQL | HIGH | Brute-force; xp_cmdshell. |
| 1521 | Oracle TNS | HIGH | Brute-force; SID enum. |
| 2049 | NFS | HIGH | World-readable exports. |
| 2375 | Docker API (unencrypted) | **CRITICAL** | Unauthenticated container/host takeover. |
| 2376 | Docker API (TLS) | HIGH | Cert validation bypass risk. |
| 3000 | Common dev / Grafana | MEDIUM | Often Grafana / Express dev with default creds. |
| 3306 | MySQL | HIGH | Brute-force; default `root:""`. |
| 3389 | RDP | **CRITICAL** | BlueKeep / DejaBlue / NLA bypass. |
| 5432 | PostgreSQL | HIGH | Brute-force; default `postgres:postgres`. |
| 5601 | Kibana | HIGH | Often unauthenticated; Elasticsearch pivot. |
| 5900 | VNC | HIGH | Often unauthenticated or weak password. |
| 5984 | CouchDB | HIGH | Default no auth; admin party. |
| 6379 | Redis | **CRITICAL** | No auth default; write `authorized_keys` for SSH. |
| 7001 | WebLogic | HIGH | Frequent CVEs (CVE-2020-14882, etc.). |
| 8000 | Common dev | MEDIUM | Django, common dev servers. |
| 8080 | HTTP-alt | MEDIUM | Tomcat, Jenkins, common proxy. |
| 8443 | HTTPS-alt | MEDIUM | Same as 8080. |
| 8888 | Common dev / Jupyter | HIGH | Jupyter often exposes interactive shell. |
| 9090 | Cockpit / Prometheus | HIGH | Server admin UI / metrics scraping. |
| 9200 | Elasticsearch | **CRITICAL** | Typically no auth. |
| 9300 | Elasticsearch transport | HIGH | Cluster join + RCE. |
| 11211 | memcached | MEDIUM | UDP DDoS amp; data dump. |
| 27017 | MongoDB | **CRITICAL** | No auth by default. |
| 50070 | Hadoop NameNode | HIGH | HDFS browse. |

When Shodan InternetDB returns `vulns[]` for a port, escalate the finding severity by one tier and include the CVE list in evidence.

### 16.4 Missing security headers — 6 findings

For every alive webapp, audit response headers. Each missing header below = one finding.

| Header | Severity (default) | Severity (sensitive path) | Notes |
|---|---|---|---|
| `Strict-Transport-Security` | MEDIUM | **HIGH** | Sensitive paths: `/login`, `/signin`, `/sso`, `/admin`, `/auth`. |
| `Content-Security-Policy` | MEDIUM | MEDIUM | XSS impact mitigation gone. |
| `X-Frame-Options` | LOW | LOW | Clickjacking. (CSP `frame-ancestors` is the modern replacement.) |
| `X-Content-Type-Options` | LOW | LOW | MIME-sniff XSS. |
| `Referrer-Policy` | INFO | INFO | Outbound link leakage. |
| `Permissions-Policy` | INFO | INFO | Feature-policy hardening. |

### 16.5 Always-on HTTP checks — 15 paths

Run these against every alive webapp regardless of Nuclei availability. Cheap; high signal.

| Path | Finding | Severity | Match logic |
|---|---|---|---|
| `/.git/config` | Exposed `.git` repo | **CRITICAL** | Body contains `[core]`, `[remote`, `repositoryformatversion` |
| `/.git/HEAD` | Exposed `.git/HEAD` | HIGH | Body matches `^ref:\s` |
| `/.env` | Exposed `.env` | **CRITICAL** | Multiline regex `^\s*[A-Z_][A-Z0-9_]*\s*=` |
| `/server-status` | Apache server-status | MEDIUM | Body contains `Apache Server Status` or matching title |
| `/server-info` | Apache mod_info | MEDIUM | Body contains `Apache Server Information` |
| `/.DS_Store` | Exposed `.DS_Store` | LOW | Byte signature `\x00\x00\x00\x01Bud1` |
| `/phpinfo.php` | phpinfo() leak | HIGH | Body contains `phpinfo()`, `PHP Version`, or matching title |
| `/info.php` | phpinfo() (alt path) | HIGH | Same as above |
| `/actuator/env` | Spring Boot `/actuator/env` | **CRITICAL** | Body contains `"propertySources"`, `systemProperties`, `systemEnvironment` |
| `/actuator/heapdump` | Spring Boot heapdump | **CRITICAL** | HPROF magic bytes / large binary download |
| `/_cat/indices` | Elasticsearch open | HIGH | Returns index list |
| `/console` | Jenkins script console | HIGH | Body contains `Jenkins`/`Script Console` |
| `/manager/html` | Tomcat Manager | HIGH | Body contains `Tomcat Web Application Manager` |
| `/wp-admin/install.php` | Orphaned WP install | LOW | Body contains `WordPress Installation` |
| `/.well-known/security.txt` | Disclosure policy info | INFO | Parse contact + policy fields |

Plus parse `/robots.txt` for `Disallow:` paths — those become the next-tier wordlist for that target.

### 16.6 SAML metadata — 5 paths

```
/saml/metadata
/FederationMetadata/2007-06/FederationMetadata.xml
/federationmetadata/2007-06/federationmetadata.xml
/simplesaml/saml2/idp/metadata.php
/auth/saml2/metadata
```

Reachable SAML metadata XML reveals: `EntityID`, signing certs (often pinned → cert-reuse pivot), `SingleSignOnService` URL, `NameIDFormat`. Mark as `MISCONFIG` (LOW severity unless metadata leaks internal hostnames or non-public certs, then MEDIUM).

### 16.7 SSO subdomain prefixes — 8 prefixes

Probe each against root domain + every sibling brand domain:
```
auth.{domain}
login.{domain}
sso.{domain}
idp.{domain}
iam.{domain}
identity.{domain}
accounts.{domain}
oauth.{domain}
```

Plus probe `/.well-known/openid-configuration` on every alive subdomain (regardless of prefix).

### 16.8 Cloud bucket permutation arsenal

**6 prefixes:**
```
""           # bare candidate
backup-
assets-
static-
dev-
prod-
```

**15 suffixes:**
```
""           # bare candidate
-backup
-assets
-static
-media
-data
-uploads
-dev
-prod
-staging
-logs
-private
-public
-dump
-archive
```

**47 generic stems** (filter unless combined with target-identifying token):
```
www, mail, email, app, apps, web, webmail, ftp, cdn, static, assets, media, img, images,
videos, download, downloads, upload, uploads, data, files, docs, support, help, kb,
blog, news, dev, test, staging, stg, qa, uat, sandbox, preprod, preview, vpn,
mx, smtp, imap, pop, dns, ns, ns1, ns2, mx1, mx2
```

**Provider URL templates:**

S3:
```
https://{candidate}.s3.amazonaws.com/
https://{candidate}.s3-{region}.amazonaws.com/      # try us-east-1, us-west-2, eu-west-1, ap-southeast-1 first
https://s3.{region}.amazonaws.com/{candidate}/
```

GCS:
```
https://{candidate}.storage.googleapis.com/
https://storage.googleapis.com/{candidate}/
```

Azure Blob:
```
https://{candidate}.blob.core.windows.net/
```

**Probe technique:** HEAD first → 200/301 = exists, 403 = exists private, 404 = skip. On exists, GET root → if XML/JSON object listing returns, **CRITICAL** `PUBLIC_CLOUD_BUCKET`. Direct-URL object reads but not listable → **HIGH** `PUBLIC_CLOUD_BUCKET_OBJECT_READ`.

### 16.9 JS guess-paths for endpoint discovery

Probe these paths on every alive webapp (in addition to scraped `<script src=...>`):

```
/main.js
/app.js
/bundle.js
/runtime.js
/index.js
/vendor.js
/_next/static/_buildManifest.js
/_next/static/_ssgManifest.js
/static/js/main.js
/static/js/bundle.js
/assets/index.js
/static/js/main.<hash>.js                 # try hash discovery via 404 patterns
```

For every found JS, also try `<jsfile>.map` for sourcemap leaks (HIGH `INFO_DISCLOSURE`).

### 16.10 Endpoint extraction regex tiers

Three tiers, run in order on every JS body + every sourcesContent[] blob:

**Tier 1 — generic quoted paths:**
```regex
['"`](/[A-Za-z0-9_\-./{}\[\]?=&%:]+)['"`]
```
Match group: the path. High recall, lots of false positives — apply allowlist downstream.

**Tier 2 — API-ish paths (biased filter on tier 1):**
```regex
['"`](/(?:api|graphql|gql|v\d+|swagger|openapi|rest|services|internal|admin|auth|oauth|user|users|account|accounts|search|export|upload|file|files|download|webhook|hooks|callback|admin)/[A-Za-z0-9_\-./{}\[\]?=&%:]+)['"`]
```

**Tier 3 — fully-qualified URLs:**
```regex
\bhttps?://[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?::\d+)?[/A-Za-z0-9_\-./{}\[\]?=&%:#]*
```

Dedup on `(method, normalized-path-template)` where the template replaces `/123/` with `/{id}/` etc.

### 16.11 Internal-host leakage regexes

Run on every JS body + sourcesContent + APK strings + manifest:

**RFC1918:**
```regex
\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|127\.(?:\d{1,3}\.){2}\d{1,3})\b
```

**Internal DNS suffixes:**
```regex
\b[A-Za-z0-9][A-Za-z0-9\-]{0,62}\.(?:internal|corp|lan|intranet|local|prod|staging|dev|qa|test)\b
```

**Kubernetes service DNS:**
```regex
\b[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+\.svc(?:\.cluster\.local)?\b
```

Each match → MEDIUM `INFO_DISCLOSURE`. Aggregate per host: if many matches share the same internal subdomain, that's a recon seed for any future internal phase.

### 16.12 Subdomain-takeover provider fingerprints (summary, 27 providers)

Watch for these CNAME targets + the corresponding "available for claim" response signature:

| Provider | CNAME pattern | Takeover signature |
|---|---|---|
| GitHub Pages | `*.github.io` | `There isn't a GitHub Pages site here.` |
| Heroku | `*.herokuapp.com` | `No such app` |
| AWS S3 | `*.s3*.amazonaws.com` | `NoSuchBucket` |
| AWS CloudFront | `*.cloudfront.net` | `Bad request` w/ specific X-Amz error |
| Azure (multiple) | `*.azurewebsites.net`, `*.blob.core.windows.net`, `*.cloudapp.net`, `*.trafficmanager.net` | Various per-product 404 patterns |
| Shopify | `shops.myshopify.com` | `Sorry, this shop is currently unavailable.` |
| Squarespace | `*.squarespace.com` | `No Such Account` |
| Tumblr | `*.tumblr.com` | `Whatever you were looking for doesn't currently exist.` |
| WordPress | `*.wordpress.com` | `Do you want to register *.wordpress.com?` |
| Fastly | various | Fastly-specific 404 |
| Pantheon | `*.pantheonsite.io` | `The gods are wise, but do not know of the site...` |
| Surge.sh | `*.surge.sh` | `project not found` |
| Bitbucket Pages | `*.bitbucket.io` | Repository not found |
| Tilda | `*.tilda.ws` | `Please renew your subscription` |
| Strikingly | `*.s.strikinglydns.com` | `PAGE NOT FOUND` |
| Smartling | `*.smartling.com` | Domain is not configured |
| Ngrok | `*.ngrok.io` | Tunnel not found |
| Webflow | `*.webflow.io` | Site not found |
| Zendesk | `*.zendesk.com` | `Help Center Closed` |
| Cargo | `*.cargocollective.com` | `404 Not Found` (with cargo branding) |
| Statuspage | `*.statuspage.io` | Not found |
| Intercom | `*.intercom.help` | Not found |
| Helpjuice | `*.helpjuice.com` | Not found |
| Helpscout | `*.helpscoutdocs.com` | Not found |
| Tictail | `*.tictail.com` | Not found |
| Brightcove | `*.brightcovegallery.com` | Not found |
| Smugmug | various | Not found |

For full per-provider detection signatures + edge cases, use SubdomainX or Subzy/Subjack against a freshly-fetched fingerprint database.

---

### 16.13 Copy-Paste Probes (curl one-liners)

Every probe path in §16.1–16.12 with a runnable curl. Defaults: `-sk` (silent + ignore TLS errors), `-m 10` (10s max), `-o /tmp/r` (response body to disk), `-w '%{http_code}\n'` (print status code), `-A "Mozilla/5.0"` (UA — change per persona).

**Always-on HTTP checks (§16.5):**

```bash
T="https://target.example"

# .git/config (CRITICAL)
curl -sk -m 10 "$T/.git/config" | grep -E '\[core\]|\[remote|repositoryformatversion'

# .git/HEAD (HIGH)
curl -sk -m 10 "$T/.git/HEAD" | grep -E '^ref:'

# .env (CRITICAL)
curl -sk -m 10 "$T/.env" | grep -E '^[[:space:]]*[A-Z_][A-Z0-9_]*[[:space:]]*='

# Apache /server-status (MEDIUM)
curl -sk -m 10 "$T/server-status" | grep -i 'Apache Server Status'

# Apache /server-info (MEDIUM)
curl -sk -m 10 "$T/server-info" | grep -i 'Apache Server Information'

# .DS_Store (LOW)
curl -sk -m 10 "$T/.DS_Store" -o /tmp/dsstore && file /tmp/dsstore | grep -i 'data'

# phpinfo.php (HIGH)
curl -sk -m 10 "$T/phpinfo.php" | grep -E 'phpinfo\(\)|PHP Version'

# info.php (HIGH)
curl -sk -m 10 "$T/info.php" | grep -E 'phpinfo\(\)|PHP Version'

# Spring Boot /actuator/env (CRITICAL)
curl -sk -m 10 "$T/actuator/env" | grep -E '"propertySources"|systemProperties|systemEnvironment'

# Spring Boot /actuator/heapdump (CRITICAL — saves binary; check size)
curl -sk -m 30 "$T/actuator/heapdump" -o /tmp/heap && file /tmp/heap | grep -i 'HPROF\|data'

# Elasticsearch open (HIGH)
curl -sk -m 10 "$T/_cat/indices?v"

# Jenkins script console (HIGH)
curl -sk -m 10 "$T/script" | grep -iE 'Jenkins|Script Console'

# Tomcat manager (HIGH)
curl -sk -m 10 "$T/manager/html" -w '%{http_code}\n' | tail -1     # 401 = present + auth-gated; 200 = no auth

# WordPress orphan installer (LOW)
curl -sk -m 10 "$T/wp-admin/install.php" | grep -i 'WordPress Installation'

# security.txt (INFO)
curl -sk -m 10 "$T/.well-known/security.txt"
```

**SSO subdomain prefixes (§16.7):**

```bash
D="target.example"
for prefix in auth login sso idp iam identity accounts oauth; do
  echo "=== ${prefix}.${D} ==="
  curl -sk -m 10 "https://${prefix}.${D}/.well-known/openid-configuration" -o /dev/null -w '%{http_code}\n'
done

# Generic OIDC discovery on any host:
curl -sk -m 10 "https://${HOST}/.well-known/openid-configuration" | jq .
```

**SAML metadata paths (§16.6):**

```bash
H="target.example.com"
for p in /saml/metadata \
         /FederationMetadata/2007-06/FederationMetadata.xml \
         /federationmetadata/2007-06/federationmetadata.xml \
         /simplesaml/saml2/idp/metadata.php \
         /auth/saml2/metadata; do
  echo "=== $p ==="
  curl -sk -m 10 "https://${H}${p}" -o /dev/null -w '%{http_code} %{size_download}\n'
done
```

**Cloud bucket probes (§16.8):**

```bash
B="candidate-bucket-name"

# S3 (us-east-1 first)
curl -sk -m 10 -I "https://${B}.s3.amazonaws.com/" -w 'STATUS:%{http_code}\n' | head -20
# If 200/301: list objects
curl -sk -m 10 "https://${B}.s3.amazonaws.com/?list-type=2" | head -50

# S3 region-specific
for r in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  curl -sk -m 10 -I "https://${B}.s3-${r}.amazonaws.com/" -w "${r}: %{http_code}\n"
done

# GCS
curl -sk -m 10 -I "https://${B}.storage.googleapis.com/"
curl -sk -m 10 "https://storage.googleapis.com/${B}/"

# Azure Blob
curl -sk -m 10 -I "https://${B}.blob.core.windows.net/"
curl -sk -m 10 "https://${B}.blob.core.windows.net/?comp=list"
```

**GraphQL introspection POST (§16.2):**

```bash
H="https://target.example/graphql"

curl -sk -m 15 -X POST "$H" \
  -H 'Content-Type: application/json' \
  -d '{
    "operationName":"IntrospectionQuery",
    "query":"query IntrospectionQuery { __schema { types { name kind fields { name type { name kind } } } queryType { name } mutationType { name } subscriptionType { name } } }"
  }' | jq '.data.__schema.types | length'
```

**Read-only secret validators (§23):**

```bash
# Postman PMAK
curl -sk -m 10 -H "X-Api-Key: PMAK-..." https://api.getpostman.com/me | jq .

# AWS (use boto3 instead of curl — pre-signing complexity)
python3 -c "import boto3; print(boto3.client('sts', aws_access_key_id='AKIA...', aws_secret_access_key='...').get_caller_identity())"

# GitHub PAT (note scope header)
curl -sk -m 10 -H "Authorization: token ghp_..." https://api.github.com/user -D /tmp/h | jq -r '.login,.email'
grep -i 'X-OAuth-Scopes' /tmp/h

# Slack
curl -sk -m 10 -H "Authorization: Bearer xoxb-..." -X POST https://slack.com/api/auth.test | jq .

# Anthropic (read-only validation)
curl -sk -m 10 -H "x-api-key: sk-ant-..." -H "anthropic-version: 2023-06-01" https://api.anthropic.com/v1/models | jq '.data | length'

# OpenAI
curl -sk -m 10 -H "Authorization: Bearer sk-..." https://api.openai.com/v1/models | jq '.data | length'

# npm
curl -sk -m 10 -H "Authorization: Bearer npm_..." https://registry.npmjs.org/-/whoami | jq .

# Atlassian (account)
curl -sk -m 10 -u "email:ATATT3xFfGF0_..." https://your-domain.atlassian.net/rest/api/3/myself | jq .

# DataDog (API + APP key both required)
curl -sk -m 10 -H "DD-API-KEY: ..." -H "DD-APPLICATION-KEY: ..." https://api.datadoghq.com/api/v1/validate | jq .
```

**Bulk webapp triage (httpx, faster than curl loop):**

```bash
# Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest
echo "target.example" | httpx -sc -title -tech-detect -web-server -ip -cdn -follow-redirects

# With probe list
cat subdomains.txt | httpx -sc -title -tech-detect -path /actuator/env,/.git/config,/.env -mc 200,301,403
```

**Save responses for evidence:**

```bash
mkdir -p evidence/$(date -u +%Y%m%d)
T="https://target.example"
P="/actuator/env"
TS=$(date -u +%Y%m%dT%H%M%SZ)
SAFE_NAME=$(echo "${T}${P}" | tr '/:' '_')
curl -sk -m 10 "$T$P" -o "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.body" \
  -D "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.headers"
sha256sum "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}".* > "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.sha256"
```

---

### 16.14 Email Security Analysis (SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC)

Spoof feasibility + SaaS tenant inference from a target's email DNS.

**SPF lookup + parsing:**

```bash
D="target.example"
dig +short TXT "$D" | grep -i 'v=spf1'
```

**Common SPF parsing checklist:**
- Ends in `-all` (hardfail) → strict; major providers reject spoofs.
- Ends in `~all` (softfail) → spam folder for spoofs.
- Ends in `?all` or no `all` → permissive; spoofs likely deliver.
- Includes (`include:`) reveal SaaS tenants:
  - `include:_spf.google.com` → Google Workspace.
  - `include:spf.protection.outlook.com` → Microsoft 365.
  - `include:_spf.salesforce.com` → Salesforce.
  - `include:mail.zendesk.com` → Zendesk customer.
  - `include:sendgrid.net` → SendGrid customer.
  - `include:mailgun.org` → Mailgun customer.
  - `include:_spf.atlassian.net` → Atlassian Cloud.
  - `include:amazonses.com` → AWS SES.
  - `include:mktomail.com` → Marketo.
  - `include:_spf.intuit.com` → Intuit (QuickBooks/Mailchimp).
  - `include:spf.mandrillapp.com` → Mandrill.
  - `include:_spf.workday.com` → Workday.

If SPF includes ≥10 mechanisms (max-lookups limit) → SPF eval likely fails → spoofs may pass. Tools: `spfquery`, `spftools` (online), `dig +trace`.

**DMARC policy + alignment:**

```bash
dig +short TXT "_dmarc.${D}"
```

Parse for:
- `p=` → primary policy (`none`, `quarantine`, `reject`).
- `sp=` → subdomain policy (defaults to `p=`).
- `aspf=` / `adkim=` → alignment mode (`r`=relaxed, `s`=strict).
- `pct=` → percentage of mail to which policy applies.
- `rua=` / `ruf=` → reporting addresses (often reveals SaaS DMARC vendors: dmarcian, valimail, Agari, easydmarc).

**Severity:**
- `p=none` → spoof-feasible, downgrade trust → MEDIUM finding.
- `p=quarantine pct<100` → partial enforcement → LOW.
- `p=reject` + `aspf=s` + `adkim=s` → well-postured → no finding.

**DKIM key discovery:**

DKIM selectors aren't well-known; common patterns:
```bash
for selector in default google selector1 selector2 mail email k1 dkim s1 s2 mta1 mta2 \
                amazonses 20240101 20230101 mailchimp sendgrid mxvault; do
  echo "=== ${selector} ==="
  dig +short TXT "${selector}._domainkey.${D}"
done
```

If a key returns: extract `p=<base64>` and check key length. RSA-1024 → MEDIUM (deprecated; should be 2048+). Missing or rotated infrequently → LOW finding.

**BIMI (Brand Indicators for Message Identification):**

```bash
dig +short TXT "default._bimi.${D}"
```

If present + `p=reject` DMARC → brand-impersonation defense in inbox UI. Absence is LOW only (operational, not exploitable).

**MTA-STS (Mail Transfer Agent Strict Transport Security):**

```bash
dig +short TXT "_mta-sts.${D}"
curl -sk -m 10 "https://mta-sts.${D}/.well-known/mta-sts.txt"
```

If neither responds → MX-server TLS not enforced; MITM-able. LOW finding. If `mode=enforce` present and policy file matches → well-postured.

**TLS-RPT (TLS Reporting):**
```bash
dig +short TXT "_smtp._tls.${D}"
```

**DNSSEC validation:**

```bash
dig +dnssec "${D}" SOA | grep -E 'flags|RRSIG'
delv "${D}" 2>&1 | grep -i 'fully validated\|insecur'
```

If `delv` returns "insecure" → DNSSEC not enabled (LOW finding; doesn't enable spoof but is hardening gap).

**MX → IdP / mail-host inference:**

```bash
dig +short MX "${D}"
```

| MX pattern | IdP / hosting |
|---|---|
| `aspmx.l.google.com`, `*.googlemail.com` | Google Workspace |
| `*.mail.protection.outlook.com` | Microsoft 365 |
| `*.mail.eo.outlook.com` | Microsoft 365 (older) |
| `*.zoho.com` | Zoho Mail |
| `*.yandex.net` | Yandex 360 |
| `*.fastmail.com` | Fastmail |
| `*.proofpoint.com`, `*.pphosted.com` | Proofpoint (M365 user with Proofpoint inbound) |
| `*.mimecast.com`, `*.mimecast-eu.com` | Mimecast |
| `*.barracudanetworks.com` | Barracuda |
| Self-hosted IPs in target ASN | On-prem mail server (often Exchange) |

**DMARC reporting-vendor inference (parse `rua=` / `ruf=`):**

| RUA/RUF host | Vendor | Implication |
|---|---|---|
| `*.dmarcian.com` | dmarcian | DMARC reporting customer |
| `*.valimail.com`, `*.dmarc-rua.com` | Valimail | DMARC reporting customer |
| `*.kdmarc.com` | Kratikal kDMARC | Indian DMARC vendor; common in IN orgs |
| `*.agari.com` | Agari (Fortra) | Email security vendor |
| `*.easydmarc.com` | EasyDMARC | DMARC reporting customer |
| `*.dmarcanalyzer.com` | DMARC Analyzer | Reporting customer |
| `*.postmarkapp.com` | Postmark | DMARC reporting addon |
| `<addr>@<target-domain>` | Self-hosted reporting | Internal mailbox; sometimes leaks team-name (`itg@`, `secops@`, `dmarc@`) |

Capture the vendor + the internal RUA mailbox. Both are leak surfaces (vendor compromise = DMARC bypass; internal mailbox = phishing target).

**Windows / PowerShell parallel for the entire §16.14 audit:**

PS 5.1 `Resolve-DnsName` does **not** accept `-Type CAA` (use PowerShell 7+ or `nslookup -type=CAA <domain>`). Otherwise:

```powershell
$D = "target.example"
"=== SPF ==="; (Resolve-DnsName $D -Type TXT -EA SilentlyContinue | ? { $_.Strings -match 'v=spf1' }).Strings
"=== DMARC ==="; (Resolve-DnsName "_dmarc.$D" -Type TXT -EA SilentlyContinue).Strings
"=== MTA-STS ==="; (Resolve-DnsName "_mta-sts.$D" -Type TXT -EA SilentlyContinue).Strings
"=== TLS-RPT ==="; (Resolve-DnsName "_smtp._tls.$D" -Type TXT -EA SilentlyContinue).Strings
"=== BIMI ==="; (Resolve-DnsName "default._bimi.$D" -Type TXT -EA SilentlyContinue).Strings
"=== MX ==="; Resolve-DnsName $D -Type MX -EA SilentlyContinue | Select NameExchange,Preference
"=== DKIM common selectors ==="
foreach ($s in @("default","google","selector1","selector2","mail","email","k1","dkim","s1","s2","amazonses","mailchimp","sendgrid","mxvault","20240101","zoho","zmail","outlook","o365")) {
  $r = Resolve-DnsName "$s._domainkey.$D" -Type TXT -EA SilentlyContinue
  if ($r) { "${s}: FOUND" }
}
"=== CAA (PS 5.1 fallback) ==="; nslookup -type=CAA $D 2>$null
```

### 16.15 Origin Discovery / CDN Bypass

If the target is behind Cloudflare/Akamai/Fastly/CloudFront, their CDN IPs are well-defined. Find IPs **not** in those ranges that serve the same site = origin.

**Cloudflare IPv4 ranges:**
```
https://www.cloudflare.com/ips-v4
```
**Akamai ASNs:** AS16625, AS20940, AS21342, AS21357.
**Fastly:** AS54113.
**AWS CloudFront:** published in `https://ip-ranges.amazonaws.com/ip-ranges.json` filter `service:CLOUDFRONT`.

**Origin discovery via DNS history:**

```bash
# SecurityTrails (paid)
curl -sk -H "APIKEY: ..." \
  "https://api.securitytrails.com/v1/history/${D}/dns/a" | jq '.records[] | {ip:.values[].ip, first_seen, last_seen}'
```

Free alternatives:
```bash
# Validin
curl -sk "https://app.validin.com/api/axon/${D}/dns" | jq .

# RiskIQ Community (free tier; auth required)
curl -sk -u "user:apikey" "https://api.riskiq.net/pt/v2/dns/passive?query=${D}" | jq .
```

Filter the result: any historical A record IP **not** in current CDN ranges = origin candidate.

**Origin via certificate SAN pivot (Censys):**

```bash
# Censys (free 250 queries/month with key)
censys search "services.tls.certificates.leaf_data.subject.common_name:${D} AND NOT services.tls.certificates.leaf_data.issuer.common_name:'Cloudflare'"
```

Or via crt.sh + manual IP check:
```bash
curl -sk "https://crt.sh/?q=%25.${D}&output=json" | jq -r '.[].name_value' | sort -u
```

**Origin via favicon hash (Shodan):**

```bash
# Compute favicon mmh3
python3 -c "
import urllib.request, codecs, mmh3
data = urllib.request.urlopen('https://target.example/favicon.ico').read()
b64 = codecs.encode(data, 'base64')
print(mmh3.hash(b64))"

# Search Shodan
shodan search "http.favicon.hash:<computed-hash>" --fields ip_str,port,org
```

Cross-reference with CDN ranges; non-CDN matches = origin candidates.

**Origin via JARM:**

```bash
# Compute JARM
python3 -c "
import jarm
print(jarm.scan('target.example'))
" 2>/dev/null || echo "Install: pip install pyjarm"

# Search Shodan for matching JARM
shodan search "ssl.jarm:<jarm-hash>" --fields ip_str,port
```

**Origin via Host-header probe (validate candidate):**

```bash
CANDIDATE_IP="203.0.113.42"
curl -sk -m 10 -H "Host: target.example.com" "https://${CANDIDATE_IP}/" -o /tmp/candidate.html
diff <(curl -sk -m 10 https://target.example.com/) /tmp/candidate.html | head -50
```

If small/no diff → confirmed origin. Document with detectability=low.

**Origin via auxiliary subdomains (often skip CDN):**

```bash
for sub in mail smtp ftp sftp cpanel webmail direct origin direct-connect noproxy \
           dev staging stg uat preprod sandbox preview origin-www old-www legacy \
           server srv host1 host2 vps server1; do
  echo "=== ${sub}.${D} ==="
  dig +short A "${sub}.${D}"
done | grep -vE '^(===|$)' | sort -u
```

Cross-reference any returned IP against CDN ranges.

**Origin via email-header bounce:**

Send mail to `<random>@${D}` from a sock-puppet account. The bounce often includes `Received:` headers showing the inbound mail server's actual IP — sometimes co-located with web origin.

**Origin via misconfigured CDN error pages:**

Some CDN 5xx error pages historically leaked upstream details. Trigger errors and inspect:
```bash
# Trigger CDN-side 5xx (oversized request, malformed Host)
curl -sk -m 10 -H "Host: " "https://target.example/" -o /tmp/err.html
curl -sk -m 10 -H "X-Forwarded-For: $(python3 -c 'print("a"*8000)')" "https://target.example/"
grep -iE 'origin|upstream|server|backend|cf-ray' /tmp/err.html
```

### 16.16 Vendor Product Fingerprints

Common edge appliances / products on the target's perimeter, with fingerprint paths and notes on common CVEs.

| Product | Fingerprint paths | Notes |
|---|---|---|
| **Citrix Netscaler / Gateway** | `/vpn/index.html`, `/logon/LogonPoint/tmindex.html`, `/citrix/` | Version in HTML; CVE-2023-3519 (RCE), CVE-2019-19781 (path traversal RCE) — both KEV-listed. |
| **F5 BIG-IP TMUI** | `/tmui/login.jsp`, `/mgmt/tm/sys/` | Banner reveals version; CVE-2022-1388 (auth bypass), CVE-2023-46747 — KEV-listed. |
| **Cisco ASA / AnyConnect** | `/+CSCOE+/`, `/CSCOE/index.html`, `/webvpn.html`, `/+CSCOE+/portal.html` | CVE-2020-3452 (file read), CVE-2018-0101 (RCE). |
| **Pulse Secure / Ivanti Connect** | `/dana-na/`, `/dana-na/auth/url_default/welcome.cgi`, `/api/v1/` | CVE-2024-21887 (KEV), CVE-2023-46805 (KEV) — chained command injection. |
| **FortiGate / FortiOS** | `/remote/login`, `/remote/info`, `/api/v2/` | CVE-2022-42475 (RCE, KEV), CVE-2024-21762 (RCE, KEV). |
| **PaloAlto GlobalProtect** | `/global-protect/`, `/global-protect/portal/css/login.css`, `/api/?type=keygen` | CVE-2024-3400 (RCE, KEV), CVE-2019-1579. |
| **VMware Horizon** | `/portal/info.jsp`, `/broker/xml`, `/login.jsp` | log4shell exposure (CVE-2021-44228, KEV). |
| **VMware vCenter** | `/sdk`, `/ui/`, `/vsphere-client/`, `/websso/SAML2/` | CVE-2021-21972 (RCE, KEV), CVE-2021-22005. |
| **VMware ESXi** | `/sdk`, `/ui/`, `/folder` | CVE-2021-21974 (heap overflow → ESXiArgs ransomware, KEV). |
| **Microsoft Exchange OWA** | `/owa/`, `/ews/exchange.asmx`, `/ecp/` | ProxyShell (CVE-2021-34473), ProxyLogon (CVE-2021-26855), ProxyNotShell (CVE-2022-41040) — all KEV. |
| **WatchGuard Firebox** | `/auth/`, `/wgcgi.cgi` | CVE-2022-26318 (CGI). |
| **SonicWall SMA** | `/cgi-bin/welcome`, `/__api__/v1/`, `/diagnostics/` | CVE-2021-20016, CVE-2024-40766 (KEV). |
| **Sophos UTM/XG/XGS** | `/userportal/`, `/webconsole/`, `/cgi-bin/` | CVE-2022-1040 (RCE, KEV). |
| **Check Point R80/R81** | `/sslvpn/portal/`, `/clients/` | CVE-2024-24919 (KEV). |
| **Zoho ManageEngine** | `/RestAPI/Login`, `/api/json/v2/` | Multiple RCE CVEs; check version. |
| **Atlassian Confluence** | `/confluence/`, `/login.action`, `/rest/api/space` | CVE-2022-26134 (OGNL RCE, KEV), CVE-2023-22515 (KEV). |
| **Atlassian Jira** | `/secure/Dashboard.jspa`, `/rest/api/2/serverInfo` | Multiple CVEs; check version. |
| **GitLab self-hosted** | `/users/sign_in`, `/-/oauth/applications`, `/help` | Version in HTML footer; CVE-2021-22205 (RCE, KEV). |
| **Telerik UI** | `/Telerik.Web.UI.WebResource.axd?type=rau` | CVE-2017-9248, CVE-2019-18935 — old but still found. |
| **ConnectWise ScreenConnect** | `/SetupWizard.aspx`, `/Bin/SetupWizard.aspx` | CVE-2024-1709 (auth bypass, KEV). |
| **SolarWinds Orion** | `/Orion/Login.aspx` | SUNBURST supply-chain (CVE-2020-10148). |
| **Kaseya VSA** | `/dl.asp`, `/userFilterTableRpt.asp` | CVE-2021-30116 (REvil supply-chain). |
| **Microsoft IIS / OWA misc** | `Server: Microsoft-IIS/<version>` | Old versions = old CVEs; check. |
| **Cisco Smart Install** | port 4786 open | CVE-2018-0171 (smart install client mode RCE). |

**Per-vendor probe pattern:**

```bash
T="https://target.example"
# Citrix
curl -sk -m 10 "$T/vpn/index.html" -o /tmp/c1 -w '%{http_code}\n'
grep -iE 'NetScaler|Citrix|version' /tmp/c1
# F5
curl -sk -m 10 "$T/tmui/login.jsp" -o /tmp/c2 -w '%{http_code}\n'
grep -iE 'BIG-IP|version' /tmp/c2
# (etc — repeat per product)
```

**Auto-fingerprint with Nuclei:**

```bash
nuclei -u $T -t http/technologies/ -severity info,low,medium,high,critical
nuclei -u $T -t http/cves/ -severity high,critical -etags fuzz
```

### 16.17 Cloud-Native Service Fingerprints

Modern apps deploy on serverless / managed services. Fingerprint the platform from the URL pattern.

| Provider | URL pattern | Notes |
|---|---|---|
| **AWS Lambda Function URL** | `*.lambda-url.<region>.on.aws` | Direct invocation; check IAM auth posture. |
| **AWS App Runner** | `*.<region>.awsapprunner.com` | Managed container; usually behind auth. |
| **AWS API Gateway** | `*.execute-api.<region>.amazonaws.com` | REST/HTTP/WebSocket; check authorizer config. |
| **AWS CloudFront** | `d{14}\.cloudfront\.net` | Distribution; origin behind it (see §16.15). |
| **AWS ALB / ELB** | `*.elb.<region>.amazonaws.com` | Behind = EC2 / ECS. |
| **AWS Amplify** | `*.amplifyapp.com` | Static + Lambda backend. |
| **Google Cloud Run** | `*.run.app` (and `*.<region>.run.app`) | Container; check public-vs-IAM auth. |
| **Google Cloud Functions** | `*.cloudfunctions.net`, `*.<region>-<project>.cloudfunctions.net` | Serverless. |
| **Google App Engine** | `*.appspot.com` | Older serverless. |
| **Azure Functions** | `*.azurewebsites.net` (also App Service) | Function App behind same domain pattern. |
| **Azure Container Apps** | `*.azurecontainerapps.io` | Containers. |
| **Azure Static Web Apps** | `*.azurestaticapps.net` | Static + Functions. |
| **Vercel** | `*.vercel.app`, `*.now.sh` (legacy) | Frontend + serverless. |
| **Netlify** | `*.netlify.app`, `*.netlify.com` | Frontend + functions. |
| **Cloudflare Workers** | `*.workers.dev` | Edge functions. |
| **Cloudflare Pages** | `*.pages.dev` | Static + functions. |
| **Heroku** | `*.herokuapp.com` | Dynos. |
| **Render** | `*.onrender.com` | Container/static. |
| **Fly.io** | `*.fly.dev` | Edge containers. |
| **Railway** | `*.railway.app` | App platform. |
| **DigitalOcean App Platform** | `*.ondigitalocean.app` | Static + container. |

**For each pattern:**
- Confirm public vs auth-required (HEAD / GET).
- Check CORS posture.
- For Lambda Function URLs / Cloud Run / Cloud Functions: check whether IAM auth is enforced (anonymous invocation = HIGH finding).
- For static + functions hybrids (Vercel/Netlify/Cloudflare Pages): the function paths are usually `/api/*`; enumerate via JS extraction.

### 16.18 Container & Kubernetes Exposure

Increasingly common; often forgotten when behind a NAT.

| Target | Port | Probe | Severity if exposed |
|---|---|---|---|
| **Docker API (unencrypted)** | 2375 | `curl -sk -m 5 http://${IP}:2375/v1.40/info` | CRITICAL (container/host takeover) |
| **Docker API (TLS)** | 2376 | `curl -sk -m 5 https://${IP}:2376/v1.40/info` | HIGH (cert validation bypass possible) |
| **Kubernetes API server** | 6443 / 8443 | `curl -sk -m 5 https://${IP}:6443/api` | HIGH if `system:anonymous` returns non-403 |
| **Kubernetes Dashboard** | 8001 / 9090 / 30000+ | `curl -sk -m 5 http://${IP}:8001/api/v1/namespaces/kube-system/services/kubernetes-dashboard` | HIGH if reachable |
| **kubelet** | 10250 (HTTPS), 10255 (HTTP, deprecated) | `curl -sk -m 5 https://${IP}:10250/pods` | CRITICAL (no auth = pod exec) |
| **etcd** | 2379 (client), 2380 (peer) | `curl -sk -m 5 https://${IP}:2379/v2/keys/` (v2) or `etcdctl --endpoints=${IP}:2379 get /` (v3) | CRITICAL (cluster state + secrets) |
| **kube-proxy** | 10256 | `curl http://${IP}:10256/healthz` | INFO |
| **kube-controller-manager** | 10257 | `curl https://${IP}:10257/metrics` | MEDIUM |
| **kube-scheduler** | 10259 | `curl https://${IP}:10259/metrics` | MEDIUM |
| **cAdvisor** | 4194 (deprecated) | `curl http://${IP}:4194/metrics` | LOW (resource metrics) |
| **Helm Tiller** (Helm 2 — deprecated but found) | 44134 | `helm --host ${IP}:44134 list` | HIGH (Tiller had cluster-admin) |

**Public container registries to check for leaks:**

| Registry | Search pattern |
|---|---|
| Docker Hub | `https://hub.docker.com/search?q=<target-keyword>&type=image` |
| Quay (Red Hat) | `https://quay.io/search?q=<target-keyword>` |
| GitHub Container Registry (GHCR) | enumerable via GitHub API: `https://api.github.com/orgs/<org>/packages?package_type=container` |
| Amazon ECR Public | `https://gallery.ecr.aws/?searchTerm=<keyword>` |
| Azure Container Registry (public) | varies; check for `*.azurecr.io` |
| Google Container Registry (public) | `https://console.cloud.google.com/gcr/images/<project>?project=<project>` |

**Per-image scan workflow:**
1. `docker pull <registry>/<image>:<tag>` (or `skopeo inspect`).
2. `docker save <image> -o /tmp/img.tar`.
3. Extract layers; scan with secret catalog (§17).
4. Inspect `Dockerfile` history (`docker history <image>`) — sometimes reveals build args or COPY of secrets.

### 16.19 CI/CD Platform Exposure

| Platform | Common exposure | Probe |
|---|---|---|
| **Jenkins** | `/script` (Groovy console = RCE if no auth), `/asynchPeople/`, `/jnlpJars/jenkins-cli.jar`, `/computer/`, `/job/<name>/api/json` | `curl -sk -m 10 "${T}/script"` and `curl -sk -m 10 "${T}/asynchPeople/api/json"` |
| **GitLab self-hosted** | `/users/sign_in` (version in HTML), `/-/oauth/applications` (auth-required), `/api/v4/version`, `/-/snippets/<id>/raw` | `curl -sk -m 10 "${T}/api/v4/version"` |
| **GitHub Actions workflow files** | `.github/workflows/*.yml` in any public repo | Search via GitHub code search: `path:.github/workflows extension:yml secrets` |
| **CircleCI config** | `.circleci/config.yml` in any repo | Search: `path:.circleci/config.yml` |
| **TeamCity** | `/login.html`, `/agent.html?agentId=*`, `/admin/admin.html` | `curl -sk -m 10 "${T}/login.html" \| grep -i 'TeamCity'` — version disclosure. CVE-2024-27198 (KEV). |
| **Bamboo (Atlassian)** | `/userlogin.action`, `/rest/api/latest/info` | `curl -sk -m 10 "${T}/rest/api/latest/info"` |
| **Drone CI** | `/api/info`, `/login` | `curl -sk -m 10 "${T}/api/info"` |
| **Travis CI (legacy)** | `.travis.yml` in repos; `https://api.travis-ci.com/repos/<owner>/<repo>` | API often exposes build env. |
| **Argo CD** | `/api/version`, `/applications` | `curl -sk -m 10 "${T}/api/version"`. Check anonymous-auth posture. |
| **Tekton** | `/apis/tekton.dev/v1beta1/pipelineruns` (K8s native) | Enumerate via K8s API. |
| **Spinnaker** | `/gate/info`, `/applications` | `curl -sk -m 10 "${T}/gate/info"` |
| **Buildkite** | per-org dashboards; usually behind auth. | Check public agents page. |

**GitHub Actions secret-leak patterns to look for in workflows:**

```yaml
# Anti-pattern: secret echoed to log
run: echo "${{ secrets.MY_API_KEY }}"

# Anti-pattern: secret in environment without mask
env:
  KEY: ${{ secrets.MY_API_KEY }}
run: ./deploy.sh   # script may echo $KEY

# Anti-pattern: pull_request_target with checkout of fork code (CVE class)
on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # checks out fork code with secrets in env
```

### 16.20 Documentation / Wiki Leak Paths

Public-share features on collaboration platforms regularly leak.

| Platform | URL pattern | What's exposed |
|---|---|---|
| **Notion (publish page)** | `*.notion.site/<slug>` or `notion.so/<workspace>/<page-id>` | Public page; sometimes whole workspaces published by accident. |
| **Confluence Cloud (anonymous)** | `<target>.atlassian.net/wiki/spaces/` | Public spaces; check `/wiki/display/<SPACE>/`. |
| **Atlassian Service Desk** | `<target>.atlassian.net/servicedesk/customer/portal/<N>` | Sometimes lists all internal request types. |
| **Trello board** | `https://trello.com/b/<id>/<slug>` | Public board with cards; check via Google `site:trello.com "${target}"`. |
| **Asana public project** | `https://app.asana.com/0/<id>/<id>` | Public project view. |
| **ReadTheDocs** | `<project>.readthedocs.io` | Hosted docs; "private builds" sometimes default to public. |
| **GitBook** | `<workspace>.gitbook.io/<book>/` | Published docs; sometimes contain internal SOPs. |
| **MkDocs / Docusaurus on subdomain** | `docs.<target>` | Often contains internal architecture diagrams + setup notes. |
| **Slab** | `<workspace>.slab.com/posts/<id>` | Published posts. |
| **Coda** | `coda.io/d/<doc-id>` | Public docs. |
| **Miro** | `https://miro.com/app/board/<id>/` | Public boards (often architecture diagrams). |
| **Lucidchart** | `https://lucid.app/lucidchart/<id>/view` | Public diagrams. |
| **Figma** | `https://www.figma.com/file/<key>/` | Public design files; sometimes leak product spec. |
| **GitHub Wiki** | `github.com/<org>/<repo>/wiki` | Public wikis; check stale ones. |
| **Linear** | `linear.app/<workspace>/issue/<id>` | Public issues (rare but happens). |
| **Confluence anonymous server** | `<target>/confluence/`, `<target>/wiki/` (self-hosted) | Anonymous read sometimes left on. |
| **Monday.com** | `view.monday.com/<id>` | Shared boards. |
| **Wrike** | `app.wrike.com/external/<id>` | External-shared spaces. |

**Dork-driven discovery:**
```
site:notion.site "{target}"
site:notion.so "{target}"
site:atlassian.net "{target}"
site:trello.com "{target}"
site:miro.com "{target}"
site:lucid.app "{target}"
site:figma.com "{target}"
site:asana.com "{target}"
site:gitbook.io "{target}"
site:readthedocs.io "{target}"
```

### 16.21 WHOIS / RDAP / Historical

WHOIS gives current registrant; RDAP is the structured replacement; historical WHOIS is the pivot gold.

**Current WHOIS:**

```bash
whois target.example                              # standard CLI
curl -sk -m 10 "https://www.whois.com/whois/${D}"  # web fallback
```

**RDAP (RFC 7480, structured JSON):**

```bash
# IANA bootstrap → returns the registry RDAP server
curl -sk "https://rdap.org/domain/${D}" | jq .
curl -sk "https://www.iana.org/rdap" | jq .   # bootstrap registry
```

What to extract from WHOIS / RDAP:
- Registrant: name, org, email, phone, address (often redacted post-GDPR but not always for non-EU registrants).
- Registrar: enables registrar-account pivot for related domains.
- Created / updated / expiry dates: pattern of bulk registrations = same registrant.
- Nameservers: NS reuse pivot.
- Status flags (`clientHold`, `clientTransferProhibited`, etc.) = posture indicators.
- Abuse contact: useful for responsible disclosure (§30).

**Historical WHOIS:**

Pre-GDPR records often have unredacted contact info. Sources:

| Source | Notes |
|---|---|
| **DomainTools** | Paid; gold-standard; full WHOIS history. |
| **WhoisXML API** | Paid; bulk + history. |
| **SecurityTrails** | Paid; WHOIS + DNS history. |
| **viewdns.info** | Free WHOIS history (limited). |
| **whoisology.com** | Paid; reverse WHOIS by registrant email. |

**Reverse-WHOIS pivots:**

If you have a registrant email, search "every domain registered by this email":
```bash
# DomainTools (paid)
curl -sk -H "X-API-Username: ..." -H "X-API-Key: ..." \
  "https://api.domaintools.com/v1/reverse-whois/?terms=admin@target.example"
```

This finds adjacent corporate assets (subsidiary domains, brand variations, employee personal projects on corp email).

### 16.22 DNS Record Catalog (TXT verification tokens, MX→IdP)

For every target domain, dump all common record types:

```bash
D="target.example"
for rtype in A AAAA MX TXT NS SOA CAA SRV CNAME PTR; do
  echo "=== ${rtype} ==="
  dig +short "${D}" "${rtype}"
done
```

**TXT record verification token catalog** (each token reveals a SaaS tenancy):

| TXT pattern | SaaS / service | Implication |
|---|---|---|
| `google-site-verification=<token>` | Google Workspace / Search Console / Analytics | Google tenancy. |
| `MS=ms<digits>` | Microsoft 365 (older) | M365 tenancy. |
| `apple-domain-verification=<token>` | Apple Business Manager / iCloud Calendar | Apple ecosystem. |
| `atlassian-domain-verification=<token>` | Atlassian Cloud (Jira/Confluence/etc.) | Atlassian customer. |
| `facebook-domain-verification=<token>` | Facebook Business / Pixel | FB Business. |
| `adobe-idp-site-verification=<token>` | Adobe Sign / Creative Cloud | Adobe customer. |
| `docusign=<token>` | DocuSign | DocuSign customer. |
| `dropbox-domain-verification=<token>` | Dropbox Business | Dropbox customer. |
| `box-verification=<token>` | Box | Box customer. |
| `webexdomainverification.<id>` | Webex | Cisco Webex. |
| `zoom_verify_<id>` | Zoom | Zoom customer (admin domain). |
| `notion=<token>` (rare) | Notion workspace | Notion enterprise. |
| `slack-domain-verification=<token>` | Slack Enterprise Grid | Slack EG. |
| `asana-domain-verification=<token>` | Asana Enterprise | Asana customer. |
| `mongodb-site-verification=<token>` | MongoDB Atlas | DB tenant. |
| `_dnsauth.<token>` | Many ACME / Let's Encrypt CAs | DNS-01 challenge in progress. |
| `pinterest-site-verification=<token>` | Pinterest Business | Marketing surface. |
| `cisco-ci-domain-verification=<token>` | Cisco Spark / Webex | Cisco. |
| `_globalsign-domain-verification=<token>` | GlobalSign cert authority | Cert provider. |
| `mailru-verification:<token>` | Mail.ru | RU presence. |
| `yandex-verification:<token>` | Yandex services | RU presence. |
| `zscaler-verification-<id>-<date>-<random>` | Zscaler (ZIA / ZPA / ZDX) | **Web SSE / SASE customer**; the date suffix is the verification-issued date. |
| `cloudflare-verify=<token>` | Cloudflare (Zero Trust / Access / WARP) | Cloudflare org-tier customer. |
| `autosect-site-verification=<token>` | AutoSect (security tooling) | Security vendor on tenant. |
| `cisco-site-verification=<token>` | Cisco (various products) | Cisco vendor. |
| `mscid=<token>` | Microsoft (newer M365 verification) | M365 tenancy (newer format). |
| `_amazonses=<token>` | AWS SES sender verification | SES sender. |
| `salesforce-domain-verification=<token>` | Salesforce | SF customer. |
| `workday-domain-verification=<token>` | Workday | Workday customer (HR + Finance). |
| `shopify-domain-verification=<token>` | Shopify | E-commerce customer. |
| `klaviyo-domain-verification=<token>` | Klaviyo | Marketing automation. |
| `mailchimp-domain-verification=<token>` | Mailchimp | Marketing email. |
| `hubspot-domain-verification=<token>` | HubSpot | CRM / marketing. |
| `zendesk-verification=<token>` | Zendesk | Support tenancy (also see §43). |
| `freshworks-verification=<token>` | Freshworks | Support / CRM customer. |
| `intercom-verification=<token>` | Intercom | Messaging tenancy. |
| `loom-site-verification=<token>` | Loom | Video. |
| `miro-site-verification=<token>` | Miro | Whiteboard tenancy. |
| `gitlab-domain-verification=<token>` | GitLab | Self-hosted or cloud verification. |

Each discovered tenancy is a separate attack surface (own credentials, own MFA posture, own data).

**Autodiscover-as-confirmation pattern:**

`autodiscover.<domain>` resolving to Microsoft IP space (`40.96.0.0/13`, `52.96.0.0/14`, `13.107.0.0/16`) is **definitive proof** of M365 Exchange Online tenancy — even when MX records are obscured by Mimecast/Proofpoint/Barracuda inbound filtering. Probe:

```powershell
Resolve-DnsName "autodiscover.$D" -Type A | Select Name,IPAddress
```

If IPs are in Microsoft ranges → `M365_CONFIRMED`. Cross-reference with `getuserrealm.srf` (§22.1) for tenant GUID extraction.

**CAA records:**
```bash
dig +short CAA "${D}"
```
Lists which CAs are allowed to issue certs. Absence = LOW finding (any CA can mis-issue). Presence + restrictive list = good posture.

**SOA serial pattern analysis:**
```bash
dig +short SOA "${D}"
```
Serial format `YYYYMMDDNN` reveals last-edit date. Pattern across multiple zones can correlate ownership.

### 16.23 Wayback CDX Deep Usage

The Wayback Machine has a structured query API.

**Basic CDX query:**
```bash
D="target.example"
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*&output=json&fl=timestamp,original&limit=10000"
```

Returns JSON array of `[timestamp, original_url]` tuples.

**Useful filters:**
- `&from=20200101&to=20231231` — date range.
- `&filter=mimetype:application/json` — only JSON responses (often APIs).
- `&filter=mimetype:application/javascript` — JS bundles.
- `&filter=statuscode:200` — only successful captures.
- `&filter=urlkey:.*api.*` — only URLs containing "api".
- `&collapse=urlkey` — dedup by URL.
- `&collapse=digest` — dedup by content (catches identical pages re-archived).

**Get specific snapshot:**
```bash
TS="20231215120000"
URL="https://target.example/admin/dashboard"
curl -sk "https://web.archive.org/web/${TS}/${URL}"
```

**Diff snapshot vs live:**
```bash
LIVE=$(curl -sk -m 10 "${URL}")
ARCHIVED=$(curl -sk -m 10 "https://web.archive.org/web/${TS}/${URL}")
diff <(echo "$LIVE") <(echo "$ARCHIVED") | head -100
```

**Save current page:**
```bash
curl -sk -X POST "https://pragma.archivelab.org/" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://target.example/admin"}'
```

**Find every archived JS:**
```bash
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.js&output=json&fl=timestamp,original&filter=statuscode:200" | \
  jq -r '.[1:][] | "\(.[0]) \(.[1])"'
```

For each, fetch the archived JS and run the secret catalog (§17). Old JS often had hard-coded keys later removed.

**Legacy-app pivot (when `*.js` returns empty):**

Static brochure-ware sites (older corporate sites, especially pre-2015) often have **zero archived JS** because the frontend was server-rendered. Pivot to legacy file extensions:

```bash
# ASP / ASP.NET classic
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.asp&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=500"

# PHP
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.php&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=500"

# JSP / .NET aspx / CGI / Coldfusion
for ext in aspx jsp cgi cfm; do
  echo "=== .$ext ==="
  curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.${ext}&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=200"
done

# JSON / XML config (sometimes leaks endpoints + creds)
for ext in json xml yml yaml ini conf; do
  echo "=== .$ext ==="
  curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.${ext}&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=100"
done

# Anything indexed (broad sweep — useful for legacy enumeration)
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=10000"
```

Legacy `.asp` / `.cfm` / `.jsp` URLs often reveal: forgotten admin panels, old user-enum endpoints, legacy auth flows, SQL-injection-prone parameters. Cross-reference with current DNS — many legacy hosts now NXDOMAIN but the URL paths sometimes survive on a renamed host.

### 16.24 Common-Prefix Subdomain Sweep (active, low-detectability)

Empirically: **passive cert-transparency enumeration (crt.sh / VirusTotal / Subfinder) misses 20–40% of high-value subdomains** because (a) many internal hosts use wildcard certs that don't expose the FQDN, (b) some hosts have never been issued public certs (HTTP-only or self-signed), (c) very-recently-provisioned hosts haven't propagated to CT log mirrors yet.

**Always pair passive enum with an active prefix-probe.** Detectability: low (single A-record query per host; no port scan, no HTTP).

**The high-yield prefix list (ordered by hit-rate from real engagements):**

```
www, mail, webmail, smtp, imap, pop, owa, autodiscover, ftp, sftp,
vpn, sslvpn, gateway, gp, globalprotect, citrix, fortinet, anyconnect,
api, app, apps, mobile, m,
portal, login, sso, idp, iam, identity, accounts, oauth, auth, adfs,
admin, manage, console, dashboard, cp, cpanel,
intranet, internal, hr, payroll, finance, sap, erp, crm, helpdesk, servicedesk,
support, help, kb, status, monitoring, grafana, kibana, prometheus,
docs, wiki, confluence, jira, bitbucket, gitlab, jenkins, sonar, nexus,
git, svn, repo, code,
dev, test, staging, stg, qa, uat, sandbox, preprod, preview, demo,
careers, jobs, vacancies, recruit, eapps,
shop, store, ecommerce, checkout, payments, pay, billing,
old, legacy, archive, backup, beta, v1, v2, classic,
cdn, static, assets, media, img, files, downloads, public,
ns, ns1, ns2, dns, mx, mx1, mx2,
zoom, teams, slack, lync, sip, voice, meet,
sclepro, tender, tenders, suppliers, vendor, vendors, procurement, purchase
```

**One-liner (PowerShell):**
```powershell
$D = "target.example"
$prefixes = @("www","mail","webmail","owa","autodiscover","ftp","vpn","sslvpn","gateway","api","app","portal","login","sso","idp","iam","identity","accounts","oauth","auth","adfs","admin","intranet","hr","sap","erp","crm","support","help","status","grafana","kibana","docs","wiki","jira","jenkins","gitlab","dev","test","staging","stg","qa","uat","sandbox","preprod","preview","careers","jobs","eapps","old","legacy","beta","tender","suppliers","procurement")
foreach ($p in $prefixes) {
  $r = Resolve-DnsName "$p.$D" -Type A -ErrorAction SilentlyContinue
  if ($r) {
    $ips = ($r | ? {$_.IPAddress}).IPAddress -join ","
    "$p.$D -> $ips"
  }
}
```

**One-liner (bash + dig):**
```bash
D="target.example"
for p in www mail webmail owa autodiscover ftp vpn sslvpn gateway api app portal login sso idp iam identity accounts oauth auth adfs admin intranet hr sap erp crm support help status grafana kibana docs wiki jira jenkins gitlab dev test staging stg qa uat sandbox preprod preview careers jobs eapps old legacy beta tender suppliers procurement; do
  IP=$(dig +short A "$p.$D" | head -1)
  [ -n "$IP" ] && echo "$p.$D -> $IP"
done
```

**Mass DNS approach (faster for large prefix lists):**
```bash
# Generate candidate FQDNs from a wordlist; resolve in parallel via puredns
puredns resolve <(awk -v d="$D" '{print $1"."d}' assetnote-best-dns-wordlist.txt) -r resolvers.txt
```

**What to extract from each hit:**
- IP / IP block → ASN lookup (§28.1) → confirms target-owned vs hosted-elsewhere.
- For `vpn.*` / `gateway.*` / `gp.*` / `globalprotect.*` / `citrix.*` → flag for active vendor fingerprint (§16.16) under separate engagement scope.
- For `api.*` / `app.*` → seed for §16.1–16.10 webapp probes.
- For `staging.*` / `dev.*` / `uat.*` → seed for §16.5 always-on HTTP checks (often weaker auth + debug endpoints).
- For `intranet.*` / `eapps.*` / `sclepro.*` → public-intranet finding (often MEDIUM; per §40).

**Real-engagement validation:** in an internal smoke test, prefix-sweep found `vpn.`, `api.`, `intranet.`, `staging.`, `support.`, `eapps.`, `sclepro.`, `autodiscover.` — all of which crt.sh missed (or returned 502 for). Treat passive + active as **complementary, not alternatives**.

---

## 17. Secret-Pattern Catalog — 48 patterns (29 base + 19 modern)

The catalog runs against any text source: GitHub code, Postman workspaces, JS bodies, sourcesContent blobs, mobile-app strings, Wayback HTML, paste sites, Stack Exchange code blocks. **Order matters: most-specific patterns first** so generic catches don't pre-empt typed ones.

| # | Name | Regex | Severity | Category |
|---|---|---|---|---|
| 1 | AWS Access Key | `\b(AKIA\|ASIA)[0-9A-Z]{16}\b` | **CRITICAL** | aws |
| 2 | AWS Secret Key (typed) | `(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"\s:=]+([A-Za-z0-9/+=]{40})` | **CRITICAL** | aws |
| 3 | AWS Secret (loose) | `(?i)aws(.{0,20})?(secret\|sk)["'=: ]+([0-9a-z/+=]{40})` | HIGH | aws |
| 4 | GCP Service Account JSON | `"type"\s*:\s*"service_account"` | **CRITICAL** | gcp |
| 5 | Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` | HIGH | gcp |
| 6 | GitHub Classic PAT | `\bghp_[A-Za-z0-9]{36}\b` | **CRITICAL** | github |
| 7 | GitHub Fine-grained PAT | `\bgithub_pat_[A-Za-z0-9_]{82}\b` | **CRITICAL** | github |
| 8 | GitHub OAuth | `\bgho_[A-Za-z0-9]{36}\b` | HIGH | github |
| 9 | GitHub Server-to-Server | `\bgh[usr]_[A-Za-z0-9]{36,}\b` | HIGH | github |
| 10 | Stripe Live Key | `\bsk_live_[0-9A-Za-z]{24,}\b` | **CRITICAL** | stripe |
| 11 | Stripe Test Key | `\bsk_test_[0-9A-Za-z]{24,}\b` | LOW | stripe |
| 12 | Slack Token | `\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b` | HIGH | slack |
| 13 | Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` | MEDIUM | slack |
| 14 | SendGrid Key | `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` | HIGH | email_svc |
| 15 | Mailgun Key (v1) | `\bkey-[0-9a-zA-Z]{32}\b` | HIGH | email_svc |
| 16 | Mailgun Key (loose) | `\bkey-[0-9a-f]{32}\b` | HIGH | email_svc |
| 17 | Twilio API Key | `\bSK[0-9a-fA-F]{32}\b` | HIGH | twilio |
| 18 | Twilio Account SID | `\bAC[a-f0-9]{32}\b` | MEDIUM | twilio |
| 19 | Twilio Auth Token | `(?i)twilio(.{0,20})?(auth\|token)["'=: ]+([a-f0-9]{32})` | HIGH | twilio |
| 20 | Heroku API Key | `(?i)heroku(.{0,20})?api["'=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})` | MEDIUM | paas |
| 21 | Firebase URL | `\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b` | LOW | firebase |
| 22 | JWT (any) | `\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b` | MEDIUM | jwt |
| 23 | Bearer Token Assignment | `(?i)authorization["'=: ]+bearer\s+[A-Za-z0-9._\-]{20,}` | MEDIUM | bearer |
| 24 | Basic Auth in URL | `https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+` | MEDIUM | basic_auth |
| 25 | RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | **CRITICAL** | private_key |
| 26 | EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | **CRITICAL** | private_key |
| 27 | OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | **CRITICAL** | private_key |
| 28 | Generic Private Key | `-----BEGIN (DSA \|PGP \|)PRIVATE KEY-----` | **CRITICAL** | private_key |
| 29 | Generic API Key | `(?i)(?:api[_\-]?key\|apikey\|api_secret\|access_token\|secret[_\-]?token)['"\s:=]+["']([A-Za-z0-9+/=_\-]{24,})["']` | MEDIUM | generic |
| 30 | Anthropic API Key | `\bsk-ant-(?:api03\|admin01)-[A-Za-z0-9_\-]{93,}\b` | **CRITICAL** | ai_api |
| 31 | OpenAI API Key (legacy) | `\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b` | **CRITICAL** | ai_api |
| 32 | OpenAI Project Key | `\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b` | **CRITICAL** | ai_api |
| 33 | OpenAI User Session | `\bsess-[A-Za-z0-9]{40}\b` | HIGH | ai_api |
| 34 | HuggingFace Token | `\bhf_[A-Za-z0-9]{30,}\b` | HIGH | ai_api |
| 35 | Cloudflare API Token | `\b[A-Za-z0-9_\-]{40}\b` (when paired with `(?i)cloudflare`/`X-Auth-Key` context) | HIGH | infra_api |
| 36 | Cloudflare Global API Key | `(?i)cf[_\-]?api[_\-]?key['"\s:=]+([a-f0-9]{37})` | **CRITICAL** | infra_api |
| 37 | DigitalOcean Token | `\bdop_v1_[a-f0-9]{64}\b` | HIGH | infra_api |
| 38 | npm Token (Modern) | `\bnpm_[A-Za-z0-9]{36}\b` | HIGH | package_registry |
| 39 | PyPI Token | `\bpypi-AgENdGV[A-Za-z0-9_\-]+\b` | HIGH | package_registry |
| 40 | Docker Hub PAT | `\bdckr_pat_[A-Za-z0-9_\-]{27,}\b` | HIGH | package_registry |
| 41 | Atlassian API Token | `\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b` | HIGH | saas_api |
| 42 | New Relic License Key | `\b(?:NRAA\|NRAK\|NRBR)-[A-F0-9]{27}\b` | MEDIUM | observability |
| 43 | DataDog API Key (in DD_API_KEY context) | `(?i)dd[_\-]?api[_\-]?key['"\s:=]+([a-f0-9]{32})` | HIGH | observability |
| 44 | Sentry DSN | `https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+` | LOW | observability |
| 45 | ngrok Auth Token | `\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b` (when `(?i)ngrok` context) | MEDIUM | tunneling |
| 46 | Linear API Key | `\blin_api_[A-Za-z0-9]{40}\b` | MEDIUM | saas_api |
| 47 | Discord Bot Token | `\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b` | HIGH | bot_token |
| 48 | Telegram Bot Token | `\b\d{8,10}:[A-Za-z0-9_\-]{35}\b` | HIGH | bot_token |

**False-positive notes:**
- Patterns 22 (JWT), 23 (Bearer), 29 (Generic) trigger on test/example data frequently. Always look at *context* — a JWT in a `README.md` example block ≠ a JWT in a production `.env` file.
- Pattern 16 (Mailgun loose) and pattern 11 (Stripe test) are noisy by design; severity is set low for that reason.
- Pattern 24 (Basic auth in URL) catches monitoring-tool URLs and CI-debug URLs as well as real creds — verify before alerting.
- For GitHub's Fine-grained PAT (pattern 7), the `82` length is by GitHub's spec — be skeptical of matches significantly longer or shorter.

---

## 18. Dork Corpus — 80+ templates, 9 categories

Substitute `{domain}` with the target domain (e.g., `example.com`) and `{company}` with the company name (e.g., `Acme Corporation`). Run via Google, Bing, Brave, DuckDuckGo, Yandex, Baidu — engines surface different results.

### 18.1 Files

```
site:{domain} filetype:env
site:{domain} ext:env OR ext:ini OR ext:cfg OR ext:conf
site:{domain} ext:sql OR ext:sqlite OR ext:dump OR ext:bak
site:{domain} ext:pem OR ext:key OR ext:p12 OR ext:pfx
site:{domain} ext:log
site:{domain} intitle:"index of"
site:{domain} inurl:.git OR inurl:/.git/
site:{domain} inurl:backup OR inurl:.bak OR inurl:old
site:{domain} ext:yml OR ext:yaml
site:{domain} ext:properties
```

### 18.2 Admin / login panels

```
site:{domain} inurl:admin OR inurl:login OR inurl:sso OR inurl:dashboard
site:{domain} intitle:"phpMyAdmin"
site:{domain} intitle:"Jenkins"
site:{domain} intitle:"Grafana"
site:{domain} intitle:"Kibana"
site:{domain} intitle:"Splunk"
site:{domain} (intitle:"login" OR intitle:"sign in")
site:{domain} intitle:"GitLab"
site:{domain} intitle:"Swagger" OR intitle:"OpenAPI"
site:{domain} inurl:phpinfo
```

### 18.3 Secrets / credential leakage

```
"{domain}" ("api_key" OR "apikey" OR "access_token")
"{domain}" (password OR passwd OR pwd)
site:pastebin.com "{domain}"
site:ghostbin.com "{domain}"
site:rentry.co "{domain}"
site:gist.github.com "{domain}"
site:hastebin.com "{domain}"
"{domain}" "BEGIN RSA PRIVATE KEY"
```

### 18.4 Cloud / CI / shadow-IT

```
site:s3.amazonaws.com "{domain}"
site:storage.googleapis.com "{domain}"
site:blob.core.windows.net "{domain}"
site:digitaloceanspaces.com "{domain}"
site:trello.com "{domain}"
site:*.atlassian.net "{domain}"
site:dev.azure.com "{domain}"
site:bitbucket.org "{domain}"
site:firebaseio.com "{domain}"
site:herokuapp.com "{domain}"
```

### 18.5 Docs / intel mining

```
site:{domain} filetype:pdf (confidential OR internal OR restricted)
site:{domain} filetype:xlsx OR filetype:csv
site:{domain} filetype:docx
site:scribd.com "{company}"
"{company}" filetype:pdf (salary OR payroll OR org-chart OR "organization chart")
site:linkedin.com/in "{company}"
site:slideshare.net "{company}"
```

### 18.6 Vuln indicators

```
site:{domain} intext:"sql syntax" OR intext:"you have an error in your sql"
site:{domain} intext:"Warning: mysql_"
site:{domain} intext:"Fatal error:" intext:"on line"
site:{domain} intext:"stack trace" OR intext:"Traceback (most recent call last)"
"Apache/2.4.49" site:{domain}
"Server: nginx/1.14" site:{domain}
site:{domain} inurl:wp-content OR inurl:wp-includes
```

### 18.7 Internal tool exposure

```
site:{domain} intitle:"Splunk"
site:{domain} intitle:"Grafana"
site:{domain} intitle:"Kibana"
site:{domain} intitle:"Prometheus Time Series"
site:{domain} intitle:"Jaeger UI"
site:{domain} intitle:"AlertManager"
site:{domain} intitle:"Argo CD"
site:{domain} intitle:"Sonarqube"
site:{domain} intitle:"Sentry"
site:{domain} intitle:"Confluence"
site:{domain} intitle:"Jira"
site:{domain} intitle:"GitLab"
site:{domain} intitle:"Gitea"
site:{domain} intitle:"Drone CI"
site:{domain} inurl:"/jenkins/"
```

### 18.8 Backup / dump file extensions

```
site:{domain} ext:bak OR ext:backup OR ext:old OR ext:orig OR ext:save OR ext:swp
site:{domain} ext:tar OR ext:tar.gz OR ext:tgz OR ext:zip OR ext:rar OR ext:7z
site:{domain} ext:db OR ext:sqlite OR ext:sqlite3 OR ext:mdb
site:{domain} ext:dump OR ext:rdb OR ext:bson
site:{domain} (intext:"-- MySQL dump" OR intext:"PostgreSQL database dump")
site:{domain} ext:pcap OR ext:pcapng OR ext:cap
site:{domain} ext:core OR ext:hprof OR ext:dmp
```

### 18.9 Sector-specific (healthcare / finance / gov)

```
# Healthcare
site:{domain} (filetype:pdf OR filetype:xlsx) (HIPAA OR PHI OR "patient records")
site:{domain} ("DICOM" OR "HL7" OR "ICD-10")

# Finance
site:{domain} (filetype:pdf OR filetype:xlsx) (SOC OR "audit report" OR "internal control")
site:{domain} (filetype:pdf OR filetype:xlsx) ("Form 10-K" OR "Form 10-Q" OR earnings)
site:{domain} ("SWIFT" OR "BIC" OR IBAN OR "wire transfer")

# Gov / public sector
site:{domain} (filetype:pdf OR filetype:doc) (FOUO OR "controlled unclassified" OR CUI)
site:{domain} (filetype:pdf OR filetype:xlsx) ("personnel security" OR clearance)
```

### 18.10 Result classification

After running, score each result via URL signature → title hint → snippet regex:
- **CRITICAL URL signatures:** `.pem`, `.p12`, `.pfx`, `.key` extensions; `id_rsa` filename.
- **HIGH URL signatures:** `/.env`, `/.git/`, database dumps, `wp-config.bak`, `/phpmyadmin`, `/jenkins`, `/phpinfo.php`.
- **MEDIUM URL signatures:** `/admin`, `/login`, `/swagger`, `.log`, `/backup`, `.DS_Store`.
- Snippet content (e.g., a secret regex hit in the snippet) overrides URL signature only if higher severity.
- Confidence: snippet-only match = TENTATIVE (operator must visit URL to confirm; tag detectability=medium).

---

## 19. GitHub Code-Search Dorks for Targets — 13 dorks

Apply each template to `{target}` (root domain stem like `acme`), `{domain}` (full root domain like `acme.com`), and optionally `{company}` (`Acme Corporation`):

```
"{target}" filename:.env
"{target}" filename:.env.example
"{target}" filename:config
"{target}" AWS_ACCESS_KEY_ID
"{target}" AWS_SECRET_ACCESS_KEY
"{target}" password
"{target}" api_key
"{target}" secret
"{target}" authorization: Bearer
"{target}" filename:id_rsa
"{target}" filename:.git-credentials
"{target}" filename:wp-config.php
"@{domain}" password                        # emails + password context
```

**Requirements:** GitHub personal access token (any scope; recommend a fine-grained PAT with read-only repo access). Rate limit per token; concurrency cap ≤5.

**For each result:**
1. Fetch the file (or relevant fragment) via the GitHub Contents API.
2. Run the secret catalog (§17).
3. If a secret hits → `SECRET_LEAK` finding with catalog severity, evidence = repo URL + file path + matched secret (truncated, last 4 chars only).
4. Optional: clone the repo to a tempdir, run `trufflehog`/`gitleaks` for full history scan.

---

## 20. Endpoint Interest Score — 0–100 rubric

For every classified endpoint (§22 in methodology skill), apply this rubric:

| Signal | Points | Conditions |
|---|---|---|
| **Unauth write** | +40 | POST/PUT/DELETE/PATCH endpoint returns 200/201/202/204 anonymously. |
| **Open GraphQL introspection** | +35 | `__schema` query returns full type list anonymously. |
| **Verb tampering bypass** | +30 | OPTIONS reveals method not documented; that method is accessible. |
| **Reflected CORS + credentials** | +25 | `Access-Control-Allow-Origin` reflects request `Origin` AND `Access-Control-Allow-Credentials: true`. |
| **Sensitive keyword in path** | +20 | Path matches one of: `admin`, `internal`, `debug`, `user`, `password`, `token`, `key`, `export`, `upload`, `backup`, `config`, `secret`, `private`, `delete`, `purge`, `wipe`. |
| **Schema leak in error** | +20 | Response body contains stack trace, ORM error class, framework signature (e.g., `ActiveRecord::RecordNotFound`, `org.hibernate.exception.*`, `django.db.utils.IntegrityError`). |
| **API key in URL** | +15 | Path or query string contains `api_key=`, `apikey=`, `token=`, `access_token=`. |
| **Wildcard CORS** | +10 | `Access-Control-Allow-Origin: *`. |
| **Missing rate-limit headers** | +10 | No `RateLimit-*` / `X-RateLimit-*` headers; no `Retry-After` after rapid requests. |

**Thresholds:**

| Score | Severity |
|---|---|
| ≥ 90 | **CRITICAL** |
| 70–89 | **HIGH** |
| 50–69 | MEDIUM |
| 25–49 | LOW |
| < 25 | INFO |

For score ≥ 70, attach an `attack_path_hint` in evidence (see §29).

---

## 21. Mobile App Ownership Confidence — 0–100 rubric

Before running deep APK static analysis, score whether the discovered app actually belongs to the target. Threshold: **≥70 = accept**.

| Signal | Points |
|---|---|
| Package reverse-DNS matches target domain (e.g., `com.acme.android` ⟂ `acme.com`) | +40 |
| Developer email is `<anything>@<target-domain>` | +25 |
| Developer website URL is the target domain (or a confirmed sibling brand domain) | +20 |
| App name contains a brand keyword from operator-supplied brand list | +10 |
| App has ≥ minimum review-score threshold (default 20 reviews) | +5 |

Apps below threshold are tagged `mobile_review_pending` and shown but not analyzed. Operator can re-score with `--mobile-ownership-threshold 50` for noisier collection.

---

## 22. Identity Fabric — Concrete Endpoints

Methodology lives in the companion `osint-methodology` skill §11. This is the URL/payload reference.

### 22.1 Microsoft Entra (Azure AD)

**OIDC metadata + tenant GUID extraction:**
```
GET https://login.microsoftonline.com/{tenant-or-domain}/.well-known/openid-configuration
```
Response field `issuer` contains the tenant GUID. GUID regex:
```regex
\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b
```
Detectability: low.

**getuserrealm.srf — managed vs federated probe:**
```
GET https://login.microsoftonline.com/getuserrealm.srf?login=<probe-user>@<domain>
```
Response: JSON with `NameSpaceType` field (`Managed` / `Federated` / `Unknown`). Federated also includes `FederationBrandName` and `AuthURL` (the upstream IdP URL). Detectability: low.

**Autodiscover v2:**
```
POST https://autodiscover-s.outlook.com/autodiscover/metadata/json/1
Body: {"Email": "<probe-user>@<domain>"}
```
Returns the protocol endpoint for the user; presence indicates tenant membership. Detectability: low.

**Autodiscover IP correlation (passive M365 confirmation):**

Resolve `autodiscover.<domain>` and check if it lands in Microsoft Exchange Online IP space. This works even when MX is wrapped by Mimecast/Proofpoint/Barracuda inbound filtering, where MX alone doesn't reveal the underlying mail platform.

```bash
dig +short A autodiscover.target.example
```
```powershell
Resolve-DnsName "autodiscover.$D" -Type A | Select Name,IPAddress
```

Microsoft Exchange Online IPs (truncated common ranges): `40.96.0.0/13`, `52.96.0.0/14`, `13.107.6.152/31`, `13.107.18.10/31`, `40.99.0.0/16`, `40.104.0.0/15`, `52.98.0.0/15`. Full list: [Office 365 URLs and IP address ranges](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges).

If `autodiscover.<domain>` lands in that space → `M365_CONFIRMED` even when nothing else does. Detectability: low (passive DNS).

**GetCredentialType — user-enum (deep mode only):**
```
POST https://login.microsoftonline.com/common/GetCredentialType
Content-Type: application/json
Body:
{
  "username": "<email>",
  "isOtherIdpSupported": true,
  "checkPhones": false,
  "isRemoteNGCSupported": true,
  "isCookieBannerShown": false,
  "isFidoSupported": true,
  "originalRequest": "",
  "country": "US",
  "forceotclogin": false,
  "isExternalFederationDisallowed": false,
  "isRemoteConnectSupported": false,
  "federationFlags": 0
}
```
Response field `IfExistsResult` indicates user existence: `0` = exists, `1` = doesn't exist, `5` = exists in federated tenant. Detectability: medium (logged in tenant audit). Cap at 20 attempts per tenant.

### 22.2 Okta

**Org slug derivation:** start with stems from discovered subdomains and root-domain stem. Probe `<slug>.okta.com` and `<slug>.oktapreview.com`. Slug regex:
```regex
[a-z0-9][a-z0-9-]{1,40}\.okta(?:preview)?\.com
```

**OIDC fingerprint:**
```
GET https://<slug>.okta.com/.well-known/openid-configuration
```

**/api/v1/authn user-enum (deep mode):**
```
POST https://<slug>.okta.com/api/v1/authn
Content-Type: application/json
Body: {"username": "<email>", "password": "invalid_password_for_enum"}
```
Response distinguishes user existence:
- `400` with `errorCode: E0000004` → user doesn't exist (or generic password error in some configs).
- `401` with `status: PASSWORD_WARN` / `LOCKED_OUT` / `MFA_REQUIRED` → user exists.
Detectability: medium (audit-log per attempt). Cap at 20 attempts per tenant.

### 22.3 ADFS

**Passive fingerprint:**
```
GET https://{domain}/adfs/idpinitiatedsignon.aspx
```
A `200 OK` with a `urn:com:microsoft:ADFS:` reference in HTML indicates ADFS. Version-string greppable in HTML resource references.

**Mex endpoint (deep mode):**
```
GET https://{domain}/adfs/Services/Trust/mex
```
Returns SOAP federation metadata including endpoint URLs, signing certs, and supported claim types.

### 22.4 Google Workspace

**OIDC discovery:**
```
GET https://{domain}/.well-known/openid-configuration
```
Google-Workspace-hosted-domain customers expose discovery endpoints with characteristic `issuer` URI (`https://accounts.google.com`) and JWKS URI. MX records pointing to `aspmx.l.google.com` are a corroborating signal.

### 22.5 Generic OIDC (Keycloak / Auth0 / Ping / OneLogin / Duo)

**Discovery:** probe `/.well-known/openid-configuration` on every alive subdomain. The `issuer` and `authorization_endpoint` field URLs fingerprint the product:

| Product | URL pattern in `issuer` |
|---|---|
| Auth0 | `https://*.auth0.com` |
| OneLogin | `https://*.onelogin.com` |
| Ping | `https://*.pingone.com`, `https://*.pingidentity.com` |
| Duo | `https://*.duosecurity.com` |
| Keycloak | URL contains `/realms/<realm>` |
| OneLogin | `https://*.onelogin.com` |

### 22.6 SAML metadata

See §16.6.

### 22.7 AWS account-ID extraction

**S3 bucket region header (passive):**
```
HEAD https://<known-bucket>.s3.amazonaws.com/
```
Response includes `x-amz-bucket-region`. Cross-reference with bucket name entropy and known patterns to scope the account.

**ARN regex (in any JSON / HTML / JS response):**
```regex
arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:([0-9]{12}):
```
Capture group: 12-digit AWS account ID.

**`AccountId` property pattern:**
```regex
(?i)["']?account[_\-]?id["']?\s*[:=]\s*["']([0-9]{12})["']
```

**Google OAuth client_id:**
```regex
\b\d{8,}-[a-z0-9]{10,40}\.apps\.googleusercontent\.com\b
```

**MSAL / Microsoft client_id (GUID property):**
```regex
(?i)["']?client[_\-]?id["']?\s*[:=]\s*["']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']
```

**OAuth scope extraction:**
```regex
(?i)["']?scope["']?\s*[:=]\s*["']([^"']+)["']
```

### 22.8 Microsoft 365 Deep Enumeration (Teams / SharePoint / OneDrive / OAuth)

**Teams federation status:**
```bash
# Resolve tenant first
curl -sk -m 10 "https://login.microsoftonline.com/${TARGET_DOMAIN}/.well-known/openid-configuration" | jq -r '.issuer'
# Federation API requires authenticated request from a federated tenant; presence of error pattern reveals fed status
curl -sk -m 10 "https://teams.microsoft.com/api/mt/emea/beta/users/<email>/externalsearchv3"
```

**SharePoint subdomain probe:**
```bash
STEM=$(echo $TARGET_DOMAIN | cut -d. -f1)
for sub in "" "-my" "-admin"; do
  echo "=== ${STEM}${sub}.sharepoint.com ==="
  curl -sk -m 10 -I "https://${STEM}${sub}.sharepoint.com/" -w '%{http_code}\n'
done
```

**Reading the result correctly:** `HTTP 200` from these probes means **the tenant exists** (Microsoft serves a generic redirect-to-auth page) — it does **NOT** mean anonymous access is granted to the tenant's content. Distinguish:
- 200 → tenant provisioned (INFO).
- 200 + redirect to a custom anonymous-share URL (`/sites/<x>/Lists/<y>/AllItems.aspx?guestaccesstoken=...`) discovered via dorks → HIGH (data exposure).
- 401/403 → tenant exists but auth required (INFO).
- 404 / NXDOMAIN → tenant not provisioned at this stem (or vanity-named — check known stems from cert transparency).

PowerShell:
```powershell
$STEM = ($D -split '\.')[0]
foreach ($s in @("","-my","-admin")) {
  try {
    $r = Invoke-WebRequest -Uri "https://${STEM}${s}.sharepoint.com/" -Method Head -UseBasicParsing -TimeoutSec 10
    "${STEM}${s}.sharepoint.com -> HTTP $($r.StatusCode) (tenant exists)"
  } catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code) { "${STEM}${s}.sharepoint.com -> HTTP $code" } else { "${STEM}${s}.sharepoint.com -> no host" }
  }
}
```

**OneDrive personal site probe** (for a known email `alice@acme.com`):
```bash
USER_TOKEN=$(echo "alice@acme.com" | tr '@.' '__')
STEM="acme"
curl -sk -m 10 -I "https://${STEM}-my.sharepoint.com/personal/${USER_TOKEN}/Documents/" -w '%{http_code}\n'
# 401 = exists; 404 = not provisioned
```

**M365 OAuth client_id discovery in JS:**
```bash
curl -sk -m 10 "https://app.target.example/main.js" | \
  grep -oE 'clientId["'\''[:=]+ ?["'\'']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
```

**Device-code phishing target check** (look for `device_authorization_endpoint` in OIDC metadata):
```bash
curl -sk -m 10 "https://login.microsoftonline.com/${TARGET_DOMAIN}/v2.0/.well-known/openid-configuration" | \
  jq '.device_authorization_endpoint'
```
If non-null and tenant doesn't restrict device-code: MEDIUM finding (device-code phishing feasible).

**Power Platform / Dynamics URLs to check:**
- `*.crm.dynamics.com` (per-region: `crm`, `crm2`-`crm15`, `crm.dynamics.com`).
- `*.api.crm.dynamics.com` (Web API).
- `make.powerapps.com` / `flow.microsoft.com` (auth-required dashboards).

**Severity:**
- Discovered SharePoint/OneDrive tenants → INFO (asset only).
- Anonymous SharePoint anonymous-share link → HIGH (data exposure).
- `device_authorization_endpoint` enabled on tenant → MEDIUM (operational risk).
- Multi-tenant OAuth app with broad Graph scopes published by target → HIGH.

### 22.9 GraphQL Field-Suggestion Enumeration (when introspection disabled)

When the standard introspection query (§16.2) returns `"errors":[{"message":"GraphQL introspection is disabled"}]`, fall back to field-suggestion enumeration. Apollo and most GraphQL libraries enable "did you mean" suggestions by default.

**Detection probe:**
```bash
curl -sk -m 10 -X POST "$T/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}' | jq -r '.errors[0].message'
# If "introspection disabled" → proceed.
```

**Field-suggestion probe** (intentionally typo a field name to trigger suggestions):
```bash
curl -sk -m 10 -X POST "$T/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ usre { id } }"}' | jq -r '.errors[].message'
# Expected: "Cannot query field \"usre\" on type \"Query\". Did you mean \"user\", \"users\", \"userById\"?"
```

Iterate over a candidate-field wordlist (use SecLists `Discovery/Web-Content/graphql.txt` or `clairvoyance` library's seed list). Each suggestion reveals real field names. Continue until no new suggestions emerge.

**Tooling:**
- **Clairvoyance** (`pip install clairvoyance`) — automated field-suggestion enumerator. `clairvoyance -w wordlist.txt -o schema.json https://target.example/graphql`.
- **GraphQL-Cop** — auditor that probes for introspection, batching, depth-limit, suggestion config. `pip install graphql-cop`.
- **InQL** (Burp extension) — Burp Suite extension for GraphQL endpoint analysis.
- **GraphQL Voyager** — visualize once schema is reconstructed.

**Other GraphQL-when-introspection-disabled techniques:**

- **Alias-based query batching** (rate-limit / auth-bypass surface):
  ```json
  {
    "query": "{ a:user(id:1){name} b:user(id:2){name} c:user(id:3){name} ... }"
  }
  ```
  Many APIs rate-limit per-request, not per-alias. Test 100+ aliases per request.

- **Query-depth-limit bypass** (DoS / introspection bypass):
  ```json
  {
    "query": "{ user { friends { friends { friends { friends { id } } } } } }"
  }
  ```
  If server allows arbitrary depth → DoS surface; if depth-limited but doesn't strip nested `__type`/`__schema` → introspection-via-depth.

- **Subscription enumeration via WebSocket:**
  ```bash
  wscat -c "wss://target.example/graphql" -s graphql-ws
  > {"type":"connection_init"}
  > {"id":"1","type":"start","payload":{"query":"subscription { __schema { types { name } } }"}}
  ```

- **Batched query bypass** (some servers process all queries in batch even if first fails):
  ```json
  [
    {"query":"{ __schema { types { name } } }"},
    {"query":"{ user(id:1) { name } }"}
  ]
  ```

**Severity:**
- Field-suggestion enumeration succeeds (50+ fields recoverable) → MEDIUM `MISCONFIG`.
- Alias batching not rate-limited → MEDIUM (rate-limit-bypass surface).
- Subscription endpoint exposed without auth → MEDIUM (often used for real-time data exfil).

---

## 23. Read-Only Secret Validators

Use these to confirm a discovered credential is live. **Read-only, never destructive.** Tag every validation with `detectability` and `checked_at` (UTC).

### 23.1 Postman API Key (PMAK-*)

```
GET https://api.getpostman.com/me
Header: X-Api-Key: PMAK-<key>
```
- `200` → live; response contains `{user: {id, username, email}}`.
- `401` → dead.
- Scope: full read access to the user's Postman account (collections, env vars, history).
- Detectability: low.

### 23.2 AWS Access Key

```
sts:GetCallerIdentity
```
Use boto3:
```python
import boto3
sts = boto3.client('sts',
    aws_access_key_id='<AKIA...>',
    aws_secret_access_key='<secret>',
    region_name='us-east-1')
ident = sts.get_caller_identity()
# ident['Account'], ident['Arn'], ident['UserId']
```
- Valid → returns Account ID + ARN + UserId.
- Invalid → `InvalidClientTokenId` or `SignatureDoesNotMatch`.
- ARN scope: `:user/` is IAM user (broad), `:assumed-role/` is temp role (narrow), `:root` is account root (do NOT validate root keys you find).
- Detectability: **medium** (CloudTrail logs `GetCallerIdentity` in account `<found>`).

### 23.3 GitHub PAT

```
GET https://api.github.com/user
Header: Authorization: token <ghp_*>
```
- `200` → live; response contains `login`, `id`, `name`, `email` (if public).
- Response header `X-OAuth-Scopes` lists token scopes. `repo` scope = write to all accessible repos; `admin:org` = org admin.
- `401` → dead.
- Detectability: low.

### 23.4 Slack Token

```
POST https://slack.com/api/auth.test
Header: Authorization: Bearer <xox*-*>
```
- `200` with `{"ok": true}` → live; response includes `team`, `team_id`, `user`, `user_id`.
- `200` with `{"ok": false, "error": "invalid_auth"}` → dead.
- Detectability: low.

### 23.5 Anthropic API Key

```
GET https://api.anthropic.com/v1/models
Headers:
  x-api-key: sk-ant-api03-...
  anthropic-version: 2023-06-01
```
- `200` → live; response lists available models.
- `401` → dead.
- `403` with org_disabled → key valid but org disabled.
- Detectability: low; usage shows in Anthropic Console for the workspace owner.

### 23.6 OpenAI API Key

```
GET https://api.openai.com/v1/models
Header: Authorization: Bearer sk-...
```
- `200` → live; lists models (may include org-specific fine-tunes).
- `401` → dead.
- `429` → live but quota exhausted.
- Detectability: low; usage shows in OpenAI dashboard.

### 23.7 npm Token

```
GET https://registry.npmjs.org/-/whoami
Header: Authorization: Bearer npm_<token>
```
- `200` with `{"username": "<user>"}` → live.
- `401` → dead.
- For scope check: `GET /-/npm/v1/tokens` returns the token's permissions (read/publish).
- Detectability: low.

### 23.8 Atlassian API Token

```
GET https://<workspace>.atlassian.net/rest/api/3/myself
Auth: Basic <base64(email:ATATT3xFfGF0_...)>
```
- `200` → live; returns account profile + email.
- `401` → dead.
- Workspace required — extract from leaked repo URL or Atlassian dork results.
- Detectability: low.

### 23.9 DataDog API + APP Key

```
GET https://api.datadoghq.com/api/v1/validate
Headers:
  DD-API-KEY: <api-key>
  DD-APPLICATION-KEY: <app-key>
```
- `200` → both keys valid.
- `403` → either key invalid.
- Per-region URL varies: `api.datadoghq.eu`, `api.us3.datadoghq.com`, etc.
- Detectability: low; appears in DataDog audit log.

### 23.10 Validator output schema

```
{
  "status":          "verified_live" | "verified_dead" | "scope_restricted" |
                     "scope_unrestricted" | "validation_skipped_by_policy" |
                     "validation_unsupported" | "validation_failed_transient",
  "provider":        "postman" | "aws" | "github" | "slack" | "anthropic" | "openai" | "npm" | "atlassian" | "datadog",
  "account_id":      "<opaque>",
  "scope":           "<freeform>",
  "metadata":        {<provider-specific>},
  "checked_at":      "<UTC ISO8601>",
  "detectability":   "low" | "medium" | "high"
}
```

### 23.11 Hard rules

- Read-only endpoint only.
- Never use the validated credential to create, modify, delete, or send anything.
- Tag every validation with detectability.
- Record `checked_at` (UTC).
- If RoE forbids validation → `validation_skipped_by_policy`, stop, document.
- For root AWS keys, infrastructure-write GitHub PATs, or admin Slack tokens — flag for the operator and let them decide.

### 23.12 Post-Discovery Enumeration Workflows

After validation confirms a key is live, you often want to enumerate what it can do. Stay read-only.

**AWS access key — IAM enum:**
```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# Identity (already done as part of validation)
aws sts get-caller-identity

# IAM-user details (only if ARN was :user/)
aws iam get-user
aws iam list-attached-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-groups-for-user --user-name $(aws iam get-user --query 'User.UserName' --output text)

# What can I actually do? (simulate-principal-policy for common dangerous actions)
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names s3:ListAllMyBuckets ec2:DescribeInstances iam:ListUsers \
                 secretsmanager:ListSecrets ssm:DescribeParameters \
                 lambda:ListFunctions rds:DescribeDBInstances

# Read-only enumeration of common services (do not WRITE)
aws s3 ls
aws ec2 describe-instances --output table --query 'Reservations[*].Instances[*].[InstanceId,State.Name,Tags[?Key==`Name`].Value]'
aws secretsmanager list-secrets --query 'SecretList[*].Name'
aws ssm describe-parameters --query 'Parameters[*].Name'
aws lambda list-functions --query 'Functions[*].FunctionName'
aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'

# CloudTrail check — is logging on?
aws cloudtrail describe-trails

# Check MFA enforcement on the user
aws iam get-account-summary | jq '.SummaryMap.AccountMFAEnabled'
aws iam list-mfa-devices --user-name <username>
```

**GitHub PAT — repo enum:**
```bash
TOKEN="ghp_..."
H="Authorization: token $TOKEN"

# Scopes already captured from X-OAuth-Scopes header
curl -sk -m 10 -I -H "$H" https://api.github.com/user | grep -i 'X-OAuth-Scopes'

# All repos accessible (own + collaborator + org member)
curl -sk -m 10 -H "$H" "https://api.github.com/user/repos?affiliation=owner,collaborator,organization_member&per_page=100"

# Org memberships
curl -sk -m 10 -H "$H" "https://api.github.com/user/orgs"

# Per-org: members, repos, secrets (secrets endpoint is metadata-only — names not values)
ORG="<orgname>"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/members"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/repos?per_page=100"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/actions/secrets"   # requires admin:org

# Per-repo workflow secrets (metadata)
REPO="<orgname/reponame>"
curl -sk -m 10 -H "$H" "https://api.github.com/repos/$REPO/actions/secrets"
```

**Slack token — workspace enum:**
```bash
TOKEN="xoxb-..."
H="Authorization: Bearer $TOKEN"

# auth.test already validated
# Identity details
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/users.identity" | jq .

# What conversations can I see? (sweeping check; respects scope)
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/conversations.list?types=public_channel,private_channel,mpim,im&limit=200" | jq '.channels[] | {id, name, is_private}'

# Workspace info
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/team.info" | jq .

# User list (only if scope includes users:read)
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/users.list?limit=100" | jq '.members[] | {name, real_name, is_admin}'

# DO NOT: chat.postMessage, files.upload, conversations.invite, etc.
```

**JWT — full triage workflow:**
```bash
JWT="eyJhbGciOiJIUzI1NiI..."

# Decode header
echo "$JWT" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
# Look for: alg (none = critical, HS256/HS384/HS512 = symmetric, RS256/RS512 = asymmetric, ES256 = ECDSA)
# Look for: kid (key ID — possible JKU/X5U injection target)
# Look for: jku, x5u (JKU/X5U values — control these = sign attacker JWTs)

# Decode payload
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Look for: exp (expired = downgraded), iat, nbf
# Look for: sub, iss, aud (identity disclosure)
# Look for: roles, scopes, permissions (privilege markers)
# Look for: sensitive claims (email, employee ID, SSN, etc.)

# Algorithm-confusion test (RS→HS)
# If alg is RS256, try crafting an HS256 token signed with the public key as secret
# Tools: jwt_tool, jwt-cracker

# Brute-force HS256 secret (if HS256 + short-secret suspicion)
hashcat -m 16500 "$JWT" /path/to/wordlist.txt
# Or: john --format=HMAC-SHA256 jwt-hash.txt --wordlist=...

# Check `none` algorithm bypass
# Re-encode header with alg=none and empty signature; some libraries accept
NEW_JWT=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
NEW_JWT="${NEW_JWT}.$(echo "$JWT" | cut -d. -f2)."
# Test against API
```

**Postman PMAK — workspace enum:**
```bash
PMAK="PMAK-..."
H="X-Api-Key: $PMAK"

# /me already done (validation)
curl -sk -m 10 -H "$H" https://api.getpostman.com/me | jq '.user'

# Workspaces
curl -sk -m 10 -H "$H" https://api.getpostman.com/workspaces | jq '.workspaces[] | {id, name, type}'

# Per-workspace collections
WS="<workspace-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/workspaces/$WS" | jq '.workspace.collections[]'
curl -sk -m 10 -H "$H" "https://api.getpostman.com/workspaces/$WS" | jq '.workspace.environments[]'

# Per-collection requests (where the secrets often live)
COL="<collection-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/collections/$COL" | jq '.collection.item[]'
# Run secret catalog over the JSON

# Environments (env vars often contain creds)
ENV="<environment-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/environments/$ENV" | jq '.environment.values[] | {key, value}'
```

**Anthropic API key — usage enum:**
```bash
KEY="sk-ant-api03-..."
H="x-api-key: $KEY"
A="anthropic-version: 2023-06-01"

# Models accessible
curl -sk -m 10 -H "$H" -H "$A" https://api.anthropic.com/v1/models | jq '.data[] | .id'

# Usage / quota (admin-scoped tokens only):
curl -sk -m 10 -H "$H" -H "$A" https://api.anthropic.com/v1/organizations/usage_report | jq .

# DO NOT: send actual completion requests against organization budget
```

**OpenAI API key — usage enum:**
```bash
KEY="sk-..."
H="Authorization: Bearer $KEY"

# Models
curl -sk -m 10 -H "$H" https://api.openai.com/v1/models | jq '.data | length'

# Org info (if key has org scope)
curl -sk -m 10 -H "$H" https://api.openai.com/v1/organizations | jq .

# Files / fine-tunes (sometimes contain training data with PII)
curl -sk -m 10 -H "$H" https://api.openai.com/v1/files | jq .
curl -sk -m 10 -H "$H" https://api.openai.com/v1/fine_tuning/jobs | jq .
```

**Generic key — provenance enum:**
1. Find the consuming domain (where in JS bundle did the key appear? what URL is the bundle served from?).
2. Check the API docs of the inferred service.
3. If the key matches a known regex, lookup vendor-specific scope check.
4. If unknown service, search GitHub for the key prefix (`gh search code "<prefix>" --type=code`).
5. Identify scope before validating; some keys are write-broad on first use.

---

## 24. Postman Public Workspace Universal Search

Postman's public-search endpoint is unauthenticated and indexes every workspace marked public.

**Verified endpoint shape (mid-2025 onward):**

```bash
curl -sk -m 15 \
  "https://www.postman.com/_api/ws/proxy" \
  -H 'Content-Type: application/json' \
  -H 'X-Entity-Team-Id: 0' \
  -d '{
    "service":"search",
    "method":"POST",
    "path":"/search-all",
    "body":{
      "queryIndices":["collaboration.workspace","runtime.collection","runtime.request"],
      "queryText":"acme.com",
      "size":100,
      "from":0,
      "clientTraceId":"",
      "queryAllIndices":false,
      "domain":"public"
    }
  }' | jq '.data[]'
```

This proxies through Postman's web app to their internal search service. Pagination via `from` (0, 100, 200, ...).

**If the proxy shape changes** (it has historically): inspect a real search request from the Postman web UI:
1. Open `https://www.postman.com/explore` in a browser.
2. Open DevTools → Network tab.
3. Search for any term.
4. Find the request to `_api/...` — copy as cURL — adapt.

**Per-workspace walk:**

For each matching workspace ID:

```bash
WS_ID="<workspace-id>"
# Workspace metadata (name, description, team, visibility)
curl -sk -m 10 "https://www.postman.com/_api/workspace/$WS_ID" | jq .

# List collections + environments + monitors in workspace
curl -sk -m 10 "https://www.postman.com/_api/workspace/$WS_ID/collection" | jq '.[].id'
curl -sk -m 10 "https://www.postman.com/_api/workspace/$WS_ID/environment" | jq '.[].id'

# Per-collection: full content (requests, headers, scripts, env vars)
COL_ID="<collection-id>"
curl -sk -m 10 "https://www.postman.com/_api/collection/$COL_ID" | jq '.collection.item[]'
```

**Ownership scoring signals:**
- Creator/team name mentions target domain or brand → strong.
- Workspace name/description mentions target → strong.
- Request URLs contain `*.target.com` → strongest signal (workspace is actively used against target's APIs).

**Run secret catalog (§17) over every text blob extracted** from the requests, env vars, pre-request scripts, and test scripts.

---

## 25. Stack Exchange OSINT Sweep

Stack Exchange and its sister sites collect code paste-ins from developers — many include secrets, internal hostnames, and proprietary code excerpts.

**Sites to query (8 with highest signal):**
```
stackoverflow.com
serverfault.com
dba.stackexchange.com
devops.stackexchange.com
security.stackexchange.com
superuser.com
sharepoint.stackexchange.com
salesforce.stackexchange.com
```

**API:**
```
GET https://api.stackexchange.com/2.3/search/advanced
   ?site=<site>
   &q=<target>
   &filter=withbody
   &pagesize=100
```

**Code block extraction regex:**
```regex
<pre><code>([\s\S]*?)</code></pre>
```
(Stack Exchange wraps code in `<pre><code>` HTML.)

**Pipeline:**
1. Search each site for the target name, brand, root domain.
2. Extract code blocks from `body` HTML.
3. Run secret catalog (§17) over each block.
4. Cross-reference post author email (where exposed in profile) against email_osint discoveries — confirms employee posting target's internal code.
5. Extract hostnames from code blocks → upsert as `subdomain` assets.

**Quota:** Stack Exchange API permits 30 requests/day without a key; with a free key, 10,000/day. Throttle with 2-second min interval per call.

---

## 26. Public SaaS Collaboration Surfaces

Many SaaS collaboration tools allow public sharing. Dork them like search engines.

**Platforms with high incident rate:**
```
trello.com
notion.so / notion.site
*.atlassian.net           (Jira / Confluence)
miro.com
asana.com
clickup.com
airtable.com
```

**Dork template:**
```
site:{platform} "{target-keyword}"
```

**Run via search-engine adapter** (DDG default; Bing / Brave / Yandex / SerpAPI optional). The same classification logic from §18.7 applies.

**Common findings:**
- Public Trello board with credentials in card titles or attached config files.
- Public Notion page with internal SOPs, API keys in code blocks, customer data.
- Public Confluence space with onboarding docs containing seed creds.
- Public Miro board with architecture diagrams revealing internal hostnames.

---

## 27. Subdomain-Source Stack (Passive)

Practical "what actually returns useful data in 2026" reference, ordered by recall:

| Source | Tier | Notes |
|---|---|---|
| crt.sh | Free | Best single source for cert-derived subdomains; **frequently 502s during peak hours — see fallback chain below**. |
| VirusTotal | Freemium | Domain → passive DNS history. |
| AlienVault OTX | Free | Passive DNS + URL data. |
| Shodan | Paid (low tier) | Subdomain enum via `domain:` filter. |
| BinaryEdge | Paid | Comparable to Shodan. |
| FOFA | Freemium | Strong China-side coverage. |
| ZoomEye | Freemium | Comparable to Shodan; CN-strong. |
| Netlas | Paid | Large-scale HTTP/DNS/cert pivots. |
| SecurityTrails | Paid | Passive DNS + asset discovery. |
| RapidDNS | Free | Public passive DNS. |
| Subfinder bundled | Free | Aggregates 30+ free sources via one CLI. |
| Amass | Free | Comparable, more thorough, slower. |
| Recon-ng | Free | Modular framework; many free providers built in. |

**DNS AXFR opportunism:** for every name server discovered, attempt zone transfer:
```
dig @<ns-host> <target-domain> AXFR
```
Most NSs reject; those that don't = full zone disclosure (CRITICAL).

**Brute-force tier:** Subfinder/Subbrute against `assetnote.io` wordlists (best-curated public wordlist source).

### 27.0.1 crt.sh down? Fallback chain (try in order)

crt.sh runs on a single nginx in front of a busy Postgres; 502 / 503 / timeout in peak hours is routine. Don't retry-loop — pivot:

```bash
D="target.example"

# 1. Censys cert search (free 250 queries/month with key) — same data, different infra
censys search "names: ${D}" --index-type certificates --fields names | jq -r '.names[]' | sort -u

# 2. Cert Spotter API (sslmate) — free w/ rate limits
curl -sk "https://api.certspotter.com/v1/issuances?domain=${D}&include_subdomains=true&expand=dns_names" | \
  jq -r '.[].dns_names[]' | sort -u

# 3. CertStream archive (Calidog) — historical CT log mirror
curl -sk "https://crt.calidog.io/?q=${D}" | jq -r '.[].name_value' | sort -u

# 4. Subfinder bundled aggregator (uses 30+ sources internally — Chaos, Anubis, BinaryEdge, BufferOver, Censys, CertSpotter, Crobat, Crtsh, DNSDumpster, FOFA, Fullhunt, GitHub, HackerTarget, IntelX, PassiveTotal, Quake, Rapiddns, Shodan, Spyse, ThreatBook, ThreatMiner, URLScan, VirusTotal, WhoisXML, ZoomEye, etc.)
subfinder -d ${D} -all -recursive -silent

# 5. AlienVault OTX — free, no key
curl -sk "https://otx.alienvault.com/api/v1/indicators/domain/${D}/passive_dns" | \
  jq -r '.passive_dns[].hostname' | sort -u

# 6. ThreatMiner — free
curl -sk "https://api.threatminer.org/v2/domain.php?q=${D}&rt=5" | jq -r '.results[]'

# 7. URLScan — passive DNS via past scans
curl -sk "https://urlscan.io/api/v1/search/?q=domain:${D}" | \
  jq -r '.results[].page.domain' | sort -u

# 8. Anubis-DB / DNSDumpster (HTML scrape, last resort)
curl -sk -A "Mozilla/5.0" "https://anubisdb.com/anubis/subdomains/${D}" | jq -r '.[]'
```

PowerShell crt.sh wrapper with retry + fallback to Subfinder:

```powershell
function Get-Subs {
  param($D)
  for ($i=0; $i -lt 3; $i++) {
    try {
      $r = Invoke-WebRequest -Uri "https://crt.sh/?q=%25.$D&output=json" -UseBasicParsing -TimeoutSec 90 -UserAgent "Mozilla/5.0"
      return ($r.Content | ConvertFrom-Json | %{ $_.name_value -split "`n" } | %{ $_.Trim().ToLower() } | ?{ $_ -and $_ -notlike "*@*" -and $_ -notmatch "^\*\." } | Sort -Unique)
    } catch {
      "crt.sh attempt $($i+1) failed; sleep 5s..." | Out-Host
      Start-Sleep -Seconds 5
    }
  }
  "crt.sh down — pivot to Subfinder: subfinder -d $D -all -silent" | Out-Host
  return @()
}
```

### 27.1 Wordlist Sources for Subdomain + Content Brute-Force

| Source | URL | Notes |
|---|---|---|
| **Assetnote Wordlists** | `https://wordlists.assetnote.io/` | Best-curated; updated regularly. Subdomain top-N (1k, 10k, 100k, 1M, 10M); content-paths per CMS/framework; per-vendor (AWS, Azure, GitLab, etc.). |
| **SecLists** | `https://github.com/danielmiessler/SecLists` | Massive collection. Subdomains: `Discovery/DNS/subdomains-top1million-110000.txt`. Content: `Discovery/Web-Content/`. |
| **jhaddix all.txt** | `https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056` | Long-running curated list. |
| **OneListForAll** | `https://github.com/six2dez/OneListForAll` | Aggregated; very large (millions). |
| **dirsearch wordlists** | `https://github.com/maurosoria/dirsearch` | Bundled with the tool. |
| **raft-large-words.txt** | inside SecLists `Discovery/Web-Content/raft-large-words.txt` | Time-tested content wordlist. |
| **bo0om wordlist** | `https://github.com/bo0om/wordlists` | Russian-language-aware. |
| **commonspeak2** | `https://github.com/assetnote/commonspeak2-wordlists` | Generated from BigQuery commit data. |
| **fuzzdb** | `https://github.com/fuzzdb-project/fuzzdb` | Fuzzing payloads + wordlists. |
| **PayloadsAllTheThings** | `https://github.com/swisskyrepo/PayloadsAllTheThings` | Per-vuln-class payloads (less for enum, more for follow-on). |
| **Custom per-target** | n/a | Best practice: derive a custom wordlist from the target's own content (extract every word from their public website + LinkedIn + careers page → unique → use as seed). |

**Size guidance:**
- **<10k entries** → fast subdomain check (1–2 min); use for opportunistic/passive-supplement.
- **10k–100k entries** → standard depth (10–30 min); use as default brute-force.
- **100k–1M entries** → thorough; use when the target is a known high-value engagement (1–4 hours).
- **>1M entries** → exhaustive; reserve for week-long engagements; expect rate-limiting.

**Tooling:**
```bash
# Subfinder + brute-force with assetnote 100k
subfinder -d target.example -all -recursive | tee passive.txt
puredns bruteforce assetnote-best-dns-wordlist.txt target.example -r resolvers.txt | tee brute.txt
cat passive.txt brute.txt | sort -u > all-subs.txt

# Content brute-force on alive hosts
ffuf -u "https://target.example/FUZZ" -w raft-large-words.txt -mc 200,301,403 -t 50 -ac
```

---

## 28. Infrastructure & Attack-Surface OSINT

- [Shodan](https://www.shodan.io/), [Censys](https://search.censys.io/) — internet device + cert search.
- [GreyNoise](https://viz.greynoise.io/) — distinguish background noise from targeted scans.
- [SecurityTrails](https://securitytrails.com/) — passive DNS + asset discovery.
- [SpiderFoot](https://www.spiderfoot.net/) — automated recon + correlation.
- [theHarvester](https://github.com/laramies/theHarvester) — subdomain, email, metadata.
- [Recon-ng](https://github.com/lanmaster53/recon-ng) — web recon framework.
- [Amass](https://github.com/owasp-amass/amass) / [Subfinder](https://github.com/projectdiscovery/subfinder) — passive subdomain.
- [BuiltWith](https://builtwith.com/) — tech stack enumeration.
- [Netlas](https://netlas.io/) — large-scale HTTP/DNS/cert pivots.
- [BinaryEdge](https://www.binaryedge.io/) / [FOFA](https://fofa.so/) / [ZoomEye](https://www.zoomeye.org/) — Shodan/Censys complements.
- [RiskIQ PassiveTotal](https://community.riskiq.com/) — passive DNS/cert/host pivots.
- [Spur](https://spur.us/) — IP lookups.
- [Robtex](https://www.robtex.com/) — passive DNS + infrastructure.

### 28.1 ASN/BGP & Internet Measurement

- [Hurricane Electric BGP Toolkit](https://bgp.he.net/), [RIPEstat](https://stat.ripe.net/), [BGPView](https://bgpview.io/), [bgp.tools](https://bgp.tools/), [PeeringDB](https://www.peeringdb.com/).

**Bulk IP → ASN — recipes that actually work in 2026:**

```bash
# Cymru bulk WHOIS (fastest; no rate-limit issues; no key required)
echo -e "begin\nverbose\n8.8.8.8\n1.1.1.1\nend" | nc whois.cymru.com 43
# Or one-shot:
whois -h whois.cymru.com " -v 8.8.8.8"

# RIPEstat (free; CORS-friendly; ~1 req/sec polite limit)
curl -sk "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8" | jq '.data'

# bgp.tools per-IP API (free; light rate-limit; requires UA)
curl -sk -A "osint-recon/1.0 (contact@example.com)" "https://bgp.tools/api/ip/8.8.8.8" | jq .

# IPinfo Lite (free 50k req/month with free key)
curl -sk "https://ipinfo.io/8.8.8.8?token=<key>" | jq .
```

**Watch out:**
- `bgpview.io` API has aggressive undocumented rate limits (~1 req/min/IP); not suitable for bulk.
- `bgp.he.net` has no public API; HTML scraping only — fragile.
- `PeeringDB` is for facility/IX info, not per-IP ASN lookup.
- For bulk (>50 IPs): use the **Cymru bulk format** above; it accepts hundreds of IPs in one TCP session.

### 28.2 Certificates & CT Monitoring

- [crt.sh](https://crt.sh/), [Censys Certificates](https://search.censys.io/certificates), [CertStream](https://certstream.calidog.io/) (real-time CT WebSocket), [Rapid7 Open Data](https://opendata.rapid7.com/), [Cert Spotter](https://sslmate.com/certspotter) (freemium).
- **Favicon mmh3 hash:** cluster infrastructure across hosts; pair with Shodan/Censys favicon search for shared-infra discovery.

### 28.3 Web tech / TLS / fingerprinting

- **httpx (ProjectDiscovery)** — Wappalyzer-compatible ~600 signatures, JARM, favicon mmh3, TLS cert SHA256, security headers, screenshots. Recommended one-shot probe wrapper for thousands of hosts.
- **JARM** — TLS handshake hash; stable per server config; useful for clustering.
- **Wappalyzer** browser extension or CLI for tech enumeration.

### 28.4 TLS Deep Audit

Beyond the cert SAN + JARM, inspect cipher suites, protocols, and config quality.

**sslyze (most thorough):**
```bash
pip install sslyze
sslyze --regular target.example:443
sslyze --json_out=tls.json target.example:443
```
Reports: protocols supported (TLS 1.0/1.1/1.2/1.3), cipher suites per protocol, cert chain, OCSP, key info, robot/heartbleed/lucky13/poodle/freak/logjam/drown/ccs/ticketbleed.

**testssl.sh (thorough + readable output):**
```bash
docker run --rm -ti drwetter/testssl.sh https://target.example
# Or native install: https://github.com/drwetter/testssl.sh
testssl.sh --jsonfile-pretty=tls-report.json target.example:443
```

**nmap script alternative (lighter):**
```bash
nmap --script ssl-enum-ciphers,ssl-cert -p 443 target.example
```

**Check for these issues:**

| Issue | Severity | What to look for |
|---|---|---|
| TLS 1.0 / 1.1 supported | MEDIUM | Deprecated; PCI-DSS forbids TLS 1.0. |
| SSL 3.0 / 2.0 supported | HIGH | Critically deprecated. |
| Weak ciphers (RC4, 3DES, CBC modes) | MEDIUM | RC4 = NOMORE attack; 3DES = SWEET32. |
| Anonymous DH | HIGH | No authentication. |
| Self-signed cert on production | MEDIUM | Trust failure. |
| Expired cert | MEDIUM | Operational + trust failure. |
| Cert valid for too long (>397 days) | LOW | Browser warnings since 2020. |
| Wildcard cert covering critical hosts | INFO | Operational risk if private key compromised. |
| Weak key size (<2048 RSA, <256 ECDSA) | HIGH | Cryptographically weak. |
| Heartbleed (CVE-2014-0160) | CRITICAL | Memory disclosure. |
| ROBOT (CVE-2017-13099) | HIGH | Bleichenbacher. |
| CCS injection (CVE-2014-0224) | HIGH | OpenSSL specific. |
| Ticketbleed (CVE-2016-9244) | HIGH | F5-specific memory disclosure. |
| HSTS not present (covered §16.4) | MEDIUM | Header audit. |

**JA3 / JA4 reference databases:**

- [ja3er.com](https://ja3er.com) — community-curated JA3 → client-software mapping.
- [TLS Fingerprint DB](https://tlsfingerprint.io/) — research aggregator.
- For server JARM: search Shodan `ssl.jarm:<hash>` to find shared infrastructure / origin candidates (see §16.15).

### 28.5 Reverse DNS Sweep & IPv6 Enumeration

When a target owns an IP range (their ASN), enumerate it.

**Reverse DNS sweep (within scope):**
```bash
# Single /24
for i in $(seq 1 254); do
  IP="203.0.113.$i"
  PTR=$(dig +short -x $IP)
  [ -n "$PTR" ] && echo "$IP -> $PTR"
done

# Larger range with parallelism
prips 203.0.113.0/22 | xargs -I {} -P 50 sh -c 'PTR=$(dig +short -x {}); [ -n "$PTR" ] && echo "{} -> $PTR"'
```

**Mass DNS approach (better for large ranges):**
```bash
# zdns: install via go install github.com/zmap/zdns/cmd/zdns@latest
prips 203.0.113.0/22 | zdns PTR
```

**Banner-only sweep (no DNS round trip):**
```bash
# masscan + banner-grab
sudo masscan -p80,443 203.0.113.0/22 --rate=1000 --banners -oX masscan.xml
```

**IPv6 enumeration:**

IPv6 has weaker enumeration tradition (huge address space precludes brute-force) but the AAAA records and known-allocation prefixes are still useful.

```bash
# AAAA records for every discovered subdomain
for sub in $(cat all-subs.txt); do
  AAAA=$(dig +short AAAA $sub)
  [ -n "$AAAA" ] && echo "$sub -> $AAAA"
done

# IPv6 reverse DNS sweep is generally infeasible (2^64 host bits per subnet)
# Instead: extract IPv6 prefixes from the target's allocations
whois -h whois.cymru.com " -v target.example.com"   # gets ASN; then look up prefix
```

**BGP route observation:**

- **RouteViews** — `http://archive.routeviews.org/` (free; historical BGP routing table snapshots).
- **RIPE RIS** — `https://ris.ripe.net/` (free; route collectors).
- Use these to detect route hijacks against the target's prefixes (defensive intel; sometimes IOC).

**Reverse DNS pivots from third-party IPs:**

If a third-party shows the target's domain in PTR records (e.g., a hosting provider's IP has PTR `customer-acme.example.com.hostingprovider.net`), that's a pivot for adjacent customer infrastructure on the same provider/datacenter.

---

## 29. Threat Intel & IOCs

- Vendor / CERT advisories: CISA/NSA/CSA joint advisories, CERT-EU, NCSC-UK, JPCERT/CC, CERT-UA.
- [MISP Project](https://www.misp-project.org/) and public MISP feeds.
- [OpenCTI](https://www.opencti.io/) — CTI knowledge graph.
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) — malware families, YARA, references.
- [ThreatFox](https://threatfox.abuse.ch/), [URLHaus](https://urlhaus.abuse.ch/), [SSLBL](https://sslbl.abuse.ch/).
- [MalwareBazaar](https://bazaar.abuse.ch/) — hash-based sample sharing.
- [PhishTank](https://www.phishtank.com/), [OpenPhish](https://openphish.com/).

### 29.1 Malware Analysis & Sandboxes

- Static: [pefile](https://github.com/erocarrera/pefile), [FLOSS](https://github.com/mandiant/flare-floss), [capa](https://github.com/mandiant/capa).
- Similarity: SSDEEP, TLSH.
- Sandboxes: [ANY.RUN](https://any.run/), [Hybrid Analysis](https://www.hybrid-analysis.com/), [CAPE](https://capesandbox.com/), [Tria.ge](https://tria.ge/).
- Intelligence: [Intezer](https://analyze.intezer.com/) (code reuse), [VirusTotal](https://www.virustotal.com/) — **caution: uploads become public**.
- TLS: [JA3](https://github.com/salesforce/ja3), [JA4](https://github.com/FingerprinTLS/ja4).

### 29.2 Vulnerability Prioritization Data Sources

Methodology in companion skill §28. Concrete data sources here.

| Source | URL | What it tells you |
|---|---|---|
| **NVD** | `https://nvd.nist.gov/vuln/search` (or API `services.nvd.nist.gov/rest/json/cves/2.0`) | Base CVE catalog with CVSS v2/v3 scores. |
| **EPSS** | `https://www.first.org/epss/` (CSV at `https://epss.cyentia.com/epss_scores-current.csv.gz`) | 0.0-1.0 probability of exploit in next 30 days. Updated daily. |
| **CISA KEV** | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CVEs proven exploited in the wild + federal-agency due-by dates. |
| **ExploitDB** | `https://www.exploit-db.com/`; offline DB via `searchsploit` | POC code presence (Metasploit, Python, shell). |
| **Metasploit module catalog** | `https://www.rapid7.com/db/modules/` (or `msfconsole > search cve:CVE-2024-XXXX`) | Automation availability. |
| **InTheWild.io** | `https://inthewild.io/` | Community-curated "actively exploited" tracker. |
| **OpenCVE** | `https://www.opencve.io/` | Timeline + watchlist + alerts. |
| **Trickest CVE → POC mapping** | `https://github.com/trickest/cve` | Auto-generated CVE → public POC repo links. |
| **GitHub Security Advisories** | `https://github.com/advisories` | Per-language / per-ecosystem advisories. |
| **MITRE CVE List** | `https://cve.mitre.org/cve/` | Official CVE registry. |
| **VulnDB** | `https://vulndb.cyberriskanalytics.com/` | Paid; commercial enrichment. |
| **OSV.dev** | `https://osv.dev/` | Open-source vulnerability DB; JSON API. |
| **Vulncheck KEV** | `https://vulncheck.com/kev` | Expanded KEV feed (more than CISA). |
| **Tenable Research** | `https://www.tenable.com/research` | Tenable's CVE detail enrichment. |
| **Qualys ThreatPROTECT** | `https://threatprotect.qualys.com/` | Qualys' threat-context enrichment. |

**Workflow:**
```bash
# 1. Get EPSS score for a CVE
curl -sk "https://api.first.org/data/v1/epss?cve=CVE-2024-3400" | jq '.data[0]'

# 2. Check if in CISA KEV
curl -sk https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  jq '.vulnerabilities[] | select(.cveID == "CVE-2024-3400")'

# 3. Check ExploitDB
searchsploit cve 2024-3400

# 4. Check Metasploit
msfconsole -q -x "search cve:2024-3400; exit"
```

**Bulk prioritization** (given a Nuclei scan output with N CVEs):
```bash
# Extract CVEs from nuclei JSON output
jq -r '.info.classification.["cve-id"][]?' nuclei-results.json | sort -u > cves.txt

# Annotate each with EPSS + KEV
while IFS= read -r CVE; do
  EPSS=$(curl -sk "https://api.first.org/data/v1/epss?cve=$CVE" | jq -r '.data[0].epss // "N/A"')
  KEV=$(curl -sk https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
    jq --arg c "$CVE" '.vulnerabilities[] | select(.cveID == $c) | .vulnerabilityName // empty')
  KEV_FLAG=$([ -n "$KEV" ] && echo "KEV" || echo "")
  echo "$CVE | EPSS:$EPSS | $KEV_FLAG"
done < cves.txt | sort -t: -k2 -nr

---

## 30. Cryptocurrency OSINT

### 30.1 Blockchain Explorers

| Chain | Explorer |
|-------|---------|
| Bitcoin | [Blockchain.com](https://www.blockchain.com/explorer), [Blockchair](https://blockchair.com/) |
| Ethereum | [Etherscan](https://etherscan.io/) |
| BNB Chain | [BSCScan](https://bscscan.com/) |
| Polygon PoS | [PolygonScan](https://polygonscan.com/) |
| Solana | [Solscan](https://solscan.io/) |
| Multi-chain | [OKLink](https://www.oklink.com/) (freemium), [Cielo](https://cielo.io/) |

### 30.2 L2 / Rollup Explorers

| L2 | Explorer | Notes |
|---|---|---|
| Arbitrum | [Arbiscan](https://arbiscan.io/) | Optimistic rollup; 7-day challenge window. |
| Optimism | [Optimistic Etherscan](https://optimistic.etherscan.io/) | Optimistic rollup; 7-day challenge window. |
| Base | [BaseScan](https://basescan.org/) | OP Stack. |
| Blast | [Blastscan](https://blastscan.io/) | OP Stack derivative. |
| Scroll | [Scrollscan](https://scrollscan.com/) | zkEVM. |
| zkSync Era | [zkSync Era Block Explorer](https://explorer.zksync.io/) | zkRollup; faster finality. |
| Polygon zkEVM | [PolygonScan zkEVM](https://zkevm.polygonscan.com/) | zkEVM. |
| StarkNet | [Voyager](https://voyager.online/), [StarkScan](https://starkscan.co/) | Cairo VM; different address derivation. |
| Cross-L2 | [L2Beat](https://l2beat.com/) | Risk framework + TVL comparison. |

### 30.3 Transaction Tracking & Analytics

- [Arkham](https://www.arkhamintelligence.com/) — multichain, entity labels, graphs, alerts.
- [TRM](https://www.trmlabs.com/) — address/tx graphs.
- [MetaSleuth](https://metasleuth.io/) — visual flow.
- [Breadcrumbs](https://www.breadcrumbs.app/) (freemium) — visual graphing + labels.
- [Bubblemaps](https://bubblemaps.io/) — holder concentration.
- [Whale Alert](https://whale-alert.io/) — large transaction monitoring.
- [Chainalysis](https://www.chainalysis.com/) / [Crystal Blockchain](https://crystalblockchain.com/) — pro analytics.
- [GraphSense](https://graphsense.info/) — open-source crypto analytics.
- [Nansen](https://www.nansen.ai/) — Smart Money labels (paid).
- [Dune](https://dune.com/) — custom queries.
- [Token Sniffer](https://tokensniffer.com/) — honeypot/scam detection.

### 30.4 NFT / Exchange / Bridges

- [OpenSea](https://opensea.io/), [NFTScan](https://www.nftscan.com/), [DappRadar](https://dappradar.com/), [CoinGecko](https://www.coingecko.com/), [CoinMarketCap](https://coinmarketcap.com/), [Glassnode](https://glassnode.com/).
- Bridges: [Socketscan](https://socketscan.io/), [L2Beat Bridges](https://l2beat.com/bridges), [Pulsy](https://pulsy.io/).

---

## 31. Media Intelligence

### 31.1 Reverse Image & Facial Search

- [Google Images](https://images.google.com/), [TinEye](https://tineye.com/), [Yandex Images](https://yandex.com/images/) (Russian/East European strong), [PimEyes](https://pimeyes.com/en), [FaceCheck](https://facecheck.id/).

### 31.2 Image Forensics

- [Forensically](https://29a.ch/photo-forensics/), [ExifTool](https://exiftool.org/), [Jimpl](https://jimpl.com/), [Jeffrey's EXIF Viewer](http://exif.regex.info/exif.cgi), [FOCA](https://www.elevenpaths.com/labstools/foca), [Metagoofil](https://www.edge-security.com/metagoofil.php), [C2PA Verify](https://verify.contentauthenticity.org/).

### 31.3 Video Analysis

- [YouTube Data Viewer](https://citizenevidence.amnestyusa.org/), [InVID & WeVerify](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/), [YouTube Geo Tag](https://mattw.io/youtube-geofind/location), [MediaInfo](https://mediaarea.net/en/MediaInfo), Snap Map.

### 31.4 Browser Extensions for Media

- [Fake News Debunker (InVID & WeVerify)](https://chrome.google.com/webstore/detail/fake-news-debunker-by-inv/mhccpoafgdgbhnjfhkcmgknndkeenfhe).
- [RevEye Reverse Image Search](https://chrome.google.com/webstore/detail/reveye-reverse-image-sear/kejaocbebojdmebagkjghljkeefgimdj).
- [EXIF Viewer Pro](https://chrome.google.com/webstore/detail/exif-viewer-pro/mmbhfeiddhndihdjeganjggkmjapkffm).
- [Wayback Machine Extension](https://chrome.google.com/webstore/detail/wayback-machine/fpnmgdkabkmnadcjpehmlllkndpkmiak).
- [Search by Image](https://chromewebstore.google.com/detail/search-by-image/cnojnbdhbhnkbcieeekonklommdnndci).

---

## 32. Geospatial Intelligence

### 32.1 Satellite & Mapping

- [Google Maps](https://www.google.com/maps), [Bing Maps](https://www.bing.com/maps/).
- [Sentinel Hub EO Browser](https://apps.sentinel-hub.com/eo-browser/), [NASA Worldview](https://worldview.earthdata.nasa.gov/), [Zoom Earth](https://zoom.earth/).
- [Wayback Imagery](https://livingatlas.arcgis.com/wayback/) — historical satellite.
- [NASA FIRMS](https://firms.modaps.eosdis.nasa.gov/map/), [Open Infrastructure Map](https://openinframap.org/), [Windy](https://www.windy.com/).

### 32.2 Geolocation Tools

- [Mapillary](https://www.mapillary.com/app), [KartaView](https://kartaview.org/), [Overpass Turbo](https://overpass-turbo.eu/), [SunCalc](https://www.suncalc.org/), [GeoNames](https://www.geonames.org/), [PeakVisor](https://peakvisor.com/), [GeoGuesser tips](https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/).

**Street View:** Google Street View, [Apple Maps](https://maps.apple.com/), [Yandex Maps](https://yandex.com/maps/), [Baidu Maps](https://map.baidu.com/).

### 32.3 Flight OSINT

- [FlightRadar24](https://www.flightradar24.com/), [FlightAware](https://www.flightaware.com/), [RadarBox](https://www.radarbox.com/).
- [ADSBExchange](https://www.adsbexchange.com/) — unfiltered.
- [Planespotters](https://www.planespotters.net/) — fleet/airframe history.
- [AirFrames](https://www.airframes.org/), [JetPhotos](https://www.jetphotos.com/).

### 32.4 Maritime OSINT

- [MarineTraffic](https://www.marinetraffic.com/), [VesselFinder](https://www.vesselfinder.com/), [FleetMon](https://www.fleetmon.com/).
- [Global Fishing Watch](https://globalfishingwatch.org/map/) — vessel behavior + AIS gap analysis.

---

## 33. AI-Assisted OSINT

> **Warning:** Never paste PII, sensitive IOCs, or unique pivots into cloud LLMs. They log inputs and may use them for training. Use local models for sensitive analysis.

| Tool | Strength |
|------|---------|
| [ChatGPT](https://chat.openai.com/) (paid) | Log parsing, dataset analysis, Code Interpreter for CSV/JSON, Vision OCR. |
| [Claude](https://claude.ai/) (paid) | 200K-token context for large doc dumps + report synthesis. |
| [Gemini](https://gemini.google.com/) | Long-context; Deep Research mode with citations. |
| [Perplexity Pro](https://www.perplexity.ai/) (paid) | Real-time web search + reasoning. |

**Local / privacy-preserving:** [Ollama](https://ollama.com/), [LM Studio](https://lmstudio.ai/), [GPT4All](https://gpt4all.io/).

### 33.1 Commercial AI OSINT Platforms

- [Cylect](https://www.cylect.io/) — entity extraction + link analysis.
- [Fivecast Matrix](https://www.fivecast.com/products/matrix/) — generative-AI triage for social-media datasets.
- [Recorded Future](https://www.recordedfuture.com/) — AI-driven threat intel.
- [DarkOwl Vision](https://www.darkowl.com/) — darknet data analysis.

### 33.2 Deepfake & Synthetic Media Detection

- [Sensity AI](https://sensity.ai/), [Reality Defender](https://realitydefender.com/), [Adobe Content Credentials Verify](https://contentcredentials.org/verify), [CarNet](https://carnet.ai/).

---

## 34. Archiving & Evidence Preservation

- [archive.today](https://archive.today/) — one-page archiver + screenshot.
- [URLScan.io](https://urlscan.io/) — webpage scan + resource map.
- [ArchiveBox](https://archivebox.io/) — self-hosted (HTML, PDF, screenshots, media).
- [Hunchly](https://www.hunch.ly/) — investigator evidence capture (paid).
- Wayback SavePageNow API v3 — on-demand archiving with job IDs.
- [SingleFileZ](https://github.com/gildas-lormeau/SingleFileZ) — browser ext for offline HTML.
- [Kasm Workspaces](https://kasmweb.com/) — containerized OSINT browser isolation.

**Evidence handling:** URL + UTC timestamp + PNG + WARC/SingleFileZ archive, SHA-256 hash all downloads, separate work profiles per case, store evidence read-only, JSONL run logs with `run_id` + tool versions.

---

## 35. Automation & Workflows

- [n8n](https://n8n.io/) — self-hosted workflow automation (RSS → scrape → alert pipelines).
- [Huginn](https://github.com/huginn/huginn) — agent-based monitoring/scraping/alerting.
- [Playwright](https://playwright.dev/) — headless browser automation with stealth plugins.
- [Browsertrix Crawler](https://github.com/webrecorder/browsertrix-crawler) — archival crawling with WARC export.
- [Prefect](https://www.prefect.io/) / [Apache Airflow](https://airflow.apache.org/) — workflow orchestration.

---

## 36. Cross-Module Sidecar Coordination

When you run a multi-module recon, late-arriving outputs need to feed into already-running modules. The pattern:

1. Each module writes a sidecar JSON to a known location when it finishes:
   - `<scan>/mobile_endpoints.json` — endpoints + hostnames extracted from APK static analysis.
   - `<scan>/secrets_sidecar.json` — hostnames + endpoints + Firebase project IDs from secrets-beyond-github sweep.
   - `<scan>/sso_tenants.json` — discovered IdP tenants for breach correlation.
2. Downstream modules check for sidecars on start; if present, ingest.
3. Cross-feed: API discovery consumes both `mobile_endpoints.json` and `secrets_sidecar.json`; SSO×breach correlation consumes `sso_tenants.json` and the breach DB.

**Sidecar shape (mobile_endpoints.json example):**
```json
{
  "endpoints": [
    {"method": "GET", "url": "https://api.acme.com/v1/users", "source": "apk:com.acme.android"},
    {"method": "POST", "url": "https://api.acme.com/v1/login", "source": "apk:com.acme.android"}
  ],
  "hostnames": ["api.acme.com", "cdn.acme.com"],
  "firebase_project_ids": ["acme-prod-12345"]
}
```

When you implement an ad-hoc multi-tool recon (no platform), use a `tmpdir + JSON sidecars + a one-line manifest` pattern. Composable, debuggable, replay-able.

---

## 37. Regional Search Engines

- **Russia / CIS:** [Yandex](https://yandex.com/), [Mail.ru Search](https://go.mail.ru/).
- **China:** [Baidu](https://www.baidu.com/), [Sogou](https://www.sogou.com/), [360 Search](https://www.so.com/).
- **Russia social:** [VK](https://vk.com/), [OK.ru](https://ok.ru/).
- **China social:** [Weibo](https://weibo.com/), [Bilibili](https://www.bilibili.com/), [Zhihu](https://www.zhihu.com/), [Douyin](https://www.douyin.com/).

---

## 38. Telegram & Messaging Intelligence

- [TGStat](https://tgstat.com/) — channel analytics + search.
- [Telemetr](https://telemetr.io/) — channel growth, overlaps, forwards.
- [Combot](https://combot.org/) — group analytics (partial paid).
- [TelegramDB Search Bot](https://t.me/TGdb_bot) — basic Telegram OSINT.
- [Discord ID](https://discord.id/) — basic Discord account info.
- [Sogou Weixin search](https://weixin.sogou.com/) — WeChat Official Accounts.
- View public Telegram channels: `https://t.me/s/<channel>`.

---

## 39. Attack-Path Hint Patterns

When emitting a HIGH/CRITICAL API endpoint finding (score ≥ 70), include a one-sentence `attack_path_hint` in evidence so the operator knows where to start exploiting. Templates:

| Trigger | Attack-path hint |
|---|---|
| Unauth POST / PUT / DELETE | *"Unauthenticated {method} {path} — try IDOR + privilege escalation; check whether numeric IDs are sequential or guessable."* |
| Open GraphQL introspection | *"Open GraphQL introspection on {path} — enumerate mutations, look for `createUser`, `setRole`, `transferFunds`-shaped names; pivot to broken-auth or business-logic flaws."* |
| Reflected CORS + creds | *"Reflected CORS with credentials on {path} — host CSRF page on attacker-controlled origin; victim's browser will leak {sensitive-data-hint}."* |
| Wildcard CORS + sensitive | *"Wildcard CORS on {path} returning user-tied data without creds — exfiltrate via cross-origin fetch from any page victim visits."* |
| Verb tampering | *"Verb tampering: {hidden-method} allowed on documented-{visible-method}-only endpoint → likely missing-method-check authz bug; try {hidden-method} {path} with valid auth."* |
| API key in URL | *"API key in URL: `?{param}=...` — token leaks to access logs, browser history, Referer headers, third-party CDNs. Check Wayback / Google for cached copies."* |
| Schema leak in error | *"Schema leak in error response — framework signature `{framework}` exposed; map to known {framework} vulns and craft targeted payloads."* |
| Sensitive keyword | *"Path contains '{keyword}' — review for direct object reference, mass-assignment, or hidden admin functionality."* |
| Open RTDB Firebase | *"Open Firebase RTDB at https://{project}.firebaseio.com/.json — read everything, then test write at `/<random-key>.json` with PUT to gauge ACL scope."* |
| Listable cloud bucket | *"Listable {provider} bucket `{bucket}` — recursive object listing + content-type analysis; look for backups, logs, customer data, AWS keys in JSON configs."* |
| .git exposed | *"Exposed .git/config on {host} — reconstruct repository with git-dumper or githacker; full source history."* |
| .env exposed | *"Exposed .env on {host} — grep for `_KEY`, `_SECRET`, `_TOKEN`, `_PASSWORD`; validate all credentials read-only via §23 validators."* |
| /actuator/env | *"Spring Boot /actuator/env exposed — dump environment variables; look for `spring.datasource.password`, JWT secrets, cloud creds."* |
| /actuator/heapdump | *"Spring Boot /actuator/heapdump exposed — download HPROF, run `jhat` or VisualVM, search for cleartext secrets in heap strings."* |
| Open Elasticsearch | *"Open Elasticsearch on {host}:9200 — `/_cat/indices?v` for index list; sample documents from each high-value index; test write to `/test-idx/_doc` to gauge ACL."* |
| Open Redis | *"Open Redis on {host}:6379 — `INFO`, `KEYS *`, sample reads; check for write access via `CONFIG SET` then `BGSAVE` to write `authorized_keys`."* |
| Open MongoDB | *"Open MongoDB on {host}:27017 — `show dbs`, `show collections`, sample find queries; check user collection for password hashes."* |
| Subdomain takeover | *"CNAME for {host} points to unclaimed {provider} resource → register `{takeover-target}` on {provider} to serve content from {host}; pivot to phishing or content injection on the trusted domain."* |
| Open kubelet | *"Open kubelet on {host}:10250 — `GET /pods` to list; `POST /run/<ns>/<pod>/<container>` for in-container exec without K8s API auth."* |
| Open etcd | *"Open etcd on {host}:2379 — `etcdctl get / --prefix --keys-only` for full cluster state; secrets stored under `/registry/secrets/`."* |
| K8s API anonymous | *"Kubernetes API on {host}:6443 with anonymous-auth — `kubectl --server=https://{host}:6443 --insecure-skip-tls-verify get pods --all-namespaces`."* |
| Citrix unpatched | *"Citrix NetScaler version {ver} on {host} — vulnerable to CVE-{cve} (KEV-listed); see vendor advisory; do not exploit but flag for client immediate patching."* |
| F5 BIG-IP TMUI exposed | *"F5 BIG-IP TMUI on {host} reachable; CVE-2022-1388 / CVE-2023-46747 KEV applicable; advise immediate patching to vendor-released hotfix."* |
| VMware vCenter accessible | *"vCenter at {host} accessible without VPN; CVE-2021-21972 RCE if unpatched; check version banner."* |
| Cloud function URL unauth | *"AWS Lambda Function URL at {url} accessible anonymously — review IAM auth configuration; if unauthenticated by design, audit input validation aggressively."* |
| npm typosquat candidate | *"Package name `{candidate}` is unregistered + similar to target's published `{official}` — typosquat takeover risk; advise client to defensively register."* |
| DMARC missing/permissive | *"DMARC `p=none` on {domain} — spoof of `{anything}@{domain}` deliverable to recipients; recommend enforcement to `p=quarantine` or `p=reject` after observing reports."* |
| Live AI API key (Anthropic/OpenAI) | *"Validated `sk-{provider}-...` key with model access — quota cost can be exfiltrated; rotate immediately + audit usage logs in provider console."* |
| Public Slack invite link | *"Slack workspace invite link discoverable via search engine — anyone can join the workspace without approval; trivially access internal channels."* |
| Open Docker registry | *"Public Docker registry at {host} — `GET /v2/_catalog` lists images; pull and scan layers for embedded secrets."* |
| Telegram bot token live | *"Telegram bot token validated — `getUpdates` reveals bot recipients (admin chats); if `getMe` shows bot is in channels, full message read access."* |
| Sourcemap with `sourcesContent[]` | *"Sourcemap on {host} includes embedded original sources — full frontend code reconstructable; grep for inline secrets and internal hostnames."* |

---

## 40. Severity Decision Matrix — Worked Examples

When in doubt, anchor on these worked examples (drawn from real engagements):

| Finding | Severity | Why |
|---|---|---|
| `/.git/config` reachable on prod webapp | **CRITICAL** | Full source-code disclosure; secret history reconstructable. |
| `/.env` reachable on prod webapp | **CRITICAL** | Plaintext creds (DB, cloud, API). |
| Open Firebase RTDB returning data | **CRITICAL** | All app data readable; often writable. |
| Listable S3 bucket containing PII | **CRITICAL** | Direct data exfil. |
| Listable S3 bucket containing logs only | HIGH | Internal hostnames + paths in logs; pivot data. |
| Spring Boot `/actuator/env` exposed | **CRITICAL** | DB creds, JWT secrets, cloud keys in env. |
| Spring Boot `/actuator/heapdump` exposed | **CRITICAL** | Heap contains live secrets in string form. |
| Open Elasticsearch (`/_cat/indices` returns) | **CRITICAL** | Full data reads; often writable. |
| Open MongoDB (no auth) | **CRITICAL** | Full data + password-hash collection. |
| Open Redis (no AUTH) | **CRITICAL** | Write `authorized_keys` → SSH foothold. |
| Open Docker API (port 2375) | **CRITICAL** | Container/host takeover. |
| Public PMAK validated live with broad scope | **CRITICAL** | Full Postman account + all team workspaces. |
| Public AWS root access key validated live | **CRITICAL** | Full account compromise. |
| Live AWS IAM-user key found on GitHub | HIGH | Limited scope (depends on IAM policy); often elevatable. |
| Live GitHub PAT found in JS bundle | HIGH | Repo write access (depends on scope). |
| Live Slack token in pastebin | HIGH | Workspace data + history; sometimes channel post. |
| Sourcemap (`.js.map`) accessible on prod | HIGH | Frontend source disclosure. |
| Open GraphQL introspection on prod | HIGH | Full schema → mutations + business-logic discovery. |
| Subdomain takeover possible (Heroku / GitHub Pages / etc.) | HIGH | Takeover → phishing on trusted domain. |
| Reflected CORS with credentials on `/api/billing` | HIGH | CSRF-via-CORS for billing data. |
| Verb tampering: DELETE allowed on documented-GET-only endpoint | HIGH | Authz bypass; potentially destructive. |
| `phpinfo.php` reachable on prod | HIGH | Discloses paths, env vars, modules → vuln-version pivot. |
| Tomcat `/manager/html` reachable | HIGH | Often default creds; WAR upload = RCE. |
| Jenkins script console accessible | HIGH | Groovy script execution = RCE. |
| Missing HSTS on `/login` | HIGH (escalated from MED) | Login pages must enforce HSTS. |
| Missing HSTS on standard pages | MEDIUM | Hardening gap. |
| Missing CSP | MEDIUM | XSS impact mitigation gone. |
| Internal IP / K8s service DNS in JS | MEDIUM | Internal topology disclosure. |
| Apache `/server-status` reachable | MEDIUM | Live request visibility. |
| `android:debuggable=true` on prod app | **CRITICAL** | Production debug-build → full client compromise. |
| `android:allowBackup=true` (no whitelist) | MEDIUM | App data exfil via `adb backup`. |
| `android:usesCleartextTraffic=true` | MEDIUM | MITM-able on hostile networks. |
| Sensitive deep-link handler (`myapp://reset-password`) | HIGH | Other apps can trigger sensitive flows. |
| Exported Android component without permission | MEDIUM | IPC attack surface. |
| Slack webhook URL leaked | MEDIUM | Send to channel; can be used for social-eng. |
| Twilio Account SID leaked (no auth token) | MEDIUM | Half a credential pair; plus account enumeration. |
| Wildcard CORS on data-returning API | MEDIUM | Lower than reflected+creds but still exfil-able. |
| Missing `X-Frame-Options` | LOW | Clickjacking. |
| `.DS_Store` exposed | LOW | Directory listing of dev's machine. |
| Stripe **test** key leaked | LOW | No real money risk. |
| Firebase URL exposed (no open RTDB) | LOW | Project-ID disclosure only. |
| Cert pinning missing in mobile app | LOW | MITM possible on hostile networks. |
| Outdated WordPress install detected | LOW | Pending CVE confirmation. |
| Missing `Referrer-Policy` / `Permissions-Policy` | INFO | Hardening, not an exposure. |
| `/.well-known/security.txt` discovered | INFO | Useful contact info only. |
| Domain in breach with 0 named accounts | INFO | Contextual only. |
| Private bucket exists (HEAD 403) | INFO | Asset only, no finding. |
| Open kubelet on 10250 | **CRITICAL** | Pod exec without K8s API auth. |
| Open etcd on 2379 | **CRITICAL** | Cluster state + secrets. |
| K8s API on 6443 with anonymous-auth | HIGH | Cluster recon; sometimes pod exec. |
| K8s dashboard exposed without auth | HIGH | Cluster admin UI. |
| Helm Tiller (Helm 2) on 44134 | HIGH | Cluster-admin scope. |
| Citrix Netscaler with KEV CVE | **CRITICAL** | Patch immediately; actively exploited. |
| F5 BIG-IP TMUI accessible | HIGH | TMUI = admin panel; CVE-2022-1388 if unpatched = CRIT. |
| Pulse Secure with CVE-2024-21887 | **CRITICAL** | KEV; chained command injection. |
| FortiGate with CVE-2024-21762 | **CRITICAL** | KEV; auth bypass + RCE. |
| PaloAlto GlobalProtect with CVE-2024-3400 | **CRITICAL** | KEV; pre-auth RCE. |
| VMware vCenter with CVE-2021-21972 | **CRITICAL** | KEV; pre-auth RCE. |
| VMware ESXi exposed without VPN | HIGH | Multiple CVEs (ESXiArgs ransomware vector). |
| MS Exchange with ProxyShell/Logon/NotShell unpatched | **CRITICAL** | KEV chain; RCE + mailbox dump. |
| AWS Lambda Function URL accessible anonymously | HIGH | Direct invocation; check IAM auth posture. |
| Public Cloud Run / Cloud Function unauthenticated | HIGH | Same. |
| Public Docker registry (anonymous catalog) | MEDIUM | Image enum + secret hunt in layers. |
| GitHub Actions secrets echoed in workflow logs | HIGH | Secret-in-log = full secret disclosure. |
| GitHub Actions `pull_request_target` checkout of fork code | HIGH | Class of bug; secrets accessible to attacker PRs. |
| GitLab self-hosted with CVE-2021-22205 | **CRITICAL** | KEV; ExifTool RCE. |
| Jenkins with `pull_request_target`-equivalent misconfig | HIGH | Build secrets accessible to PRs. |
| Public Notion page with internal SOPs | MEDIUM | Operational intel; sometimes credentials. |
| Public Trello board with credentials in cards | HIGH | Often plaintext API keys. |
| Public Confluence space with onboarding docs | MEDIUM | Seed creds + tech-stack reveal. |
| Public Miro board with architecture diagrams | LOW | Internal-host disclosure. |
| DMARC policy `p=none` on production sending domain | MEDIUM | Spoof feasible (escalated from LOW for risk surface). |
| SPF `~all` (softfail) without strict DMARC | MEDIUM | Spoofs land in spam, but land. |
| MX server allows open relay (test with 250 OK to RCPT TO foreign domain) | HIGH | Spam + spoof feasibility. |
| Live Anthropic / OpenAI API key with broad scope | **CRITICAL** | Quota cost + potential PII in past responses. |
| Live npm token with `publish` scope | **CRITICAL** | Supply-chain compromise of all maintained packages. |
| Live PyPI / Docker Hub / GHCR token with publish scope | **CRITICAL** | Supply-chain compromise. |
| Atlassian token with admin scope | HIGH | Workspace-wide read; sometimes write. |
| Subdomain takeover candidate confirmed | HIGH | Trusted-domain phishing surface. |
| Sensitive CI/CD wordlist hits (Jenkinsfile, .gitlab-ci.yml on public repo) | MEDIUM | Build-script intel; often references secret names. |
| Public Postman workspace with internal API endpoints | MEDIUM | API attack surface mapped. |
| WAF/CDN trivially bypassable (origin discoverable via §16.15) | HIGH | All WAF protections null. |
| TLS 1.0/1.1 supported on prod | MEDIUM | Compliance gap; PCI-DSS forbids TLS 1.0. |
| RC4 / 3DES cipher accepted | MEDIUM | NOMORE / SWEET32 attacks. |
| Cert about to expire (<30 days) | LOW | Operational risk; not exploitable. |
| Self-signed cert on prod | MEDIUM | Trust failure for users. |
| Heartbleed (CVE-2014-0160) detected | **CRITICAL** | Memory disclosure including session tokens + keys. |
| Public Slack invite link discoverable | HIGH | Anyone joins workspace; full DM/channel access. |
| Vendor / supplier / e-procurement portal publicly exposed + breach corpus shows vendor accounts compromised | **HIGH** | Vendor impersonation + procurement fraud (BEC vector); regulatory exposure if PII/payment data flows. |
| Job-application / careers portal collects PII over plain HTTP (no TLS) | **HIGH** | Cleartext PII at scale; regulatory exposure under GDPR / CCPA / India DPDP Act / LGPD. |
| Decommissioned legacy mail (NXDOMAIN today) + breach corpus has historical employee URLs against it + cloud SSO migration confirmed via autodiscover IPs | **CRITICAL** | Stolen passwords almost certainly survived migration via reuse; SSO_EXPOSURE escalates regardless of the legacy host being dead. |
| Public-facing intranet (`intranet.<domain>` resolves and returns content without VPN) | MEDIUM | Internal-staff portal exposed; often leaks org structure, employee directory, internal apps. |
| Staging / preprod / UAT / sandbox subdomain publicly resolvable | MEDIUM | Often weaker auth, debug endpoints, test creds; sometimes mirrors prod data. |
| `vpn.<domain>` resolves but vendor + version unknown (passive only) | INFO | Attack surface flag only; escalate to HIGH-CRITICAL after active fingerprint matches a KEV CVE (§16.16). |
| DMARC RUA points to a third-party reporting vendor (kdmarc / dmarcian / Valimail / Agari / EasyDMARC) | INFO | Tenant signal only; vendor compromise = DMARC bypass for *all* their customers. |

---

## 41. LinkedIn Employee Enumeration

LinkedIn is the highest-signal source for employee enumeration during external red-team work. Use it for: target list generation, role prioritization, email-pattern derivation, pretext development.

### 41.1 Search techniques

**Free LinkedIn (no Sales Navigator):**
- People-search by company: `https://www.linkedin.com/search/results/people/?currentCompany=["<company-id>"]`. Get company-id from the company's LinkedIn URL or profile JSON.
- Bypass connection-degree filter: search shows 1st/2nd-degree only by default; use Google dorking instead.

**Google dork for LinkedIn employee enum:**
```
site:linkedin.com/in "<company name>"
site:linkedin.com/in "<company name>" "engineer"   # role filter
site:linkedin.com/in "<company name>" "<location>" # location filter
site:linkedin.com/in "<company name>" -inurl:/posts
```

**Bing/DuckDuckGo equivalents** — sometimes return different result sets; cross-engine union.

**LinkedIn Sales Navigator (paid):**
- Most efficient if available. Lead lists by company × role × seniority. Export CSV.

**Tools:**
- **theHarvester** with `-b linkedin` source (uses search-engine-driven enum).
- **CrossLinked** — `https://github.com/m8r0wn/CrossLinked` — CLI tool that does the LinkedIn dorking.
- **LinkedInDumper** / **Linkook** — open-source enum tools (verify currency; they break frequently).
- **PhantomBuster** / **Apollo.io** / **RocketReach** / **Hunter.io Email Finder** — paid SaaS that does the enum + email derivation in one workflow.

### 41.2 Role inference for prioritization

For each enumerated employee, capture:
- **Name** (canonical form: First Last; remove suffixes like "PMP", "PhD" for email-pattern matching).
- **Job title** (raw + normalized to a role tier).
- **Tenure** (years at company; longer = more access typically).
- **Location** (city / region; informs phishing time-of-day).
- **Recent activity** (posts, comments, articles — informs pretext).

**Role priority for breach lookup + phishing target list:**

| Role tier | Examples | Why |
|---|---|---|
| **P0** | CEO, CFO, CTO, CISO, CIO, COO, GC, CRO | Exec accounts; BEC + finance + legal authority. |
| **P1** | VP / Director of IT / Security / Engineering / Finance / HR | Privileged tool access; reset workflows. |
| **P2** | DevOps, SRE, Platform, Security Engineer, DBA | GitHub / cloud / CI access; secrets in their accounts. |
| **P3** | Software Engineer, Architect, Senior Developer | Code + occasional cloud access. |
| **P4** | Sales, Marketing, HR, Finance Analyst, Customer Support | SaaS access (Salesforce, HubSpot, Workday); BEC enabler. |
| **P5** | Generic individual contributor, intern, contractor | Lowest single-account value but breadth matters. |

### 41.3 Email-pattern derivation from confirmed names

For each captured name, derive candidate emails using §11 templates. Cross-reference against:
- Hunter.io `domain-search` to confirm pattern.
- Breach corpus (HudsonRock + HIBP + DeHashed + IntelX) to find matches.

### 41.4 Sock-puppet considerations

- **Never connect from the corporate persona.** LinkedIn shows "viewed your profile" notifications.
- **Use a sock puppet** with a plausible profile (5+ years built history, similar industry, mutual connections to throw off correlation). Tools: persona-builder workflows.
- **LinkedIn "private mode" (anonymous viewing)** — toggle in settings; reduces one signal but Sales Navigator can still see anonymized "someone viewed your profile."
- **Connection requests are detectable.** Don't send any during recon.
- **Profile views accumulate suspicion** if you view 100+ employees of one company in a day. Throttle: <20/day per persona.

### 41.5 Output

Per discovered employee:
```
Person:
  name:        "Alice Doe"
  title:       "Senior DevOps Engineer"
  role_tier:   P2
  company:     "Acme Corp"
  location:    "Boston, MA"
  linkedin_url: https://www.linkedin.com/in/alicedoe
  derived_emails:
    - alice.doe@acme.com    (TENTATIVE)
    - adoe@acme.com         (TENTATIVE)
    - alice@acme.com        (TENTATIVE)
  breach_hits:
    - alice.doe@acme.com    (HudsonRock; cleartext password redacted; FIRM)
  pretext_hooks:
    - "DevOps tooling vendor evaluation" (recent posts)
    - "Boston DevOps Days speaker" (conference activity)
```

---

## 42. Job Posting Tech-Stack Analysis

Job postings reveal the target's internal tech stack with surprising precision. Free, public, and they include the exact vendor names.

### 42.1 Sources

| Platform | URL | Notes |
|---|---|---|
| LinkedIn Jobs | `https://www.linkedin.com/jobs/search/?keywords=&f_C=<company-id>` | Most current; require LI account. |
| Indeed | `https://www.indeed.com/cmp/<company>` | Company page with job feed. |
| Glassdoor | `https://www.glassdoor.com/Jobs/<company>-Jobs-E<id>.htm` | Plus salary data + employee reviews. |
| Lever (ATS) | `https://jobs.lever.co/<company>` | Direct ATS — full job descriptions. |
| Greenhouse (ATS) | `https://boards.greenhouse.io/<company>` | Direct ATS. |
| Workable (ATS) | `https://apply.workable.com/<company>/` | Direct ATS. |
| AshbyHQ (ATS) | `https://jobs.ashbyhq.com/<company>` | Direct ATS. |
| AngelList / Wellfound | `https://wellfound.com/company/<company>/jobs` | Startup-focused. |
| BuiltIn | `https://builtin.com/companies/view/<company>` | Tech-focused. |
| Stack Overflow Jobs | (deprecated 2022 but archive available) | Historical tech-stack data. |
| Company careers page | `https://careers.<target>.com` or `https://<target>.com/careers` | Direct source; sometimes more detail than ATS. |

### 42.2 What to extract

For each job posting, harvest:
- **Required technologies** ("must have experience with X, Y, Z") → confirmed in-use.
- **Nice-to-have technologies** → likely in use but maybe in transition.
- **Vendor names** (Workday, Salesforce, Snowflake, Databricks, Datadog, etc.) → SaaS tenants.
- **Internal tool / project codenames** (often slip into "you'll work on Project Aurora") → recon vocabulary.
- **Team size hints** ("part of a 12-person platform team") → org-structure intel.
- **Office locations** ("hybrid 3 days in Boston office") → physical recon.
- **Cloud + on-prem ratio hints** ("migrating from on-prem to AWS") → posture intel.
- **Compliance frameworks mentioned** (SOC2, FedRAMP, HIPAA, PCI) → defensive priorities + reporting context.

### 42.3 Tooling

- **scrapy / BeautifulSoup** — custom scrapers per ATS.
- **theHarvester** with appropriate sources.
- **JobScraper** scripts on GitHub.
- **Manual** — for small targets, manual review of 20–30 postings is fast and high-fidelity.

### 42.4 Output

Per discovered tech mention:
```
Tech_inferred:
  product:     "Snowflake"
  category:    "data warehouse"
  source:      "linkedin job posting #<id>"
  source_url:  https://www.linkedin.com/jobs/view/...
  confidence:  TENTATIVE  (job listing implies in-use; not yet confirmed by direct probe)
  posting_date: 2026-03-15
  required_or_nice: "required"
```

Aggregate to a **target tech-stack profile** that informs:
- Which secret patterns to look for (Snowflake-specific keys, Databricks tokens).
- Which SaaS tenants to fingerprint (Snowflake account URL pattern).
- Which vendor-product fingerprints to probe (Snowflake DSN paths in JS).

---

## 43. Slack / Discord / Telegram Workspace Discovery

### 43.1 Slack

- **Public workspace search** (limited; Slack used to have one but deprecated):
  - **Slofile** (third-party): `https://slofile.com/` — community Slack workspace directory.
  - **Slacklist** / **Slack Communities** — community-curated lists.
- **Invite-link enumeration** — Slack invite URLs follow `https://join.slack.com/t/<workspace-slug>/shared_invite/<token>`. Common discovery:
  - Google: `site:join.slack.com "{target}"` or `inurl:slack.com inurl:shared_invite "{target}"`.
  - GitHub: `"join.slack.com/t/<target-stem>"` filename:README.
  - Twitter/X / Reddit: search for shared invite links.
- **Confirm workspace exists**: visit `https://<slug>.slack.com/api/auth.test` (returns workspace metadata when called by an authenticated session, but the page itself returns differently per workspace existence).
- **High-value finding**: any open invite link that bypasses the target's normal member-approval flow → operator can join workspace without authorization → MEDIUM/HIGH finding (depending on what's in the workspace).

### 43.2 Discord

- **Discord server discovery** is harder (no central public directory).
- **DiscordServers.com** — third-party directory.
- **Discord.me** / **Top.gg** — community directories.
- Google: `site:discord.gg "{target}"` or `site:discord.com "{target}"`.
- **Confirm server**: invite URLs `https://discord.gg/<token>` resolve to a JSON via `https://discord.com/api/v9/invites/<token>?with_counts=true`. Returns server name, ID, member count, channel info.
- **Bot enumeration**: if you find a bot token (catalog §17 row 47), use `getMe` to get bot identity + servers it's joined to (read-only check).

### 43.3 Telegram

Already covered in §38. Quick reference:
- TGStat — channel analytics + search.
- Telemetr — channel growth + overlaps.
- Combot — group analytics.
- View public channels: `https://t.me/s/<channel>`.
- Invite link enum: search Google `site:t.me "{target}"`.

### 43.4 Microsoft Teams (federation)

- See companion methodology skill §11.10.
- Federation status check via Microsoft Graph (auth-required).
- Open-federation default = anyone can chat target's users with `<email>@<target>` lookup.

### 43.5 Mattermost / Rocket.Chat / self-hosted

- `https://mattermost.<target>.com` or `chat.<target>` patterns.
- Open registration check: probe `/signup` page; if accessible without invite → anyone joins.
- Check version disclosure (`/api/v4/system/ping`) for known CVEs.

---

## 44. Package Registry Leak Hunting

Public package registries (npm, PyPI, RubyGems, Docker Hub, etc.) often contain inadvertent secrets in published packages.

### 44.1 npm

- **Search packages by org / scope:**
  ```bash
  npm search "<target-keyword>"
  npm view @<scope>/<package-name>
  ```
- **List org's packages:** `https://www.npmjs.com/org/<org>` or `https://registry.npmjs.org/-/org/<org>/package`.
- **Per-package historical versions:** `https://registry.npmjs.org/<package>` — JSON with all versions.
- **Tarball download for scan:**
  ```bash
  npm pack <package>@<version>
  tar -xzf package-version.tgz
  # Run secret catalog (§17) on extracted files
  ```
- **Common leaks:** `.env` files included in published tarball, `package.json` `scripts` references to internal CI secrets, hardcoded API keys in `dist/` builds.

### 44.2 PyPI

- **Search packages:** `https://pypi.org/search/?q=<target>`.
- **Per-package metadata + history:** `https://pypi.org/pypi/<package>/json`.
- **Download wheel/sdist for scan:**
  ```bash
  pip download <package>==<version> --no-deps -d /tmp/pkg
  unzip /tmp/pkg/*.whl -d /tmp/pkg/extracted
  # Run secret catalog
  ```
- **Common leaks:** `setup.py` with hardcoded URLs, embedded test fixtures with real credentials, accidentally-included `.pypirc` files.

### 44.3 RubyGems

- **Search:** `https://rubygems.org/search?query=<target>`.
- **Per-gem metadata:** `https://rubygems.org/api/v1/gems/<gem-name>.json`.
- **Download:**
  ```bash
  gem fetch <gem-name>
  gem unpack <gem-name>-<version>.gem
  ```

### 44.4 Cargo (Rust crates)

- **Search:** `https://crates.io/search?q=<target>`.
- **Per-crate metadata:** `https://crates.io/api/v1/crates/<crate-name>`.

### 44.5 Packagist (PHP / Composer)

- **Search:** `https://packagist.org/search/?q=<target>`.
- **Per-package metadata:** `https://packagist.org/packages/<vendor>/<package>.json`.

### 44.6 NuGet (.NET)

- **Search:** `https://www.nuget.org/packages?q=<target>`.

### 44.7 Maven Central (Java)

- **Search:** `https://search.maven.org/?q=<target>`.

### 44.8 Docker Hub / Quay / GHCR / ECR Public

Already covered in §16.18; worth noting for completeness as part of registry-sweep workflow.

### 44.9 Workflow

For each registry, for each candidate package owned-by-target:
1. List all historical versions (often `<package>@1.0.0` was clean but `<package>@0.9.0` had a leaked key).
2. Download each version's archive.
3. Extract; run secret catalog (§17) over all files.
4. Note `.env`, `package.json`/`setup.py`/`Cargo.toml` for hardcoded values.
5. For Docker images: scan each layer (use `dive` or `skopeo` + `docker save` + extract layers).

### 44.10 Typosquat surveillance

For every published package the target owns, generate typosquat candidates (similar names, common substitutions) and check whether they're already taken by attackers (supply-chain attack surface).

```bash
# Example: target package "acme-utils"
# Candidates: acme-util, acmeutils, acme_utils, acme.utils, ac-me-utils, etc.
for candidate in acme-util acmeutils acme_utils acme.utils ac-me-utils; do
  npm view $candidate 2>&1 | head -3
done
```

If a candidate is registered to a non-target party → MEDIUM finding (typosquat, possible supply-chain attack vector).

---

## 45. Sat Imagery for Physical Recon

For engagements that include a physical-touch component (badge access, tailgating, dumpster diving, on-site network), public imagery helps scout the target.

### 45.1 Sat imagery sources

| Source | URL | Notes |
|---|---|---|
| **Google Earth Pro** | desktop app | Historical timeline; high resolution (sub-meter) for major cities. |
| **Google Maps** | maps.google.com | Current; satellite layer; street view inside building lobbies sometimes. |
| **Bing Maps Bird's Eye** | bing.com/maps | Oblique/45-degree imagery for many regions; sometimes shows building facades better than top-down. |
| **Apple Maps Look Around** | (iOS / Mac) | Street-level; 3D in major cities. |
| **Yandex Maps Panorama** | yandex.com/maps | Russia + global; sometimes higher-resolution street-level than Google. |
| **NearMap** (paid) | nearmap.com | Highest-resolution commercial; updated frequently in served regions (US/AU/NZ/CA mostly). |
| **Maxar / Planet Labs** (paid) | maxar.com / planet.com | Tasking + recent imagery. |
| **Sentinel Hub EO Browser** | apps.sentinel-hub.com | Free Sentinel-2 (10m); good for change detection. |
| **NASA Worldview** | worldview.earthdata.nasa.gov | Free; multiple sensors. |
| **Wayback ArcGIS** | livingatlas.arcgis.com/wayback/ | Historical satellite. |
| **OpenStreetMap** | openstreetmap.org | Crowd-sourced map data with building outlines. |

### 45.2 What to extract for physical recon

- **Building entrance count + locations** — main entrance, employee entrances, loading docks, fire exits.
- **Parking lot ingress / egress** — single guarded entry vs open lot.
- **Fence lines + camera locations** — physical perimeter.
- **HVAC / utility access** — roof access, service entries.
- **Adjacent occupants** — neighboring tenants in same building / business park.
- **Vehicle types in lot** — proxy for executive presence + employee count.
- **Smoking area locations** — common social-engineering staging area.

### 45.3 OSINT-derived physical intel beyond satellites

- **LinkedIn employee photos** — badge templates often visible in profile photos taken at the office.
- **Glassdoor "office tour" photos** — employees post interior photos.
- **Indeed / Glassdoor reviews** — sometimes describe security culture ("loose badge enforcement", "tailgating common").
- **Instagram geotagged photos** — at the office address; reveals interior layout, badge designs, kitchen / common-area locations.
- **Public press releases** — often contain "ribbon cutting" photos of new offices showing layout + executive faces.
- **Conference talks by IT/security staff** — sometimes describe physical security setup.
- **Meetup / workshop event listings** — at the target's office; may include photos.

### 45.4 Vehicle / fleet intel

- **License plates** in LinkedIn/Instagram backgrounds — sometimes correlates to specific exec.
- **Company-branded vehicles** in sat imagery — fleet count + location.
- **Helicopter pad** / **executive parking** — clue to senior-leadership routine.

### 45.5 Discipline

- Document that imagery + photos are public-source.
- Don't trespass for "verification" — physical recon during OSINT phase = look only.
- Note imagery date — buildings change.

---

## 46. Tooling Quick-Install

One-liner installs for the most-used external recon tools. All assume Linux/Mac with go/python/git installed.

### 46.1 Subdomain enumeration

```bash
# Subfinder (passive, fast)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass (thorough, slow)
go install github.com/owasp-amass/amass/v4/...@master

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# DNSx (resolution + brute)
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Puredns (brute-force with wildcard handling)
go install github.com/d3mondev/puredns/v2@latest
```

### 46.2 HTTP probing & enrichment

```bash
# httpx (tech-detect, status, JARM, favicon)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Gowitness (screenshots)
go install github.com/sensepost/gowitness@latest

# Aquatone (screenshots + clustering)
go install github.com/michenriksen/aquatone@latest
```

### 46.3 Vulnerability scanning

```bash
# Nuclei (template scanner)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -ut    # update templates

# Naabu (port scan)
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Masscan (fast port scan; requires sudo)
git clone https://github.com/robertdavidgraham/masscan && cd masscan && make
```

### 46.4 Content discovery

```bash
# Ffuf (fuzzer / dirbuster)
go install github.com/ffuf/ffuf/v2@latest

# Gobuster
go install github.com/OJ/gobuster/v3@latest

# Feroxbuster (recursive content disco)
cargo install feroxbuster
```

### 46.5 JS / endpoint extraction

```bash
# Katana (crawler)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# GoSpider
go install github.com/jaeles-project/gospider@latest

# LinkFinder (JS endpoint regex)
git clone https://github.com/GerbenJavado/LinkFinder && cd LinkFinder && pip install -r requirements.txt

# Subjs (extract JS URLs from HTML)
go install github.com/lc/subjs@latest
```

### 46.6 Wayback / archive

```bash
# gau (get all urls from Wayback + others)
go install github.com/lc/gau/v2/cmd/gau@latest

# Waybackurls
go install github.com/tomnomnom/waybackurls@latest
```

### 46.7 Cloud / AWS

```bash
# AWS CLI
pip install awscli
# or: brew install awscli

# Cloud_enum (S3/Azure/GCP enum)
git clone https://github.com/initstring/cloud_enum && cd cloud_enum && pip install -r requirements.txt

# S3Scanner
pip install s3scanner

# CloudSploit
git clone https://github.com/aquasecurity/cloudsploit && cd cloudsploit && npm install
```

### 46.8 Identity / SSO

```bash
# o365creeper / o365enum
git clone https://github.com/gremwell/o365enum

# CredMaster (per-protocol auth probe)
git clone https://github.com/knavesec/CredMaster
```

### 46.9 Mobile

```bash
# google-play-scraper (Python)
pip install google-play-scraper

# androguard (APK static analysis)
pip install androguard
# or: brew install androguard

# apkleaks (secret scan in APK)
pip install apkleaks
```

### 46.10 TLS / cert

```bash
# sslyze
pip install sslyze

# testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git

# JARM
pip install pyjarm

# Cert-spotter / certgraph
go install github.com/lanrat/certgraph@latest
```

### 46.11 Misc utilities

```bash
# Anew (line-dedup that streams)
go install github.com/tomnomnom/anew@latest

# Gf (regex-based grep templates)
go install github.com/tomnomnom/gf@latest

# Hakrawler (web crawler)
go install github.com/hakluke/hakrawler@latest

# Trufflehog (secret scanner)
go install github.com/trufflesecurity/trufflehog@latest

# Gitleaks
go install github.com/zricethezav/gitleaks/v8@latest

# jq (JSON parsing)
sudo apt install jq    # or brew install jq
```

### 46.12 Frameworks / orchestration

```bash
# ProjectDiscovery's "PDTM" (manages the full PD toolkit)
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -install-all

# reconftw (scripted recon framework)
git clone https://github.com/six2dez/reconftw && cd reconftw && ./install.sh

# Axiom (distributed recon on cloud nodes)
git clone https://github.com/pry0cc/axiom && cd axiom && ./interact/axiom-configure
```

---

## 47. Sector-Specific Recon Notes

Most recon generalizes; some sectors have unique attack-surface elements worth flagging.

### 47.1 Healthcare

- **DICOM** (medical imaging) — port 11112, sometimes 4242 (testing).
- **HL7 v2** (clinical messaging) — port 2575 (TCP, often plaintext).
- **HL7 FHIR** (modern REST API) — typically `/fhir/R4/<resource>` paths; OAuth / SMART-on-FHIR auth posture varies wildly.
- **PACS / RIS / EHR systems** — Epic (`*.epic.com` SaaS), Cerner/Oracle Health, Allscripts/Veradigm, Athenahealth, NextGen, Meditech, eClinicalWorks. Each has known CVE history.
- **Searches:** `site:{domain} ("EHR" OR "PACS" OR "PHI" OR "HIPAA")`, `intitle:"Epic Systems" "{target}"`.
- **Severity escalation:** any PHI exposure → CRITICAL (regulatory + reputational); HL7/DICOM open without auth → CRITICAL.

### 47.2 Finance

- **SWIFT terminals** — typically internal-only; if external-facing, CRITICAL. Look for SWIFT Alliance Web Platform.
- **FIX protocol** (electronic trading) — port 9876 (common); cleartext.
- **Bloomberg terminals** — typically VDI; check for `bloomberg.com`-related auth surfaces.
- **Trading platform vendors** — Fidessa, Charles River, Eze Software, Aladdin (BlackRock).
- **Banking middleware** — Temenos T24, Finacle (Infosys), FIS, Jack Henry, Fiserv. Each has known CVE history.
- **Searches:** `site:{domain} ("PCI" OR "SOX" OR "GLBA" OR "MAS")`, `intitle:"Temenos" "{target}"`.
- **Severity escalation:** any account/balance data exposure → CRITICAL; SWIFT exposure → CRITICAL; trade-execution surface exposure → CRITICAL.

### 47.3 ICS / SCADA / OT

> **Caution:** ICS/SCADA assets often run on legacy systems where even passive scanning can cause disruption. **Do not actively probe ICS without explicit RoE coverage and operator coordination with the OT team.**

- **Modbus** — port 502 (TCP).
- **BACnet** — port 47808 (UDP).
- **Siemens S7** — port 102 (ISO-TSAP).
- **DNP3** — port 20000 (TCP).
- **EtherNet/IP** — port 44818 (TCP).
- **Niagara Framework** — port 1911, 4911, 5011, 502.
- **Honeywell EBI / Tridium** — varies.
- **GE Proficy / iFIX** — varies.
- **Common findings:** unauthenticated read access (BACnet point list, Modbus register read), default credentials on HMI panels, public-facing engineering workstations.
- **Sources:** Shodan ICS-specific filters (`port:502`, `tag:ics`), Censys, Onyphe.
- **Detectability:** medium-to-high; ICS networks often have low background traffic and are heavily monitored.

### 47.4 IoT / Consumer / SOHO

- **MQTT** — port 1883 (cleartext), 8883 (TLS). Topics often readable without auth.
- **CoAP** — port 5683 (UDP).
- **UPnP / SSDP** — port 1900 (UDP); often discloses internal device map.
- **Common router admin patterns:** `/cgi-bin/`, `/setup.cgi`, `/admin/index.html`. Default creds are the norm.
- **Camera DVRs / NVRs** — Hikvision, Dahua, Axis. Multiple CVEs.
- **Smart-home hubs** — exposed APIs sometimes leak auth tokens.

### 47.5 Government

- **`.gov` and `.mil` domains** require special engagement-scope discipline.
- **FedRAMP / FISMA / DoD CMMC** — defensive posture is generally above baseline.
- **OSINT data sources:** USAspending.gov, SAM.gov (System for Award Management), FBO.gov / sam.gov (procurement).
- **Common findings:** vendor of record disclosed in public contracts → adjacent-vendor pivot.
- **Severity:** as high or higher than commercial; political sensitivity layered on top of technical impact.

### 47.6 Maritime / Aviation / Auto

- **Maritime:** AIS (Automatic Identification System) — vessel positions; tools MarineTraffic, VesselFinder. Engine telemetry sometimes exposed via VSAT.
- **Aviation:** ADS-B (already covered §32.3); operator/airline-specific OPS data sometimes exposed.
- **Automotive:** OEM telematics backends (Tesla, GM OnStar, etc.) — typically authenticated, but APIs leak via mobile-app reverse engineering.

### 47.7 Universal sector caveat

**Most external recon techniques apply universally.** Sector-specific protocols add attack surface; sector-specific compliance regimes add reporting requirements. Don't assume "healthcare/finance/etc. has different OSINT" — the OSINT is the same; the targeted services differ.

---

## 48. Runnable Helper — `secret_scan.py`

Drop-in Python helper that mirrors the 29-pattern catalog from §17. Pure stdlib, no dependencies. For operator use against captured text.

```python
#!/usr/bin/env python3
"""Stdlib-only secret scanner. Mirrors the 29-pattern catalog.

Usage:
  echo "AKIAIOSFODNN7EXAMPLE" | python3 secret_scan.py
  python3 secret_scan.py file1.txt file2.js dir/

Output: one JSON object per line: {pattern, severity, category, match, file, line}
"""
import json
import os
import re
import sys

SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"

PATTERNS = [
    ("AWS_ACCESS_KEY",       SEV_CRITICAL, "aws",         r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS_SECRET_TYPED",     SEV_CRITICAL, "aws",         r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})"),
    ("AWS_SECRET_LOOSE",     SEV_HIGH,     "aws",         r"(?i)aws(.{0,20})?(secret|sk)[\"'=: ]+([0-9a-z/+=]{40})"),
    ("GCP_SERVICE_ACCOUNT",  SEV_CRITICAL, "gcp",         r'"type"\s*:\s*"service_account"'),
    ("GOOGLE_API_KEY",       SEV_HIGH,     "gcp",         r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("GH_PAT_CLASSIC",       SEV_CRITICAL, "github",      r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GH_PAT_FINEGRAINED",   SEV_CRITICAL, "github",      r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("GH_OAUTH",             SEV_HIGH,     "github",      r"\bgho_[A-Za-z0-9]{36}\b"),
    ("GH_S2S",               SEV_HIGH,     "github",      r"\bgh[usr]_[A-Za-z0-9]{36,}\b"),
    ("STRIPE_LIVE",          SEV_CRITICAL, "stripe",      r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("STRIPE_TEST",          SEV_LOW,      "stripe",      r"\bsk_test_[0-9A-Za-z]{24,}\b"),
    ("SLACK_TOKEN",          SEV_HIGH,     "slack",       r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b"),
    ("SLACK_WEBHOOK",        SEV_MEDIUM,   "slack",       r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("SENDGRID",             SEV_HIGH,     "email_svc",   r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("MAILGUN_V1",           SEV_HIGH,     "email_svc",   r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("MAILGUN_LOOSE",        SEV_HIGH,     "email_svc",   r"\bkey-[0-9a-f]{32}\b"),
    ("TWILIO_API",           SEV_HIGH,     "twilio",      r"\bSK[0-9a-fA-F]{32}\b"),
    ("TWILIO_SID",           SEV_MEDIUM,   "twilio",      r"\bAC[a-f0-9]{32}\b"),
    ("TWILIO_AUTH",          SEV_HIGH,     "twilio",      r"(?i)twilio(.{0,20})?(auth|token)[\"'=: ]+([a-f0-9]{32})"),
    ("HEROKU_API",           SEV_MEDIUM,   "paas",        r"(?i)heroku(.{0,20})?api[\"'=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
    ("FIREBASE_URL",         SEV_LOW,      "firebase",    r"\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b"),
    ("JWT",                  SEV_MEDIUM,   "jwt",         r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("BEARER_AUTH",          SEV_MEDIUM,   "bearer",      r"(?i)authorization[\"'=: ]+bearer\s+[A-Za-z0-9._\-]{20,}"),
    ("BASIC_AUTH_URL",       SEV_MEDIUM,   "basic_auth",  r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("RSA_PRIVKEY",          SEV_CRITICAL, "private_key", r"-----BEGIN RSA PRIVATE KEY-----"),
    ("EC_PRIVKEY",           SEV_CRITICAL, "private_key", r"-----BEGIN EC PRIVATE KEY-----"),
    ("OPENSSH_PRIVKEY",      SEV_CRITICAL, "private_key", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("GENERIC_PRIVKEY",      SEV_CRITICAL, "private_key", r"-----BEGIN (DSA |PGP |)PRIVATE KEY-----"),
    ("GENERIC_API_KEY",      SEV_MEDIUM,   "generic",     r"(?i)(?:api[_\-]?key|apikey|api_secret|access_token|secret[_\-]?token)['\"\s:=]+[\"']([A-Za-z0-9+/=_\-]{24,})[\"']"),
]

COMPILED = [(n, s, c, re.compile(p)) for (n, s, c, p) in PATTERNS]

def scan_text(text: str, source: str = "<stdin>"):
    for line_no, line in enumerate(text.splitlines(), start=1):
        for name, sev, cat, rx in COMPILED:
            for m in rx.finditer(line):
                yield {
                    "pattern": name,
                    "severity": sev,
                    "category": cat,
                    "match": m.group(0)[:80],   # truncate to avoid huge dumps
                    "source": source,
                    "line": line_no,
                }

def scan_path(path: str):
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                p = os.path.join(root, f)
                yield from scan_path(p)
        return
    try:
        with open(path, "r", errors="replace") as fh:
            yield from scan_text(fh.read(), source=path)
    except Exception:
        return

def main():
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            for hit in scan_path(arg):
                print(json.dumps(hit))
    else:
        data = sys.stdin.read()
        for hit in scan_text(data):
            print(json.dumps(hit))

if __name__ == "__main__":
    main()
```

Save as `secret_scan.py`, then:
```bash
python3 secret_scan.py path/to/repo/        # scan a directory tree
python3 secret_scan.py file1 file2 file3    # scan specific files
cat my.log | python3 secret_scan.py         # pipe stdin
```

Output is JSONL — one finding per line — drops cleanly into `jq` for filtering or directly into a finding store.

---

## 49. Skill Self-Test

Drop these prompts into a fresh Claude session to verify the skill loads correctly.

1. *"What paths should I probe to find Swagger or OpenAPI specs on a webapp?"* → §16.1.
2. *"Give me the GraphQL introspection query I should POST."* → §16.2.
3. *"What are the high-risk ports to flag from a Shodan scan?"* → §16.3.
4. *"Show me the secret regex catalog."* → §17 (48 patterns) + §48 (runnable Python).
5. *"How do I score an API endpoint by attack interest?"* → §20.
6. *"Validate a leaked Postman API key — what URL?"* → §23.1.
7. *"Give me dorks for pastebin/gist/ghostbin leaks for a target."* → §18.3.
8. *"What endpoints fingerprint a Microsoft Entra tenant?"* → §22.1 + §22.8 for M365 deep.
9. *"How do I score whether a discovered Android app belongs to my target?"* → §21.
10. *"What attack-path hint when I find unauth POST on `/api/users`?"* → §39 (first row).
11. *"Curl one-liner to test for `/actuator/env`."* → §16.13.
12. *"Show me the GraphQL field-suggestion enumeration trick when introspection is disabled."* → §22.9.
13. *"Found a hard-coded JWT in JS. Walk me through full triage."* → §23.12 (JWT workflow).
14. *"Generate cloud bucket candidates for `Shree Cement Limited` with subdomains api/billing/hr."* → §16.8.
15. *"How do I find Microsoft 365 Teams federation status + SharePoint subdomains?"* → §22.8.
16. *"Probe paths for Citrix Netscaler / F5 BIG-IP / Pulse Secure."* → §16.16.
17. *"Find the origin behind Cloudflare on `target.example`."* → §16.15 + companion methodology §27.
18. *"What ports/paths probe for Kubernetes/etcd/kubelet exposure?"* → §16.18.
19. *"Audit `acme.com`'s SPF/DMARC for spoof feasibility."* → §16.14.
20. *"List wordlist sources for subdomain bruteforce + content discovery."* → §27.1.
21. *"Run reverse-DNS sweep across a /22 the target owns."* → §28.5.
22. *"Validate an OpenAI API key without burning quota."* → §23.6 + §23.12.
23. *"Find leaked secrets across npm/PyPI/Docker Hub for the target."* → §44.
24. *"How do I enumerate target employees on LinkedIn for a phishing list?"* → §41.
25. *"What's a Slack invite link enumeration technique?"* → §43.1.
26. *"What's the EPSS score and KEV status for CVE-2024-3400?"* → §29.2.
27. *"What modern AI API keys (Anthropic / OpenAI / HuggingFace / Cloudflare) match catalog patterns?"* → §17 rows 30–48.
28. *"Severity matrix for `android:debuggable=true` on prod app?"* → §40.
29. *"Install commands for the standard recon toolkit (subfinder/httpx/nuclei/etc.)?"* → §46.
30. *"For a healthcare engagement, what additional ports / protocols matter?"* → §47.1.
31. *"Pull HudsonRock breach corpus for `target.com` via direct API (no UI)."* → §15.0.1.
32. *"Run the full §16.14 email security audit from a Windows box (PowerShell)."* → §16.14 PowerShell parallel.
33. *"crt.sh just 502'd. What's the fallback chain?"* → §27.0.1.
34. *"Bulk IP → ASN lookup for 200 IPs without burning bgpview rate limit."* → §28.1 (Cymru bulk).
35. *"Common-prefix subdomain sweep for `target.example` covering vpn / api / staging / portal / intranet."* → §16.24.
36. *"Legacy mail (`mail.<domain>`) is NXDOMAIN today but breach corpus has employee URLs against it. What's the finding?"* → §15.2 legacy-mail-decommissioned pattern.
37. *"Confirm M365 tenancy when MX is wrapped by Mimecast (so MX doesn't reveal underlying mail platform)."* → §22.1 autodiscover IP correlation + §16.22 autodiscover-as-confirmation.
38. *"DMARC RUA points to `kdmarc.com` — what does that tell me?"* → §16.14 DMARC reporting-vendor table.
39. *"SharePoint HEAD probe returns HTTP 200. Does that mean anonymous access is granted?"* → §22.8 (no — tenant exists, not anonymous access; distinguish).
40. *"Wayback `*.js` query returned empty for a brochure-ware site. Pivot?"* → §16.23 legacy-app pivot (.asp / .php / .jsp / .cfm / .aspx).

---

## 50. Changelog

- **v2.1.1 (2026-04-27)** — battle-test gap fixes from real-engagement smoke run. Added: §15.0.1 HudsonRock Cavalier direct-API recipe (curl + PowerShell, full JSON shape, free-tier redaction caveats, rate-limit guidance). §15.2 expanded with legacy-mail-decommissioned escalation pattern (NXDOMAIN legacy mail + breach corpus + autodiscover-confirmed cloud migration → CRITICAL SSO_EXPOSURE). §16.14 expanded with DMARC reporting-vendor table (Kratikal kdmarc / dmarcian / Valimail / Agari / EasyDMARC / DMARC Analyzer / Postmark) + full Windows/PowerShell parallel for the entire email security audit + caveat that PS 5.1 `Resolve-DnsName -Type CAA` errors (use PS 7+ or `nslookup -type=CAA`). §16.22 expanded TXT verification token catalog with 17 new tokens (zscaler-verification, cloudflare-verify, autosect, cisco-site-verification, mscid, _amazonses, salesforce-domain-verification, workday/shopify/klaviyo/mailchimp/hubspot/zendesk/freshworks/intercom/loom/miro/gitlab) + new "Autodiscover-as-confirmation" pattern for M365 detection when MX is wrapped by Mimecast/Proofpoint/Barracuda. §22.1 added passive Autodiscover IP correlation pattern with Microsoft Exchange Online IP ranges. §22.8 added clarification: SharePoint HEAD HTTP 200 = tenant exists, NOT anonymous access granted (operators commonly misread). New §16.23 legacy-app pivot block (when Wayback `*.js` returns empty for brochure-ware sites, pivot to .asp/.php/.jsp/.cfm/.aspx/.json/.xml/.yml/.ini/.conf — with full broad-sweep one-liner). New §16.24 Common-Prefix Subdomain Sweep — formalized active prefix-probe technique with 100+ ordered prefix list, PowerShell + bash + puredns recipes, and real-engagement validation note (passive enum misses 20-40% of high-value subdomains; always pair with active prefix probe). §27.0.1 added crt.sh fallback chain (Censys, CertSpotter, Calidog, Subfinder, OTX, ThreatMiner, URLScan, Anubis-DB) with PowerShell wrapper that retries crt.sh 3× then falls back to Subfinder. §28.1 added Bulk IP→ASN recipes (Cymru bulk WHOIS, RIPEstat, bgp.tools, IPinfo Lite) + caveat that bgpview.io API has aggressive rate limits unsuitable for bulk. §40 severity matrix gained 8 rows: vendor procurement portal exposed + breach corpus hits (HIGH), PII-collection portal over plain HTTP (HIGH), decommissioned legacy mail + breach + cloud migration (CRITICAL), public-facing intranet without VPN (MEDIUM), staging/preprod publicly resolvable (MEDIUM), vpn.<domain> resolves but vendor unknown (INFO escalating to HIGH-CRITICAL on KEV match), DMARC RUA → third-party vendor (INFO). §49 self-test expanded from 30 → 40 prompts targeting all new content.
- **v2.1 (2026-04-27)** — comprehensive expansion based on 32-test smoke-test gap analysis. Added: copy-paste curl probes for every check (§16.13), email security analysis with SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC parsing + SaaS tenant inference (§16.14), origin discovery / CDN bypass via DNS history + cert SAN + favicon hash + JARM + Host-header probe (§16.15), vendor product fingerprints for Citrix/F5/Pulse/Fortinet/PaloAlto/Cisco/VMware/Exchange + KEV CVE associations (§16.16), cloud-native service URL fingerprints — Lambda Function URLs, Cloud Run, Cloud Functions, Azure Functions, Vercel, Netlify, Cloudflare Workers, etc. (§16.17), container & Kubernetes exposure (kubelet, etcd, K8s API, dashboard, Helm Tiller, container registries) (§16.18), CI/CD platform exposure (Jenkins deeper, GitLab, GitHub Actions, CircleCI, TeamCity, Argo CD, Spinnaker) (§16.19), documentation/wiki leak paths (Notion, Confluence, Trello, Miro, Lucidchart, Figma, ReadTheDocs, GitBook, Slab, Coda, etc.) (§16.20), WHOIS/RDAP/historical-WHOIS recipes + reverse-WHOIS pivots (§16.21), DNS record catalog with TXT verification token table → SaaS tenant inference (§16.22), Wayback CDX deep usage with all filter parameters (§16.23). Expanded: §17 secret catalog from 29 → 48 patterns adding modern AI API keys (Anthropic, OpenAI legacy + project, HuggingFace), infra (Cloudflare, DigitalOcean), package registries (npm, PyPI, Docker Hub), SaaS (Atlassian, Linear), observability (New Relic, DataDog, Sentry DSN), bot tokens (Discord, Telegram), and ngrok. Expanded §18 dork corpus from 50+ → 80+ with internal-tool exposure (Splunk/Grafana/Kibana/Argo CD/Sonarqube/Confluence/Jira/GitLab/Gitea), backup-file extensions, and sector-specific dorks (healthcare/finance/gov). Added §22.8 Microsoft 365 deep enumeration (Teams federation, SharePoint subdomain probe, OneDrive personal-site probe, OAuth client_id discovery, device-code phishing target check, Power Platform). Added §22.9 GraphQL field-suggestion enumeration recipe + alias batching, query-depth bypass, subscription enumeration, batched-query bypass. Added §23.5–23.9 read-only validators for Anthropic, OpenAI, npm, Atlassian, DataDog (5 new). Added §23.12 post-discovery enumeration workflows (AWS IAM enum, GitHub PAT scope/repo enum, Slack workspace enum, JWT full triage with algorithm-confusion + brute-force + none-bypass, Postman PMAK workspace enum, Anthropic + OpenAI usage enum, generic key provenance enum). Pinned §24 Postman search endpoint with verified shape + DevTools fallback recipe. Added §27.1 wordlist sources (Assetnote, SecLists, jhaddix, OneListForAll, raft-large-words, fuzzdb, etc.) + size guidance. Added §28.4 TLS deep audit (sslyze + testssl.sh + nmap + JA3/JA4 + cipher/protocol/cert checks). Added §28.5 reverse DNS sweep + IPv6 enumeration + BGP route observation. Added §29.2 vulnerability prioritization data sources (NVD/EPSS/CISA KEV/ExploitDB/Metasploit/InTheWild/OpenCVE/Trickest CVE+POC mapping/OSV.dev/VulnCheck KEV) + bulk prioritization workflow. Expanded §39 attack-path hints with 15 more templates (open kubelet/etcd, K8s API anonymous, Citrix/F5/vCenter/Cloud Function unauth, npm typosquat, DMARC missing, live AI keys, Slack invite, sourcemap with sourcesContent). Expanded §40 severity matrix with 30 more worked examples covering Kubernetes/container, vendor products with KEV CVEs, M365/cloud-native, CI/CD misconfig, documentation leaks, email-security gaps, AI/package-registry credentials, TLS issues. Added §41 LinkedIn employee enumeration tradecraft (search techniques + role inference + email-pattern derivation + sock-puppet considerations). Added §42 job posting tech-stack analysis (sources + extraction + tooling). Added §43 Slack/Discord/Telegram/Mattermost workspace discovery. Added §44 package registry leak hunting (npm/PyPI/RubyGems/Cargo/Packagist/NuGet/Maven Central + workflow + typosquat surveillance). Added §45 sat imagery for physical recon (sources + extraction + LinkedIn/Glassdoor/Instagram/conference intel + vehicle/fleet intel). Added §46 tooling quick-install (subdomain, HTTP probing, vuln scanning, content discovery, JS extraction, Wayback, cloud, identity, mobile, TLS, utilities, frameworks). Added §47 sector-specific recon notes (healthcare DICOM/HL7/FHIR/EHR + finance SWIFT/FIX/Bloomberg/banking middleware + ICS-SCADA Modbus/BACnet/S7/DNP3 + IoT MQTT/CoAP/UPnP + government FedRAMP/FISMA + maritime/aviation/auto). Renumbered Runnable Helper → §48, Self-Test → §49 (refreshed for v2.1), Changelog → §50.
- **v2.0 (2026-04-27)** — major rewrite for external red-team posture. Added: pre-built wordlists (§16), 29-pattern secret catalog (§17), 50+ dork corpus (§18), GitHub code-search dorks (§19), endpoint interest score (§20), mobile ownership confidence (§21), identity-fabric concrete endpoints (§22), read-only secret validators (§23), Postman workspace search (§24), Stack Exchange sweep (§25), public SaaS dorks (§26), subdomain-source stack (§27), domain-level breach severity (§15.1), L2 explorer table (§30.2), USCC + ICP workflow (§14.2), cross-module sidecar coordination (§36), attack-path hint patterns (§39), severity decision matrix (§40), runnable secret-scan helper (§41). Strengthened: confidence levels (§2), output format (§3), do-not rules (§5). Original tool tables retained and lightly reorganized.
- **v1.x** — original tool-reference cheat sheet.

---
