---
name: offsec-reference
description: "Comprehensive offensive security reference. Match user intent to the skill map below, then load the relevant reference file for detailed methodology."
allowed-tools: Read Grep
---

# Offensive Security Reference

Match the user's intent against **Triggers** below. Load the file from `references/` only when needed. Load the most specific match first.

| File | Triggers |
|------|----------|
| `bug-bounty.md` | bug bounty, recon, subdomain enumeration, asset discovery, HackerOne, vulnerability hunting, A-to-B chaining |
| `gabut-exitium.md` | hunting methodology, workflow, mindset, session planning, target selection, critical thinking |
| `offensive-advanced-redteam.md` | red team, C2, command and control, redirectors, beacon, data exfiltration, covert channel |
| `offensive-ai-security.md` | AI security, LLM attacks, prompt injection, chatbot exploitation, system prompt extraction |
| `offensive-basic-exploitation.md` | buffer overflow, stack overflow, basic exploitation, Linux exploitation, shellcode injection, NOP sled |
| `offensive-bug-identification.md` | kernel bugs, driver analysis, eBPF, dynamic analysis, bug classes, root cause analysis |
| `offensive-cms-wordpress-vercel.md` | WordPress, Vercel, Next.js, CMS, wp-admin, plugin vulnerabilities, wp-json, xmlrpc |
| `offensive-crash-analysis/` | crash analysis, exploitability assessment, triage, ASAN, debugger, memory corruption |
| `offensive-deserialization.md` | deserialization, Java deserialization, PHP unserialize, Python pickle, gadget chains, ysoserial |
| `offensive-edr-evasion.md` | EDR, endpoint detection, evasion, antivirus bypass, unhooking, syscalls, AMSI bypass, ETW patching |
| `offensive-exploit-dev-course.md` | exploit development course, fuzzing lab, harness writing, vulnerability research training |
| `offensive-exploit-development.md` | heap exploitation, use-after-free, browser exploitation, heap spray, type confusion, V8 |
| `offensive-fast-checking.md` | quick security check, fast audit, security checklist, rapid assessment, low-hanging fruit |
| `offensive-file-upload.md` | file upload, upload bypass, webshell, content-type bypass, extension bypass, polyglot file |
| `offensive-fuzzing-course.md` | fuzzing course, AFL++ setup, coverage-guided fuzzing, fuzzing infrastructure |
| `offensive-fuzzing.md` | fuzzing, AFL++, libFuzzer, Honggfuzz, Boofuzz, syzkaller, greybox fuzzing, harness |
| `offensive-graphql.md` | GraphQL, introspection, batching attack, query complexity, nested queries, schema extraction |
| `offensive-idor.md` | IDOR, insecure direct object reference, access control, horizontal privilege escalation, parameter tampering |
| `offensive-initial-access.md` | initial access, phishing, payload delivery, macro, HTA, ISO, LNK, DLL sideloading, MOTW bypass |
| `offensive-jwt.md` | JWT, JSON Web Token, algorithm confusion, alg none, RS256 to HS256, kid injection, token forgery |
| `offensive-keylogger-arch.md` | keylogger, SetWindowsHookEx, keyboard capture, input monitoring |
| `offensive-mitigations.md` | kernel mitigations, KASLR, KPTI, SMEP, SMAP, CFI, exploit mitigations bypass |
| `offensive-oauth.md` | OAuth, OIDC, OpenID Connect, authorization code, token theft, redirect_uri bypass |
| `offensive-open-redirect.md` | open redirect, URL redirect, redirect bypass, OAuth redirect chain |
| `offensive-osint-methodology.md` | OSINT methodology, intelligence gathering, reconnaissance framework, target profiling |
| `offensive-osint.md` | OSINT, email discovery, domain recon, social media, leaked credentials, breach data, Shodan |
| `offensive-parameter-pollution.md` | parameter pollution, HPP, duplicate parameters, server-side parsing, WAF bypass via HPP |
| `offensive-race-condition.md` | race condition, TOCTOU, concurrency, parallel requests, limit bypass, single-packet attack |
| `offensive-rce.md` | RCE, remote code execution, command injection, code injection, eval injection |
| `offensive-request-smuggling.md` | request smuggling, HTTP smuggling, CL.TE, TE.CL, HTTP desync, H2 smuggling |
| `offensive-shellcode.md` | shellcode, position-independent code, encoder, staged payload, msfvenom, custom shellcode |
| `offensive-sqli.md` | SQL injection, SQLi, union-based, blind SQLi, error-based, time-based, sqlmap |
| `offensive-ssrf.md` | SSRF, server-side request forgery, cloud metadata, IMDS, IP bypass, DNS rebinding |
| `offensive-ssti.md` | SSTI, server-side template injection, Jinja2, Twig, Freemarker, sandbox escape |
| `offensive-vuln-classes.md` | vulnerability classes, vuln taxonomy, attack patterns, comprehensive vuln list |
| `offensive-waf-bypass.md` | WAF bypass, web application firewall, filter evasion, encoding bypass, Cloudflare bypass |
| `offensive-windows-boundaries/` | Windows security boundaries, privilege escalation, kernel exploitation, Win32k, token manipulation |
| `offensive-windows-mitigations/` | Windows mitigations, DEP, ASLR, CFG, CET, ACG, Windows Defender, exploit guard |
| `offensive-xss.md` | XSS, cross-site scripting, reflected XSS, stored XSS, DOM XSS, CSP bypass |
| `offensive-xxe.md` | XXE, XML external entity, DTD, SSRF via XXE, blind XXE, parameter entities |
| `osint-methodology.md` | OSINT framework, intelligence cycle, source evaluation, pivot analysis, attribution |
| `report-writing.md` | vulnerability report, bug report, CVSS scoring, proof of concept, impact statement |
| `security-arsenal.md` | security tools, tool list, pentest tools, Burp Suite, nuclei, ffuf, nmap |
| `triage-validation.md` | triage, validation, false positive, severity assessment, exploitability confirmation |
| `web2-recon.md` | web recon, subdomain enumeration, port scanning, directory bruteforce, fingerprinting |
| `web2-vuln-classes.md` | web vulnerabilities, OWASP, injection flaws, broken authentication, security misconfiguration |
| `web3-audit.md` | smart contract, Solidity, blockchain audit, DeFi, reentrancy, flash loan, EVM |
