# Preflight Check

Run before starting any engagement. Verifies tools and installs missing ones.

## Mandatory Tools

| Tool | Phase | macOS | Linux |
|------|-------|-------|-------|
| `dig` | 1 | `brew install bind` | `apt install dnsutils` |
| `curl` | 1 | (pre-installed) | `apt install curl` |
| `whois` | 1 | (pre-installed) | `apt install whois` |
| `nmap` | 2 | `brew install nmap` | `apt install nmap` |
| `gobuster` | 3 | `brew install gobuster` | `go install github.com/OJ/gobuster/v3@latest` |
| `ffuf` | 3 | `brew install ffuf` | `go install github.com/ffuf/ffuf/v2@latest` |
| `nuclei` | 5 | `brew install nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

## Recommended Tools

| Tool | Phase | macOS | Linux |
|------|-------|-------|-------|
| `subfinder` | 1 | `brew install subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `amass` | 1 | `brew install amass` | `go install github.com/owasp-amass/amass/v4/...@master` |
| `theHarvester` | 1 | `pip3 install theHarvester` | `pip3 install theHarvester` |
| `masscan` | 2 | `brew install masscan` | `apt install masscan` |
| `feroxbuster` | 3 | `brew install feroxbuster` | `apt install feroxbuster` |
| `arjun` | 3 | `pip3 install arjun` | `pip3 install arjun` |
| `sqlmap` | 6 | `brew install sqlmap` | `apt install sqlmap` |
| `hydra` | 6 | `brew install hydra` | `apt install hydra` |

## Wordlists (SecLists)

```bash
# macOS
brew install seclists
# Linux
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

## Procedure

1. Detect platform (macOS/Linux)
2. Check mandatory tools — `which <tool>`
3. Report status table
4. Install missing mandatory tools (with user confirmation)
5. Check recommended tools — offer to install
6. Verify wordlists exist
7. Update nuclei templates — `nuclei -update-templates`
8. Write report to `./ptest-output/preflight.md`
