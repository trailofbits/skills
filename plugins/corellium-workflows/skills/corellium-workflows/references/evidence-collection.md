# Evidence Collection Reference

Procedures for collecting, exporting, and packaging analysis evidence from Corellium virtual devices. Use after the analysis phases of ios-malware-analysis or during any security research session.

## Network Capture

### Export from Web UI

1. Navigate to `Network Monitor` in the device panel
2. Click `Export` → select PCAP format
3. The capture includes all traffic since the monitor was enabled
4. Decrypted HTTPS traffic is included (Corellium's sslsplit decryption)

### Export via API

```bash
# Download full capture as PCAP
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/netmon/pcap" \
  -o "${EVIDENCE_DIR}/network_capture.pcap"
```

### Analysis with Wireshark

Open the PCAP in Wireshark for detailed protocol analysis:

```bash
# Open capture in Wireshark
wireshark "${EVIDENCE_DIR}/network_capture.pcap"

# Extract HTTP objects (files, images, JSON responses)
tshark -r "${EVIDENCE_DIR}/network_capture.pcap" \
  --export-objects "http,${EVIDENCE_DIR}/http_objects/"

# Filter to specific host
tshark -r "${EVIDENCE_DIR}/network_capture.pcap" \
  -Y "ip.addr == 192.0.2.1" \
  -w "${EVIDENCE_DIR}/filtered_c2.pcap"

# Extract DNS queries
tshark -r "${EVIDENCE_DIR}/network_capture.pcap" \
  -Y "dns.qry.name" \
  -T fields -e dns.qry.name | sort -u > "${EVIDENCE_DIR}/dns_queries.txt"

# Extract HTTP request URLs
tshark -r "${EVIDENCE_DIR}/network_capture.pcap" \
  -Y "http.request" \
  -T fields -e http.host -e http.request.uri | sort -u > "${EVIDENCE_DIR}/http_urls.txt"

# Extract TLS server names (SNI)
tshark -r "${EVIDENCE_DIR}/network_capture.pcap" \
  -Y "tls.handshake.extensions_server_name" \
  -T fields -e tls.handshake.extensions_server_name | sort -u > "${EVIDENCE_DIR}/tls_sni.txt"
```

### Quick Network IoC Extraction

```bash
# One-liner to extract unique destination IPs (excluding Apple/system ranges)
tshark -r "${EVIDENCE_DIR}/network_capture.pcap" \
  -T fields -e ip.dst | sort -u | \
  grep -v -E '^(17\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
  > "${EVIDENCE_DIR}/external_ips.txt"
```

## CoreTrace Log Analysis

### Export CoreTrace Logs

```bash
# Via API
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/coretrace/log" \
  -o "${EVIDENCE_DIR}/coretrace.log"
```

### Log Format

CoreTrace output follows this format:
```
<cpu> [timestamp.nanoseconds] threadid/pid:processname @programcounter
  syscall(arguments...) = return_value
```

Example:
```
0 [1709478234.123456789] 0x1a3/456:SuspiciousApp @0x102a3b4c5
  open("/var/mobile/Containers/Data/Application/ABC/Documents/config.dat", O_RDONLY, 0x0) = 5
0 [1709478234.234567890] 0x1a3/456:SuspiciousApp @0x102a3b4c6
  read(5, 0x16f6a0000, 4096) = 256
0 [1709478234.345678901] 0x1a3/456:SuspiciousApp @0x102a3b4c7
  close(5) = 0
```

### Filtering CoreTrace Output

```bash
# Filter to specific process
grep ":MalwareApp " "${EVIDENCE_DIR}/coretrace.log" > "${EVIDENCE_DIR}/malware_syscalls.log"

# Extract file access patterns
grep -E "^\s+open\(" "${EVIDENCE_DIR}/malware_syscalls.log" | \
  sed 's/.*open("\([^"]*\)".*/\1/' | sort -u > "${EVIDENCE_DIR}/files_accessed.txt"

# Extract network connections
grep -E "^\s+connect\(" "${EVIDENCE_DIR}/malware_syscalls.log" > "${EVIDENCE_DIR}/connections.txt"

# Find process spawning (unusual for iOS apps)
grep -E "^\s+(fork|posix_spawn|execve)\(" "${EVIDENCE_DIR}/malware_syscalls.log" > "${EVIDENCE_DIR}/process_spawn.txt"

# Detect anti-debugging
grep -E "^\s+(ptrace|sysctl)\(" "${EVIDENCE_DIR}/malware_syscalls.log" > "${EVIDENCE_DIR}/anti_debug.txt"
```

### Common Malicious Syscall Patterns

| Pattern | Interpretation | Evidence Grep |
|---------|---------------|---------------|
| Rapid `open`/`read`/`close` on AddressBook.sqlitedb | Contact harvesting | `grep "AddressBook" coretrace.log` |
| `connect` to non-Apple IPs + `write` with large buffers | Data exfiltration | `grep -A1 "connect\|write" malware_syscalls.log` |
| `stat` on `/Applications/Cydia.app` et al. | Jailbreak detection | `grep "Cydia\|substrate\|cydia" coretrace.log` |
| `ptrace(PT_DENY_ATTACH)` | Anti-debugging | `grep "ptrace" coretrace.log` |
| `open` on other app containers | Container escape attempt | `grep "/var/mobile/Containers" coretrace.log` |
| `mmap` with `PROT_EXEC` on downloaded files | Dynamic code loading | `grep "mmap.*PROT_EXEC" coretrace.log` |

## Frida Output Collection

### Structured Logging

Use `send()` instead of `console.log()` for structured output that's easier to process:

```javascript
// In Frida script — use send() for structured data
send({
  type: 'ioc',
  category: 'network',
  indicator: 'c2.example.com',
  context: 'NSURLSession dataTask',
  timestamp: new Date().toISOString()
});

// In Frida script — use console.log() for human-readable output
console.log('[C2] NSURLSession request to c2.example.com');
```

### Capturing Frida Output

```bash
# Run Frida script and capture output to file
frida -U -f com.malware.app -l analysis.js \
  --timeout 120 \
  > "${EVIDENCE_DIR}/frida_output.log" 2>&1

# For structured output, use frida-tools' -o flag
frida -U -f com.malware.app -l analysis.js \
  -o "${EVIDENCE_DIR}/frida_structured.json"
```

### Extracting IoCs from Frida Logs

```bash
# Extract domains from Frida C2 analysis output
grep -oE '\[C2:HTTP\] (GET|POST) https?://[^ ]+' "${EVIDENCE_DIR}/frida_output.log" | \
  sed 's/.*https\?:\/\/\([^\/]*\).*/\1/' | sort -u > "${EVIDENCE_DIR}/c2_domains.txt"

# Extract behavioral indicators
grep '^\[BEHAVIOR\]' "${EVIDENCE_DIR}/frida_output.log" > "${EVIDENCE_DIR}/behaviors.txt"

# Extract anti-analysis indicators
grep '^\[EVASION\|ANTI-ANALYSIS\]' "${EVIDENCE_DIR}/frida_output.log" > "${EVIDENCE_DIR}/evasion.txt"
```

## Screenshot and Screencast Capture

### Screenshots via API

```bash
# Single screenshot
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/screenshot" \
  -o "${EVIDENCE_DIR}/screenshot_$(date +%s).png"
```

### Timed Screenshot Series

```bash
# Capture screenshots every 10 seconds for 2 minutes
for i in $(seq 1 12); do
  curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
    "${CORELLIUM_API}/v1/instances/{id}/screenshot" \
    -o "${EVIDENCE_DIR}/screen_$(printf '%03d' $i).png"
  sleep 10
done
```

## Filesystem Artifact Collection

### Via File Browser API

```bash
# List files in the app's Documents directory
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/files/var/mobile/Containers/Data/Application/" | jq '.'

# Download specific artifacts
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/files/var/mobile/Containers/Data/Application/{app-uuid}/Documents/config.plist" \
  -o "${EVIDENCE_DIR}/config.plist"
```

### Common Artifact Locations

| Location | Contents |
|----------|----------|
| `/var/mobile/Containers/Data/Application/{uuid}/Documents/` | App documents (config, databases, cached data) |
| `/var/mobile/Containers/Data/Application/{uuid}/Library/Preferences/` | NSUserDefaults plist files |
| `/var/mobile/Containers/Data/Application/{uuid}/Library/Caches/` | Cached network responses, images |
| `/var/mobile/Containers/Data/Application/{uuid}/tmp/` | Temporary files (dropped payloads) |
| `/var/mobile/Library/AddressBook/` | Contacts database |
| `/var/mobile/Library/Calendar/` | Calendar database |
| `/var/mobile/Library/SMS/` | Message database |
| `/private/var/log/` | System logs |
| `/var/mobile/Library/Cookies/` | HTTP cookies |

### Bulk Artifact Download

```bash
# Download all files from the app's data container
# First, get the app container path
APP_UUID=$(ssh root@${DEVICE_IP} \
  "find /var/mobile/Containers/Data/Application -name '.com.malware.app*' -maxdepth 2" | \
  head -1 | cut -d/ -f7)

# Then download key directories
for dir in Documents Library/Preferences Library/Caches tmp; do
  mkdir -p "${EVIDENCE_DIR}/filesystem/${dir}"
  curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
    "${CORELLIUM_API}/v1/instances/{id}/files/var/mobile/Containers/Data/Application/${APP_UUID}/${dir}/" | \
    jq -r '.[].name' | while read file; do
      curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
        "${CORELLIUM_API}/v1/instances/{id}/files/var/mobile/Containers/Data/Application/${APP_UUID}/${dir}/${file}" \
        -o "${EVIDENCE_DIR}/filesystem/${dir}/${file}"
    done
done
```

## Evidence Packaging

### Directory Structure

Organize collected evidence for handoff to the reporting phase (ios-malware-analysis Phase 5):

```
evidence/
├── sample/
│   ├── sample.ipa                     # Original sample
│   └── sha256.txt                     # Sample hash
├── network/
│   ├── capture.pcap                   # Full network capture
│   ├── dns_queries.txt                # Extracted DNS queries
│   ├── http_urls.txt                  # Extracted HTTP URLs
│   ├── tls_sni.txt                    # TLS Server Name Indication values
│   ├── external_ips.txt               # Non-Apple destination IPs
│   └── http_objects/                  # Extracted HTTP response objects
├── syscalls/
│   ├── coretrace.log                  # Full CoreTrace output
│   ├── malware_syscalls.log           # Filtered to malware process
│   ├── files_accessed.txt             # Files opened by malware
│   ├── connections.txt                # Network connections
│   └── anti_debug.txt                 # Anti-debugging indicators
├── frida/
│   ├── frida_output.log               # Console output
│   ├── c2_domains.txt                 # Extracted C2 domains
│   ├── behaviors.txt                  # Behavioral indicators
│   └── evasion.txt                    # Anti-analysis techniques
├── screenshots/
│   ├── screen_001.png ... screen_NNN.png
│   └── timeline.txt                   # Screenshot timestamps
├── filesystem/
│   ├── Documents/                     # App documents
│   ├── Library/Preferences/           # Plists
│   ├── Library/Caches/                # Cached data
│   └── tmp/                           # Temporary/dropped files
└── metadata/
    ├── device_info.json               # Corellium device details
    ├── analysis_timeline.txt          # Timestamped analysis log
    └── analyst_notes.md               # Free-form notes
```

### Metadata Collection

```bash
# Record device information
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}" | \
  jq '{id, name, flavor, os, state, created}' > "${EVIDENCE_DIR}/metadata/device_info.json"

# Record sample hash
shasum -a 256 sample.ipa > "${EVIDENCE_DIR}/sample/sha256.txt"

# Create analysis timeline entry
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Evidence collection complete" \
  >> "${EVIDENCE_DIR}/metadata/analysis_timeline.txt"
```

### Archive for Handoff

```bash
# Create a compressed archive of all evidence
tar czf "evidence_$(date +%Y%m%d_%H%M%S).tar.gz" \
  -C "${EVIDENCE_DIR}" .

# Generate manifest with checksums
find "${EVIDENCE_DIR}" -type f -exec shasum -a 256 {} \; \
  > "${EVIDENCE_DIR}/manifest.sha256"
```
