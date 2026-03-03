---
name: corellium-workflows
description: >
  Manages Corellium virtual iOS devices for security research and malware
  analysis. Configures device snapshots, network monitoring, CoreTrace,
  and Frida integration. Use when setting up isolated analysis environments,
  performing safe malware detonation, or automating batch sample analysis.
allowed-tools:
  - Read
  - Write
  - Edit
  - Grep
  - Glob
  - Bash
---

# Corellium Workflows for iOS Security Research

Operational guidance for using Corellium's virtual iOS devices as isolated analysis environments. Corellium provides jailbroken virtual iPhones with built-in security research tooling: transparent HTTPS interception, syscall tracing (CoreTrace), pre-installed Frida, snapshot save/restore, and a REST API for automation.

This skill covers device lifecycle management, safe detonation workflows for malware analysis, evidence collection from built-in monitoring tools, and API-driven batch processing. It complements the Frida skills (frida-scripting, frida-ios-security) by providing the isolated execution environment, and the ios-malware-analysis skill by providing the lab infrastructure.

## When to Use

- Setting up Corellium virtual devices for iOS security research or malware analysis
- Creating snapshot-based safe detonation labs (install sample → analyze → restore clean state)
- Capturing network traffic with Corellium's built-in HTTPS interception (no Frida bypass needed)
- Tracing syscalls with CoreTrace to observe low-level process behavior
- Connecting Frida (web UI or local client via USBFlux) to virtual devices
- Automating batch sample analysis via the Corellium REST API
- Preserving forensic evidence from virtual device analysis sessions

## When NOT to Use

- **Physical device testing** — Use standard Frida setup with `frida-ps -U` for physical iOS devices
- **Android analysis** — Corellium supports Android, but the workflow differs significantly; this skill covers iOS
- **Production app monitoring** — Corellium is a lab tool, not a production monitoring platform
- **Writing Frida scripts** — Use **frida-scripting** for Interceptor/Stalker/ObjC API reference
- **iOS security assessment methodology** — Use **frida-ios-security** for the assessment workflow; this skill provides the environment
- **Malware analysis methodology** — Use **ios-malware-analysis** for the analytical framework; this skill provides the lab

## Quick Reference

| Task | Method |
|------|--------|
| Create device | Web UI: `Devices → Create Device` / API: `POST /v1/instances` |
| Save snapshot | Web UI: `Snapshots → Take Snapshot` / API: `POST /v1/instances/{id}/snapshots` |
| Restore snapshot | Web UI: `Snapshots → Restore` / API: `POST /v1/snapshots/{id}/restore` |
| Enable network monitor | Web UI: `Network Monitor → Enable` / API: `POST /v1/instances/{id}/netmon/enable` |
| Start CoreTrace | Web UI: `CoreTrace → Start` / API: `POST /v1/instances/{id}/coretrace/start` |
| Connect Frida (web) | Web UI: `Apps → Open Frida` (browser-based console) |
| Connect Frida (local) | USBFlux + `frida -U <app>` or SSH tunnel + `frida -H <ip>:<port>` |
| Upload file | Web UI: File browser / API: `PUT /v1/instances/{id}/files/{path}` |
| Take screenshot | API: `GET /v1/instances/{id}/screenshot` |

## Setup

### Prerequisites

1. **Corellium account** — Individual (app.corellium.com) or Enterprise (on-premise/private cloud)
2. **API token** — Generate from `Profile → API Keys`. Store securely; never commit to repositories

### Security Warning

**Never hardcode API tokens.** Use environment variables or a secrets manager:

```bash
# Set token as environment variable
export CORELLIUM_API_TOKEN="your-token-here"

# Use in scripts
curl -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" ...
```

### Device Provisioning

Create a jailbroken iOS device for security research:

1. **Choose iOS version** — Select based on your analysis needs:
   - Latest available: broadest app compatibility
   - Specific version: match a known vulnerable target
   - Older versions: test legacy app behavior

2. **Select device model** — iPhone models affect available features (Face ID vs Touch ID, screen size for UI overlay analysis)

3. **Enable jailbreak** — Required for Frida and filesystem access. Corellium's jailbreak is pre-configured and stable

4. **Boot the device** — First boot takes 1-2 minutes; subsequent restores from snapshot are faster

## Core Workflow: Safe Detonation Lab

The snapshot-restore workflow is the foundation for safe malware analysis. It ensures you can always return to a clean state after detonating a sample.

### Step 1: Provision a Jailbroken Device

Create a new virtual device with jailbreak enabled. Choose an iOS version that matches your target sample's requirements.

### Step 2: Create Clean Baseline Snapshot

**Before installing any samples**, save a baseline snapshot:

- Web UI: `Snapshots → Take Snapshot → Name: "clean-baseline"`
- This is your recovery point. If anything goes wrong, restore to this snapshot

**Snapshot strategy** (Corellium allows up to 5 snapshots per device):

| Slot | Purpose | When to Create |
|------|---------|---------------|
| 1 | Clean baseline | After initial device setup |
| 2 | Pre-analysis | After installing analysis tools, before sample |
| 3 | Mid-analysis | After interesting behavior observed, before risky actions |
| 4-5 | Working | Rotate as needed during analysis |

### Step 3: Configure Network Monitoring

Enable Corellium's built-in network monitor before installing the sample:

- Web UI: `Network Monitor → Enable`
- This activates transparent HTTPS interception using an injected CA certificate and sslsplit
- **No Frida SSL bypass needed** — Corellium intercepts at the OS level, below most certificate pinning implementations

Network monitor capabilities:
- Full HTTP/HTTPS request and response capture
- Per-process filtering
- Real-time display in web UI
- Export as PCAP for Wireshark analysis
- Automatic TLS decryption (no client-side bypass required)

### Step 4: Install the Sample

Upload the malware sample to the device:

- **Web UI file browser** — Drag and drop the IPA or app bundle
- **SCP via SSH** — `scp sample.ipa root@<device-ip>:/tmp/`
- **API upload** — `PUT /v1/instances/{id}/files/tmp/sample.ipa`

For IPA files, install with:
```bash
# SSH into the device
ssh root@<device-ip>
# Install the IPA
appinst /tmp/sample.ipa
```

### Step 5: Enable CoreTrace and Frida

Before executing the sample, start monitoring:

1. **CoreTrace** — Start syscall tracing filtered to the sample's process:
   - Web UI: `CoreTrace → Start → Filter by process name`
   - CoreTrace output format: `<cpu> [time.nsec] threadid/pid:comm @pc`

2. **Frida** — Connect and load analysis scripts:
   - Web UI: `Apps → Find the app → Open Frida` for browser-based console
   - Local: Use USBFlux or SSH tunnel (see Frida Integration section below)
   - Load hooks from **ios-malware-analysis** behavioral profiling phase

### Step 6: Execute the Sample

Launch the malware and observe:
- Watch network monitor for C2 communication
- Watch CoreTrace for syscall activity
- Watch Frida output for API-level behavior
- Interact with the app as a user would to trigger UI-dependent behavior

### Step 7: Collect Evidence

Before restoring the snapshot, export all analysis data:
- Network captures (PCAP export)
- CoreTrace logs
- Frida script output
- Screenshots/screencasts
- Filesystem artifacts (modified files, dropped payloads)

See [references/evidence-collection.md](references/evidence-collection.md) for detailed collection procedures.

### Step 8: Restore Clean Snapshot

After evidence collection, restore to the baseline:
- Web UI: `Snapshots → clean-baseline → Restore`
- This completely reverts the device to its pre-analysis state
- Ready for the next sample

## Network Monitoring

### How It Works

Corellium's network monitor operates at the virtual device's network interface level:

1. An injected CA certificate is pre-installed in the device trust store
2. sslsplit transparently intercepts TLS connections
3. All HTTP/HTTPS traffic is captured and decoded
4. Traffic is displayed in real-time in the web UI

### Advantages Over Frida SSL Bypass

| Feature | Corellium Network Monitor | Frida SSL Bypass |
|---------|--------------------------|-----------------|
| Setup effort | One click | Script per pinning implementation |
| Coverage | All processes, all connections | Only hooked processes |
| Certificate pinning | Bypassed at OS level | Must target each framework |
| Binary protocol capture | Yes (raw PCAP) | Requires custom hooks |
| Performance impact | Minimal (network-level) | Per-hook overhead |

### Limitations

- Cannot intercept certificate-pinned connections that use custom TLS implementations (rare on iOS)
- Does not capture localhost traffic between processes on the device
- Some apps detect non-standard CA certificates and refuse to communicate

### Per-Process Filtering

Filter network traffic to focus on the sample's communications:
- Web UI: Click the process filter dropdown and select the target app
- This reduces noise from system processes (Apple services, daemon traffic)

## CoreTrace

### What It Captures

CoreTrace is Corellium's syscall tracing tool, similar to strace/dtrace but built into the virtual device.

**Output format:**
```
<cpu> [timestamp.nanoseconds] threadid/pid:processname @programcounter
  syscall(args...) = return_value
```

**Example:**
```
0 [1234567890.123456789] 0x1a3/456:MalwareApp @0x1a2b3c4d
  open("/var/mobile/Containers/Data/Application/.../Documents/config.plist", 0x0, 0x0) = 5
```

### Useful Filters

| Filter | Purpose |
|--------|---------|
| Process name | Focus on the malware process only |
| Syscall type | Filter to `open`, `connect`, `write` for file/network activity |
| File path | Track access to specific directories |

### Common Syscall Patterns for Malware

| Syscall Pattern | Indicates |
|----------------|-----------|
| `open` + `read` on `/var/mobile/Containers` | Data access in other app containers |
| `connect` to non-Apple IPs | C2 or exfiltration |
| `fork` or `posix_spawn` | Process creation (unusual for iOS apps) |
| `ptrace` with `PT_DENY_ATTACH` | Anti-debugging |
| `sysctl` with `KERN_PROC` | Debugger detection |
| `stat`/`access` on jailbreak paths | Jailbreak detection |
| Rapid `open`/`read`/`close` on contacts/photos databases | Data harvesting |

## Frida Integration

### Web UI Console

The simplest way to use Frida on a Corellium device:

1. Navigate to `Apps` in the device panel
2. Find the target app
3. Click `Open Frida` — opens a browser-based Frida REPL
4. Paste scripts directly or type commands interactively

**Advantages:** No local setup, no version matching, immediate access
**Limitations:** No script file loading, limited REPL features, no `frida-trace`

### Local Frida Client via USBFlux

For full Frida functionality (script files, frida-trace, frida-ps):

1. **Install USBFlux** — Download from Corellium (makes virtual device appear as USB device)
2. **Connect** — `frida-ps -U` should list processes on the virtual device
3. **Use normally** — `frida -U -f com.example.app -l script.js`

### Local Frida Client via SSH Tunnel

Alternative to USBFlux:

```bash
# Forward Frida port via SSH
ssh -L 27042:localhost:27042 root@<device-ip>

# Connect using host mode
frida -H 127.0.0.1 <app>
```

### Version Matching

Corellium pre-installs a specific Frida version. If using a local client:
- Check the device's Frida version: `ssh root@<ip> frida-server --version`
- Install the matching client: `pip install frida-tools==<version>`
- Mismatched versions cause connection failures or crashes

## Snapshot Management

### Snapshot Types

| Type | What It Captures | Use Case |
|------|-----------------|----------|
| Standard | Filesystem state | Quick save/restore, most analysis |
| Live | Filesystem + RAM state | Capture running process memory, mid-execution state |

### Strategy for Malware Analysis

```text
Analysis session flow:

[Clean Baseline] ──install──→ [Pre-Execution] ──run──→ [Post-Execution]
      ↑                             ↑                         ↑
   Snapshot 1                   Snapshot 2               Snapshot 3
   (always keep)             (restore point)          (if interesting)
      ↑
   Restore here to start fresh for next sample
```

### Sharing (Enterprise)

Enterprise Corellium allows sharing snapshots between team members:
- Share a "ready-to-analyze" snapshot with pre-installed tools
- Share a "malware-active" snapshot for collaborative analysis
- Clone devices from shared snapshots for parallel analysis

## Device Configuration

### Sensor Simulation

Corellium can simulate device sensors — useful for triggering geofenced or condition-dependent malware:

| Sensor | Simulation | Use Case |
|--------|-----------|----------|
| GPS/Location | Set arbitrary coordinates | Trigger geofenced malware activation |
| Motion | Simulate movement patterns | Bypass "real device" checks that monitor accelerometer |
| Battery | Set charge level and state | Trigger battery-level-dependent behavior |

### Boot Arguments and Kernel Patches

Advanced configuration for security research:
- Custom boot arguments for debugging
- Kernel patches for disabling specific security features
- Random seed control for reproducible analysis

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| Frida connection refused | Version mismatch between local client and device server | Match versions: `frida-server --version` on device, `pip install frida-tools==<version>` locally |
| Network monitor not capturing | Monitor not enabled before app launch | Enable monitor first, then launch app. Some initial traffic may be missed |
| CoreTrace too noisy | No process filter applied | Filter by process name; exclude system daemons |
| Snapshot restore fails | Device in transitional state | Wait for device to fully boot, then retry restore |
| USBFlux not connecting | Service not running or port conflict | Restart USBFlux service, check for port 27042 conflicts |
| App won't install | Code signing issue on jailbroken device | Use `appinst` or `ldid -S` to ad-hoc sign |
| HTTPS interception failing | App uses custom TLS implementation | Fall back to Frida SSL bypass hooks (see frida-ios-security) |
| Device running slowly | Resource contention on Corellium host | Reduce number of concurrent virtual devices |

## Cost Optimization

Corellium charges by compute time. Minimize costs:

- **Snapshot and stop** — When not actively analyzing, stop the device (snapshot first)
- **Batch your analysis** — Plan analysis sessions; don't leave devices idling
- **Use the API** — Automated workflows are faster and more consistent than manual analysis
- **Share snapshots** (Enterprise) — Avoid duplicate device provisioning across team members

## Related Skills

| Skill | How It Helps |
|-------|-------------|
| **frida-scripting** | Frida API reference for writing scripts to run on Corellium virtual devices |
| **frida-ios-security** | iOS security assessment methodology; Corellium provides the test environment |
| **ios-malware-analysis** | Malware analysis methodology; Corellium provides the isolated detonation lab |

## Resources

**[Corellium Documentation](https://support.corellium.com/)**
Official documentation for device management, API reference, and feature guides.

**[Corellium API Reference](https://app.corellium.com/api/docs)**
REST API documentation for automation workflows.

**[Frida Documentation](https://frida.re/docs/home/)**
Frida setup and API reference for use with Corellium virtual devices.
