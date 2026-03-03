# API Automation Reference

REST API operations and SDK examples for automating Corellium workflows. Use for batch sample analysis, CI/CD integration, and programmatic device management.

## Authentication

All API requests require a Bearer token:

```bash
# Environment variable (recommended)
export CORELLIUM_API_TOKEN="your-token-here"

# Never hardcode tokens in scripts or commit them to repositories
```

## REST API Key Operations

### Device Management

```bash
# List all devices
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances" | jq '.[] | {id, name, state, flavor}'

# Create a new device
curl -s -X POST -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  -H "Content-Type: application/json" \
  "${CORELLIUM_API}/v1/instances" \
  -d '{
    "flavor": "iphone12",
    "os": "16.0",
    "name": "malware-lab",
    "patches": ["jailbroken"]
  }'

# Start a stopped device
curl -s -X POST -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/start"

# Stop a device (saves compute time)
curl -s -X POST -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/stop"

# Delete a device
curl -s -X DELETE -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}"

# Wait for device to be ready
# Poll until state is "on"
while true; do
  STATE=$(curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
    "${CORELLIUM_API}/v1/instances/{id}" | jq -r '.state')
  [ "$STATE" = "on" ] && break
  sleep 5
done
```

### Snapshot Management

```bash
# List snapshots for a device
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/snapshots" | jq '.[] | {id, name, created}'

# Create a snapshot
curl -s -X POST -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  -H "Content-Type: application/json" \
  "${CORELLIUM_API}/v1/instances/{id}/snapshots" \
  -d '{"name": "clean-baseline"}'

# Restore a snapshot
curl -s -X POST -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/snapshots/{snapshot_id}/restore"

# Delete a snapshot (to free a slot)
curl -s -X DELETE -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/snapshots/{snapshot_id}"
```

### File Operations

```bash
# Upload a file to the device
curl -s -X PUT -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @sample.ipa \
  "${CORELLIUM_API}/v1/instances/{id}/files/tmp/sample.ipa"

# Download a file from the device
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/files/tmp/output.log" \
  -o output.log

# List directory contents
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/files/var/mobile/" | jq '.'
```

### Network Monitor

```bash
# Enable network monitoring
curl -s -X POST -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/netmon/enable"

# Disable network monitoring
curl -s -X POST -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/netmon/disable"

# Download network capture (PCAP format)
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/netmon/pcap" \
  -o capture.pcap
```

### CoreTrace

```bash
# Start CoreTrace
curl -s -X POST -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/coretrace/start"

# Stop CoreTrace
curl -s -X POST -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/coretrace/stop"

# Download CoreTrace log
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/coretrace/log" \
  -o coretrace.log
```

### Screenshots

```bash
# Take a screenshot (returns PNG)
curl -s -H "Authorization: Bearer ${CORELLIUM_API_TOKEN}" \
  "${CORELLIUM_API}/v1/instances/{id}/screenshot" \
  -o screenshot.png
```

## Python SDK Examples

Using the `corellium-api` Python package for automation.

### Setup

```python
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.28"]
# ///

import os
import time
import requests

API_BASE = os.environ.get("CORELLIUM_API", "https://app.corellium.com/api")
TOKEN = os.environ["CORELLIUM_API_TOKEN"]

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}
```

### Device Lifecycle

```python
def create_device(name, ios_version="16.0", model="iphone12"):
    """Create a jailbroken virtual device."""
    resp = requests.post(f"{API_BASE}/v1/instances", headers=headers, json={
        "flavor": model,
        "os": ios_version,
        "name": name,
        "patches": ["jailbroken"]
    })
    resp.raise_for_status()
    return resp.json()["id"]

def wait_for_device(instance_id, timeout=300):
    """Wait until the device is fully booted."""
    start = time.time()
    while time.time() - start < timeout:
        resp = requests.get(f"{API_BASE}/v1/instances/{instance_id}", headers=headers)
        state = resp.json().get("state")
        if state == "on":
            return True
        time.sleep(5)
    raise TimeoutError(f"Device {instance_id} did not boot within {timeout}s")

def stop_device(instance_id):
    """Stop a device to save compute time."""
    requests.post(f"{API_BASE}/v1/instances/{instance_id}/stop", headers=headers)

def delete_device(instance_id):
    """Delete a device permanently."""
    requests.delete(f"{API_BASE}/v1/instances/{instance_id}", headers=headers)
```

### Snapshot Operations

```python
def create_snapshot(instance_id, name):
    """Create a named snapshot."""
    resp = requests.post(
        f"{API_BASE}/v1/instances/{instance_id}/snapshots",
        headers=headers,
        json={"name": name}
    )
    resp.raise_for_status()
    return resp.json()["id"]

def restore_snapshot(snapshot_id):
    """Restore a device to a snapshot."""
    resp = requests.post(
        f"{API_BASE}/v1/snapshots/{snapshot_id}/restore",
        headers=headers
    )
    resp.raise_for_status()

def list_snapshots(instance_id):
    """List all snapshots for a device."""
    resp = requests.get(
        f"{API_BASE}/v1/instances/{instance_id}/snapshots",
        headers=headers
    )
    return resp.json()

def find_snapshot_by_name(instance_id, name):
    """Find a snapshot by name."""
    for snap in list_snapshots(instance_id):
        if snap["name"] == name:
            return snap["id"]
    return None
```

### File Operations

```python
def upload_file(instance_id, local_path, remote_path):
    """Upload a file to the virtual device."""
    with open(local_path, "rb") as f:
        resp = requests.put(
            f"{API_BASE}/v1/instances/{instance_id}/files/{remote_path}",
            headers={**headers, "Content-Type": "application/octet-stream"},
            data=f.read()
        )
    resp.raise_for_status()

def download_file(instance_id, remote_path, local_path):
    """Download a file from the virtual device."""
    resp = requests.get(
        f"{API_BASE}/v1/instances/{instance_id}/files/{remote_path}",
        headers=headers
    )
    resp.raise_for_status()
    with open(local_path, "wb") as f:
        f.write(resp.content)
```

### Network and CoreTrace

```python
def enable_netmon(instance_id):
    """Enable network monitoring."""
    requests.post(f"{API_BASE}/v1/instances/{instance_id}/netmon/enable", headers=headers)

def disable_netmon(instance_id):
    """Disable network monitoring."""
    requests.post(f"{API_BASE}/v1/instances/{instance_id}/netmon/disable", headers=headers)

def download_pcap(instance_id, output_path):
    """Download network capture as PCAP."""
    resp = requests.get(
        f"{API_BASE}/v1/instances/{instance_id}/netmon/pcap",
        headers=headers
    )
    with open(output_path, "wb") as f:
        f.write(resp.content)

def start_coretrace(instance_id):
    """Start CoreTrace syscall tracing."""
    requests.post(f"{API_BASE}/v1/instances/{instance_id}/coretrace/start", headers=headers)

def stop_coretrace(instance_id):
    """Stop CoreTrace."""
    requests.post(f"{API_BASE}/v1/instances/{instance_id}/coretrace/stop", headers=headers)

def download_coretrace(instance_id, output_path):
    """Download CoreTrace log."""
    resp = requests.get(
        f"{API_BASE}/v1/instances/{instance_id}/coretrace/log",
        headers=headers
    )
    with open(output_path, "wb") as f:
        f.write(resp.content)
```

## Batch Analysis Workflow

Automated pipeline: provision → install → analyze → collect → restore → repeat.

```python
def analyze_sample(instance_id, baseline_snapshot_id, sample_path, frida_script_path, output_dir):
    """
    Run a complete analysis cycle on a single sample.

    Args:
        instance_id: Corellium device instance ID
        baseline_snapshot_id: Snapshot ID to restore after analysis
        sample_path: Local path to the IPA/app to analyze
        frida_script_path: Local path to the Frida analysis script
        output_dir: Local directory for evidence output
    """
    import subprocess
    from pathlib import Path

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    sample_name = Path(sample_path).stem

    # 1. Restore to clean baseline
    print(f"[{sample_name}] Restoring baseline snapshot...")
    restore_snapshot(baseline_snapshot_id)
    wait_for_device(instance_id)

    # 2. Enable monitoring
    print(f"[{sample_name}] Enabling network monitor and CoreTrace...")
    enable_netmon(instance_id)
    start_coretrace(instance_id)

    # 3. Upload and install sample
    print(f"[{sample_name}] Uploading sample...")
    upload_file(instance_id, sample_path, f"tmp/{Path(sample_path).name}")

    # 4. Install via SSH (assumes SSH access configured)
    # This step depends on your SSH setup — adapt as needed
    print(f"[{sample_name}] Installing sample...")

    # 5. Run Frida analysis script
    print(f"[{sample_name}] Running Frida analysis...")
    frida_output = output / f"{sample_name}_frida.log"
    # Use local Frida client (USBFlux or SSH tunnel must be configured)
    # subprocess.run(["frida", "-U", "-f", bundle_id, "-l", frida_script_path,
    #                 "--timeout", "120"], capture_output=True, text=True)

    # 6. Wait for analysis duration
    print(f"[{sample_name}] Observing behavior (120s)...")
    time.sleep(120)

    # 7. Collect evidence
    print(f"[{sample_name}] Collecting evidence...")
    stop_coretrace(instance_id)
    disable_netmon(instance_id)

    download_pcap(instance_id, str(output / f"{sample_name}_network.pcap"))
    download_coretrace(instance_id, str(output / f"{sample_name}_coretrace.log"))

    # Take final screenshot
    resp = requests.get(
        f"{API_BASE}/v1/instances/{instance_id}/screenshot",
        headers=headers
    )
    with open(output / f"{sample_name}_screenshot.png", "wb") as f:
        f.write(resp.content)

    print(f"[{sample_name}] Analysis complete. Evidence in {output_dir}")


def batch_analyze(instance_id, baseline_snapshot_id, samples_dir, frida_script, output_dir):
    """
    Analyze multiple samples sequentially with automatic snapshot restore.

    Args:
        instance_id: Corellium device instance ID
        baseline_snapshot_id: Clean baseline snapshot ID
        samples_dir: Directory containing IPA files to analyze
        frida_script: Path to the Frida analysis script
        output_dir: Base output directory for all evidence
    """
    from pathlib import Path

    samples = sorted(Path(samples_dir).glob("*.ipa"))
    print(f"Found {len(samples)} samples to analyze")

    for i, sample in enumerate(samples, 1):
        print(f"\n{'='*60}")
        print(f"Sample {i}/{len(samples)}: {sample.name}")
        print(f"{'='*60}")
        try:
            analyze_sample(
                instance_id, baseline_snapshot_id,
                str(sample), frida_script,
                f"{output_dir}/{sample.stem}"
            )
        except Exception as e:
            print(f"[ERROR] {sample.name}: {e}")
            # Restore baseline and continue with next sample
            restore_snapshot(baseline_snapshot_id)
            wait_for_device(instance_id)

    print(f"\nBatch analysis complete. {len(samples)} samples processed.")
```

## JavaScript SDK Examples

Using the `@corellium/client-api` npm package.

```javascript
// Setup
const Corellium = require('@corellium/client-api');

const client = new Corellium.ApiClient();
client.authentications['BearerAuth'].apiKey = process.env.CORELLIUM_API_TOKEN;

const instancesApi = new Corellium.InstancesApi(client);
const snapshotsApi = new Corellium.SnapshotsApi(client);
```

```javascript
// Create device and snapshot
async function setupAnalysisDevice() {
  const instance = await instancesApi.createInstance({
    flavor: 'iphone12',
    os: '16.0',
    name: 'malware-lab',
    patches: ['jailbroken']
  });

  // Wait for boot
  let state;
  do {
    await new Promise(r => setTimeout(r, 5000));
    const info = await instancesApi.getInstance(instance.id);
    state = info.state;
  } while (state !== 'on');

  // Create baseline snapshot
  const snapshot = await snapshotsApi.createSnapshot(instance.id, {
    name: 'clean-baseline'
  });

  return { instanceId: instance.id, snapshotId: snapshot.id };
}
```

## Error Handling and Rate Limiting

```python
import time

def api_call_with_retry(func, *args, max_retries=4, **kwargs):
    """Execute an API call with exponential backoff retry."""
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:  # Rate limited
                wait = 2 ** (attempt + 1)
                print(f"Rate limited, waiting {wait}s...")
                time.sleep(wait)
            elif e.response.status_code >= 500:  # Server error
                wait = 2 ** (attempt + 1)
                print(f"Server error, retrying in {wait}s...")
                time.sleep(wait)
            else:
                raise
        except requests.exceptions.ConnectionError:
            wait = 2 ** (attempt + 1)
            print(f"Connection error, retrying in {wait}s...")
            time.sleep(wait)
    raise RuntimeError(f"API call failed after {max_retries} retries")
```
