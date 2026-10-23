# Firebase APK Security Scanner

Scan Android APKs for Firebase security misconfigurations including open databases, exposed storage buckets, and authentication bypasses.

## When to Use

Use this skill when you need to:
- Audit Android applications for Firebase misconfigurations
- Test Firebase endpoints extracted from APKs (Realtime Database, Firestore, Storage)
- Check authentication security (open signup, anonymous auth, email enumeration)
- Enumerate Cloud Functions and test for unauthenticated access
- Perform mobile app security assessments involving Firebase backends

## When NOT to Use

- Scanning apps you do not have explicit authorization to test
- Testing production Firebase projects without written permission
- When you only need to extract Firebase config without testing (use manual grep/strings instead)
- For non-Android targets (iOS, web apps) - this skill is APK-specific
- When the target app does not use Firebase

## What It Does

This skill automates Firebase security testing for Android applications. When invoked, Claude will:

- **Decompile** the APK using apktool
- **Extract** Firebase configuration from all sources (google-services.json, XML resources, assets, smali code, DEX strings)
- **Test** authentication endpoints for misconfigurations
- **Probe** Realtime Database and Firestore for open read/write access
- **Check** Storage buckets for public listing and upload vulnerabilities
- **Enumerate** Cloud Functions and test accessibility
- **Generate** detailed reports with findings and remediation guidance

## Key Features

- Supports native Android, React Native, Flutter, and Cordova apps
- Extracts config from 7+ sources including raw DEX binary strings
- Tests 14 distinct vulnerability categories
- Automatic cleanup of test data created during scans
- Detailed vulnerability reference documentation included

## Installation

```
/plugin install trailofbits/skills/plugins/firebase-apk-scanner
```

## Prerequisites

Install required dependencies before use:

**macOS:**
```bash
brew install apktool curl jq binutils
```

**Ubuntu/Debian:**
```bash
sudo apt install apktool curl jq unzip binutils
```

## Usage

```
/firebase-apk-scanner:scan-apk ./app.apk
/firebase-apk-scanner:scan-apk ./apks/
```

Or run the standalone script directly, from the plugin directory:

```bash
./skills/firebase-apk-scanner/scanner.sh app.apk
./skills/firebase-apk-scanner/scanner.sh ./apks/ --no-cleanup
```

## Vulnerability Categories

| Category | Tests | Severity |
|----------|-------|----------|
| **Authentication** | Open signup, anonymous auth, email enumeration | Critical/High/Medium |
| **Realtime Database** | Unauthenticated read/write, auth token bypass | Critical/High |
| **Firestore** | Document access, collection enumeration | Critical/High |
| **Storage** | Bucket listing, unauthenticated upload | Critical/High |
| **Cloud Functions** | Unauthenticated access, function enumeration | Medium/Low |
| **Remote Config** | Public parameter exposure | Medium |

## Calcifier recipe for `firebase-apk-scanner`

The [`firebase-apk-scanner` Python recipe](skills/firebase-apk-scanner/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/firebase-apk-scanner/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/firebase-apk-scanner/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `target` | `str` | Required |
| `authorization` | `Literal['explicit-permission']` | Required |
| `production` | `Literal['non-production', 'written-permission']` | Required |
