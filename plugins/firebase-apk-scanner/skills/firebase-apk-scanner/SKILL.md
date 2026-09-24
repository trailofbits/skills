---
name: firebase-apk-scanner
description: Scans authorized Android APKs for Firebase misconfigurations. Use when analyzing APK files for Firebase vulnerabilities, mobile app security audits, or testing Firebase endpoints.
argument-hint: [apk-file-or-directory]
allowed-tools: Bash({baseDir}/scanner.sh:*) Bash(apktool:*) Bash(curl:*) Bash(jq:*) Read Grep Glob
disable-model-invocation: true
---

# Firebase APK Security Scanner

Scan only APKs the user is authorized to test. Do not test production Firebase
projects without written permission.

## Rationalizations to Reject

- “The database is read-only” — exposed data is still a critical finding.
- “Anonymous auth is not real accounts” — its tokens can bypass `auth != null` rules.
- “The API key is public anyway” — that does not justify open backend rules.
- “There is no sensitive data yet” — insecure rules remain vulnerabilities.
- “It is an internal app” — APKs can be extracted from devices.
- “We will fix it before launch” — document the finding now.

## Workflow

1. Confirm the supplied APK path exists. If `$ARGUMENTS` is empty, ask for it.

   ```bash
   ls -la "$ARGUMENTS"
   ```

2. Run the bundled scanner. It decompiles the APK, extracts Firebase
   configuration, tests discovered endpoints, and writes text and JSON reports.

   ```bash
   {baseDir}/scanner.sh "$ARGUMENTS"
   ```

   Record the exact output directory printed as `Results saved to: ...`. Do not
   glob `firebase_scan_*`: previous scans may still be in the working directory.

3. If that output directory contains `scan_report.json`, read it even when the
   scanner exits non-zero: an all-failed or `NO_CONFIG` scan intentionally exits
   non-zero after writing its report. Use the manual fallback only when no report
   was written or the scanner is unavailable.

   Extract the summary, status, configuration, and vulnerability identifiers:

   ```bash
   report="/exact/path/printed/by/scanner/scan_report.json"
   jq '{total_apks, vulnerable_apks, failed_apks, untested_apks,
        total_vulnerabilities,
        results: [.results[] | {apk, status,
          config: (.config // {} | {project_ids, database_urls, storage_buckets,
            api_keys, auth_domains, function_names}),
          vulnerabilities}]}' "$report"
   ```

   Replace the path above with the exact report path from step 2. Include API
   keys and auth domains when extracted: they are evidence from the APK and may
   be needed to explain or reproduce an exposed endpoint.

4. Report the scan summary, extracted configuration, vulnerabilities, and
   specific remediation. Read [vulnerabilities.md](references/vulnerabilities.md)
   only when explaining a finding or its remediation.

   `failed_apks` and `untested_apks` were not tested. Report both explicitly;
   neither is vulnerable nor clean. A `NO_CONFIG` result means Firebase may be
   absent, or the configuration may be obfuscated or packed beyond extraction.

   Assign severity as follows: critical for unauthenticated database read/write,
   Storage write, or private-app open signup; high for anonymous auth, bucket
   listing, or collection enumeration; medium for email enumeration, exposed
   Cloud Functions, or Remote Config; low for other information disclosure.
   Include the scanner's per-APK evidence files when reporting a vulnerability.

5. The scanner tests every discovered Realtime Database, Firestore, and Storage
   endpoint, but authentication, Cloud Functions, and Remote Config currently
   use only the first discovered API key or project. Cloud Function tests use
   `us-central1`. For every additional project or relevant region, state that it
   was not covered and, when authorized, test it manually. The scanner removes
   its own test data; remove any data created during manual testing too.

6. If the scanner is unavailable or produces no report, read
   [manual-fallback.md](references/manual-fallback.md). Keep tests authorized,
   clean up any created test data, test all discovered projects, and report the
   failure or untested state rather than calling it clean.

## Scope

Use this for Android Firebase assessments: Realtime Database, Firestore, Storage,
authentication, Cloud Functions, and Remote Config. For configuration-only
requests, extract configuration without testing endpoints. Do not use it for
iOS, web targets, or APKs that do not use Firebase.
