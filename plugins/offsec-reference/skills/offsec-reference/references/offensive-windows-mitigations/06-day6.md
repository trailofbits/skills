## Day 6: Comprehensive Mitigation Testing and Validation

- **Estimated Time**: 4-5 hours
- **Goal**: Systematically test all mitigations and document security posture.
- **Activities**:
  - _Reading_:
    - [Exploit Protection Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference)
  - _Online Resources_:
    - [Windows Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
  - _Tool Setup_:
    - Security Compliance Toolkit
    - BinSkim Binary Analyzer (replaces deprecated BinScope)
  - _Exercise_:
    - Audit system mitigation status
    - Test each protection mechanism
    - Build comprehensive security report

### Deliverables

- **Audit Report**: `mitigation_audit.csv` from your test directory
- **Compliance Check**: `compliance_report.json` showing system hardening status
- **Drift/Match**: A screenshot showing your test binary PASSING the build gate

### Mitigation Audit

**Automated Audit Script**:

```bash
# mitigation_audit.ps1
Write-Host "=== Windows Mitigation Audit ===" -ForegroundColor Cyan

# 1. Check DEP
Write-Host "`n[*] Checking DEP..." -ForegroundColor Yellow
$dep = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty DataExecutionPrevention_SupportPolicy
switch ($dep) {
    0 { Write-Host "[-] DEP: Always Off" -ForegroundColor Red }
    1 { Write-Host "[+] DEP: Always On" -ForegroundColor Green }
    2 { Write-Host "[~] DEP: Opt-In (default)" -ForegroundColor Yellow }
    3 { Write-Host "[+] DEP: Opt-Out" -ForegroundColor Green }
}

# 2. Check ASLR
Write-Host "`n[*] Checking ASLR..." -ForegroundColor Yellow
$aslr = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -ErrorAction SilentlyContinue
if ($aslr.MoveImages -eq 0) {
    Write-Host "[-] ASLR: Disabled" -ForegroundColor Red
} else {
    Write-Host "[+] ASLR: Enabled" -ForegroundColor Green
}

# 3. Check SEHOP
Write-Host "`n[*] Checking SEHOP..." -ForegroundColor Yellow
$sehop = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -ErrorAction SilentlyContinue
if ($sehop.DisableExceptionChainValidation -eq 1) {
    Write-Host "[-] SEHOP: Disabled" -ForegroundColor Red
} else {
    Write-Host "[+] SEHOP: Enabled" -ForegroundColor Green
}

# 4. Check VBS
Write-Host "`n[*] Checking VBS..." -ForegroundColor Yellow
$vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($vbs.VirtualizationBasedSecurityStatus -eq 2) {
    Write-Host "[+] VBS: Running" -ForegroundColor Green

    $services = $vbs.SecurityServicesRunning
    if ($services -contains 1) {
        Write-Host "  [+] Credential Guard: Running" -ForegroundColor Green
    }
    if ($services -contains 2) {
        Write-Host "  [+] HVCI: Running" -ForegroundColor Green
    }
} else {
    Write-Host "[-] VBS: Not Running" -ForegroundColor Red
}

# 5. Check CFG
Write-Host "`n[*] Checking CFG support..." -ForegroundColor Yellow
# CFG is per-process, check common system binaries
$testBinaries = @(
    "C:\Windows\System32\notepad.exe",
    "C:\Windows\System32\cmd.exe",
    "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)

foreach ($bin in $testBinaries) {
    if (Test-Path $bin) {
        try {
            # Use Get-ProcessMitigation to check CFG for the binary
            $mitigation = Get-ProcessMitigation -Name ([System.IO.Path]::GetFileName($bin)) -ErrorAction SilentlyContinue

            if ($mitigation -and $mitigation.CFG.Enable -in @("ON", $true)) {
                Write-Host "  [+] $([System.IO.Path]::GetFileName($bin)) has CFG enabled" -ForegroundColor Green
            } else {
                # Fallback: Check PE headers directly
                $bytes = [System.IO.File]::ReadAllBytes($bin)
                $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
                $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)

                # DllCharacteristics location
                if ($machine -eq 0x8664) {  # x64
                    $dllCharOffset = $peOffset + 0x46 + 0x18
                } else {  # x86
                    $dllCharOffset = $peOffset + 0x46
                }

                $dllChar = [BitConverter]::ToUInt16($bytes, $dllCharOffset)
                $cfgFlag = 0x4000  # IMAGE_DLLCHARACTERISTICS_GUARD_CF

                if (($dllChar -band $cfgFlag) -eq $cfgFlag) {
                    Write-Host "  [+] $([System.IO.Path]::GetFileName($bin)) has CFG in PE header" -ForegroundColor Green
                } else {
                    Write-Host "  [-] $([System.IO.Path]::GetFileName($bin)) lacks CFG" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "  [~] Could not check $([System.IO.Path]::GetFileName($bin))" -ForegroundColor Gray
        }
    }
}

Write-Host "`n  Note: CFG is enabled per-process. System-wide default:" -ForegroundColor Gray
try {
    $sysCFG = (Get-ProcessMitigation -System).CFG.Enable
    if ($sysCFG -in @("ON", $true)) {
        Write-Host "    [+] System-wide CFG: Enabled by default" -ForegroundColor Green
    } else {
        Write-Host "    [-] System-wide CFG: Not enabled by default" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [~] Could not query system CFG policy" -ForegroundColor Gray
}

# 6. Check CET (Control-flow Enforcement Technology)
Write-Host "`n[*] Checking CET..." -ForegroundColor Yellow
$cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1

# Check for CET-capable CPU (11th gen Intel Tiger Lake+, AMD Zen 3+)
$cetCapableCPU = $false
if ($cpu.Name -match "11th Gen|12th Gen|13th Gen|14th Gen|Core Ultra" -or
    $cpu.Name -match "Ryzen.*(5[0-9]{3}|7[0-9]{3}|9[0-9]{3})" -or
    $cpu.Name -match "EPYC.*7[0-9]{3}") {
    $cetCapableCPU = $true
}

if ($cetCapableCPU) {
    Write-Host "[+] CET: CPU is CET-capable ($($cpu.Name))" -ForegroundColor Green

    # Check if Shadow Stack is enabled at system level
    try {
        $mitigation = Get-ProcessMitigation -System
        $shadowStack = $mitigation.UserShadowStack
        $shadowStackValue = $shadowStack.Enable

        Write-Host "  Debug: UserShadowStack.Enable = '$shadowStackValue'" -ForegroundColor Gray

        if ($shadowStackValue -eq "ON" -or $shadowStackValue -eq $true -or $shadowStackValue -eq 1) {
            Write-Host "  [+] User-mode Shadow Stack: Enabled" -ForegroundColor Green
        } elseif ($shadowStackValue -eq "OFF" -or $shadowStackValue -eq $false -or $shadowStackValue -eq 0) {
            Write-Host "  [-] User-mode Shadow Stack: Explicitly disabled" -ForegroundColor Red
        } elseif ([string]::IsNullOrEmpty($shadowStackValue) -or $shadowStackValue -eq "NOTSET" -or $null -eq $shadowStackValue) {
            Write-Host "  [-] User-mode Shadow Stack: Not configured" -ForegroundColor Yellow
            Write-Host "      To enable: Set-ProcessMitigation -System -Enable UserShadowStack" -ForegroundColor Gray
            Write-Host "      Requires: Windows 11 22H2+, CET-enabled in BIOS" -ForegroundColor Gray
        } else {
            Write-Host "  [?] User-mode Shadow Stack: Unknown status ($shadowStackValue)" -ForegroundColor Yellow
        }

        # Check kernel shadow stack (Windows 11 24H2+)
        if ($mitigation.PSObject.Properties.Name -contains "KernelShadowStack") {
            $kernelShadow = $mitigation.KernelShadowStack
            $kernelValue = $kernelShadow.Enable

            Write-Host "  Debug: KernelShadowStack.Enable = '$kernelValue'" -ForegroundColor Gray

            if ($kernelValue -eq "ON" -or $kernelValue -eq $true -or $kernelValue -eq 1) {
                Write-Host "  [+] Kernel-mode Shadow Stack: Enabled" -ForegroundColor Green
            } elseif ($kernelValue -eq "OFF" -or $kernelValue -eq $false -or $kernelValue -eq 0) {
                Write-Host "  [-] Kernel-mode Shadow Stack: Explicitly disabled" -ForegroundColor Red
            } elseif ([string]::IsNullOrEmpty($kernelValue) -or $kernelValue -eq "NOTSET" -or $null -eq $kernelValue) {
                Write-Host "  [-] Kernel-mode Shadow Stack: Not configured" -ForegroundColor Yellow
                Write-Host "      Requires Windows 11 24H2+ and BIOS CET support" -ForegroundColor Gray
            } else {
                Write-Host "  [?] Kernel-mode Shadow Stack: Unknown status ($kernelValue)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [-] Kernel-mode Shadow Stack: Not available (requires Windows 11 24H2+)" -ForegroundColor Yellow
        }

        # Check Windows version
        $osVersion = [System.Environment]::OSVersion.Version
        $buildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
        $displayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion

        Write-Host "`n  Windows Version: $($osVersion.Major).$($osVersion.Minor) Build $buildNumber" -ForegroundColor Gray

        if ($buildNumber -ge 26100) {
            Write-Host "  [+] Windows 11 24H2+ detected (Build $buildNumber)" -ForegroundColor Green
            Write-Host "      CET/Shadow Stack is supported on this version" -ForegroundColor Gray
            Write-Host "      If not working, check BIOS settings for CET/IBT support" -ForegroundColor Gray
        } elseif ($buildNumber -ge 22621) {
            Write-Host "  [+] Windows 11 22H2+ detected (Build $buildNumber)" -ForegroundColor Green
            Write-Host "      User-mode Shadow Stack is supported" -ForegroundColor Gray
        } elseif ($buildNumber -ge 22000) {
            Write-Host "  [~] Windows 11 detected (Build $buildNumber)" -ForegroundColor Yellow
            Write-Host "      User-mode Shadow Stack requires 22H2+ (Build 22621+)" -ForegroundColor Yellow
        } else {
            Write-Host "  [!] Windows 10 detected (Build $buildNumber)" -ForegroundColor Yellow
            Write-Host "      CET/Shadow Stack requires Windows 11 (Build 22000+)" -ForegroundColor Yellow
        }

    } catch {
        Write-Host "  [~] Could not query Shadow Stack status: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[-] CET: CPU does not support CET ($($cpu.Name))" -ForegroundColor Yellow
    Write-Host "    CET requires: Intel 11th Gen (Tiger Lake)+, or AMD Zen 3+" -ForegroundColor Gray
}

# 7. Check Exploit Protection
Write-Host "`n[*] Checking Exploit Protection..." -ForegroundColor Yellow
try {
    $exploitProtection = Get-ProcessMitigation -System

    # DEP
    $depStatus = $exploitProtection.DEP.Enable
    if ($depStatus -in @("ON", $true)) {
        Write-Host "  [+] DEP (System): Enabled" -ForegroundColor Green
    } elseif ($depStatus -eq "NOTSET") {
        Write-Host "  [~] DEP (System): Not configured (uses default)" -ForegroundColor Yellow
    } else {
        Write-Host "  [-] DEP (System): $depStatus" -ForegroundColor Red
    }

    # ASLR
    $aslrStatus = $exploitProtection.ASLR.ForceRelocateImages
    if ($aslrStatus -in @("ON", $true)) {
        Write-Host "  [+] ASLR (System): Force relocate enabled" -ForegroundColor Green
    } elseif ($aslrStatus -eq "NOTSET") {
        Write-Host "  [~] ASLR (System): Not forced (per-binary ASLR still active)" -ForegroundColor Yellow
    } else {
        Write-Host "  [-] ASLR (System): $aslrStatus" -ForegroundColor Red
    }

    # Heap Integrity
    $heapStatus = $exploitProtection.Heap.TerminateOnError
    if ($heapStatus -in @("ON", $true)) {
        Write-Host "  [+] Heap Integrity: Terminate on error enabled" -ForegroundColor Green
    } elseif ($heapStatus -eq "NOTSET") {
        Write-Host "  [~] Heap Integrity: Not configured (default protection active)" -ForegroundColor Yellow
    } else {
        Write-Host "  [-] Heap Integrity: $heapStatus" -ForegroundColor Red
    }

    # CFG
    $cfgStatus = $exploitProtection.CFG.Enable
    if ($cfgStatus -in @("ON", $true)) {
        Write-Host "  [+] Control Flow Guard: Enabled system-wide" -ForegroundColor Green
    } elseif ($cfgStatus -eq "NOTSET") {
        Write-Host "  [~] CFG: Not forced (per-binary CFG still works)" -ForegroundColor Yellow
    } else {
        Write-Host "  [-] CFG: $cfgStatus" -ForegroundColor Red
    }

    Write-Host "`n  Note: NOTSET means Windows uses default behavior (mitigations still active)" -ForegroundColor Gray
} catch {
    Write-Host "  [!] Could not query Exploit Protection settings" -ForegroundColor Red
}

Write-Host "`n=== Audit Complete ===" -ForegroundColor Cyan
```

**Run Audit**:

```bash
Set-ExecutionPolicy Bypass -Scope Process -Force
.\src\mitigation_audit.ps1 > audit_report.txt
```

### ProcessMitigation PowerShell Module

**Available Cmdlets**:

- `Get-ProcessMitigation` - Query current settings
- `Set-ProcessMitigation` - Configure mitigations
- `ConvertTo-ProcessMitigationPolicy` - Convert policy formats

**System-Wide Configuration**:

```bash
# View all system mitigations
Get-ProcessMitigation -System

# Enable DEP system-wide
Set-ProcessMitigation -System -Enable DEP

# Enable multiple mitigations
Set-ProcessMitigation -System -Enable DEP, SEHOP, ForceRelocateImages

# Enable CFG system-wide
Set-ProcessMitigation -System -Enable CFG

# Enable User Shadow Stack (Windows 11 22H2+, requires CET-capable CPU)
Set-ProcessMitigation -System -Enable UserShadowStack

# Reset system settings to defaults
Set-ProcessMitigation -System -Reset
```

**Per-Application Configuration**:

```bash
# Check specific application
Get-ProcessMitigation -Name notepad.exe

# Enable CFG for application
Set-ProcessMitigation -Name "myapp.exe" -Enable CFG

# Disable specific mitigation (for legacy apps)
Set-ProcessMitigation -Name "legacy.exe" -Disable ForceRelocateImages

# Multiple settings at once
Set-ProcessMitigation -Name "secure.exe" `
    -Enable DEP, CFG, SEHOP, ForceRelocateImages `
    -Disable EmulateAtlThunks

# Remove application-specific overrides (revert to system defaults)
Set-ProcessMitigation -Name "myapp.exe" -Remove
```

**Export/Import Configurations**:

```bash
# Export ALL per-application mitigation overrides to XML
Get-ProcessMitigation -RegistryConfigFilePath settings.xml

# Import settings from XML
Set-ProcessMitigation -PolicyFilePath .\settings.xml

# Convert EMET policy to ProcessMitigation format
ConvertTo-ProcessMitigationPolicy -EMETFilePath .\emet.xml -OutputFilePath .\converted.xml
```

**Important Notes**:

- Export only saves **per-application overrides**, not system-wide defaults
- System defaults are built into Windows and don't need to be exported
- You cannot export just `-System` or just `-Name` - it's all per-app configs or nothing
- The XML format uses `<AppConfig Executable="...">` for each application

### Scenario: The Legacy App Exception

Security Engineers often face a dilemma: a critical business application crashes with ASLR enabled. You must create an exception.

### Binary Analysis

**Using dumpbin (Recommended - included with Visual Studio)**:

```bash
# Check PE headers for mitigation flags
dumpbin /headers bin\vuln_server_cfg.exe | findstr "DLL characteristics"

# Look for these flags in hex:
# 0x0040 - Dynamic base (ASLR)
# 0x0100 - NX compatible (DEP)
# 0x0400 - No SEH
# 0x4000 - Control Flow Guard
# 0x8000 - Guard CF function table present
# 0x0020 - High Entropy VA (64-bit ASLR)

# Example output:
#            8160 DLL characteristics
#                   High Entropy Virtual Addresses
#                   Dynamic base
#                   NX compatible
#                   Control Flow Guard

# Decode hex flags manually:
# C120 = 0x4000 (CFG) + 0x8000 (CFG table) + 0x0100 (DEP) + 0x0020 (High Entropy)
# 8160 = 0x4000 (CFG) + 0x4000 (CFG) + 0x0100 (DEP) + 0x0040 (ASLR) + 0x0020 (High Entropy)

# Check for CFG specifically
dumpbin /loadconfig bin\vuln_server_cfg.exe | findstr "Guard"

# Quick mitigation checker script
function Check-Mitigations {
    param([string]$Path)

    $output = dumpbin /headers $Path 2>&1 | Out-String
    $match = $output -match '([0-9A-F]+)\s+DLL characteristics'

    if ($match) {
        $hex = $matches[1]
        $value = [Convert]::ToInt32($hex, 16)

        [PSCustomObject]@{
            Binary = Split-Path $Path -Leaf
            ASLR = ($value -band 0x0040) -ne 0
            DEP = ($value -band 0x0100) -ne 0
            CFG = ($value -band 0x4000) -ne 0
            HighEntropyVA = ($value -band 0x0020) -ne 0
            HexValue = "0x$hex"
        }
    } else {
        Write-Error "Could not parse DLL characteristics from $Path"
    }
}

# Usage: Check-Mitigations "bin\myapp.exe"
```

**Using PowerShell to check running processes**:

```bash
# Check mitigation policies for all running processes
Get-Process | ForEach-Object {
    $name = $_.ProcessName
    try {
        $mitigation = Get-ProcessMitigation -Name "$name.exe" -ErrorAction SilentlyContinue
        if ($mitigation) {
            [PSCustomObject]@{
                Process = $name
                DEP = $mitigation.DEP.Enable
                ASLR = $mitigation.ASLR.ForceRelocateImages
                CFG = $mitigation.CFG.Enable
                SEHOP = $mitigation.SEHOP.Enable
            }
        }
    } catch {}
} | Where-Object { $_.DEP -ne 'NOTSET' -or $_.ASLR -ne 'NOTSET' -or $_.CFG -ne 'NOTSET' } | Format-Table -AutoSize

# Note: This shows policy overrides, not actual binary mitigations
# NOTSET means using default Windows behavior (which is usually secure)
# To check actual PE binary flags, use Check-Mitigations function or dumpbin
```

**Manual PE Header Check**:

```bash
# check_pe_security.ps1
param([string]$binary)

Write-Host "Analyzing: $binary" -ForegroundColor Cyan

# Use dumpbin (Visual Studio)
$headers = & dumpbin.exe /headers $binary 2>$null

# Check flags
$features = @{
    "ASLR" = $headers | Select-String "Dynamic base"
    "DEP" = $headers | Select-String "NX compatible"
    "CFG" = $headers | Select-String "Guard CF"
    "High Entropy ASLR" = $headers | Select-String "High Entropy Virtual Addresses"
    "Safe SEH" = $headers | Select-String "Safe SEH"
}

foreach ($feature in $features.Keys) {
    if ($features[$feature]) {
        Write-Host "[+] $feature: Enabled" -ForegroundColor Green
    } else {
        Write-Host "[-] $feature: Disabled" -ForegroundColor Red
    }
}
```

### Windows 11 24H2 Security Baseline

Microsoft's security baseline for 24H2 includes recommended mitigation settings:

**Recommended Exploit Protection Settings**:

| Mitigation         | Recommendation                     |
| ------------------ | ---------------------------------- |
| DEP                | Enable for all applications        |
| ASLR (BottomUp)    | Enable system-wide                 |
| ASLR (HighEntropy) | Enable for 64-bit apps             |
| CFG                | Enable where supported             |
| SEHOP              | Enable (default on)                |
| Heap Termination   | Enable                             |
| ACG                | Enable for browsers, security apps |

**VBS-Related Settings**:

- Memory Integrity (HVCI): Enable
- Kernel DMA Protection: Enable
- Credential Guard: Enable for enterprise

**Checking Baseline Compliance**:

```bash
# Export current settings
Get-ProcessMitigation -RegistryConfigFilePath current_settings.xml

# Compare with baseline (Microsoft Security Compliance Toolkit)
# Download from: https://www.microsoft.com/en-us/download/details.aspx?id=55319

# Manual comparison - check for risky overrides
[xml]$config = Get-Content current_settings.xml
$riskyApps = $config.MitigationPolicy.AppConfig | Where-Object {
    $_.DEP.Enable -eq 'false' -or
    $_.ASLR.ForceRelocateImages -eq 'false' -or
    $_.CFG.Enable -eq 'false'
}

if ($riskyApps) {
    Write-Host "WARNING: Found applications with weakened mitigations:" -ForegroundColor Red
    $riskyApps | ForEach-Object {
        Write-Host "  - $($_.Executable)" -ForegroundColor Yellow
        if ($_.DEP.Enable -eq 'false') { Write-Host "    DEP: Disabled" -ForegroundColor Red }
        if ($_.ASLR.ForceRelocateImages -eq 'false') { Write-Host "    ASLR: Disabled" -ForegroundColor Red }
        if ($_.CFG.Enable -eq 'false') { Write-Host "    CFG: Disabled" -ForegroundColor Red }
    }
} else {
    Write-Host "No risky mitigation overrides found" -ForegroundColor Green
}
```

### Exploit Protection XML Baseline Exercise

> [!TIP]
> **Enterprise Workflow**: Organizations use Exploit Protection XML policies to
> standardize mitigation settings across endpoints. This exercise teaches you
> to export, import, and audit these policies.

#### Step 1: Export Current Settings

```bash
# Export system-wide and per-app settings to XML
mkdir C:\Baselines
Get-ProcessMitigation -RegistryConfigFilePath C:\Baselines\current_settings.xml

# View the exported XML structure
Get-Content C:\Baselines\current_settings.xml | Select-Object -First 50
```

#### Step 2: Create a Hardened Baseline

Save the following as `hardened_baseline.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<MitigationPolicy>
  <AppConfig Executable="notepad.exe">
    <DEP Enable="true" EmulateAtlThunks="false" />
    <ASLR ForceRelocateImages="true" RequireInfo="false" />
  </AppConfig>

  <AppConfig Executable="calc.exe">
    <DEP Enable="true" EmulateAtlThunks="false" />
    <ASLR ForceRelocateImages="true" RequireInfo="false" />
    <CFG Enable="true" SuppressExports="false" />
  </AppConfig>
</MitigationPolicy>
```

**For system-wide settings**:

```bash
# Configure system-wide mitigations (not supported in XML)
Set-ProcessMitigation -System -Enable DEP, ForceRelocateImages, CFG, SEHOP, TerminateOnError
```

#### Step 3: Apply the Configuration

```bash
# Method 1: Import from XML (if it works)
Set-ProcessMitigation -PolicyFilePath C:\Baselines\hardened_baseline.xml

# Method 2: Direct PowerShell configuration (more reliable)
Set-ProcessMitigation -Name "chrome.exe" -Enable DEP, ForceRelocateImages, CFG, SEHOP
Set-ProcessMitigation -Name "msedge.exe" -Enable DEP, ForceRelocateImages, CFG

# Configure system-wide settings
Set-ProcessMitigation -System -Enable DEP, ForceRelocateImages, CFG, SEHOP, TerminateOnError

# Verify the configuration
Get-ProcessMitigation -Name chrome.exe
Get-ProcessMitigation -System
```

#### Step 4: Compare and Audit

```bash
# compare_baselines.ps1 - Compare current vs baseline settings
param(
    [string]$BaselinePath = "C:\Baselines\hardened_baseline.xml",
    [string]$CurrentPath = "C:\Baselines\current_settings.xml"
)

# Export fresh current settings
Get-ProcessMitigation -RegistryConfigFilePath $CurrentPath

# Load both XMLs
[xml]$baseline = Get-Content $BaselinePath
[xml]$current = Get-Content $CurrentPath

Write-Host "=== Exploit Protection Baseline Comparison ===" -ForegroundColor Cyan
Write-Host ""

# Compare System Config
Write-Host "System-Level Mitigations:" -ForegroundColor Yellow

$systemMitigations = @("DEP", "ASLR", "SEHOP", "Heap", "ControlFlowGuard")
foreach ($mit in $systemMitigations) {
    $baselineNode = $baseline.MitigationPolicy.SystemConfig.$mit
    $currentNode = $current.MitigationPolicy.SystemConfig.$mit

    if ($baselineNode -and $currentNode) {
        $baselineEnable = $baselineNode.Enable
        $currentEnable = $currentNode.Enable

        if ($baselineEnable -eq $currentEnable) {
            Write-Host "  [OK] $mit : $currentEnable" -ForegroundColor Green
        } else {
            Write-Host "  [!!] $mit : Expected=$baselineEnable, Actual=$currentEnable" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Per-Application Overrides:" -ForegroundColor Yellow
$currentApps = $current.MitigationPolicy.AppConfig | ForEach-Object { $_.Executable }
foreach ($app in $currentApps) {
    Write-Host "  - $app" -ForegroundColor Cyan
}
```

#### Step 5: Verify Effect on Test Binary

```bash
# Create test to verify baseline applies
# 1. Compile a test binary without hardening

# 2. Add per-process mitigation via policy

# 3. Apply policy

# 4. Check that mitigations are enforced at runtime

# DEP should show ON even though binary was compiled with /NXCOMPAT:NO
# (System policy overrides binary preference)
```

### Per-Binary PE Mitigation Audit Checklist

#### PowerShell Audit Script

Save as `audit_pe_mitigations.ps1`:

```bash
# audit_pe_mitigations.ps1
# Audits PE binary mitigations using dumpbin
param(
    [Parameter(Mandatory=$true)]
    [string]$TargetPath,

    [Parameter(Mandatory=$false)]
    [switch]$Recurse
)

# Function to find dumpbin.exe
function Find-Dumpbin {
    # Check if dumpbin is in PATH
    $dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($dumpbin) {
        return $dumpbin.Source
    }

    # Search common Visual Studio installation paths
    $vsPaths = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe"
    )

    foreach ($pattern in $vsPaths) {
        $found = Get-Item $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }

    return $null
}

# Find dumpbin
$dumpbinPath = Find-Dumpbin
if (-not $dumpbinPath) {
    Write-Error "dumpbin.exe not found. Please run this from Developer Command Prompt or install Visual Studio Build Tools."
    Write-Host "`nAlternative: Use the Check-Mitigations function instead:" -ForegroundColor Yellow
    Write-Host "  Check-Mitigations '$TargetPath'" -ForegroundColor Gray
    exit 1
}

Write-Host "Using dumpbin: $dumpbinPath" -ForegroundColor Gray

# Function to audit a single binary
function Audit-Binary {
    param([string]$FilePath)

    # Get DLL characteristics
    $output = & $dumpbinPath /headers $FilePath 2>&1 | Out-String
    $match = $output -match '([0-9A-F]+)\s+DLL characteristics'

    if ($match) {
        $hex = $matches[1]
        $value = [Convert]::ToInt32($hex, 16)

        return [PSCustomObject]@{
            Binary = Split-Path $FilePath -Leaf
            Path = $FilePath
            HexValue = "0x$hex"
            DEP = ($value -band 0x0100) -ne 0
            ASLR = ($value -band 0x0040) -ne 0
            HighEntropyVA = ($value -band 0x0020) -ne 0
            CFG = ($value -band 0x4000) -ne 0
            CFGTable = ($value -band 0x8000) -ne 0
            NoSEH = ($value -band 0x0400) -ne 0
        }
    }
    return $null
}

# Check if target is a directory
if (Test-Path $TargetPath -PathType Container) {
    if (-not $Recurse) {
        Write-Error "Target is a directory. Use -Recurse to scan all binaries in the directory."
        exit 1
    }

    Write-Host "`n=== Scanning Directory: $TargetPath ===" -ForegroundColor Cyan

    # Find all PE files
    $files = Get-ChildItem -Path $TargetPath -Include *.exe,*.dll -Recurse -ErrorAction SilentlyContinue

    if ($files.Count -eq 0) {
        Write-Host "No PE files found in directory" -ForegroundColor Yellow
        exit 0
    }

    Write-Host "Found $($files.Count) PE files. Analyzing..." -ForegroundColor White

    $results = @()
    $processed = 0

    foreach ($file in $files) {
        $processed++
        if ($processed % 10 -eq 0) {
            Write-Progress -Activity "Scanning binaries" -Status "$processed of $($files.Count)" -PercentComplete (($processed / $files.Count) * 100)
        }

        try {
            $result = Audit-Binary -FilePath $file.FullName
            if ($result) {
                $results += $result
            }
        } catch {
            # Skip files that can't be analyzed
        }
    }

    Write-Progress -Activity "Scanning binaries" -Completed

    # Display summary
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total binaries analyzed: $($results.Count)" -ForegroundColor White

    $stats = @{
        DEP = ($results | Where-Object { $_.DEP }).Count
        ASLR = ($results | Where-Object { $_.ASLR }).Count
        HighEntropyVA = ($results | Where-Object { $_.HighEntropyVA }).Count
        CFG = ($results | Where-Object { $_.CFG }).Count
    }

    Write-Host "`nMitigation Coverage:" -ForegroundColor Yellow
    foreach ($mitigation in $stats.GetEnumerator() | Sort-Object Name) {
        $percentage = [math]::Round(($mitigation.Value / $results.Count) * 100, 1)
        Write-Host "  $($mitigation.Key): $($mitigation.Value)/$($results.Count) ($percentage%)" -ForegroundColor White
    }

    # Show binaries without key mitigations
    Write-Host "`nBinaries without DEP:" -ForegroundColor Red
    $results | Where-Object { -not $_.DEP } | Select-Object -First 10 Binary | ForEach-Object { Write-Host "  - $($_.Binary)" -ForegroundColor Yellow }

    Write-Host "`nBinaries without ASLR:" -ForegroundColor Red
    $results | Where-Object { -not $_.ASLR } | Select-Object -First 10 Binary | ForEach-Object { Write-Host "  - $($_.Binary)" -ForegroundColor Yellow }

    Write-Host "`nBinaries without CFG:" -ForegroundColor Red
    $results | Where-Object { -not $_.CFG } | Select-Object -First 10 Binary | ForEach-Object { Write-Host "  - $($_.Binary)" -ForegroundColor Yellow }

    # Export to CSV
    $csvPath = "mitigation_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`nFull results exported to: $csvPath" -ForegroundColor Green

    exit 0
}

# Verify target exists
if (-not (Test-Path $TargetPath)) {
    Write-Error "Target file not found: $TargetPath"
    exit 1
}

$TargetPath = Resolve-Path $TargetPath

Write-Host "`n=== PE Mitigation Audit ===" -ForegroundColor Cyan
Write-Host "Target: $TargetPath`n" -ForegroundColor White

# Get DLL characteristics
$output = & $dumpbinPath /headers $TargetPath 2>&1 | Out-String
$match = $output -match '([0-9A-F]+)\s+DLL characteristics'

if ($match) {
    $hex = $matches[1]
    $value = [Convert]::ToInt32($hex, 16)

    Write-Host "DLL Characteristics: 0x$hex" -ForegroundColor White
    Write-Host ""

    # Check each mitigation
    $mitigations = @{
        "DEP (NX)" = @{ Flag = 0x0100; Enabled = ($value -band 0x0100) -ne 0 }
        "ASLR (Dynamic Base)" = @{ Flag = 0x0040; Enabled = ($value -band 0x0040) -ne 0 }
        "High Entropy VA" = @{ Flag = 0x0020; Enabled = ($value -band 0x0020) -ne 0 }
        "Control Flow Guard" = @{ Flag = 0x4000; Enabled = ($value -band 0x4000) -ne 0 }
        "Guard CF Function Table" = @{ Flag = 0x8000; Enabled = ($value -band 0x8000) -ne 0 }
        "No SEH" = @{ Flag = 0x0400; Enabled = ($value -band 0x0400) -ne 0 }
        "Terminal Server Aware" = @{ Flag = 0x0800; Enabled = ($value -band 0x0800) -ne 0 }
    }

    foreach ($mitigation in $mitigations.GetEnumerator() | Sort-Object Name) {
        $status = if ($mitigation.Value.Enabled) { "[+]" } else { "[-]" }
        $color = if ($mitigation.Value.Enabled) { "Green" } else { "Red" }
        $flagHex = "0x{0:X4}" -f $mitigation.Value.Flag

        Write-Host "$status $($mitigation.Key) ($flagHex)" -ForegroundColor $color
    }

    # Check for CFG details
    Write-Host "`n--- Control Flow Guard Details ---" -ForegroundColor Yellow
    $cfgOutput = & $dumpbinPath /loadconfig $TargetPath 2>&1 | Select-String "Guard"
    if ($cfgOutput) {
        $cfgOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    } else {
        Write-Host "  No CFG information found" -ForegroundColor Gray
    }

} else {
    Write-Error "Could not parse DLL characteristics from binary"
    exit 1
}

Write-Host "`n=== Audit Complete ===" -ForegroundColor Cyan
```

#### Usage Examples

```bash
# Audit current directory
.\src\audit_pe_mitigations.ps1 -TargetPath "bin\acg_test.exe"

# Audit Windows System32 (requires admin)
.\src\audit_pe_mitigations.ps1 -TargetPath "C:\Windows\System32" -Recurse

# Audit your application deployment
.\src\audit_pe_mitigations.ps1 -TargetPath "C:\Program Files\MyApp" -Recurse -OutputFile "myapp_audit.csv"
```

### End-to-End Testing

**Test Suite for All Mitigations**:

```c
// mitigation_test_suite.c
// Compile with ALL protections, then test each
//
// IMPORTANT: Stack cookie (/GS) and CFG failures use __fastfail()
// which generates a non-continuable exception that CANNOT be caught
// by __try/__except. These mitigations terminate the process immediately.
//
// For reliable testing, run each test as a SEPARATE PROCESS and check
// the exit code. The wrapper below demonstrates this approach.

#include <windows.h>
#include <stdio.h>
#include <string.h>

// Exit codes to identify which mitigation triggered
// NOTE: These are arbitrary values for our testing purposes
#define EXIT_DEP_BLOCKED      0xDE9     // 3561 decimal
#define EXIT_COOKIE_BLOCKED   0xC001E   // 786462 decimal
#define EXIT_CFG_BLOCKED      0xCF6     // 3318 decimal
#define EXIT_HEAP_BLOCKED     0xEA9     // 3753 decimal
#define EXIT_TEST_PASSED      0

// Test 1: DEP (should block shellcode execution)
// DEP violations ARE catchable via SEH (they're access violations)
void test_dep() {
    printf("\n=== Testing DEP ===\n");
    fflush(stdout);

    char shellcode[] = "\xCC\xC3";  // int3; ret (in .data section = NX)
    void (*func)() = (void(*)())shellcode;

    __try {
        func();  // Should crash (DEP blocks execution)
        printf("[-] DEP FAILED: Shellcode executed!\n");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[+] DEP OK: Shellcode blocked (Access Violation)\n");
    }
    fflush(stdout);
}

// Test 2: Stack Cookie - MUST run as separate process
// __fastfail() cannot be caught by SEH!
void test_stack_cookie_inner() {
    char buffer[64];
    printf("[*] Triggering stack cookie overflow...\n");
    fflush(stdout);
    memset(buffer, 'A', 200);  // Overflow corrupts cookie
    // Cookie check at function epilogue triggers __fastfail()
    // Process terminates with exit code 0xC0000409 - NOT catchable!
}

void test_stack_cookie() {
    printf("\n=== Testing Stack Cookie ===\n");
    printf("[*] NOTE: Cookie failures use __fastfail() - not SEH-catchable\n");
    printf("[*] Run 'mitigation_test_suite.exe --cookie' separately\n");
    printf("[*] Expected exit code: 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN)\n");
    fflush(stdout);
}

// Test 3: CFG - MUST run as separate process
// __fastfail(FAST_FAIL_GUARD_ICALL_CHECK_FAILURE) cannot be caught!
void test_cfg_inner() {
    printf("[*] Calling invalid address 0x41414141 via function pointer...\n");
    fflush(stdout);
    void (*func_ptr)() = (void(*)())0x41414141;
    func_ptr();  // CFG blocks, calls __fastfail(10)
}

void test_cfg() {
    printf("\n=== Testing CFG ===\n");
    printf("[*] NOTE: CFG failures use __fastfail() - not SEH-catchable\n");
    printf("[*] Run 'mitigation_test_suite.exe --cfg' separately\n");
    printf("[*] Expected exit code: 0x80000003 (STATUS_BREAKPOINT via __fastfail)\n");
    printf("[*] NOTE: /GS cookie failure = 0xC0000409, CFG failure = 0x80000003\n");
    printf("[*]       They use different __fastfail subcodes but same mechanism\n");
    fflush(stdout);
}

// Test 4: Heap Cookie (may or may not be catchable depending on failure mode)
void test_heap_protection() {
    printf("\n=== Testing Heap Protection ===\n");
    printf("[*] NOTE: Modern heap (Segment Heap) may not place chunks adjacently\n");
    fflush(stdout);

    __try {
        char *chunk1 = (char*)HeapAlloc(GetProcessHeap(), 0, 64);
        char *chunk2 = (char*)HeapAlloc(GetProcessHeap(), 0, 64);

        printf("[*] chunk1=%p, chunk2=%p, gap=%lld\n",
               chunk1, chunk2, (long long)(chunk2-chunk1));
        fflush(stdout);

        // Overflow - may or may not corrupt chunk2 depending on allocator
        memset(chunk1, 'A', 128);

        // Free may detect corruption (or may not, depending on heap layout)
        HeapFree(GetProcessHeap(), 0, chunk2);
        HeapFree(GetProcessHeap(), 0, chunk1);

        printf("[?] Heap test completed - corruption may not be adjacent\n");
        printf("    Use 'gflags /p /enable <exe> /full' for guaranteed detection\n");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[+] Heap Protection OK: Corruption detected\n");
    }
    fflush(stdout);
}

int main(int argc, char** argv) {
    // Allow running individual tests that will crash
    if (argc > 1) {
        if (strcmp(argv[1], "--cookie") == 0) {
            test_stack_cookie_inner();  // Will __fastfail -> exit 0xC0000409
            return 0;
        }
        if (strcmp(argv[1], "--cfg") == 0) {
            test_cfg_inner();  // Will __fastfail -> exit 0x80000003
            return 0;
        }
    }

    printf("=== Windows Mitigation Test Suite ===\n");
    printf("This tests each protection mechanism.\n");
    printf("\nIMPORTANT: /GS and CFG use __fastfail() which bypasses SEH!\n");
    printf("To test those, run with --cookie or --cfg flags separately.\n");
    fflush(stdout);

    test_dep();
    test_stack_cookie();  // Just prints instructions
    test_cfg();           // Just prints instructions
    test_heap_protection();

    printf("\n=== Partial Test Suite Complete ===\n");
    printf("\nTo fully test /GS and CFG, run:\n");
    printf("  .\\mitigation_test_suite.exe --cookie\n");
    printf("    Expected exit: 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN)\n");
    printf("  .\\mitigation_test_suite.exe --cfg\n");
    printf("    Expected exit: 0x80000003 (STATUS_BREAKPOINT via __fastfail)\n");
    fflush(stdout);

    return 0;
}
```

**Compile Test Suite**:

```bash
# Save to C:\Windows_Mitigations_Lab\src\mitigation_test_suite.c
cd C:\Windows_Mitigations_Lab

# Compile with ALL protections enabled
cl /GS /Zi /guard:cf src\mitigation_test_suite.c /Fe:bin\mitigation_test_suite.exe /link /NXCOMPAT /DYNAMICBASE /guard:cf /DEBUG

# Run main test suite (DEP + heap tests in-process)
.\bin\mitigation_test_suite.exe

# Run cookie test separately (process will terminate)
.\bin\mitigation_test_suite.exe --cookie
echo Exit code: %errorlevel%
# Expected: 0xC0000409 (-1073740791 decimal)

# Run CFG test separately (process will terminate)
.\bin\mitigation_test_suite.exe --cfg
echo Exit code: %errorlevel%
# Expected: 0x80000003 (-2147483645 decimal) OR 0xC0000409 (-1073740791 decimal)
# NOTE: Exit code varies by Windows version and WER (Windows Error Reporting) settings
#       - Older Windows: CFG uses __fastfail(10) -> int 0x29 -> exit 0x80000003
#       - Newer Windows: Both /GS and CFG may exit with 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN)
#       - The important part: Process terminates immediately, cannot be caught by SEH
```

### Practical Exercise

#### Task 1: Mitigation Blocking Demo

**Test Binary**: Use this vulnerable code to test each mitigation:

```c
// mitigation_demo.c - Vulnerable to multiple attack types
// Compile WITHOUT protections first, then WITH to compare
//
// NO PROTECTIONS: cl /GS- mitigation_demo.c /link /NXCOMPAT:NO /DYNAMICBASE:NO
// WITH PROTECTIONS: cl /GS /guard:cf mitigation_demo.c /link /NXCOMPAT /DYNAMICBASE /guard:cf

#include <windows.h>
#include <stdio.h>
#include <string.h>

// Vulnerability 1: Stack buffer overflow (tests DEP + Stack Cookies)
void vuln_stack(const char* input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds check!
    printf("Copied: %s\n", buffer);
}

// Vulnerability 2: Function pointer hijack (tests CFG)
typedef void (*callback_t)(void);
void safe_func() { printf("Safe function called\n"); fflush(stdout); }
void evil_func() {
    printf("HIJACKED! Function pointer redirected to evil_func.\n");
    printf("NOTE: CFG ALLOWS this because evil_func IS a valid function.\n");
    printf("CFG only blocks calls to non-function addresses (shellcode/ROP).\n");
    fflush(stdout);
}

struct target {
    char data[64];
    callback_t cb;
};

void vuln_cfg(const char* input) {
    struct target t;
    t.cb = safe_func;
    strcpy(t.data, input);  // Can overflow into cb pointer
    fflush(stdout);
    t.cb();  // CFG checks if target is valid
    // If overflow redirects to evil_func: CFG ALLOWS (valid function)
    // If overflow redirects to arbitrary address: CFG BLOCKS
}

// Vulnerability 3: Format string (tests ASLR effectiveness)
void vuln_format(const char* input) {
    printf(input);  // Direct format string
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <stack|cfg|format> <input>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "stack") == 0) vuln_stack(argv[2]);
    else if (strcmp(argv[1], "cfg") == 0) vuln_cfg(argv[2]);
    else if (strcmp(argv[1], "format") == 0) vuln_format(argv[2]);

    return 0;
}
```

**Pwntools-Style Exploit Testing Script**:

```python
#!/usr/bin/env python3
# mitigation_test_exploit.py - Test exploits against mitigations
# Run against both unprotected and protected binaries

import subprocess
import struct
import sys

def test_dep_bypass(binary):
    """Attempt shellcode execution - DEP should block"""
    print("\n" + "="*50)
    print("[TEST 1] DEP - Shellcode Execution")
    print("="*50)

    # Large overflow to ensure we hit the return address/cookie
    # Use printable characters to avoid string termination issues
    payload = "A" * 200

    try:
        result = subprocess.run([binary, "stack", payload],
                               capture_output=True, timeout=5)

        exit_code = result.returncode & 0xFFFFFFFF if result.returncode < 0 else result.returncode

        if exit_code == 0xC0000409 or result.returncode == -1073740791:  # Stack buffer overrun
            print("[+] STACK COOKIE BLOCKED: Buffer overrun detected")
            print(f"    Exit code: {hex(exit_code)} ({result.returncode})")
            return True
        elif exit_code == 0xC0000005:  # Access violation
            print("[+] DEP BLOCKED: Access violation (expected)")
            return True
        elif result.returncode == 0:
            print("[-] No crash detected - overflow may be too small")
            return False
        else:
            print(f"[-] Unexpected result: {hex(exit_code)} ({result.returncode})")
            return False
    except subprocess.TimeoutExpired:
        print("[*] Process hung - possible infinite loop")
        return False
    except Exception as e:
        print(f"[*] Exception: {e}")
        return False

def test_aslr_leak(binary):
    """Attempt to leak addresses - ASLR makes them unpredictable"""
    print("\n" + "="*50)
    print("[TEST 2] ASLR - Address Leak Attempt")
    print("="*50)

    # Format string to leak stack addresses
    payload = "%p." * 15

    try:
        result = subprocess.run([binary, "format", payload],
                               capture_output=True, text=True, timeout=5)

        leaks = result.stdout.split('.')
        print("[*] Leaked addresses:")

        addresses = []
        for leak in leaks:
            if leak.startswith('0x') or leak.startswith('00'):
                try:
                    addr = int(leak, 16)
                    if addr > 0x10000:
                        addresses.append(addr)
                        print(f"    {hex(addr)}")
                except:
                    pass

        if len(addresses) > 0:
            print(f"\n[*] Leaked {len(addresses)} addresses")
            print("[!] With ASLR, these addresses change each run")
            print("[*] Run again to verify randomization:")
            return True
        else:
            print("[-] No addresses leaked")
            return False
    except Exception as e:
        print(f"[*] Exception: {e}")
        return False

def test_cfg_bypass(binary):
    """Attempt function pointer hijack - CFG should block"""
    print("\n" + "="*50)
    print("[TEST 3] CFG - Function Pointer Hijack")
    print("="*50)

    # Large overflow to ensure we corrupt the function pointer
    # Use printable characters to avoid string termination
    payload = "A" * 200

    try:
        result = subprocess.run([binary, "cfg", payload],
                               capture_output=True, timeout=5)

        exit_code = result.returncode & 0xFFFFFFFF if result.returncode < 0 else result.returncode

        if exit_code == 0x80000003 or result.returncode == -2147483645:  # STATUS_BREAKPOINT (__fastfail)
            print("[+] CFG BLOCKED: __fastfail(10) -> exit 0x80000003")
            print(f"    Exit code: {hex(exit_code)} ({result.returncode})")
            return True
        elif exit_code == 0xC0000409 or result.returncode == -1073740791:  # /GS cookie
            print("[+] /GS BLOCKED: Cookie corruption before CFG check")
            print(f"    Exit code: {hex(exit_code)} ({result.returncode})")
            return True
        elif exit_code == 0xC0000005:
            print("[+] CRASHED: Access violation")
            print(f"    Exit code: {hex(exit_code)} ({result.returncode})")
            return False
        elif result.returncode == 0:
            print("[-] No crash detected - overflow may be too small")
            return False
        else:
            print(f"[-] Unexpected result: {hex(exit_code)} ({result.returncode})")
            return False
    except subprocess.TimeoutExpired:
        print("[*] Process hung - possible infinite loop")
        return False
    except Exception as e:
        print(f"[*] Exception: {e}")
        return False

def run_all_tests(binary):
    """Run all mitigation tests"""
    print("="*60)
    print(f"MITIGATION TEST SUITE - Target: {binary}")
    print("="*60)

    results = {
        "DEP": test_dep_bypass(binary),
        "ASLR": test_aslr_leak(binary),
        "CFG": test_cfg_bypass(binary)
    }

    print("\n" + "="*60)
    print("RESULTS SUMMARY")
    print("="*60)
    for mitigation, blocked in results.items():
        status = "BLOCKED" if blocked else "BYPASSED/UNKNOWN"
        color = "+" if blocked else "-"
        print(f"[{color}] {mitigation}: {status}")

    print("\n[*] Compare results between:")
    print("    - Binary compiled WITHOUT protections")
    print("    - Binary compiled WITH protections")
    print("    - The difference shows mitigation effectiveness!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mitigation_test_exploit.py <binary>")
        print("Example: python mitigation_test_exploit.py mitigation_demo.exe")
        sys.exit(1)

    run_all_tests(sys.argv[1])
```

**Compile and Test Instructions**:

```bash
# Save files
# - mitigation_demo.c -> C:\Windows_Mitigations_Lab\src\mitigation_demo.c
# - mitigation_test_exploit.py -> C:\Windows_Mitigations_Lab\exploits\mitigation_test_exploit.py

cd C:\Windows_Mitigations_Lab

# Step 1: Compile WITHOUT protections (vulnerable baseline)
cl /GS- src\mitigation_demo.c /Fe:bin\mitigation_demo_unprotected.exe /link /NXCOMPAT:NO /DYNAMICBASE:NO
# Flags explained:
#   /GS-           = Disable stack cookies
#   /NXCOMPAT:NO   = Disable DEP
#   /DYNAMICBASE:NO = Disable ASLR

# Step 2: Compile WITH all protections
cl /GS /Zi /guard:cf src\mitigation_demo.c /Fe:bin\mitigation_demo_protected.exe /link /NXCOMPAT /DYNAMICBASE /guard:cf /DEBUG
# Flags explained:
#   /GS            = Enable stack cookies
#   /guard:cf      = Enable CFG (compile-time)
#   /NXCOMPAT      = Enable DEP
#   /DYNAMICBASE   = Enable ASLR
#   /guard:cf      = Enable CFG (link-time)

# Step 3: Test unprotected binary (should be exploitable)
python exploits\mitigation_test_exploit.py bin\mitigation_demo_unprotected.exe

# Step 4: Test protected binary (mitigations should block)
python exploits\mitigation_test_exploit.py bin\mitigation_demo_protected.exe

# Step 5: Compare results
# Unprotected: Exploits may succeed or crash without mitigation detection
# Protected: Should see specific mitigation blocks (DEP, /GS, CFG)

# Manual testing examples:
# Test stack overflow
.\bin\mitigation_demo_protected.exe stack AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

# Test format string (leak addresses)
.\bin\mitigation_demo_protected.exe format "%p.%p.%p.%p.%p.%p.%p.%p"

# Test CFG (overflow function pointer)
.\bin\mitigation_demo_protected.exe cfg AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

**Testing CFG and /GS Separately**:

The above tests show /GS catching overflows before CFG is tested. To test them independently:

```c
// cfg_isolated_test.c - Test CFG without /GS interference
// Save to: C:\Windows_Mitigations_Lab\src\cfg_isolated_test.c

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*callback_t)(void);

void safe_function() {
    printf("[*] Safe function called\n");
}

void evil_function() {
    printf("[!] Evil function called (CFG allows - valid function)\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <valid|invalid|overflow>\n", argv[0]);
        return 1;
    }

    // Allocate on heap to avoid /GS stack cookies
    callback_t* func_ptr = (callback_t*)malloc(sizeof(callback_t));
    *func_ptr = safe_function;

    if (strcmp(argv[1], "valid") == 0) {
        // Test 1: Call valid function (should work)
        printf("[TEST] Calling valid function pointer\n");
        (*func_ptr)();

    } else if (strcmp(argv[1], "invalid") == 0) {
        // Test 2: Call invalid address (CFG should block)
        printf("[TEST] Calling invalid address 0x41414141\n");
        printf("[*] CFG should block this with __fastfail\n");
        fflush(stdout);
        *func_ptr = (callback_t)0x41414141;
        (*func_ptr)();  // CFG blocks here

    } else if (strcmp(argv[1], "overflow") == 0) {
        // Test 3: Overflow to corrupt pointer (no /GS on heap)
        printf("[TEST] Heap overflow to corrupt function pointer\n");

        // Enable Low-Fragmentation Heap for tighter packing
        HANDLE heap = GetProcessHeap();
        ULONG heapFragValue = 2;
        HeapSetInformation(heap, HeapCompatibilityInformation,
                          &heapFragValue, sizeof(heapFragValue));

        // Prime the LFH by allocating many same-sized chunks
        // This activates LFH for this size class (64 bytes)
        #define PRIME_COUNT 20
        void* priming[PRIME_COUNT];
        for (int i = 0; i < PRIME_COUNT; i++) {
            priming[i] = HeapAlloc(heap, 0, 64);
        }

        // Free every other one to create holes
        for (int i = 0; i < PRIME_COUNT; i += 2) {
            HeapFree(heap, 0, priming[i]);
        }

        // Now allocate our target chunks - should fill the holes adjacently
        char* buffer = (char*)HeapAlloc(heap, 0, 64);
        callback_t* target = (callback_t*)HeapAlloc(heap, 0, 64);
        *target = safe_function;

        printf("[*] buffer=%p, target=%p, distance=%lld bytes\n",
               buffer, target, (long long)((char*)target - buffer));

        long long distance = (long long)((char*)target - buffer);
        if (distance > 0 && distance <= 128) {
            printf("[+] Chunks are adjacent! Overflow will corrupt function pointer\n");
        } else if (distance < 0 && distance >= -128) {
            printf("[!] Target is BEFORE buffer (distance=%lld)\n", distance);
            printf("[*] Overflow won't reach it, but this shows heap layout\n");
        } else {
            printf("[!] Chunks not adjacent (distance=%lld bytes)\n", distance);
            printf("[*] Modern heap security: randomization prevents reliable overflow\n");
        }

        // Overflow buffer to corrupt target function pointer
        // Fill with pattern that creates invalid address (0x4141414141414141)
        if (distance > 0 && distance <= 128) {
            printf("[*] Overflowing buffer to corrupt function pointer...\n");
            memset(buffer, 0x41, distance + 8);  // Overflow exactly to target
        } else {
            printf("[*] Attempting overflow anyway (for demonstration)...\n");
            memset(buffer, 0x41, 128);
        }

        printf("[*] Calling function pointer (CFG will check validity)...\n");
        fflush(stdout);
        (*target)();  // If corrupted to 0x4141..., CFG blocks with __fastfail

        printf("[*] Function call succeeded - pointer was not corrupted\n");

        // Cleanup
        HeapFree(heap, 0, buffer);
        HeapFree(heap, 0, target);
        for (int i = 1; i < PRIME_COUNT; i += 2) {
            HeapFree(heap, 0, priming[i]);
        }
    }

    free(func_ptr);
    return 0;
}
```

```bash
# Compile CFG-only test (no /GS to avoid interference)
cl /GS- /Zi /guard:cf src\cfg_isolated_test.c /Fe:bin\cfg_isolated_test.exe /link /guard:cf /DEBUG

# Test 1: Valid function call (should work)
.\bin\cfg_isolated_test.exe valid

# Test 2: Invalid address (CFG should block)
.\bin\cfg_isolated_test.exe invalid
echo Exit code: %errorlevel%
# Expected: -1073740791 (0xC0000409) or -2147483645 (0x80000003)
# CFG detected invalid function pointer and called __fastfail

# Test 3: Heap overflow (corrupts adjacent function pointer)
.\bin\cfg_isolated_test.exe overflow
echo Exit code: %errorlevel%
# Expected behaviors:
#   - If chunks adjacent: CFG blocks corrupted pointer -> exit -1073740791
#   - If chunks not adjacent: Safe function called (no corruption)
# Note: LFH packing is probabilistic - run multiple times if needed
# You can also run in a loop to see CFG catch it:
for /L %i in (1,1,10) do @(.\bin\cfg_isolated_test.exe overflow 2>nul && echo Run %i: No crash) || echo Run %i: CFG BLOCKED
```

```bash
# Compile /GS-only test (no CFG to avoid interference)
cl /GS /Zi src\mitigation_demo.c /Fe:bin\gs_isolated_test.exe /link /NXCOMPAT /DYNAMICBASE /DEBUG

# Test stack overflow (should trigger /GS)
.\bin\gs_isolated_test.exe stack AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
echo Exit code: %errorlevel%
# Expected: -1073740791 (0xC0000409 - STATUS_STACK_BUFFER_OVERRUN)
```

### Task 2: Audit two systems and compare security postures

1. **System A: Default Windows 10**
   - Run mitigation audit script
   - Document all findings
   - Test binaries for protections

2. **System B: Hardened Windows 11**
   - Enable ALL mitigations:
     - VBS + HVCI
     - Credential Guard
     - Exploit Protection policies
     - CET (if supported)
   - Run same audit
   - Compare results

3. **Binary Analysis**:
   - Analyze 10 Windows binaries
   - Check for all protections
   - Document which lack protections

4. **Exploit Testing**:
   - Take Week 5 exploits
   - Test against hardened system
   - Document which protections block which exploits

5. **Final Report**:

   ```markdown
   # Windows Security Audit Report

   ## System Configuration

   - OS Version:
   - Patch Level:
   - Hardware:

   ## Mitigation Status

   | Mitigation | Status | Notes               |
   | ---------- | ------ | ------------------- |
   | DEP        | +      | Opt-Out policy      |
   | ASLR       | +      | High Entropy on x64 |
   | CFG        | +      | System-wide         |
   | CET        | -      | CPU not supported   |
   | VBS        | +      | Running with HVCI   |
   | Cred Guard | +      | Active              |

   ## Binary Analysis Results

   [List of 10 binaries with protection status]

   ## Exploit Test Results

   [Which Week 5 exploits were blocked]

   ## Recommendations

   [Steps to improve security posture]
   ```

**Success Criteria**:

- Comprehensive audit completed
- All mitigations tested
- Binary analysis for 10+ executables
- Week 5 exploits blocked
- Professional security report generated

### Discussion Questions

1. **Why is "Enforcement" (Blocking) better than "Audit" (Logging), but harder to implement?**

   > Enforcement prevents the attack in real-time. Audit only logs that it WOULD have
   > been blocked — the attack still succeeds. But enforcement risks breaking legitimate
   > applications. The safe approach: deploy in Audit mode first, analyze event logs
   > (Event ID 3076) for false positives, then switch to Enforcement (Event ID 3077)
   > after validating no business-critical apps are affected.

2. **If you were a red teamer, which mitigation would annoy you the most?**

   > CET (shadow stacks) — because it's hardware-enforced with no known generic bypass.
   > CFG can be bypassed via valid-function redirects (proven in Day 2-3). ASLR can be
   > defeated with info leaks. /GS can be bypassed with info disclosure + partial
   > overwrites (proven in Day 2). But CET has no "allowed" bypass case — you must
   > abandon ROP entirely and pivot to data-only attacks.

3. **How does the "Assume Breach" mentality relate to VBS/Credential Guard?**
   > "Assume Breach" means planning for the scenario where an attacker already has
   > admin/SYSTEM access. Without Credential Guard, SYSTEM can dump all domain
   > credentials. With Credential Guard, even SYSTEM cannot access VTL 1 secrets.
   > This limits lateral movement even after full compromise of a single machine.

### Key Takeaways

1. **Exit codes distinguish mitigations**: /GS cookie failure = `0xC0000409`, CFG failure =
   `0x80000003`, DEP violation = `0xC0000005`, heap corruption = `0xC0000374`. Knowing
   these codes lets you identify WHICH mitigation blocked an exploit in crash analysis.
2. **\_\_fastfail() bypasses SEH entirely**: Both /GS and CFG use `__fastfail()` which
   executes `int 0x29` — trapping directly to the kernel. No `__try/__except` handler
   can catch it. Test these mitigations as separate processes and check exit codes.
3. **Audit tools are essential**: `dumpbin /headers`, `BinSkim`, and `Get-ProcessMitigation`
   reveal which binaries lack protections. A single unprotected DLL in your process can
   be the entry point for an exploit.
4. **CFG coarse-grained limitation persists in testing**: The mitigation_demo's `evil_func`
   is a valid function entry point — CFG allows the call. Only calls to non-function
   addresses (shellcode, ROP gadgets, `0x41414141`) are blocked.
5. **System-wide policy overrides binary preferences**: Even if a binary was compiled
   with `/NXCOMPAT:NO`, system-level `Set-ProcessMitigation` can force DEP on. This is
   how security teams protect legacy binaries without recompilation.
6. **BinSkim is the modern replacement for BinScope**: BinSkim checks 15+ security rules
   and integrates with CI/CD via SARIF output. Use it as a build gate.
7. **Windows 11 24H2 Hotpatching changes forensics**: Code pages in memory may not match
   on-disk binaries after hotpatch application. This affects both defenders (memory
   analysis) and attackers (persistence assumptions).

