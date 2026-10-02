# Platform-specific rule decisions

Use this before choosing format checks or indicators. A suspicious feature is
not a unique malware signature; require corroboration and test clean files.

| Platform | Format guard | Common/weak alone | Candidates to investigate |
| --- | --- | --- | --- |
| Windows PE | `uint16(0) == 0x5A4D` | API names, Windows paths | Distinctive mutexes, PDB paths, configuration markers |
| macOS Mach-O | Known endian-specific Mach-O/fat magic | Common Objective-C methods | Family-specific persistence paths and behavior strings |
| JavaScript/Node | Usually no binary magic | `require`, `fetch`, `axios` | Distinctive obfuscation and eval/decode chains |
| npm/pip packages | Package format/context | `postinstall`, `dependencies` | Specific exfiltration destinations plus credential access |
| Office OOXML | ZIP prefix `uint32(0) == 0x04034B50` | VBA keywords; ZIP magic alone | Document structure, auto-execution and distinctive payload evidence |
| VS Code extensions | Extension context | `vscode.workspace` | Unusual activation and hidden file access with corroboration |
| Chrome extensions | `crx` module | Ordinary Chrome APIs | Permission combinations and manifest anomalies |
| Android DEX | `dex` module | Standard DEX structures | Unusual classes/reflection and relevant permissions |

`uintNN()` reads little-endian. Test every magic predicate on real sample bytes.
Little-endian Mach-O values include `0xFEEDFACE` (32-bit) and `0xFEEDFACF` (64-bit);
opposite-endian values are `0xCEFAEDFE` and `0xCFFAEDFE`. For fat bytes `CA FE BA BE`,
use `uint32be(0) == 0xCAFEBABE` or `uint32(0) == 0xBEBAFECA`. A magic match does not
by itself establish a valid complete file or maliciousness.

## macOS candidates

Investigate keylogger-related APIs (`CGEventTapCreate`, `kCGEventKeyDown`), SSH
tunnel messages, LaunchAgents/LaunchDaemons paths, and keychain-access commands.
All can occur legitimately: combine family-specific library/configuration markers
with independent behavior evidence. Use magic and strings when the deployed
engine lacks the required structured-format support; do not assume every engine
version has the same modules.

## JavaScript choices

- npm packages: examine lifecycle hooks and the combination of credential access,
  network use and a specific exfiltration destination.
- Chrome extensions: inspect module-supported manifest/permission structure.
- Other extensions: use manifest patterns and background-script behavior.
- Standalone JavaScript: examine distinctive names, packed payloads, eval/decode
  chains and obfuscation, while checking benign obfuscators.
- Minified bundles: prefer stable URLs or magic values; function names can be
  mangled. `process.env`, `Buffer`, and `crypto` alone are not malicious.
- Ethereum selectors must be identified correctly: `a9 05 9c bb` is
  `transfer(address,uint256)`; `70 a0 82 31` is `balanceOf(address)`. Neither is
  independently evidence of malicious behavior.

## Engine feature checks

Preserve the feature-specific version requirements when using private patterns
(YARA-X 1.3.0+), inline warning suppression (1.4.0+), or numeric underscores (1.5.0+).
Use warning suppression only after understanding the warning, not as a substitute
for fixing a slow pattern. `$_unused` suppresses an unused-pattern warning;
`private $helper` hides a matching pattern from displayed results.

The `crx` module requires 1.5.0+; `crx.permhash()` and the newer `dex` module require
1.11.0+. Legacy YARA's DEX API is different. Read the module references linked from
SKILL.md before choosing APIs, and check the actual deployed engine with `yr --version`
and `yr check`; successful compilation on a newer workstation does not prove
compatibility with an older deployment.
