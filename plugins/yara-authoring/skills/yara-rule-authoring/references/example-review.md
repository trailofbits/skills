# Reviewing the historical examples

The attributed files in `examples/` illustrate detection ideas, not a promise of
current formatting, zero diagnostics, or production accuracy. Review them before
reuse. No malware/goodware corpus scan was performed for this documentation check;
syntax and lint results alone cannot establish detection quality.

All five files were checked without modification using the combined review
helper, YARA-X CLI 1.20.0 and Python yara-x 1.20.0. Results below are exit statuses:
0 means that check's pass criterion, not necessarily absence of informational
messages. Nonzero statuses are deliberately retained, not suppressed.

| Example | Syntax | Format | Lint | Atoms | What requires attention |
| --- | ---: | ---: | ---: | ---: | --- |
| `MAL_Mac_ProtonRAT_Jan25.yar` | 0 | 1 | 0 | 1 | Formatting; `MachO` helper naming warning W001; `nocase` / `ascii wide` information requires sample evidence before keeping both modes. |
| `MAL_NPM_SupplyChain_Jan25.yar` | 0 | 1 | 0 | 0 | Formatting still differs from the current formatter; detection behavior is not corpus-validated here. |
| `MAL_Win_Remcos_Jan25.yar` | 0 | 1 | 0 | 0 | Formatting still differs from the current formatter; detection behavior is not corpus-validated here. |
| `SUSP_CRX_SuspiciousPermissions.yar` | 2 | 1 | 0 | 0 | The CLI warns that example permission hashes are 32 characters but `crx.permhash()` returns 64; those placeholder comparisons cannot match. Replace them with real observed hashes before use. Python lint/atom success does not erase the CLI warning. |
| `SUSP_JS_Obfuscation_Jan25.yar` | 0 | 1 | 0 | 1 | Formatting; `$magic3` has a 50/100 atom score; several `nocase` uses need justification. |

For production work, adapt a copy, preserve attribution, address these findings,
then test representative malicious and clean inputs. Do not disable checks or
invent indicators merely to make this table green. Rule behavior was intentionally
not rewritten here without the relevant samples.
