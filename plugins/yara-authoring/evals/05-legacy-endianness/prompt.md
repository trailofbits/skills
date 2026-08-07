---
max_turns: 40
timeout_seconds: 900
allowed_tools: [Skill, Read, Grep, Glob, Bash, Write]
model: sonnet
runs: 3
---
I'm moving an old ruleset off legacy YARA. This rule passes `yr check` cleanly, but the
two magic-byte branches never fire on real files and I can't work out why. The string
match works fine on its own.

```yara
rule OLD_MultiFormat_Dropper
{
    strings:
        $cfg = "dropper_cfg_v2" ascii
    condition:
        (uint32(0) == 0xCAFEBABE or uint32(0) == 0x504B0304) and $cfg
}
```

The two formats are Mach-O universal (fat) binaries and ZIP-based Office documents, and I
need both kept. Fix the condition so it matches real files, save the corrected rule as
`migrated.yar` in the current directory, and tell me what was wrong.
