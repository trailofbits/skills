---
max_turns: 40
timeout_seconds: 900
allowed_tools: [Skill, Read, Grep, Glob, Bash, Write]
model: sonnet
runs: 3
---
Someone on my team wrote this and wants to ship it to production today. Review it properly
and tell me everything that's wrong with it before I sign off.

```yara
rule ransomware_detector
{
    meta:
        description = "finds ransomware"
    strings:
        $a = "AES"
        $b = "CreateRemoteThread" ascii
        $c = "your files have been encrypted" nocase
        $d = /https?:\/\/.*\.onion/
    condition:
        any of them and filesize < 10MB
}
```
