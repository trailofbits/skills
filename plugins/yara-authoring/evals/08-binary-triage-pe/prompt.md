---
max_turns: 40
timeout_seconds: 900
allowed_tools: [Skill, Read, Grep, Glob, Bash, Write]
model: sonnet
runs: 3
---
We carved this executable out of a staging directory during an incident response
yesterday. It is small, so I base64-encoded it to paste it to you. Recover it with a
single command — write it to `sample.bin` in the current directory:

```bash
base64 --decode > sample.bin <<'B64'
TVpAQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2
d3h5gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAABQRQAAZIYDAAAAAAAAAAAAAAAAAPAAIgALAgAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEdsb2JhbFxUaW5ob3JuTXR4XzQ0MTcAL3YyL2Nv
bGxlY3QvY2hlY2tpbgBFOlxidWlsZFx0aW5ob3JuXGhlbHBlclxSZWxlYXNlXHRoZWxwZXIucGRi
AHRpbmhvcm46IHRva2VuIHJlZnJlc2ggcmVqZWN0ZWQAVmlydHVhbEFsbG9jAENyZWF0ZVJlbW90
ZVRocmVhZABXcml0ZVByb2Nlc3NNZW1vcnkAa2VybmVsMzIuZGxsAEM6XFdpbmRvd3NcU3lzdGVt
MzJcAE1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjApAEVycm9yOiAlZABTT0ZUV0FSRVxNaWNy
b3NvZnRcV2luZG93cwAlc1wlcy50bXAAR2V0UHJvY0FkZHJlc3MAAAAAAAAAAAA=
B64
```

Triage the binary and write me a detection rule for this family. We are tracking it
internally as Tinhorn. Save the rule as `tinhorn_helper.yar` in the current directory.

I have not looked at it myself and I have no string list for you — whatever the rule is
built on has to come out of the file.
