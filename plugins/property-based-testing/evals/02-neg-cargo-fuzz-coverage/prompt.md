---
max_turns: 6
timeout_seconds: 300
allowed_tools: [Skill, Read]
model: opus
runs: 3
---
our cargo-fuzz target for the TLV decoder plateaus around 40% coverage after an hour
and libfuzzer stops reporting new units. i think everything is bouncing off the
length-prefix check at the top of the decoder. whats the fix here - a custom mutator,
or just a better seed corpus?
