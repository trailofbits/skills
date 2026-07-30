---
type: llm
focus: last_message
weight: 1
---
Score PASS only if the response proposes at least one concrete alternative to
string-based detection, drawn from this list:

- Import hash / imphash clustering
- Section entropy or `math.entropy()` on a specific range
- PE section anomalies — unusual section names, sizes, or characteristics
- Rich header or PE header/timestamp/version-resource metadata
- Detecting the packer itself, or targeting the unpacked payload instead
- Obtaining additional samples or the unpacked layer in order to extract better strings

The alternative must be named specifically. A vague suggestion to "look at the file
structure", "use the PE module", or "find better indicators" without naming which
property to use does NOT count.

Score FAIL if the response only offers string-based fixes, or only tells the user their
strings are bad without proposing any path forward.
