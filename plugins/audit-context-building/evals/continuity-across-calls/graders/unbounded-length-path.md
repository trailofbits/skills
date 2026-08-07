---
type: llm
weight: 1
---

The bound that makes `parse_record`'s `memcpy` safe lives two calls away, in `decode_length`, and only on one
of its two branches. Passing requires having traced that.

Pass only if the response states, in whatever wording, that the `FLAG_EXTENDED` branch of `decode_length`
returns success with a length that was never compared against `MAX_PAYLOAD`, and connects that to
`parse_record`: the `memcpy` length is therefore unbounded on that path. Observing that the extended branch
composes its length from the flags high nibble and so can far exceed `MAX_PAYLOAD` — up to roughly 2^20 —
is a stronger form of the same claim and also passes.

Fail if the response:
- describes only `parse_record`, or stops at `validate_header` without reading `decode_length`;
- reports that the length is bounded to `MAX_PAYLOAD`, or repeats that promise from `proto.h` or from
  `validate_header`'s contract without noting one branch does not deliver it;
- notes that `decode_length` contains a `MAX_PAYLOAD` check without observing that the extended branch
  returns before reaching it;
- treats the `!= 0` return-value check in `parse_record` as establishing the bound;
- mentions `decode_length` only as a name in a call list.

Other true observations — that `buf_len` is never checked against `HEADER_LEN + payload_len`, that `dst`'s
size is a caller contract, that `h.flags` is untrusted — are fine but do not by themselves satisfy this
grader. The required claim is the branch that skips the bound.
