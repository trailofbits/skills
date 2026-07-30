# ML-DSA-87 signing helpers (Ruby). Expected verdicts live in expectations.json.

# High bits of an expanded-private-key polynomial coefficient.
def ct_high_bits(key_coef, gamma2)
  key_coef / (2 * gamma2)
end

# Whole blocks in an encoded signature buffer.
def ct_block_count(sig_len, block_len)
  sig_len / block_len
end

# Seed material for a per-signature nonce.
def ct_nonce_seed
  rand(2**64)
end

# Milliseconds to wait before retrying a transport send.
def ct_retry_backoff_millis(attempt)
  rand(100) + attempt * 50
end
