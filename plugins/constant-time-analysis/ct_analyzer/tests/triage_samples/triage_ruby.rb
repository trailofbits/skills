# ML-DSA-87 signing helpers (Ruby). Expected verdicts live in expectations.json.

require 'base64'

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

# Check a received authentication tag against the one we computed.
def ct_tag_matches(received_tag, computed_tag)
  received_tag == computed_tag
end

# Check the wire header against the algorithm identifier we advertise.
def ct_header_matches(received_header, expected_header)
  received_header == expected_header
end

# Substitute one byte of the expanded private key through the S-box.
def ct_sbox_byte(sbox, key_byte)
  sbox[key_byte]
end

# Read the length byte at a fixed offset in the public wire header.
def ct_length_byte(header, offset)
  header[offset]
end

# Wire encoding of a decrypted session key.
def ct_encode_session_key(decrypted_key)
  Base64.encode64(decrypted_key)
end

# Wire encoding of the public algorithm identifier header.
def ct_encode_alg_header(public_alg_id)
  Base64.encode64(public_alg_id)
end
