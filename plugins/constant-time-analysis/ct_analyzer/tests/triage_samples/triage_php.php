<?php
/**
 * ML-DSA-87 signing helpers (PHP). Expected verdicts live in expectations.json.
 */

/** High bits of an expanded-private-key polynomial coefficient. */
function ct_high_bits(int $key_coef, int $gamma2): int
{
    return intdiv($key_coef, 2 * $gamma2);
}

/** Whole blocks in an encoded signature buffer. */
function ct_block_count(int $sig_len, int $block_len): int
{
    return (int) ($sig_len / $block_len);
}

/** Seed material for a per-signature nonce. */
function ct_nonce_seed(): int
{
    return mt_rand();
}

/** Milliseconds to wait before retrying a transport send. */
function ct_retry_backoff_millis(int $attempt): int
{
    return rand(0, 100) + $attempt * 50;
}

/** Wire encoding of a decrypted session key. */
function ct_encode_session_key(string $decrypted_key): string
{
    return base64_encode($decrypted_key);
}

/** Wire encoding of the public algorithm identifier header. */
function ct_encode_alg_header(string $public_alg_id): string
{
    return base64_encode($public_alg_id);
}

/** Check a received authentication tag against the one we computed. */
function ct_tag_matches(string $received_tag, string $computed_tag): bool
{
    return strcmp($received_tag, $computed_tag) === 0;
}

/** Check the wire header against the algorithm identifier we advertise. */
function ct_header_matches(string $received_header, string $expected_header): bool
{
    return strcmp($received_header, $expected_header) === 0;
}

/** Substitute one byte of the expanded private key through the S-box. */
function ct_sbox_byte(string $sbox, int $key_byte): string
{
    return $sbox[$key_byte];
}

/** Read the length byte at a fixed offset in the public wire header. */
function ct_length_byte(string $header, int $offset): string
{
    return $header[$offset];
}
