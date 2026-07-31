"""ML-DSA-87 signing helpers (Python). Expected verdicts live in expectations.json."""

import base64
import random


def ct_high_bits(key_coef: int, gamma2: int) -> int:
    """High bits of an expanded-private-key polynomial coefficient."""
    return key_coef // (2 * gamma2)


def ct_block_count(sig_len: int, block_len: int) -> int:
    """Whole blocks in an encoded signature buffer."""
    return sig_len // block_len


def ct_nonce_seed() -> int:
    """Seed material for a per-signature nonce."""
    return random.randint(0, 2**64 - 1)


def ct_retry_backoff_millis(attempt: int) -> float:
    """Milliseconds to wait before retrying a transport send."""
    return random.random() * 100 + attempt * 50


def ct_tag_matches(received_tag: bytes, computed_tag: bytes) -> bool:
    """Check a received authentication tag against the one we computed."""
    return received_tag == computed_tag


def ct_header_matches(received_header: bytes, expected_header: bytes) -> bool:
    """Check the wire header against the algorithm identifier we advertise."""
    return received_header == expected_header


def ct_sbox_byte(sbox: bytes, key_byte: int) -> int:
    """Substitute one byte of the expanded private key through the S-box."""
    return sbox[key_byte]


def ct_length_byte(header: bytes, offset: int) -> int:
    """Read the length byte at a fixed offset in the public wire header."""
    return header[offset]


def ct_encode_session_key(decrypted_key: bytes) -> str:
    """Wire encoding of a decrypted session key."""
    return base64.b64encode(decrypted_key).decode()


def ct_encode_alg_header(public_alg_id: bytes) -> str:
    """Wire encoding of the public algorithm identifier header."""
    return base64.b64encode(public_alg_id).decode()
