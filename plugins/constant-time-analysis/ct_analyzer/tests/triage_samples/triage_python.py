"""ML-DSA-87 signing helpers (Python). Expected verdicts live in expectations.json."""

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
