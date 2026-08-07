//! ML-DSA-87 signing helpers (Rust). Expected verdicts live in expectations.json.
//! `#[no_mangle]` keeps the emitted symbol names readable.

/// High bits of an expanded-private-key polynomial coefficient.
#[no_mangle]
pub extern "C" fn ct_high_bits(key_coef: i32, gamma2: i32) -> i32 {
    key_coef / (2 * gamma2)
}

/// Whole blocks in an encoded signature buffer.
#[no_mangle]
pub extern "C" fn ct_block_count(sig_len: usize, block_len: usize) -> usize {
    sig_len / block_len
}

/// Compare a received authentication tag against the computed one.
#[no_mangle]
pub extern "C" fn ct_tag_matches(received_tag: *const u8, computed_tag: *const u8, len: usize) -> i32 {
    for i in 0..len {
        unsafe {
            if *received_tag.add(i) != *computed_tag.add(i) {
                return 0;
            }
        }
    }
    1
}

/// Reject signatures whose encoded length is not a whole number of blocks.
#[no_mangle]
pub extern "C" fn ct_length_is_valid(sig_len: usize, block_len: usize) -> i32 {
    if block_len == 0 {
        return 0;
    }
    if sig_len % block_len != 0 {
        return 0;
    }
    1
}
