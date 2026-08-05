// ML-DSA-87 signing helpers (Swift). Expected verdicts live in expectations.json.
// @_cdecl keeps the emitted symbol names readable instead of Swift-mangled.

/// High bits of an expanded-private-key polynomial coefficient.
@_cdecl("ct_high_bits")
public func ctHighBits(keyCoef: Int32, gamma2: Int32) -> Int32 {
    return keyCoef / (2 * gamma2)
}

/// Whole blocks in an encoded signature buffer.
@_cdecl("ct_block_count")
public func ctBlockCount(sigLen: Int, blockLen: Int) -> Int {
    return sigLen / blockLen
}

/// Compare a received authentication tag against the computed one.
@_cdecl("ct_tag_matches")
public func ctTagMatches(receivedTag: UnsafePointer<UInt8>, computedTag: UnsafePointer<UInt8>, len: Int) -> Int32 {
    for i in 0..<len {
        if receivedTag[i] != computedTag[i] {
            return 0
        }
    }
    return 1
}

/// Reject signatures whose encoded length is not a whole number of blocks.
@_cdecl("ct_length_is_valid")
public func ctLengthIsValid(sigLen: Int, blockLen: Int) -> Int32 {
    if blockLen == 0 {
        return 0
    }
    return sigLen % blockLen == 0 ? 1 : 0
}
