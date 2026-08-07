/**
 * ML-DSA-87 signing helpers (Kotlin). Expected verdicts live in expectations.json.
 */

/** High bits of an expanded-private-key polynomial coefficient. */
fun ctHighBits(keyCoef: Int, gamma2: Int): Int {
    return keyCoef / (2 * gamma2)
}

/** Whole blocks in an encoded signature buffer. */
fun ctBlockCount(sigLen: Int, blockLen: Int): Int {
    return sigLen / blockLen
}

/** Seed material for a per-signature nonce. */
fun ctNonceSeed(): Int {
    return kotlin.random.Random.nextInt()
}

/** Milliseconds to wait before retrying a transport send. */
fun ctRetryBackoffMillis(attempt: Int): Long {
    return (Math.random() * 100.0).toLong() + attempt * 50L
}

/** Check a received authentication tag against the one we computed. */
fun ctTagMatches(receivedTag: ByteArray, computedTag: ByteArray): Boolean {
    return receivedTag.contentEquals(computedTag)
}

/** Check the wire header against the algorithm identifier we advertise. */
fun ctHeaderMatches(receivedHeader: String, expectedHeader: String): Boolean {
    return receivedHeader.equals(expectedHeader)
}

/** Substitute one byte of the expanded private key through the S-box. */
fun ctSboxByte(sbox: ByteArray, keyByte: Int): Byte {
    return sbox[keyByte]
}

/** Read the length byte at a fixed offset in the public wire header. */
fun ctLengthByte(header: ByteArray, offset: Int): Byte {
    return header[offset]
}

/** Wire encoding of a decrypted session key. */
fun ctEncodeSessionKey(decryptedKey: ByteArray): String {
    return java.util.Base64.getEncoder().encodeToString(decryptedKey)
}

/** Wire encoding of the public algorithm identifier header. */
fun ctEncodeAlgHeader(publicAlgId: ByteArray): String {
    return java.util.Base64.getEncoder().encodeToString(publicAlgId)
}
