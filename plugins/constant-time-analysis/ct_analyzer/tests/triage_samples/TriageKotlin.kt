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
