/**
 * ML-DSA-87 signing helpers (JavaScript). Expected verdicts live in expectations.json.
 */

/** High bits of an expanded-private-key polynomial coefficient. */
function ctHighBits(keyCoef, gamma2) {
  return Math.trunc(keyCoef / (2 * gamma2));
}

/** Whole blocks in an encoded signature buffer. */
function ctBlockCount(sigLen, blockLen) {
  return Math.trunc(sigLen / blockLen);
}

/** Seed material for a per-signature nonce. */
function ctNonceSeed() {
  return Math.random();
}

/** Milliseconds to wait before retrying a transport send. */
function ctRetryBackoffMillis(attempt) {
  return Math.random() * 100 + attempt * 50;
}

module.exports = { ctHighBits, ctBlockCount, ctNonceSeed, ctRetryBackoffMillis };
