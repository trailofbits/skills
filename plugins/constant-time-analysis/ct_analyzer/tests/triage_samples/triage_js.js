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

/** Check a received authentication tag against the one we computed. */
function ctTagMatches(receivedTag, computedTag) {
  return receivedTag.indexOf(computedTag) === 0;
}

/** Check the wire header against the algorithm identifier we advertise. */
function ctHeaderMatches(receivedHeader, expectedHeader) {
  return receivedHeader.indexOf(expectedHeader) === 0;
}

/** Substitute one byte of the expanded private key through the S-box. */
function ctSboxByte(sbox, keyByte) {
  return sbox[keyByte];
}

/** Read the length byte at a fixed offset in the public wire header. */
function ctLengthByte(header, offset) {
  return header[offset];
}

/** Wire encoding of a decrypted session key. */
function ctEncodeSessionKey(decryptedKey) {
  return btoa(decryptedKey);
}

/** Wire encoding of the public algorithm identifier header. */
function ctEncodeAlgHeader(publicAlgId) {
  return btoa(publicAlgId);
}

module.exports = {
  ctHighBits,
  ctBlockCount,
  ctNonceSeed,
  ctRetryBackoffMillis,
  ctTagMatches,
  ctHeaderMatches,
  ctSboxByte,
  ctLengthByte,
  ctEncodeSessionKey,
  ctEncodeAlgHeader,
};
