/**
 * ML-DSA-87 signing helpers (TypeScript). Expected verdicts live in expectations.json.
 */

/** High bits of an expanded-private-key polynomial coefficient. */
export function ctHighBits(keyCoef: number, gamma2: number): number {
  return Math.trunc(keyCoef / (2 * gamma2));
}

/** Whole blocks in an encoded signature buffer. */
export function ctBlockCount(sigLen: number, blockLen: number): number {
  return Math.trunc(sigLen / blockLen);
}

/** Seed material for a per-signature nonce. */
export function ctNonceSeed(): number {
  return Math.random();
}

/** Milliseconds to wait before retrying a transport send. */
export function ctRetryBackoffMillis(attempt: number): number {
  return Math.random() * 100 + attempt * 50;
}

/** Check a received authentication tag against the one we computed. */
export function ctTagMatches(receivedTag: string, computedTag: string): boolean {
  return receivedTag.indexOf(computedTag) === 0;
}

/** Check the wire header against the algorithm identifier we advertise. */
export function ctHeaderMatches(receivedHeader: string, expectedHeader: string): boolean {
  return receivedHeader.indexOf(expectedHeader) === 0;
}

/** Substitute one byte of the expanded private key through the S-box. */
export function ctSboxByte(sbox: Uint8Array, keyByte: number): number {
  return sbox[keyByte];
}

/** Read the length byte at a fixed offset in the public wire header. */
export function ctLengthByte(header: Uint8Array, offset: number): number {
  return header[offset];
}

/** Wire encoding of a decrypted session key. */
export function ctEncodeSessionKey(decryptedKey: string): string {
  return btoa(decryptedKey);
}

/** Wire encoding of the public algorithm identifier header. */
export function ctEncodeAlgHeader(publicAlgId: string): string {
  return btoa(publicAlgId);
}
