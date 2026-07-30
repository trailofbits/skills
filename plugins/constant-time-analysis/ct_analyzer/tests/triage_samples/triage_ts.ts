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
