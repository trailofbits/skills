/**
 * ML-DSA-87 signing helpers (Java). Expected verdicts live in expectations.json.
 */
public class TriageJava {

    /** High bits of an expanded-private-key polynomial coefficient. */
    public static int ctHighBits(int keyCoef, int gamma2) {
        return keyCoef / (2 * gamma2);
    }

    /** Whole blocks in an encoded signature buffer. */
    public static int ctBlockCount(int sigLen, int blockLen) {
        return sigLen / blockLen;
    }

    /** Seed material for a per-signature nonce. */
    public static long ctNonceSeed() {
        return new java.util.Random().nextLong();
    }

    /** Milliseconds to wait before retrying a transport send. */
    public static long ctRetryBackoffMillis(int attempt) {
        return (long) (Math.random() * 100.0) + (attempt * 50L);
    }
}
