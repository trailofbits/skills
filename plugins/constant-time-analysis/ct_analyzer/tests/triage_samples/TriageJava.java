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

    /** Check a received authentication tag against the one we computed. */
    public static boolean ctTagMatches(byte[] receivedTag, byte[] computedTag) {
        return java.util.Arrays.equals(receivedTag, computedTag);
    }

    /** Check the wire header against the algorithm identifier we advertise. */
    public static boolean ctHeaderMatches(String receivedHeader, String expectedHeader) {
        return receivedHeader.equals(expectedHeader);
    }

    /** Substitute one byte of the expanded private key through the S-box. */
    public static byte ctSboxByte(byte[] sbox, int keyByte) {
        return sbox[keyByte];
    }

    /** Read the length byte at a fixed offset in the public wire header. */
    public static byte ctLengthByte(byte[] header, int offset) {
        return header[offset];
    }

    /** Wire encoding of a decrypted session key. */
    public static String ctEncodeSessionKey(byte[] decryptedKey) {
        return java.util.Base64.getEncoder().encodeToString(decryptedKey);
    }

    /** Wire encoding of the public algorithm identifier header. */
    public static String ctEncodeAlgHeader(byte[] publicAlgId) {
        return java.util.Base64.getEncoder().encodeToString(publicAlgId);
    }
}
