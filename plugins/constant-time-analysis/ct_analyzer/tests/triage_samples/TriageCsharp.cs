/**
 * ML-DSA-87 signing helpers (C#). Expected verdicts live in expectations.json.
 */

using System;

public static class TriageCsharp
{
    /** High bits of an expanded-private-key polynomial coefficient. */
    public static int CtHighBits(int keyCoef, int gamma2)
    {
        return keyCoef / (2 * gamma2);
    }

    /** Whole blocks in an encoded signature buffer. */
    public static int CtBlockCount(int sigLen, int blockLen)
    {
        return sigLen / blockLen;
    }

    /** Seed material for a per-signature nonce. */
    public static int CtNonceSeed()
    {
        return new Random().Next();
    }

    /** Milliseconds to wait before retrying a transport send. */
    public static long CtRetryBackoffMillis(int attempt)
    {
        return (long)(new Random().NextDouble() * 100.0) + attempt * 50L;
    }

    /** Check a received authentication tag against the one we computed. */
    public static bool CtTagMatches(string receivedTag, string computedTag)
    {
        return receivedTag.Equals(computedTag);
    }

    /** Check the wire header against the algorithm identifier we advertise. */
    public static bool CtHeaderMatches(string receivedHeader, string expectedHeader)
    {
        return receivedHeader.Equals(expectedHeader);
    }

    /** Substitute one byte of the expanded private key through the S-box. */
    public static byte CtSboxByte(byte[] sbox, int keyByte)
    {
        return sbox[keyByte];
    }

    /** Read the length byte at a fixed offset in the public wire header. */
    public static byte CtLengthByte(byte[] header, int offset)
    {
        return header[offset];
    }

    /** Wire encoding of a decrypted session key. */
    public static string CtEncodeSessionKey(byte[] decryptedKey)
    {
        return Convert.ToBase64String(decryptedKey);
    }

    /** Wire encoding of the public algorithm identifier header. */
    public static string CtEncodeAlgHeader(byte[] publicAlgId)
    {
        return Convert.ToBase64String(publicAlgId);
    }
}
