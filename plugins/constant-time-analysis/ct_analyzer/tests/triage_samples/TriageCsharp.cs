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
}
