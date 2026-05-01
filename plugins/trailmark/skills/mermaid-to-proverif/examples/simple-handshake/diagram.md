# Simple Authenticated Key Exchange Sequence Diagram

```mermaid
sequenceDiagram
    participant I as Initiator
    participant R as Responder

    rect rgb(230, 240, 255)
        Note over I,R: Setup (out-of-band key registration)
        Note over I: keygen() → sk_I, pk_I
        Note over R: keygen() → sk_R, pk_R
    end

    rect rgb(230, 255, 230)
        Note over I,R: Handshake
        Note over I: keygen() → ek_I, epk_I
        Note over I: sig_I = Sign(sk_I, "msg1" || epk_I)
        I->>R: epk_I || sig_I
        Note over R: Verify(pk_I, "msg1" || epk_I, sig_I)
        Note over R: keygen() → ek_R, epk_R
        Note over R: transcript = epk_I || epk_R
        Note over R: sig_R = Sign(sk_R, "msg2" || transcript)
        Note over R: dh = DH(ek_R, epk_I)
        Note over R: sk_R = HKDF(dh || transcript, info="session-key-v1")
        R-->>I: epk_R || sig_R
        Note over I: Verify(pk_R, "msg2" || epk_I || epk_R, sig_R)
        Note over I: dh = DH(ek_I, epk_R)
        Note over I: sk_I = HKDF(dh || transcript, info="session-key-v1")
    end

    rect rgb(255, 240, 200)
        Note over I,R: Application Data
        I->>R: ChaCha20Poly1305(sk, nonce, plaintext)
    end

    alt signature verification failure
        R-->>I: abort(INVALID_SIGNATURE)
    end
```

## Protocol Summary

- **Parties:** Initiator (I), Responder (R)
- **Round complexity:** 2 messages (1 round-trip)
- **Key primitives:** X25519 (DH), Ed25519 (Sign/Verify), HKDF-SHA256, ChaCha20-Poly1305
- **Authentication:** Mutual — both parties sign their ephemeral key; both verify the peer's signature
- **Forward secrecy:** Yes — session key derived exclusively from ephemeral DH; long-term keys only used for authentication
- **Notable:** Long-term keys registered out-of-band; no PKI or certificate exchange in-protocol
