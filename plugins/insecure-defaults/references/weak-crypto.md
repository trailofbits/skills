# Weak Cryptographic Defaults

**Report when:** A broken or non-cryptographic primitive standing in for a security-relevant one: password hashing, token generation, encryption, signature verification.

**Skip when:** Checksums, ETags, cache keys, deduplication hashes, test vectors. Non-security shuffling or sampling.

The algorithm alone is never the finding. `hashlib.md5` over a cache key is fine; the same call over a password is not. Trace to the use site before filing.

## VULNERABLE - Report These

**MD5 for password hashing**
```python
# File: src/auth/passwords.py
import hashlib

def hash_password(password):
    """Hash user password"""
    return hashlib.md5(password.encode()).hexdigest()
```
**Why vulnerable:** MD5 is cryptographically broken. Rainbow tables exist. Use bcrypt/Argon2.

**DES encryption for sensitive data**
```java
// File: Encryption.java
public static byte[] encrypt(String data, byte[] key) {
    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    SecretKeySpec secretKey = new SecretKeySpec(key, "DES");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    return cipher.doFinal(data.getBytes());
}
```
**Why vulnerable:** DES has 56-bit keys (brute-forceable). ECB mode leaks patterns.

**SHA1 for signature verification**
```javascript
// File: webhooks.js
function verifySignature(payload, signature) {
  const hmac = crypto.createHmac('sha1', WEBHOOK_SECRET);
  const computed = hmac.update(payload).digest('hex');
  return computed === signature;
}
```
**Why vulnerable:** SHA1 collisions exist. Use SHA256 or better.

## SECURE - Skip These

**Weak crypto for non-security checksums**
```python
# File: src/utils/cache.py
import hashlib

def cache_key(data):
    """Generate cache key - not security-sensitive"""
    return hashlib.md5(data.encode()).hexdigest()  # OK - just for cache lookup
```

**Modern crypto for passwords**
```python
# File: src/auth/passwords.py
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

**Strong encryption**
```java
// File: Encryption.java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
// 256-bit key, authenticated encryption
```
