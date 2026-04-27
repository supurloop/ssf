# Cryptography

[SSF](../README.md)

Cryptographic interfaces.

| Module | Description | Source Files | Documentation |
|--------|-------------|--------------|---------------|
| ssfsha1 | SHA-1 hash (RFC 3174; legacy protocol use only) | ssfsha1.c, ssfsha1.h | [ssfsha1.md](ssfsha1.md) |
| ssfsha2 | SHA-2 hash (SHA-224/256/384/512 family) | ssfsha2.c, ssfsha2.h | [ssfsha2.md](ssfsha2.md) |
| ssfhmac | HMAC (RFC 2104) over SHA-1 / SHA-256 / SHA-384 / SHA-512 | ssfhmac.c, ssfhmac.h | [ssfhmac.md](ssfhmac.md) |
| ssfhkdf | HKDF (RFC 5869) HMAC-based extract-and-expand key derivation | ssfhkdf.c, ssfhkdf.h | [ssfhkdf.md](ssfhkdf.md) |
| ssfpoly1305 | Poly1305 one-time MAC (RFC 7539/8439) | ssfpoly1305.c, ssfpoly1305.h | [ssfpoly1305.md](ssfpoly1305.md) |
| ssfchacha20 | ChaCha20 stream cipher (RFC 7539/8439) | ssfchacha20.c, ssfchacha20.h | [ssfchacha20.md](ssfchacha20.md) |
| ssfchacha20poly1305 | ChaCha20-Poly1305 AEAD (RFC 7539/8439) | ssfchacha20poly1305.c, ssfchacha20poly1305.h | [ssfchacha20poly1305.md](ssfchacha20poly1305.md) |
| ssfaes | AES block cipher (128/192/256-bit) | ssfaes.c, ssfaes.h | [ssfaes.md](ssfaes.md) |
| ssfaesgcm | AES-GCM authenticated encryption | ssfaesgcm.c, ssfaesgcm.h | [ssfaesgcm.md](ssfaesgcm.md) |
| ssfaesccm | AES-CCM AEAD (RFC 3610, NIST SP 800-38C) | ssfaesccm.c, ssfaesccm.h | [ssfaesccm.md](ssfaesccm.md) |
| ssfcrypt | High-level cryptographic helpers (constant-time compare, secure zeroize) | ssfcrypt.c, ssfcrypt.h | [ssfcrypt.md](ssfcrypt.md) |
| ssfprng | Cryptographically secure capable PRNG | ssfprng.c, ssfprng.h | [ssfprng.md](ssfprng.md) |
| ssfbn | Multi-precision big-number arithmetic (foundation for RSA, ECC, DH) | ssfbn.c, ssfbn.h | [ssfbn.md](ssfbn.md) |
| ssfec | Elliptic curve point arithmetic (NIST P-256 / P-384) | ssfec.c, ssfec.h | [ssfec.md](ssfec.md) |
| ssfecdsa | ECDSA signatures (RFC 6979 deterministic) + ECDH key agreement over NIST P-256 / P-384 | ssfecdsa.c, ssfecdsa.h | [ssfecdsa.md](ssfecdsa.md) |
| ssfx25519 | X25519 key agreement (RFC 7748) — constant-time, self-contained | ssfx25519.c, ssfx25519.h | [ssfx25519.md](ssfx25519.md) |
| ssfed25519 | Ed25519 signatures (RFC 8032 pure mode) — deterministic, self-contained | ssfed25519.c, ssfed25519.h | [ssfed25519.md](ssfed25519.md) |
| ssfrsa | RSA signatures (PKCS#1 v1.5 and PSS) + key generation over 2048/3072/4096-bit keys | ssfrsa.c, ssfrsa.h | [ssfrsa.md](ssfrsa.md) |
| ssftls | TLS 1.3 core building blocks: key schedule, transcript hash, record layer (no handshake state machine) | ssftls.c, ssftls.h | [ssftls.md](ssftls.md) |

## See Also

- [Codecs](../_codec/README.md) — Encoding interfaces used alongside cryptographic primitives
- [Error Detection Codes](../_edc/README.md) — Integrity verification after decryption
- [Error Correction Codes](../_ecc/README.md) — Forward error correction
