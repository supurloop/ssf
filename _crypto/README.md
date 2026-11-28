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
| ssfaesctr | AES-CTR confidentiality-only stream cipher (NIST SP 800-38A §6.5) | ssfaesctr.c, ssfaesctr.h | [ssfaesctr.md](ssfaesctr.md) |
| ssfcrypt | High-level cryptographic helpers (constant-time compare, secure zeroize) | ssfcrypt.c, ssfcrypt.h | [ssfcrypt.md](ssfcrypt.md) |
| ssfprng | Cryptographically secure capable PRNG | ssfprng.c, ssfprng.h | [ssfprng.md](ssfprng.md) |
| ssfbn | Multi-precision big-number arithmetic (foundation for RSA, ECC, DH) | ssfbn.c, ssfbn.h | [ssfbn.md](ssfbn.md) |
| ssfec | Elliptic curve point arithmetic (NIST P-256 / P-384) | ssfec.c, ssfec.h | [ssfec.md](ssfec.md) |
| ssfecdsa | ECDSA signatures (RFC 6979 deterministic) + ECDH key agreement over NIST P-256 / P-384 | ssfecdsa.c, ssfecdsa.h | [ssfecdsa.md](ssfecdsa.md) |
| ssfx25519 | X25519 key agreement (RFC 7748) — constant-time, no ssfbn dependency | ssfx25519.c, ssfx25519.h | [ssfx25519.md](ssfx25519.md) |
| ssfed25519 | Ed25519 signatures (RFC 8032 pure mode) — deterministic, no ssfbn dependency | ssfed25519.c, ssfed25519.h | [ssfed25519.md](ssfed25519.md) |
| ssffe25519 | GF(2²⁵⁵ − 19) field arithmetic shared by ssfx25519 and ssfed25519 (internal) | ssffe25519.c, ssffe25519.h | [ssffe25519.md](ssffe25519.md) |
| ssfrsa | RSA signatures (PKCS#1 v1.5 and PSS) + key generation over 2048/3072/4096-bit keys | ssfrsa.c, ssfrsa.h | [ssfrsa.md](ssfrsa.md) |
| ssftls | TLS 1.3 core building blocks: key schedule, transcript hash, record layer (no handshake state machine) | ssftls.c, ssftls.h | [ssftls.md](ssftls.md) |
| ssfcms | RFC 5652 CMS SignedData verifier (zero-copy parse, detached file signatures by digest, ECDSA / RSA / Ed25519, RFC 6211 algorithm protection) | ssfcms.c, ssfcms.h | [ssfcms.md](ssfcms.md) |

<a id="constant-time"></a>

## Constant time

Code that handles secrets (private keys, nonces, scalars, MAC keys, shared secrets) runs the
same instruction sequence whatever the secret is: no branch and no memory index depends on
it. Masked selects build their masks through [`SSF_CT_VALUE_BARRIER`](../ssfport.md#notes)
and the [`SSFCryptCT*`](ssfcrypt.md#notes) predicates. Without them, GCC and clang turn masks
into branches on cores with no conditional move.

This is checked as compiled, not just as written. Each constant-time function runs under
qemu with different secrets and must give an identical instruction trace. That covers ssfbn
(conditional copy, swap and compare, modular and Montgomery arithmetic, ModExp, the safegcd
inverse), ssffe25519, Poly1305, AES-GCM, `SSFCryptCTMemEq`, X25519, Ed25519, P-256 ECDH /
ECDSA and RSA key generation's 65537^-1 mod lambda. It was run with GCC 15.2 and clang 23 at
`-Os` and `-O2`, for Cortex-M0+, M23, M3, M4 and M33 (2026-11). Results:

- **Cortex-M3 / M4 / M33:** every case passes.
- **Cortex-M0 / M0+ / M23 (ARMv6-M, ARMv8-M Baseline):** every case passes except RSA key
  generation's trial division (below). These cores have no 32 x 32 -> 64 multiply, and
  libgcc's `__aeabi_lmul` / `__muldi3`, which a 64-bit product would otherwise call, branches
  on its operands. So every product in the constant-time code goes through
  [`SSF_CT_MUL32` / `SSF_CT_SMUL32`](ssfcrypt.md#notes), which use a branch-free multiply
  there. It is also faster than the libgcc call: RSA-2048 sign 19-27% fewer instructions on
  Cortex-M0+.
- **Open, every core:** RSA key generation's trial division of the secret prime candidates
  by small primes uses a divide whose time depends on the operands (libgcc on M0 / M0+;
  the `UDIV` instruction's early termination on M3 / M4 / M23 / M33). Fix planned.

What the check does not cover: memory access patterns as seen by a cache (table lookups
indexed by secrets, such as the AES S-box); operand-dependent instruction timing (for
example the Cortex-M3's early-terminating `UMULL`); compilers and options not listed; and
inputs it did not try.

## See Also

- [Codecs](../_codec/README.md) — Encoding interfaces used alongside cryptographic primitives
- [Error Detection Codes](../_edc/README.md) — Integrity verification after decryption
- [Error Correction Codes](../_ecc/README.md) — Forward error correction
