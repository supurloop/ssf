# Cryptography

[SSF](../README.md)

Cryptographic interfaces.

| Module | Description | Source Files | Documentation |
|--------|-------------|--------------|---------------|
| ssfsha2 | SHA-2 hash (SHA-224/256/384/512 family) | ssfsha2.c, ssfsha2.h | [ssfsha2.md](ssfsha2.md) |
| ssfaes | AES block cipher (128/192/256-bit) | ssfaes.c, ssfaes.h | [ssfaes.md](ssfaes.md) |
| ssfaesgcm | AES-GCM authenticated encryption | ssfaesgcm.c, ssfaesgcm.h | [ssfaesgcm.md](ssfaesgcm.md) |
| ssfprng | Cryptographically secure capable PRNG | ssfprng.c, ssfprng.h | [ssfprng.md](ssfprng.md) |

## See Also

- [Codecs](../_codec/README.md) — Encoding interfaces used alongside cryptographic primitives
- [Error Detection Codes](../_edc/README.md) — Integrity verification after decryption
- [Error Correction Codes](../_ecc/README.md) — Forward error correction
