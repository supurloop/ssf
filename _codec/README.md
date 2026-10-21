# Codecs

[SSF](../README.md)

Encoding and decoding interfaces.

| Module | Description | Source Files | Documentation |
|--------|-------------|--------------|---------------|
| ssfasn1 | ASN.1 DER encoder/decoder (zero-copy decode + measure-then-write encode; X.509 / PKCS#1 / SEC 1) | ssfasn1.c, ssfasn1.h | [ssfasn1.md](ssfasn1.md) |
| ssfbase64 | Base64 encoder/decoder | ssfbase64.c, ssfbase64.h | [ssfbase64.md](ssfbase64.md) |
| ssfdec | Integer to decimal string | ssfdec.c, ssfdec.h | [ssfdec.md](ssfdec.md) |
| ssfgobj | Generic object parser/generator (BETA) | ssfgobj.c, ssfgobj.h | [ssfgobj.md](ssfgobj.md) |
| ssfhex | Binary to hex ASCII encoder/decoder | ssfhex.c, ssfhex.h | [ssfhex.md](ssfhex.md) |
| ssfini | INI file parser/generator | ssfini.c, ssfini.h | [ssfini.md](ssfini.md) |
| ssfjson | JSON parser/generator | ssfjson.c, ssfjson.h | [ssfjson.md](ssfjson.md) |
| ssfstr | Safe C string interface | ssfstr.c, ssfstr.h | [ssfstr.md](ssfstr.md) |
| ssftlv | TLV encoder/decoder | ssftlv.c, ssftlv.h | [ssftlv.md](ssftlv.md) |
| ssfubjson | UBJSON (Universal Binary JSON) parser/generator | ssfubjson.c, ssfubjson.h | [ssfubjson.md](ssfubjson.md) |

## See Also

- [Data Structures](../_struct/README.md) — Efficient data structure primitives
- [Cryptography](../_crypto/README.md) — Cryptographic primitives useful with encoded data
