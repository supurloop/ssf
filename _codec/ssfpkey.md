# ssfpkey — Private Key Decoder

[SSF](../README.md) | [Codecs](README.md)

Decodes an unencrypted private key file, PEM or DER, into the form the SSF signing functions
take: a PKCS#1 `RSAPrivateKey` for [`SSFRSASignPSS()`](../_crypto/ssfrsa.md), a curve-size
scalar for [`SSFECDSASign()`](../_crypto/ssfecdsa.md), or a seed and public key for
[`SSFEd25519Sign()`](../_crypto/ssfed25519.md). Every key is validated before it is returned.
No filesystem access: the input is a buffer the caller supplies. A P-256 / P-384 key can also
be rebuilt from its raw scalar alone with [`SSFPKeyFromECPriv()`](#ssfpkeyfromecpriv), so a
device can store just the 32 or 48 bytes that [`SSFECDSAKeyGen()`](../_crypto/ssfecdsa.md)
produced.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfpkey--private-key-decoder) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfasn1`](ssfasn1.md) — DER parsing
- [`ssfpem`](ssfpem.md) — PEM blocks (only `SSFPKeyDecodePEM()`)
- [`ssfecdsa`](../_crypto/ssfecdsa.md), [`ssfed25519`](../_crypto/ssfed25519.md),
  [`ssfrsa`](../_crypto/ssfrsa.md) — key validation and public-key derivation
- [`ssfcrypt`](../_crypto/ssfcrypt.md) — `SSFCryptSecureZero()`

<a id="notes"></a>

## [↑](#ssfpkey--private-key-decoder) Notes

- **Formats.**

  | Format | PEM label | Keys |
  |---|---|---|
  | PKCS#8 `PrivateKeyInfo` v1 / `OneAsymmetricKey` v2 (RFC 5208, RFC 5958) | `PRIVATE KEY` | RSA, P-256, P-384, Ed25519 (RFC 8410) |
  | SEC 1 `ECPrivateKey` (RFC 5915) | `EC PRIVATE KEY` | P-256, P-384 |
  | PKCS#1 `RSAPrivateKey` (RFC 8017) | `RSA PRIVATE KEY` | RSA 2048 to 4096 bits ([`ssfrsa`](../_crypto/ssfrsa.md)) |

  In PEM the label decides the format; a body that does not match its label is refused. In DER
  the format is recognised from the structure.
- **Refused.** Encrypted keys (`ENCRYPTED PRIVATE KEY`, and legacy PEM with `Proc-Type`
  headers): decrypting needs PBKDF2 and AES-CBC, which SSF does not carry for this. X25519 /
  X448 keys, other curves, explicit curve parameters, multi-prime RSA and any version number
  other than the ones the formats define. Also refused, though some tools write them: RSA-PSS
  keys under the `id-RSASSA-PSS` OID (`openssl genpkey -algorithm RSA-PSS`; generate an
  `rsaEncryption` key instead, which signs RSA-PSS just the same), a compressed EC public key in
  the file (`-conv_form compressed`; the match check compares uncompressed points), and RSA
  PKCS#8 whose AlgorithmIdentifier omits the NULL parameters (RFC 8017 requires it). A PEM buffer must hold exactly one key block; other
  blocks (`EC PARAMETERS`, `CERTIFICATE`, ...) are checked and skipped, so a malformed one still
  fails the decode.
- **Validation.** EC: the scalar must be in [1, n − 1]; a scalar shorter than the curve size
  (leading zero bytes dropped by some encoders) is left-padded, a longer one refused. RSA:
  [`SSFRSAPrivKeyIsValid()`](../_crypto/ssfrsa.md) (n = p·q, exponents and CRT values
  consistent). Ed25519: a 32-byte seed. A standalone SEC 1 key must name its curve; under
  PKCS#8 the curve may come from the wrapper, and if both name one they must agree. Framing is
  exact: no trailing bytes at any level.
- **Public key check.** EC and Ed25519 keys always come back with their public key, derived
  from the private key. If the file also holds one (SEC 1 `[1]`, PKCS#8 v2 `[1]`) it must be
  equal, uncompressed for EC; a mismatched or corrupted file fails at load rather than at first
  use. RSA files carrying a PKCS#8 v2 public key are refused, since checking it would need it
  re-encoded; no common tool writes one.
- **Where the key lives.** For EC and Ed25519 the key is copied into the `SSFPKey_t`. For RSA,
  `rsaDer` points into the DER that was decoded (the input for `SSFPKeyDecodeDER()`, `derBuf`
  for `SSFPKeyDecodePEM()`), so that buffer must outlive the key. After a failed decode, or
  `SSFPKeyWipe()`, `type` is `SSF_PKEY_TYPE_NONE`.
- **Secret handling.** On any failure the `SSFPKey_t` is zeroed, and `SSFPKeyDecodePEM()`
  zeroes all of `derBuf`. On success `derBuf` holds the key's DER; wipe it with
  `SSFCryptSecureZero()` when it is no longer needed, and the key with
  [`SSFPKeyWipe()`](#ssfpkeywipe). Key bytes are never traced.
- **Cost (Cortex-M4, arm-none-eabi-gcc -Os).** Code: about 1.8 KB, plus 0.7 KB for
  [`ssfpem`](ssfpem.md). Stack (reachable call-graph peak, default configuration): about
  7.2 KB for an EC key (the public-key derivation), about 19.1 KB for an RSA key
  (`SSFRSAPrivKeyIsValid()` at the default RSA-4096 cap, below RSA signing's own peak), about
  1.5 KB for Ed25519. EC and RSA loading each cost one private-key-sized operation, a
  load-time cost, not a per-signature one. [`SSFPKeyFromECPriv()`](#ssfpkeyfromecpriv) costs
  the same as loading an EC key: one public-key derivation (a fixed-base scalar
  multiplication, about the cost of one key generation), with the same stack peak.

<a id="configuration"></a>

## [↑](#ssfpkey--private-key-decoder) Configuration

No options file. The curves follow `SSF_EC_CONFIG_ENABLE_P256` / `_P384`
([`ssfec`](../_crypto/ssfec.md)); a key on a disabled curve is refused as unknown, and
`SSFPKeyFromECPriv()` returns false for one. RSA
follows the `SSF_RSA_CONFIG_ENABLE_*` key sizes ([`ssfrsa`](../_crypto/ssfrsa.md)): with none
built, an RSA key is refused, and one of a size not built fails validation. The
unit-test entry point is gated by `SSF_CONFIG_PKEY_UNIT_TEST` in `ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfpkey--private-key-decoder) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| `SSF_PKEY_MAX_PRIV_SIZE` | Constant | `48`: the largest `priv` (P-384 scalar). |
| `SSF_PKEY_MAX_PUB_SIZE` | Constant | `97`: the largest `pub` (P-384 uncompressed point). |
| `SSFPKeyType_t` | Enum | `SSF_PKEY_TYPE_NONE` (`0`: no key; what a zeroed, wiped or failed-decode `SSFPKey_t` holds), `SSF_PKEY_TYPE_RSA`, `_P256`, `_P384`, `_ED25519`. |
| `SSFPKey_t` | Struct | `type`; RSA: `rsaDer`, `rsaDerLen`; EC: `priv` / `privLen` (32 or 48-byte scalar), `pub` / `pubLen` (65 or 97-byte uncompressed point); Ed25519: `priv` (32-byte seed), `pub` (32 bytes). |

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-pem) | [`bool SSFPKeyDecodePEM(pem, pemLen, derBuf, derBufSize, keyOut)`](#ssfpkeydecodepem) | Decode the one private key block of a PEM buffer |
| | [`bool SSFPKeyDecodeDER(der, derLen, keyOut)`](#ssfpkeydecodeder) | Decode a DER private key |
| [e.g.](#ex-fromecpriv) | [`bool SSFPKeyFromECPriv(type, priv, privLen, keyOut)`](#ssfpkeyfromecpriv) | Build a P-256 / P-384 key from its raw scalar |
| | [`void SSFPKeyWipe(key)`](#ssfpkeywipe) | Zero a key |

<a id="function-reference"></a>

## [↑](#ssfpkey--private-key-decoder) Function Reference

<a id="ssfpkeydecodepem"></a>

### [↑](#ssfpkey--private-key-decoder) [`bool SSFPKeyDecodePEM()`](#functions)

```c
bool SSFPKeyDecodePEM(const char *pem, size_t pemLen, uint8_t *derBuf, size_t derBufSize,
                      SSFPKey_t *keyOut);
```

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pem` | in | `const char *` | PEM text. Need not be null-terminated. Must not be `NULL`. |
| `pemLen` | in | `size_t` | Length of `pem`. |
| `derBuf` | out | `uint8_t *` | Receives the key block's DER. Must not be `NULL` and must not overlap `pem`. About 1.2 KB fits an RSA-2048 key, 2.4 KB RSA-4096; 200 bytes fits any EC or Ed25519 key. |
| `derBufSize` | in | `size_t` | Size of `derBuf`. |
| `keyOut` | out | `SSFPKey_t *` | Receives the key. Must not be `NULL`. |

**Returns:** `true` if exactly one supported, valid, unencrypted key block was found. On
`false`, `*keyOut` and all of `derBuf` are zeroed.

<a id="ex-pem"></a>

```c
static uint8_t der[1300];
SSFPKey_t key;
uint8_t hash[SSF_SHA2_256_BYTE_SIZE];
uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
size_t sigLen;

if (SSFPKeyDecodePEM(keyPem, keyPemLen, der, sizeof(der), &key) &&
    (key.type == SSF_PKEY_TYPE_P256))
{
    SSFSHA256(msg, msgLen, hash, sizeof(hash));
    SSFECDSASign(SSF_EC_CURVE_P256, key.priv, key.privLen, hash, sizeof(hash),
                 sig, sizeof(sig), &sigLen);
}
SSFPKeyWipe(&key);
SSFCryptSecureZero(der, sizeof(der));
```

---

<a id="ssfpkeydecodeder"></a>

### [↑](#ssfpkey--private-key-decoder) [`bool SSFPKeyDecodeDER()`](#functions)

```c
bool SSFPKeyDecodeDER(const uint8_t *der, size_t derLen, SSFPKey_t *keyOut);
```

Decodes PKCS#8, SEC 1 or PKCS#1 DER, recognised from the structure, with the same validation
as [`SSFPKeyDecodePEM()`](#ssfpkeydecodepem). `der` and `keyOut` must not be `NULL`. For RSA,
`keyOut->rsaDer` points into `der`.

**Returns:** `true` for a supported, valid key; on `false`, `*keyOut` is zeroed.

---

<a id="ssfpkeyfromecpriv"></a>

### [↑](#ssfpkey--private-key-decoder) [`bool SSFPKeyFromECPriv()`](#functions)

```c
bool SSFPKeyFromECPriv(SSFPKeyType_t type, const uint8_t *priv, size_t privLen,
                       SSFPKey_t *keyOut);
```

Builds the key from its big-endian private scalar and derives its public key. The result is
the same, byte for byte, as [`SSFPKeyDecodeDER()`](#ssfpkeydecodeder) of the SEC 1 DER of that
key, so it can go anywhere a decoded key can, e.g.
[`SSFTLSCSetClientCert()`](../_net/README.md).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `type` | in | `SSFPKeyType_t` | `SSF_PKEY_TYPE_P256` or `SSF_PKEY_TYPE_P384`; any other type asserts. |
| `priv` | in | `const uint8_t *` | The scalar, fixed width: leading zero bytes are kept, not dropped. Must not be `NULL` and must not overlap `*keyOut`. |
| `privLen` | in | `size_t` | Must equal the curve size, 32 for P-256 or 48 for P-384, or it asserts, as in [`ssfecdsa`](../_crypto/ssfecdsa.md). A length read from storage must be checked by the caller first. |
| `keyOut` | out | `SSFPKey_t *` | Receives the key. Must not be `NULL`. |

**Returns:** `true` if the scalar is in [1, n − 1]. `false` if it is not (0, n or more), or if
the curve is compiled out; `*keyOut` is then zeroed (`SSF_PKEY_TYPE_NONE`).

<a id="ex-fromecpriv"></a>

```c
/* Once, at provisioning: generate the key and store only its scalar */
uint8_t scalar[32];
uint8_t pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
size_t pubLen;
SSFECDSAKeyGen(SSF_EC_CURVE_P256, scalar, sizeof(scalar), pub, sizeof(pub), &pubLen);
/* ... write scalar to secure storage, wipe it ... */

/* At every boot: read the scalar back, rebuild the key, present it with the certificate */
static SSFPKey_t key;
/* ... read scalar from secure storage ... */
if (SSFPKeyFromECPriv(SSF_PKEY_TYPE_P256, scalar, sizeof(scalar), &key))
{
    SSFTLSCSetClientCert(&session, chain, chainLens, 1u, &key);
}
SSFCryptSecureZero(scalar, sizeof(scalar));
```

---

<a id="ssfpkeywipe"></a>

### [↑](#ssfpkey--private-key-decoder) [`void SSFPKeyWipe()`](#functions)

```c
void SSFPKeyWipe(SSFPKey_t *key);
```

Zeroes the whole structure with `SSFCryptSecureZero()`. For RSA it does not touch the DER that
`rsaDer` points into; wipe that buffer separately.
