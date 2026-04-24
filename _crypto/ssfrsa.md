# ssfrsa — RSA Signatures and Key Generation

[SSF](../README.md) | [Cryptography](README.md)

RSA digital signatures and key generation over 2048 / 3072 / 4096-bit keys, per
RFC 8017 (PKCS#1 v2.2) and FIPS 186-4. Provides two signature padding schemes — the legacy
`RSASSA-PKCS1-v1_5` and the modern `RSASSA-PSS` — plus a key-generation routine that
produces PKCS#1 DER-encoded `RSAPrivateKey` / `RSAPublicKey` blobs. Private-key operations
use the Chinese Remainder Theorem for a roughly 4× speedup over direct modular
exponentiation.

This module is the heavyweight entry point in the public-key family. Compared with
[ECDSA over NIST curves](ssfecdsa.md) or [Ed25519](ssfed25519.md) it is significantly
larger (code, keys, signatures, and stack) and slower for operations that touch the
private key. Use it when you need interop with X.509 / PKIX, TLS-with-RSA, or the
long-tail of legacy protocols that still mandate RSA; otherwise, prefer one of the
elliptic-curve primitives — EC-family signatures are ~100× smaller on the wire for
comparable security.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfrsa--rsa-signatures-and-key-generation) Dependencies

- [`ssfport.h`](../ssfport.h) — also supplies the platform entropy source used by keygen
  and PSS salt generation (`/dev/urandom` on POSIX; see [Notes](#notes)).
- [`ssfbn`](ssfbn.md) — big-number arithmetic including the constant-time
  [`SSFBNModExp`](ssfbn.md#modexp) Montgomery ladder used for every RSA private operation.
- [`ssfasn1`](../_codec/ssfasn1.h) — DER encode / decode for PKCS#1 `RSAPublicKey` and
  `RSAPrivateKey`.
- [`ssfsha2`](ssfsha2.md) — SHA-256 / SHA-384 / SHA-512 inside PKCS#1 v1.5 DigestInfo
  encoding, MGF1, and PSS `H` / `H'` computation.
- [`ssfprng`](ssfprng.md) — seeded from platform entropy for prime generation and PSS salt.
- [`ssfct`](ssfct.md) — constant-time comparison on the PKCS#1 v1.5 and PSS verify paths.

<a id="notes"></a>

## [↑](#ssfrsa--rsa-signatures-and-key-generation) Notes

- **Prefer PSS for new designs; PKCS#1 v1.5 is legacy only.** RSASSA-PSS is provably
  secure under the random-oracle model and has no known forgery attack classes. PKCS#1
  v1.5 is still believed to be secure for signatures *when implemented carefully on both
  sides*, but is prone to subtle verifier bugs (Bleichenbacher '06 forgery against
  low-exponent verifiers that fail to check the full padding, and its descendants). Use
  the `PSS` entry points unless the wire format pins you to v1.5 (certificate chains
  pre-PKCS#1 v2.1, older TLS 1.2 profiles, JWS `RS256` legacy).
- **Public exponent is fixed at `e = 65537` (F4).** There is no way to choose a different
  exponent. F4 is the universal modern choice; low-exponent attacks (e = 3 with short
  message, Coppersmith) are not reachable here.
- **Supported key sizes are 2048, 3072, and 4096 bits.** 2048-bit keys are the current
  NIST floor for moderate-assurance signatures and interoperable TLS; 3072 is recommended
  for new systems targeting a 10-year lifetime; 4096 is reasonable for long-term or
  high-assurance contexts. Keys below 2048 are not supported (the keygen validates and
  `SSFBN_CONFIG_MAX_BITS` gates the upper bound).
- **Hash-to-key-size pairing per NIST SP 800-57 §5.6.2:**

  | Key size | Recommended hash(es) |
  |---|---|
  | RSA-2048 | SHA-256 |
  | RSA-3072 | SHA-256, SHA-384 |
  | RSA-4096 | SHA-256, SHA-384, SHA-512 |

  This module enforces that the `hashLen` matches the selected `SSFRSAHash_t` enum value
  (32 / 48 / 64 bytes) but does not cross-check against key size — using SHA-256 with an
  RSA-4096 key is legal per the API, it just bottoms out at ~128-bit security.
- **Key generation is slow — orders of magnitude slower than any other SSF crypto
  operation.** Seconds on a desktop CPU, several minutes on an embedded microcontroller
  (Cortex-M4 / -M7 class). The runtime is dominated by probabilistic prime generation:
  each candidate `p` / `q` draws fresh entropy, runs several Miller-Rabin rounds
  (`SSF_RSA_CONFIG_MILLER_RABIN_ROUNDS`, default 5), and may fail and retry. Do not
  generate keys inside a real-time loop or during startup on a device with a watchdog.
- **Key-generation entropy is platform-dependent.** Keygen and PSS signing both pull
  initial entropy from `/dev/urandom` on POSIX via the internal `_SSFRSAGetEntropy()`
  helper; on Windows this currently `SSF_ASSERT(false)`s and returns `false`. On a
  bare-metal target without `/dev/urandom`, patch the helper to read from a hardware TRNG
  or provision keys off-device at manufacture and only ever use sign / verify at
  runtime. **Never** ship `SSFRSAKeyGen` on a target without a genuine entropy source —
  predictable primes are catastrophic.
- **PKCS#1 v1.5 signing is deterministic; PSS signing is not.** `SSFRSASignPKCS1` uses no
  randomness at sign time — signing the same `(key, hash)` twice yields the same
  signature. `SSFRSASignPSS` draws a fresh random salt (of length equal to the hash
  output) from the platform entropy source on every call, so repeat calls produce
  different signatures that all verify. PSS signing therefore requires
  entropy availability at sign time as well as at key-gen time — on targets where runtime
  entropy is scarce, prefer PKCS#1 v1.5 (for legacy protocols) or Ed25519 /
  deterministic-ECDSA (for new ones).
- **PSS salt length is fixed at the hash output length.** RFC 8017 §9.1.1 and TLS 1.3
  both use this convention; interop with verifiers that expect a different salt length
  (e.g., `sLen = 0` for some "fully-deterministic PSS" profiles) is not supported.
- **Private-key operations run via CRT.** Signing performs `m^d mod n` by decomposing
  into `m^dp mod p` and `m^dq mod q` then recombining with the precomputed inverse `qInv
  = q⁻¹ mod p`. This is ~4× faster than direct exponentiation and uses shorter
  intermediates. The well-known **CRT fault-injection attack** (Boneh–DeMillo–Lipton)
  recovers the factors of `n` from a single faulty signature if an attacker can glitch
  one of the two `modexp` branches during sign. This is not exploitable on pure-software
  targets under normal conditions, but matters for secure-element integration — pair with
  a verify-after-sign check at the application layer if the signing device is physically
  accessible.
- **Key storage format is PKCS#1 DER.** `RSAPublicKey` = `SEQUENCE { INTEGER n, INTEGER
  e }`; `RSAPrivateKey` = `SEQUENCE { version, n, e, d, p, q, dp, dq, qInv, ... }`, all
  unsigned big-endian. **This is not PKCS#8** (no `AlgorithmIdentifier` wrapper) and not
  PEM (no Base64, no `-----BEGIN-----` header). If your storage format is PKCS#8 or PEM,
  strip those layers at the call site before handing the bytes in.
- **The PSS verify path currently has a variable-time pad check** (ssfrsa.c:1171–1177
  inspects each zero byte of `PS` with an early-return `if`). This does not enable any
  known direct forgery, but it does leak where `PS` diverged from the expected pattern —
  a defense-in-depth concern flagged for a future hardening pass. The final `H == H'`
  comparison is already constant-time via [`SSFCTMemEq`](ssfct.md).
- **Keys are not parsed lazily on every call.** Each sign / verify / key-validate entry
  point re-parses the DER blob on entry. If you're signing many messages under the same
  key, this is a few hundred microseconds per call that could in principle be
  amortised — at the moment the API does not expose a parsed-key handle.

<a id="configuration"></a>

## [↑](#ssfrsa--rsa-signatures-and-key-generation) Configuration

Options live in [`_opt/ssfrsa_opt.h`](../_opt/ssfrsa_opt.h). Disable features you don't
need — each compiles its entry points out of the build, reclaiming flash.

| Macro | Default | Description |
|-------|---------|-------------|
| `SSF_RSA_CONFIG_ENABLE_KEYGEN` | `1` | Enable `SSFRSAKeyGen`. Disabling removes ~3 KB of code (Miller-Rabin, prime generation, CRT parameter setup) and drops peak stack significantly — sign/verify are much lighter than keygen. |
| `SSF_RSA_CONFIG_ENABLE_PKCS1_V15` | `1` | Enable `SSFRSASignPKCS1` / `SSFRSAVerifyPKCS1`. |
| `SSF_RSA_CONFIG_ENABLE_PSS` | `1` | Enable `SSFRSASignPSS` / `SSFRSAVerifyPSS`. |
| `SSF_RSA_CONFIG_MILLER_RABIN_ROUNDS` | `5` | Number of Miller-Rabin witnesses per prime candidate in keygen. Five rounds gives a false-positive probability ≤ 2⁻¹⁰⁰ for random inputs (FIPS 186-4 §C.3 minimum is 4 for RSA-2048, 5 for RSA-3072/4096). Higher values slow keygen proportionally with marginal security gain. |

Key-size support is also gated by [`SSF_BN_CONFIG_MAX_BITS`](ssfbn.md#configuration) —
pick `2048` for RSA-2048 only, `3072` for up-to-3072, `4096` for full support. Each
doubling of `SSF_BN_CONFIG_MAX_BITS` doubles the stack footprint of every `SSFBN_t`.

<a id="api-summary"></a>

## [↑](#ssfrsa--rsa-signatures-and-key-generation) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-rsa-max-key-bytes"></a>`SSF_RSA_MAX_KEY_BYTES` | Constant | `SSF_BN_CONFIG_MAX_BITS / 8` — maximum key (and signature) byte length. At default 4096-bit BN width: 512. |
| <a id="ssf-rsa-max-sig-size"></a>`SSF_RSA_MAX_SIG_SIZE` | Constant | Same as `SSF_RSA_MAX_KEY_BYTES`. RSA signatures are always exactly `keyBytes` long. |
| <a id="ssf-rsa-max-pub-key-der-size"></a>`SSF_RSA_MAX_PUB_KEY_DER_SIZE` | Constant | `SSF_RSA_MAX_KEY_BYTES + 40` — maximum DER size of a PKCS#1 `RSAPublicKey`. |
| <a id="ssf-rsa-max-priv-key-der-size"></a>`SSF_RSA_MAX_PRIV_KEY_DER_SIZE` | Constant | `5 × SSF_RSA_MAX_KEY_BYTES + 200` — maximum DER size of a PKCS#1 `RSAPrivateKey` (holds `n, e, d, p, q, dp, dq, qInv`). |
| <a id="ssfrsahash-t"></a>`SSFRSAHash_t` | Enum | Hash selector: `SSF_RSA_HASH_SHA256`, `SSF_RSA_HASH_SHA384`, `SSF_RSA_HASH_SHA512` (plus `MIN` / `MAX` sentinels). |

<a id="functions"></a>

### Functions

**[Key management](#key-management)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-keygen) | [`bool SSFRSAKeyGen(bits, privKeyDer, privKeyDerSize, privKeyDerLen, pubKeyDer, pubKeyDerSize, pubKeyDerLen)`](#ssfrsakeygen) | Generate a 2048 / 3072 / 4096-bit key pair (enable via `SSF_RSA_CONFIG_ENABLE_KEYGEN`) |
| | [`bool SSFRSAPubKeyIsValid(pubKeyDer, pubKeyDerLen)`](#ssfrsapubkeyisvalid) | Validate a DER-encoded `RSAPublicKey` blob |

**[PKCS#1 v1.5 signatures](#pkcs1-v15)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-pkcs1) | [`bool SSFRSASignPKCS1(privKeyDer, ..., hash, hashVal, hashLen, sig, sigSize, sigLen)`](#ssfrsasignpkcs1) | Sign a hash with deterministic PKCS#1 v1.5 padding |
| [e.g.](#ex-pkcs1) | [`bool SSFRSAVerifyPKCS1(pubKeyDer, ..., hash, hashVal, hashLen, sig, sigLen)`](#ssfrsaverifypkcs1) | Verify a PKCS#1 v1.5 signature |

**[PSS signatures](#pss)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-pss) | [`bool SSFRSASignPSS(privKeyDer, ..., hash, hashVal, hashLen, sig, sigSize, sigLen)`](#ssfrsasignpss) | Sign a hash with RSA-PSS (random salt, hash-length) |
| [e.g.](#ex-pss) | [`bool SSFRSAVerifyPSS(pubKeyDer, ..., hash, hashVal, hashLen, sig, sigLen)`](#ssfrsaverifypss) | Verify an RSA-PSS signature |

<a id="function-reference"></a>

## [↑](#ssfrsa--rsa-signatures-and-key-generation) Function Reference

<a id="key-management"></a>

### [↑](#functions) Key Management

<a id="ssfrsakeygen"></a>
```c
bool SSFRSAKeyGen(uint16_t bits,
                  uint8_t *privKeyDer, size_t privKeyDerSize, size_t *privKeyDerLen,
                  uint8_t *pubKeyDer,  size_t pubKeyDerSize,  size_t *pubKeyDerLen);
```
Gated on `SSF_RSA_CONFIG_ENABLE_KEYGEN`. Generate a fresh RSA key pair.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `bits` | in | `uint16_t` | Key size. Must be `2048`, `3072`, or `4096`. |
| `privKeyDer` | out | `uint8_t *` | Buffer for PKCS#1 `RSAPrivateKey` DER. |
| `privKeyDerSize` | in | `size_t` | Must be ≥ [`SSF_RSA_MAX_PRIV_KEY_DER_SIZE`](#ssf-rsa-max-priv-key-der-size). |
| `privKeyDerLen` | out | `size_t *` | Bytes actually written to `privKeyDer`. |
| `pubKeyDer` | out | `uint8_t *` | Buffer for PKCS#1 `RSAPublicKey` DER. |
| `pubKeyDerSize` | in | `size_t` | Must be ≥ [`SSF_RSA_MAX_PUB_KEY_DER_SIZE`](#ssf-rsa-max-pub-key-der-size). |
| `pubKeyDerLen` | out | `size_t *` | Bytes actually written to `pubKeyDer`. |

**Returns:** `true` on success; `false` if entropy is unavailable, if `bits` is not one of
the supported sizes, or if the caller's DER buffers are undersized. **Runtime is
seconds-to-minutes** — see [Notes](#notes).

<a id="ex-keygen"></a>

**Example:**

```c
uint8_t priv[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
uint8_t pub[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
size_t  privLen, pubLen;

if (!SSFRSAKeyGen(2048,
                  priv, sizeof(priv), &privLen,
                  pub,  sizeof(pub),  &pubLen))
{
    /* Entropy unavailable, or bits unsupported. */
}
/* priv[0..privLen-1] is the PKCS#1 RSAPrivateKey DER;
   pub[0..pubLen-1] is the PKCS#1 RSAPublicKey DER.
   Protect priv as secret; distribute pub freely. */
```

<a id="ssfrsapubkeyisvalid"></a>
```c
bool SSFRSAPubKeyIsValid(const uint8_t *pubKeyDer, size_t pubKeyDerLen);
```
Parse the DER blob and return whether it is a well-formed PKCS#1 `RSAPublicKey` with a
modulus in the supported size range and a valid public exponent. Does **not** check that
the modulus is actually the product of two primes (which would require factoring); a
well-formed but deliberately weak key — e.g., a modulus with a small factor — would still
return `true` here. Use this to reject mis-encoded or size-wrong keys at ingestion time.

---

<a id="pkcs1-v15"></a>

### [↑](#functions) PKCS#1 v1.5 Signatures

Gated on `SSF_RSA_CONFIG_ENABLE_PKCS1_V15`.

<a id="ssfrsasignpkcs1"></a>
```c
bool SSFRSASignPKCS1(const uint8_t *privKeyDer, size_t privKeyDerLen,
                     SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                     uint8_t *sig, size_t sigSize, size_t *sigLen);
```
Produce an RSASSA-PKCS1-v1_5 signature (RFC 8017 §8.2). Deterministic — no entropy is
consumed at sign time. The caller supplies `hashVal` as the raw output of the matching
hash algorithm; the module wraps it in a `DigestInfo` ASN.1 structure and applies the
`0x00 || 0x01 || 0xFF...FF || 0x00 || DigestInfo` padding before the RSA private
operation.

<a id="ssfrsaverifypkcs1"></a>
```c
bool SSFRSAVerifyPKCS1(const uint8_t *pubKeyDer, size_t pubKeyDerLen,
                       SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                       const uint8_t *sig, size_t sigLen);
```
Verify a PKCS#1 v1.5 signature. Performs the public operation `sig^e mod n`, reconstructs
the expected `EM` from `(hash, hashVal)`, and compares the recovered and expected blocks
with [`SSFCTMemEq()`](ssfct.md). Any mismatch — wrong key, wrong hash algorithm, tampered
signature, corrupted DER — returns `false`. Callers should treat all `false` outcomes
identically.

<a id="ex-pkcs1"></a>

**Example:**

```c
/* Compute the message hash first — RSA signs a hash, not the raw message. */
uint8_t hash[SSF_SHA2_256_BYTE_SIZE];
SSFSHA256(msg, (uint32_t)msgLen, hash, sizeof(hash));

/* Sign with PKCS#1 v1.5 + SHA-256. */
uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
size_t  sigLen;
if (!SSFRSASignPKCS1(privDer, privLen,
                     SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                     sig, sizeof(sig), &sigLen))
{
    /* Sign failure. */
}

/* At the peer: verify. */
if (!SSFRSAVerifyPKCS1(pubDer, pubLen,
                       SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                       sig, sigLen))
{
    /* Reject. */
}
```

---

<a id="pss"></a>

### [↑](#functions) RSA-PSS Signatures

Gated on `SSF_RSA_CONFIG_ENABLE_PSS`.

<a id="ssfrsasignpss"></a>
```c
bool SSFRSASignPSS(const uint8_t *privKeyDer, size_t privKeyDerLen,
                   SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                   uint8_t *sig, size_t sigSize, size_t *sigLen);
```
Produce an RSASSA-PSS signature (RFC 8017 §8.1). Draws a random `sLen`-byte salt from the
platform entropy source (where `sLen == hashLen`), forms `mHash || salt`, hashes into
`H`, applies MGF1 masking with `H`, and wraps the whole thing with the standard PSS
trailer before the RSA private operation. Returns `false` if entropy is unavailable.
Non-deterministic: repeat calls produce different signatures that all verify.

<a id="ssfrsaverifypss"></a>
```c
bool SSFRSAVerifyPSS(const uint8_t *pubKeyDer, size_t pubKeyDerLen,
                     SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                     const uint8_t *sig, size_t sigLen);
```
Verify an RSA-PSS signature. Performs `sig^e mod n`, recovers `EM`, extracts `H` and
`salt`, recomputes `H'`, and compares. `H == H'` is constant-time; the intermediate
padding-pattern check is currently variable-time (see [Notes](#notes)).

<a id="ex-pss"></a>

**Example:**

```c
/* Same preparation as PKCS#1 v1.5 — hash the message first. */
uint8_t hash[SSF_SHA2_256_BYTE_SIZE];
SSFSHA256(msg, (uint32_t)msgLen, hash, sizeof(hash));

uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
size_t  sigLen;

if (!SSFRSASignPSS(privDer, privLen,
                   SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                   sig, sizeof(sig), &sigLen))
{
    /* Entropy unavailable or sign failure. PSS needs randomness at sign
       time — unlike PKCS#1 v1.5 which is fully deterministic. */
}

/* Verify. Same signature data will fail if any of the key / hash / message
   bytes differ between signer and verifier. */
if (!SSFRSAVerifyPSS(pubDer, pubLen,
                     SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                     sig, sigLen))
{
    /* Reject. */
}
```
