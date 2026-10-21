# ssfecdsa — ECDSA Signatures and ECDH Key Agreement

[SSF](../README.md) | [Cryptography](README.md)

ECDSA digital signatures (FIPS 186-4) and ECDH key agreement (NIST SP 800-56A rev. 3, SEC 1
v2) over NIST P-256 and P-384. This module is the main application-facing entry point for
NIST-curve public-key operations — key generation, sign, verify, and ECDH derivation — built
on top of [`ssfec`](ssfec.md) and [`ssfbn`](ssfbn.md).

Two design choices worth calling out up front:

- **Signing is deterministic (RFC 6979).** The per-signature nonce `k` is derived from the
  private key and the message hash via HMAC-SHA-based HKDF-style extraction, not from a
  live RNG. This eliminates the classic ECDSA vulnerability — if you ever sign two
  different messages with the same `k`, an attacker who sees both signatures recovers your
  private key. Since the spec is permissive about how `k` is chosen, getting this wrong is
  extremely common in real systems (Sony PlayStation 3, Bitcoin wallets, Android key store
  bugs). Here the nonce is a deterministic function of the inputs, so no RNG quality or
  RNG-availability concerns at sign time.
- **Hash is pinned to the curve.** P-256 signs SHA-256 hashes; P-384 signs SHA-384 hashes.
  The caller computes the hash externally (typically via [`ssfsha2`](ssfsha2.md)) and
  passes the bytes to [`SSFECDSASign()`](#ssfecdsasign) /
  [`SSFECDSAVerify()`](#ssfecdsaverify). Mismatched hash length relative to the curve is a
  call-site error.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfecdsa--ecdsa-signatures-and-ecdh-key-agreement) Dependencies

- [`ssfport.h`](../ssfport.h) — also supplies the platform entropy source used by key
  generation (`/dev/urandom` on POSIX; needs a port on other targets, see
  [Notes](#notes)).
- [`ssfec`](ssfec.md) — curve point arithmetic (constant-time scalar multiplication for
  sign and ECDH; dual scalar multiplication for verify)
- [`ssfbn`](ssfbn.md) — big-number arithmetic (modular inverse for sign, reduction mod `n`)
- [`ssfhmac`](ssfhmac.md) — HMAC-SHA-based RFC 6979 deterministic nonce derivation
- [`ssfprng`](ssfprng.md) — only used by [`SSFECDSAKeyGen()`](#ssfecdsakeygen); signing
  itself does not need randomness
- [`ssfcrypt`](ssfcrypt.md) — constant-time comparisons in the signature path

<a id="notes"></a>

## [↑](#ssfecdsa--ecdsa-signatures-and-ecdh-key-agreement) Notes

- **Key-generation entropy is platform-dependent.** [`SSFECDSAKeyGen()`](#ssfecdsakeygen)
  seeds [`SSFPRNGInitContext()`](ssfprng.md#ssfprnginitcontext) from `/dev/urandom` on
  POSIX (macOS, Linux); on Windows it currently trips a `SSF_ASSERT(false)` and returns
  `false`. On a bare-metal target the caller must either (a) patch the internal
  `_SSFECDSAGetEntropy()` helper to read from a hardware RNG / TRNG or ROSC, or
  (b) perform key generation on a trusted build host and provision the derived
  `(privKey, pubKey)` pair into the device, using only
  [`SSFECDSAPubKeyFromPrivKey()`](#ssfecdsapubkeyfromprivkey) at runtime. **Never** use
  this module's `KeyGen` on a target that lacks a genuine entropy source — the whole
  module's security collapses if private keys are predictable.
- **Signing does not need an RNG.** After the one-time key-gen step, nothing in
  [`SSFECDSASign()`](#ssfecdsasign) consumes randomness. The signature nonce is
  `HMAC-SHA(privateKey, hash)`-derived per RFC 6979. Signatures are deterministic:
  identical inputs produce identical signatures.
- **Hash-algorithm pinning per curve.** The recommended pairing is:

  | Curve | Recommended hash | `hashLen` |
  |---|---|---|
  | P-256 | SHA-256 | 32 |
  | P-384 | SHA-384 | 48 |

  The code enforces only `1 ≤ hashLen ≤ coordBytes` (per FIPS 186-4 §6.4 / RFC 5758 §3.2,
  which allow any hash no larger than the curve's coordinate size — `bits2int` handles the
  variable length). Shorter-than-recommended hashes are accepted but reduce the effective
  security level; use the recommended pairing unless you have a concrete interop reason to
  deviate. Hashes *longer* than `coordBytes` are rejected by a `SSF_REQUIRE` — this
  implementation does not do the RFC 5758 truncation-from-left step. Using the wrong hash
  *algorithm* (different construction at the same length) produces a technically valid
  signature that commits to the wrong value — a semantic failure, not a crypto-primitive
  failure. Sign and verify must agree on the hash algorithm.
- **Private key format is raw big-endian integer.** Size is exactly `coordBytes` for the
  curve — 32 for P-256, 48 for P-384. No ASN.1 wrapping, no length prefix. `SSFECDSA*`
  functions accept this bare-integer form directly. When interoperating with PEM / DER
  PKCS#8 or SEC 1 `ECPrivateKey` files, extract the bare integer at the call site.
- **Public key format is SEC 1 uncompressed.** `0x04 || X || Y`, inherited from
  [`ssfec`](ssfec.md#serialization). Length is `1 + 2·coordBytes` — 65 bytes for P-256,
  97 for P-384. Compressed encodings (`0x02`/`0x03`) are not accepted.
- **Signature format is DER `SEQUENCE { INTEGER r, INTEGER s }`** per SEC 1 / X.690.
  Length is variable (39–72 bytes for P-256, 71–104 for P-384) because each `INTEGER` may
  gain an extra `0x00` leading byte when its high bit is set. Size the output buffer to
  [`SSF_ECDSA_MAX_SIG_SIZE`](#ssf-ecdsa-max-sig-size); the actual length is returned via
  `*sigLen`.
- **ECDH output is the raw X coordinate of `d·P_peer`.** Feed it through
  [`ssfhkdf`](ssfhkdf.md) (NIST SP 800-56C extraction + expansion) to produce usable
  session keys. Do **not** use the raw ECDH bytes directly as a symmetric key — the
  distribution of valid shared X coordinates is not uniform over `{0, 1}^(coordBytes·8)`,
  and using them verbatim gives an attacker predictable structure to exploit.
- **The peer's public key is validated inside both `SSFECDHComputeSecret` and
  `SSFECDSAVerify`.** They parse and validate via [`SSFECPointDecode()`](ssfec.md#serialization),
  which runs [`SSFECPointValidate()`](ssfec.md#ssfecpointvalidate) (on-curve, in range,
  not identity). An invalid or off-curve key returns `false` before any scalar arithmetic
  runs, so invalid-curve attacks are closed by construction.
- **Signing is constant-time; verification is not.** Sign uses the constant-time
  [`SSFECScalarMul`](ssfec.md#ssfecscalarmul) path and constant-time modular inverse
  ([`SSFBNModInv`](ssfbn.md#modinv), which is Fermat-based over the prime curve order `n`)
  and constant-time MAC compare via [`ssfcrypt`](ssfcrypt.md). Verify uses the variable-time
  [`SSFECScalarMulDual`](ssfec.md#ssfecscalarmuldual) — fine because everything fed into
  verify is public.
- **Zero `r` or `s` in a signature is rejected.** Per FIPS 186-4 §6.4.2 the verifier
  rejects any signature where `r` or `s` is outside `[1, n-1]`; an all-zero `s` in
  particular would permit forgeries. This module enforces those ranges both during sign
  (loops until it produces a valid pair) and during verify (hard-rejects).
- **Private keys are zeroized before return from every function that touches them.**
  `SSFECDSAKeyGen`, `SSFECDSAPubKeyFromPrivKey`, `SSFECDSASign`, and
  `SSFECDHComputeSecret` all run [`SSFBNZeroize`](ssfbn.md#ssfbnzeroize) over the working
  private-key bignum before unwinding their stack frame. Callers are still responsible for
  erasing the caller-provided `privKey` byte buffer at an appropriate time.

<a id="configuration"></a>

## [↑](#ssfecdsa--ecdsa-signatures-and-ecdh-key-agreement) Configuration

Options live in [`_opt/ssfecdsa_opt.h`](../_opt/ssfecdsa_opt.h). Curve enablement flows
through from [`ssfec`](ssfec.md#configuration) via `SSF_EC_CONFIG_ENABLE_P256` /
`SSF_EC_CONFIG_ENABLE_P384`.

| Macro | Default | Description |
|-------|---------|-------------|
| `SSF_ECDSA_CONFIG_ENABLE_SIGN` | `1` | Compile `SSFECDSASign` and the DER-encode helper. Setting to `0` drops them — and drops the only `ssfasn1` reference in this module. The verify path was refactored so DER-input parsing is purely byte-level (no `ssfasn1` calls), so a verify-only build can omit the entire `ssfasn1` module from its project. `SSFECDSAVerify`, `SSFECDSAKeyGen`, and `SSFECDHComputeSecret` are unaffected. |

The [`SSF_CRYPT_PROFILE_MIN_MEMORY`](ssfcrypt.md#configuration) profile defaults
`SSF_ECDSA_CONFIG_ENABLE_SIGN = 0` since the typical MIN_MEMORY use case (firmware-update
verifier) needs verify but not on-device signing.

<a id="api-summary"></a>

## [↑](#ssfecdsa--ecdsa-signatures-and-ecdh-key-agreement) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-ecdsa-max-priv-key-size"></a>`SSF_ECDSA_MAX_PRIV_KEY_SIZE` | Constant | Maximum private-key byte length across enabled curves. Alias for [`SSF_EC_MAX_COORD_BYTES`](ssfec.md#ssf-ec-max-coord-bytes) — `32` for P-256-only, `48` when P-384 is enabled. |
| <a id="ssf-ecdsa-max-pub-key-size"></a>`SSF_ECDSA_MAX_PUB_KEY_SIZE` | Constant | Maximum public-key byte length (SEC 1 uncompressed) — `65` for P-256-only, `97` when P-384 is enabled. |
| <a id="ssf-ecdsa-max-sig-size"></a>`SSF_ECDSA_MAX_SIG_SIZE` | Constant | Maximum DER signature byte length — `72` for P-256-only, `104` when P-384 is enabled. |
| <a id="ssf-ecdh-max-secret-size"></a>`SSF_ECDH_MAX_SECRET_SIZE` | Constant | Maximum ECDH shared-secret byte length (curve coordinate bytes) — same as `SSF_ECDSA_MAX_PRIV_KEY_SIZE`. |

<a id="functions"></a>

### Functions

**[Key management](#key-management)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-keygen) | [`bool SSFECDSAKeyGen(curve, privKey, privKeySize, pubKey, pubKeySize, pubKeyLen)`](#ssfecdsakeygen) | Generate a fresh `(privKey, pubKey)` pair from platform entropy |
| [e.g.](#ex-derive) | [`bool SSFECDSAPubKeyFromPrivKey(curve, privKey, privKeyLen, pubKey, pubKeySize, pubKeyLen)`](#ssfecdsapubkeyfromprivkey) | Derive the public key from a provisioned private key |
| | [`bool SSFECDSAPubKeyIsValid(curve, pubKey, pubKeyLen)`](#ssfecdsapubkeyisvalid) | Parse + validate a public key blob (on-curve, in-range, non-identity) |

**[ECDSA sign / verify](#sign-verify)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-sign) | [`bool SSFECDSASign(curve, privKey, privKeyLen, hash, hashLen, sig, sigSize, sigLen)`](#ssfecdsasign) | Produce a DER signature; RFC 6979 deterministic |
| [e.g.](#ex-verify) | [`bool SSFECDSAVerify(curve, pubKey, pubKeyLen, hash, hashLen, sig, sigLen)`](#ssfecdsaverify) | Verify a DER signature |

**[ECDH key agreement](#ecdh)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-ecdh) | [`bool SSFECDHComputeSecret(curve, privKey, privKeyLen, peerPubKey, peerPubKeyLen, secret, secretSize, secretLen)`](#ssfecdhcomputesecret) | Compute the raw ECDH shared secret (the X coordinate of `d·P_peer`); the peer's public key is validated before use |

<a id="function-reference"></a>

## [↑](#ssfecdsa--ecdsa-signatures-and-ecdh-key-agreement) Function Reference

<a id="key-management"></a>

### [↑](#functions) Key Management

<a id="ssfecdsakeygen"></a>
```c
bool SSFECDSAKeyGen(SSFECCurve_t curve,
                    uint8_t *privKey, size_t privKeySize,
                    uint8_t *pubKey,  size_t pubKeySize, size_t *pubKeyLen);
```
Generate a fresh `(privKey, pubKey)` pair for `curve`. Draws
[`SSF_PRNG_ENTROPY_SIZE`](ssfprng.md#ssf-prng-entropy-size) (16) bytes from the platform
entropy source, seeds an internal [`SSFPRNGContext_t`](ssfprng.md#ssfprngcontext-t), and
rejection-samples a `d ∈ [1, n−1]` — then derives `Q = d·G` via constant-time scalar
multiplication and encodes the result. Returns `false` if entropy is unavailable, if the
100 rejection-sampling attempts all fail (overwhelmingly unlikely), or if the caller's
output buffers are undersized.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `curve` | in | `SSFECCurve_t` | Curve selector. |
| `privKey` | out | `uint8_t *` | Raw big-endian private key. Must not be `NULL`. |
| `privKeySize` | in | `size_t` | Size of `privKey`. Must be ≥ `coordBytes` (32 / 48). |
| `pubKey` | out | `uint8_t *` | SEC 1 uncompressed public key (`0x04 ‖ X ‖ Y`). Must not be `NULL`. |
| `pubKeySize` | in | `size_t` | Size of `pubKey`. Must be ≥ `1 + 2·coordBytes` (65 / 97). |
| `pubKeyLen` | out | `size_t *` | Actual bytes written to `pubKey`. Must not be `NULL`. |

**Returns:** `true` on success, `false` on entropy failure or buffer sizing failure.

<a id="ex-keygen"></a>

**Example:**

```c
uint8_t priv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];   /* 32 B for P-256 */
uint8_t pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];     /* 65 B for P-256 */
size_t  pubLen;

if (!SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                    priv, sizeof(priv),
                    pub,  sizeof(pub), &pubLen))
{
    /* Platform entropy unavailable — on a target without /dev/urandom,
       wire up a TRNG in _SSFECDSAGetEntropy(). */
}
/* priv holds the raw 32-byte scalar; pub holds 0x04 || X(32) || Y(32). */
```

<a id="ssfecdsapubkeyfromprivkey"></a>
```c
bool SSFECDSAPubKeyFromPrivKey(SSFECCurve_t curve,
                               const uint8_t *privKey, size_t privKeyLen,
                               uint8_t *pubKey, size_t pubKeySize, size_t *pubKeyLen);
```
Derive the public key `Q = d·G` from a pre-existing private key, without touching the
entropy source. Useful when keys are provisioned into a device at manufacture and the
device needs its own public key at boot. Returns `false` if the scalar is outside
`[1, n−1]` or if buffer sizes are wrong.

<a id="ex-derive"></a>

**Example:**

```c
/* Private key provisioned from a secure element or factory-burned flash. */
extern const uint8_t provisioned_priv[32];

uint8_t pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
size_t  pubLen;

SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P256,
                          provisioned_priv, 32,
                          pub, sizeof(pub), &pubLen);
/* pub is now the device's ECDSA public key, ready to include in CSRs,
   attestations, or ECDH handshakes. */
```

<a id="ssfecdsapubkeyisvalid"></a>
```c
bool SSFECDSAPubKeyIsValid(SSFECCurve_t curve, const uint8_t *pubKey, size_t pubKeyLen);
```
Parse the SEC 1 uncompressed encoding and return whether it decodes to a valid on-curve
point. Shorthand for `SSFECPointDecode(...)` + throwing away the resulting point. Useful
when certifying a public key or accepting one into a key store — run this before the key
enters a long-lived context so mis-encoded or off-curve keys are rejected up front.

---

<a id="sign-verify"></a>

### [↑](#functions) ECDSA Sign and Verify

<a id="ssfecdsasign"></a>
```c
bool SSFECDSASign(SSFECCurve_t curve,
                  const uint8_t *privKey, size_t privKeyLen,
                  const uint8_t *hash,    size_t hashLen,
                  uint8_t *sig, size_t sigSize, size_t *sigLen);
```
Produce a DER-encoded ECDSA signature over `hash`. Deterministic (RFC 6979): the per-
signature nonce `k` is derived as `HMAC-DRBG(privKey, hash)` with the SHA algorithm
matching the curve, so calling twice with the same inputs yields the same signature.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `curve` | in | `SSFECCurve_t` | Curve selector. |
| `privKey` | in | `const uint8_t *` | Raw big-endian private key. Must not be `NULL`. |
| `privKeyLen` | in | `size_t` | Must equal `coordBytes` for the curve (32 / 48). |
| `hash` | in | `const uint8_t *` | Message digest. Must not be `NULL`. |
| `hashLen` | in | `size_t` | Must be in `[1, coordBytes]` — 32 for P-256, 48 for P-384. The recommended pairing is SHA-256 / P-256 and SHA-384 / P-384; longer hashes are rejected and shorter ones reduce security (see [Notes](#notes)). |
| `sig` | out | `uint8_t *` | Buffer for DER signature. Must not be `NULL`. |
| `sigSize` | in | `size_t` | Size of `sig`. Must be ≥ [`SSF_ECDSA_MAX_SIG_SIZE`](#ssf-ecdsa-max-sig-size). |
| `sigLen` | out | `size_t *` | Actual bytes written to `sig`. |

**Returns:** `true` on success; `false` if the private key is invalid or the output buffer
is too small.

<a id="ex-sign"></a>

**Example:**

```c
/* Sign a message with P-256 + SHA-256. */
const uint8_t *msg;
size_t         msgLen;

uint8_t hash[SSF_SHA2_256_BYTE_SIZE];
SSFSHA256(msg, (uint32_t)msgLen, hash, sizeof(hash));

uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
size_t  sigLen;

if (!SSFECDSASign(SSF_EC_CURVE_P256,
                  priv, 32,
                  hash, sizeof(hash),
                  sig,  sizeof(sig), &sigLen))
{
    /* Should not happen for a valid privKey; indicates a bug or buffer
       sizing mistake at the call site. */
}
/* sig[0..sigLen-1] is the DER SEQUENCE { INTEGER r, INTEGER s }. */
```

<a id="ssfecdsaverify"></a>
```c
bool SSFECDSAVerify(SSFECCurve_t curve,
                    const uint8_t *pubKey, size_t pubKeyLen,
                    const uint8_t *hash,   size_t hashLen,
                    const uint8_t *sig,    size_t sigLen);
```
Verify a DER-encoded ECDSA signature. Validates the public key (decode + on-curve + in
range), parses the signature, rejects out-of-range `r` or `s`, and performs the verify
equation via the variable-time [`SSFECScalarMulDual`](ssfec.md#ssfecscalarmuldual).

**Returns:** `true` iff the signature is well-formed **and** verifies against the public
key and hash. Any parse failure, out-of-range component, or verify-equation mismatch
returns `false` — callers should treat all `false` outcomes identically and reject the
signed message.

<a id="ex-verify"></a>

**Example:**

```c
/* At the peer: verify the signature we just received. */
if (!SSFECDSAVerify(SSF_EC_CURVE_P256,
                    peerPub, peerPubLen,
                    hash,    sizeof(hash),
                    sig,     sigLen))
{
    /* Signature is bad — message was tampered with, signer used the wrong
       key, or the encoding is malformed. Reject the message. */
    return;
}
/* Accept and process the message. */
```

---

<a id="ecdh"></a>

### [↑](#functions) ECDH Key Agreement

<a id="ssfecdhcomputesecret"></a>
```c
bool SSFECDHComputeSecret(SSFECCurve_t curve,
                          const uint8_t *privKey,    size_t privKeyLen,
                          const uint8_t *peerPubKey, size_t peerPubKeyLen,
                          uint8_t *secret, size_t secretSize, size_t *secretLen);
```
Compute the raw ECDH shared secret `(X coord of d·P_peer)`. The peer's public key is
decoded and validated before any scalar arithmetic runs, so invalid-curve attempts are
rejected without leaking anything. The shared point is then computed with the constant-time
[`SSFECScalarMul`](ssfec.md#ssfecscalarmul), converted to affine, and the X coordinate is
returned big-endian in `coordBytes` bytes.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `curve` | in | `SSFECCurve_t` | Curve selector. |
| `privKey` | in | `const uint8_t *` | Local private key. |
| `privKeyLen` | in | `size_t` | Must equal `coordBytes`. |
| `peerPubKey` | in | `const uint8_t *` | Peer's SEC 1 uncompressed public key. |
| `peerPubKeyLen` | in | `size_t` | `1 + 2·coordBytes`. |
| `secret` | out | `uint8_t *` | Raw shared secret buffer. |
| `secretSize` | in | `size_t` | Must be ≥ `coordBytes`. |
| `secretLen` | out | `size_t *` | Actual bytes written (= `coordBytes`). |

**Returns:** `true` on success; `false` if the peer's key is invalid, the private key is
out of range, or the output buffer is too small.

**The raw output is not a key.** Pass it through
[`SSFHKDFExtract()`](ssfhkdf.md#ssfhkdfextract) +
[`SSFHKDFExpand()`](ssfhkdf.md#ssfhkdfexpand), or the one-shot
[`SSFHKDF()`](ssfhkdf.md#ssfhkdf), to derive the actual session keying material.

<a id="ex-ecdh"></a>

**Example:**

```c
/* ECDH + HKDF: produce two 32-byte AES-256 keys (client-write and
   server-write) from the raw shared secret. */
uint8_t shared[SSF_ECDH_MAX_SECRET_SIZE];
size_t  sharedLen;

if (!SSFECDHComputeSecret(SSF_EC_CURVE_P256,
                          myPriv, 32,
                          peerPub, peerPubLen,
                          shared, sizeof(shared), &sharedLen))
{
    /* Peer supplied an invalid public key — abort the handshake. */
    return;
}
/* sharedLen == 32; shared[] is the raw ECDH X coordinate. */

uint8_t clientKey[32];
uint8_t serverKey[32];
const uint8_t salt[] = "session-salt";

SSFHKDF(SSF_HMAC_HASH_SHA256,
        salt, sizeof(salt) - 1,
        shared, sharedLen,
        (const uint8_t *)"client write key", 16,
        clientKey, sizeof(clientKey));

SSFHKDF(SSF_HMAC_HASH_SHA256,
        salt, sizeof(salt) - 1,
        shared, sharedLen,
        (const uint8_t *)"server write key", 16,
        serverKey, sizeof(serverKey));

/* Wipe the raw ECDH output now that the session keys have been derived. */
memset(shared, 0, sizeof(shared));
```
