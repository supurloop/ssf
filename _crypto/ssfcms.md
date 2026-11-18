# ssfcms — CMS SignedData Verifier

[SSF](../README.md) | [Crypto](README.md)

Verifies RFC 5652 Cryptographic Message Syntax `SignedData`, the format behind detached file
signatures, firmware manifests, S/MIME and PKCS#7. The parser is zero-copy over the caller's DER
and the verifier checks each signer's digest, signed attributes, signature and certificate chain
against a caller-supplied trust store. There is no encoder: the module verifies, it does not sign.

[Dependencies](#dependencies) | [Limitations](#limitations) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfcms--cms-signeddata-verifier) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfasn1`](../_codec/ssfasn1.md) — DER decoding
- [`ssfx509`](../_codec/ssfx509.md) — certificate parsing, `SSFX509VerifySignature()` for the
  signature itself and `SSFX509VerifyChainPurpose()` for the signer's chain
- [`ssfsha2`](ssfsha2.md) — SHA-256 / SHA-384 / SHA-512 digests of attached content
- [`ssfcrypt`](ssfcrypt.md) — `SSFCryptCTMemEq()` for the constant-time message-digest comparison
- [`ssftls`](ssftls.md) — trace callback type and `SSF_TLS_TRACE_CERT_*` macros

<a id="limitations"></a>

## [↑](#ssfcms--cms-signeddata-verifier) Limitations

- **SignedData only.** `ContentInfo` must carry `id-signedData`. EnvelopedData, DigestedData,
  EncryptedData and AuthenticatedData are not recognized.
- **DER only, definite lengths.** BER indefinite-length encoding, which `openssl cms -sign` emits
  by default, fails to parse. Produce DER with `-noindef`, or convert BER to DER before calling.
  Constructed OCTET STRING content (`0x24`) is likewise rejected.
- **Bounded.** The message must be at most [`SSF_CMS_CONFIG_MAX_DER_LEN`](#cfg-max-der-len)
  bytes and hold at most [`SSF_CMS_CONFIG_MAX_SIGNERS`](#cfg-max-signers) signers,
  [`SSF_CMS_CONFIG_MAX_CERTS`](#cfg-max-certs) certificates and
  [`SSF_CMS_CONFIG_MAX_DIGEST_ALGS`](#cfg-max-digest-algs) digest algorithms; more of any of
  these fails the parse, since an unretained signer or certificate would be invisible to the
  verifier. A signer whose `signedAttrs` encoding exceeds
  [`SSF_CMS_CONFIG_MAX_SIGNED_ATTRS_LEN`](#cfg-max-signed-attrs-len) parses but cannot verify.
- **Algorithms.** Digests SHA-256, SHA-384 and SHA-512 (RFC 5754). Signatures as
  [`ssfx509`](../_codec/ssfx509.md) supports them: `ecdsa-with-SHA256` / `-SHA384` on P-256 or
  P-384 keys (the hash may not be longer than the curve order), `rsaEncryption` with the hash taken
  from the digest algorithm (RFC 3370), `sha256/384/512WithRSAEncryption`, `id-RSASSA-PSS` with
  parameters (RFC 4056), and `id-Ed25519` paired with SHA-512 (RFC 8419). SHA-1 and MD5 are
  rejected.
- **Versions.** `SignedData` version 1 or 3; `SignerInfo` version 1 with `issuerAndSerialNumber`
  or version 3 with `subjectKeyIdentifier`. A version that disagrees with the identifier form
  fails the parse.
- **Not implemented.** Revocation (`crls` is skipped), countersignatures and timestamp tokens in
  `unsignedAttrs` (skipped unread), attribute certificates and other `CertificateChoices`
  (skipped), and verification of a signer that has no signed attributes from a bare digest
  (see [Notes](#notes)).

<a id="notes"></a>

## [↑](#ssfcms--cms-signeddata-verifier) Notes

- **Zero-copy.** Every pointer in [`SSFCMSSignedData_t`](#type-signeddata) and
  [`SSFCMSVerifyResult_t`](#type-result) points into the DER passed to
  [`SSFCMSParse()`](#ssfcmsparse), which must outlive them. Certificates are kept as DER spans and
  parsed on demand, so the structure stays a few hundred bytes.
- **Parse is strict.** Any structural DER error, trailing bytes at any level, an unexpected
  `contentType`, an unsupported version, a digest `AlgorithmIdentifier` (in `digestAlgorithms`,
  a SignerInfo, or a `CMSAlgorithmProtection` attribute) whose parameters are anything but
  absent or `NULL`, a `signedAttrs` set missing `content-type` or `message-digest`
  (RFC 5652 §5.3) or carrying any of `content-type`, `message-digest`, `signing-time` or
  `CMSAlgorithmProtection` more than once or with other than exactly one value (§11), or a
  `CMSAlgorithmProtection` without its `signatureAlgorithm` (RFC 6211 §2) returns `false`.
  Unknown attributes such as S/MIME capabilities are left unread. Two places inside
  `signedAttrs` are not held to this: bytes after an `Attribute`'s value `SET` are not
  rejected, and an unknown attribute is not checked for at least one value or for being
  repeated. Both lie inside the signed bytes, which are hashed verbatim, so they cannot alter
  what the signature covers.
- **The content digest comes from the caller.** The primary use is a detached signature over a
  file the caller has already hashed. [`SSFCMSVerifyDigest()`](#ssfcmsverifydigest) takes that
  digest and its algorithm; [`SSFCMSGetDigestAlg()`](#ssfcmsgetdigestalg) says which algorithm a
  signer used, so the natural order is parse, read the algorithm, hash the file, verify. When the
  message carries its content, [`SSFCMSVerifyAttached()`](#ssfcmsverifyattached) hashes it
  internally. A digest supplied for a message with attached content is never ignored: without
  signed attributes it must equal the digest of that content; with signed attributes it is checked
  against the signed `message-digest` attribute, which is what the signature binds, and the
  attached copy of the content is not consulted. A caller who wants the attached copy itself
  checked uses [`SSFCMSVerifyAttached()`](#ssfcmsverifyattached).
- **Verification order, per signer.** The signer's digest algorithm is supported and listed in
  `digestAlgorithms`; the supplied digest is for that algorithm and length (or attached content
  is digested); if `CMSAlgorithmProtection` is present its digest and signature algorithms,
  parameters included, equal the SignerInfo's (RFC 6211), which defeats algorithm substitution;
  with signed attributes, `content-type` equals `eContentType` and `message-digest` equals the
  content digest in constant time, then the attributes re-tagged from `[0] IMPLICIT` to `SET`
  (§5.4) are what the signature covers; without signed attributes the content itself is covered,
  so it must be attached `id-data`; the signer certificate is located by issuer and serial or by
  SKID among the embedded certificates and then the trust anchors; the embedded certificates are
  ordered into a chain by issuer-to-subject links up to the first one a trust anchor issued (when
  several embedded certificates share the issuer name, as across a CA key rollover, the one whose
  Subject Key Identifier equals the child's Authority Key Identifier is taken, else the first), and
  that chain passes `SSFX509VerifyChainPurpose()` for `SSF_X509_PURPOSE_CODE_SIGNING` at
  `nowUnixSec`: validity, CA constraints, path length, Key Usage `digitalSignature` or
  `nonRepudiation` on the signer when Key Usage is present, EKU `codeSigning` or
  `anyExtendedKeyUsage` when EKU is present, Name Constraints and no unknown critical extension;
  only then does the signature verify with that certificate's key under the declared algorithms
  through `SSFX509VerifySignature()`, so a public key taken from the message is never used before
  its certificate is trusted (the same order as OpenSSL `CMS_verify`). The first signer that
  passes every step wins; the result reports which one.
- **Trust anchors.** The anchor is typically the root or an intermediate the caller trusts and is
  not usually embedded in the message. A signer certificate that is itself a trust anchor is
  accepted when it is self-signed. Anchors sharing a subject name are distinguished by the key
  that verifies, as in `ssfx509`.
- **Time.** Certificates are checked at the caller's `nowUnixSec`, never at the message's
  `signing-time`, which is reported in the result for the caller's own policy.
- **Trace output.** Failure reasons and the verified signer are reported through a module-wide
  [`ssftls`](ssftls.md) trace callback installed with [`SSFCMSSetTraceCtx()`](#ssfcmssettracectx),
  category `SSF_TLS_TRACE_CERT`. Messages begin with `CMS:`. The callback pointer is the module's
  only static state.
- **Stack usage.** The verifier holds two parsed `SSFX509Cert_t` structures, a re-tagging buffer of
  `SSF_CMS_CONFIG_MAX_SIGNED_ATTRS_LEN` bytes and the chain arrays, on top of whatever
  `SSFX509VerifyChainPurpose()` uses (see the `ssfx509` footnotes in the [SSF
  README](../README.md#crypto)).
- **Test fixtures.** `ssfcms_ut_fix.h` is generated by the scripts in `ssfcms_ut_fixtures/`:
  `gen.sh` makes the keys, certificates and messages with OpenSSL 3.2, `gen_modeled.pl` the
  production-shaped message below, `gen_rollover.sh` the CA key-rollover messages (two
  intermediates with the same name and different keys), and `toc.sh` converts the DER into the
  header. The content is
  24 bytes; the ECDSA chain message is `openssl cms -sign -binary -noindef -outform DER -in
  content.bin -signer leaf.pem -inkey leaf.key -certfile int.pem -md sha256`, and variants add
  `-keyid`, `-nodetach`, `-noattr`, `-keyopt rsa_padding_mode:pss`, a second `-signer`, an RSA
  leaf issued by the P-256 intermediate, or drop `-noindef` for the rejected BER form. Regenerating changes every key, so the tests assert only
  on structure, names, serial prefixes and lengths. The unit test also builds its own messages for Ed25519,
  `CMSAlgorithmProtection`, the configured limits and malformed attribute sets. A further fixture
  models a production firmware signature: a root that is not embedded, two CA levels issued with
  `openssl ca` carrying ADCS-style 19-byte serials, Certificate Policies, CRL and AIA pointers and
  GeneralizedTime expiry in 2075, a leaf with a 20-byte serial and a CN-first subject, signed
  attributes including `CMSAlgorithmProtection`, and an RFC 3161 token from `openssl ts` in the
  unsigned attributes. OpenSSL produced every key, certificate, signature (`openssl pkeyutl -sign
  -rawin -digest sha256` over the DER `SET` of attributes) and token; a short script assembled the
  CMS around them, and `openssl cms -verify -purpose any` confirms the result against the root.

<a id="configuration"></a>

## [↑](#ssfcms--cms-signeddata-verifier) Configuration

Options live in [`_opt/ssfcms_opt.h`](../_opt/ssfcms_opt.h).

| Macro | Default | Description |
|-------|---------|-------------|
| <a id="cfg-max-der-len"></a>`SSF_CMS_CONFIG_MAX_DER_LEN` | `8192` | Longest `ContentInfo` [`SSFCMSParse()`](#ssfcmsparse) accepts. A detached signature with a three-certificate chain is about 4 KB. |
| <a id="cfg-max-signers"></a>`SSF_CMS_CONFIG_MAX_SIGNERS` | `2` | `SignerInfo` entries retained; more fail the parse. |
| <a id="cfg-max-certs"></a>`SSF_CMS_CONFIG_MAX_CERTS` | `4` | Embedded certificates retained; more fail the parse. Sizes the chain the verifier can assemble. |
| <a id="cfg-max-digest-algs"></a>`SSF_CMS_CONFIG_MAX_DIGEST_ALGS` | `2` | `digestAlgorithms` entries retained; more fail the parse. |
| <a id="cfg-max-signed-attrs-len"></a>`SSF_CMS_CONFIG_MAX_SIGNED_ATTRS_LEN` | `512` | Largest `signedAttrs` encoding the verifier can re-tag; sizes an on-stack buffer. OpenSSL's default set is about 150 bytes. |

The unit-test entry point is gated by `SSF_CONFIG_CMS_UNIT_TEST` in `ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfcms--cms-signeddata-verifier) API Summary

### Types

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-digest"></a>`SSFCMSDigestAlg_t` | Enum | `SSF_CMS_DIGEST_SHA256`, `SSF_CMS_DIGEST_SHA384`, `SSF_CMS_DIGEST_SHA512`, bracketed by `_MIN` and `_MAX`. |
| <a id="type-cert"></a>`SSFCMSCert_t` | Struct | One embedded certificate as a DER span: `der` / `derLen`. |
| <a id="type-signer"></a>`SSFCMSSignerInfo_t` | Struct | One `SignerInfo`: `version`; the identifier as `sidIssuerRaw` / `sidSerial` (version 1) or `sidSkid` (version 3); `digestAlgOidRaw`; the whole `signedAttrs` TLV (`NULL` if absent) with the decoded `contentTypeOidRaw`, `messageDigest`, `hasSigningTime` / `signingTime`, and `hasAlgProtection` with `apDigestAlgOidRaw`, `apSigAlgOidRaw`, `apSigAlgParams`; `sigAlgOidRaw` / `sigAlgParams`; `signature`. Each pointer has its `Len`. |
| <a id="type-signeddata"></a>`SSFCMSSignedData_t` | Struct | Parsed `SignedData`: `version`; `digestAlgOidRaw[]` / `digestAlgsLen`; `eContentTypeOidRaw`; `hasEContent` with `eContent` / `eContentLen`; `certs[]` / `certsLen`; `signers[]` / `signersLen`. |
| <a id="type-result"></a>`SSFCMSVerifyResult_t` | Struct | `signerIndex`, `signerSubject` (an [`SSFX509Name_t`](../_codec/ssfx509.md#type-name) into the signer certificate), `hasSigningTime` / `signingTime`. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-verify) | [`bool SSFCMSParse(der, derLen, sdOut)`](#ssfcmsparse) | Zero-copy parse of a `ContentInfo` carrying `SignedData` |
| [e.g.](#ex-verify) | [`bool SSFCMSGetDigestAlg(sd, signerIndex, algOut)`](#ssfcmsgetdigestalg) | Digest algorithm a signer used, so the caller can hash the file |
| [e.g.](#ex-verify) | [`bool SSFCMSVerifyDigest(sd, digest, digestLen, digestAlg, trustDer, trustDerLen, trustCount, nowUnixSec, resultOut)`](#ssfcmsverifydigest) | Verify against the caller's content digest |
| | [`bool SSFCMSVerifyAttached(sd, trustDer, trustDerLen, trustCount, nowUnixSec, resultOut)`](#ssfcmsverifyattached) | Verify against content carried in the message |
| | [`void SSFCMSSetTraceCtx(fnOpt, userCtxOpt)`](#ssfcmssettracectx) | Install the diagnostic trace callback |

<a id="function-reference"></a>

## [↑](#ssfcms--cms-signeddata-verifier) Function Reference

<a id="ssfcmsparse"></a>

### [↑](#functions) [`bool SSFCMSParse()`](#functions)

```c
bool SSFCMSParse(const uint8_t *der, uint32_t derLen, SSFCMSSignedData_t *sdOut);
```

Parses a DER `ContentInfo` whose content is `SignedData` into `*sdOut`, zeroing the structure
first. Applies every check listed under **Parse is strict** in [Notes](#notes).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `der` | in | `const uint8_t *` | The CMS message. Must not be `NULL`, and must stay valid while `*sdOut` is used. |
| `derLen` | in | `uint32_t` | Length of `der`; at most `SSF_CMS_CONFIG_MAX_DER_LEN`. |
| `sdOut` | out | `SSFCMSSignedData_t *` | Receives the parsed message. Must not be `NULL`. |

**Returns:** `true` on success; `false` on any structural or profile violation, after which the
contents of `*sdOut` are undefined.

---

<a id="ssfcmsgetdigestalg"></a>

### [↑](#functions) [`bool SSFCMSGetDigestAlg()`](#functions)

```c
bool SSFCMSGetDigestAlg(const SSFCMSSignedData_t *sd, uint8_t signerIndex,
                        SSFCMSDigestAlg_t *algOut);
```

Reports the digest algorithm signer `signerIndex` declares, so the caller can hash the content
with it before calling [`SSFCMSVerifyDigest()`](#ssfcmsverifydigest).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sd` | in | `const SSFCMSSignedData_t *` | Parsed message. Must not be `NULL`. |
| `signerIndex` | in | `uint8_t` | Signer to query; must be less than `sd->signersLen`. |
| `algOut` | out | `SSFCMSDigestAlg_t *` | Receives the algorithm. Must not be `NULL`. |

**Returns:** `true` if the signer's digest algorithm is one the module supports; `false`
otherwise, in which case that signer can never verify.

---

<a id="ssfcmsverifydigest"></a>

### [↑](#functions) [`bool SSFCMSVerifyDigest()`](#functions)

```c
bool SSFCMSVerifyDigest(const SSFCMSSignedData_t *sd, const uint8_t *digest, uint32_t digestLen,
                        SSFCMSDigestAlg_t digestAlg, const uint8_t **trustDer,
                        const uint32_t *trustDerLen, uint8_t trustCount, uint64_t nowUnixSec,
                        SSFCMSVerifyResult_t *resultOut);
```

Verifies the message against a content digest the caller computed, running the steps under
**Verification order** in [Notes](#notes) for each signer until one passes.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `sd` | in | `const SSFCMSSignedData_t *` | Parsed message. Must not be `NULL`. |
| `digest` | in | `const uint8_t *` | Digest of the signed content. Must not be `NULL`. |
| `digestLen` | in | `uint32_t` | Length of `digest`; must be the output size of `digestAlg`. Must be greater than `0`. |
| `digestAlg` | in | `SSFCMSDigestAlg_t` | Algorithm that produced `digest`. Must be a valid enumerator. |
| `trustDer` | in | `const uint8_t **` | Array of DER trust-anchor certificates. No entry may be `NULL`. |
| `trustDerLen` | in | `const uint32_t *` | Length of each `trustDer[j]`. |
| `trustCount` | in | `uint8_t` | Number of anchors; must be at least `1`. |
| `nowUnixSec` | in | `uint64_t` | Time at which every certificate must be valid. |
| `resultOut` | out | `SSFCMSVerifyResult_t *` | Receives which signer verified and what it asserted; zeroed on `false`. Must not be `NULL`. |

**Returns:** `true` if some signer verifies completely; `false` otherwise, with the reason
reported through the trace callback when one is installed.

<a id="ex-verify"></a>

```c
SSFCMSSignedData_t sd;
SSFCMSDigestAlg_t alg;
SSFCMSVerifyResult_t res;
uint8_t digest[SSF_SHA2_512_BYTE_SIZE];
const uint8_t *trust[1]   = { rootDer };
uint32_t trustLen[1]      = { rootDerLen };

if (SSFCMSParse(sigDer, sigDerLen, &sd) && SSFCMSGetDigestAlg(&sd, 0u, &alg))
{
    /* Hash the file with alg using ssfsha2's Begin/Update/End, chunk by chunk, into digest */
    if (SSFCMSVerifyDigest(&sd, digest, SSF_SHA2_256_BYTE_SIZE, alg, trust, trustLen, 1u,
                           nowUnixSec, &res))
    {
        /* file is signed by res.signerSubject, trusted via rootDer; res.signingTime if present */
    }
}
```

---

<a id="ssfcmsverifyattached"></a>

### [↑](#functions) [`bool SSFCMSVerifyAttached()`](#functions)

```c
bool SSFCMSVerifyAttached(const SSFCMSSignedData_t *sd, const uint8_t **trustDer,
                          const uint32_t *trustDerLen, uint8_t trustCount, uint64_t nowUnixSec,
                          SSFCMSVerifyResult_t *resultOut);
```

Verifies a message that carries its content in `eContent`, digesting that content with each
signer's algorithm. Returns `false` without verifying anything when the content is detached.
Parameters are as for [`SSFCMSVerifyDigest()`](#ssfcmsverifydigest) without the digest.

**Returns:** `true` if some signer verifies completely; `false` otherwise.

---

<a id="ssfcmssettracectx"></a>

### [↑](#functions) [`void SSFCMSSetTraceCtx()`](#functions)

```c
void SSFCMSSetTraceCtx(void (*fnOpt)(int, int, const char *, void *), void *userCtxOpt);
```

Installs the module-wide trace callback, with the shape of
[`SSFTLSTraceFn_t`](ssftls.md), receiving `SSF_TLS_TRACE_ERROR` or `SSF_TLS_TRACE_DEBUG`, the
category `SSF_TLS_TRACE_CERT`, a formatted message and `userCtxOpt`. Pass `NULL` to disable.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `fnOpt` | in (opt) | `void (*)(int, int, const char *, void *)` | Trace callback, or `NULL` to disable. |
| `userCtxOpt` | in (opt) | `void *` | Opaque pointer passed back to `fnOpt`; may be `NULL`. |
