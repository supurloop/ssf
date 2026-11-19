# ssfx509 — X.509 Certificate Parser, Generator, and Chain Verifier

[SSF](../README.md) | [Codecs](README.md)

X.509 v3 certificate support per RFC 5280, built on [`ssfasn1`](ssfasn1.md):

- A **zero-copy parser** that decodes a DER certificate into an [`SSFX509Cert_t`](#type-cert)
  whose pointer fields reference the caller's DER buffer. Extracts the common Distinguished Name
  attributes, validity window, SubjectPublicKeyInfo, and the extensions a TLS client needs
  (Basic Constraints, Key Usage, Extended Key Usage, Subject Alternative Name, Subject / Authority
  Key Identifier, Name Constraints).
- A **certificate generator** that encodes a TBSCertificate and a complete Certificate from an
  [`SSFX509GenParams_t`](#type-genparams) using the measure-then-write pattern, for self-signed
  device certificates, test fixtures, and small embedded CAs.
- A **chain verifier** that checks signatures (ECDSA P-256 / P-384, RSA PKCS#1 v1.5 and RSA-PSS,
  Ed25519), validity periods, CA constraints, path length, Key Usage, Extended Key Usage, Name
  Constraints, SKID / AKID consistency, unrecognized critical extensions, and the leaf's SAN
  against a hostname or IPv4 address, anchoring the chain in a caller-supplied trust store.

[Dependencies](#dependencies) | [Limitations](#limitations) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfx509--x509-certificate-parser-generator-and-chain-verifier) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfasn1`](ssfasn1.md) — DER decoding and encoding
- [`ssfmatch`](ssfmatch.md) — case-insensitive hostname comparison
- [`ssfstr`](ssfstr.md) — bounded C-string length for every name the API receives as a string
- [`ssfsha2`](../_crypto/ssfsha2.md) — SHA-256 / SHA-384 / SHA-512 TBS digests for signature verification
- [`ssfecdsa`](../_crypto/ssfecdsa.md) — ECDSA signature verification over P-256 / P-384
- [`ssfrsa`](../_crypto/ssfrsa.md) — RSA PKCS#1 v1.5 and RSA-PSS signature verification
- [`ssfed25519`](../_crypto/ssfed25519.md) — Ed25519 signature verification
- [`ssftls`](../_crypto/ssftls.md) — trace callback type and `SSF_TLS_TRACE_CERT_*` macros used
  to report verification diagnostics

<a id="limitations"></a>

## [↑](#ssfx509--x509-certificate-parser-generator-and-chain-verifier) Limitations

- **DER only, bounded size.** Certificates larger than
  [`SSF_X509_CONFIG_MAX_CERT_SIZE`](#cfg-max-cert-size) cannot be generated; both the measuring
  and the writing call of each encoder return `0`. The parser itself is zero-copy and reads any
  length the caller presents.
- **Generation input bounds.** The encoders refuse, with `0` from both passes, any Distinguished
  Name attribute over its RFC 5280 Appendix A upper bound (CN, O, OU 64 characters; ST, L 128;
  C exactly 2), any `dNSName` over 253 octets, and any key identifier over 64 octets (the longest
  RFC 7093 method, SHA-512). Values are emitted as `UTF8String` regardless of attribute type.
  String lengths are measured with a bounded scan of at most the limit plus one byte, so an
  over-long or unterminated value is refused without reading past its bound; the same bound caps
  the `hostnameStr` scan in [`SSFX509VerifyChain()`](#ssfx509verifychain), where a hostname over
  253 characters simply never matches.
- **Distinguished Names.** Only CN, O, OU, C, ST, and L are extracted into named fields. When an
  attribute repeats, the last occurrence wins. Attributes whose value is not one of the six
  DirectoryString types (for example an INTEGER `serialNumber`) are skipped rather than failing
  the parse. The raw DER of the whole Name is always retained in `raw` / `rawLen`, and the
  verifier compares issuer / subject names byte-for-byte on that raw DER.
- **Subject Alternative Names.** Up to [`SSF_X509_CONFIG_MAX_SAN_ENTRIES`](#cfg-max-san-entries)
  GeneralName entries of any type are retained with their tag number in `type`; further entries
  are dropped silently. Only `dNSName` (`SSF_X509_SAN_DNS`) and `iPAddress` (`SSF_X509_SAN_IP`)
  are interpreted by hostname matching and Name Constraints. `iPAddress` matching is IPv4 only.
- **Extensions.** Up to [`SSF_X509_CONFIG_MAX_EXTENSIONS`](#cfg-max-extensions) raw extensions are
  retained in `exts[]`; a certificate with more fails to parse. Authority Key Identifier is read
  only in its `keyIdentifier [0]` form. Extended Key Usage is reduced to four flags:
  `id-kp-serverAuth`, `id-kp-clientAuth`, `id-kp-codeSigning`, and `anyExtendedKeyUsage`, the
  last of which satisfies whichever purpose the verifier is checking per RFC 5280 §4.2.1.12. Name
  Constraints are
  read from every certificate but enforced only from intermediates and the trust anchor, and
  only `dNSName` and `iPAddress` subtrees are enforced, up to
  [`SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS`](#cfg-max-name-constraints) permitted and the same
  number of excluded. A constraint on any other name form (`directoryName`, `rfc822Name`, URI,
  `otherName`, and so on) is recorded but not enforced, so, as RFC 5280 §4.2.1.10 allows, a
  subordinate certificate carrying an instance of that form is rejected: a non-empty subject DN
  is a `directoryName` instance, and an `rfc822Name` SAN or an `emailAddress` subject attribute
  is an `rfc822Name` instance. In practice a CA with a `directoryName` constraint therefore
  cannot issue certificates that have a subject. A `dNSName` constraint may use the leading-dot form (`.example.com`),
  which matches proper subdomains only, in line with OpenSSL, NSS, and Go. An `iPAddress`
  subtree is matched by address family: a 16-byte (IPv6) permitted subtree never matches a
  4-byte SAN, so a CA that permits only IPv6 space rejects every IPv4 `iPAddress` SAN while
  leaving `dNSName` SANs unconstrained, and a 16-byte excluded subtree never excludes an IPv4
  SAN.
- **Not implemented.** Certificate revocation (CRL / OCSP), certificate policies and policy
  mappings, inhibit-anyPolicy, `issuerUniqueID` / `subjectUniqueID` (skipped), `otherName` /
  `rfc822Name` / URI SANs, IPv6 SANs and IPv6 Name Constraints, and Public Suffix List awareness
  for wildcard matching.
- **Server-authentication oriented.** [`SSFX509VerifyChain()`](#ssfx509verifychain) requires a
  hostname and, when the leaf carries an Extended Key Usage extension, requires it to include
  `serverAuth`. Verifying client certificates needs a caller-side check on `ekuClientAuth`
  instead.
- **Time.** Validity times are decoded by [`ssfasn1`](ssfasn1.md) into Unix seconds from either
  `UTCTime` or `GeneralizedTime`; the 1970 epoch is the floor, and the `99991231235959Z` "no
  expiry" convention is treated as an ordinary far-future date. The generator emits `UTCTime`
  only, so a `notBefore` or `notAfter` later than `2049-12-31T23:59:59Z` cannot be encoded and
  both encoder passes return `false`.

<a id="notes"></a>

## [↑](#ssfx509--x509-certificate-parser-generator-and-chain-verifier) Notes

- **The parser is zero-copy.** Every pointer in [`SSFX509Cert_t`](#type-cert) points into the
  DER buffer passed to [`SSFX509Parse()`](#ssfx509parse). The buffer must outlive the parsed
  structure and must not be modified while it is in use. The struct itself is large (several
  hundred bytes, scaling with the SAN / extension / Name Constraints limits); allocate it
  statically or on a stack you have sized for it.
- **Parse is strict about DER but lenient about content.** Any structural DER error (bad tags,
  truncated lengths, non-minimal INTEGER, malformed serial number, missing mandatory field, a
  SAN GeneralName whose declared length overruns the extension) returns `false`, as does a
  version field above v3 or more extensions than
  [`SSF_X509_CONFIG_MAX_EXTENSIONS`](#cfg-max-extensions), since an extension that could not be
  retained would escape the critical-extension and duplicate checks. Unknown extensions and
  unknown SAN types are retained without interpretation rather than rejected; policy decisions
  are left to [`SSFX509VerifyChain()`](#ssfx509verifychain). Two values are normalized at parse
  time: a `dNSName` SAN that is empty or contains a NUL byte is dropped, because no hostname can
  match it safely, and a `pathLenConstraint` above 127 is clamped to 127 so it stays a constraint.
  A `pathLenConstraint` that is not a valid unsigned INTEGER fails the parse, and an RSA-PSS
  `saltLength` that is not one fails verification. Likewise, an extension's `critical` flag, the
  Basic Constraints `cA` flag, the Authority Key Identifier `keyIdentifier`, or the EC curve OID
  that is present but does not decode fails the parse rather than reading as absent or false.
  A public key or signature BIT STRING with a nonzero unused-bit count fails the parse, and a
  Key Usage BIT STRING whose padding bits are set is malformed, so it carries no key usage bits.
  A recognized extension whose body is not the structure RFC 5280 defines (for example a Basic
  Constraints value that is not a SEQUENCE) does not fail the parse; the extension's `has*` flag
  is set and its decoded fields keep their fail-closed defaults, so such a certificate cannot act
  as a CA, carries no key usage bits, no key purposes, no SANs, and no key identifier.
  Name Constraints are the exception, because "no constraints" is not a fail-closed default: a
  Name Constraints value that is not exactly one non-empty SEQUENCE of an optional non-empty
  `[0]` followed by an optional non-empty `[1]`, or whose GeneralSubtree or GeneralName does not
  decode, fails the parse. GeneralName forms other than `dNSName` and `iPAddress` are still
  skipped (not enforced).
- **Serial numbers** must be 1–20 bytes and non-negative (RFC 5280 §4.1.2.2). A zero serial is
  accepted, as the RFC asks verifiers to tolerate it.
- **Signature algorithm consistency.** Both the TBS `signature` AlgorithmIdentifier and the outer
  `signatureAlgorithm` are captured, OID and raw parameters (`sigAlgOidRaw` / `sigAlgParams`
  and `outerSigAlgOidRaw` / `outerSigAlgParams`). The chain verifier rejects certificates where
  either part differs (RFC 5280 §4.1.1.2 and §4.1.2.3); only the TBS copy is covered by the
  signature, so the outer copy is never used for verification decisions.
- **Chain layout.** For [`SSFX509VerifyChain()`](#ssfx509verifychain), `chainDer[0]` is the leaf
  and each `chainDer[i]` must be signed by `chainDer[i + 1]`. The last chain certificate must be
  signed by one of the trust anchors; the anchors themselves are never part of the chain array.
  A self-signed leaf is verified by passing it as a one-element chain **and** as a trust anchor.
- **Verification order.** The verifier runs these checks and stops at the first failure: parse
  every chain cert; all certs are v3; TBS and outer signature algorithm identifiers agree,
  parameters included (§4.1.1.2); every cert is within its validity window at `nowUnixSec`; each
  `cert[i]` names `cert[i + 1]`'s subject as its issuer (§6.1.3 (a)(4)), is signed by
  `cert[i + 1]`, and their AKID / SKID agree when both are present; if the leaf has Extended Key
  Usage it includes `serverAuth` or `anyExtendedKeyUsage`; the last cert's issuer name matches a trust anchor's
  subject, that anchor is itself valid at `nowUnixSec`, its SKID agrees with the cert's AKID when
  both are present, and the anchor's key verifies the signature (the anchor that verifies is the
  one whose path length and Name Constraints are enforced below; other anchors that merely share
  its subject name, as during a root key rollover, play no part); every intermediate asserts
  `cA = TRUE` in Basic Constraints and, if Key Usage is present, includes `keyCertSign`; path
  length constraints hold for intermediates and the trust anchor (RFC 5280 §6.1.4(k)); if the
  leaf has Extended Key Usage it includes `serverAuth`; Name Constraints of every intermediate
  and of the trust anchor are satisfied by every subordinate certificate's SANs
  (§6.1.4(g)); no cert carries a critical extension outside the recognized set (Basic
  Constraints, Key Usage, SAN, SKID, AKID, EKU, Name Constraints); and finally `hostname` matches
  a `dNSName` or `iPAddress` SAN of the leaf.
- **Hostname matching** (RFC 6125 §6.4.3) is case-insensitive and exact against each `dNSName`.
  A single leading `*.` wildcard label is honored only when the hostname's leftmost label is
  non-empty and the base domain after `*.` contains at least one interior `.` (so `*.example.com`
  matches `www.example.com`, but matches neither `.example.com` nor, for `*.com`, anything). A
  hostname written as a dotted-decimal IPv4 address is matched against 4-byte `iPAddress` SANs
  only, never against `dNSName` SANs (RFC 9525 §6.3), so a `dNSName` of `8.8.8.8` or `*.0.0.1`
  cannot satisfy it; each octet is read as decimal, so leading zeros are accepted (`010.0.0.1`
  equals `10.0.0.1`). A hostname containing `:` (an IPv6 literal, not supported) matches no
  SAN. A trailing dot is not stripped, so `host.example.com.` never matches. The Common
  Name is never consulted. `hostname` must be non-empty; an empty string is a
  precondition violation and asserts.
- **Signature verification** derives the hash from the signature algorithm OID and the key type
  / curve from the **issuer's** SubjectPublicKeyInfo, so `ecdsa-with-SHA256` over a P-384 key
  (RFC 5758 §3.2) verifies correctly. The reverse, a hash longer than the key's curve order such as
  `ecdsa-with-SHA384` over a P-256 key, is truncated to the leftmost order-size bytes by
  [`ssfecdsa`](../_crypto/ssfecdsa.md) as RFC 5758 §3.2 specifies, and verifies too. Supported
  pairings: `ecdsa-with-SHA256` and `ecdsa-with-SHA384` with P-256 or P-384 keys
  (only curves enabled by `SSF_EC_CONFIG_ENABLE_P256` / `_P384`; a key on a curve compiled out of
  the build is treated as unsupported and verification returns `false`);
  `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`; plain
  `rsaEncryption` when a separate digest algorithm names the hash, as CMS allows (RFC 3370);
  `id-RSASSA-PSS` with SHA-256, SHA-384, or SHA-512 parameters; and `id-Ed25519`, which when a
  digest algorithm is given accepts only SHA-512 (RFC 8419). A digest algorithm given alongside
  any algorithm that already implies its hash must agree with it. Any other algorithm fails
  verification. All of this is [`SSFX509VerifySignature()`](#ssfx509verifysignature);
  [`SSFX509VerifyCertSignature()`](#ssfx509verifycertsignature) is that function applied to a
  certificate's own TBS and signature. RSA-PSS is
  verified with the `saltLength` declared in the certificate's PSS parameters, or 20 when the
  field is absent, since RFC 4055 declares `DEFAULT 20` and DER omits default values (OpenSSL
  writes salt-20 certificates this way). Salt lengths above the hash length are rejected. The
  parameters are parsed strictly and fail verification unless they are one SEQUENCE with, in
  order: `hashAlgorithm` SHA-256, SHA-384 or SHA-512 (NULL or absent parameters); a
  `maskGenAlgorithm` of MGF1 over that same hash; an optional valid `saltLength`; an optional
  `trailerField` of 1; and nothing else. Because `hashAlgorithm` and `maskGenAlgorithm` default
  to SHA-1 and MGF1-SHA-1 in RFC 4055, which this module does not support, absent parameters, or
  parameters that omit either field, fail to verify; no other hash is ever substituted.
- **Generation uses measure-then-write.** Call [`SSFX509EncodeTBS()`](#ssfx509encodetbs) or
  [`SSFX509EncodeCert()`](#ssfx509encodecert) with `bufOpt == NULL` to learn the exact size in
  `*lenOut`, then again with a buffer. The usual flow is: encode the TBS, sign those exact bytes with
  [`ssfecdsa`](../_crypto/ssfecdsa.md) / [`ssfrsa`](../_crypto/ssfrsa.md) /
  [`ssfed25519`](../_crypto/ssfed25519.md), then encode the Certificate with that signature.
  `SSFX509EncodeCert()` re-encodes the TBS internally, so the same `params` must be passed to
  both calls. The write pass emits every element directly into the caller's buffer, header first
  using the measured content length, and asserts that the bytes written equal the bytes measured,
  so a `true` return always leaves a complete, well-formed encoding of exactly `*lenOut` bytes.
- **Generation parameters.** String fields in [`SSFX509GenName_t`](#type-genname) that are `NULL`
  are omitted from the Name. `sanDNSNames`, `sanIPAddrs`, and the four `nc*` arrays are
  `NULL`-terminated pointer arrays and may themselves be `NULL` when empty. `sanIPAddrs` entries
  are 4-byte IPv4 addresses; `ncPermittedIPs` / `ncExcludedIPs` entries are 8 bytes (address
  followed by mask). The Name Constraints extension is always emitted as critical, as RFC 5280
  requires. `pathLenConstraint = -1` omits the field. Key Usage is emitted as a DER named bit
  list covering both octets of `keyUsageBits` with trailing zero bits trimmed, so every bit
  including `decipherOnly` round-trips through the parser.
- **Trace output.** Verification failures and signature-dispatch decisions are reported through a
  module-wide [`ssftls`](../_crypto/ssftls.md) trace callback installed with
  [`SSFX509SetTraceCtx()`](#ssfx509settracectx) (category `SSF_TLS_TRACE_CERT`, levels `ERROR`
  and `DEBUG`). When no callback is installed, tracing is a no-op. This callback pointer is the
  module's only static state; set it before concurrent use rather than while verifications are in
  flight.
- **Stack usage is dominated by the chain verifier.** [`SSFX509VerifyChain()`](#ssfx509verifychain)
  holds `SSF_X509_CONFIG_MAX_CHAIN_DEPTH` parsed certificates plus one trust-anchor parse on the
  stack. Generation uses no scratch buffers: each nesting level of the encoder adds well under
  200 bytes, and the output goes straight into the caller's buffer. Reduce the chain depth or the
  SAN / extension / Name Constraints limits in [`_opt/ssfx509_opt.h`](../_opt/ssfx509_opt.h) to
  fit smaller stacks; see the module's footnotes in the [SSF README](../README.md#codecs).

<a id="configuration"></a>

## [↑](#ssfx509--x509-certificate-parser-generator-and-chain-verifier) Configuration

Options live in [`_opt/ssfx509_opt.h`](../_opt/ssfx509_opt.h).

| Macro | Default | Description |
|-------|---------|-------------|
| <a id="cfg-max-cert-size"></a>`SSF_X509_CONFIG_MAX_CERT_SIZE` | `4096` | Largest DER TBSCertificate or Certificate [`SSFX509EncodeTBS()`](#ssfx509encodetbs) / [`SSFX509EncodeCert()`](#ssfx509encodecert) will produce. Both the measuring and the writing call return `0` when the result would exceed it. No buffers are sized from it. |
| <a id="cfg-max-chain-depth"></a>`SSF_X509_CONFIG_MAX_CHAIN_DEPTH` | `8` | Maximum `chainLen` accepted by [`SSFX509VerifyChain()`](#ssfx509verifychain) (leaf plus intermediates). Sizes the on-stack array of parsed certificates. |
| <a id="cfg-max-extensions"></a>`SSF_X509_CONFIG_MAX_EXTENSIONS` | `16` | Number of extension records retained in `SSFX509Cert_t.exts[]`. A certificate with more extensions fails to parse, so the critical-extension and duplicate checks always see every extension. Raise it if a deployment's certificates legitimately carry more. |
| <a id="cfg-max-name-constraints"></a>`SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS` | `8` | Number of `dNSName` / `iPAddress` permitted subtrees and, separately, excluded subtrees retained per CA certificate. A certificate with more fails to parse, because dropping an exclusion would loosen the constraint. Raise it if a deployment's CAs legitimately carry more. |
| <a id="cfg-max-san-entries"></a>`SSF_X509_CONFIG_MAX_SAN_ENTRIES` | `8` | Number of Subject Alternative Name entries retained in `SSFX509Cert_t.san[]`. Excess entries are dropped and cannot match a hostname. |

The unit-test entry point is gated by `SSF_CONFIG_X509_UNIT_TEST` in `ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfx509--x509-certificate-parser-generator-and-chain-verifier) API Summary

### Constants

**SAN entry types** (GeneralName tag numbers, stored in `SSFX509SAN_t.type` and
`SSFX509NameConstraint_t.type`):

| Symbol | Value | GeneralName |
|--------|------:|-------------|
| `SSF_X509_SAN_DNS` | `2` | `dNSName` |
| `SSF_X509_SAN_IP` | `7` | `iPAddress` |

**Key Usage bits** (RFC 5280 §4.2.1.3; bit 0 of the BIT STRING is the MSB of `keyUsageBits`):

| Symbol | Value | Key usage |
|--------|------:|-----------|
| `SSF_X509_KU_DIGITAL_SIGNATURE` | `0x8000` | digitalSignature |
| `SSF_X509_KU_NON_REPUDIATION` | `0x4000` | nonRepudiation / contentCommitment |
| `SSF_X509_KU_KEY_ENCIPHERMENT` | `0x2000` | keyEncipherment |
| `SSF_X509_KU_DATA_ENCIPHERMENT` | `0x1000` | dataEncipherment |
| `SSF_X509_KU_KEY_AGREEMENT` | `0x0800` | keyAgreement |
| `SSF_X509_KU_KEY_CERT_SIGN` | `0x0400` | keyCertSign |
| `SSF_X509_KU_CRL_SIGN` | `0x0200` | cRLSign |

### Types

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-name"></a>`SSFX509Name_t` | Struct | Parsed Distinguished Name: pointer / length pairs for `cn`, `o`, `ou`, `c`, `st`, `l` (each `NULL` / `0` when absent) plus `raw` / `rawLen`, the DER of the entire Name SEQUENCE. |
| <a id="type-ext"></a>`SSFX509Ext_t` | Struct | One raw extension: `oidRaw` / `oidRawLen` (OID body bytes), `critical`, and `value` / `valueLen` (the OCTET STRING contents). |
| <a id="type-san"></a>`SSFX509SAN_t` | Struct | One SAN entry: `type` (GeneralName tag number) and `val` / `valLen` (the entry's content bytes; a DNS name is **not** null-terminated). |
| <a id="type-nc"></a>`SSFX509NameConstraint_t` | Struct | One Name Constraints subtree: `type` is `SSF_X509_SAN_DNS` (`val` is a DNS suffix) or `SSF_X509_SAN_IP` (`val` is 8 bytes: IPv4 address then mask). |
| <a id="type-cert"></a>`SSFX509Cert_t` | Struct | Parsed certificate. `version` (`0` = v1, `2` = v3); `serial`; TBS and outer signature algorithm OIDs plus their raw parameters (`sigAlgParams`, `outerSigAlgParams`); `issuer` / `subject` names; `notBefore` / `notAfter` in Unix seconds; `pubKeyAlgOidRaw`, `pubKey` / `pubKeyLen` / `pubKeyUnusedBits`, `ecCurveOidRaw`; `exts[]` / `extsLen`; decoded flags `hasBasicConstraints`, `isCA`, `pathLenConstraint` (`-1` = absent), `hasKeyUsage`, `keyUsageBits`, `hasExtKeyUsage`, `ekuServerAuth`, `ekuClientAuth`, `ekuCodeSigning`, `ekuAnyPurpose`; `san[]` / `sanLen`; `skid`, `akid`; `hasNameConstraints` with `permittedSubtrees[]` / `excludedSubtrees[]`; `tbsRaw` / `tbsRawLen` (bytes the signature covers); `signature` / `signatureLen` / `signatureUnusedBits`. All pointers reference the source DER buffer. |
| <a id="type-genname"></a>`SSFX509GenName_t` | Struct | Name attributes for generation as null-terminated strings: `cn`, `o`, `ou`, `c`, `st`, `l`. `NULL` omits the attribute. |
| <a id="type-genparams"></a>`SSFX509GenParams_t` | Struct | Everything needed to build a certificate: `version` (`0` or `2`), `serial` / `serialLen` (an unsigned big-endian magnitude, written as a positive DER INTEGER), signature algorithm OID and optional parameters, `issuer` / `subject`, `notBefore` / `notAfter`, public key algorithm OID, optional EC curve OID, `pubKey` / `pubKeyLen`; extension controls `addBasicConstraints` / `isCA` / `pathLenConstraint`, `addKeyUsage` / `keyUsageBits`, `addExtKeyUsage` / `ekuServerAuth` / `ekuClientAuth` / `ekuCodeSigning`, `sanDNSNames` / `sanIPAddrs`, `skid` / `skidLen`, `akid` / `akidLen`, one optional raw extension (`addRawExt`, `rawExtOid*`, `rawExtValue*`, `rawExtCritical`), and Name Constraints (`addNameConstraints`, `ncPermittedDNS`, `ncPermittedIPs`, `ncExcludedDNS`, `ncExcludedIPs`). |

<a id="functions-parse"></a>

### Parsing and Inspection

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-parse) | [`bool SSFX509Parse(der, derLen, cert)`](#ssfx509parse) | Zero-copy parse of a DER certificate |
| [e.g.](#ex-parse) | [`bool SSFX509IsValid(cert, nowUnixSec)`](#ssfx509isvalid) | `notBefore <= now <= notAfter` |
| | [`bool SSFX509IsECDSA(cert)`](#ssfx509is-helpers) | Signature algorithm is `ecdsa-with-SHA256` |
| | [`bool SSFX509IsECDSASHA384(cert)`](#ssfx509is-helpers) | Signature algorithm is `ecdsa-with-SHA384` |
| | [`bool SSFX509IsRSA(cert)`](#ssfx509is-helpers) | Public key algorithm is `rsaEncryption` |
| | [`bool SSFX509IsP256(cert)`](#ssfx509is-helpers) | EC public key curve is P-256 |
| | [`bool SSFX509IsP384(cert)`](#ssfx509is-helpers) | EC public key curve is P-384 |
| | [`bool SSFX509IsRSAPSSSHA256(cert)`](#ssfx509is-helpers) | Signature algorithm is `id-RSASSA-PSS` (see note) |
| | [`bool SSFX509IsRSAPSSSHA384(cert)`](#ssfx509is-helpers) | Signature algorithm is `id-RSASSA-PSS` (see note) |
| | [`bool SSFX509IsRSAPKCS1SHA256(cert)`](#ssfx509is-helpers) | Signature algorithm is `sha256WithRSAEncryption` |
| | [`bool SSFX509IsRSAPKCS1SHA384(cert)`](#ssfx509is-helpers) | Signature algorithm is `sha384WithRSAEncryption` |
| | [`bool SSFX509IsRSAPKCS1SHA512(cert)`](#ssfx509is-helpers) | Signature algorithm is `sha512WithRSAEncryption` |
| | [`bool SSFX509IsEd25519(cert)`](#ssfx509is-helpers) | Signature algorithm is `id-Ed25519` |

<a id="functions-gen"></a>

### Certificate Generation

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-generate) | [`bool SSFX509EncodeTBS(bufOpt, bufOptSize, params, lenOut)`](#ssfx509encodetbs) | Encode a TBSCertificate; `bufOpt == NULL` measures |
| [e.g.](#ex-generate) | [`bool SSFX509EncodeCert(bufOpt, bufOptSize, params, signature, signatureLen, lenOut)`](#ssfx509encodecert) | Encode a complete Certificate around a precomputed signature |

<a id="functions-verify"></a>

### Verification

| | Function | Description |
|---|----------|-------------|
| | [`bool SSFX509VerifySignature(keyCert, sigAlgOidRaw, sigAlgOidRawLen, sigAlgParamsOpt, sigAlgParamsLen, digestAlgOidRawOpt, digestAlgOidRawLen, data, dataLen, sig, sigLen)`](#ssfx509verifysignature) | Verify a signature over arbitrary bytes with a certificate's key |
| [e.g.](#ex-verify-sig) | [`bool SSFX509VerifyCertSignature(cert, issuer)`](#ssfx509verifycertsignature) | Verify `cert`'s signature with `issuer`'s public key |
| [e.g.](#ex-verify-chain) | [`bool SSFX509VerifyChain(chainDer, chainDerLen, chainLen, trustDer, trustDerLen, trustCount, hostnameStr, nowUnixSec)`](#ssfx509verifychain) | Full RFC 5280 path validation plus hostname match |
| | [`bool SSFX509VerifyChainPurpose(chainDer, chainDerLen, chainLen, trustDer, trustDerLen, trustCount, purpose, hostnameStrOpt, nowUnixSec)`](#ssfx509verifychainpurpose) | Path validation for TLS server authentication or code signing |
| [e.g.](#ex-trace) | [`void SSFX509SetTraceCtx(fnOpt, userCtxOpt)`](#ssfx509settracectx) | Install the diagnostic trace callback |
| | [`bool SSFX509MatchIPAddress(hostnameStr, sanIP, sanIPLen)`](#ssfx509matchipaddress) | Match a dotted-decimal IPv4 string against an `iPAddress` SAN |
| | [`bool SSFX509CheckSKIDAKID(cert, issuer)`](#ssfx509checkskidakid) | AKID / SKID consistency between a cert and its issuer |

<a id="function-reference"></a>

## [↑](#ssfx509--x509-certificate-parser-generator-and-chain-verifier) Function Reference

<a id="ssfx509parse"></a>

### [↑](#functions-parse) [`bool SSFX509Parse()`](#functions-parse)

```c
bool SSFX509Parse(const uint8_t *der, uint32_t derLen, SSFX509Cert_t *cert);
```

Parses a DER-encoded X.509 certificate into `*cert`. The structure is zeroed first
(`pathLenConstraint` is set to `-1`), then filled with pointers into `der`. Decodes the version,
serial number, both signature AlgorithmIdentifiers, issuer and subject Names, validity, the
SubjectPublicKeyInfo (including the EC curve OID when present), the extensions listed in
[Limitations](#limitations), the raw TBS span, and the signature BIT STRING.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `der` | in | `const uint8_t *` | DER certificate. Must not be `NULL`. Must remain valid and unmodified while `*cert` is used. |
| `derLen` | in | `uint32_t` | Length of `der` in bytes. |
| `cert` | out | `SSFX509Cert_t *` | Receives the parsed certificate. Must not be `NULL`. |

**Returns:** `true` on success; `false` on any DER structure error, a serial number that is empty,
longer than 20 bytes, or negative, or a missing mandatory field. On `false` the contents of
`*cert` are undefined.

<a id="ex-parse"></a>

```c
SSFX509Cert_t cert;

if (SSFX509Parse(der, derLen, &cert) && SSFX509IsValid(&cert, nowUnixSec))
{
    /* cert.subject.cn / cert.subject.cnLen point into der[] */
    if (cert.hasBasicConstraints && cert.isCA) { /* CA certificate */ }
    for (i = 0; i < cert.sanLen; i++)
    {
        if (cert.san[i].type == SSF_X509_SAN_DNS) { /* cert.san[i].val, cert.san[i].valLen */ }
    }
}
```

---

<a id="ssfx509isvalid"></a>

### [↑](#functions-parse) [`bool SSFX509IsValid()`](#functions-parse)

```c
bool SSFX509IsValid(const SSFX509Cert_t *cert, uint64_t nowUnixSec);
```

Checks the validity window.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cert` | in | `const SSFX509Cert_t *` | Parsed certificate. Must not be `NULL`. |
| `nowUnixSec` | in | `uint64_t` | Current time in Unix seconds. |

**Returns:** `true` if `cert->notBefore <= nowUnixSec <= cert->notAfter`. Both ends are
inclusive per RFC 5280 §4.1.2.5.

---

<a id="ssfx509is-helpers"></a>

### [↑](#functions-parse) OID helpers [`SSFX509Is*()`](#functions-parse)

```c
bool SSFX509IsECDSA(const SSFX509Cert_t *cert);           /* sigAlg == ecdsa-with-SHA256        */
bool SSFX509IsECDSASHA384(const SSFX509Cert_t *cert);     /* sigAlg == ecdsa-with-SHA384        */
bool SSFX509IsRSA(const SSFX509Cert_t *cert);             /* pubKeyAlg == rsaEncryption         */
bool SSFX509IsP256(const SSFX509Cert_t *cert);            /* ecCurveOid == secp256r1            */
bool SSFX509IsP384(const SSFX509Cert_t *cert);            /* ecCurveOid == secp384r1            */
bool SSFX509IsRSAPSSSHA256(const SSFX509Cert_t *cert);    /* sigAlg == id-RSASSA-PSS            */
bool SSFX509IsRSAPSSSHA384(const SSFX509Cert_t *cert);    /* sigAlg == id-RSASSA-PSS            */
bool SSFX509IsRSAPKCS1SHA256(const SSFX509Cert_t *cert);  /* sigAlg == sha256WithRSAEncryption  */
bool SSFX509IsRSAPKCS1SHA384(const SSFX509Cert_t *cert);  /* sigAlg == sha384WithRSAEncryption  */
bool SSFX509IsRSAPKCS1SHA512(const SSFX509Cert_t *cert);  /* sigAlg == sha512WithRSAEncryption  */
bool SSFX509IsEd25519(const SSFX509Cert_t *cert);         /* sigAlg == id-Ed25519               */
```

Byte-compare one OID field of a parsed certificate against a well-known OID. `IsRSA` tests the
public key algorithm; `IsP256` / `IsP384` test the EC curve parameter of the public key; all
others test the TBS signature algorithm. `cert` must not be `NULL`.

**Note:** `SSFX509IsRSAPSSSHA256()` and `SSFX509IsRSAPSSSHA384()` both answer whether the signature
algorithm is `id-RSASSA-PSS`; the hash is carried in `sigAlgParams`, which
[`SSFX509VerifyCertSignature()`](#ssfx509verifycertsignature) decodes to pick SHA-256 or SHA-384.

**Returns:** `true` if the OID matches.

---

<a id="ssfx509encodetbs"></a>

### [↑](#functions-gen) [`uint32_t SSFX509EncodeTBS()`](#functions-gen)

```c
bool SSFX509EncodeTBS(uint8_t *bufOpt, uint32_t bufOptSize, const SSFX509GenParams_t *params,
                      uint32_t *lenOut);
```

Encodes a TBSCertificate SEQUENCE from `params`: version (omitted for v1), serial, signature
AlgorithmIdentifier, issuer, validity (UTCTime), subject, SubjectPublicKeyInfo, and, for v3, an
`extensions [3]` block containing whichever of Basic Constraints, Key Usage, Extended Key Usage,
SAN, SKID, AKID, the raw extension, and Name Constraints are enabled in `params`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `bufOpt` | out (opt) | `uint8_t *` | Output buffer, or `NULL` to measure. |
| `bufOptSize` | in | `uint32_t` | Size of `bufOpt` in bytes; must be `0` when `bufOpt` is `NULL`. |
| `params` | in | `const SSFX509GenParams_t *` | Generation parameters. Must not be `NULL`. |
| `lenOut` | out | `uint32_t *` | Receives the bytes written, or the bytes required when measuring; `0` on `false`. Must not be `NULL`. |

**Returns:** `true` with `*lenOut` set on success. `false` if `bufOptSize` is too small, the
encoding would exceed `SSF_X509_CONFIG_MAX_CERT_SIZE`, or an input exceeds one of the generation
bounds listed under [Limitations](#limitations). A `true` return is always the complete encoding;
nothing is written past `bufOptSize` on `false`.

---

<a id="ssfx509encodecert"></a>

### [↑](#functions-gen) [`uint32_t SSFX509EncodeCert()`](#functions-gen)

```c
bool SSFX509EncodeCert(uint8_t *bufOpt, uint32_t bufOptSize, const SSFX509GenParams_t *params,
                       const uint8_t *signature, uint32_t signatureLen, uint32_t *lenOut);
```

Encodes a complete Certificate: `SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }`.
The TBS is re-encoded from `params`, the AlgorithmIdentifier is built from `params->sigAlgOidRaw`
and `params->sigAlgParams`, and `signature` is wrapped in a BIT STRING with zero unused bits.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `bufOpt` | out (opt) | `uint8_t *` | Output buffer, or `NULL` to measure. |
| `bufOptSize` | in | `uint32_t` | Size of `bufOpt` in bytes; must be `0` when `bufOpt` is `NULL`. |
| `params` | in | `const SSFX509GenParams_t *` | The same parameters used to encode the signed TBS. Must not be `NULL`. |
| `signature` | in | `const uint8_t *` | Signature over the TBS bytes, already in the algorithm's wire form (DER `ECDSA-Sig-Value` for ECDSA, raw octets for RSA and Ed25519). Must not be `NULL`. |
| `signatureLen` | in | `uint32_t` | Length of `signature`. |
| `lenOut` | out | `uint32_t *` | Receives the bytes written, or the bytes required when measuring; `0` on `false`. Must not be `NULL`. |

**Returns:** `true` with `*lenOut` set on success; `false` if `bufOptSize` is too small, the result
would exceed `SSF_X509_CONFIG_MAX_CERT_SIZE`, or `params` fails a generation bound. A `true`
return is always the complete encoding.

<a id="ex-generate"></a>

```c
static const uint8_t oidEcdsaSHA256[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
static const uint8_t oidEcPublicKey[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
static const uint8_t oidP256[]        = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static const uint8_t serial[]         = { 0x01 };
static const char *sans[]             = { "device.local", NULL };
SSFX509GenParams_t p;
uint8_t tbs[SSF_X509_CONFIG_MAX_CERT_SIZE];
uint8_t cert[SSF_X509_CONFIG_MAX_CERT_SIZE];
uint8_t hash[SSF_SHA2_256_BYTE_SIZE];
uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
size_t sigLen;
uint32_t tbsLen;
uint32_t certLen;

memset(&p, 0, sizeof(p));
p.version = 2;                                 /* v3 */
p.serial = serial;              p.serialLen = sizeof(serial);
p.sigAlgOidRaw = oidEcdsaSHA256; p.sigAlgOidRawLen = sizeof(oidEcdsaSHA256);
p.issuer.cn = "device.local";   p.subject.cn = "device.local";
p.notBefore = 1700000000ull;    p.notAfter = 2000000000ull;
p.pubKeyAlgOidRaw = oidEcPublicKey; p.pubKeyAlgOidRawLen = sizeof(oidEcPublicKey);
p.ecCurveOidRaw = oidP256;      p.ecCurveOidRawLen = sizeof(oidP256);
p.pubKey = pub;                 p.pubKeyLen = (uint32_t)pubLen;   /* SEC 1 uncompressed point */
p.addBasicConstraints = true;   p.isCA = false; p.pathLenConstraint = -1;
p.addKeyUsage = true;           p.keyUsageBits = SSF_X509_KU_DIGITAL_SIGNATURE;
p.addExtKeyUsage = true;        p.ekuServerAuth = true;
p.sanDNSNames = sans;

if (!SSFX509EncodeTBS(tbs, sizeof(tbs), &p, &tbsLen))
{ /* params too large for SSF_X509_CONFIG_MAX_CERT_SIZE or over a generation bound */ }

/* Hash the exact TBS bytes with SHA-256 (matching ecdsa-with-SHA256) and sign the digest;  */
/* ssfecdsa emits the DER ECDSA-Sig-Value that X.509 expects in signatureValue.             */
SSFSHA256(tbs, tbsLen, hash, sizeof(hash));
if (!SSFECDSASign(SSF_EC_CURVE_P256, priv, privLen, hash, sizeof(hash), sig, sizeof(sig), &sigLen))
{ /* signing failed */ }

if (SSFX509EncodeCert(cert, sizeof(cert), &p, sig, (uint32_t)sigLen, &certLen))
{
    /* cert[0..certLen) is a self-signed DER certificate */
}
```

---

<a id="ssfx509verifysignature"></a>

### [↑](#functions-verify) [`bool SSFX509VerifySignature()`](#functions-verify)

```c
bool SSFX509VerifySignature(const SSFX509Cert_t *keyCert, const uint8_t *sigAlgOidRaw,
                            uint32_t sigAlgOidRawLen, const uint8_t *sigAlgParamsOpt,
                            uint32_t sigAlgParamsLen, const uint8_t *digestAlgOidRawOpt,
                            uint32_t digestAlgOidRawLen, const uint8_t *data, uint32_t dataLen,
                            const uint8_t *sig, uint32_t sigLen);
```

Verifies `sig` over `data` with the public key in `keyCert`. The signature algorithm OID selects
the scheme and, where it implies one, the hash; the optional digest algorithm OID supplies the
hash for `rsaEncryption` and must agree with the implied hash everywhere else. This is the
primitive CMS and other detached-signature formats need; the supported pairings are listed under
**Signature verification** in [Notes](#notes).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `keyCert` | in | `const SSFX509Cert_t *` | Parsed certificate holding the verifying key. Must not be `NULL`. |
| `sigAlgOidRaw` | in | `const uint8_t *` | Signature algorithm OID content bytes. Must not be `NULL`. |
| `sigAlgOidRawLen` | in | `uint32_t` | Length of `sigAlgOidRaw`. |
| `sigAlgParamsOpt` | in (opt) | `const uint8_t *` | Raw DER algorithm parameters (RSA-PSS), or `NULL` with a length of `0`. |
| `sigAlgParamsLen` | in | `uint32_t` | Length of `sigAlgParamsOpt`. |
| `digestAlgOidRawOpt` | in (opt) | `const uint8_t *` | Digest algorithm OID content bytes, or `NULL` with a length of `0`. |
| `digestAlgOidRawLen` | in | `uint32_t` | Length of `digestAlgOidRawOpt`. |
| `data` | in | `const uint8_t *` | Signed bytes. May be `NULL` only when `dataLen` is `0`. |
| `dataLen` | in | `uint32_t` | Length of `data`. |
| `sig` | in | `const uint8_t *` | Signature in wire form: DER `ECDSA-Sig-Value`, raw RSA octets, or 64 Ed25519 bytes. Must not be `NULL`. |
| `sigLen` | in | `uint32_t` | Length of `sig`. |

**Returns:** `true` if the signature verifies; `false` on a bad signature, an unsupported or
inconsistent algorithm pairing, or a key on an unsupported curve (including P-256 or P-384 when
that curve is disabled in `ssfec_opt.h`). A hash longer than the curve order is truncated, not
refused.

---

<a id="ssfx509verifycertsignature"></a>

### [↑](#functions-verify) [`bool SSFX509VerifyCertSignature()`](#functions-verify)

```c
bool SSFX509VerifyCertSignature(const SSFX509Cert_t *cert, const SSFX509Cert_t *issuer);
```

Verifies that `cert->signature` is a valid signature over `cert->tbsRaw` under `issuer`'s public
key. The hash is selected from `cert`'s signature algorithm OID (and PSS parameters); the key type
and curve come from `issuer`'s SubjectPublicKeyInfo. Supported algorithms are listed in
[Notes](#notes). No validity, name, or constraint checks are performed; use
[`SSFX509VerifyChain()`](#ssfx509verifychain) for those.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cert` | in | `const SSFX509Cert_t *` | Parsed certificate whose signature is checked. Must not be `NULL` and must have been successfully parsed. |
| `issuer` | in | `const SSFX509Cert_t *` | Parsed certificate supplying the public key. Pass `cert` itself for a self-signed certificate. Must not be `NULL`. |

**Returns:** `true` if the signature verifies; `false` on a bad signature, an unsupported
algorithm, or a key / algorithm mismatch.

<a id="ex-verify-sig"></a>

```c
SSFX509Cert_t root;

if (SSFX509Parse(rootDer, rootDerLen, &root) && SSFX509VerifyCertSignature(&root, &root))
{
    /* self-signature is good */
}
```

---

<a id="ssfx509verifychain"></a>

### [↑](#functions-verify) [`bool SSFX509VerifyChain()`](#functions-verify)

```c
bool SSFX509VerifyChain(const uint8_t **chainDer, const uint32_t *chainDerLen,
                        uint8_t chainLen,
                        const uint8_t **trustDer, const uint32_t *trustDerLen,
                        uint8_t trustCount,
                        const char *hostnameStr, uint64_t nowUnixSec);
```

Validates a certificate chain against a trust store and checks the leaf against `hostnameStr`. The
full sequence of checks is given under **Verification order** in [Notes](#notes). Every
certificate is parsed internally from DER; the caller never needs to parse first.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `chainDer` | in | `const uint8_t **` | Array of DER certificates, `chainDer[0]` = leaf, each signed by the next. No entry may be `NULL`. |
| `chainDerLen` | in | `const uint32_t *` | Length of each `chainDer[i]`. |
| `chainLen` | in | `uint8_t` | Number of chain certificates, `1` to `SSF_X509_CONFIG_MAX_CHAIN_DEPTH`. |
| `trustDer` | in | `const uint8_t **` | Array of DER trust-anchor (CA) certificates. No entry may be `NULL`. |
| `trustDerLen` | in | `const uint32_t *` | Length of each `trustDer[j]`. |
| `trustCount` | in | `uint8_t` | Number of trust anchors; must be at least `1`. |
| `hostnameStr` | in | `const char *` | Null-terminated DNS name or dotted-decimal IPv4 address the leaf must be issued for. Must not be `NULL` or empty. |
| `nowUnixSec` | in | `uint64_t` | Current time in Unix seconds used for every validity check. |

**Returns:** `true` if every check passes; `false` at the first failure. The reason is reported
through the trace callback when one is installed.

<a id="ex-verify-chain"></a>

```c
const uint8_t *chain[2]   = { leafDer, intermediateDer };
uint32_t chainLen[2]      = { leafDerLen, intermediateDerLen };
const uint8_t *trust[1]   = { rootDer };
uint32_t trustLen[1]      = { rootDerLen };

if (SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "api.example.com", nowUnixSec))
{
    /* leaf is trusted for api.example.com at nowUnixSec */
}
```

---

<a id="ssfx509verifychainpurpose"></a>

### [↑](#functions-verify) [`bool SSFX509VerifyChainPurpose()`](#functions-verify)

```c
bool SSFX509VerifyChainPurpose(const uint8_t **chainDer, const uint32_t *chainDerLen,
                               uint8_t chainLen,
                               const uint8_t **trustDer, const uint32_t *trustDerLen,
                               uint8_t trustCount, SSFX509Purpose_t purpose,
                               const char *hostnameStrOpt, uint64_t nowUnixSec);
```

The chain verifier with the leaf checks chosen by `purpose`. Every step listed under
**Verification order** in [Notes](#notes) runs for either purpose except the last three, which
depend on it:

| `purpose` | Extended Key Usage, when present | Key Usage, when present | Hostname |
|-----------|----------------------------------|--------------------------|----------|
| `SSF_X509_PURPOSE_SERVER_AUTH` | must include `serverAuth` or `anyExtendedKeyUsage` | not checked on the leaf | `hostnameStrOpt` required and matched against the leaf's SANs |
| `SSF_X509_PURPOSE_CODE_SIGNING` | must include `codeSigning` or `anyExtendedKeyUsage` | must include `digitalSignature` or `nonRepudiation` | ignored; may be `NULL` |

[`SSFX509VerifyChain()`](#ssfx509verifychain) is this function with
`SSF_X509_PURPOSE_SERVER_AUTH`. [`ssfcms`](../_crypto/ssfcms.md) uses
`SSF_X509_PURPOSE_CODE_SIGNING` for the signer of a SignedData message.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `purpose` | in | `SSFX509Purpose_t` | `SSF_X509_PURPOSE_SERVER_AUTH` or `SSF_X509_PURPOSE_CODE_SIGNING`; any other value asserts. |
| `hostnameStrOpt` | in (opt) | `const char *` | Required and non-empty for server authentication (asserts otherwise); ignored for code signing. |

The remaining parameters are those of [`SSFX509VerifyChain()`](#ssfx509verifychain).

**Returns:** `true` if every check passes; `false` at the first failure, reported through the
trace callback when one is installed.

---

<a id="ssfx509settracectx"></a>

### [↑](#functions-verify) [`void SSFX509SetTraceCtx()`](#functions-verify)

```c
void SSFX509SetTraceCtx(void (*fnOpt)(int, int, const char *, void *), void *userCtxOpt);
```

Installs the module-wide trace callback used by the verifier. `fnOpt` has the shape of
[`SSFTLSTraceFn_t`](../_crypto/ssftls.md) and receives the level (`SSF_TLS_TRACE_ERROR` or
`SSF_TLS_TRACE_DEBUG`), the category (always `SSF_TLS_TRACE_CERT`), a formatted message, and
`userCtxOpt`. Pass `NULL` to disable tracing. Set this before starting concurrent verifications.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `fnOpt` | in (opt) | `void (*)(int, int, const char *, void *)` | Trace callback, or `NULL` to disable. |
| `userCtxOpt` | in (opt) | `void *` | Opaque pointer passed back to `fnOpt`; may be `NULL`. |

<a id="ex-trace"></a>

```c
static void _trace(int level, int category, const char *msg, void *ctx)
{
    (void)category; (void)ctx;
    printf("x509 %s: %s\r\n", level == SSF_TLS_TRACE_ERROR ? "ERROR" : "debug", msg);
}

SSFX509SetTraceCtx(_trace, NULL);
```

---

<a id="ssfx509matchipaddress"></a>

### [↑](#functions-verify) [`bool SSFX509MatchIPAddress()`](#functions-verify)

```c
bool SSFX509MatchIPAddress(const char *hostnameStr, const uint8_t *sanIP, uint32_t sanIPLen);
```

Parses `hostnameStr` as a dotted-decimal IPv4 address and compares it with a 4-byte `iPAddress`
SAN value. Used internally by the chain verifier and exposed for callers doing their own SAN
matching.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `hostnameStr` | in | `const char *` | Null-terminated string such as `"192.168.1.10"`. Must not be `NULL`. |
| `sanIP` | in | `const uint8_t *` | SAN `iPAddress` content bytes. Must not be `NULL`. |
| `sanIPLen` | in | `uint32_t` | Length of `sanIP`; only `4` can match. |

**Returns:** `true` if `hostnameStr` is a valid IPv4 literal equal to `sanIP`; `false` otherwise,
including for IPv6 SANs and non-numeric hostnames.

---

<a id="ssfx509checkskidakid"></a>

### [↑](#functions-verify) [`bool SSFX509CheckSKIDAKID()`](#functions-verify)

```c
bool SSFX509CheckSKIDAKID(const SSFX509Cert_t *cert, const SSFX509Cert_t *issuer);
```

Checks RFC 5280 §4.2.1.1 key-identifier consistency: when `cert` carries an Authority Key
Identifier and `issuer` carries a Subject Key Identifier, the two must be identical.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cert` | in | `const SSFX509Cert_t *` | Parsed subordinate certificate. Must not be `NULL`. |
| `issuer` | in | `const SSFX509Cert_t *` | Parsed issuing certificate. Must not be `NULL`. |

**Returns:** `true` if the identifiers match or either is absent; `false` only when both are
present and differ.
