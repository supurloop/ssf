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

- [`ssfport.h`](../ssfport.h) — also supplies the platform entropy source used by keygen,
  PSS salt generation, and the per-operation blinding applied to every private-key
  operation (`/dev/urandom` on POSIX; see [Notes](#notes)).
- [`ssfbn`](ssfbn.md) — big-number arithmetic including the constant-time
  [`SSFBNModExpHalf`](ssfbn.md#modexp) fixed-window exponentiation used, at prime width, for
  every RSA private operation.
- [`ssfasn1`](../_codec/ssfasn1.h) — DER encode / decode for PKCS#1 `RSAPublicKey` and
  `RSAPrivateKey`.
- [`ssfsha2`](ssfsha2.md) — SHA-256 / SHA-384 / SHA-512 inside PKCS#1 v1.5 DigestInfo
  encoding, MGF1, and PSS `H` / `H'` computation.
- [`ssfprng`](ssfprng.md) — seeded from platform entropy for prime generation, PSS salt,
  and the message / exponent blinds drawn on each private-key operation.
- [`ssfcrypt`](ssfcrypt.md) — constant-time comparison on the PKCS#1 v1.5 and PSS verify paths.

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
  `SSF_BN_CONFIG_MAX_BITS` gates the upper bound).
- **4096 bits is the deliberate ceiling.** Larger keys (6144, 8192) are not supported and are
  refused like any other unsupported size. They are rare in practice, and their stack, RAM
  and time costs are not practical for the embedded systems SSF targets: every operation's
  buffers and number temporaries are sized to the largest enabled key; private-key time grows
  roughly with the cube of the key size, verify time (e = 65537) with its square. The largest
  enabled size sets the stack for every key size, so enable only the sizes your peers use.
  Measured stack on the signature-verify path (`SSFRSAVerifyPSS` → `SSFBNModExpPub` →
  `SSFBNModExpMontPub` → `SSFBNMontConvertOut` → `SSFBNMontMul`; deepest call-graph path,
  Cortex-M4, `-Os`):

  | Largest enabled size | Verify path stack |
  |---|---|
  | 4096 (default) | ~8.8 KB |
  | 3072 | ~6.8 KB |
  | 2048 | ~4.7 KB |

  Most public CA chains are RSA-2048 or RSA-4096, so a TLS client that must reach
  arbitrary servers keeps 4096 on; a device that talks only to its own infrastructure can
  turn off the sizes that infrastructure does not use.
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
  each candidate `p` / `q` comes from a PRNG seeded with fresh platform entropy for that prime
  pair, runs several Miller-Rabin rounds
  (`SSF_RSA_CONFIG_MILLER_RABIN_ROUNDS`, default 5), and may fail and retry. Do not
  generate keys inside a real-time loop or during startup on a device with a watchdog.
- **Key-generation entropy is platform-dependent.** Keygen and PSS signing both pull
  entropy from `SSFPortGetEntropy()` in [`ssfport.c`](../ssfport.c), which reads
  `/dev/urandom` on POSIX hosts and calls `BCryptGenRandom` on Windows, and returns `false`
  (failing keygen / signing) when no source is available. On a bare-metal target, implement
  `SSFPortGetEntropy()` with a hardware TRNG, or provision keys off-device at manufacture and
  only ever use sign / verify at runtime. **Never** ship `SSFRSAKeyGen` on a target without a genuine entropy source —
  predictable primes are catastrophic.
- **Key-generation seed size.** Each prime search seeds an [`ssfprng`](ssfprng.md) context with
  `SSF_PRNG_ENTROPY_SIZE` bytes of platform entropy. With `SSF_RSA_CONFIG_ENABLE_4096` set that
  is 32 bytes (AES-256), so RSA-4096 keys are not capped at 128-bit seed entropy; builds limited
  to RSA-2048 / 3072 may use 16 bytes, which matches their 112 / 128-bit strength.
- **PKCS#1 v1.5 signatures are deterministic in value, but signing now requires entropy.**
  `SSFRSASignPKCS1` still yields the same signature for the same `(key, hash)` — the value
  is deterministic and interoperable. However, every private-key operation now draws
  platform entropy at sign time for message and exponent blinding (see the CRT note below);
  the blinding cancels out so the produced signature is unchanged, but **signing fails if
  entropy is unavailable**. This is a behavior change: PKCS#1 v1.5 signing previously
  consumed no randomness. `SSFRSASignPSS` additionally draws a fresh random salt (of length
  equal to the hash output) on every call, so repeat PSS calls produce different signatures
  that all verify. Both schemes therefore require entropy availability at sign time as well
  as at key-gen time — on targets where runtime entropy is scarce, prefer Ed25519 /
  deterministic-ECDSA.
- **PSS signing uses a salt as long as the hash; verification accepts `0..hashLen`.**
  [`SSFRSASignPSS()`](#ssfrsasignpss) always emits `sLen = hashLen` (the RFC 8017 §9.1.1 and
  TLS 1.3 convention). [`SSFRSAVerifyPSS()`](#ssfrsaverifypss) takes the signer's `saltLen`
  and accepts any `0 <= saltLen <= hashLen`, so it interoperates with signers using shorter
  salts (e.g. `sLen = 0` or the RFC 4055 default of 20). Signing with any other salt length
  is not supported.
- **Private-key operations run via CRT, constant-time and blinded.** Signing performs
  `m^d mod n` by decomposing into `m^dp mod p` and `m^dq mod q` then recombining with the
  precomputed inverse `qInv = q⁻¹ mod p`. This is ~4× faster than direct exponentiation and
  uses shorter intermediates. The recombination is **constant-time**: the `m1 − m2` step and
  the `qInv * (m1 − m2)` multiply use branchless modular subtraction and a constant-time
  modular multiply, so no secret-dependent branch or variable-time multiply leaks the CRT
  intermediates through timing. Each private-key operation also applies **message (base) and
  exponent blinding**: a fresh random `r` is drawn, the input is blinded as `c · r^e mod n`,
  the CRT exponents are blinded as `dp + eb·(p−1)` / `dq + eb·(q−1)`, and the result is
  unblinded with `r⁻¹ mod n`. This randomizes the operand and exponent on every call,
  frustrating differential power / timing analysis of the private op. The well-known
  **CRT fault-injection attack** (Boneh–DeMillo–Lipton) recovers the factors of `n` from a
  single faulty signature if an attacker can glitch one of the two `modexp` branches during
  sign; this is defended by the built-in verify-after-sign check (see below). The blinding
  and the fresh `r` are the reason signing now requires platform entropy on every call.
- **One step of the private-key operation is variable-time, by design.** `r⁻¹ mod n` is
  computed with [`SSFBNModInvOdd()`](ssfbn.md#modinv) (the binary extended GCD for odd `n`),
  whose run time depends on `r`. It does not expose the message or the CRT exponents: `r` is
  fresh random on every call and never reused, and the exponentiations that use `dp` / `dq`
  are constant-time and exponent-blinded. What a precise timing observer could learn is
  information about a single call's blinding factor, which weakens base blinding for that
  call only. This was reviewed and accepted (AUDIT2 RSA-9). The reduction of the blinded
  input by the secret primes (`cB mod p`, `cB mod q`) was the second such step; since
  OPTIMIZE BN-O7 [`SSFBNMod()`](ssfbn.md#ssfbnmod) reduces an odd modulus by constant-time
  Montgomery reduction. Deployments where an attacker can take very fine-grained timing or
  power measurements of individual signatures should treat RSA signing here as blinded but
  not fully constant-time.
- **Key generation derives `d` in constant time.** With the fixed `e = 65537` (prime, and
  coprime to `λ(n)` by the FIPS check), `d = (1 + k · λ(n)) / 65537` for
  `k = −λ(n)⁻¹ mod 65537`: a sum of limbs for `λ(n) mod 65537` (`2³² ≡ 1`), a fixed
  16-step Fermat inverse mod 65537 and an exact division, none of whose timing depends on
  `λ(n)`. It yields the same `d` (the unique inverse below `λ(n)`) as the variable-time
  extended Euclid used before OPTIMIZE BN-07.
- **Key storage format is PKCS#1 DER.** `RSAPublicKey` = `SEQUENCE { INTEGER n, INTEGER
  e }`; `RSAPrivateKey` = `SEQUENCE { version, n, e, d, p, q, dp, dq, qInv }` (version 0,
  two-prime; `otherPrimeInfos` is not supported), all unsigned big-endian. Decoding is
  strict: nothing may follow the last INTEGER inside the `SEQUENCE` or follow the `SEQUENCE`
  itself, so pass the exact encoded length (`*pubKeyDerLen` / `*privKeyDerLen` from
  `SSFRSAKeyGen`), not the size of a larger or zero-padded buffer. **This is not PKCS#8** (no `AlgorithmIdentifier` wrapper) and not
  PEM (no Base64, no `-----BEGIN-----` header). If your storage format is PKCS#8 or PEM,
  strip those layers at the call site before handing the bytes in.
- **Malformed DER is rejected gracefully — untrusted input cannot abort the process.** The
  DER key decoders bound every integer before it reaches the big-number layer or any
  fixed-size buffer: a modulus that is empty, even, or wider than `SSF_RSA_MAX_KEY_BYTES`
  (the largest build-enabled key) is rejected, and in `RSAPrivateKey` the CRT fields
  `p / q / dp / dq / qInv` must fit half the modulus width, `p` must be exactly half
  the modulus width in limbs (as every generated key is), and `p` and `q` must be odd
  (an even prime, `q = 0` included, returns `false` from every signing call rather than
  reaching the odd-modulus requirement of the Montgomery layer). Every key INTEGER must
  be a minimal, non-negative DER INTEGER
  ([`SSFASN1DecGetUInt`](../_codec/ssfasn1.md#ssfasn1decgetuint)), so a negative or
  zero-padded modulus is rejected rather than read as a magnitude. An out-of-range width
  would otherwise overflow the `SSF_RSA_MAX_KEY_BYTES` encoded-message buffers in the verify
  and sign paths or trip a halting `SSF_REQUIRE` in `ssfbn`. As a result `SSFRSAPubKeyIsValid`,
  `SSFRSAPrivKeyIsValid`, and the verify and sign entry points return `false` on malformed or
  hostile key / DER input instead of aborting — safe to call on attacker-controlled bytes.
  Note that the decoders enforce only these structural bounds; the exact-size and exponent
  policy (bit length in the enabled set, `e >= 65537`) is applied by `SSFRSAPubKeyIsValid()`
  and `SSFRSAPrivKeyIsValid()`, not by the verify entry points. Certificate and CMS
  verification apply their own key-strength rule before calling them (modulus at least
  `SSF_X509_CONFIG_RSA_MIN_BITS`, default 2048, and an odd `e >= 3`; see
  [`ssfx509`](../_codec/ssfx509.md#ssfx509verifysignature)); direct callers of the verify
  functions should check the key themselves.
- **PSS verify is constant-time end-to-end.** The trailer byte, top-bit mask, MGF1 unmask,
  PS-zero scan, salt separator, and final `H == H'` comparison are all folded into a
  single-byte XOR/OR accumulator (`diff`) so the wall-clock time to reach the final
  return is independent of which byte of the recovered `EM` first diverged from the PSS
  padding pattern.
- **Sign performs verify-after-sign.** After the CRT private op produces `s`, the signer
  recomputes `m' = s^e mod n` via the public-key path and rejects the signature unless
  `m' == m`. This catches a faulty CRT branch (Boneh-DeMillo-Lipton fault attack), a
  tampered private-key DER (mismatched `dp` / `dq` / `qInv`), and most transient
  glitches. The cost is one extra public-exponent modular exponentiation per sign —
  small relative to the CRT private op (the public op with `e = 65537` is ~10–20× faster
  than the private op).
- **All sign / keygen entry points zeroize secrets and scrub the deeper stack region on
  every return path.** Failure paths get the same wipe as success paths; the CRT helper
  zeroes its CRT intermediates (`cp`, `cq`, `m1`, `m2`, `h`, expanded full-width copies
  and the `h*q` product) before returning. A `noinline` stack-scrub helper at the end of
  each entry point then zeroes the freed frames the underlying `ssfbn` calls left below it:
  their buffers are wiped by `ssfbn` itself, but register spills and saved registers (limbs
  of `p`, `q` and the CRT intermediates) are not. The scrub is sized to the depth those
  calls reach ([`SSF_RSA_SIGN_STACK_SCRUB_BYTES`](#ssf-rsa-stack-scrub-bytes) for signing,
  [`SSF_RSA_KEYGEN_STACK_SCRUB_BYTES`](#ssf-rsa-stack-scrub-bytes) for keygen), measured
  with Cortex-M4 GCC `-Os`, so it covers them without raising the peak stack (SAFE-05).
  Other compilers and flags can go slightly deeper (M4 `-O2`: 64–80 B, Cortex-M0+ `-Os`:
  96–112 B); set [`SSF_RSA_CONFIG_STACK_SCRUB_MARGIN`](#configuration) to `128u` there to
  cover that too, at the cost of as much more peak stack.
- **Keys are not parsed lazily on every call.** Each sign / verify / key-validate entry
  point re-parses the DER blob on entry. If you're signing many messages under the same
  key, this is a few hundred microseconds per call that could in principle be
  amortised — at the moment the API does not expose a parsed-key handle.
- **Code not reached by the unit tests, by construction.** The `p == 1` rejection in
  [`SSFRSAPrivKeyIsValid()`](#ssfrsaprivkeyisvalid) cannot fire: the private-key decoder pins
  `p` to half the modulus width, and the public-field rules then refuse any modulus narrow
  enough for a one-limb `p`. It is kept as a defensive check.

<a id="configuration"></a>

## [↑](#ssfrsa--rsa-signatures-and-key-generation) Configuration

Options live in [`_opt/ssfrsa_opt.h`](../_opt/ssfrsa_opt.h). Disable features you don't
need — each compiles its entry points out of the build, reclaiming flash.

| Macro | Default | Description |
|-------|---------|-------------|
| `SSF_RSA_CONFIG_ENABLE_2048` | `1` | Accept and generate 2048-bit keys. Requires `SSF_BN_CONFIG_MAX_BITS ≥ 4096` (2 × 2048). |
| `SSF_RSA_CONFIG_ENABLE_3072` | `1` | Accept and generate 3072-bit keys. Requires `SSF_BN_CONFIG_MAX_BITS ≥ 6144`. |
| `SSF_RSA_CONFIG_ENABLE_4096` | `1` | Accept and generate 4096-bit keys. Requires `SSF_BN_CONFIG_MAX_BITS ≥ 8192`. |
| `SSF_RSA_CONFIG_ENABLE_KEYGEN` | `1` | Enable `SSFRSAKeyGen`. Disabling removes ~3 KB of code (Miller-Rabin, prime generation, CRT parameter setup) and drops peak stack significantly — sign/verify are much lighter than keygen. |
| `SSF_RSA_CONFIG_ENABLE_PKCS1_V15` | `1` | Enable `SSFRSASignPKCS1` / `SSFRSAVerifyPKCS1`. |
| `SSF_RSA_CONFIG_ENABLE_PSS` | `1` | Enable `SSFRSASignPSS` / `SSFRSAVerifyPSS`. |
| `SSF_RSA_CONFIG_STACK_SCRUB_MARGIN` | `0` | Bytes added to the end-of-call stack scrub of the sign and keygen entry points (see [Notes](#notes)). The scrub sizes are measured for Cortex-M4 GCC `-Os`; set `128u` for other compilers or flags (M4 `-O2`, Cortex-M0+) to scrub their slightly deeper frames too. Each byte also adds a byte of peak stack. Can be set with `-D`. |
| `SSF_RSA_CONFIG_MILLER_RABIN_ROUNDS` | `5` | Number of Miller-Rabin witnesses per prime candidate in keygen. Five rounds gives a false-positive probability ≤ 2⁻¹⁰⁰ for random inputs and meets the FIPS 186-4 Table C.3 minimum for every supported size (the required count falls as the primes grow, so RSA-2048's 1024-bit primes are the most demanding). Higher values slow keygen proportionally with marginal security gain. |

Disabling unused sizes shrinks the public-key validator's accept set and lets the test
harness drop unused size-specific test blocks. The header validates that the BN cap
covers `2 × largest enabled size` — that's the binding constraint for keygen and CRT
recombine, which run a full-width `n × n` product through [`SSFBNMul`](ssfbn.md#mul).

Setting **all three** size flags to `0` is allowed: the entire RSA module compiles to
nothing (ssfrsa.c body is gated on the derived `SSF_RSA_ANY_ENABLED` macro), the public
API headers expose no declarations, and `SSFRSAUnitTest` becomes a one-line "skipped"
stub so a pure-ECC build can keep `ssfrsa.c` in the project without dragging RSA in.
Two declarations stay visible in that build: the `SSFRSAHash_t` enum (ssfx509 uses it to name
the hash of every signature scheme) and `SSFRSAUnitTest` (main.c references it under
`SSF_CONFIG_RSA_UNIT_TEST`).

<a id="api-summary"></a>

## [↑](#ssfrsa--rsa-signatures-and-key-generation) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-rsa-max-key-bits"></a>`SSF_RSA_MAX_KEY_BITS` | Constant | The largest enabled RSA key size in bits — `2048`, `3072`, or `4096` depending on `SSF_RSA_CONFIG_ENABLE_*`. Tracks the public-key validator's accept set rather than the underlying BN cap. |
| <a id="ssf-rsa-max-key-bytes"></a>`SSF_RSA_MAX_KEY_BYTES` | Constant | `SSF_RSA_MAX_KEY_BITS / 8` — maximum key (and signature) byte length. `512` for default (RSA-4096), `384` for RSA-3072 maximum, `256` for RSA-2048-only. |
| <a id="ssf-rsa-max-sig-size"></a>`SSF_RSA_MAX_SIG_SIZE` | Constant | Same as `SSF_RSA_MAX_KEY_BYTES`. RSA signatures are always exactly `keyBytes` long. |
| <a id="ssf-rsa-max-pub-key-der-size"></a>`SSF_RSA_MAX_PUB_KEY_DER_SIZE` | Constant | `SSF_RSA_MAX_KEY_BYTES + 40` — maximum DER size of a PKCS#1 `RSAPublicKey`. |
| <a id="ssf-rsa-max-priv-key-der-size"></a>`SSF_RSA_MAX_PRIV_KEY_DER_SIZE` | Constant | `5 × SSF_RSA_MAX_KEY_BYTES + 200` — maximum DER size of a PKCS#1 `RSAPrivateKey` (holds `n, e, d, p, q, dp, dq, qInv`). |
| <a id="ssf-rsa-stack-scrub-bytes"></a>`SSF_RSA_SIGN_STACK_SCRUB_BYTES`, `SSF_RSA_KEYGEN_STACK_SCRUB_BYTES` | Constant | Bytes of stack zeroed below the sign / keygen entry points' frames on return: the depth their `ssfbn` calls reach (Cortex-M4 GCC `-Os`), from `SSF_BN_MAX_MOD_LIMBS` and the window size `SSF_BN_MODEXP_WIN_K`, plus `SSF_RSA_CONFIG_STACK_SCRUB_MARGIN`. 14,792 / 14,352 at the RSA-4096 cap with the default window (11,272 / 10,896 at 3072, 7,752 / 7,440 at 2048). |
| <a id="ssfrsahash-t"></a>`SSFRSAHash_t` | Enum | Hash selector: `SSF_RSA_HASH_SHA256`, `SSF_RSA_HASH_SHA384`, `SSF_RSA_HASH_SHA512` (plus `MIN` / `MAX` sentinels). |

<a id="functions"></a>

### Functions

**[Key management](#key-management)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-keygen) | [`bool SSFRSAKeyGen(bits, privKeyDer, privKeyDerSize, privKeyDerLen, pubKeyDer, pubKeyDerSize, pubKeyDerLen)`](#ssfrsakeygen) | Generate a 2048 / 3072 / 4096-bit key pair (enable via `SSF_RSA_CONFIG_ENABLE_KEYGEN`) |
| | [`bool SSFRSAPubKeyIsValid(pubKeyDer, pubKeyDerLen)`](#ssfrsapubkeyisvalid) | Validate a DER-encoded `RSAPublicKey` blob |
| | [`bool SSFRSAPrivKeyIsValid(privKeyDer, privKeyDerLen)`](#ssfrsaprivkeyisvalid) | Validate a DER-encoded `RSAPrivateKey` blob |

**[FIPS 186-4 keygen post-condition helpers](#fips-helpers)**

| | Function | Description |
|---|----------|-------------|
| | [`bool SSFRSAFipsPrimeDistanceOK(p, q, halfBits)`](#fips-helpers) | Check `\|p − q\| > 2^(halfBits − 100)` |
| | [`bool SSFRSAFipsDLowerBoundOK(d, halfBits)`](#fips-helpers) | Check `d > 2^halfBits` |
| | [`bool SSFRSAFipsECoprimeOK(e, pMinus1, qMinus1)`](#fips-helpers) | Check `gcd(e, λ(n)) == 1` |

**[PKCS#1 v1.5 signatures](#pkcs1-v15)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-pkcs1) | [`bool SSFRSASignPKCS1(privKeyDer, ..., hash, hashVal, hashLen, sig, sigSize, sigLen)`](#ssfrsasignpkcs1) | Sign a hash with deterministic PKCS#1 v1.5 padding |
| [e.g.](#ex-pkcs1) | [`bool SSFRSAVerifyPKCS1(pubKeyDer, ..., hash, hashVal, hashLen, sig, sigLen)`](#ssfrsaverifypkcs1) | Verify a PKCS#1 v1.5 signature |

**[PSS signatures](#pss)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-pss) | [`bool SSFRSASignPSS(privKeyDer, ..., hash, hashVal, hashLen, sig, sigSize, sigLen)`](#ssfrsasignpss) | Sign a hash with RSA-PSS (random salt, hash-length) |
| [e.g.](#ex-pss) | [`bool SSFRSAVerifyPSS(pubKeyDer, ..., hash, hashVal, hashLen, saltLen, sig, sigLen)`](#ssfrsaverifypss) | Verify an RSA-PSS signature with the signer's salt length |

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
| `bits` | in | `uint16_t` | Key size. Must be `2048`, `3072`, or `4096`, and that size must be enabled by its `SSF_RSA_CONFIG_ENABLE_*` flag. |
| `privKeyDer` | out | `uint8_t *` | Buffer for PKCS#1 `RSAPrivateKey` DER. |
| `privKeyDerSize` | in | `size_t` | Must be ≥ [`SSF_RSA_MAX_PRIV_KEY_DER_SIZE`](#ssf-rsa-max-priv-key-der-size). |
| `privKeyDerLen` | out | `size_t *` | Bytes actually written to `privKeyDer`. |
| `pubKeyDer` | out | `uint8_t *` | Buffer for PKCS#1 `RSAPublicKey` DER. |
| `pubKeyDerSize` | in | `size_t` | Must be ≥ [`SSF_RSA_MAX_PUB_KEY_DER_SIZE`](#ssf-rsa-max-pub-key-der-size). |
| `pubKeyDerLen` | out | `size_t *` | Bytes actually written to `pubKeyDer`. |

**Returns:** `true` on success; `false` if entropy is unavailable or if no acceptable key pair
is found within the bounded search (prime generation exhausts its candidate budget, or every
one of a fixed number of prime pairs fails the FIPS 186-4 post-checks). With a working entropy
source the latter is vanishingly rare. **Runtime is seconds-to-minutes** — see [Notes](#notes).

**Preconditions (trap via `SSF_REQUIRE`, never return `false`):** all pointers non-`NULL`;
`bits` one of the build-enabled sizes; `privKeyDerSize >= SSF_RSA_MAX_PRIV_KEY_DER_SIZE` and
`pubKeyDerSize >= SSF_RSA_MAX_PUB_KEY_DER_SIZE`. The buffer minimums are the build-wide maxima
(sized for the largest enabled key), **not** the size of the key being generated: in a build
with RSA-4096 enabled, a buffer sized for a 2048-bit key traps even when `bits == 2048`.
If `bits` comes from outside the firmware (a provisioning command, a stored configuration
field, a certificate being renewed), validate it before calling, e.g.:

```c
static bool AppRSAKeyGenBitsOK(uint16_t bits)
{
#if SSF_RSA_CONFIG_ENABLE_2048 == 1
    if (bits == 2048u) return true;
#endif
#if SSF_RSA_CONFIG_ENABLE_3072 == 1
    if (bits == 3072u) return true;
#endif
#if SSF_RSA_CONFIG_ENABLE_4096 == 1
    if (bits == 4096u) return true;
#endif
    return false;
}
```

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
    /* Entropy unavailable, or the bounded key search failed. */
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

<a id="ssfrsaprivkeyisvalid"></a>
```c
bool SSFRSAPrivKeyIsValid(const uint8_t *privKeyDer, size_t privKeyDerLen);
```
Parse the DER blob and return whether it is a well-formed PKCS#1 `RSAPrivateKey` (version
0, all eight integers `n / e / d / p / q / dp / dq / qInv` present, `n = p · q`,
`dp = d mod (p − 1)` and `dq = d mod (q − 1)`, `e · dp ≡ 1 (mod p − 1)` and
`e · dq ≡ 1 (mod q − 1)` (together equivalent to `e · d ≡ 1 (mod λ(n))`), `qInv = q⁻¹ mod p`,
modulus in the supported size range). Counterpart of
[`SSFRSAPubKeyIsValid()`](#ssfrsapubkeyisvalid) for the private blob. Use this to reject
malformed key material at ingestion time before passing it to the sign entry points.

Every decoded private field and intermediate is zeroized before the function returns, on
both the accept and the reject paths. The consistency checks are **variable-time** (they
reduce by the even `p − 1` and `q − 1`, where `SSFBNMod` / `SSFBNModMul` run shift-and-subtract,
whose run time depends on the key values): call it once when a key
is loaded or imported, not in a loop whose timing an attacker can observe. Before 2026-11-19
only `dp = d mod (p − 1)` and `dq = d mod (q − 1)` were checked, so a key with consistent but
wrong `d`, `dp`, `dq` was accepted (signing it then failed verify-after-sign).

---

<a id="fips-helpers"></a>

### [↑](#functions) FIPS 186-4 Keygen Post-Condition Helpers

```c
bool SSFRSAFipsPrimeDistanceOK(const SSFBN_t *p, const SSFBN_t *q, uint16_t halfBits);
bool SSFRSAFipsDLowerBoundOK(const SSFBN_t *d, uint16_t halfBits);
bool SSFRSAFipsECoprimeOK(const SSFBN_t *e, const SSFBN_t *pMinus1, const SSFBN_t *qMinus1);
```

The three post-condition checks from FIPS 186-4 §B.3 that
[`SSFRSAKeyGen()`](#ssfrsakeygen) runs against each candidate `(p, q, d)` before accepting
the key:

- **`PrimeDistanceOK`** rejects `|p − q| ≤ 2^(halfBits − 100)` (B.3.3 step 5.4) — primes
  too close together let Fermat factorisation recover them in a single sqrt.
- **`DLowerBoundOK`** rejects `d ≤ 2^halfBits` (B.3.1 step 4.1.b) — small private
  exponents are vulnerable to Boneh-Durfee lattice attacks.
- **`ECoprimeOK`** rejects `gcd(e, λ(n)) ≠ 1` where `λ(n) = lcm(p−1, q−1)` — required for
  `d = e⁻¹ mod λ(n)` to exist.

These take [`SSFBN_t`](ssfbn.md#ssfbn-t) operands rather than DER bytes because they
operate on the integer values directly. They are exposed in the public header for
consumers building their own keygen on top of [`ssfbn`](ssfbn.md), and for FIPS-compliance
test harnesses that need to drive the post-conditions independently. `halfBits` is `nlen
/ 2` — i.e., 1024 for RSA-2048, 1536 for RSA-3072, 2048 for RSA-4096.

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
Produce an RSASSA-PKCS1-v1_5 signature (RFC 8017 §8.2). The signature **value** is
deterministic — the same `(key, hash)` always yields the same bytes — but the private
operation draws platform entropy for blinding, so **the call requires an entropy source and
returns `false` if entropy is unavailable** (the blinding cancels, leaving the output
unchanged; see [Notes](#notes)). The caller supplies `hashVal` as the raw output of the
matching hash algorithm; the module wraps it in a `DigestInfo` ASN.1 structure and applies
the `0x00 || 0x01 || 0xFF...FF || 0x00 || DigestInfo` padding before the RSA private
operation.

<a id="ssfrsaverifypkcs1"></a>
```c
bool SSFRSAVerifyPKCS1(const uint8_t *pubKeyDer, size_t pubKeyDerLen,
                       SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                       const uint8_t *sig, size_t sigLen);
```
Verify a PKCS#1 v1.5 signature. Performs the public operation `sig^e mod n`, reconstructs
the expected `EM` from `(hash, hashVal)`, and compares the recovered and expected blocks
with [`SSFCryptCTMemEq()`](ssfcrypt.md). Any mismatch — wrong key, wrong hash algorithm, tampered
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
                     SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen, size_t saltLen,
                     const uint8_t *sig, size_t sigLen);
```
Verify an RSA-PSS signature. Performs `sig^e mod n`, recovers `EM`, extracts `H` and
`salt`, recomputes `H'`, and compares. `saltLen` is the salt length the signer used; RFC 8017 recommends the hash length,
which is what [`SSFRSASignPSS()`](#ssfrsasignpss) emits and what X.509 certificates default to when
their PSS parameters carry no `saltLength` (RFC 4055 declares DEFAULT 20). The verifier accepts
`0 <= saltLen <= hashLen` and asserts on a larger value, since a salt longer than the hash has no
security benefit and is not issued by any mainstream signer. The whole check, including the
padding pattern and `H == H'`, is constant-time (see [Notes](#notes)).

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
    /* Entropy unavailable or sign failure. PSS needs randomness at sign time
       for the salt; PKCS#1 v1.5 is deterministic in value but likewise needs
       entropy for the private-op blinding. */
}

/* Verify. Same signature data will fail if any of the key / hash / message
   bytes differ between signer and verifier. */
if (!SSFRSAVerifyPSS(pubDer, pubLen,
                     SSF_RSA_HASH_SHA256, hash, sizeof(hash), sizeof(hash),
                     sig, sigLen))
{
    /* Reject. */
}
```
