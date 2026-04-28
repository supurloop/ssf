# ssfec — Elliptic Curve Point Arithmetic

[SSF](../README.md) | [Cryptography](README.md)

Elliptic curve point arithmetic over the NIST short-Weierstrass prime curves P-256 and
P-384, per FIPS 186-4, NIST SP 800-186, and SEC 1 v2. Provides the curve primitives that
[`ssfecdsa`](ssfecdsa.h) is built on: point addition, constant-time scalar multiplication
(for signing and ECDH key derivation), dual scalar multiplication via Shamir's trick (for
ECDSA verification), point validation, and SEC 1 uncompressed serialization.

Internally all point arithmetic is done in **Jacobian projective coordinates**
`(X, Y, Z)` representing the affine point `(X/Z², Y/Z³)`. Callers convert to and from the
affine representation used on the wire via
[`SSFECPointFromAffine()`](#ssfecpointfromaffine) /
[`SSFECPointToAffine()`](#ssfecpointtoaffine), or use the direct
[`SSFECPointEncode()`](#serialization) / [`SSFECPointDecode()`](#serialization) helpers which
handle the conversion plus SEC 1 framing. The identity element (point at infinity) is
represented with `Z = 0`.

This module is a back-end primitive. Most callers will use it indirectly through
`ssfecdsa`; use it directly only when implementing an EC-based protocol that SSF does not
already cover.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfec--elliptic-curve-point-arithmetic) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfbn`](ssfbn.md) — big-number arithmetic used for every coordinate operation

<a id="notes"></a>

## [↑](#ssfec--elliptic-curve-point-arithmetic) Notes

- **Always validate untrusted points with [`SSFECPointValidate()`](#ssfecpointvalidate).**
  Accepting an attacker-controlled point that is *not* on the curve — or is on a
  related weak "twist" — without validation enables the invalid-curve class of attack: scalar
  multiplication against such a point can leak substantial bits of a private key. The
  validate function checks: (1) coordinates lie in `[0, p-1]`; (2) the point is not
  identity; (3) the point satisfies `y² ≡ x³ + ax + b (mod p)`. Run it on every point that
  arrived from outside the local trust boundary (peer's ECDH share, signature verification
  input, decoded wire bytes). [`SSFECPointDecode()`](#serialization) calls it internally, so
  decoded points are already validated.
- **Which scalar-mul to use depends on whether scalars are secret:**

  | Function | Constant time? | Use for |
  |---|---|---|
  | [`SSFECScalarMul`](#ssfecscalarmul) | Yes (Montgomery ladder; every bit processed identically, conditional swaps via [`SSFBNCondSwap`](ssfbn.md#condswap), working points zeroized after use) | Signing (`k·G`), ECDH (`d·P_peer`), any operation where the scalar is a private key or ephemeral secret |
  | [`SSFECScalarMulDual`](#ssfecscalarmuldual) | **No** — Shamir's-trick double-scalar. Intentionally variable-time | ECDSA verify (both `u₁ = z·s⁻¹ mod n` and `u₂ = r·s⁻¹ mod n` are derived from public message + signature data) |

  One edge-case caveat (from the header comment): `SSFECScalarMul`'s handling of the
  identity-input corner case may leak timing for the first few scalar bits. This is not
  exploitable for a uniformly-random scalar (the odds of the attacker learning "the top two
  bits are zero" against the cost of generating matching candidate keys is zero-utility), but
  it does mean an adversary choosing both scalar and base can observe a structural signal.
  Never expose `SSFECScalarMul` as a black-box oracle where the attacker picks `k`.
- **Jacobian vs. affine — when to convert.** Point arithmetic stays in Jacobian form for
  efficiency (avoids per-step modular inversions). You only convert back to affine when
  producing a value that leaves the module: encoding the point to SEC 1 bytes, extracting
  the X coordinate for an ECDSA `r` value or ECDH shared secret, or passing into an
  external API. [`SSFECPointToAffine()`](#ssfecpointtoaffine) does the inversion once; avoid
  calling it inside a scalar-mul inner loop.
- **Curve selection at compile time.** Both curves are enabled by default. Disabling one
  via `ssfec_opt.h` trims flash and rodata (each curve carries six ~32/48-byte `SSFBN_t`
  constants — `p`, `a`, `b`, `gₓ`, `gᵧ`, `n`). Disabling both is a compile error. The
  header also compile-time asserts that
  [`SSF_BN_CONFIG_MAX_BITS`](ssfbn.md#ssf-bn-config-max-bits) is large enough for each
  enabled curve (`≥ 512` for P-256, `≥ 768` for P-384). The minimum is twice the curve
  operand width because [`SSFBNModMulNIST()`](ssfbn.md#modmulnist) routes through
  [`SSFBNMul()`](ssfbn.md#mul), whose `2N`-limb intermediate product is gated by
  `SSF_BN_MAX_LIMBS`.
- **For ECC-only builds, drop the BN width.** Stack usage inside scalar multiplication
  scales linearly with `SSF_BN_CONFIG_MAX_BITS`. The default 8192-bit width (set by
  `ssfbn_opt.h` to accommodate RSA-4096) bloats every `SSFBN_t` and `SSFECPoint_t`
  intermediate. If you do not need RSA, setting `SSF_BN_CONFIG_MAX_BITS = 512`
  (P-256-only) or `768` (P-384) cuts scalar-mul peak stack by roughly an order of
  magnitude.
- **Identity is represented as `Z = 0`.** [`SSFECPointIsIdentity()`](#ssfecpointisidentity)
  checks that flag; [`SSFECPointSetIdentity()`](#ssfecpointsetidentity) produces it;
  [`SSFECPointToAffine()`](#ssfecpointtoaffine) returns `false` if asked to convert the
  identity (no finite affine representation exists).
- **Addition fully handles all cases.** [`SSFECPointAdd()`](#ssfecpointadd) internally
  dispatches between generic addition (different points) and doubling (same point), and
  handles the identity-plus-anything case. Callers do not need to special-case these; the
  scalar-mul routines rely on this.
- **SEC 1 uncompressed encoding only.** [`SSFECPointEncode()`](#serialization) writes
  `0x04 ‖ X ‖ Y` (length `1 + 2·coordBytes` = `65` bytes for P-256, `97` for P-384). The
  compressed (`0x02` / `0x03`) and hybrid (`0x06` / `0x07`) SEC 1 forms are not supported
  in either direction. Wire formats that require compressed points (some TLS extensions,
  some COSE profiles) need a caller-side expansion step.
- **`SSFECPointOnCurve` vs. `SSFECPointValidate`.** `OnCurve` checks only the curve
  equation, not the range or identity conditions. `Validate` includes `OnCurve` plus both.
  Use `Validate` for untrusted input; `OnCurve` is there for debug / invariant-checking on
  points the code itself has produced.

<a id="configuration"></a>

## [↑](#ssfec--elliptic-curve-point-arithmetic) Configuration

Options live in [`_opt/ssfec_opt.h`](../_opt/ssfec_opt.h). At least one curve must be
enabled.

| Macro | Default | Description |
|-------|---------|-------------|
| `SSF_EC_CONFIG_ENABLE_P256` | `1` | Enable NIST P-256 (`secp256r1` / `prime256v1`). Requires `SSF_BN_CONFIG_MAX_BITS ≥ 512` (2 × 256). |
| `SSF_EC_CONFIG_ENABLE_P384` | `1` | Enable NIST P-384 (`secp384r1`). Requires `SSF_BN_CONFIG_MAX_BITS ≥ 768` (2 × 384). |

Disabling a curve removes its parameter constants from the build and compiles out any code
paths that reference it. Disabling both produces `#error At least one EC curve must be
enabled.`

<a id="api-summary"></a>

## [↑](#ssfec--elliptic-curve-point-arithmetic) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssfeccurve-t"></a>`SSFECCurve_t` | Enum | Curve selector: `SSF_EC_CURVE_P256`, `SSF_EC_CURVE_P384` (plus `MIN` / `MAX` sentinels). |
| <a id="ssfecpoint-t"></a>`SSFECPoint_t` | Struct | Jacobian point `{ SSFBN_t x; SSFBN_t y; SSFBN_t z; }`. Affine `(x, y) = (X/Z², Y/Z³)`; identity when `Z = 0`. |
| <a id="ssfeccurveparams-t"></a>`SSFECCurveParams_t` | Struct | Curve parameters: field prime `p`, curve coefficients `a` and `b`, generator `(gₓ, gᵧ)`, order `n`, working limb count, coordinate byte length. Obtain via [`SSFECGetCurveParams()`](#ssfecgetcurveparams). |
| <a id="ssf-ec-max-coord-bytes"></a>`SSF_EC_MAX_COORD_BYTES` | Constant | `48` if P-384 is enabled, `32` otherwise — the coordinate byte length of the widest enabled curve. |
| <a id="ssf-ec-max-encoded-size"></a>`SSF_EC_MAX_ENCODED_SIZE` | Constant | `1 + 2 × SSF_EC_MAX_COORD_BYTES` — the SEC 1 uncompressed-form encoded length for the widest enabled curve (`65` or `97`). |

<a id="functions"></a>

### Functions

**[Curve parameters](#ssfecgetcurveparams)**

| | Function | Description |
|---|----------|-------------|
| | [`const SSFECCurveParams_t *SSFECGetCurveParams(curve)`](#ssfecgetcurveparams) | Returns the parameter table for a curve, or `NULL` if not enabled |

**[Point lifecycle](#point-lifecycle)**

| | Function | Description |
|---|----------|-------------|
| | [`void SSFECPointSetIdentity(pt, curve)`](#ssfecpointsetidentity) | Set `pt` to the identity (point at infinity) |
| | [`bool SSFECPointIsIdentity(pt)`](#ssfecpointisidentity) | Returns `true` iff `pt` is the identity (`Z == 0`) |
| | [`void SSFECPointFromAffine(pt, x, y, curve)`](#ssfecpointfromaffine) | Build a Jacobian point from affine `(x, y)` (sets `Z = 1`) |
| | [`bool SSFECPointToAffine(x, y, pt, curve)`](#ssfecpointtoaffine) | Extract affine `(x, y)` from a Jacobian point |

**[Point validation](#point-validation)**

| | Function | Description |
|---|----------|-------------|
| | [`bool SSFECPointOnCurve(pt, curve)`](#ssfecpointoncurve) | Curve-equation check only |
| | [`bool SSFECPointValidate(pt, curve)`](#ssfecpointvalidate) | Full validation for untrusted input (range + not-identity + on-curve) |

**[Serialization (SEC 1 uncompressed)](#serialization)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-codec) | [`bool SSFECPointEncode(pt, curve, out, outSize, outLen)`](#serialization) | Write `0x04 ‖ X ‖ Y` |
| [e.g.](#ex-codec) | [`bool SSFECPointDecode(pt, curve, data, dataLen)`](#serialization) | Parse + validate `0x04 ‖ X ‖ Y` |

**[Arithmetic](#arithmetic)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-add) | [`void SSFECPointAdd(r, p, q, curve)`](#ssfecpointadd) | `r = P + Q` (handles all corner cases) |
| [e.g.](#ex-scalarmul) | [`void SSFECScalarMul(r, k, p, curve)`](#ssfecscalarmul) | `r = k·P` — **constant-time**, for secret `k` |
| [e.g.](#ex-scalarmuldual) | [`void SSFECScalarMulDual(r, u1, p, u2, q, curve)`](#ssfecscalarmuldual) | `r = u₁·P + u₂·Q` — variable-time, ECDSA verify only |

<a id="function-reference"></a>

## [↑](#ssfec--elliptic-curve-point-arithmetic) Function Reference

<a id="ssfecgetcurveparams"></a>

### [↑](#functions) Curve Parameters

```c
const SSFECCurveParams_t *SSFECGetCurveParams(SSFECCurve_t curve);
```

Returns a pointer to the curve's parameter struct, or `NULL` if `curve` is not enabled in
the build. The returned struct is read-only static data; do not modify or free. Most
callers do not need this — the arithmetic functions take the `SSFECCurve_t` enum directly
and look up the params internally. Retrieve the struct explicitly when you need the
generator `(gₓ, gᵧ)` (e.g., to compute a public key `Q = d·G`), the curve order `n` (to
reduce ECDSA nonces and signatures), or the coordinate byte length for sizing a buffer.

---

<a id="point-lifecycle"></a>

### [↑](#functions) Point Lifecycle

<a id="ssfecpointsetidentity"></a>
```c
void SSFECPointSetIdentity(SSFECPoint_t *pt, SSFECCurve_t curve);
```
Initialises `pt` as the identity (point at infinity) with the curve's working limb count.
Internally sets `X = 0`, `Y = 1`, `Z = 0`.

<a id="ssfecpointisidentity"></a>
```c
bool SSFECPointIsIdentity(const SSFECPoint_t *pt);
```
Returns `true` if `Z == 0`. Cheap constant-time check.

<a id="ssfecpointfromaffine"></a>
```c
void SSFECPointFromAffine(SSFECPoint_t *pt, const SSFBN_t *x, const SSFBN_t *y,
                          SSFECCurve_t curve);
```
Builds a Jacobian `pt` from affine coordinates by setting `(X, Y, Z) = (x, y, 1)`. Does
**not** validate that `(x, y)` lies on the curve — if `(x, y)` came from untrusted input,
follow up with [`SSFECPointValidate()`](#ssfecpointvalidate).

<a id="ssfecpointtoaffine"></a>
```c
bool SSFECPointToAffine(SSFBN_t *x, SSFBN_t *y, const SSFECPoint_t *pt, SSFECCurve_t curve);
```
Computes affine `(x, y) = (X/Z², Y/Z³)` by inverting `Z` modulo `p`. Returns `false` if `pt`
is the identity (no finite affine representation). The modular inversion is the expensive
part of this call; defer it until just before you need the affine value on the wire or as
an input to a non-EC primitive.

---

<a id="point-validation"></a>

### [↑](#functions) Point Validation

<a id="ssfecpointoncurve"></a>
```c
bool SSFECPointOnCurve(const SSFECPoint_t *pt, SSFECCurve_t curve);
```
Checks whether `pt` satisfies the curve equation `y² ≡ x³ + ax + b (mod p)` by converting
to affine and substituting. Returns `false` for the identity (which has no affine form) and
for any point that fails the equation. Does **not** check coordinate ranges — use
[`SSFECPointValidate()`](#ssfecpointvalidate) for that.

<a id="ssfecpointvalidate"></a>
```c
bool SSFECPointValidate(const SSFECPoint_t *pt, SSFECCurve_t curve);
```
Full validation suitable for untrusted input. Checks: (1) point is not identity; (2) `x` and
`y` are in `[0, p-1]`; (3) the curve equation holds. All three must pass for `true`. Run
this on any point whose bytes arrived from outside — the peer's ECDH public key, a decoded
signature, a certificate's subject public key. Missing this check enables invalid-curve
attacks on the subsequent scalar multiplication. [`SSFECPointDecode()`](#serialization)
already calls `Validate` internally, so bytes that successfully decode are safe to use.

---

<a id="serialization"></a>

### [↑](#functions) Serialization (SEC 1 Uncompressed)

```c
bool SSFECPointEncode(const SSFECPoint_t *pt, SSFECCurve_t curve,
                      uint8_t *out, size_t outSize, size_t *outLen);
bool SSFECPointDecode(SSFECPoint_t *pt,       SSFECCurve_t curve,
                      const uint8_t *data,    size_t dataLen);
```

Read and write the SEC 1 v2 uncompressed point encoding: one byte `0x04` followed by the
fixed-width big-endian `X` and `Y` coordinates. Total length is `1 + 2 × coordBytes` —
`65` bytes for P-256, `97` for P-384. The compressed forms (`0x02` / `0x03`, one byte plus
`X`) are not supported.

- `SSFECPointEncode` writes the encoded bytes into `out`, stores the actual length in
  `*outLen`, and returns `false` if `outSize` is smaller than the required
  `1 + 2 × coordBytes`. Cannot encode the identity.
- `SSFECPointDecode` parses `data`, rejecting anything whose first byte is not `0x04` or
  whose total length is wrong for the selected curve, then calls
  [`SSFECPointValidate()`](#ssfecpointvalidate) on the decoded point. Returns `false` on
  any failure, leaving `pt` in an indeterminate state — do not use `pt` if `false`.

<a id="ex-codec"></a>

**Example:**

```c
/* Encode a public key to the SEC 1 uncompressed bytes that go in a
   TLS ServerKeyExchange or a CBOR COSE_Key entry. */
uint8_t  wire[SSF_EC_MAX_ENCODED_SIZE];
size_t   wireLen;

if (!SSFECPointEncode(&pub, SSF_EC_CURVE_P256, wire, sizeof(wire), &wireLen))
{
    /* Buffer too small. Size it to at least 1 + 2 * 32 = 65 bytes for P-256. */
}

/* On the peer, parse + validate the received bytes in one step.
   On failure the message is rejected with no further exposure. */
SSFECPoint_t peerPub;
if (!SSFECPointDecode(&peerPub, SSF_EC_CURVE_P256, wire, wireLen))
{
    /* Malformed, wrong length, or off-curve. Abort the handshake. */
}
/* peerPub is guaranteed on-curve, non-identity, coordinates in range. */
```

---

<a id="arithmetic"></a>

### [↑](#functions) Arithmetic

<a id="ssfecpointadd"></a>
```c
void SSFECPointAdd(SSFECPoint_t *r, const SSFECPoint_t *p, const SSFECPoint_t *q,
                   SSFECCurve_t curve);
```
`r = P + Q`. Internally dispatches to the full Jacobian addition formula when `P ≠ ±Q`, to
a doubling formula when `P = Q`, and to a pass-through when either operand is the
identity. `r` may alias `p` or `q`.

<a id="ex-add"></a>

**Example:**

```c
SSFECPoint_t r;
SSFECPointAdd(&r, &P, &Q, SSF_EC_CURVE_P256);
/* r = P + Q (still in Jacobian form). */
```

<a id="ssfecscalarmul"></a>
```c
void SSFECScalarMul(SSFECPoint_t *r, const SSFBN_t *k, const SSFECPoint_t *p,
                    SSFECCurve_t curve);
```
Constant-time scalar multiplication `r = k·P` via the Montgomery ladder. Processes every
bit of `k` up to the curve's working width using constant-time conditional swaps
([`SSFBNCondSwap()`](ssfbn.md#condswap)) and unconditional `Add` / `Double` calls. Working
points are [`SSFBNZeroize`](ssfbn.md#ssfbnzeroize)'d before return to keep key-derived
state out of the stack.

`k` must be in `[1, n-1]` (non-zero and less than the curve order). The caller is
responsible for ensuring that — e.g., by rejection-sampling from
[`ssfprng`](ssfprng.md) output until the candidate is in range, or by reducing mod `n` with
[`SSFBNMod()`](ssfbn.md#ssfbnmod).

<a id="ex-scalarmul"></a>

**Example:**

```c
/* Compute an ECDH shared secret: given our private scalar d and the peer's
   validated public point Q, the shared secret is the X coordinate of d * Q. */
SSFECPoint_t shared;
SSFECScalarMul(&shared, &d_priv, &peerPub, SSF_EC_CURVE_P256);

SSFBN_t sharedX, sharedY;
SSFECPointToAffine(&sharedX, &sharedY, &shared, SSF_EC_CURVE_P256);

uint8_t out[32];
SSFBNToBytes(&sharedX, out, sizeof(out));   /* 32 bytes of raw shared secret */
/* Feed `out` into ssfhkdf to derive actual session keys. */

/* Zeroize the secret intermediates. */
SSFBNZeroize(&sharedX); SSFBNZeroize(&sharedY);
```

<a id="ssfecscalarmuldual"></a>
```c
void SSFECScalarMulDual(SSFECPoint_t *r,
                        const SSFBN_t *u1, const SSFECPoint_t *p,
                        const SSFBN_t *u2, const SSFECPoint_t *q,
                        SSFECCurve_t curve);
```
`r = u₁·P + u₂·Q` using Shamir's trick (a joint double-and-add that processes both scalars
in lockstep, with a precomputed 4-entry table `{O, P, Q, P+Q}`). **Not constant-time.**
Intended specifically for ECDSA verification, where both `u₁` and `u₂` are derived from
public data (the message digest and the signature). Do not use on any combination that
involves a secret scalar — use two separate [`SSFECScalarMul()`](#ssfecscalarmul) calls
plus a [`SSFECPointAdd()`](#ssfecpointadd) instead.

<a id="ex-scalarmuldual"></a>

**Example:**

```c
/* Inside an ECDSA verifier: R' = u1*G + u2*Q, where
     u1 = e * s^-1 mod n,  u2 = r * s^-1 mod n,
   G is the curve generator, Q is the signer's public key. Both u1 and u2
   are derived from public values (message digest, signature), so the
   variable-time dual scalar mul is safe here. */
SSFECPoint_t G_point, Rprime;
SSFECPointFromAffine(&G_point, &c->gx, &c->gy, SSF_EC_CURVE_P256);

SSFECScalarMulDual(&Rprime, &u1, &G_point, &u2, &Q_signer, SSF_EC_CURVE_P256);

/* Extract affine x and compare mod n to the signature's r field. */
```
