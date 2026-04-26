/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfec.h                                                                                       */
/* Provides elliptic curve point arithmetic over NIST prime curves P-256 and P-384.              */
/*                                                                                               */
/* FIPS 186-4: Digital Signature Standard (DSS)                                                  */
/* NIST SP 800-186: Recommendations for Discrete Logarithm-based Cryptography                   */
/* SEC 1 v2: Elliptic Curve Cryptography                                                        */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2024 Supurloop Software LLC                                                         */
/*                                                                                               */
/* Redistribution and use in source and binary forms, with or without modification, are          */
/* permitted provided that the following conditions are met:                                     */
/*                                                                                               */
/* 1. Redistributions of source code must retain the above copyright notice, this list of        */
/* conditions and the following disclaimer.                                                      */
/* 2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/* conditions and the following disclaimer in the documentation and/or other materials provided  */
/* with the distribution.                                                                        */
/* 3. Neither the name of the copyright holder nor the names of its contributors may be used to  */
/* endorse or promote products derived from this software without specific prior written         */
/* permission.                                                                                   */
/*                                                                                               */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/* OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/* MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE    */
/* COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL      */
/* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/* GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/* AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Per US export restrictions for open source cryptographic software the Department of Commerce  */
/* has been notified of the inclusion of cryptographic software in the SSF. This is a copy of    */
/* the notice emailed on Nov 11, 2021:                                                           */
/* --------------------------------------------------------------------------------------------- */
/* Unrestricted Encryption Source Code Notification                                              */
/* To : crypt@bis.doc.gov; enc@nsa.gov                                                           */
/* Subject : Addition to SSF Source Code                                                         */
/* Department of Commerce                                                                        */
/* Bureau of Export Administration                                                               */
/* Office of Strategic Trade and Foreign Policy Controls                                         */
/* 14th Street and Pennsylvania Ave., N.W.                                                       */
/* Room 2705                                                                                     */
/* Washington, DC 20230                                                                          */
/* Re: Unrestricted Encryption Source Code Notification Commodity : Addition to SSF Source Code  */
/*                                                                                               */
/* Dear Sir / Madam,                                                                             */
/*                                                                                               */
/* Pursuant to paragraph(e)(1) of Part 740.13 of the U.S.Export Administration Regulations       */
/* ("EAR", 15 CFR Part 730 et seq.), we are providing this written notification of the Internet  */
/* location of the unrestricted, publicly available Source Code being added to the Small System  */
/* Framework (SSF) Source Code. SSF Source Code is a free embedded system application framework  */
/* developed by Supurloop Software LLC in the Public Interest. This notification serves as a     */
/* notification of an addition of new software to the SSF archive. This archive is updated from  */
/* time to time, but its location is constant. Therefore this notification serves as a one-time  */
/* notification for subsequent updates that may occur in the future to the software covered by   */
/* this notification. Such updates may add or enhance cryptographic functionality of the SSF.    */
/* The Internet location for the SSF Source Code is: https://github.com/supurloop/ssf            */
/*                                                                                               */
/* This site may be mirrored to a number of other sites located outside the United States.       */
/*                                                                                               */
/* The following software is being added to the SSF archive:                                     */
/*                                                                                               */
/* ssfec.c, ssfec.h - Elliptic curve point arithmetic.                                           */
/*                                                                                               */
/* If you have any questions, please email me at xxx@xxx, or call me on (XXX) XXX-XXXX.          */
/*                                                                                               */
/* Sincerely,                                                                                    */
/* James Higgins                                                                                 */
/* President                                                                                     */
/* Supurloop Software LLC                                                                        */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_EC_H_INCLUDE
#define SSF_EC_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfbn.h"

/* --------------------------------------------------------------------------------------------- */
/* Compile-time validation                                                                       */
/* --------------------------------------------------------------------------------------------- */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
#if SSF_BN_CONFIG_MAX_BITS < 256
#error SSF_BN_CONFIG_MAX_BITS must be >= 256 for P-256 support.
#endif
#endif

#if SSF_EC_CONFIG_ENABLE_P384 == 1
#if SSF_BN_CONFIG_MAX_BITS < 384
#error SSF_BN_CONFIG_MAX_BITS must be >= 384 for P-384 support.
#endif
#endif

/* --------------------------------------------------------------------------------------------- */
/* Limitations                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* At least one curve must be enabled via SSF_EC_CONFIG_ENABLE_P256 or SSF_EC_CONFIG_ENABLE_P384 */
/* in ssfoptions.h.                                                                              */
/* Scalar multiplication uses a Montgomery ladder for constant-time execution. The edge case of  */
/* identity input handling may leak timing for the first few scalar bits; this is not exploitable */
/* for properly generated random scalars.                                                        */
/* SSFECScalarMulDual is NOT constant-time; it is intended for ECDSA verify where both scalars   */
/* are derived from public data.                                                                 */
/* Stack usage scales with SSF_BN_CONFIG_MAX_BITS. For ECC-only applications, set                */
/* SSF_BN_CONFIG_MAX_BITS to 384 to minimize stack usage.                                        */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
#define SSF_EC_MAX_COORD_BYTES (48u)
#elif SSF_EC_CONFIG_ENABLE_P256 == 1
#define SSF_EC_MAX_COORD_BYTES (32u)
#else
#error At least one EC curve must be enabled.
#endif

#define SSF_EC_MAX_ENCODED_SIZE (1u + 2u * SSF_EC_MAX_COORD_BYTES)

/* Widest ECC scalar / field element in limbs, derived from the enabled-curves configuration.    */
/* Use as the SSFBN_DEFINE `limbs` argument in ECC-only code — at `SSF_BN_CONFIG_MAX_BITS = 4096` */
/* every ECC SSFBN_t drops from 516 B to 56 B (P-384) or 40 B (P-256-only) under Phase 2.        */
#define SSF_EC_MAX_LIMBS (SSF_EC_MAX_COORD_BYTES / 4u)

/* Curve selection */
typedef enum
{
    SSF_EC_CURVE_MIN = -1,
    SSF_EC_CURVE_P256,   /* NIST P-256 / secp256r1 / prime256v1 */
    SSF_EC_CURVE_P384,   /* NIST P-384 / secp384r1 */
    SSF_EC_CURVE_MAX,
} SSFECCurve_t;

/* Jacobian point: affine (x,y) = (X/Z^2, Y/Z^3). Identity when Z = 0.                         */
typedef struct SSFECPoint
{
    SSFBN_t x;
    SSFBN_t y;
    SSFBN_t z;
} SSFECPoint_t;

/* Declare an SSFECPoint_t backed by three fresh zero-initialized SSFBNLimb_t arrays (one per    */
/* coordinate), each of capacity `nlimbs`. Use SSF_EC_MAX_LIMBS for curve-generic ECC code;      */
/* narrower caps are valid once the curve is known at compile time.                              */
#define SSFECPOINT_DEFINE(name, nlimbs) \
    SSFBNLimb_t name##_x_storage[(nlimbs)] = {0u}; \
    SSFBNLimb_t name##_y_storage[(nlimbs)] = {0u}; \
    SSFBNLimb_t name##_z_storage[(nlimbs)] = {0u}; \
    SSFECPoint_t name = { \
        { name##_x_storage, 0u, (uint16_t)(nlimbs) }, \
        { name##_y_storage, 0u, (uint16_t)(nlimbs) }, \
        { name##_z_storage, 0u, (uint16_t)(nlimbs) } \
    }

/* Curve parameters (FIPS 186-4 / NIST SP 800-186).                                             */
typedef struct SSFECCurveParams
{
    SSFBN_t p;       /* Field prime */
    SSFBN_t a;       /* Curve coefficient a (= p - 3 for P-256, P-384) */
    SSFBN_t b;       /* Curve coefficient b */
    SSFBN_t gx;      /* Generator X (affine) */
    SSFBN_t gy;      /* Generator Y (affine) */
    SSFBN_t n;       /* Curve order */
    uint16_t limbs;  /* Working limb count (8 for P-256, 12 for P-384) */
    uint16_t bytes;  /* Coordinate byte length (32 for P-256, 48 for P-384) */
} SSFECCurveParams_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Returns curve parameters for the given curve. Returns NULL if curve is not enabled.           */
const SSFECCurveParams_t *SSFECGetCurveParams(SSFECCurve_t curve);

/* Set point to identity (0, 1, 0) with the curve's working limb count.                         */
void SSFECPointSetIdentity(SSFECPoint_t *pt, SSFECCurve_t curve);

/* Returns true if point is identity (Z == 0).                                                   */
bool SSFECPointIsIdentity(const SSFECPoint_t *pt);

/* Set Jacobian point from affine coordinates (x, y). Sets Z = 1.                               */
void SSFECPointFromAffine(SSFECPoint_t *pt, const SSFBN_t *x, const SSFBN_t *y,
                          SSFECCurve_t curve);

/* Convert Jacobian point to affine (x, y). Returns false if point is identity.                  */
bool SSFECPointToAffine(SSFBN_t *x, SSFBN_t *y, const SSFECPoint_t *pt, SSFECCurve_t curve);

/* Returns true if point lies on the curve y^2 = x^3 + ax + b (mod p).                          */
bool SSFECPointOnCurve(const SSFECPoint_t *pt, SSFECCurve_t curve);

/* Full point validation for untrusted input: on-curve, not identity, coordinates in range.      */
bool SSFECPointValidate(const SSFECPoint_t *pt, SSFECCurve_t curve);

/* Encode point in SEC 1 uncompressed format: 0x04 || X || Y.                                   */
/* Returns false if outSize is too small. outLen receives actual encoded length.                  */
bool SSFECPointEncode(const SSFECPoint_t *pt, SSFECCurve_t curve,
                      uint8_t *out, size_t outSize, size_t *outLen);

/* Decode SEC 1 uncompressed point. Validates the decoded point. Returns false on any failure.   */
bool SSFECPointDecode(SSFECPoint_t *pt, SSFECCurve_t curve,
                      const uint8_t *data, size_t dataLen);

/* Point addition: r = p + q (Jacobian). r may alias p or q.                                     */
void SSFECPointAdd(SSFECPoint_t *r, const SSFECPoint_t *p, const SSFECPoint_t *q,
                   SSFECCurve_t curve);

/* Constant-time scalar multiplication: r = k * p (Montgomery ladder).                           */
/* k must be in [1, n-1].                                                                        */
void SSFECScalarMul(SSFECPoint_t *r, const SSFBN_t *k, const SSFECPoint_t *p,
                    SSFECCurve_t curve);

/* Dual scalar multiplication: r = u1 * p + u2 * q (Shamir's trick, not constant-time).         */
/* For ECDSA verify where u1, u2 are derived from public data.                                   */
void SSFECScalarMulDual(SSFECPoint_t *r,
                        const SSFBN_t *u1, const SSFECPoint_t *p,
                        const SSFBN_t *u2, const SSFECPoint_t *q,
                        SSFECCurve_t curve);

#if (SSF_EC_CONFIG_FIXED_BASE_P256 == 1) || (SSF_EC_CONFIG_FIXED_BASE_P384 == 1)
/* Specialized dual scalar multiplication: r = u1 * G + u2 * q where G is the curve generator.   */
/* Uses SSFECScalarMulBase{P256,P384} for u1*G (fixed-base comb, ~4x faster than the ladder)     */
/* plus the windowed SSFECScalarMul for u2*Q, then a final point add. Faster than                */
/* SSFECScalarMulDual's Shamir's trick when fixed-base tables are configured for `curve`.        */
/* Inputs are public; not constant-time. Intended for ECDSA verify.                              */
void SSFECScalarMulDualBase(SSFECPoint_t *r,
                            const SSFBN_t *u1,
                            const SSFBN_t *u2, const SSFECPoint_t *q,
                            SSFECCurve_t curve);
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 || SSF_EC_CONFIG_FIXED_BASE_P384 */

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
/* Fixed-base scalar multiplication for P-256: r = k * G. Constant-time, ~3-4x faster than     */
/* SSFECScalarMul(r, k, G, SSF_EC_CURVE_P256) thanks to a precomputed Lim-Lee comb table over   */
/* multiples of G. k must be in [0, n) where n is the P-256 curve order.                       */
void SSFECScalarMulBaseP256(SSFECPoint_t *r, const SSFBN_t *k);
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 */

#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
/* Fixed-base scalar multiplication for P-384: r = k * G. Constant-time, ~3-4x faster than     */
/* SSFECScalarMul(r, k, G, SSF_EC_CURVE_P384) thanks to a precomputed Lim-Lee comb table over   */
/* multiples of G. k must be in [0, n) where n is the P-384 curve order.                       */
void SSFECScalarMulBaseP384(SSFECPoint_t *r, const SSFBN_t *k);
#endif /* SSF_EC_CONFIG_FIXED_BASE_P384 */

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_EC_UNIT_TEST == 1
void SSFECUnitTest(void);

/* Test-only wrapper exposing the static _SSFECPointAddMixed for direct verification.            */
/* q must have Z=1 (affine) or Z=0 (identity); the function asserts neither, but mathematically  */
/* relies on Z=1 for the non-identity case. r may alias p or q.                                   */
void _SSFECPointAddMixedForTest(SSFECPoint_t *r, const SSFECPoint_t *p,
                                const SSFECPoint_t *q, SSFECCurve_t curve);

/* Test-only wrapper exposing the static _SSFECPointAddMixedNoDouble for direct verification.    */
/* Same contract as _SSFECPointAddMixed except: the caller must guarantee P != Q (and P != -Q is */
/* still handled). For P == Q the result is undefined (the function skips computing 2*P to save  */
/* one full doubling). Used by the comb runtime where R-vs-table[mask] collisions are            */
/* statistically impossible (~2^-bits).                                                            */
void _SSFECPointAddMixedNoDoubleForTest(SSFECPoint_t *r, const SSFECPoint_t *p,
                                        const SSFECPoint_t *q, SSFECCurve_t curve);

/* Test-only wrapper exposing the static variable-time wNAF scalar mul. Result is r = k*P.       */
/* PUBLIC-INPUT ONLY — timing depends on the bit pattern of k. Used internally by                */
/* SSFECScalarMulDualBase for the [u2]Q half of ECDSA verify.                                     */
void _SSFECScalarMulVTwNAFForTest(SSFECPoint_t *r, const SSFBN_t *k,
                                  const SSFECPoint_t *p, SSFECCurve_t curve);
#endif /* SSF_CONFIG_EC_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_EC_H_INCLUDE */
