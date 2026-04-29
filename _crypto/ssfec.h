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
#if SSF_BN_CONFIG_MAX_BITS < 512
#error SSF_BN_CONFIG_MAX_BITS must be >= 512 for P-256 support (2 x 256-bit operand).
#endif
#endif

#if SSF_EC_CONFIG_ENABLE_P384 == 1
#if SSF_BN_CONFIG_MAX_BITS < 768
#error SSF_BN_CONFIG_MAX_BITS must be >= 768 for P-384 support (2 x 384-bit operand).
#endif
#endif

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

/* Widest ECC scalar / field element in limbs, derived from the enabled-curves configuration. */
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

/* Declares an SSFECPoint_t backed by three zero-initialized SSFBNLimb_t arrays (X, Y, Z). */
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
const SSFECCurveParams_t *SSFECGetCurveParams(SSFECCurve_t curve);
void SSFECPointSetIdentity(SSFECPoint_t *pt, SSFECCurve_t curve);
bool SSFECPointIsIdentity(const SSFECPoint_t *pt);
void SSFECPointFromAffine(SSFECPoint_t *pt, const SSFBN_t *x, const SSFBN_t *y,
                          SSFECCurve_t curve);
bool SSFECPointToAffine(SSFBN_t *x, SSFBN_t *y, const SSFECPoint_t *pt, SSFECCurve_t curve);
bool SSFECPointOnCurve(const SSFECPoint_t *pt, SSFECCurve_t curve);
bool SSFECPointValidate(const SSFECPoint_t *pt, SSFECCurve_t curve);
bool SSFECPointEncode(const SSFECPoint_t *pt, SSFECCurve_t curve, uint8_t *out, size_t outSize,
                      size_t *outLen);
bool SSFECPointDecode(SSFECPoint_t *pt, SSFECCurve_t curve, const uint8_t *data, size_t dataLen);
void SSFECPointAdd(SSFECPoint_t *r, const SSFECPoint_t *p, const SSFECPoint_t *q,
                   SSFECCurve_t curve);
void SSFECScalarMul(SSFECPoint_t *r, const SSFBN_t *k, const SSFECPoint_t *p, SSFECCurve_t curve);
void SSFECScalarMulDual(SSFECPoint_t *r, const SSFBN_t *u1, const SSFECPoint_t *p,
                        const SSFBN_t *u2, const SSFECPoint_t *q, SSFECCurve_t curve);

#if (SSF_EC_CONFIG_FIXED_BASE_P256 == 1) || (SSF_EC_CONFIG_FIXED_BASE_P384 == 1)
void SSFECScalarMulDualBase(SSFECPoint_t *r, const SSFBN_t *u1,
                            const SSFBN_t *u2, const SSFECPoint_t *q, SSFECCurve_t curve);
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 || SSF_EC_CONFIG_FIXED_BASE_P384 */

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
void SSFECScalarMulBaseP256(SSFECPoint_t *r, const SSFBN_t *k);
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 */

#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
void SSFECScalarMulBaseP384(SSFECPoint_t *r, const SSFBN_t *k);
#endif /* SSF_EC_CONFIG_FIXED_BASE_P384 */

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_EC_UNIT_TEST == 1
void SSFECUnitTest(void);

/* Test wrapper for _SSFECPointAddMixed (q must have Z=1 affine or Z=0 identity). */
void _SSFECPointAddMixedForTest(SSFECPoint_t *r, const SSFECPoint_t *p,
                                const SSFECPoint_t *q, SSFECCurve_t curve);

/* Test wrapper for _SSFECPointAddMixedNoDouble (caller must guarantee P != Q). */
void _SSFECPointAddMixedNoDoubleForTest(SSFECPoint_t *r, const SSFECPoint_t *p,
                                        const SSFECPoint_t *q, SSFECCurve_t curve);

/* Test wrapper for the variable-time wNAF scalar mul (PUBLIC-INPUT ONLY). */
void _SSFECScalarMulVTwNAFForTest(SSFECPoint_t *r, const SSFBN_t *k,
                                  const SSFECPoint_t *p, SSFECCurve_t curve);
#endif /* SSF_CONFIG_EC_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_EC_H_INCLUDE */

