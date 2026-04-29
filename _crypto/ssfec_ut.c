/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfec_ut.c                                                                                    */
/* Provides unit tests for the ssfec elliptic curve point arithmetic module.                     */
/* Test vectors from FIPS 186-4 and SEC 1 v2.                                                    */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
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
#include "ssfassert.h"
#include "ssfec.h"
#include "ssfport.h"
#include "ssfprng.h"
#if SSF_CONFIG_EC_MICROBENCH == 1
#include "ssfecdsa.h"
#include "ssfsha2.h"
#include <stdio.h>
#endif

/* Cross-check the SSFEC implementation against OpenSSL's EC_POINT / EC_GROUP. Gated on          */
/* SSF_CONFIG_HAVE_OPENSSL (1 on native macOS/Linux, 0 on cross builds -- see ssfport.h).        */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_EC_UNIT_TEST == 1)
#define SSF_EC_OSSL_VERIFY 1
#else
#define SSF_EC_OSSL_VERIFY 0
#endif

#if SSF_EC_OSSL_VERIFY == 1
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#endif

#if SSF_CONFIG_EC_UNIT_TEST == 1

#if SSF_EC_OSSL_VERIFY == 1

/* --------------------------------------------------------------------------------------------- */
/* OpenSSL EC cross-check helpers -- analogous to the BIGNUM helpers in ssfbn_ut.c.              */
/* --------------------------------------------------------------------------------------------- */

/* Convert an SSFBN_t to a BIGNUM via the canonical big-endian byte representation. */
static void _ECToOSSLBN(BIGNUM *dst, const SSFBN_t *src)
{
    uint8_t buf[SSF_EC_MAX_LIMBS * sizeof(SSFBNLimb_t)];
    size_t outSize = (size_t)src->len * sizeof(SSFBNLimb_t);
    SSF_ASSERT(outSize <= sizeof(buf));
    SSF_ASSERT(SSFBNToBytes(src, buf, outSize) == true);
    SSF_ASSERT(BN_bin2bn(buf, (int)outSize, dst) != NULL);
}

/* Convert a BIGNUM into an SSFBN_t at the curve's limb count. The BIGNUM must fit. */
static void _ECFromOSSLBN(SSFBN_t *dst, const BIGNUM *src, uint16_t numLimbs)
{
    uint8_t buf[SSF_EC_MAX_LIMBS * sizeof(SSFBNLimb_t)];
    size_t outSize = (size_t)numLimbs * sizeof(SSFBNLimb_t);
    SSF_ASSERT(outSize <= sizeof(buf));
    SSF_ASSERT(BN_num_bytes(src) <= (int)outSize);
    SSF_ASSERT(BN_bn2binpad(src, buf, (int)outSize) == (int)outSize);
    SSF_ASSERT(SSFBNFromBytes(dst, buf, outSize, numLimbs) == true);
}

/* Get the OpenSSL EC group for a given curve. */
static EC_GROUP *_ECGetOSSLGroup(SSFECCurve_t curve)
{
    int nid = (curve == SSF_EC_CURVE_P256) ? NID_X9_62_prime256v1 : NID_secp384r1;
    EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
    SSF_ASSERT(g != NULL);
    return g;
}

/* Convert SSFECPoint_t to OpenSSL EC_POINT. Identity points map to OpenSSL infinity. */
static void _ECPointToOSSL(EC_POINT *dst, const SSFECPoint_t *src,
                           SSFECCurve_t curve, EC_GROUP *group, BN_CTX *ctx)
{
    if (SSFECPointIsIdentity(src))
    {
        SSF_ASSERT(EC_POINT_set_to_infinity(group, dst) == 1);
    }
    else
    {
        SSFBN_DEFINE(ax, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ay, SSF_EC_MAX_LIMBS);
        BIGNUM *bnX = BN_new();
        BIGNUM *bnY = BN_new();
        SSF_ASSERT(SSFECPointToAffine(&ax, &ay, src, curve) == true);
        _ECToOSSLBN(bnX, &ax);
        _ECToOSSLBN(bnY, &ay);
        SSF_ASSERT(EC_POINT_set_affine_coordinates(group, dst, bnX, bnY, ctx) == 1);
        BN_free(bnX); BN_free(bnY);
    }
}

/* Convert OpenSSL EC_POINT to SSFECPoint_t (always Z=1 on output, since OpenSSL is affine).   */
static void _ECPointFromOSSL(SSFECPoint_t *dst, const EC_POINT *src,
                             SSFECCurve_t curve, EC_GROUP *group, BN_CTX *ctx)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    if (EC_POINT_is_at_infinity(group, src))
    {
        SSFECPointSetIdentity(dst, curve);
    }
    else
    {
        SSFBN_DEFINE(ax, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ay, SSF_EC_MAX_LIMBS);
        BIGNUM *bnX = BN_new();
        BIGNUM *bnY = BN_new();
        SSF_ASSERT(EC_POINT_get_affine_coordinates(group, src, bnX, bnY, ctx) == 1);
        _ECFromOSSLBN(&ax, bnX, c->limbs);
        _ECFromOSSLBN(&ay, bnY, c->limbs);
        SSFECPointFromAffine(dst, &ax, &ay, curve);
        BN_free(bnX); BN_free(bnY);
    }
}

/* Deep-copy an SSFECPoint_t (x, y, z fields). Used by the aliasing tests below: the input  */
/* point is snapshotted before each aliased call, then restored afterward, so the next test  */
/* iteration sees an unmodified P/Q.                                                          */
static void _ECPointCopy(SSFECPoint_t *dst, const SSFECPoint_t *src)
{
    SSFBNCopy(&dst->x, &src->x);
    SSFBNCopy(&dst->y, &src->y);
    SSFBNCopy(&dst->z, &src->z);
}

/* Compare an SSFECPoint_t to an OpenSSL EC_POINT by comparing affine coordinates. */
static bool _ECPointEqOSSL(const SSFECPoint_t *a, const EC_POINT *b,
                           SSFECCurve_t curve, EC_GROUP *group, BN_CTX *ctx)
{
    bool aIsId = SSFECPointIsIdentity(a);
    int  bIsId = EC_POINT_is_at_infinity(group, b);
    if (aIsId != (bIsId != 0)) return false;
    if (aIsId) return true;

    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
        SSFBN_DEFINE(ax, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ay, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(bx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(by, SSF_EC_MAX_LIMBS);
        BIGNUM *bnBx = BN_new();
        BIGNUM *bnBy = BN_new();
        bool eq;

        SSF_ASSERT(SSFECPointToAffine(&ax, &ay, a, curve) == true);
        SSF_ASSERT(EC_POINT_get_affine_coordinates(group, b, bnBx, bnBy, ctx) == 1);
        _ECFromOSSLBN(&bx, bnBx, c->limbs);
        _ECFromOSSLBN(&by, bnBy, c->limbs);
        eq = (SSFBNCmp(&ax, &bx) == 0) && (SSFBNCmp(&ay, &by) == 0);

        BN_free(bnBx); BN_free(bnBy);
        return eq;
    }
}

/* Driver: per-curve cross-check vs OpenSSL.                                                    */
/*                                                                                              */
/* Tests:                                                                                       */
/*  1. Curve generator (gx, gy) matches OpenSSL's EC_GROUP_get0_generator                      */
/*  2. Random PointAdd: SSFECPointAdd(P, Q) matches OpenSSL EC_POINT_add                       */
/*  3. Random PointDouble (via Add(P, P)): matches OpenSSL EC_POINT_dbl                        */
/*  4. Random ScalarMul on G: SSFECScalarMul(k, G) matches EC_POINT_mul(k, NULL)               */
/*  5. Random ScalarMul on arbitrary point: matches EC_POINT_mul(0, Q, k)                      */
/*  6. Fixed-base ScalarMulBase{P256|P384}: matches EC_POINT_mul                               */
/*  7. ScalarMulDual: [u1]P + [u2]Q matches OpenSSL                                            */
/*  8. ScalarMulDualBase: [u1]G + [u2]Q matches OpenSSL                                        */
/*  9. PointEncode/Decode roundtrip equivalent to OpenSSL i2o/o2i                              */
static void _ECVerifyAtCurve(SSFECCurve_t curve, uint16_t iters)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    EC_GROUP *group = _ECGetOSSLGroup(curve);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bnK1 = BN_new();
    BIGNUM *bnK2 = BN_new();
    BIGNUM *bnOrder = BN_new();
    EC_POINT *osslP = EC_POINT_new(group);
    EC_POINT *osslQ = EC_POINT_new(group);
    EC_POINT *osslR = EC_POINT_new(group);
    EC_POINT *osslT = EC_POINT_new(group);
    SSFECPOINT_DEFINE(G,    SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(P,    SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q,    SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(R,    SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(k1, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(k2, SSF_EC_MAX_LIMBS);
    uint16_t i;

    SSF_ASSERT(ctx != NULL);
    SSF_ASSERT(bnK1 != NULL && bnK2 != NULL && bnOrder != NULL);
    SSF_ASSERT(osslP != NULL && osslQ != NULL && osslR != NULL && osslT != NULL);

    SSF_ASSERT(EC_GROUP_get_order(group, bnOrder, ctx) == 1);
    SSFECPointFromAffine(&G, &c->gx, &c->gy, curve);

    /* === Test 1: Generator matches OpenSSL =================================================== */
    {
        const EC_POINT *osslG = EC_GROUP_get0_generator(group);
        SSF_ASSERT(_ECPointEqOSSL(&G, osslG, curve, group, ctx) == true);
        SSF_ASSERT(SSFECPointOnCurve(&G, curve) == true);
        SSF_ASSERT(EC_POINT_is_on_curve(group, osslG, ctx) == 1);
    }

    /* === Per-iteration random tests ========================================================== */
    for (i = 0; i < iters; i++)
    {
        /* Random scalars k1, k2 in [1, n-1]. */
        SSF_ASSERT(BN_rand_range(bnK1, bnOrder) == 1);
        if (BN_is_zero(bnK1)) BN_one(bnK1);
        SSF_ASSERT(BN_rand_range(bnK2, bnOrder) == 1);
        if (BN_is_zero(bnK2)) BN_one(bnK2);
        _ECFromOSSLBN(&k1, bnK1, c->limbs);
        _ECFromOSSLBN(&k2, bnK2, c->limbs);

        /* === Test 4: ScalarMul on G: SSF [k1]G vs OpenSSL [k1]G ============================= */
        SSFECScalarMul(&P, &k1, &G, curve);
        SSF_ASSERT(EC_POINT_mul(group, osslP, bnK1, NULL, NULL, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&P, osslP, curve, group, ctx) == true);

        /* P is now [k1]G in both libs. Build Q = [k2]G similarly. */
        SSFECScalarMul(&Q, &k2, &G, curve);
        SSF_ASSERT(EC_POINT_mul(group, osslQ, bnK2, NULL, NULL, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&Q, osslQ, curve, group, ctx) == true);

        /* === Test 2: PointAdd: P + Q ======================================================== */
        SSFECPointAdd(&R, &P, &Q, curve);
        SSF_ASSERT(EC_POINT_add(group, osslR, osslP, osslQ, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

        /* === Test 3: PointDouble (via Add(P, P)): 2P ======================================== */
        SSFECPointAdd(&R, &P, &P, curve);
        SSF_ASSERT(EC_POINT_dbl(group, osslR, osslP, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

        /* === Test 5: ScalarMul on arbitrary point: [k2]P (where P = [k1]G) ================== */
        SSFECScalarMul(&R, &k2, &P, curve);
        SSF_ASSERT(EC_POINT_mul(group, osslR, NULL, osslP, bnK2, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

        /* === Test 7: ScalarMulDual: [k1]P + [k2]Q ========================================== */
        SSFECScalarMulDual(&R, &k1, &P, &k2, &Q, curve);
        SSF_ASSERT(EC_POINT_mul(group, osslT, NULL, osslP, bnK1, ctx) == 1); /* [k1]P */
        SSF_ASSERT(EC_POINT_mul(group, osslR, NULL, osslQ, bnK2, ctx) == 1); /* [k2]Q */
        SSF_ASSERT(EC_POINT_add(group, osslR, osslT, osslR, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

        /* === Test 8: ScalarMulDualBase: [k1]G + [k2]Q ====================================== */
        SSFECScalarMulDualBase(&R, &k1, &k2, &Q, curve);
        SSF_ASSERT(EC_POINT_mul(group, osslR, bnK1, osslQ, bnK2, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

        /* === Test 9: PointEncode/Decode roundtrip ========================================== */
        {
            uint8_t sec1[1u + 2u * SSF_EC_MAX_LIMBS * sizeof(SSFBNLimb_t)];
            uint8_t osslSec1[1u + 2u * SSF_EC_MAX_LIMBS * sizeof(SSFBNLimb_t)];
            size_t sec1Len;
            size_t osslSec1Len;
            SSFECPOINT_DEFINE(decoded, SSF_EC_MAX_LIMBS);

            /* Encode P with both libs. */
            SSF_ASSERT(SSFECPointEncode(&P, curve, sec1, sizeof(sec1), &sec1Len) == true);
            osslSec1Len = EC_POINT_point2oct(group, osslP, POINT_CONVERSION_UNCOMPRESSED,
                                             osslSec1, sizeof(osslSec1), ctx);
            SSF_ASSERT(osslSec1Len > 0u);
            SSF_ASSERT(sec1Len == osslSec1Len);
            SSF_ASSERT(memcmp(sec1, osslSec1, sec1Len) == 0);

            /* Decode SSF's encoding back via SSF -- must round-trip. */
            SSF_ASSERT(SSFECPointDecode(&decoded, curve, sec1, sec1Len) == true);
            SSF_ASSERT(_ECPointEqOSSL(&decoded, osslP, curve, group, ctx) == true);

            /* Decode OpenSSL's encoding via SSF -- must accept and equal P. */
            SSF_ASSERT(SSFECPointDecode(&decoded, curve, osslSec1, osslSec1Len) == true);
            SSF_ASSERT(_ECPointEqOSSL(&decoded, osslP, curve, group, ctx) == true);
        }

        /* === Aliasing tests: output point shares storage with an input. ====================== */
        /* All four aliasing patterns must produce the same result as the non-aliased call.       */
        /* Catches a class of bugs where the implementation overwrites an input limb before       */
        /* finishing reading from it. Snapshot/restore so subsequent iterations see clean P/Q.    */
        {
            SSFECPOINT_DEFINE(Psave, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(Qsave, SSF_EC_MAX_LIMBS);
            EC_POINT *osslAdd = EC_POINT_new(group);
            EC_POINT *osslMul = EC_POINT_new(group);
            SSF_ASSERT(osslAdd != NULL && osslMul != NULL);

            _ECPointCopy(&Psave, &P);
            _ECPointCopy(&Qsave, &Q);

            /* Reference: P + Q (OpenSSL) and [k2]P (OpenSSL). */
            SSF_ASSERT(EC_POINT_add(group, osslAdd, osslP, osslQ, ctx) == 1);
            SSF_ASSERT(EC_POINT_mul(group, osslMul, NULL, osslP, bnK2, ctx) == 1);

            /* Add aliasing: r = first input.   P := P + Q */
            SSFECPointAdd(&P, &P, &Q, curve);
            SSF_ASSERT(_ECPointEqOSSL(&P, osslAdd, curve, group, ctx) == true);
            _ECPointCopy(&P, &Psave);

            /* Add aliasing: r = second input.  Q := P + Q */
            SSFECPointAdd(&Q, &P, &Q, curve);
            SSF_ASSERT(_ECPointEqOSSL(&Q, osslAdd, curve, group, ctx) == true);
            _ECPointCopy(&Q, &Qsave);

            /* Add aliasing: r = both inputs.   P := P + P (= 2P, doubling via aliased Add) */
            SSF_ASSERT(EC_POINT_dbl(group, osslAdd, osslP, ctx) == 1);
            SSFECPointAdd(&P, &P, &P, curve);
            SSF_ASSERT(_ECPointEqOSSL(&P, osslAdd, curve, group, ctx) == true);
            _ECPointCopy(&P, &Psave);

            /* ScalarMul aliasing: r = input point.  P := [k2]P */
            SSFECScalarMul(&P, &k2, &P, curve);
            SSF_ASSERT(_ECPointEqOSSL(&P, osslMul, curve, group, ctx) == true);
            _ECPointCopy(&P, &Psave);

            EC_POINT_free(osslAdd);
            EC_POINT_free(osslMul);
        }
    }

#if (SSF_EC_CONFIG_FIXED_BASE_P256 == 1) || (SSF_EC_CONFIG_FIXED_BASE_P384 == 1)
    /* === Test 6: Fixed-base ScalarMulBase{P256|P384} matches OpenSSL [k]G =================== */
    for (i = 0; i < iters; i++)
    {
        SSF_ASSERT(BN_rand_range(bnK1, bnOrder) == 1);
        if (BN_is_zero(bnK1)) BN_one(bnK1);
        _ECFromOSSLBN(&k1, bnK1, c->limbs);

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
        if (curve == SSF_EC_CURVE_P256)
        {
            SSFECScalarMulBaseP256(&R, &k1);
            SSF_ASSERT(EC_POINT_mul(group, osslR, bnK1, NULL, NULL, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
        }
#endif
#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
        if (curve == SSF_EC_CURVE_P384)
        {
            SSFECScalarMulBaseP384(&R, &k1);
            SSF_ASSERT(EC_POINT_mul(group, osslR, bnK1, NULL, NULL, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
        }
#endif
    }
#endif

    /* === Identity-handling sanity: SSF identity round-trips through OpenSSL ============== */
    {
        SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
        SSFECPointSetIdentity(&O, curve);
        SSF_ASSERT(EC_POINT_set_to_infinity(group, osslT) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&O, osslT, curve, group, ctx) == true);
    }

    /* === Edge scalars: k = 0, 1, n-1, n cross-checked with OpenSSL ======================= */
    /* Random scalars almost certainly miss these specific values. OpenSSL handles them in    */
    /* well-defined ways (k=0 -> identity, k=1 -> G, k=n-1 -> -G, k=n -> identity); SSF must too. */
    {
        SSFBN_DEFINE(kEdge, SSF_EC_MAX_LIMBS);
        BIGNUM *bnEdge = BN_new();

        /* k = 0 -> identity */
        SSFBNSetZero(&kEdge, c->limbs);
        BN_zero(bnEdge);
        SSFECScalarMul(&R, &kEdge, &G, curve);
        SSF_ASSERT(EC_POINT_mul(group, osslR, bnEdge, NULL, NULL, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);

        /* k = 1 -> G */
        SSFBNSetUint32(&kEdge, 1u, c->limbs);
        BN_one(bnEdge);
        SSFECScalarMul(&R, &kEdge, &G, curve);
        SSF_ASSERT(EC_POINT_mul(group, osslR, bnEdge, NULL, NULL, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

        /* k = n-1 -> -G */
        SSFBNCopy(&kEdge, &c->n);
        (void)SSFBNSubUint32(&kEdge, &kEdge, 1u);
        SSF_ASSERT(BN_copy(bnEdge, bnOrder) != NULL);
        SSF_ASSERT(BN_sub_word(bnEdge, 1) == 1);
        SSFECScalarMul(&R, &kEdge, &G, curve);
        SSF_ASSERT(EC_POINT_mul(group, osslR, bnEdge, NULL, NULL, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

        /* k = n -> identity (curve order kills G) */
        SSFBNCopy(&kEdge, &c->n);
        SSF_ASSERT(BN_copy(bnEdge, bnOrder) != NULL);
        SSFECScalarMul(&R, &kEdge, &G, curve);
        SSF_ASSERT(EC_POINT_mul(group, osslR, bnEdge, NULL, NULL, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
        if (curve == SSF_EC_CURVE_P256)
        {
            SSFBNSetZero(&kEdge, c->limbs);
            BN_zero(bnEdge);
            SSFECScalarMulBaseP256(&R, &kEdge);
            SSF_ASSERT(EC_POINT_mul(group, osslR, bnEdge, NULL, NULL, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

            SSFBNSetUint32(&kEdge, 1u, c->limbs);
            BN_one(bnEdge);
            SSFECScalarMulBaseP256(&R, &kEdge);
            SSF_ASSERT(EC_POINT_mul(group, osslR, bnEdge, NULL, NULL, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

            SSFBNCopy(&kEdge, &c->n);
            (void)SSFBNSubUint32(&kEdge, &kEdge, 1u);
            SSF_ASSERT(BN_copy(bnEdge, bnOrder) != NULL);
            SSF_ASSERT(BN_sub_word(bnEdge, 1) == 1);
            SSFECScalarMulBaseP256(&R, &kEdge);
            SSF_ASSERT(EC_POINT_mul(group, osslR, bnEdge, NULL, NULL, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
        }
#endif
#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
        if (curve == SSF_EC_CURVE_P384)
        {
            SSFBNSetZero(&kEdge, c->limbs);
            BN_zero(bnEdge);
            SSFECScalarMulBaseP384(&R, &kEdge);
            SSF_ASSERT(EC_POINT_mul(group, osslR, bnEdge, NULL, NULL, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

            SSFBNSetUint32(&kEdge, 1u, c->limbs);
            BN_one(bnEdge);
            SSFECScalarMulBaseP384(&R, &kEdge);
            SSF_ASSERT(EC_POINT_mul(group, osslR, bnEdge, NULL, NULL, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
        }
#endif
        BN_free(bnEdge);
    }

    /* === ScalarMul on identity input -> identity (cross-checked with OpenSSL) ============== */
    {
        SSFECPOINT_DEFINE(Oin, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(kArbit, SSF_EC_MAX_LIMBS);
        BIGNUM *bnArbit = BN_new();

        SSFECPointSetIdentity(&Oin, curve);
        SSF_ASSERT(EC_POINT_set_to_infinity(group, osslT) == 1);

        SSFBNSetUint32(&kArbit, 12345u, c->limbs);
        SSF_ASSERT(BN_set_word(bnArbit, 12345u) == 1);

        SSFECScalarMul(&R, &kArbit, &Oin, curve);
        SSF_ASSERT(EC_POINT_mul(group, osslR, NULL, osslT, bnArbit, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);

        BN_free(bnArbit);
    }

    /* === PointAdd identity edge cases cross-checked with OpenSSL ========================== */
    {
        SSFECPOINT_DEFINE(Oin, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(NegG, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(negY, SSF_EC_MAX_LIMBS);

        SSFECPointSetIdentity(&Oin, curve);
        SSF_ASSERT(EC_POINT_set_to_infinity(group, osslT) == 1);

        /* G + O = G */
        SSFECPointAdd(&R, &G, &Oin, curve);
        SSF_ASSERT(EC_POINT_copy(osslP, EC_GROUP_get0_generator(group)) == 1);
        SSF_ASSERT(EC_POINT_add(group, osslR, osslP, osslT, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

        /* O + G = G */
        SSFECPointAdd(&R, &Oin, &G, curve);
        SSF_ASSERT(EC_POINT_add(group, osslR, osslT, osslP, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

        /* G + (-G) = O */
        SSFBNSub(&negY, &c->p, &c->gy);
        SSFBNCopy(&NegG.x, &c->gx);
        SSFBNCopy(&NegG.y, &negY);
        SSFBNSetOne(&NegG.z, c->limbs);
        SSFECPointAdd(&R, &G, &NegG, curve);
        _ECPointToOSSL(osslQ, &NegG, curve, group, ctx);
        SSF_ASSERT(EC_POINT_add(group, osslR, osslP, osslQ, ctx) == 1);
        SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);
    }

    /* === Random non-G base points ========================================================= */
    /* Existing tests use P = [k1]G as the "arbitrary" base, so any bug specific to a base    */
    /* generated by something other than SSF's own ScalarMul is invisible. Here OpenSSL        */
    /* generates the base (Pbase = [r]G via OpenSSL only), then SSF runs ScalarMul / Add on it */
    /* with random scalars and we cross-check each result.                                     */
    {
        SSFECPOINT_DEFINE(Pbase, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Qbase, SSF_EC_MAX_LIMBS);
        EC_POINT *osslPbase = EC_POINT_new(group);
        EC_POINT *osslQbase = EC_POINT_new(group);
        BIGNUM   *bnR = BN_new();
        uint16_t  it;
        SSF_ASSERT(osslPbase != NULL && osslQbase != NULL && bnR != NULL);

        for (it = 0; it < 6u; it++)
        {
            /* Build Pbase = [r]G via OpenSSL only. */
            SSF_ASSERT(BN_rand_range(bnR, bnOrder) == 1);
            if (BN_is_zero(bnR)) BN_one(bnR);
            SSF_ASSERT(EC_POINT_mul(group, osslPbase, bnR, NULL, NULL, ctx) == 1);
            _ECPointFromOSSL(&Pbase, osslPbase, curve, group, ctx);

            /* Sanity: SSF agrees this point is on the curve. */
            SSF_ASSERT(SSFECPointOnCurve(&Pbase, curve) == true);

            /* Build a second non-G base Qbase the same way for the Add test. */
            SSF_ASSERT(BN_rand_range(bnR, bnOrder) == 1);
            if (BN_is_zero(bnR)) BN_one(bnR);
            SSF_ASSERT(EC_POINT_mul(group, osslQbase, bnR, NULL, NULL, ctx) == 1);
            _ECPointFromOSSL(&Qbase, osslQbase, curve, group, ctx);

            /* Random scalars k1, k2. */
            SSF_ASSERT(BN_rand_range(bnK1, bnOrder) == 1);
            if (BN_is_zero(bnK1)) BN_one(bnK1);
            SSF_ASSERT(BN_rand_range(bnK2, bnOrder) == 1);
            if (BN_is_zero(bnK2)) BN_one(bnK2);
            _ECFromOSSLBN(&k1, bnK1, c->limbs);
            _ECFromOSSLBN(&k2, bnK2, c->limbs);

            /* SSFECScalarMul on the non-G base. */
            SSFECScalarMul(&R, &k1, &Pbase, curve);
            SSF_ASSERT(EC_POINT_mul(group, osslR, NULL, osslPbase, bnK1, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

            /* SSFECPointAdd of two non-G bases. */
            SSFECPointAdd(&R, &Pbase, &Qbase, curve);
            SSF_ASSERT(EC_POINT_add(group, osslR, osslPbase, osslQbase, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

            /* SSFECScalarMulDual on two non-G bases. */
            SSFECScalarMulDual(&R, &k1, &Pbase, &k2, &Qbase, curve);
            SSF_ASSERT(EC_POINT_mul(group, osslT, NULL, osslPbase, bnK1, ctx) == 1);
            SSF_ASSERT(EC_POINT_mul(group, osslR, NULL, osslQbase, bnK2, ctx) == 1);
            SSF_ASSERT(EC_POINT_add(group, osslR, osslT, osslR, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
        }

        EC_POINT_free(osslPbase);
        EC_POINT_free(osslQbase);
        BN_free(bnR);
    }

    /* === Scalars k > n: reduction-mod-n behaviour ========================================== */
    /* SSFBN_t at SSF_EC_MAX_LIMBS holds at most ~curve_bits, so k can only exceed n by the    */
    /* gap between n and 2^curve_bits -- small for both NIST curves but enough to verify the   */
    /* implementation reduces mod n correctly. OpenSSL handles k > n via internal reduction;   */
    /* SSF must produce the same point.                                                         */
    {
        SSFBN_DEFINE(kBig, SSF_EC_MAX_LIMBS);
        BIGNUM  *bnBig    = BN_new();
        BIGNUM  *bnDelta  = BN_new();
        BIGNUM  *bnReduce = BN_new();
        uint16_t it;
        SSF_ASSERT(bnBig != NULL && bnDelta != NULL && bnReduce != NULL);

        for (it = 0; it < 4u; it++)
        {
            /* Random delta in [1, 2^32). bnBig = n + delta. Always > n, always < 2^curve_bits  */
            /* for both P-256 (n ~= 2^256 - 2^224 - ...) and P-384 (similar margin).            */
            SSF_ASSERT(BN_rand(bnDelta, 32, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 1);
            if (BN_is_zero(bnDelta)) BN_one(bnDelta);
            SSF_ASSERT(BN_add(bnBig, bnOrder, bnDelta) == 1);
            SSF_ASSERT(BN_cmp(bnBig, bnOrder) > 0);
            _ECFromOSSLBN(&kBig, bnBig, c->limbs);

            /* SSF [kBig]G must equal OpenSSL [kBig]G (which internally reduces mod n). */
            SSFECScalarMul(&R, &kBig, &G, curve);
            SSF_ASSERT(EC_POINT_mul(group, osslR, bnBig, NULL, NULL, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);

            /* Sanity: kBig and (kBig mod n) must produce the same point. */
            SSF_ASSERT(BN_mod(bnReduce, bnBig, bnOrder, ctx) == 1);
            SSF_ASSERT(EC_POINT_mul(group, osslT, bnReduce, NULL, NULL, ctx) == 1);
            SSF_ASSERT(_ECPointEqOSSL(&R, osslT, curve, group, ctx) == true);

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
            if (curve == SSF_EC_CURVE_P256)
            {
                SSFECScalarMulBaseP256(&R, &kBig);
                SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
            }
#endif
#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
            if (curve == SSF_EC_CURVE_P384)
            {
                SSFECScalarMulBaseP384(&R, &kBig);
                SSF_ASSERT(_ECPointEqOSSL(&R, osslR, curve, group, ctx) == true);
            }
#endif
        }

        BN_free(bnBig);
        BN_free(bnDelta);
        BN_free(bnReduce);
    }

    BN_free(bnK1); BN_free(bnK2); BN_free(bnOrder);
    EC_POINT_free(osslP); EC_POINT_free(osslQ);
    EC_POINT_free(osslR); EC_POINT_free(osslT);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
}

#endif /* SSF_EC_OSSL_VERIFY */

/* Suppress C6262 (large stack frame). This unit-test entry point intentionally allocates many */
/* curve-state locals across its sub-test blocks; the host test environment has ample stack.   */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6262)
#endif
void SSFECUnitTest(void)
{
#if SSF_EC_OSSL_VERIFY == 1
    /* OpenSSL EC cross-check: ~10 random k per curve exercises every public op against an     */
    /* independent reference. Order matters -- run these first so any disagreement surfaces     */
    /* before the self-consistency tests below.                                                  */
    SSF_UT_PRINTF("--- ssfec OpenSSL cross-check ---\n");
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    _ECVerifyAtCurve(SSF_EC_CURVE_P256, 20u);
#endif
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    _ECVerifyAtCurve(SSF_EC_CURVE_P384, 12u);
#endif
    SSF_UT_PRINTF("--- end OpenSSL cross-check ---\n");
#endif
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    /* ---- P-256: generator is on curve ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);

        SSF_ASSERT(c != NULL);
        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointOnCurve(&G, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointValidate(&G, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointIsIdentity(&G) == false);
    }

    /* ---- P-256: identity handling ---- */
    {
        SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);

        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&O) == true);
    }

    /* ---- P-256: SEC 1 encode/decode roundtrip of generator ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(G2, SSF_EC_MAX_LIMBS);
        uint8_t enc[SSF_EC_MAX_ENCODED_SIZE];
        size_t encLen;

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointEncode(&G, SSF_EC_CURVE_P256, enc, sizeof(enc), &encLen) == true);
        SSF_ASSERT(encLen == 65u);
        SSF_ASSERT(enc[0] == 0x04u);

        SSF_ASSERT(SSFECPointDecode(&G2, SSF_EC_CURVE_P256, enc, encLen) == true);
        {
            SSFBN_DEFINE(x1, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(y1, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(x2, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(y2, SSF_EC_MAX_LIMBS);
            SSF_ASSERT(SSFECPointToAffine(&x1, &y1, &G, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&x2, &y2, &G2, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&x1, &x2) == 0);
            SSF_ASSERT(SSFBNCmp(&y1, &y2) == 0);
        }
    }

    /* ---- P-256: invalid point rejection ---- */
    {
        uint8_t bad[65];
        SSFECPOINT_DEFINE(pt, SSF_EC_MAX_LIMBS);

        /* All zeros (not on curve) */
        memset(bad, 0, sizeof(bad));
        bad[0] = 0x04u;
        SSF_ASSERT(SSFECPointDecode(&pt, SSF_EC_CURVE_P256, bad, 65) == false);

        /* Wrong format byte */
        bad[0] = 0x05u;
        SSF_ASSERT(SSFECPointDecode(&pt, SSF_EC_CURVE_P256, bad, 65) == false);

        /* Wrong length */
        bad[0] = 0x04u;
        SSF_ASSERT(SSFECPointDecode(&pt, SSF_EC_CURVE_P256, bad, 64) == false);
    }

    /* ---- P-256: SEC1 format-specific rejection (compressed/hybrid/infinity) ---- */
    /* SSF only supports the uncompressed format (0x04). Per SEC1 v2 Sec. 2.3.3:                   */
    /*   0x00 = point at infinity (length 1)                                                       */
    /*   0x02 = compressed, even Y    | length 1 + coord_bytes                                    */
    /*   0x03 = compressed, odd  Y    | length 1 + coord_bytes                                    */
    /*   0x04 = uncompressed          | length 1 + 2*coord_bytes -- the only one we support       */
    /*   0x06 = hybrid, even Y        | length 1 + 2*coord_bytes                                  */
    /*   0x07 = hybrid, odd Y         | length 1 + 2*coord_bytes                                  */
    /* All non-0x04 forms must be rejected. Catches a real interop hazard: a peer sending a       */
    /* compressed pubkey would crash or be silently accepted by a lenient decoder.                */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(decoded, SSF_EC_MAX_LIMBS);
        uint8_t enc[65];
        size_t encLen;

        /* Get a valid uncompressed encoding of G to lift X / X||Y from. */
        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointEncode(&G, SSF_EC_CURVE_P256, enc, sizeof(enc), &encLen) == true);
        SSF_ASSERT(encLen == 65u);

        /* (1) Compressed even (0x02 || X, length 33). */
        {
            uint8_t comp[33];
            comp[0] = 0x02u;
            memcpy(&comp[1], &enc[1], c->bytes);
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, comp, sizeof(comp)) == false);
        }

        /* (2) Compressed odd (0x03 || X, length 33). */
        {
            uint8_t comp[33];
            comp[0] = 0x03u;
            memcpy(&comp[1], &enc[1], c->bytes);
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, comp, sizeof(comp)) == false);
        }

        /* (3) Hybrid even (0x06 || X || Y, length 65). Even though X||Y is valid, format reject. */
        {
            uint8_t hyb[65];
            memcpy(hyb, enc, sizeof(hyb));
            hyb[0] = 0x06u;
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, hyb, sizeof(hyb)) == false);
        }

        /* (4) Hybrid odd (0x07 || X || Y, length 65). */
        {
            uint8_t hyb[65];
            memcpy(hyb, enc, sizeof(hyb));
            hyb[0] = 0x07u;
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, hyb, sizeof(hyb)) == false);
        }

        /* (5) Point at infinity (0x00, length 1). SSF should reject the encoding entirely. */
        {
            uint8_t infBuf[1] = { 0x00u };
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, infBuf, 1u) == false);
        }

        /* (6) Spec-conforming compressed-format BUFFER LENGTH but with 0x04 prefix.              */
        /* Length 33 with any prefix (including 0x04) is invalid for uncompressed and unsupported */
        /* for compressed -- must be rejected.                                                     */
        {
            uint8_t comp[33];
            comp[0] = 0x04u;
            memcpy(&comp[1], &enc[1], c->bytes);
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, comp, sizeof(comp)) == false);
        }

        /* (7) Other arbitrary nonsense prefixes (0x01, 0x08, 0xFF) -- all rejected at any size. */
        {
            uint8_t nonsense[65];
            const uint8_t bad_prefixes[] = { 0x01u, 0x08u, 0xFFu };
            size_t pi;
            memcpy(nonsense, enc, sizeof(nonsense));
            for (pi = 0; pi < sizeof(bad_prefixes) / sizeof(bad_prefixes[0]); pi++)
            {
                nonsense[0] = bad_prefixes[pi];
                SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256,
                                            nonsense, sizeof(nonsense)) == false);
            }
        }
    }

    /* ---- P-256: malformed Jacobian Z exercises PointToAffine failure path ---- */
    /* SSFECPointOnCurve / SSFECPointValidate take a fast path when Z == 1 (affine input).      */
    /* The slow path at ssfec.c:706 / 748 calls SSFECPointToAffine, which fails when ModInv(Z,p)*/
    /* fails -- i.e. when Z == 0 (mod p). A non-zero, non-one Z = p produces this. Real callers */
    /* (SSFECPointDecode -> Validate) always pass Z = 1, so the slow-path return-false is       */
    /* otherwise unreached. Confirm the validators correctly reject the malformed input.        */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(badPt, SSF_EC_MAX_LIMBS);

        SSFBNSetUint32(&badPt.x, 1u, c->limbs);
        SSFBNSetUint32(&badPt.y, 1u, c->limbs);
        SSFBNCopy(&badPt.z, &c->p);  /* Z = p => non-zero, non-one, ModInv(Z, p) fails */

        SSF_ASSERT(SSFECPointOnCurve(&badPt, SSF_EC_CURVE_P256) == false);
        SSF_ASSERT(SSFECPointValidate(&badPt, SSF_EC_CURVE_P256) == false);
    }

#if SSF_EC_CONFIG_ENABLE_P384 == 1
    /* ---- P-384: SEC1 format-specific rejection (mirror of P-256) ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(decoded, SSF_EC_MAX_LIMBS);
        uint8_t enc[97];  /* 1 + 2*48 */
        size_t encLen;

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);
        SSF_ASSERT(SSFECPointEncode(&G, SSF_EC_CURVE_P384, enc, sizeof(enc), &encLen) == true);
        SSF_ASSERT(encLen == 97u);

        /* Compressed even/odd (length 49). */
        {
            uint8_t comp[49];
            memcpy(&comp[1], &enc[1], c->bytes);
            comp[0] = 0x02u;
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P384, comp, sizeof(comp)) == false);
            comp[0] = 0x03u;
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P384, comp, sizeof(comp)) == false);
        }

        /* Hybrid even/odd (length 97). */
        {
            uint8_t hyb[97];
            memcpy(hyb, enc, sizeof(hyb));
            hyb[0] = 0x06u;
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P384, hyb, sizeof(hyb)) == false);
            hyb[0] = 0x07u;
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P384, hyb, sizeof(hyb)) == false);
        }

        /* Infinity. */
        {
            uint8_t infBuf[1] = { 0x00u };
            SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P384, infBuf, 1u) == false);
        }
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

    /* ---- P-256: 1 * G = G ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(one, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&one, 1u, c->limbs);
        SSFECScalarMul(&R, &one, &G, SSF_EC_CURVE_P256);

        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &c->gy) == 0);
    }

    /* ---- P-256: G + G = 2 * G consistency ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(sum, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(dbl, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(two, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(sx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(sy, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(dx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(dy, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);

        /* sum = G + G */
        SSFECPointAdd(&sum, &G, &G, SSF_EC_CURVE_P256);

        /* dbl = 2 * G */
        SSFBNSetUint32(&two, 2u, c->limbs);
        SSFECScalarMul(&dbl, &two, &G, SSF_EC_CURVE_P256);

        SSF_ASSERT(SSFECPointToAffine(&sx, &sy, &sum, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&dx, &dy, &dbl, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&sx, &dx) == 0);
        SSF_ASSERT(SSFBNCmp(&sy, &dy) == 0);
    }

    /* ---- P-256: n * G = identity (order verification) ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFECScalarMul(&R, &c->n, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);
    }

    /* ---- P-256: SSFECScalarMul edge cases (window boundaries for windowed impl) ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G,    SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R,    SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Acc,  SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ax, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ay, SSF_EC_MAX_LIMBS);
        uint32_t small_k;

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);

        /* k = 0 -> identity */
        SSFBNSetZero(&k, c->limbs);
        SSFECScalarMul(&R, &k, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);

        /* k = 1 -> G */
        SSFBNSetUint32(&k, 1u, c->limbs);
        SSFECScalarMul(&R, &k, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &c->gy) == 0);

        /* For each small_k in {2, 3, 15, 16, 17, 31, 32, 33}, verify [small_k]G via */
        /* SSFECScalarMul matches the result of small_k repeated SSFECPointAdd ops.  */
        /* These probe across window boundaries (4-bit windows: every 16).            */
        {
            const uint32_t edges[] = { 2u, 3u, 15u, 16u, 17u, 31u, 32u, 33u };
            size_t ei;
            for (ei = 0; ei < sizeof(edges) / sizeof(edges[0]); ei++)
            {
                uint32_t step;
                small_k = edges[ei];

                /* Acc = small_k * G via repeated addition. */
                SSFBNCopy(&Acc.x, &G.x); SSFBNCopy(&Acc.y, &G.y); SSFBNCopy(&Acc.z, &G.z);
                for (step = 1u; step < small_k; step++)
                {
                    SSFECPointAdd(&Acc, &Acc, &G, SSF_EC_CURVE_P256);
                }

                /* R = small_k * G via SSFECScalarMul. */
                SSFBNSetUint32(&k, small_k, c->limbs);
                SSFECScalarMul(&R, &k, &G, SSF_EC_CURVE_P256);

                SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R,   SSF_EC_CURVE_P256) == true);
                SSF_ASSERT(SSFECPointToAffine(&ax, &ay, &Acc, SSF_EC_CURVE_P256) == true);
                SSF_ASSERT(SSFBNCmp(&rx, &ax) == 0);
                SSF_ASSERT(SSFBNCmp(&ry, &ay) == 0);
            }
        }
    }

    /* ---- P-256: G + identity = G ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
        SSFECPointAdd(&R, &G, &O, SSF_EC_CURVE_P256);

        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &c->gy) == 0);
    }

    /* ---- P-256: identity + G = G (z1==0 cascade override) ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
        SSFECPointAdd(&R, &O, &G, SSF_EC_CURVE_P256);

        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &c->gy) == 0);
    }

    /* ---- P-256: identity + identity = identity (both z==0 cascade) ---- */
    {
        SSFECPOINT_DEFINE(O1, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(O2, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);

        SSFECPointSetIdentity(&O1, SSF_EC_CURVE_P256);
        SSFECPointSetIdentity(&O2, SSF_EC_CURVE_P256);
        SSFECPointAdd(&R, &O1, &O2, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);
    }

    /* ---- P-256: G + (-G) = identity (H==0, R!=0 cascade -- P + -Q case) ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(negG, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(negY, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        /* -G = (gx, p - gy, 1) */
        SSFBNSub(&negY, &c->p, &c->gy);
        SSFECPointFromAffine(&negG, &c->gx, &negY, SSF_EC_CURVE_P256);
        SSFECPointAdd(&R, &G, &negG, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);
    }

    /* ---- P-256: G + G = 2G via Add must equal Double(G) (H==0, R==0 cascade) ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaAdd, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaScalar, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(two, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(addX, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(addY, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(scX, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(scY, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFECPointAdd(&viaAdd, &G, &G, SSF_EC_CURVE_P256);

        SSFBNSetUint32(&two, 2u, c->limbs);
        SSFECScalarMul(&viaScalar, &two, &G, SSF_EC_CURVE_P256);

        SSF_ASSERT(SSFECPointToAffine(&addX, &addY, &viaAdd,    SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&scX,  &scY,  &viaScalar, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&addX, &scX) == 0);
        SSF_ASSERT(SSFBNCmp(&addY, &scY) == 0);
    }

    /* ---- P-256: dual scalar mul consistency: u1*G + u2*G = (u1+u2)*G ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R1, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R2, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(u1, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(u2, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(uSum, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(r1x, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(r1y, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(r2x, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(r2y, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&u1, 3u, c->limbs);
        SSFBNSetUint32(&u2, 5u, c->limbs);

        /* R1 = 3*G + 5*G via dual scalar mul */
        SSFECScalarMulDual(&R1, &u1, &G, &u2, &G, SSF_EC_CURVE_P256);

        /* R2 = 8*G via scalar mul */
        SSFBNSetUint32(&uSum, 8u, c->limbs);
        SSFECScalarMul(&R2, &uSum, &G, SSF_EC_CURVE_P256);

        SSF_ASSERT(SSFECPointToAffine(&r1x, &r1y, &R1, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&r2x, &r2y, &R2, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&r1x, &r2x) == 0);
        SSF_ASSERT(SSFBNCmp(&r1y, &r2y) == 0);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if SSF_EC_CONFIG_ENABLE_P384 == 1
    /* ---- P-384: generator is on curve ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);

        SSF_ASSERT(c != NULL);
        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);
        SSF_ASSERT(SSFECPointOnCurve(&G, SSF_EC_CURVE_P384) == true);
        SSF_ASSERT(SSFECPointValidate(&G, SSF_EC_CURVE_P384) == true);
    }

    /* ---- P-384: 1 * G = G ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(one, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);
        SSFBNSetUint32(&one, 1u, c->limbs);
        SSFECScalarMul(&R, &one, &G, SSF_EC_CURVE_P384);

        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P384) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &c->gy) == 0);
    }

    /* ---- P-384: n * G = identity ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);
        SSFECScalarMul(&R, &c->n, &G, SSF_EC_CURVE_P384);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);
    }

    /* ---- NIST KAT: P-384 [d]G from RFC 6979 Sec. A.2.6 (mirror of the P-256 KAT) ---- */
    {
        static const uint8_t d_bytes[] = {
            0x6Bu, 0x9Du, 0x3Du, 0xADu, 0x2Eu, 0x1Bu, 0x8Cu, 0x1Cu,
            0x05u, 0xB1u, 0x98u, 0x75u, 0xB6u, 0x65u, 0x9Fu, 0x4Du,
            0xE2u, 0x3Cu, 0x3Bu, 0x66u, 0x7Bu, 0xF2u, 0x97u, 0xBAu,
            0x9Au, 0xA4u, 0x77u, 0x40u, 0x78u, 0x71u, 0x37u, 0xD8u,
            0x96u, 0xD5u, 0x72u, 0x4Eu, 0x4Cu, 0x70u, 0xA8u, 0x25u,
            0xF8u, 0x72u, 0xC9u, 0xEAu, 0x60u, 0xD2u, 0xEDu, 0xF5u
        };
        static const uint8_t expected_x[] = {
            0xECu, 0x3Au, 0x4Eu, 0x41u, 0x5Bu, 0x4Eu, 0x19u, 0xA4u,
            0x56u, 0x86u, 0x18u, 0x02u, 0x9Fu, 0x42u, 0x7Fu, 0xA5u,
            0xDAu, 0x9Au, 0x8Bu, 0xC4u, 0xAEu, 0x92u, 0xE0u, 0x2Eu,
            0x06u, 0xAAu, 0xE5u, 0x28u, 0x6Bu, 0x30u, 0x0Cu, 0x64u,
            0xDEu, 0xF8u, 0xF0u, 0xEAu, 0x90u, 0x55u, 0x86u, 0x60u,
            0x64u, 0xA2u, 0x54u, 0x51u, 0x54u, 0x80u, 0xBCu, 0x13u
        };
        static const uint8_t expected_y[] = {
            0x80u, 0x15u, 0xD9u, 0xB7u, 0x2Du, 0x7Du, 0x57u, 0x24u,
            0x4Eu, 0xA8u, 0xEFu, 0x9Au, 0xC0u, 0xC6u, 0x21u, 0x89u,
            0x67u, 0x08u, 0xA5u, 0x93u, 0x67u, 0xF9u, 0xDFu, 0xB9u,
            0xF5u, 0x4Cu, 0xA8u, 0x4Bu, 0x3Fu, 0x1Cu, 0x9Du, 0xB1u,
            0x28u, 0x8Bu, 0x23u, 0x1Cu, 0x3Au, 0xE0u, 0xD4u, 0xFEu,
            0x73u, 0x44u, 0xFDu, 0x25u, 0x33u, 0x26u, 0x47u, 0x20u
        };
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(qx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(qy, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(expx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(expy, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);
        SSF_ASSERT(SSFBNFromBytes(&d,    d_bytes,    sizeof(d_bytes),    c->limbs) == true);
        SSF_ASSERT(SSFBNFromBytes(&expx, expected_x, sizeof(expected_x), c->limbs) == true);
        SSF_ASSERT(SSFBNFromBytes(&expy, expected_y, sizeof(expected_y), c->limbs) == true);

        SSFECScalarMul(&Q, &d, &G, SSF_EC_CURVE_P384);
        SSF_ASSERT(SSFECPointToAffine(&qx, &qy, &Q, SSF_EC_CURVE_P384) == true);
        SSF_ASSERT(SSFBNCmp(&qx, &expx) == 0);
        SSF_ASSERT(SSFBNCmp(&qy, &expy) == 0);

#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
        SSFECScalarMulBaseP384(&Q, &d);
        SSF_ASSERT(SSFECPointToAffine(&qx, &qy, &Q, SSF_EC_CURVE_P384) == true);
        SSF_ASSERT(SSFBNCmp(&qx, &expx) == 0);
        SSF_ASSERT(SSFBNCmp(&qy, &expy) == 0);
#endif
    }

    /* ---- NIST PKV-style negative tests for P-384 (mirror of P-256 edge cases) ---- */
    /* Failure modes from FIPS 186-4 PKV: (1) Q_x or Q_y out of range; (2) point not on curve. */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
        SSFECPOINT_DEFINE(badPt, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(decoded, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(badY, SSF_EC_MAX_LIMBS);
        uint8_t bad[97];  /* 1 + 2*48 for P-384 */

        /* PKV failure (2): off-curve via (G.x, G.y + 1). */
        badY.len = c->limbs;
        SSFBNCopy(&badY, &c->gy);
        (void)SSFBNAddUint32(&badY, &badY, 1u);
        SSFBNCopy(&badPt.x, &c->gx);
        SSFBNCopy(&badPt.y, &badY);
        SSFBNSetOne(&badPt.z, c->limbs);
        SSF_ASSERT(SSFECPointOnCurve(&badPt, SSF_EC_CURVE_P384) == false);
        SSF_ASSERT(SSFECPointValidate(&badPt, SSF_EC_CURVE_P384) == false);

        /* Same via SEC1 decode. */
        bad[0] = 0x04u;
        SSF_ASSERT(SSFBNToBytes(&c->gx, &bad[1],             c->bytes) == true);
        SSF_ASSERT(SSFBNToBytes(&badY,  &bad[1u + c->bytes], c->bytes) == true);
        SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P384, bad, sizeof(bad)) == false);

        /* PKV failure (1): Q_x = p (out of range). */
        SSFBNCopy(&badPt.x, &c->p);
        SSFBNCopy(&badPt.y, &c->gy);
        SSFBNSetOne(&badPt.z, c->limbs);
        SSF_ASSERT(SSFECPointValidate(&badPt, SSF_EC_CURVE_P384) == false);
        SSF_ASSERT(SSFBNToBytes(&c->p,  &bad[1],             c->bytes) == true);
        SSF_ASSERT(SSFBNToBytes(&c->gy, &bad[1u + c->bytes], c->bytes) == true);
        SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P384, bad, sizeof(bad)) == false);

        /* PKV failure (1): Q_y = p (out of range). */
        SSFBNCopy(&badPt.x, &c->gx);
        SSFBNCopy(&badPt.y, &c->p);
        SSFBNSetOne(&badPt.z, c->limbs);
        SSF_ASSERT(SSFECPointValidate(&badPt, SSF_EC_CURVE_P384) == false);
        SSF_ASSERT(SSFBNToBytes(&c->gx, &bad[1],             c->bytes) == true);
        SSF_ASSERT(SSFBNToBytes(&c->p,  &bad[1u + c->bytes], c->bytes) == true);
        SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P384, bad, sizeof(bad)) == false);

        /* PKV failure (2): all-zeros (0, 0) -- not on curve. */
        memset(bad, 0, sizeof(bad));
        bad[0] = 0x04u;
        SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P384, bad, sizeof(bad)) == false);

        /* PKV positive: the curve generator must validate. */
        SSFBNCopy(&badPt.x, &c->gx);
        SSFBNCopy(&badPt.y, &c->gy);
        SSFBNSetOne(&badPt.z, c->limbs);
        SSF_ASSERT(SSFECPointValidate(&badPt, SSF_EC_CURVE_P384) == true);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

    /* ====================================================================================== */
    /* === Algebraic identity stress tests ====================================================*/
    /* ====================================================================================== */
    /* These are intrinsic group properties that must hold for any valid EC implementation:    */
    /*   commutativity:    P + Q == Q + P                                                       */
    /*   associativity:    (P + Q) + R == P + (Q + R)                                           */
    /*   scalar additivity: [k1]P + [k2]P == [k1+k2]P                                          */
    /*   distributivity:   [k]P + [k]Q == [k](P + Q)                                            */
    /* High iter counts catch subtle accumulator/aliasing bugs that the existing 10-iter tests */
    /* might miss. All checks are self-consistency -- no external reference needed.             */

#if SSF_EC_CONFIG_ENABLE_P256 == 1
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G,  SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(P,  SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Q,  SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R,  SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(L,  SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(M,  SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k1, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k2, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(kSum, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(lx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ly, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(mx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(my, SSF_EC_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x77u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));
        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);

        /* Commutativity: P + Q == Q + P (100 random pairs). */
        for (i = 0; i < 100u; i++)
        {
            SSFBNRandomBelow(&k1, &c->n, &prng);
            SSFBNRandomBelow(&k2, &c->n, &prng);
            SSFECScalarMul(&P, &k1, &G, SSF_EC_CURVE_P256);
            SSFECScalarMul(&Q, &k2, &G, SSF_EC_CURVE_P256);

            SSFECPointAdd(&L, &P, &Q, SSF_EC_CURVE_P256);
            SSFECPointAdd(&M, &Q, &P, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&lx, &ly, &L, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&mx, &my, &M, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&lx, &mx) == 0);
            SSF_ASSERT(SSFBNCmp(&ly, &my) == 0);
        }

        /* Associativity: (P + Q) + R == P + (Q + R) (50 random triples). */
        for (i = 0; i < 50u; i++)
        {
            SSFBNRandomBelow(&k1, &c->n, &prng);
            SSFBNRandomBelow(&k2, &c->n, &prng);
            SSFECScalarMul(&P, &k1, &G, SSF_EC_CURVE_P256);
            SSFECScalarMul(&Q, &k2, &G, SSF_EC_CURVE_P256);
            SSFBNRandomBelow(&k1, &c->n, &prng);
            SSFECScalarMul(&R, &k1, &G, SSF_EC_CURVE_P256);

            /* (P + Q) + R */
            SSFECPointAdd(&L, &P, &Q, SSF_EC_CURVE_P256);
            SSFECPointAdd(&L, &L, &R, SSF_EC_CURVE_P256);
            /* P + (Q + R) */
            SSFECPointAdd(&M, &Q, &R, SSF_EC_CURVE_P256);
            SSFECPointAdd(&M, &P, &M, SSF_EC_CURVE_P256);

            SSF_ASSERT(SSFECPointToAffine(&lx, &ly, &L, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&mx, &my, &M, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&lx, &mx) == 0);
            SSF_ASSERT(SSFBNCmp(&ly, &my) == 0);
        }

        /* Scalar additivity: [k1]G + [k2]G == [k1+k2 mod n]G (50 iters). */
        for (i = 0; i < 50u; i++)
        {
            SSFBNRandomBelow(&k1, &c->n, &prng);
            SSFBNRandomBelow(&k2, &c->n, &prng);
            SSFBNModAdd(&kSum, &k1, &k2, &c->n);  /* CT-correct (k1 + k2) mod n */

            SSFECScalarMul(&P, &k1, &G, SSF_EC_CURVE_P256);
            SSFECScalarMul(&Q, &k2, &G, SSF_EC_CURVE_P256);
            SSFECPointAdd(&L, &P, &Q, SSF_EC_CURVE_P256);
            SSFECScalarMul(&M, &kSum, &G, SSF_EC_CURVE_P256);

            /* If [k1+k2]G is identity (kSum happened to be 0), so should L. */
            if (SSFECPointIsIdentity(&M))
            {
                SSF_ASSERT(SSFECPointIsIdentity(&L) == true);
            }
            else
            {
                SSF_ASSERT(SSFECPointToAffine(&lx, &ly, &L, SSF_EC_CURVE_P256) == true);
                SSF_ASSERT(SSFECPointToAffine(&mx, &my, &M, SSF_EC_CURVE_P256) == true);
                SSF_ASSERT(SSFBNCmp(&lx, &mx) == 0);
                SSF_ASSERT(SSFBNCmp(&ly, &my) == 0);
            }
        }

        /* Distributivity: [k](P + Q) == [k]P + [k]Q (30 iters; uses 2 base points). */
        for (i = 0; i < 30u; i++)
        {
            SSFECPOINT_DEFINE(Pin, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(Qin, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(Sum, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(kx, SSF_EC_MAX_LIMBS);

            SSFBNRandomBelow(&kx, &c->n, &prng);
            SSFECScalarMul(&Pin, &kx, &G, SSF_EC_CURVE_P256);
            SSFBNRandomBelow(&kx, &c->n, &prng);
            SSFECScalarMul(&Qin, &kx, &G, SSF_EC_CURVE_P256);
            SSFBNRandomBelow(&kx, &c->n, &prng);  /* the multiplier k */

            /* L = [k]P + [k]Q */
            SSFECScalarMul(&P, &kx, &Pin, SSF_EC_CURVE_P256);
            SSFECScalarMul(&Q, &kx, &Qin, SSF_EC_CURVE_P256);
            SSFECPointAdd(&L, &P, &Q, SSF_EC_CURVE_P256);
            /* M = [k](P + Q) */
            SSFECPointAdd(&Sum, &Pin, &Qin, SSF_EC_CURVE_P256);
            SSFECScalarMul(&M, &kx, &Sum, SSF_EC_CURVE_P256);

            if (SSFECPointIsIdentity(&L))
            {
                SSF_ASSERT(SSFECPointIsIdentity(&M) == true);
            }
            else
            {
                SSF_ASSERT(SSFECPointToAffine(&lx, &ly, &L, SSF_EC_CURVE_P256) == true);
                SSF_ASSERT(SSFECPointToAffine(&mx, &my, &M, SSF_EC_CURVE_P256) == true);
                SSF_ASSERT(SSFBNCmp(&lx, &mx) == 0);
                SSF_ASSERT(SSFBNCmp(&ly, &my) == 0);
            }
        }

        SSFPRNGDeInitContext(&prng);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if SSF_EC_CONFIG_ENABLE_P384 == 1
    /* Same identities for P-384 with reduced iter counts. */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
        SSFECPOINT_DEFINE(G,  SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(P,  SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Q,  SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(L,  SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(M,  SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k1, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k2, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(kSum, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(lx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ly, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(mx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(my, SSF_EC_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x99u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));
        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);

        /* Commutativity: 50 iters. */
        for (i = 0; i < 50u; i++)
        {
            SSFBNRandomBelow(&k1, &c->n, &prng);
            SSFBNRandomBelow(&k2, &c->n, &prng);
            SSFECScalarMul(&P, &k1, &G, SSF_EC_CURVE_P384);
            SSFECScalarMul(&Q, &k2, &G, SSF_EC_CURVE_P384);
            SSFECPointAdd(&L, &P, &Q, SSF_EC_CURVE_P384);
            SSFECPointAdd(&M, &Q, &P, SSF_EC_CURVE_P384);
            SSF_ASSERT(SSFECPointToAffine(&lx, &ly, &L, SSF_EC_CURVE_P384) == true);
            SSF_ASSERT(SSFECPointToAffine(&mx, &my, &M, SSF_EC_CURVE_P384) == true);
            SSF_ASSERT(SSFBNCmp(&lx, &mx) == 0);
            SSF_ASSERT(SSFBNCmp(&ly, &my) == 0);
        }

        /* Scalar additivity: 25 iters (associativity skipped -- covered amply by P-256). */
        for (i = 0; i < 25u; i++)
        {
            SSFBNRandomBelow(&k1, &c->n, &prng);
            SSFBNRandomBelow(&k2, &c->n, &prng);
            SSFBNModAdd(&kSum, &k1, &k2, &c->n);  /* CT-correct (k1 + k2) mod n */

            SSFECScalarMul(&P, &k1, &G, SSF_EC_CURVE_P384);
            SSFECScalarMul(&Q, &k2, &G, SSF_EC_CURVE_P384);
            SSFECPointAdd(&L, &P, &Q, SSF_EC_CURVE_P384);
            SSFECScalarMul(&M, &kSum, &G, SSF_EC_CURVE_P384);

            if (SSFECPointIsIdentity(&M))
            {
                SSF_ASSERT(SSFECPointIsIdentity(&L) == true);
            }
            else
            {
                SSF_ASSERT(SSFECPointToAffine(&lx, &ly, &L, SSF_EC_CURVE_P384) == true);
                SSF_ASSERT(SSFECPointToAffine(&mx, &my, &M, SSF_EC_CURVE_P384) == true);
                SSF_ASSERT(SSFBNCmp(&lx, &mx) == 0);
                SSF_ASSERT(SSFBNCmp(&ly, &my) == 0);
            }
        }

        SSFPRNGDeInitContext(&prng);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
    /* ---- Fixed-base P-256: SSFECScalarMulBaseP256 must agree with SSFECScalarMul ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaBase, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaLadder, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(bx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(by, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(lx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ly, SSF_EC_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x33u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));
        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);

        /* k = 1: result must equal G. */
        SSFBNSetUint32(&k, 1u, c->limbs);
        SSFECScalarMulBaseP256(&viaBase, &k);
        SSF_ASSERT(SSFECPointToAffine(&bx, &by, &viaBase, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&bx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&by, &c->gy) == 0);

        /* k = 2: result must equal 2*G via SSFECScalarMul. */
        SSFBNSetUint32(&k, 2u, c->limbs);
        SSFECScalarMulBaseP256(&viaBase, &k);
        SSFECScalarMul(&viaLadder, &k, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&bx, &by, &viaBase,   SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&lx, &ly, &viaLadder, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&bx, &lx) == 0);
        SSF_ASSERT(SSFBNCmp(&by, &ly) == 0);

        /* Random k parity sweep -- fixed-base must match the ladder for arbitrary scalars. */
        for (i = 0; i < 32u; i++)
        {
            SSFBNRandomBelow(&k, &c->n, &prng);

            SSFECScalarMulBaseP256(&viaBase, &k);
            SSFECScalarMul(&viaLadder, &k, &G, SSF_EC_CURVE_P256);

            SSF_ASSERT(SSFECPointToAffine(&bx, &by, &viaBase,   SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&lx, &ly, &viaLadder, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&bx, &lx) == 0);
            SSF_ASSERT(SSFBNCmp(&by, &ly) == 0);
        }

        SSFPRNGDeInitContext(&prng);
    }
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 */

#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
    /* ---- Fixed-base P-384: SSFECScalarMulBaseP384 must agree with SSFECScalarMul ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaBase, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaLadder, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(bx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(by, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(lx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ly, SSF_EC_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x55u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));
        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);

        SSFBNSetUint32(&k, 1u, c->limbs);
        SSFECScalarMulBaseP384(&viaBase, &k);
        SSF_ASSERT(SSFECPointToAffine(&bx, &by, &viaBase, SSF_EC_CURVE_P384) == true);
        SSF_ASSERT(SSFBNCmp(&bx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&by, &c->gy) == 0);

        SSFBNSetUint32(&k, 2u, c->limbs);
        SSFECScalarMulBaseP384(&viaBase, &k);
        SSFECScalarMul(&viaLadder, &k, &G, SSF_EC_CURVE_P384);
        SSF_ASSERT(SSFECPointToAffine(&bx, &by, &viaBase,   SSF_EC_CURVE_P384) == true);
        SSF_ASSERT(SSFECPointToAffine(&lx, &ly, &viaLadder, SSF_EC_CURVE_P384) == true);
        SSF_ASSERT(SSFBNCmp(&bx, &lx) == 0);
        SSF_ASSERT(SSFBNCmp(&by, &ly) == 0);

        for (i = 0; i < 16u; i++)
        {
            SSFBNRandomBelow(&k, &c->n, &prng);

            SSFECScalarMulBaseP384(&viaBase, &k);
            SSFECScalarMul(&viaLadder, &k, &G, SSF_EC_CURVE_P384);

            SSF_ASSERT(SSFECPointToAffine(&bx, &by, &viaBase,   SSF_EC_CURVE_P384) == true);
            SSF_ASSERT(SSFECPointToAffine(&lx, &ly, &viaLadder, SSF_EC_CURVE_P384) == true);
            SSF_ASSERT(SSFBNCmp(&bx, &lx) == 0);
            SSF_ASSERT(SSFBNCmp(&by, &ly) == 0);
        }

        SSFPRNGDeInitContext(&prng);
    }
#endif /* SSF_EC_CONFIG_FIXED_BASE_P384 */

#if (SSF_EC_CONFIG_FIXED_BASE_P256 == 1) || (SSF_EC_CONFIG_FIXED_BASE_P384 == 1)
    /* ---- SSFECScalarMulDualBase parity vs SSFECScalarMulDual (Shamir's trick reference) ---- */
    {
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x77u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
        {
            const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
            SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(viaShamir, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(viaDualBase, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(u1, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(u2, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(sx, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(sy, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(dx, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(dy, SSF_EC_MAX_LIMBS);

            SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
            SSFBNSetUint32(&d, 0x12345678u, c->limbs);
            SSFECScalarMul(&Q, &d, &G, SSF_EC_CURVE_P256);

            for (i = 0; i < 16u; i++)
            {
                SSFBNRandomBelow(&u1, &c->n, &prng);
                SSFBNRandomBelow(&u2, &c->n, &prng);

                SSFECScalarMulDual(&viaShamir, &u1, &G, &u2, &Q, SSF_EC_CURVE_P256);
                SSFECScalarMulDualBase(&viaDualBase, &u1, &u2, &Q, SSF_EC_CURVE_P256);

                SSF_ASSERT(SSFECPointToAffine(&sx, &sy, &viaShamir,   SSF_EC_CURVE_P256) == true);
                SSF_ASSERT(SSFECPointToAffine(&dx, &dy, &viaDualBase, SSF_EC_CURVE_P256) == true);
                SSF_ASSERT(SSFBNCmp(&sx, &dx) == 0);
                SSF_ASSERT(SSFBNCmp(&sy, &dy) == 0);
            }
        }
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 */

#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
        {
            const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
            SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(viaShamir, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(viaDualBase, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(u1, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(u2, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(sx, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(sy, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(dx, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(dy, SSF_EC_MAX_LIMBS);

            SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);
            SSFBNSetUint32(&d, 0x87654321u, c->limbs);
            SSFECScalarMul(&Q, &d, &G, SSF_EC_CURVE_P384);

            for (i = 0; i < 8u; i++)
            {
                SSFBNRandomBelow(&u1, &c->n, &prng);
                SSFBNRandomBelow(&u2, &c->n, &prng);

                SSFECScalarMulDual(&viaShamir, &u1, &G, &u2, &Q, SSF_EC_CURVE_P384);
                SSFECScalarMulDualBase(&viaDualBase, &u1, &u2, &Q, SSF_EC_CURVE_P384);

                SSF_ASSERT(SSFECPointToAffine(&sx, &sy, &viaShamir,   SSF_EC_CURVE_P384) == true);
                SSF_ASSERT(SSFECPointToAffine(&dx, &dy, &viaDualBase, SSF_EC_CURVE_P384) == true);
                SSF_ASSERT(SSFBNCmp(&sx, &dx) == 0);
                SSF_ASSERT(SSFBNCmp(&sy, &dy) == 0);
            }
        }
#endif /* SSF_EC_CONFIG_FIXED_BASE_P384 */

        SSFPRNGDeInitContext(&prng);
    }
#endif /* fixed-base configured */

#if SSF_EC_CONFIG_ENABLE_P256 == 1
    /* ---- Mixed (Jacobian + affine) addition: must equal full Jacobian add when q has Z=1 --- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G,        SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(P,        SSF_EC_MAX_LIMBS);  /* Jacobian (Z != 1) */
        SSFECPOINT_DEFINE(Q,        SSF_EC_MAX_LIMBS);  /* affine (Z == 1) */
        SSFECPOINT_DEFINE(viaMixed, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaFull,  SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(scalar,        SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(mx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(my, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(fx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(fy, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);

        /* P = [3]G -- has Z != 1 in Jacobian form. */
        SSFBNSetUint32(&scalar, 3u, c->limbs);
        SSFECScalarMul(&P, &scalar, &G, SSF_EC_CURVE_P256);

        /* Q = G -- affine (Z = 1) by construction of SSFECPointFromAffine. */
        SSFBNCopy(&Q.x, &G.x); SSFBNCopy(&Q.y, &G.y); SSFBNCopy(&Q.z, &G.z);

        _SSFECPointAddMixedForTest(&viaMixed, &P, &Q, SSF_EC_CURVE_P256);
        SSFECPointAdd(&viaFull, &P, &Q, SSF_EC_CURVE_P256);

        SSF_ASSERT(SSFECPointToAffine(&mx, &my, &viaMixed, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&fx, &fy, &viaFull,  SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&mx, &fx) == 0);
        SSF_ASSERT(SSFBNCmp(&my, &fy) == 0);

        /* Mixed-add edge: p is identity, result must be q (= G). */
        {
            SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
            SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
            _SSFECPointAddMixedForTest(&viaMixed, &O, &Q, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&mx, &my, &viaMixed, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&mx, &c->gx) == 0);
            SSF_ASSERT(SSFBNCmp(&my, &c->gy) == 0);
        }

        /* Mixed-add edge: q is identity (Z=0), result must be p. */
        {
            SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
            SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
            _SSFECPointAddMixedForTest(&viaMixed, &P, &O, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&mx, &my, &viaMixed, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&fx, &fy, &P,        SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&mx, &fx) == 0);
            SSF_ASSERT(SSFBNCmp(&my, &fy) == 0);
        }

        /* Mixed-add edge: p == q (with q affine). Result = 2*p (= 2*G when both = G affine). */
        /* Use Q for both -- Q is affine. */
        _SSFECPointAddMixedForTest(&viaMixed, &Q, &Q, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&scalar, 2u, c->limbs);
        SSFECScalarMul(&viaFull, &scalar, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&mx, &my, &viaMixed, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&fx, &fy, &viaFull,  SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&mx, &fx) == 0);
        SSF_ASSERT(SSFBNCmp(&my, &fy) == 0);

        /* Mixed-add edge: p == -q (with q affine, p = -q). Result = identity. */
        {
            SSFECPOINT_DEFINE(negG, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(negY, SSF_EC_MAX_LIMBS);
            SSFBNSub(&negY, &c->p, &c->gy);
            SSFECPointFromAffine(&negG, &c->gx, &negY, SSF_EC_CURVE_P256);
            _SSFECPointAddMixedForTest(&viaMixed, &negG, &Q, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointIsIdentity(&viaMixed) == true);
        }

        /* ---- _SSFECPointAddMixedNoDouble: must agree with mixed-add for P != Q ---- */

        /* General case: same result as full mixed-add when P != Q. */
        _SSFECPointAddMixedNoDoubleForTest(&viaMixed, &P, &Q, SSF_EC_CURVE_P256);
        SSFECPointAdd(&viaFull, &P, &Q, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&mx, &my, &viaMixed, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&fx, &fy, &viaFull,  SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&mx, &fx) == 0);
        SSF_ASSERT(SSFBNCmp(&my, &fy) == 0);

        /* P is identity -> result is Q. */
        {
            SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
            SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
            _SSFECPointAddMixedNoDoubleForTest(&viaMixed, &O, &Q, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&mx, &my, &viaMixed, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&mx, &c->gx) == 0);
            SSF_ASSERT(SSFBNCmp(&my, &c->gy) == 0);
        }

        /* Q is identity -> result is P. */
        {
            SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
            SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
            _SSFECPointAddMixedNoDoubleForTest(&viaMixed, &P, &O, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&mx, &my, &viaMixed, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&fx, &fy, &P,        SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&mx, &fx) == 0);
            SSF_ASSERT(SSFBNCmp(&my, &fy) == 0);
        }

        /* P == -Q -> identity. (Q is affine G; build -G in Jacobian and add.) */
        {
            SSFECPOINT_DEFINE(negG, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(negY, SSF_EC_MAX_LIMBS);
            SSFBNSub(&negY, &c->p, &c->gy);
            SSFECPointFromAffine(&negG, &c->gx, &negY, SSF_EC_CURVE_P256);
            _SSFECPointAddMixedNoDoubleForTest(&viaMixed, &negG, &Q, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointIsIdentity(&viaMixed) == true);
        }
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if SSF_EC_CONFIG_ENABLE_P256 == 1
#if (SSF_EC_CONFIG_FIXED_BASE_P256 == 1) || (SSF_EC_CONFIG_FIXED_BASE_P384 == 1)
    /* ---- Variable-time wNAF scalar mul: must agree with constant-time SSFECScalarMul ----    */
    /* _SSFECScalarMulVTwNAFForTest is only compiled when at least one FIXED_BASE_* flag is set */
    /* (it lives in the same #if block as the comb-table machinery in ssfec.c).                 */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaCT, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaWNAF, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(cx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(cy, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(wx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(wy, SSF_EC_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0xCCu ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&d, 0xDEADBEEFu, c->limbs);
        SSFECScalarMul(&Q, &d, &G, SSF_EC_CURVE_P256);

        /* k = 0 -> identity */
        SSFBNSetZero(&k, c->limbs);
        _SSFECScalarMulVTwNAFForTest(&viaWNAF, &k, &Q, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&viaWNAF) == true);

        /* k = 1 -> Q */
        SSFBNSetUint32(&k, 1u, c->limbs);
        _SSFECScalarMulVTwNAFForTest(&viaWNAF, &k, &Q, SSF_EC_CURVE_P256);
        SSFECScalarMul(&viaCT, &k, &Q, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&cx, &cy, &viaCT,   SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&wx, &wy, &viaWNAF, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&cx, &wx) == 0);
        SSF_ASSERT(SSFBNCmp(&cy, &wy) == 0);

        /* Edge values that exercise wNAF window boundaries. */
        {
            const uint32_t edges[] = { 2u, 3u, 15u, 16u, 17u, 31u, 32u, 33u, 0xDEADBEEFu };
            size_t ei;
            for (ei = 0; ei < sizeof(edges) / sizeof(edges[0]); ei++)
            {
                SSFBNSetUint32(&k, edges[ei], c->limbs);
                _SSFECScalarMulVTwNAFForTest(&viaWNAF, &k, &Q, SSF_EC_CURVE_P256);
                SSFECScalarMul(&viaCT,   &k, &Q, SSF_EC_CURVE_P256);
                SSF_ASSERT(SSFECPointToAffine(&cx, &cy, &viaCT,   SSF_EC_CURVE_P256) == true);
                SSF_ASSERT(SSFECPointToAffine(&wx, &wy, &viaWNAF, SSF_EC_CURVE_P256) == true);
                SSF_ASSERT(SSFBNCmp(&cx, &wx) == 0);
                SSF_ASSERT(SSFBNCmp(&cy, &wy) == 0);
            }
        }

        /* Random parity sweep -- Q is Jacobian (not Z=1). */
        for (i = 0; i < 16u; i++)
        {
            SSFBNRandomBelow(&k, &c->n, &prng);
            _SSFECScalarMulVTwNAFForTest(&viaWNAF, &k, &Q, SSF_EC_CURVE_P256);
            SSFECScalarMul(&viaCT, &k, &Q, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&cx, &cy, &viaCT,   SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&wx, &wy, &viaWNAF, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&cx, &wx) == 0);
            SSF_ASSERT(SSFBNCmp(&cy, &wy) == 0);
        }

        /* Affine-input sweep -- G is Z=1 (built from c->gx, c->gy). Hits the wNAF affine    */
        /* fast path (table[0] is Z=1, so adds of +/-table[0] use mixed-coordinate addition).*/
        for (i = 0; i < 8u; i++)
        {
            SSFBNRandomBelow(&k, &c->n, &prng);
            _SSFECScalarMulVTwNAFForTest(&viaWNAF, &k, &G, SSF_EC_CURVE_P256);
            SSFECScalarMul(&viaCT, &k, &G, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&cx, &cy, &viaCT,   SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&wx, &wy, &viaWNAF, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&cx, &wx) == 0);
            SSF_ASSERT(SSFBNCmp(&cy, &wy) == 0);
        }

        SSFPRNGDeInitContext(&prng);
    }
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 || SSF_EC_CONFIG_FIXED_BASE_P384 */

    /* ---- Public SSFECPointAdd: results must match for any combination of Z=1 / Jacobian ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G,    SSF_EC_MAX_LIMBS); /* affine (Z=1)   */
        SSFECPOINT_DEFINE(Pjac, SSF_EC_MAX_LIMBS); /* Jacobian (Z!=1) */
        SSFECPOINT_DEFINE(R,    SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Rref, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(refx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(refy, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&d, 3u, c->limbs);
        SSFECScalarMul(&Pjac, &d, &G, SSF_EC_CURVE_P256);

        /* q affine: Pjac + G should equal 4*G. */
        SSFBNSetUint32(&d, 4u, c->limbs);
        SSFECScalarMul(&Rref, &d, &G, SSF_EC_CURVE_P256);
        SSFECPointAdd(&R, &Pjac, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx,   &ry,   &R,    SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&refx, &refy, &Rref, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &refx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &refy) == 0);

        /* p affine (and commutativity): G + Pjac = 4*G. */
        SSFECPointAdd(&R, &G, &Pjac, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &refx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &refy) == 0);

        /* Both affine: G + G = 2*G. */
        SSFBNSetUint32(&d, 2u, c->limbs);
        SSFECScalarMul(&Rref, &d, &G, SSF_EC_CURVE_P256);
        SSFECPointAdd(&R, &G, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx,   &ry,   &R,    SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&refx, &refy, &Rref, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &refx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &refy) == 0);

        /* Both Jacobian: Pjac + Pjac = 6*G (no fast path). */
        SSFBNSetUint32(&d, 6u, c->limbs);
        SSFECScalarMul(&Rref, &d, &G, SSF_EC_CURVE_P256);
        SSFECPointAdd(&R, &Pjac, &Pjac, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx,   &ry,   &R,    SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&refx, &refy, &Rref, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &refx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &refy) == 0);
    }

    /* ---- (Gap 1) Aliasing: SSFECPointAdd and SSFECScalarMul must work with output==input ---- */
    /* The internal helpers document "r may alias p or q" but the contract was never explicitly  */
    /* tested. These cases would catch a class of mid-computation overwrite bugs that pass all   */
    /* non-aliased tests.                                                                        */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G,    SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(P,    SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Q,    SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Rref, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(refx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(refy, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&d, 3u, c->limbs);
        SSFECScalarMul(&P, &d, &G, SSF_EC_CURVE_P256);  /* P = 3G (Jacobian) */
        SSFBNSetUint32(&d, 5u, c->limbs);
        SSFECScalarMul(&Q, &d, &G, SSF_EC_CURVE_P256);  /* Q = 5G (Jacobian) */
        SSFBNSetUint32(&d, 8u, c->limbs);
        SSFECScalarMul(&Rref, &d, &G, SSF_EC_CURVE_P256);  /* Rref = 8G */
        SSF_ASSERT(SSFECPointToAffine(&refx, &refy, &Rref, SSF_EC_CURVE_P256) == true);

        /* Case 1a: SSFECPointAdd(&P, &P, &Q) -- output aliases first input. */
        {
            SSFECPOINT_DEFINE(Plocal, SSF_EC_MAX_LIMBS);
            SSFBNCopy(&Plocal.x, &P.x); SSFBNCopy(&Plocal.y, &P.y); SSFBNCopy(&Plocal.z, &P.z);
            SSFECPointAdd(&Plocal, &Plocal, &Q, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &Plocal, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&rx, &refx) == 0);
            SSF_ASSERT(SSFBNCmp(&ry, &refy) == 0);
        }

        /* Case 1b: SSFECPointAdd(&Q, &P, &Q) -- output aliases second input. */
        {
            SSFECPOINT_DEFINE(Qlocal, SSF_EC_MAX_LIMBS);
            SSFBNCopy(&Qlocal.x, &Q.x); SSFBNCopy(&Qlocal.y, &Q.y); SSFBNCopy(&Qlocal.z, &Q.z);
            SSFECPointAdd(&Qlocal, &P, &Qlocal, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &Qlocal, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&rx, &refx) == 0);
            SSF_ASSERT(SSFBNCmp(&ry, &refy) == 0);
        }

        /* Case 1c: SSFECPointAdd(&P, &P, &P) -- both inputs aliased to output (P+P=2P=6G). */
        {
            SSFECPOINT_DEFINE(Plocal, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(Rref6, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(refx6, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(refy6, SSF_EC_MAX_LIMBS);
            SSFBNCopy(&Plocal.x, &P.x); SSFBNCopy(&Plocal.y, &P.y); SSFBNCopy(&Plocal.z, &P.z);
            SSFBNSetUint32(&d, 6u, c->limbs);
            SSFECScalarMul(&Rref6, &d, &G, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&refx6, &refy6, &Rref6, SSF_EC_CURVE_P256) == true);

            SSFECPointAdd(&Plocal, &Plocal, &Plocal, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &Plocal, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&rx, &refx6) == 0);
            SSF_ASSERT(SSFBNCmp(&ry, &refy6) == 0);
        }

        /* Case 1d: SSFECScalarMul(&P, &k, &P) -- output aliases input point ([5]*3G = 15G). */
        {
            SSFECPOINT_DEFINE(Plocal, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(Rref15, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(refx15, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(refy15, SSF_EC_MAX_LIMBS);
            SSFBNCopy(&Plocal.x, &P.x); SSFBNCopy(&Plocal.y, &P.y); SSFBNCopy(&Plocal.z, &P.z);
            SSFBNSetUint32(&d, 5u, c->limbs);
            SSFECScalarMul(&Plocal, &d, &Plocal, SSF_EC_CURVE_P256);

            SSFBNSetUint32(&d, 15u, c->limbs);
            SSFECScalarMul(&Rref15, &d, &G, SSF_EC_CURVE_P256);
            SSF_ASSERT(SSFECPointToAffine(&refx15, &refy15, &Rref15, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &Plocal, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&rx, &refx15) == 0);
            SSF_ASSERT(SSFBNCmp(&ry, &refy15) == 0);
        }
    }

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
    /* ---- (Gap 2) Comb table validation: [2^(i*d)]G via comb must equal direct ScalarMul ---- */
    /* Targeted single-bit-set scalars exercise table[2^i] = G_i for each strip i. Stronger      */
    /* than the random-k parity test for catching constants-table generation errors.             */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaComb, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(viaMul, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(cx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(cy, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(mx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(my, SSF_EC_MAX_LIMBS);
        uint32_t d_bits = (256u + SSF_EC_FIXED_BASE_COMB_H - 1u) / SSF_EC_FIXED_BASE_COMB_H;
        uint32_t i;

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);

        for (i = 0; i < SSF_EC_FIXED_BASE_COMB_H; i++)
        {
            uint32_t bit_pos = i * d_bits;
            if (bit_pos >= (uint32_t)c->limbs * SSF_BN_LIMB_BITS) break;

            SSFBNSetZero(&k, c->limbs);
            SSFBNSetBit(&k, bit_pos);

            SSFECScalarMulBaseP256(&viaComb, &k);
            SSFECScalarMul(&viaMul, &k, &G, SSF_EC_CURVE_P256);

            SSF_ASSERT(SSFECPointToAffine(&cx, &cy, &viaComb, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&mx, &my, &viaMul,  SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&cx, &mx) == 0);
            SSF_ASSERT(SSFBNCmp(&cy, &my) == 0);
        }
    }
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 */

    /* ---- (Gap 3) NIST KAT: [d]G for the RFC 6979 P-256 test vector ---- */
    /* d and Q from RFC 6979 Appendix A.2.5. Locks the scalar-mul math against an external      */
    /* reference (not derivable from any other test in this suite).                              */
    {
        static const uint8_t d_bytes[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
        static const uint8_t expected_x[] = {
            0x60u, 0xFEu, 0xD4u, 0xBAu, 0x25u, 0x5Au, 0x9Du, 0x31u,
            0xC9u, 0x61u, 0xEBu, 0x74u, 0xC6u, 0x35u, 0x6Du, 0x68u,
            0xC0u, 0x49u, 0xB8u, 0x92u, 0x3Bu, 0x61u, 0xFAu, 0x6Cu,
            0xE6u, 0x69u, 0x62u, 0x2Eu, 0x60u, 0xF2u, 0x9Fu, 0xB6u
        };
        static const uint8_t expected_y[] = {
            0x79u, 0x03u, 0xFEu, 0x10u, 0x08u, 0xB8u, 0xBCu, 0x99u,
            0xA4u, 0x1Au, 0xE9u, 0xE9u, 0x56u, 0x28u, 0xBCu, 0x64u,
            0xF2u, 0xF1u, 0xB2u, 0x0Cu, 0x2Du, 0x7Eu, 0x9Fu, 0x51u,
            0x77u, 0xA3u, 0xC2u, 0x94u, 0xD4u, 0x46u, 0x22u, 0x99u
        };
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(qx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(qy, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(expx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(expy, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFBNFromBytes(&d, d_bytes, sizeof(d_bytes), c->limbs) == true);
        SSF_ASSERT(SSFBNFromBytes(&expx, expected_x, sizeof(expected_x), c->limbs) == true);
        SSF_ASSERT(SSFBNFromBytes(&expy, expected_y, sizeof(expected_y), c->limbs) == true);

        /* Path A: variable-base scalar mul. */
        SSFECScalarMul(&Q, &d, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&qx, &qy, &Q, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&qx, &expx) == 0);
        SSF_ASSERT(SSFBNCmp(&qy, &expy) == 0);

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
        /* Path B: fixed-base comb. Same expected coordinates. */
        SSFECScalarMulBaseP256(&Q, &d);
        SSF_ASSERT(SSFECPointToAffine(&qx, &qy, &Q, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&qx, &expx) == 0);
        SSF_ASSERT(SSFBNCmp(&qy, &expy) == 0);
#endif
    }

    /* ---- (Gap 4) Off-curve negative test: PointValidate / PointDecode must reject ---- */
    /* Build (G.x, G.y + 1) -- guaranteed off-curve since (G.x, G.y) IS on the curve.      */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(badPt, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(decoded, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(badY, SSF_EC_MAX_LIMBS);
        uint8_t bad_sec1[65];

        badY.len = c->limbs;
        SSFBNCopy(&badY, &c->gy);
        (void)SSFBNAddUint32(&badY, &badY, 1u);  /* G.y + 1 < p for P-256 */

        SSFBNCopy(&badPt.x, &c->gx);
        SSFBNCopy(&badPt.y, &badY);
        SSFBNSetOne(&badPt.z, c->limbs);

        SSF_ASSERT(SSFECPointOnCurve(&badPt, SSF_EC_CURVE_P256) == false);
        SSF_ASSERT(SSFECPointValidate(&badPt, SSF_EC_CURVE_P256) == false);

        /* Also rejected via SEC1 decode. */
        bad_sec1[0] = 0x04u;
        SSF_ASSERT(SSFBNToBytes(&c->gx, &bad_sec1[1], c->bytes) == true);
        SSF_ASSERT(SSFBNToBytes(&badY,  &bad_sec1[1u + c->bytes], c->bytes) == true);
        SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, bad_sec1, sizeof(bad_sec1)) == false);
    }

    /* ---- (Gap 5) Coordinate boundary: PointOnCurve handles X = p-1 cleanly ---- */
    /* Sanity test that the modular arithmetic in OnCurve works at the high end of the field   */
    /* without overflow or underflow. (G.x, p-1) is essentially never on the curve, so we just  */
    /* verify a clean rejection rather than acceptance.                                          */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(boundPt, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(pMinus1, SSF_EC_MAX_LIMBS);

        pMinus1.len = c->limbs;
        SSFBNCopy(&pMinus1, &c->p);
        (void)SSFBNSubUint32(&pMinus1, &pMinus1, 1u);

        SSFBNCopy(&boundPt.x, &pMinus1);
        SSFBNCopy(&boundPt.y, &pMinus1);
        SSFBNSetOne(&boundPt.z, c->limbs);

        /* Must complete without crashing; expected result is "not on curve". */
        SSF_ASSERT(SSFECPointOnCurve(&boundPt, SSF_EC_CURVE_P256) == false);
    }

    /* ---- (Gap 7) k = n-1: [n-1]G = -G (same x-coord, y = p - G.y) ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(expY, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);

        k.len = c->limbs;
        SSFBNCopy(&k, &c->n);
        (void)SSFBNSubUint32(&k, &k, 1u);  /* k = n - 1 */

        SSFECScalarMul(&R, &k, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P256) == true);

        expY.len = c->limbs;
        SSFBNSub(&expY, &c->p, &c->gy);
        SSF_ASSERT(SSFBNCmp(&rx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &expY) == 0);

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
        SSFECScalarMulBaseP256(&R, &k);
        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &expY) == 0);
#endif
    }

    /* ====================================================================================== */
    /* === Comprehensive interface edge-case coverage =======================================  */
    /* ====================================================================================== */

    /* ---- Edge: SSFECGetCurveParams with invalid enum returns NULL ---- */
    {
        SSF_ASSERT(SSFECGetCurveParams((SSFECCurve_t)0xFFu) == NULL);
    }

    /* ---- Edge: SSFECPointSetIdentity is idempotent ---- */
    {
        SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&O) == true);
        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&O) == true);
    }

    /* ---- Edge: PointToAffine with Z=1 input (no fast-path; runs full inversion) ---- */
    /* Verifies the post-#3 behavior where the Z=1 fast-path was removed: PointFromAffine    */
    /* output (Z=1) must still round-trip cleanly through PointToAffine.                      */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G,  SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        /* G has Z=1. PointToAffine must produce affine coords equal to (gx, gy). */
        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &G, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &c->gy) == 0);
    }

    /* ---- Edge: PointToAffine returns false for identity input ---- */
    {
        SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &O, SSF_EC_CURVE_P256) == false);
    }

    /* ---- Edge: FromAffine then ToAffine round-trip preserves coordinates ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(P, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(srcx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(srcy, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);

        /* Use a Jacobian point's affine coords as source. */
        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&d, 7u, c->limbs);
        SSFECScalarMul(&P, &d, &G, SSF_EC_CURVE_P256);  /* P = 7G in Jacobian */
        SSF_ASSERT(SSFECPointToAffine(&srcx, &srcy, &P, SSF_EC_CURVE_P256) == true);

        /* Round-trip: those affine coords -> FromAffine -> ToAffine should equal originals. */
        SSFECPointFromAffine(&P, &srcx, &srcy, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &P, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &srcx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &srcy) == 0);
    }

    /* ---- Edge: PointOnCurve returns false for identity ---- */
    {
        SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointOnCurve(&O, SSF_EC_CURVE_P256) == false);
    }

    /* ---- Edge: PointValidate rejects coordinates >= p ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(badPt, SSF_EC_MAX_LIMBS);

        /* x = p (out of range), y = G.y, Z = 1. */
        SSFBNCopy(&badPt.x, &c->p);
        SSFBNCopy(&badPt.y, &c->gy);
        SSFBNSetOne(&badPt.z, c->limbs);
        SSF_ASSERT(SSFECPointValidate(&badPt, SSF_EC_CURVE_P256) == false);

        /* x = G.x, y = p (out of range). */
        SSFBNCopy(&badPt.x, &c->gx);
        SSFBNCopy(&badPt.y, &c->p);
        SSFBNSetOne(&badPt.z, c->limbs);
        SSF_ASSERT(SSFECPointValidate(&badPt, SSF_EC_CURVE_P256) == false);
    }

    /* ---- Edge: PointEncode rejects insufficient buffer (returns false, doesn't write) ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        uint8_t asmall[10];  /* Too small: needs 65 bytes for P-256 */
        size_t outLen = 0xDEADBEEFu;

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointEncode(&G, SSF_EC_CURVE_P256, asmall, sizeof(asmall), &outLen) == false);
        /* outLen must NOT be updated on failure (caller reads it as "use this many bytes"). */
        SSF_ASSERT(outLen == 0xDEADBEEFu);

        /* Exact size succeeds. */
        {
            uint8_t exact[65];
            SSF_ASSERT(SSFECPointEncode(&G, SSF_EC_CURVE_P256, exact, sizeof(exact), &outLen) == true);
            SSF_ASSERT(outLen == 65u);
        }
    }

    /* ---- Edge: PointEncode of identity fails (no affine coords) ---- */
    {
        SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
        uint8_t enc[65];
        size_t outLen;
        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointEncode(&O, SSF_EC_CURVE_P256, enc, sizeof(enc), &outLen) == false);
    }

    /* ---- Edge: PointDecode rejects (0, 0) -- not on curve ---- */
    {
        SSFECPOINT_DEFINE(decoded, SSF_EC_MAX_LIMBS);
        uint8_t allZero[65] = { 0 };
        allZero[0] = 0x04u;
        SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, allZero, sizeof(allZero)) == false);
    }

    /* ---- Edge: PointDecode rejects coords >= p ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(decoded, SSF_EC_MAX_LIMBS);
        uint8_t bad[65];
        SSFBN_DEFINE(maxBytes, SSF_EC_MAX_LIMBS);

        /* x = p, y = G.y. */
        bad[0] = 0x04u;
        SSF_ASSERT(SSFBNToBytes(&c->p,  &bad[1],            c->bytes) == true);
        SSF_ASSERT(SSFBNToBytes(&c->gy, &bad[1u + c->bytes], c->bytes) == true);
        SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, bad, sizeof(bad)) == false);

        /* x = G.x, y = p. */
        SSF_ASSERT(SSFBNToBytes(&c->gx, &bad[1],             c->bytes) == true);
        SSF_ASSERT(SSFBNToBytes(&c->p,  &bad[1u + c->bytes], c->bytes) == true);
        SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, bad, sizeof(bad)) == false);
        (void)maxBytes;
    }

    /* ---- Edge: SEC1 Encode -> Decode roundtrip preserves a non-G point ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(P, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(decoded, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(dx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(dy, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
        uint8_t enc[65];
        size_t encLen;

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&d, 12345u, c->limbs);
        SSFECScalarMul(&P, &d, &G, SSF_EC_CURVE_P256);

        SSF_ASSERT(SSFECPointEncode(&P, SSF_EC_CURVE_P256, enc, sizeof(enc), &encLen) == true);
        SSF_ASSERT(SSFECPointDecode(&decoded, SSF_EC_CURVE_P256, enc, encLen) == true);

        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &P,       SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&dx, &dy, &decoded, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &dx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &dy) == 0);
    }

    /* ---- Edge: ScalarMul on identity input -> identity for any k ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);

        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);

        /* k = 1: [1] * O = O */
        SSFBNSetUint32(&k, 1u, c->limbs);
        SSFECScalarMul(&R, &k, &O, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);

        /* k = 12345: [k] * O = O */
        SSFBNSetUint32(&k, 12345u, c->limbs);
        SSFECScalarMul(&R, &k, &O, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);
    }

    /* ---- Edge: ScalarMulDual with zero scalars ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(P, SSF_EC_MAX_LIMBS);  /* = 3G */
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Ref, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(zero, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(refx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(refy, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&d, 3u, c->limbs);
        SSFECScalarMul(&P, &d, &G, SSF_EC_CURVE_P256);
        SSFBNSetZero(&zero, c->limbs);

        /* [0]G + [0]P = identity */
        SSFECScalarMulDual(&R, &zero, &G, &zero, &P, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);

        /* [1]G + [0]P = G */
        SSFBNSetUint32(&d, 1u, c->limbs);
        SSFECScalarMulDual(&R, &d, &G, &zero, &P, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &c->gy) == 0);

        /* [0]G + [1]P = P (whose affine = 3G's affine) */
        SSFECScalarMulDual(&R, &zero, &G, &d, &P, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&d, 3u, c->limbs);
        SSFECScalarMul(&Ref, &d, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx,   &ry,   &R,   SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&refx, &refy, &Ref, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &refx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &refy) == 0);
    }

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
    /* ---- Edge: ScalarMulDualBase with zero scalars ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Ref, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(zero, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(refx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(refy, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFBNSetUint32(&d, 5u, c->limbs);
        SSFECScalarMul(&Q, &d, &G, SSF_EC_CURVE_P256);
        SSFBNSetZero(&zero, c->limbs);

        /* [0]G + [0]Q = identity */
        SSFECScalarMulDualBase(&R, &zero, &zero, &Q, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);

        /* [k]G + [0]Q = [k]G */
        SSFBNSetUint32(&d, 7u, c->limbs);
        SSFECScalarMulDualBase(&R, &d, &zero, &Q, SSF_EC_CURVE_P256);
        SSFECScalarMul(&Ref, &d, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx,   &ry,   &R,   SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&refx, &refy, &Ref, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &refx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &refy) == 0);

        /* [0]G + [k]Q = [k]Q */
        SSFECScalarMulDualBase(&R, &zero, &d, &Q, SSF_EC_CURVE_P256);
        SSFECScalarMul(&Ref, &d, &Q, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx,   &ry,   &R,   SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&refx, &refy, &Ref, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &refx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &refy) == 0);
    }
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 */

    /* ---- Edge: ScalarMulDual with one input point being identity ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(O, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(Ref, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(u1, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(u2, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(refx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(refy, SSF_EC_MAX_LIMBS);

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);

        /* [3]G + [5]O = [3]G */
        SSFBNSetUint32(&u1, 3u, c->limbs);
        SSFBNSetUint32(&u2, 5u, c->limbs);
        SSFECScalarMulDual(&R, &u1, &G, &u2, &O, SSF_EC_CURVE_P256);
        SSFECScalarMul(&Ref, &u1, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointToAffine(&rx,   &ry,   &R,   SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointToAffine(&refx, &refy, &Ref, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &refx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &refy) == 0);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if 0 /* GENERATE_AFFINE_COMB_TABLES -- flip to 1, run, paste dumps into the .h files.           */
      /* Generates BOTH P-256 and P-384 comb tables in affine form (Z=1) so the comb runtime can */
      /* use mixed-coordinate addition for ~10% speedup.                                          */
    {
        struct curve_spec {
            SSFECCurve_t curve;
            uint16_t nLimbs;
            uint32_t dBits;
            const char *label;
        };
        static const struct curve_spec specs[] = {
            { SSF_EC_CURVE_P256,  8u, 64u, "P-256" },
            { SSF_EC_CURVE_P384, 12u, 96u, "P-384" },
        };
        size_t si;

        for (si = 0; si < sizeof(specs) / sizeof(specs[0]); si++)
        {
            const SSFECCurveParams_t *c = SSFECGetCurveParams(specs[si].curve);
            SSFECPOINT_DEFINE(G,    SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(t1,   SSF_EC_MAX_LIMBS); SSFECPOINT_DEFINE(t2,   SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(t3,   SSF_EC_MAX_LIMBS); SSFECPOINT_DEFINE(t4,   SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(t5,   SSF_EC_MAX_LIMBS); SSFECPOINT_DEFINE(t6,   SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(t7,   SSF_EC_MAX_LIMBS); SSFECPOINT_DEFINE(t8,   SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(t9,   SSF_EC_MAX_LIMBS); SSFECPOINT_DEFINE(t10,  SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(t11,  SSF_EC_MAX_LIMBS); SSFECPOINT_DEFINE(t12,  SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(t13,  SSF_EC_MAX_LIMBS); SSFECPOINT_DEFINE(t14,  SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(t15,  SSF_EC_MAX_LIMBS); SSFECPOINT_DEFINE(zero, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(scalar, SSF_EC_MAX_LIMBS);
            SSFECPoint_t *all[16];
            uint16_t pi;

            SSFECPointFromAffine(&G, &c->gx, &c->gy, specs[si].curve);
            SSFECPointSetIdentity(&zero, specs[si].curve);

            SSFBNCopy(&t1.x, &G.x); SSFBNCopy(&t1.y, &G.y); SSFBNCopy(&t1.z, &G.z);
            SSFBNSetZero(&scalar, c->limbs); SSFBNSetBit(&scalar, specs[si].dBits);
            SSFECScalarMul(&t2, &scalar, &G, specs[si].curve);
            SSFBNSetZero(&scalar, c->limbs); SSFBNSetBit(&scalar, 2u * specs[si].dBits);
            SSFECScalarMul(&t4, &scalar, &G, specs[si].curve);
            SSFBNSetZero(&scalar, c->limbs); SSFBNSetBit(&scalar, 3u * specs[si].dBits);
            SSFECScalarMul(&t8, &scalar, &G, specs[si].curve);
            SSFECPointAdd(&t3,  &t1, &t2, specs[si].curve);
            SSFECPointAdd(&t5,  &t1, &t4, specs[si].curve);
            SSFECPointAdd(&t6,  &t2, &t4, specs[si].curve);
            SSFECPointAdd(&t7,  &t3, &t4, specs[si].curve);
            SSFECPointAdd(&t9,  &t1, &t8, specs[si].curve);
            SSFECPointAdd(&t10, &t2, &t8, specs[si].curve);
            SSFECPointAdd(&t11, &t3, &t8, specs[si].curve);
            SSFECPointAdd(&t12, &t4, &t8, specs[si].curve);
            SSFECPointAdd(&t13, &t5, &t8, specs[si].curve);
            SSFECPointAdd(&t14, &t6, &t8, specs[si].curve);
            SSFECPointAdd(&t15, &t7, &t8, specs[si].curve);

            all[0]=&zero; all[1]=&t1;  all[2]=&t2;  all[3]=&t3;
            all[4]=&t4;   all[5]=&t5;  all[6]=&t6;  all[7]=&t7;
            all[8]=&t8;   all[9]=&t9;  all[10]=&t10; all[11]=&t11;
            all[12]=&t12; all[13]=&t13; all[14]=&t14; all[15]=&t15;

            /* Convert each non-identity entry to affine (Z=1). */
            for (pi = 1; pi < 16u; pi++)
            {
                SSFBN_DEFINE(ax, SSF_EC_MAX_LIMBS);
                SSFBN_DEFINE(ay, SSF_EC_MAX_LIMBS);
                SSF_ASSERT(SSFECPointToAffine(&ax, &ay, all[pi], specs[si].curve) == true);
                SSFBNCopy(&all[pi]->x, &ax);
                SSFBNCopy(&all[pi]->y, &ay);
                SSFBNSetUint32(&all[pi]->z, 1u, c->limbs);
            }

            SSF_UT_PRINTF("\n/* === BEGIN %s AFFINE COMB TABLE DUMP === */\n", specs[si].label);
            for (pi = 0; pi < 16u; pi++)
            {
                uint16_t lim, li;
                const SSFBN_t *coords[3] = { &all[pi]->x, &all[pi]->y, &all[pi]->z };
                SSF_UT_PRINTF("    /* table[%2u] */\n    {\n", (unsigned)pi);
                for (lim = 0; lim < 3u; lim++)
                {
                    SSF_UT_PRINTF("        { ");
                    for (li = 0; li < specs[si].nLimbs; li++)
                    {
                        SSFBNLimb_t v = (li < coords[lim]->len) ? coords[lim]->limbs[li] : 0u;
                        SSF_UT_PRINTF("0x%08Xu%s", (unsigned)v,
                               (li + 1u < specs[si].nLimbs) ? ", " : "");
                    }
                    SSF_UT_PRINTF(" },\n");
                }
                SSF_UT_PRINTF("    },\n");
            }
            SSF_UT_PRINTF("/* === END %s AFFINE COMB TABLE DUMP === */\n\n", specs[si].label);
        }
    }
#endif

#if SSF_CONFIG_EC_MICROBENCH == 1
    /* ====================================================================================== */
    /* Microbenchmark -- [k]G scalar multiplication. Driven by random scalars to avoid         */
    /* branch-predictor caching artefacts. Gated by SSF_CONFIG_EC_MICROBENCH so the normal     */
    /* test run stays quick.                                                                    */
    /* ====================================================================================== */
    {
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;
        SSFPortTick_t t0, t1;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0xA5u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        SSF_UT_PRINTF("\n--- ssfec microbenchmark (ms for iter count shown) ---\n");

#if SSF_EC_CONFIG_ENABLE_P256 == 1
        {
            const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
            SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
            const uint32_t iters = 2000u;

            SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSFBNRandomBelow(&k, &c->n, &prng);
                SSFECScalarMul(&R, &k, &G, SSF_EC_CURVE_P256);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  ScalarMul       P-256 [k]G   %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSFBNRandomBelow(&k, &c->n, &prng);
                SSFECScalarMulBaseP256(&R, &k);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  BaseP256 [k]G (fixed-base) %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 */
        }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if SSF_EC_CONFIG_ENABLE_P384 == 1
        {
            const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
            SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
            const uint32_t iters = 1000u;

            SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);
            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSFBNRandomBelow(&k, &c->n, &prng);
                SSFECScalarMul(&R, &k, &G, SSF_EC_CURVE_P384);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  ScalarMul       P-384 [k]G   %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));

#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSFBNRandomBelow(&k, &c->n, &prng);
                SSFECScalarMulBaseP384(&R, &k);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  BaseP384 [k]G (fixed-base) %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));
#endif /* SSF_EC_CONFIG_FIXED_BASE_P384 */
        }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

#if SSF_EC_CONFIG_ENABLE_P256 == 1
        /* Dual scalar mul (ECDSA verify hot path): u1*G + u2*Q. */
        {
            const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
            SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(u1, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(u2, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
            const uint32_t iters = 1000u;

            SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
            /* Build a representative public key Q = [d]G. */
            SSFBNSetUint32(&d, 0xDEADBEEFu, c->limbs);
            SSFECScalarMul(&Q, &d, &G, SSF_EC_CURVE_P256);

            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSFBNRandomBelow(&u1, &c->n, &prng);
                SSFBNRandomBelow(&u2, &c->n, &prng);
                SSFECScalarMulDual(&R, &u1, &G, &u2, &Q, SSF_EC_CURVE_P256);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  ScalarMulDual   P-256 (Shamir)  %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSFBNRandomBelow(&u1, &c->n, &prng);
                SSFBNRandomBelow(&u2, &c->n, &prng);
                SSFECScalarMulDualBase(&R, &u1, &u2, &Q, SSF_EC_CURVE_P256);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  DualBase P-256 (fixed+windowed) %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 */
        }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if SSF_EC_CONFIG_ENABLE_P384 == 1
        {
            const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
            SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
            SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(u1, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(u2, SSF_EC_MAX_LIMBS);
            SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
            const uint32_t iters = 500u;

            SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);
            SSFBNSetUint32(&d, 0xCAFEBABEu, c->limbs);
            SSFECScalarMul(&Q, &d, &G, SSF_EC_CURVE_P384);

            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSFBNRandomBelow(&u1, &c->n, &prng);
                SSFBNRandomBelow(&u2, &c->n, &prng);
                SSFECScalarMulDual(&R, &u1, &G, &u2, &Q, SSF_EC_CURVE_P384);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  ScalarMulDual   P-384 (Shamir)  %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));

#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSFBNRandomBelow(&u1, &c->n, &prng);
                SSFBNRandomBelow(&u2, &c->n, &prng);
                SSFECScalarMulDualBase(&R, &u1, &u2, &Q, SSF_EC_CURVE_P384);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  DualBase P-384 (fixed+windowed) %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));
#endif /* SSF_EC_CONFIG_FIXED_BASE_P384 */
        }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

        /* End-to-end ECDSA sign / keygen / ECDH benchmarks. These exercise the wired-in       */
        /* fixed-base scalar mul (when configured) inside the ssfecdsa code path.               */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
        {
            const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
            uint8_t privKey[32];
            uint8_t pubKey[1 + 64];
            uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
            uint8_t hash[32];
            size_t pubKeyLen;
            size_t sigLen;
            const uint32_t iters = 500u;

            (void)c;
            /* Deterministic placeholder hash; actual content doesn't matter for timing. */
            for (i = 0; i < (uint16_t)sizeof(hash); i++) hash[i] = (uint8_t)(0x42u ^ i);

            /* Fresh keypair for the sign/verify bench loops. */
            SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                                      pubKey, sizeof(pubKey), &pubKeyLen) == true);

            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                uint8_t pkBuf[32];
                uint8_t pubBuf[1 + 64];
                size_t pkLen;
                SSFECDSAKeyGen(SSF_EC_CURVE_P256, pkBuf, sizeof(pkBuf),
                               pubBuf, sizeof(pubBuf), &pkLen);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  ECDSAKeyGen     P-256        %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));

            sigLen = 0;
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                                        hash, sizeof(hash), sig, sizeof(sig),
                                        &sigLen) == true);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  ECDSASign       P-256        %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));

            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, pubKeyLen,
                                          hash, sizeof(hash),
                                          sig, sigLen) == true);
            }
            t1 = SSFPortGetTick64();
            SSF_UT_PRINTF("  ECDSAVerify     P-256        %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN -- sig produced by Sign feeds Verify */
        }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

        SSF_UT_PRINTF("--- end ssfec microbenchmark ---\n");

        SSFPRNGDeInitContext(&prng);
    }
#endif /* SSF_CONFIG_EC_MICROBENCH */
}
#ifdef _WIN32
#pragma warning(pop)
#endif
#endif /* SSF_CONFIG_EC_UNIT_TEST */
