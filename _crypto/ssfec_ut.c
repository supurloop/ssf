/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfec_ut.c                                                                                    */
/* Provides unit tests for the ssfec elliptic curve point arithmetic module.                     */
/* Test vectors from FIPS 186-4 and SEC 1 v2.                                                    */
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
#include "ssfassert.h"
#include "ssfec.h"
#if SSF_CONFIG_EC_MICROBENCH == 1
#include "ssfport.h"
#include "ssfprng.h"
#include "ssfecdsa.h"
#include "ssfsha2.h"
#include <stdio.h>
#endif

#if SSF_CONFIG_EC_UNIT_TEST == 1

void SSFECUnitTest(void)
{
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

        /* k = 0 → identity */
        SSFBNSetZero(&k, c->limbs);
        SSFECScalarMul(&R, &k, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);

        /* k = 1 → G */
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

    /* ---- P-256: G + (-G) = identity (H==0, R!=0 cascade — P + -Q case) ---- */
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

        /* Random k parity sweep — fixed-base must match the ladder for arbitrary scalars. */
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

        /* P = [3]G — has Z != 1 in Jacobian form. */
        SSFBNSetUint32(&scalar, 3u, c->limbs);
        SSFECScalarMul(&P, &scalar, &G, SSF_EC_CURVE_P256);

        /* Q = G — affine (Z = 1) by construction of SSFECPointFromAffine. */
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
        /* Use Q for both — Q is affine. */
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
    /* ---- Variable-time wNAF scalar mul: must agree with constant-time SSFECScalarMul ---- */
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

        /* Random parity sweep — Q is Jacobian (not Z=1). */
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

        /* Affine-input sweep — G is Z=1 (built from c->gx, c->gy). Hits the wNAF affine     */
        /* fast path (table[0] is Z=1, so adds of ±table[0] use mixed-coordinate addition).  */
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
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if 0 /* GENERATE_AFFINE_COMB_TABLES — flip to 1, run, paste dumps into the .h files.            */
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

            printf("\n/* === BEGIN %s AFFINE COMB TABLE DUMP === */\n", specs[si].label);
            for (pi = 0; pi < 16u; pi++)
            {
                uint16_t lim, li;
                const SSFBN_t *coords[3] = { &all[pi]->x, &all[pi]->y, &all[pi]->z };
                printf("    /* table[%2u] */\n    {\n", (unsigned)pi);
                for (lim = 0; lim < 3u; lim++)
                {
                    printf("        { ");
                    for (li = 0; li < specs[si].nLimbs; li++)
                    {
                        SSFBNLimb_t v = (li < coords[lim]->len) ? coords[lim]->limbs[li] : 0u;
                        printf("0x%08Xu%s", (unsigned)v,
                               (li + 1u < specs[si].nLimbs) ? ", " : "");
                    }
                    printf(" },\n");
                }
                printf("    },\n");
            }
            printf("/* === END %s AFFINE COMB TABLE DUMP === */\n\n", specs[si].label);
        }
    }
#endif

#if SSF_CONFIG_EC_MICROBENCH == 1
    /* ====================================================================================== */
    /* Microbenchmark — [k]G scalar multiplication. Driven by random scalars to avoid          */
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

        printf("\n--- ssfec microbenchmark (ms for iter count shown) ---\n");

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
            printf("  ScalarMul       P-256 [k]G   %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSFBNRandomBelow(&k, &c->n, &prng);
                SSFECScalarMulBaseP256(&R, &k);
            }
            t1 = SSFPortGetTick64();
            printf("  BaseP256 [k]G (fixed-base) %u iter: %llu ms\n",
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
            printf("  ScalarMul       P-384 [k]G   %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));

#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSFBNRandomBelow(&k, &c->n, &prng);
                SSFECScalarMulBaseP384(&R, &k);
            }
            t1 = SSFPortGetTick64();
            printf("  BaseP384 [k]G (fixed-base) %u iter: %llu ms\n",
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
            printf("  ScalarMulDual   P-256 (Shamir)  %u iter: %llu ms\n",
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
            printf("  DualBase P-256 (fixed+windowed) %u iter: %llu ms\n",
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
            printf("  ScalarMulDual   P-384 (Shamir)  %u iter: %llu ms\n",
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
            printf("  DualBase P-384 (fixed+windowed) %u iter: %llu ms\n",
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
            printf("  ECDSAKeyGen     P-256        %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));

            sigLen = 0;
            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                                        hash, sizeof(hash), sig, sizeof(sig),
                                        &sigLen) == true);
            }
            t1 = SSFPortGetTick64();
            printf("  ECDSASign       P-256        %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));

            t0 = SSFPortGetTick64();
            for (i = 0; i < iters; i++)
            {
                SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, pubKeyLen,
                                          hash, sizeof(hash),
                                          sig, sigLen) == true);
            }
            t1 = SSFPortGetTick64();
            printf("  ECDSAVerify     P-256        %u iter: %llu ms\n",
                   (unsigned)iters, (unsigned long long)(t1 - t0));
        }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

        printf("--- end ssfec microbenchmark ---\n");

        SSFPRNGDeInitContext(&prng);
    }
#endif /* SSF_CONFIG_EC_MICROBENCH */
}
#endif /* SSF_CONFIG_EC_UNIT_TEST */
