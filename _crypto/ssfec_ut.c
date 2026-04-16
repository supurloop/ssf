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

#if SSF_CONFIG_EC_UNIT_TEST == 1

void SSFECUnitTest(void)
{
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    /* ---- P-256: generator is on curve ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPoint_t G;

        SSF_ASSERT(c != NULL);
        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointOnCurve(&G, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointValidate(&G, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFECPointIsIdentity(&G) == false);
    }

    /* ---- P-256: identity handling ---- */
    {
        SSFECPoint_t O;

        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&O) == true);
    }

    /* ---- P-256: SEC 1 encode/decode roundtrip of generator ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPoint_t G, G2;
        uint8_t enc[SSF_EC_MAX_ENCODED_SIZE];
        size_t encLen;

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointEncode(&G, SSF_EC_CURVE_P256, enc, sizeof(enc), &encLen) == true);
        SSF_ASSERT(encLen == 65u);
        SSF_ASSERT(enc[0] == 0x04u);

        SSF_ASSERT(SSFECPointDecode(&G2, SSF_EC_CURVE_P256, enc, encLen) == true);
        {
            SSFBN_t x1, y1, x2, y2;
            SSF_ASSERT(SSFECPointToAffine(&x1, &y1, &G, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFECPointToAffine(&x2, &y2, &G2, SSF_EC_CURVE_P256) == true);
            SSF_ASSERT(SSFBNCmp(&x1, &x2) == 0);
            SSF_ASSERT(SSFBNCmp(&y1, &y2) == 0);
        }
    }

    /* ---- P-256: invalid point rejection ---- */
    {
        uint8_t bad[65];
        SSFECPoint_t pt;

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
        SSFECPoint_t G, R;
        SSFBN_t one;
        SSFBN_t rx, ry;

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
        SSFECPoint_t G, sum, dbl;
        SSFBN_t two;
        SSFBN_t sx, sy, dx, dy;

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
        SSFECPoint_t G, R;

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFECScalarMul(&R, &c->n, &G, SSF_EC_CURVE_P256);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);
    }

    /* ---- P-256: G + identity = G ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPoint_t G, O, R;
        SSFBN_t rx, ry;

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P256);
        SSFECPointSetIdentity(&O, SSF_EC_CURVE_P256);
        SSFECPointAdd(&R, &G, &O, SSF_EC_CURVE_P256);

        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P256) == true);
        SSF_ASSERT(SSFBNCmp(&rx, &c->gx) == 0);
        SSF_ASSERT(SSFBNCmp(&ry, &c->gy) == 0);
    }

    /* ---- P-256: dual scalar mul consistency: u1*G + u2*G = (u1+u2)*G ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        SSFECPoint_t G, R1, R2;
        SSFBN_t u1, u2, uSum;
        SSFBN_t r1x, r1y, r2x, r2y;

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
        SSFECPoint_t G;

        SSF_ASSERT(c != NULL);
        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);
        SSF_ASSERT(SSFECPointOnCurve(&G, SSF_EC_CURVE_P384) == true);
        SSF_ASSERT(SSFECPointValidate(&G, SSF_EC_CURVE_P384) == true);
    }

    /* ---- P-384: 1 * G = G ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);
        SSFECPoint_t G, R;
        SSFBN_t one;
        SSFBN_t rx, ry;

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
        SSFECPoint_t G, R;

        SSFECPointFromAffine(&G, &c->gx, &c->gy, SSF_EC_CURVE_P384);
        SSFECScalarMul(&R, &c->n, &G, SSF_EC_CURVE_P384);
        SSF_ASSERT(SSFECPointIsIdentity(&R) == true);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */
}
#endif /* SSF_CONFIG_EC_UNIT_TEST */
