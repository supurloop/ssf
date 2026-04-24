/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbn_ut.c                                                                                    */
/* Provides unit tests for the ssfbn big number arithmetic module.                               */
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
#include "ssfbn.h"

#if SSF_CONFIG_BN_UNIT_TEST == 1

void SSFBNUnitTest(void)
{
    /* ---- SetZero, SetUint32, IsZero, IsOne ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetZero(&a, 4);
        SSF_ASSERT(SSFBNIsZero(&a) == true);
        SSF_ASSERT(SSFBNIsOne(&a) == false);
        SSF_ASSERT(a.len == 4);

        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNIsZero(&a) == false);
        SSF_ASSERT(SSFBNIsOne(&a) == true);

        SSFBNSetUint32(&a, 42u, 4);
        SSF_ASSERT(SSFBNIsZero(&a) == false);
        SSF_ASSERT(SSFBNIsOne(&a) == false);
        SSF_ASSERT(SSFBNIsEven(&a) == true);

        SSFBNSetUint32(&a, 43u, 4);
        SSF_ASSERT(SSFBNIsEven(&a) == false);
    }

    /* ---- FromBytes / ToBytes roundtrip ---- */
    {
        static const uint8_t data[] = { 0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xABu, 0xCDu, 0xEFu };
        uint8_t out[8];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSF_ASSERT(SSFBNFromBytes(&a, data, sizeof(data), 4) == true);
        SSF_ASSERT(SSFBNToBytes(&a, out, sizeof(out)) == true);
        SSF_ASSERT(memcmp(data, out, sizeof(data)) == 0);
    }

    /* ---- FromBytes / ToBytes with leading zero pad ---- */
    {
        static const uint8_t data[] = { 0xFFu };
        uint8_t out[4];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSF_ASSERT(SSFBNFromBytes(&a, data, 1, 2) == true);
        SSF_ASSERT(SSFBNToBytes(&a, out, sizeof(out)) == true);
        SSF_ASSERT(out[0] == 0x00u);
        SSF_ASSERT(out[1] == 0x00u);
        SSF_ASSERT(out[2] == 0x00u);
        SSF_ASSERT(out[3] == 0xFFu);
    }

    /* ---- Comparison ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 100u, 4);
        SSFBNSetUint32(&b, 200u, 4);
        SSF_ASSERT(SSFBNCmp(&a, &b) == -1);
        SSF_ASSERT(SSFBNCmp(&b, &a) == 1);
        SSF_ASSERT(SSFBNCmp(&a, &a) == 0);
    }

    /* ---- Add / Sub ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 100u, 4);
        SSFBNSetUint32(&b, 200u, 4);
        SSF_ASSERT(SSFBNAdd(&r, &a, &b) == 0);
        {
            SSFBN_DEFINE(expected, SSF_BN_MAX_LIMBS);
            SSFBNSetUint32(&expected, 300u, 4);
            SSF_ASSERT(SSFBNCmp(&r, &expected) == 0);
        }

        SSF_ASSERT(SSFBNSub(&r, &b, &a) == 0);
        {
            SSFBN_DEFINE(expected, SSF_BN_MAX_LIMBS);
            SSFBNSetUint32(&expected, 100u, 4);
            SSF_ASSERT(SSFBNCmp(&r, &expected) == 0);
        }
    }

    /* ---- Multiplication ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* 7 * 6 = 42 */
        SSFBNSetUint32(&a, 7u, 2);
        SSFBNSetUint32(&b, 6u, 2);
        SSFBNMul(&r, &a, &b);
        SSF_ASSERT(r.len == 4);
        SSF_ASSERT(r.limbs[0] == 42u);
        SSF_ASSERT(r.limbs[1] == 0u);
    }

    /* ---- BitLen and GetBit ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 0u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 0);

        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 1);

        SSFBNSetUint32(&a, 255u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 8);

        SSFBNSetUint32(&a, 256u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 9);

        /* GetBit: 0b1010 = 10 */
        SSFBNSetUint32(&a, 10u, 4);
        SSF_ASSERT(SSFBNGetBit(&a, 0) == 0);
        SSF_ASSERT(SSFBNGetBit(&a, 1) == 1);
        SSF_ASSERT(SSFBNGetBit(&a, 2) == 0);
        SSF_ASSERT(SSFBNGetBit(&a, 3) == 1);
        SSF_ASSERT(SSFBNGetBit(&a, 4) == 0);
    }

    /* ---- Shift left / right ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 1u, 4);
        SSFBNShiftLeft1(&a);
        SSF_ASSERT(a.limbs[0] == 2u);
        SSFBNShiftLeft1(&a);
        SSF_ASSERT(a.limbs[0] == 4u);

        SSFBNShiftRight1(&a);
        SSF_ASSERT(a.limbs[0] == 2u);
        SSFBNShiftRight1(&a);
        SSF_ASSERT(a.limbs[0] == 1u);
        SSFBNShiftRight1(&a);
        SSF_ASSERT(a.limbs[0] == 0u);
    }

    /* ---- ModAdd / ModSub with small modulus ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* (5 + 6) mod 7 = 4 */
        SSFBNSetUint32(&a, 5u, 4);
        SSFBNSetUint32(&b, 6u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSFBNModAdd(&r, &a, &b, &m);
        SSF_ASSERT(r.limbs[0] == 4u);

        /* (2 - 5) mod 7 = 4 */
        SSFBNSetUint32(&a, 2u, 4);
        SSFBNSetUint32(&b, 5u, 4);
        SSFBNModSub(&r, &a, &b, &m);
        SSF_ASSERT(r.limbs[0] == 4u);
    }

    /* ---- ModMul with small modulus ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* (5 * 6) mod 7 = 30 mod 7 = 2 */
        SSFBNSetUint32(&a, 5u, 4);
        SSFBNSetUint32(&b, 6u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSFBNModMul(&r, &a, &b, &m);
        SSF_ASSERT(r.limbs[0] == 2u);
    }

    /* ---- ModExp: 3^10 mod 7 = 59049 mod 7 = 4 ---- */
    {
        SSFBN_DEFINE(base, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(exp, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&base, 3u, 4);
        SSFBNSetUint32(&exp, 10u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSFBNModExp(&r, &base, &exp, &m);
        SSF_ASSERT(r.limbs[0] == 4u);
    }

    /* ---- ModInv: 2^(-1) mod 7 = 4 (since 2*4 = 8 = 1 mod 7) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 2u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == true);
        SSF_ASSERT(r.limbs[0] == 4u);
    }

    /* ---- ModInv: 0 has no inverse ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 0u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == false);
    }

    /* ---- CondSwap ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 10u, 4);
        SSFBNSetUint32(&b, 20u, 4);
        SSFBNCondSwap(&a, &b, 0u);
        SSF_ASSERT(a.limbs[0] == 10u);
        SSF_ASSERT(b.limbs[0] == 20u);
        SSFBNCondSwap(&a, &b, 1u);
        SSF_ASSERT(a.limbs[0] == 20u);
        SSF_ASSERT(b.limbs[0] == 10u);
    }

    /* ---- Zeroize ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBNSetUint32(&a, 0xDEADBEEFu, 4);
        SSFBNZeroize(&a);
        SSF_ASSERT(a.limbs[0] == 0u);
        SSF_ASSERT(a.len == 0);
    }

    /* ---- NIST P-256: verify p is consistent with SSF_BN_NIST_P256 ---- */
    {
        SSF_ASSERT(SSFBNCmp(&SSF_BN_NIST_P256, &SSF_BN_NIST_P256) == 0);
        SSF_ASSERT(SSFBNIsZero(&SSF_BN_NIST_P256) == false);
        SSF_ASSERT(SSFBNBitLen(&SSF_BN_NIST_P256) == 256u);
    }

    /* ---- ModMulNIST: a * 1 mod p = a ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 42u, 8);
        SSFBNSetUint32(&one, 1u, 8);
        SSFBNModMulNIST(&r, &a, &one, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNCmp(&r, &a) == 0);
    }

    /* ---- ModMulNIST: a * 0 mod p = 0 ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(zero, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 42u, 8);
        SSFBNSetZero(&zero, 8);
        SSFBNModMulNIST(&r, &a, &zero, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNIsZero(&r) == true);
    }

    /* ---- Montgomery: roundtrip convert in/out ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aBack, SSF_BN_MAX_LIMBS);
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 12345u, 8);
        SSFBNMontInit(&mont, &SSF_BN_NIST_P256);
        SSFBNMontConvertIn(&aM, &a, &mont);
        SSFBNMontConvertOut(&aBack, &aM, &mont);
        SSF_ASSERT(SSFBNCmp(&a, &aBack) == 0);
    }
}
#endif /* SSF_CONFIG_BN_UNIT_TEST */
