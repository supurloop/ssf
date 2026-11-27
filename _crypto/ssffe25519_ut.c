/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssffe25519_ut.c                                                                               */
/* Unit tests for the shared GF(2^255 - 19) field arithmetic.                                    */
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
#include <string.h>
#include "ssfassert.h"
#include "ssffe25519.h"

#if SSF_CONFIG_FE25519_UNIT_TEST == 1

/* Test values; expected results computed with Python big integers */
static const SSFFE25519_t _utMax =
        {{ 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
           0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu }};
static const SSFFE25519_t _utP =
        {{ 0xFFFFFFEDu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
           0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x7FFFFFFFu }};
static const SSFFE25519_t _utX =
        {{ 0x7FFFFFFFu, 0xDEADBEEFu, 0x9ABCDEF0u, 0x12345678u,
           0xF0F0F0F0u, 0x0F0F0F0Fu, 0x3C3C3C3Cu, 0x5A5A5A5Au }};
static const SSFFE25519_t _utMaxSq =
        {{ 0x00000559u, 0x00000000u, 0x00000000u, 0x00000000u,
           0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u }};
static const SSFFE25519_t _utXSq =
        {{ 0xA2AC86CCu, 0x596ED399u, 0x15D6C1ACu, 0x29E43CB7u,
           0xC564CD60u, 0x08B44EB8u, 0x5AC31B3Fu, 0x46B4A7CAu }};
static const SSFFE25519_t _utMaxX =
        {{ 0x800001C9u, 0x2F1C989Du, 0x5D4C38D0u, 0xA1907F6Eu,
           0xD2D2D2B2u, 0x2D2D2D4Du, 0xB4B4B4AEu, 0x0F0F0F0Au }};
static const SSFFE25519_t _utInvX =
        {{ 0xAD7FB911u, 0xFB11017Du, 0x4EDE0633u, 0x5D18F1D1u,
           0xB75D7321u, 0xE6ECF83Cu, 0xFBA14E45u, 0x76C426C7u }};
static const SSFFE25519_t _utInvMax =
        {{ 0x67C8A600u, 0x7C8A60DDu, 0xC8A60DD6u, 0x8A60DD67u,
           0xA60DD67Cu, 0x60DD67C8u, 0x0DD67C8Au, 0x5D67C8A6u }};

/* --------------------------------------------------------------------------------------------- */
/* Asserts a == b limb for limb.                                                                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFFE25519UTEq(const SSFFE25519_t *a, const SSFFE25519_t *b)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);

    SSF_ASSERT(memcmp(a->v, b->v, sizeof(a->v)) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssffe25519 external interface.                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFFE25519UnitTest(void)
{
    SSFFE25519_t r;
    SSFFE25519_t a;
    SSFFE25519_t b;
    SSFFE25519_t one;
    uint8_t bytes[32];
    uint16_t k;

    /* ---- Contracts ---- */
    /* Mul, Sqr, Reduce, CSwap and Copy have no argument checks by design (dbc_hot_audit.txt A) */
    SSF_ASSERT_TEST(SSFFE25519Inv(NULL, &_utX));
    SSF_ASSERT_TEST(SSFFE25519Inv(&r, NULL));
    SSF_ASSERT_TEST(SSFFE25519ToBytes(NULL, &_utX));
    SSF_ASSERT_TEST(SSFFE25519ToBytes(bytes, NULL));
    SSF_ASSERT_TEST(SSFFE25519SetZero(NULL));
    SSF_ASSERT_TEST(SSFFE25519SetOne(NULL));

    /* ---- Mul / Sqr: fully reduced results, inputs up to 2^256 - 1 (Ed25519's lazy adds) ---- */
    SSFFE25519Mul(&r, &_utMax, &_utMax);
    _SSFFE25519UTEq(&r, &_utMaxSq);
    SSFFE25519Mul(&r, &_utX, &_utX);
    _SSFFE25519UTEq(&r, &_utXSq);
    SSFFE25519Mul(&r, &_utMax, &_utX);
    _SSFFE25519UTEq(&r, &_utMaxX);
    SSFFE25519Sqr(&r, &_utMax);
    _SSFFE25519UTEq(&r, &_utMaxSq);
    SSFFE25519Sqr(&r, &_utX);
    _SSFFE25519UTEq(&r, &_utXSq);

    /* r may alias an input */
    SSFFE25519Copy(&a, &_utX);
    SSFFE25519Sqr(&a, &a);
    _SSFFE25519UTEq(&a, &_utXSq);
    SSFFE25519Copy(&a, &_utMax);
    SSFFE25519Mul(&a, &a, &_utX);
    _SSFFE25519UTEq(&a, &_utMaxX);

    /* ---- Reduce: p -> 0, p - 1 kept, p + 1 -> 1, 2^255 -> 19, 2^256 - 1 -> 37 ---- */
    SSFFE25519Copy(&a, &_utP);
    SSFFE25519Reduce(&a);
    SSFFE25519SetZero(&b);
    _SSFFE25519UTEq(&a, &b);
    SSFFE25519Copy(&a, &_utP);
    a.v[0]--;
    SSFFE25519Copy(&b, &a);
    SSFFE25519Reduce(&a);
    _SSFFE25519UTEq(&a, &b);
    SSFFE25519Copy(&a, &_utP);
    a.v[0]++;
    SSFFE25519Reduce(&a);
    SSFFE25519SetOne(&one);
    _SSFFE25519UTEq(&a, &one);
    SSFFE25519SetZero(&a);
    a.v[7] = 0x80000000u;
    SSFFE25519Reduce(&a);
    SSFFE25519SetZero(&b);
    b.v[0] = 19u;
    _SSFFE25519UTEq(&a, &b);
    SSFFE25519Copy(&a, &_utMax);
    SSFFE25519Reduce(&a);
    b.v[0] = 37u;
    _SSFFE25519UTEq(&a, &b);

    /* ---- ToBytes: canonical (p encodes as zero), little-endian ---- */
    SSFFE25519ToBytes(bytes, &_utP);
    for (k = 0u; k < 32u; k++) SSF_ASSERT(bytes[k] == 0u);
    SSFFE25519ToBytes(bytes, &_utX);
    SSF_ASSERT((bytes[0] == 0xFFu) && (bytes[3] == 0x7Fu) && (bytes[4] == 0xEFu));
    SSF_ASSERT((bytes[31] == 0x5Au) && (bytes[28] == 0x5Au));

    /* ---- CSwap: only the low bit of swap counts ---- */
    SSFFE25519Copy(&a, &_utX);
    SSFFE25519Copy(&b, &_utMax);
    SSFFE25519CSwap(&a, &b, 0u);
    _SSFFE25519UTEq(&a, &_utX);
    _SSFFE25519UTEq(&b, &_utMax);
    SSFFE25519CSwap(&a, &b, 2u);
    _SSFFE25519UTEq(&a, &_utX);
    SSFFE25519CSwap(&a, &b, 1u);
    _SSFFE25519UTEq(&a, &_utMax);
    _SSFFE25519UTEq(&b, &_utX);
    SSFFE25519CSwap(&a, &b, 0xFFFFFFFFu);
    _SSFFE25519UTEq(&a, &_utX);

    /* ---- Inv: x^-1, (2^256 - 1)^-1, x * x^-1 == 1 ---- */
    SSFFE25519Inv(&r, &_utX);
    _SSFFE25519UTEq(&r, &_utInvX);
    SSFFE25519Mul(&a, &r, &_utX);
    _SSFFE25519UTEq(&a, &one);
    SSFFE25519Inv(&r, &_utMax);
    _SSFFE25519UTEq(&r, &_utInvMax);
}
#endif /* SSF_CONFIG_FE25519_UNIT_TEST */
