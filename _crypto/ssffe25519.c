/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssffe25519.c                                                                                  */
/* GF(2^255 - 19) field arithmetic shared by ssfx25519 and ssfed25519.                           */
/* One compiled copy where both modules carried their own (OPTIMIZE FE-O2).                      */
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
#include <stdint.h>
#include <string.h>
#include "ssfassert.h"
#include "ssffe25519.h"

/* p = 2^255 - 19 as 8 limbs */
const SSFFE25519_t SSF_FE25519_P = {{ 0xFFFFFFEDu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                                      0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x7FFFFFFFu }};

/* --------------------------------------------------------------------------------------------- */
/* r = a * b mod p, fully reduced; a and b may be any value below 2^256.                         */
/* --------------------------------------------------------------------------------------------- */
void SSFFE25519Mul(SSFFE25519_t *r, const SSFFE25519_t *a, const SSFFE25519_t *b)
{
    uint32_t t[16];
    uint64_t carry;
    uint8_t i, j;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);

    /* Schoolbook multiply: a * b -> t[0..15] */
    memset(t, 0, sizeof(t));
    for (i = 0; i < 8u; i++)
    {
        carry = 0;
        for (j = 0; j < 8u; j++)
        {
            uint64_t prod = (uint64_t)a->v[i] * (uint64_t)b->v[j] + (uint64_t)t[i + j] + carry;
            t[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
        t[i + 8u] += (uint32_t)carry;
    }

    /* Reduce: low = t[0..7], high = t[8..15]. result = low + 38 * high */
    carry = 0;
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)t[i] + (uint64_t)38u * (uint64_t)t[i + 8u];
        r->v[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* Carry might remain (up to ~6 bits). Fold unconditionally; carry == 0 leaves r unchanged. */
    {
        uint64_t c = carry * 38u;
        for (i = 0; i < 8u; i++)
        {
            c += (uint64_t)r->v[i];
            r->v[i] = (uint32_t)c;
            c >>= 32;
        }

        /* Fold the 0/1 carry-out of the fold above once more; it cannot carry again (X-1) */
        c *= 38u;
        for (i = 0; i < 8u; i++)
        {
            c += (uint64_t)r->v[i];
            r->v[i] = (uint32_t)c;
            c >>= 32;
        }
    }

    /* Final reduce so output is in [0, p) (handles residual fold-loop carry on edge inputs). */
    SSFFE25519Reduce(r);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^2 mod p, fully reduced; a may be any value below 2^256.                                 */
/* --------------------------------------------------------------------------------------------- */
void SSFFE25519Sqr(SSFFE25519_t *r, const SSFFE25519_t *a)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);

    SSFFE25519Mul(r, a, a);
}

/* --------------------------------------------------------------------------------------------- */
/* Reduces a (any value below 2^256) to [0, p) in place.                                         */
/* --------------------------------------------------------------------------------------------- */
void SSFFE25519Reduce(SSFFE25519_t *a)
{
    uint64_t carry;
    uint64_t borrow = 0;
    uint64_t diff;
    uint32_t t[8];
    uint32_t mask;
    uint8_t i;

    SSF_REQUIRE(a != NULL);

    /* If bit 255 is set, clear it and add 19 (since 2^255 = 19 mod p). */
    carry = (uint64_t)(a->v[7] >> 31) * 19u;
    a->v[7] &= 0x7FFFFFFFu;
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)a->v[i];
        a->v[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* Repeat in case of another overflow. */
    carry = (uint64_t)(a->v[7] >> 31) * 19u;
    a->v[7] &= 0x7FFFFFFFu;
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)a->v[i];
        a->v[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* a < 2^255 now; subtract p and conditional-select if no borrow. */
    for (i = 0; i < 8u; i++)
    {
        diff = (uint64_t)a->v[i] - (uint64_t)SSF_FE25519_P.v[i] - borrow;
        t[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }
    mask = (uint32_t)(-(int32_t)(1u - borrow));   /* all-ones if a >= p, else 0 */
    for (i = 0; i < 8u; i++)
    {
        a->v[i] = (a->v[i] & ~mask) | (t[i] & mask);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Writes a, fully reduced, to 32 little-endian bytes at b.                                      */
/* --------------------------------------------------------------------------------------------- */
void SSFFE25519ToBytes(uint8_t *b, const SSFFE25519_t *a)
{
    SSFFE25519_t t;
    uint8_t i;

    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(a != NULL);

    SSFFE25519Copy(&t, a);
    SSFFE25519Reduce(&t);
    for (i = 0; i < 8u; i++)
    {
        b[i * 4u]      = (uint8_t)(t.v[i]);
        b[i * 4u + 1u] = (uint8_t)(t.v[i] >> 8);
        b[i * 4u + 2u] = (uint8_t)(t.v[i] >> 16);
        b[i * 4u + 3u] = (uint8_t)(t.v[i] >> 24);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Swaps a and b if the low bit of swap is set, in constant time.                                */
/* --------------------------------------------------------------------------------------------- */
void SSFFE25519CSwap(SSFFE25519_t *a, SSFFE25519_t *b, uint32_t swap)
{
    uint32_t mask = (uint32_t)(0u - (swap & 1u));
    uint8_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);

    for (i = 0; i < 8u; i++)
    {
        uint32_t diff = (a->v[i] ^ b->v[i]) & mask;
        a->v[i] ^= diff;
        b->v[i] ^= diff;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^(-1) mod p by Fermat (a^(p - 2)): 255 squarings, 11 multiplies.                         */
/* --------------------------------------------------------------------------------------------- */
void SSFFE25519Inv(SSFFE25519_t *r, const SSFFE25519_t *a)
{
    SSFFE25519_t t0, t1, t2, t3;
    uint16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);

    /* a^2 */
    SSFFE25519Sqr(&t0, a);
    /* a^9 = ((a^2)^2)^2 * a */
    SSFFE25519Sqr(&t1, &t0);
    SSFFE25519Sqr(&t1, &t1);
    SSFFE25519Mul(&t1, &t1, a);
    /* a^11 = a^9 * a^2 */
    SSFFE25519Mul(&t0, &t1, &t0);
    /* a^22 = (a^11)^2 */
    SSFFE25519Sqr(&t2, &t0);
    /* a^(2^5 - 1) = a^31 = a^22 * a^9 */
    SSFFE25519Mul(&t1, &t2, &t1);
    /* a^(2^10 - 1) */
    SSFFE25519Sqr(&t2, &t1);
    for (i = 1; i < 5u; i++) SSFFE25519Sqr(&t2, &t2);
    SSFFE25519Mul(&t1, &t2, &t1);
    /* a^(2^20 - 1) */
    SSFFE25519Sqr(&t2, &t1);
    for (i = 1; i < 10u; i++) SSFFE25519Sqr(&t2, &t2);
    SSFFE25519Mul(&t2, &t2, &t1);
    /* a^(2^40 - 1) */
    SSFFE25519Sqr(&t3, &t2);
    for (i = 1; i < 20u; i++) SSFFE25519Sqr(&t3, &t3);
    SSFFE25519Mul(&t2, &t3, &t2);
    /* a^(2^50 - 1) */
    SSFFE25519Sqr(&t2, &t2);
    for (i = 1; i < 10u; i++) SSFFE25519Sqr(&t2, &t2);
    SSFFE25519Mul(&t1, &t2, &t1);
    /* a^(2^100 - 1) */
    SSFFE25519Sqr(&t2, &t1);
    for (i = 1; i < 50u; i++) SSFFE25519Sqr(&t2, &t2);
    SSFFE25519Mul(&t2, &t2, &t1);
    /* a^(2^200 - 1) */
    SSFFE25519Sqr(&t3, &t2);
    for (i = 1; i < 100u; i++) SSFFE25519Sqr(&t3, &t3);
    SSFFE25519Mul(&t2, &t3, &t2);
    /* a^(2^250 - 1) */
    SSFFE25519Sqr(&t2, &t2);
    for (i = 1; i < 50u; i++) SSFFE25519Sqr(&t2, &t2);
    SSFFE25519Mul(&t1, &t2, &t1);
    /* a^(2^255 - 21) = a^(p-2) */
    SSFFE25519Sqr(&t1, &t1);
    SSFFE25519Sqr(&t1, &t1);
    SSFFE25519Sqr(&t1, &t1);
    SSFFE25519Sqr(&t1, &t1);
    SSFFE25519Sqr(&t1, &t1);
    SSFFE25519Mul(r, &t1, &t0);
}
