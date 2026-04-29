/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfx25519.c                                                                                   */
/* Provides X25519 Diffie-Hellman key exchange implementation (RFC 7748).                        */
/* Self-contained with dedicated GF(2^255-19) field arithmetic.                                  */
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
#include "ssfx25519.h"
#include "ssfcrypt.h"
#include "ssfusexport.h"

/* --------------------------------------------------------------------------------------------- */
/* Field element: 256 bits in 8 x 32-bit limbs, little-endian limb order.                       */
/* Values are in [0, 2p) during computation; fully reduced to [0, p) at export.                  */
/* p = 2^255 - 19                                                                                */
/* --------------------------------------------------------------------------------------------- */
typedef struct { uint32_t v[8]; } _fe_t;

/* p = 2^255 - 19 as 8 limbs */
static const _fe_t _fe_p = {{ 0xFFFFFFEDu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                              0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x7FFFFFFFu }};

/* Forward declaration for _fe_reduce (used by _fe_mul to fully reduce its output). */
static void _fe_reduce(_fe_t *a);

/* --------------------------------------------------------------------------------------------- */
/* Field arithmetic: GF(2^255 - 19) (mirrors helpers in ssfed25519.c).                           */
/* --------------------------------------------------------------------------------------------- */
static void _fe_0(_fe_t *r)
{
    memset(r->v, 0, sizeof(r->v));
}

static void _fe_1(_fe_t *r)
{
    memset(r->v, 0, sizeof(r->v));
    r->v[0] = 1u;
}

static void _fe_copy(_fe_t *r, const _fe_t *a)
{
    memcpy(r->v, a->v, sizeof(r->v));
}

/* r = a + b. Result may be up to 2p if both inputs < p. The carry-fold runs unconditionally --  */
/* a 0-carry input degenerates to adding 0 through the limb chain, which leaves r unchanged. The */
/* fold path used to be branch-guarded; making it branch-free closes a timing channel since the  */
/* carry value depends on the secret-derived ladder operands.                                     */
static void _fe_add(_fe_t *r, const _fe_t *a, const _fe_t *b)
{
    uint64_t carry = 0;
    uint8_t i;
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)a->v[i] + (uint64_t)b->v[i];
        r->v[i] = (uint32_t)carry;
        carry >>= 32;
    }
    /* 2^256 mod p = 2 * 19 = 38. carry is 0 or 1; multiply unconditionally. */
    {
        uint64_t c = 38u * carry;
        for (i = 0; i < 8u; i++)
        {
            c += (uint64_t)r->v[i];
            r->v[i] = (uint32_t)c;
            c >>= 32;
        }
    }

    /* Fully reduce so output is in [0, p) (required for downstream _fe_mul bounds). */
    _fe_reduce(r);
}

/* r = a - b mod p (branch-free borrow-fold; output stays in [0, 2p)). */
static void _fe_sub(_fe_t *r, const _fe_t *a, const _fe_t *b)
{
    uint64_t borrow = 0;
    uint64_t carry = 0;
    uint8_t i;

    for (i = 0; i < 8u; i++)
    {
        uint64_t diff = (uint64_t)a->v[i] - (uint64_t)b->v[i] - borrow;
        r->v[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }

    /* Conditionally add 2p: borrow is 0 or 1, so (borrow * 2 * _fe_p.v[i]) is the addend. */
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)r->v[i] + 2u * (uint64_t)_fe_p.v[i] * borrow;
        r->v[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* Fully reduce. See _fe_add for rationale; same Wycheproof tcId 57 sensitivity applies. */
    _fe_reduce(r);
}

/* r = a * b mod p. Schoolbook 8x8 multiply with fast reduction by 38. */
static void _fe_mul(_fe_t *r, const _fe_t *a, const _fe_t *b)
{
    uint32_t t[16];
    uint64_t carry;
    uint8_t i, j;

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
    }

    /* Final reduce so output is in [0, p) (handles residual fold-loop carry on edge inputs). */
    _fe_reduce(r);
}

/* r = a^2 mod p. Optimized: cross-terms computed once and doubled. */
static void _fe_sqr(_fe_t *r, const _fe_t *a)
{
    _fe_mul(r, a, a);
}

/* r = a * c mod p, where c is a small uint32_t constant. */
static void _fe_mul_small(_fe_t *r, const _fe_t *a, uint32_t c)
{
    uint64_t carry = 0;
    uint8_t i;

    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)a->v[i] * (uint64_t)c;
        r->v[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* Fold carry back: carry * 38 mod p. Unconditional -- carry == 0 leaves r unchanged. */
    {
        uint64_t c2 = carry * 38u;
        for (i = 0; i < 8u; i++)
        {
            c2 += (uint64_t)r->v[i];
            r->v[i] = (uint32_t)c2;
            c2 >>= 32;
        }
    }

    /* Reduce to [0, p) (same residual-carry concern as _fe_mul). */
    _fe_reduce(r);
}

/* Fully reduce a to [0, p). */
static void _fe_reduce(_fe_t *a)
{
    uint64_t carry;
    uint64_t borrow = 0;
    uint64_t diff;
    uint32_t t[8];
    uint32_t mask;
    uint8_t i;

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
        diff = (uint64_t)a->v[i] - (uint64_t)_fe_p.v[i] - borrow;
        t[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }
    mask = (uint32_t)(-(int32_t)(1u - borrow));   /* all-ones if a >= p, else 0 */
    for (i = 0; i < 8u; i++)
    {
        a->v[i] = (a->v[i] & ~mask) | (t[i] & mask);
    }
}

/* Import from 32 little-endian bytes. Clears bit 255 per RFC 7748 Sec. 5: callers MUST mask the*/
/* most-significant bit of the final byte before treating the input as a u-coordinate.           */
static void _fe_from_bytes(_fe_t *a, const uint8_t *b)
{
    uint8_t i;
    for (i = 0; i < 8u; i++)
    {
        a->v[i] = ((uint32_t)b[i * 4u]) |
                  ((uint32_t)b[i * 4u + 1u] << 8) |
                  ((uint32_t)b[i * 4u + 2u] << 16) |
                  ((uint32_t)b[i * 4u + 3u] << 24);
    }
    a->v[7] &= 0x7FFFFFFFu;
}

/* Export to 32 little-endian bytes. Fully reduces first. */
static void _fe_to_bytes(uint8_t *b, const _fe_t *a)
{
    _fe_t t;
    uint8_t i;
    _fe_copy(&t, a);
    _fe_reduce(&t);
    for (i = 0; i < 8u; i++)
    {
        b[i * 4u]      = (uint8_t)(t.v[i]);
        b[i * 4u + 1u] = (uint8_t)(t.v[i] >> 8);
        b[i * 4u + 2u] = (uint8_t)(t.v[i] >> 16);
        b[i * 4u + 3u] = (uint8_t)(t.v[i] >> 24);
    }
}

/* Constant-time conditional swap: if the low bit of swap is set, exchange a and b. Mask         */
/* construction (-(swap & 1u) cast to uint32_t) yields all-ones when bit 0 is set, all-zero      */
/* otherwise -- no compiler-emitted branch on the secret bit.                                    */
static void _fe_cswap(_fe_t *a, _fe_t *b, uint32_t swap)
{
    uint32_t mask = (uint32_t)(0u - (swap & 1u));
    uint8_t i;
    for (i = 0; i < 8u; i++)
    {
        uint32_t diff = (a->v[i] ^ b->v[i]) & mask;
        a->v[i] ^= diff;
        b->v[i] ^= diff;
    }
}

/* r = a^(-1) mod p via Fermat's little theorem: a^(p-2) mod p.                                 */
/* Uses an addition chain for p-2 = 2^255 - 21.                                                 */
/* Total: 255 squarings + 11 multiplications.                                                    */
static void _fe_inv(_fe_t *r, const _fe_t *a)
{
    _fe_t t0, t1, t2, t3;
    uint16_t i;

    /* a^2 */
    _fe_sqr(&t0, a);
    /* a^9 = ((a^2)^2)^2 * a */
    _fe_sqr(&t1, &t0);
    _fe_sqr(&t1, &t1);
    _fe_mul(&t1, &t1, a);
    /* a^11 = a^9 * a^2 */
    _fe_mul(&t0, &t1, &t0);
    /* a^22 = (a^11)^2 */
    _fe_sqr(&t2, &t0);
    /* a^(2^5 - 1) = a^31 = a^22 * a^9 */
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^10 - 1) */
    _fe_sqr(&t2, &t1);
    for (i = 1; i < 5u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^20 - 1) */
    _fe_sqr(&t2, &t1);
    for (i = 1; i < 10u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t2, &t2, &t1);
    /* a^(2^40 - 1) */
    _fe_sqr(&t3, &t2);
    for (i = 1; i < 20u; i++) _fe_sqr(&t3, &t3);
    _fe_mul(&t2, &t3, &t2);
    /* a^(2^50 - 1) */
    _fe_sqr(&t2, &t2);
    for (i = 1; i < 10u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^100 - 1) */
    _fe_sqr(&t2, &t1);
    for (i = 1; i < 50u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t2, &t2, &t1);
    /* a^(2^200 - 1) */
    _fe_sqr(&t3, &t2);
    for (i = 1; i < 100u; i++) _fe_sqr(&t3, &t3);
    _fe_mul(&t2, &t3, &t2);
    /* a^(2^250 - 1) */
    _fe_sqr(&t2, &t2);
    for (i = 1; i < 50u; i++) _fe_sqr(&t2, &t2);
    _fe_mul(&t1, &t2, &t1);
    /* a^(2^255 - 21) = a^(p-2) */
    _fe_sqr(&t1, &t1);
    _fe_sqr(&t1, &t1);
    _fe_sqr(&t1, &t1);
    _fe_sqr(&t1, &t1);
    _fe_sqr(&t1, &t1);
    _fe_mul(r, &t1, &t0);
}

/* --------------------------------------------------------------------------------------------- */
/* Scrubs the deeper-stack region used by the Montgomery ladder.                                 */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static void _x25519_stack_scrub(void)
{
    volatile uint8_t scratch[4096];
    size_t i;
    for (i = 0; i < sizeof(scratch); i++) scratch[i] = 0u;
    SSF_OPTIMIZER_BARRIER(scratch);
}

/* --------------------------------------------------------------------------------------------- */
/* X25519 scalar multiplication (RFC 7748 Sec. 5; constant-time Montgomery ladder on x-coords).  */
/* --------------------------------------------------------------------------------------------- */
static void _x25519_scalar_mul(uint8_t out[32], const uint8_t scalar[32],
                               const uint8_t point[32])
{
    uint8_t k[32];
    _fe_t x_1, x_2, z_2, x_3, z_3;
    _fe_t A, AA, B, BB, E, C, D, DA, CB, t;
    int16_t i;
    uint32_t swap = 0;

    /* Copy and clamp the scalar */
    memcpy(k, scalar, 32);
    k[0]  &= 248u;
    k[31] &= 127u;
    k[31] |= 64u;

    /* Import the u-coordinate */
    _fe_from_bytes(&x_1, point);

    /* Initialize: x_2 = 1, z_2 = 0 (point at infinity) */
    _fe_1(&x_2);
    _fe_0(&z_2);

    /* x_3 = u, z_3 = 1 */
    _fe_copy(&x_3, &x_1);
    _fe_1(&z_3);

    /* Montgomery ladder: bit 254 down to bit 0 */
    for (i = 254; i >= 0; i--)
    {
        uint32_t bit = (uint32_t)((k[i >> 3] >> (i & 7)) & 1u);

        _fe_cswap(&x_2, &x_3, swap ^ bit);
        _fe_cswap(&z_2, &z_3, swap ^ bit);
        swap = bit;

        _fe_add(&A, &x_2, &z_2);
        _fe_sqr(&AA, &A);
        _fe_sub(&B, &x_2, &z_2);
        _fe_sqr(&BB, &B);
        _fe_sub(&E, &AA, &BB);
        _fe_add(&C, &x_3, &z_3);
        _fe_sub(&D, &x_3, &z_3);
        _fe_mul(&DA, &D, &A);
        _fe_mul(&CB, &C, &B);

        _fe_add(&t, &DA, &CB);
        _fe_sqr(&x_3, &t);
        _fe_sub(&t, &DA, &CB);
        _fe_sqr(&t, &t);
        _fe_mul(&z_3, &x_1, &t);

        _fe_mul(&x_2, &AA, &BB);

        /* z_2 = E * (AA + a24 * E), where a24 = 121665 */
        _fe_mul_small(&t, &E, 121665u);
        _fe_add(&t, &AA, &t);
        _fe_mul(&z_2, &E, &t);
    }

    _fe_cswap(&x_2, &x_3, swap);
    _fe_cswap(&z_2, &z_3, swap);

    /* Result = x_2 * z_2^(-1) */
    _fe_inv(&z_2, &z_2);
    _fe_mul(&x_2, &x_2, &z_2);
    _fe_to_bytes(out, &x_2);

    /* Zeroize the clamped scalar plus every _fe_t local that touched the secret. */
    SSFCryptSecureZero(k, sizeof(k));
    SSFCryptSecureZero(&x_1, sizeof(x_1));
    SSFCryptSecureZero(&x_2, sizeof(x_2));
    SSFCryptSecureZero(&z_2, sizeof(z_2));
    SSFCryptSecureZero(&x_3, sizeof(x_3));
    SSFCryptSecureZero(&z_3, sizeof(z_3));
    SSFCryptSecureZero(&A, sizeof(A));
    SSFCryptSecureZero(&AA, sizeof(AA));
    SSFCryptSecureZero(&B, sizeof(B));
    SSFCryptSecureZero(&BB, sizeof(BB));
    SSFCryptSecureZero(&E, sizeof(E));
    SSFCryptSecureZero(&C, sizeof(C));
    SSFCryptSecureZero(&D, sizeof(D));
    SSFCryptSecureZero(&DA, sizeof(DA));
    SSFCryptSecureZero(&CB, sizeof(CB));
    SSFCryptSecureZero(&t, sizeof(t));
    /* Deep-frame scrub is invoked at the public-API boundary (one frame shallower). */
}

/* --------------------------------------------------------------------------------------------- */
/* Generate an X25519 key pair.                                                                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFX25519KeyGen(uint8_t privKey[32], uint8_t pubKey[32])
{
    static const uint8_t basepoint[32] = { 9 }; /* u = 9 */

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(pubKey != NULL);

    if (!SSFPortGetEntropy(privKey, 32u)) return false;

    _x25519_scalar_mul(pubKey, privKey, basepoint);
    _x25519_stack_scrub();
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Compute the public key from a private key.                                                    */
/* --------------------------------------------------------------------------------------------- */
void SSFX25519PubKeyFromPrivKey(const uint8_t privKey[32], uint8_t pubKey[32])
{
    static const uint8_t basepoint[32] = { 9 };

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(pubKey != NULL);

    _x25519_scalar_mul(pubKey, privKey, basepoint);
    _x25519_stack_scrub();
}

/* --------------------------------------------------------------------------------------------- */
/* Compute X25519 shared secret.                                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFX25519ComputeSecret(const uint8_t privKey[32],
                            const uint8_t peerPubKey[32],
                            uint8_t secret[32])
{
    uint8_t i;
    uint8_t zero = 0;

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(peerPubKey != NULL);
    SSF_REQUIRE(secret != NULL);

    _x25519_scalar_mul(secret, privKey, peerPubKey);
    _x25519_stack_scrub();

    /* Check for all-zero output (low-order point attack) */
    for (i = 0; i < 32u; i++) zero |= secret[i];
    if (zero == 0u) return false;

    return true;
}

