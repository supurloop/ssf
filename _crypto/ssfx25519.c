/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfx25519.c                                                                                   */
/* Provides X25519 Diffie-Hellman key exchange implementation (RFC 7748).                        */
/* GF(2^255-19) arithmetic from ssffe25519 (shared with ssfed25519) plus local add / sub.        */
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
#include "ssfx25519.h"
#include "ssfcrypt.h"
#include "ssfusexport.h"

/* --------------------------------------------------------------------------------------------- */
/* Field arithmetic: GF(2^255 - 19); add, sub, import and small multiply (rest in ssffe25519)    */
/* --------------------------------------------------------------------------------------------- */
/* r = a + b. Result may be up to 2p if both inputs < p. The carry-fold runs unconditionally --  */
/* a 0-carry input degenerates to adding 0 through the limb chain, which leaves r unchanged. The */
/* fold path used to be branch-guarded; making it branch-free closes a timing channel since the  */
/* carry value depends on the secret-derived ladder operands.                                     */
static void _fe_add(SSFFE25519_t *r, const SSFFE25519_t *a, const SSFFE25519_t *b)
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
    SSFFE25519Reduce(r);
}

/* r = a - b mod p (branch-free borrow-fold; output stays in [0, 2p)). */
static void _fe_sub(SSFFE25519_t *r, const SSFFE25519_t *a, const SSFFE25519_t *b)
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

    /* Conditionally add 2p: borrow is 0 or 1, so borrow * 2 * p.v[i] is the addend. */
    for (i = 0; i < 8u; i++)
    {
        carry += (uint64_t)r->v[i] + 2u * (uint64_t)SSF_FE25519_P.v[i] * borrow;
        r->v[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* Fully reduce. See _fe_add for rationale; same Wycheproof tcId 57 sensitivity applies. */
    SSFFE25519Reduce(r);
}

/* r = a * c mod p, where c is a small uint32_t constant. */
static void _fe_mul_small(SSFFE25519_t *r, const SSFFE25519_t *a, uint32_t c)
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
    SSFFE25519Reduce(r);
}

/* Import from 32 little-endian bytes. Clears bit 255 per RFC 7748 Sec. 5: callers MUST mask the*/
/* most-significant bit of the final byte before treating the input as a u-coordinate.           */
static void _fe_from_bytes(SSFFE25519_t *a, const uint8_t *b)
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

#if (SSF_X25519_CONFIG_ENABLE_STACK_SCRUB != 0u) && (SSF_X25519_CONFIG_ENABLE_STACK_SCRUB != 1u)
#error SSF_X25519_CONFIG_ENABLE_STACK_SCRUB must be 0 or 1.
#endif

#if SSF_X25519_CONFIG_ENABLE_STACK_SCRUB == 1
#if SSF_X25519_CONFIG_STACK_SCRUB_SIZE < 1
#error SSF_X25519_CONFIG_STACK_SCRUB_SIZE must be > 0 when the stack scrub is enabled.
#endif

/* --------------------------------------------------------------------------------------------- */
/* Zeroes SSF_X25519_CONFIG_STACK_SCRUB_SIZE bytes of stack below the caller (ladder residue).   */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static void _x25519_stack_scrub(void)
{
    volatile uint8_t scratch[SSF_X25519_CONFIG_STACK_SCRUB_SIZE];
    size_t i;
    for (i = 0; i < sizeof(scratch); i++) scratch[i] = 0u;
    SSF_OPTIMIZER_BARRIER(scratch);
}
#else /* SSF_X25519_CONFIG_ENABLE_STACK_SCRUB */
/* Stack scrub disabled by configuration; call sites compile to nothing. */
#define _x25519_stack_scrub() do { } while (0)
#endif /* SSF_X25519_CONFIG_ENABLE_STACK_SCRUB */

/* --------------------------------------------------------------------------------------------- */
/* X25519 scalar multiplication (RFC 7748 Sec. 5; constant-time Montgomery ladder on x-coords).  */
/* --------------------------------------------------------------------------------------------- */
static void _x25519_scalar_mul(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t k[32];
    SSFFE25519_t x_1, x_2, z_2, x_3, z_3;
    SSFFE25519_t A, AA, B, BB, E, C, D, DA, CB, t;
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
    SSFFE25519SetOne(&x_2);
    SSFFE25519SetZero(&z_2);

    /* x_3 = u, z_3 = 1 */
    SSFFE25519Copy(&x_3, &x_1);
    SSFFE25519SetOne(&z_3);

    /* Montgomery ladder: bit 254 down to bit 0 */
    for (i = 254; i >= 0; i--)
    {
        uint32_t bit = (uint32_t)((k[i >> 3] >> (i & 7)) & 1u);

        SSFFE25519CSwap(&x_2, &x_3, swap ^ bit);
        SSFFE25519CSwap(&z_2, &z_3, swap ^ bit);
        swap = bit;

        _fe_add(&A, &x_2, &z_2);
        SSFFE25519Sqr(&AA, &A);
        _fe_sub(&B, &x_2, &z_2);
        SSFFE25519Sqr(&BB, &B);
        _fe_sub(&E, &AA, &BB);
        _fe_add(&C, &x_3, &z_3);
        _fe_sub(&D, &x_3, &z_3);
        SSFFE25519Mul(&DA, &D, &A);
        SSFFE25519Mul(&CB, &C, &B);

        _fe_add(&t, &DA, &CB);
        SSFFE25519Sqr(&x_3, &t);
        _fe_sub(&t, &DA, &CB);
        SSFFE25519Sqr(&t, &t);
        SSFFE25519Mul(&z_3, &x_1, &t);

        SSFFE25519Mul(&x_2, &AA, &BB);

        /* z_2 = E * (AA + a24 * E), where a24 = 121665 */
        _fe_mul_small(&t, &E, 121665u);
        _fe_add(&t, &AA, &t);
        SSFFE25519Mul(&z_2, &E, &t);
    }

    SSFFE25519CSwap(&x_2, &x_3, swap);
    SSFFE25519CSwap(&z_2, &z_3, swap);

    /* Result = x_2 * z_2^(-1) */
    SSFFE25519Inv(&z_2, &z_2);
    SSFFE25519Mul(&x_2, &x_2, &z_2);
    SSFFE25519ToBytes(out, &x_2);

    /* Zeroize the clamped scalar plus every SSFFE25519_t local that touched the secret. */
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
bool SSFX25519ComputeSecret(const uint8_t privKey[32], const uint8_t peerPubKey[32],
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

