/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfx25519_ut.c                                                                                */
/* Provides unit tests for the ssfx25519 X25519 module.                                          */
/* Test vectors from RFC 7748 Section 6.1.                                                       */
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
#include <stdio.h>
#include "ssfassert.h"
#include "ssfx25519.h"
#include "ssfsha2.h"

/* Cross-validate X25519 derive / pubkey-from-priv against OpenSSL on host builds where         */
/* libcrypto is linked. Same gating pattern as ssfecdsa_ut.c / ssfed25519_ut.c.                  */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_X25519_UNIT_TEST == 1)
#define SSF_X25519_OSSL_VERIFY 1
#else
#define SSF_X25519_OSSL_VERIFY 0
#endif

#if SSF_X25519_OSSL_VERIFY == 1
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#if SSF_CONFIG_X25519_UNIT_TEST == 1

#if SSF_X25519_OSSL_VERIFY == 1
/* --------------------------------------------------------------------------------------------- */
/* X25519 OpenSSL cross-check helpers.                                                            */
/* OpenSSL exposes X25519 only through the EVP one-shot API: a 32-byte private key becomes an    */
/* opaque EVP_PKEY via EVP_PKEY_new_raw_private_key, key derivation runs through                 */
/* EVP_PKEY_derive after EVP_PKEY_derive_set_peer.                                                */
/* --------------------------------------------------------------------------------------------- */
static EVP_PKEY *_X25519OSSLPrivFromBytes(const uint8_t priv[32])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    SSF_ASSERT(pkey != NULL);
    return pkey;
}

static EVP_PKEY *_X25519OSSLPubFromBytes(const uint8_t pub[32])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, 32);
    SSF_ASSERT(pkey != NULL);
    return pkey;
}

static void _X25519OSSLDerive(EVP_PKEY *priv, EVP_PKEY *peer, uint8_t out[32])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    size_t outLen = 32;
    SSF_ASSERT(ctx != NULL);
    SSF_ASSERT(EVP_PKEY_derive_init(ctx) == 1);
    SSF_ASSERT(EVP_PKEY_derive_set_peer(ctx, peer) == 1);
    SSF_ASSERT(EVP_PKEY_derive(ctx, out, &outLen) == 1);
    SSF_ASSERT(outLen == 32);
    EVP_PKEY_CTX_free(ctx);
}

static void _X25519OSSLPubFromPriv(const uint8_t priv[32], uint8_t pubOut[32])
{
    EVP_PKEY *p = _X25519OSSLPrivFromBytes(priv);
    size_t pubLen = 32;
    SSF_ASSERT(EVP_PKEY_get_raw_public_key(p, pubOut, &pubLen) == 1);
    SSF_ASSERT(pubLen == 32);
    EVP_PKEY_free(p);
}

/* --------------------------------------------------------------------------------------------- */
/* Random fuzz: per iteration draw two random privs and check that SSF and OpenSSL agree on      */
/* both pubkey-from-priv and the ECDH shared secret in both directions.                          */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyX25519AgainstOpenSSL(uint16_t iters)
{
    uint16_t iter;

    SSF_UT_PRINTF("--- ssfx25519 OpenSSL cross-check (%u iters, bidirectional) ---\n",
           (unsigned)iters);

    for (iter = 0; iter < iters; iter++)
    {
        uint8_t privA[32], privB[32];
        uint8_t pubSSF_A[32], pubSSF_B[32];
        uint8_t pubOSSL_A[32], pubOSSL_B[32];
        uint8_t secretSSF[32], secretOSSL[32];

        SSF_ASSERT(RAND_bytes(privA, 32) == 1);
        SSF_ASSERT(RAND_bytes(privB, 32) == 1);

        /* === Pubkey-from-priv must match byte-for-byte === */
        SSFX25519PubKeyFromPrivKey(privA, pubSSF_A);
        SSFX25519PubKeyFromPrivKey(privB, pubSSF_B);
        _X25519OSSLPubFromPriv(privA, pubOSSL_A);
        _X25519OSSLPubFromPriv(privB, pubOSSL_B);
        SSF_ASSERT(memcmp(pubSSF_A, pubOSSL_A, 32) == 0);
        SSF_ASSERT(memcmp(pubSSF_B, pubOSSL_B, 32) == 0);

        /* === SSF derives → OpenSSL derives → must match (privA, pubB direction) === */
        SSF_ASSERT(SSFX25519ComputeSecret(privA, pubSSF_B, secretSSF) == true);
        {
            EVP_PKEY *opriv = _X25519OSSLPrivFromBytes(privA);
            EVP_PKEY *opub  = _X25519OSSLPubFromBytes(pubSSF_B);
            _X25519OSSLDerive(opriv, opub, secretOSSL);
            EVP_PKEY_free(opriv);
            EVP_PKEY_free(opub);
        }
        SSF_ASSERT(memcmp(secretSSF, secretOSSL, 32) == 0);

        /* === Reverse direction (privB, pubA) — sanity check on commutativity through both === */
        SSF_ASSERT(SSFX25519ComputeSecret(privB, pubSSF_A, secretSSF) == true);
        {
            EVP_PKEY *opriv = _X25519OSSLPrivFromBytes(privB);
            EVP_PKEY *opub  = _X25519OSSLPubFromBytes(pubSSF_A);
            _X25519OSSLDerive(opriv, opub, secretOSSL);
            EVP_PKEY_free(opriv);
            EVP_PKEY_free(opub);
        }
        SSF_ASSERT(memcmp(secretSSF, secretOSSL, 32) == 0);
    }

    SSF_UT_PRINTF("--- end ssfx25519 OpenSSL cross-check ---\n");
}
#endif /* SSF_X25519_OSSL_VERIFY */

/* --------------------------------------------------------------------------------------------- */
/* Stack scrub probe helpers (X3 regression). Polluter writes a sentinel pattern into a deep     */
/* frame, returns; ComputeSecret runs at the same call depth and must scrub its freed frame      */
/* before returning. The scanner allocates a deep frame at the same depth and reads its          */
/* uninitialised contents — those reflect what the previous frame at that depth wrote. After     */
/* scrub the sentinel count must drop to near-zero; pre-scrub thousands of bytes survive.        */
/*                                                                                               */
/* The sentinel value MUST NOT be 0xCC: MSVC's /RTC1 (Debug runtime checks) initializes every    */
/* stack frame with 0xCCCCCCCC on entry, so 0xCC bytes in the scanner would be indistinguishable */
/* from the polluter's writes versus RTC1's own fill. 0xAB is arbitrary and outside both the     */
/* RTC1 fill (0xCC) and the heap-debug fill (0xFD / 0xCD).                                       */
/*                                                                                               */
/* The polluter and scanner also disable /RTC1 for their own bodies via                          */
/* `#pragma runtime_checks("scu", off)`. With RTC1 active MSVC writes 0xCC into every newly      */
/* allocated stack frame on function entry — including the scanner's `buf` — which would erase   */
/* the bytes the polluter just wrote at the same stack offset, making the test always read 0    */
/* sentinels regardless of whether the scrub helper ran.                                          */
/* --------------------------------------------------------------------------------------------- */
#define _SSFX25519_UT_STACK_PROBE_SIZE (4096u)
#define _SSFX25519_UT_SENTINEL         (0xABu)

#if defined(_MSC_VER)
#pragma runtime_checks("scu", off)
#endif

SSF_NOINLINE
static void _SSFX25519UTPolluteStack(uint8_t pattern)
{
    volatile uint8_t buf[_SSFX25519_UT_STACK_PROBE_SIZE];
    size_t i;
    for (i = 0; i < sizeof(buf); i++) buf[i] = pattern;
    SSF_OPTIMIZER_BARRIER(buf);
}

/* Reading uninitialized stack is the test — silence GCC/clang's -Wuninitialized and MSVC       */
/* /analyze's C6001 for this body.                                                              */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 6001)
#endif
SSF_NOINLINE
static size_t _SSFX25519UTCountSentinel(uint8_t pattern)
{
    volatile uint8_t buf[_SSFX25519_UT_STACK_PROBE_SIZE];
    size_t hits = 0;
    size_t i;
    /* The volatile reads in the loop force the compiler to materialize buf at a real stack     */
    /* slot, so a pre-loop barrier is not required (and would warn C4700 reading uninitialised  */
    /* memory under the MSVC variant of SSF_OPTIMIZER_BARRIER).                                 */
    for (i = 0; i < sizeof(buf); i++)
    {
        if (buf[i] == pattern) hits++;
    }
    return hits;
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#if defined(_MSC_VER)
#pragma runtime_checks("scu", restore)
#endif

/* --------------------------------------------------------------------------------------------- */
/* SSF-internal deterministic fuzz. Runs without OpenSSL. Uses ECDH's commutative property as    */
/* the oracle: privA·pubB must byte-equal privB·pubA. State is advanced via a SHA-512 chain      */
/* from a fixed master seed so failures reproduce across runs.                                    */
/* --------------------------------------------------------------------------------------------- */
static void _X25519SelfFuzz(uint16_t iters)
{
    uint8_t state[64];
    uint16_t iter;

    SSF_UT_PRINTF("--- ssfx25519 self-fuzz (%u iters, deterministic) ---\n", (unsigned)iters);

    memset(state, 0xA5u, sizeof(state));

    for (iter = 0; iter < iters; iter++)
    {
        uint8_t privA[32], privB[32];
        uint8_t pubA[32], pubB[32];
        uint8_t secretA[32], secretB[32];

        /* Advance state := SHA-512(state || iter). */
        {
            uint8_t in[66];
            memcpy(in, state, 64);
            in[64] = (uint8_t)(iter);
            in[65] = (uint8_t)(iter >> 8);
            SSFSHA512(in, sizeof(in), state, 64);
        }

        memcpy(privA, state, 32);
        memcpy(privB, state + 32, 32);

        SSFX25519PubKeyFromPrivKey(privA, pubA);
        SSFX25519PubKeyFromPrivKey(privB, pubB);

        /* Commutative property: privA · pubB == privB · pubA. */
        SSF_ASSERT(SSFX25519ComputeSecret(privA, pubB, secretA) == true);
        SSF_ASSERT(SSFX25519ComputeSecret(privB, pubA, secretB) == true);
        SSF_ASSERT(memcmp(secretA, secretB, 32) == 0);
    }

    SSF_UT_PRINTF("--- end ssfx25519 self-fuzz ---\n");
}

void SSFX25519UnitTest(void)
{
    /* ---- RFC 7748 Section 6.1: Test Vector 1 ---- */
    {
        /* Alice's private key */
        static const uint8_t privA[] = {
            0x77u, 0x07u, 0x6Du, 0x0Au, 0x73u, 0x18u, 0xA5u, 0x7Du,
            0x3Cu, 0x16u, 0xC1u, 0x72u, 0x51u, 0xB2u, 0x66u, 0x45u,
            0xDFu, 0x4Cu, 0x2Fu, 0x87u, 0xEBu, 0xC0u, 0x99u, 0x2Au,
            0xB1u, 0x77u, 0xFBu, 0xA5u, 0x1Du, 0xB9u, 0x2Cu, 0x2Au
        };
        /* Alice's public key = privA * basepoint */
        static const uint8_t expectedPubA[] = {
            0x85u, 0x20u, 0xF0u, 0x09u, 0x89u, 0x30u, 0xA7u, 0x54u,
            0x74u, 0x8Bu, 0x7Du, 0xDCu, 0xB4u, 0x3Eu, 0xF7u, 0x5Au,
            0x0Du, 0xBFu, 0x3Au, 0x0Du, 0x26u, 0x38u, 0x1Au, 0xF4u,
            0xEBu, 0xA4u, 0xA9u, 0x8Eu, 0xAAu, 0x9Bu, 0x4Eu, 0x6Au
        };
        /* Bob's private key */
        static const uint8_t privB[] = {
            0x5Du, 0xABu, 0x08u, 0x7Eu, 0x62u, 0x4Au, 0x8Au, 0x4Bu,
            0x79u, 0xE1u, 0x7Fu, 0x8Bu, 0x83u, 0x80u, 0x0Eu, 0xE6u,
            0x6Fu, 0x3Bu, 0xB1u, 0x29u, 0x26u, 0x18u, 0xB6u, 0xFDu,
            0x1Cu, 0x2Fu, 0x8Bu, 0x27u, 0xFFu, 0x88u, 0xE0u, 0xEBu
        };
        /* Bob's public key = privB * basepoint */
        static const uint8_t expectedPubB[] = {
            0xDEu, 0x9Eu, 0xDBu, 0x7Du, 0x7Bu, 0x7Du, 0xC1u, 0xB4u,
            0xD3u, 0x5Bu, 0x61u, 0xC2u, 0xECu, 0xE4u, 0x35u, 0x37u,
            0x3Fu, 0x83u, 0x43u, 0xC8u, 0x5Bu, 0x78u, 0x67u, 0x4Du,
            0xADu, 0xFCu, 0x7Eu, 0x14u, 0x6Fu, 0x88u, 0x2Bu, 0x4Fu
        };
        /* Shared secret = privA * pubB = privB * pubA */
        static const uint8_t expectedSecret[] = {
            0x4Au, 0x5Du, 0x9Du, 0x5Bu, 0xA4u, 0xCEu, 0x2Du, 0xE1u,
            0x72u, 0x8Eu, 0x3Bu, 0xF4u, 0x80u, 0x35u, 0x0Fu, 0x25u,
            0xE0u, 0x7Eu, 0x21u, 0xC9u, 0x47u, 0xD1u, 0x9Eu, 0x33u,
            0x76u, 0xF0u, 0x9Bu, 0x3Cu, 0x1Eu, 0x16u, 0x17u, 0x42u
        };
        uint8_t pubA[32], pubB[32], secretA[32], secretB[32];

        /* Compute public keys */
        SSFX25519PubKeyFromPrivKey(privA, pubA);
        SSF_ASSERT(memcmp(pubA, expectedPubA, 32) == 0);

        SSFX25519PubKeyFromPrivKey(privB, pubB);
        SSF_ASSERT(memcmp(pubB, expectedPubB, 32) == 0);

        /* Compute shared secrets from both sides */
        SSF_ASSERT(SSFX25519ComputeSecret(privA, pubB, secretA) == true);
        SSF_ASSERT(SSFX25519ComputeSecret(privB, pubA, secretB) == true);

        SSF_ASSERT(memcmp(secretA, expectedSecret, 32) == 0);
        SSF_ASSERT(memcmp(secretB, expectedSecret, 32) == 0);
    }

    /* ---- RFC 7748 Section 5.2: Iterated test (1 iteration as sanity check) ---- */
    {
        /* Start: k = u = 9 (basepoint) */
        uint8_t k[32] = { 9 };
        uint8_t out[32];

        /* After 1 iteration: k = X25519(9, 9) */
        static const uint8_t expected1[] = {
            0x42u, 0x2Cu, 0x8Eu, 0x7Au, 0x62u, 0x27u, 0xD7u, 0xBCu,
            0xA1u, 0x35u, 0x0Bu, 0x3Eu, 0x2Bu, 0xB7u, 0x27u, 0x9Fu,
            0x78u, 0x97u, 0xB8u, 0x7Bu, 0xB6u, 0x85u, 0x4Bu, 0x78u,
            0x3Cu, 0x60u, 0xE8u, 0x03u, 0x11u, 0xAEu, 0x30u, 0x79u
        };

        SSFX25519PubKeyFromPrivKey(k, out);
        /* out = X25519(k=9, u_basepoint=9) */
        SSF_ASSERT(memcmp(out, expected1, 32) == 0);
    }

    /* ---- RFC 7748 §5.2 Iterated test: 1000 iterations ---- */
    /* Per RFC: k = u = 9 initially; each iter computes new_k = X25519(k, u) then sets u = old k.*/
    /* Expected final k after 1000 iters: 684CF59BA83309552800EF566F2F4D3C1C3887C49360E3875F2EB94D99532C51 */
    {
        uint8_t k[32] = { 9 };
        uint8_t u[32] = { 9 };
        uint8_t newK[32];
        uint8_t prevK[32];
        uint16_t i;

        static const uint8_t expected1000[] = {
            0x68u, 0x4Cu, 0xF5u, 0x9Bu, 0xA8u, 0x33u, 0x09u, 0x55u,
            0x28u, 0x00u, 0xEFu, 0x56u, 0x6Fu, 0x2Fu, 0x4Du, 0x3Cu,
            0x1Cu, 0x38u, 0x87u, 0xC4u, 0x93u, 0x60u, 0xE3u, 0x87u,
            0x5Fu, 0x2Eu, 0xB9u, 0x4Du, 0x99u, 0x53u, 0x2Cu, 0x51u
        };

        for (i = 0; i < 1000u; i++)
        {
            memcpy(prevK, k, 32);
            SSF_ASSERT(SSFX25519ComputeSecret(k, u, newK) == true);
            memcpy(u, prevK, 32);
            memcpy(k, newK, 32);
        }
        SSF_ASSERT(memcmp(k, expected1000, 32) == 0);
    }

    /* ---- Key generation + ECDHE roundtrip ---- */
    {
        uint8_t privA[32], pubA[32];
        uint8_t privB[32], pubB[32];
        uint8_t secretA[32], secretB[32];

        SSF_ASSERT(SSFX25519KeyGen(privA, pubA) == true);
        SSF_ASSERT(SSFX25519KeyGen(privB, pubB) == true);

        /* Shared secrets must match */
        SSF_ASSERT(SSFX25519ComputeSecret(privA, pubB, secretA) == true);
        SSF_ASSERT(SSFX25519ComputeSecret(privB, pubA, secretB) == true);
        SSF_ASSERT(memcmp(secretA, secretB, 32) == 0);
    }

    /* ---- All-zero peer key rejection ---- */
    {
        uint8_t priv[32], pub[32], secret[32];
        uint8_t zeroPub[32];

        SSF_ASSERT(SSFX25519KeyGen(priv, pub) == true);
        memset(zeroPub, 0, 32);
        SSF_ASSERT(SSFX25519ComputeSecret(priv, zeroPub, secret) == false);
    }

    /* ---- X10b: low-order peer-key rejection coverage. */
    /* The 7 known small-order encodings on Curve25519 / its twist (per libsodium's              */
    /* has_small_order_blocklist). RFC 7748 §6.1's all-zero-output check rejects any peer key   */
    /* that produces a zero shared secret; the design assumption is that all small-order points  */
    /* satisfy that. This test verifies the assumption empirically — if any entry comes back as  */
    /* a non-rejected (true) result, that's evidence the all-zero check is insufficient and we   */
    /* need an explicit input blocklist (X6).                                                     */
    {
        static const uint8_t lowOrderPub[][32] = {
            /* 0 — order 4. */
            { 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0 },
            /* 1 — order 4 on twist. */
            { 1, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0 },
            /* 325606250916557431795983626356110631294008115727848805560023387167927233504 — order 8. */
            { 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
              0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
              0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
              0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
            /* 39382357235489614581723060781553021112529911719440698176882885853963445705823 — order 8. */
            { 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
              0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
              0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
              0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
            /* p-1 — order 4. */
            { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
            /* p — equivalent to 0 mod p. */
            { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
            /* p+1 — equivalent to 1 mod p. */
            { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        };
        uint8_t priv[32], pub[32], secret[32];
        size_t i;

        SSF_ASSERT(SSFX25519KeyGen(priv, pub) == true);
        for (i = 0; i < sizeof(lowOrderPub) / sizeof(lowOrderPub[0]); i++)
        {
            SSF_ASSERT(SSFX25519ComputeSecret(priv, lowOrderPub[i], secret) == false);
        }
    }

    /* ---- Pub key derivation consistency ---- */
    {
        uint8_t priv[32], pub1[32], pub2[32];

        SSF_ASSERT(SSFX25519KeyGen(priv, pub1) == true);
        SSFX25519PubKeyFromPrivKey(priv, pub2);
        SSF_ASSERT(memcmp(pub1, pub2, 32) == 0);
    }

    /* ---- X3 regression: ComputeSecret performs a deep-stack scrub before returning.    */
    /* The Montgomery ladder leaves ~14 _fe_t locals (~448 bytes) in its freed frame, all  */
    /* derived from the secret scalar. Sentinel-residue test sandwiches a ComputeSecret    */
    /* call between a polluter (writes 0xCC into a 4 KiB deep frame) and a scanner (counts */
    /* surviving 0xCC bytes at the same call depth). After the scrub helper executes, the */
    /* count must drop to near zero.                                                        */
    {
        uint8_t priv[32], pub[32], peerPriv[32], peerPub[32], secret[32];
        size_t hitsAfter;

        SSF_ASSERT(SSFX25519KeyGen(priv, pub) == true);
        SSF_ASSERT(SSFX25519KeyGen(peerPriv, peerPub) == true);

        _SSFX25519UTPolluteStack(_SSFX25519_UT_SENTINEL);
        SSF_ASSERT(SSFX25519ComputeSecret(priv, peerPub, secret) == true);
        hitsAfter = _SSFX25519UTCountSentinel(_SSFX25519_UT_SENTINEL);

        /* Pre-fix: thousands of sentinels survive (no scrub). Post-fix: scrub helper      */
        /* zeroes the deep region; small residue tolerated for scanner's own frame layout. */
        /*                                                                                  */
        /* The threshold is platform-tuned. On GCC/clang the call-frame overhead between    */
        /* the polluter and the scrub is ~50 bytes, so residue stays well under 64. MSVC    */
        /* /RTC1 + /GS produce ~80–400 byte frame overheads (RTC1 fill on padding, /GS      */
        /* canaries, larger spill slots) that are NOT secret-bearing — they're saved-reg    */
        /* values, return addresses, and uninit fill — but they happen to fall inside the   */
        /* polluter's address range and get counted. 512 is comfortably below the ~4 KiB    */
        /* unscrubbed total and still rejects a regression that disabled the scrub.          */
#if defined(_MSC_VER)
        SSF_ASSERT(hitsAfter < 512u);
#else
        SSF_ASSERT(hitsAfter < 64u);
#endif
    }

    /* SSF-internal deterministic ECDH fuzz. Independent of OpenSSL — exercises the              */
    /* commutative property privA·pubB == privB·pubA across 256 deterministic random keypairs.   */
    _X25519SelfFuzz(256u);

    /* === Wycheproof X25519 vectors (Google adversarial test suite) === */
    /* X25519 has 264 "valid" cases (must match expected shared byte-for-byte) and 254             */
    /* "acceptable" cases (RFC 7748 doesn't strictly require either accept or reject — typically   */
    /* twist points / low-order edge cases). 0 "invalid" cases for X25519. This harness asserts    */
    /* zero new mismatches on the valid set; acceptable cases are tracked separately and don't     */
    /* count toward mismatches either way.                                                          */
    {
        #include "wycheproof_x25519.h"
        uint8_t secret[32];
        uint16_t i;
        uint16_t pass = 0, mismatches = 0, acceptableAccepted = 0, acceptableRejected = 0;

        SSF_UT_PRINTF("--- Wycheproof X25519 (%u tests) ---\n",
               (unsigned)SSF_WYCHEPROOF_X25519_NTESTS);
        for (i = 0; i < (uint16_t)SSF_WYCHEPROOF_X25519_NTESTS; i++)
        {
            const _SSFWycheproofX25519Test_t *t = &_wp_X25519_tests[i];
            bool got, sharedOk = false;

            got = SSFX25519ComputeSecret(t->privKey, t->pubKey, secret);
            if (got) sharedOk = (memcmp(secret, t->shared, t->sharedLen) == 0);

            if (t->acceptable)
            {
                /* Either accept (with any output) or reject is RFC-compliant. Track stats only. */
                if (got) acceptableAccepted++;
                else     acceptableRejected++;
                continue;
            }

            /* expectedValid == true: must accept and shared must match.                          */
            /* expectedValid == false (none today for X25519, future-proof): must reject.        */
            {
                bool expectedOk = t->expectedValid ? (got && sharedOk) : (!got);
                if (expectedOk) pass++;
                else
                {
                    mismatches++;
                    SSF_UT_PRINTF("  tcId %4u: expected %s, got %s\n",
                           (unsigned)t->tcId,
                           t->expectedValid ? "valid" : "invalid",
                           got ? (sharedOk ? "valid" : "wrong-shared") : "rejected");
                }
            }
        }
        SSF_UT_PRINTF("--- Wycheproof X25519: %u pass, %u acceptable-accepted, "
               "%u acceptable-rejected, %u mismatches ---\n",
               (unsigned)pass, (unsigned)acceptableAccepted,
               (unsigned)acceptableRejected, (unsigned)mismatches);
        SSF_ASSERT(mismatches == 0u);
    }

#if SSF_X25519_OSSL_VERIFY == 1
    /* Comprehensive OpenSSL cross-check: random privs, byte-equal pubkeys, byte-equal shared    */
    /* secrets in both directions. Catches any divergence in scalar clamping, ladder formulae,    */
    /* field-arithmetic carry handling, or output reduction.                                       */
    _VerifyX25519AgainstOpenSSL(64u);
#endif
}
#endif /* SSF_CONFIG_X25519_UNIT_TEST */
