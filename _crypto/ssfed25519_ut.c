/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfed25519_ut.c                                                                               */
/* Provides unit tests for the ssfed25519 Ed25519 module.                                        */
/* Test vectors from RFC 8032 Section 7.1.                                                       */
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
#include "ssfed25519.h"
#include "ssfsha2.h"

/* Cross-validate Ed25519 sign / verify / pubkey-from-seed against OpenSSL when it is linked */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_ED25519_UNIT_TEST == 1)
#define SSF_ED25519_OSSL_VERIFY 1
#else
#define SSF_ED25519_OSSL_VERIFY 0
#endif

#if SSF_ED25519_OSSL_VERIFY == 1
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#if SSF_CONFIG_ED25519_UNIT_TEST == 1

/* Stack scrub probe (B1): polluter fills a deep frame; scanner counts survivors at that depth */
#define _SSFED25519_UT_STACK_PROBE_SIZE (SSF_ED25519_CONFIG_STACK_SCRUB_SIZE)
/* Not 0xCC (MSVC /RTC1 frame fill) nor 0xFD / 0xCD (MSVC heap-debug fill) */
#define _SSFED25519_UT_SENTINEL (0xABu)

/* Stack bounds assume optimized frames; unoptimized MSVC and ASan builds enlarge them (E-5) */
#if (defined(_MSC_VER) && defined(_DEBUG)) || defined(__SANITIZE_ADDRESS__)
#define _SSFED25519_UT_STACK_BOUNDS (0u)
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define _SSFED25519_UT_STACK_BOUNDS (0u)
#else
#define _SSFED25519_UT_STACK_BOUNDS (1u)
#endif
#else
#define _SSFED25519_UT_STACK_BOUNDS (1u)
#endif

/* /RTC1 would refill the scanner's frame with 0xCC on entry, erasing the polluter's bytes */
#if defined(_MSC_VER)
#pragma runtime_checks("scu", off)
#endif

/* --------------------------------------------------------------------------------------------- */
/* Fills a scrub-sized deep stack frame with pattern.                                            */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static void _SSFEd25519UTPolluteStack(uint8_t pattern)
{
    volatile uint8_t buf[_SSFED25519_UT_STACK_PROBE_SIZE];
    size_t i;
    for (i = 0; i < sizeof(buf); i++) buf[i] = pattern;
    SSF_OPTIMIZER_BARRIER(buf);
}

/* Reading uninitialized stack is the test; silence -Wuninitialized and MSVC C6001 here */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#endif
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 6001)
#endif
/* --------------------------------------------------------------------------------------------- */
/* Returns the number of bytes equal to pattern in an uninitialized scrub-sized stack frame.     */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static size_t _SSFEd25519UTCountSentinel(uint8_t pattern)
{
    volatile uint8_t buf[_SSFED25519_UT_STACK_PROBE_SIZE];
    size_t hits = 0;
    size_t i;
    /* Volatile reads materialize buf; a pre-loop barrier would warn C4700 on MSVC */
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

/* Stack high-water-mark probe (AUDIT X-2/E-4): peak is size minus deepest overwritten index */
#define _SSFED25519_UT_HWM_PROBE_SIZE (8192u)

#if defined(_MSC_VER)
#pragma runtime_checks("scu", off)
#endif

/* --------------------------------------------------------------------------------------------- */
/* Fills an 8 KiB deep stack frame with pattern.                                                 */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static void _SSFEd25519UTPolluteDeep(uint8_t pattern)
{
    volatile uint8_t buf[_SSFED25519_UT_HWM_PROBE_SIZE];
    size_t i;
    for (i = 0; i < sizeof(buf); i++) buf[i] = pattern;
    SSF_OPTIMIZER_BARRIER(buf);
}

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#endif
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 6001)
#endif
/* --------------------------------------------------------------------------------------------- */
/* Returns the stack bytes used since _SSFEd25519UTPolluteDeep(), or 0 if none were touched.     */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static size_t _SSFEd25519UTStackUsed(uint8_t pattern)
{
    volatile uint8_t buf[_SSFED25519_UT_HWM_PROBE_SIZE];
    size_t i;
    for (i = 0; i < sizeof(buf); i++)
    {
        /* Is this the deepest byte the operation overwrote? */
        if (buf[i] != pattern)
        {
            /* Yes, everything from here up to the frame top was used. */
            return sizeof(buf) - i;
        }
        /* No, still untouched sentinel; keep scanning upward. */
    }
    return 0u;
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

#if SSF_ED25519_OSSL_VERIFY == 1
/* --------------------------------------------------------------------------------------------- */
/* Returns an OpenSSL EVP_PKEY private key for a 32-byte seed.                                   */
/* --------------------------------------------------------------------------------------------- */
static EVP_PKEY *_Ed25519OSSLPrivFromSeed(const uint8_t seed[32])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    SSF_ASSERT(pkey != NULL);
    return pkey;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns an OpenSSL EVP_PKEY public key for a 32-byte SSF pubKey.                              */
/* --------------------------------------------------------------------------------------------- */
static EVP_PKEY *_Ed25519OSSLPubFromBytes(const uint8_t pub[32])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    SSF_ASSERT(pkey != NULL);
    return pkey;
}

/* --------------------------------------------------------------------------------------------- */
/* Signs msg with OpenSSL (EVP_DigestSign, NULL md) into the 64-byte out.                        */
/* --------------------------------------------------------------------------------------------- */
static void _Ed25519OSSLSign(EVP_PKEY *priv, const uint8_t *msg, size_t msgLen,
                              uint8_t out[64])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t sigLen = 64;
    SSF_ASSERT(ctx != NULL);
    SSF_ASSERT(EVP_DigestSignInit(ctx, NULL, NULL, NULL, priv) == 1);
    SSF_ASSERT(EVP_DigestSign(ctx, out, &sigLen, msg, msgLen) == 1);
    SSF_ASSERT(sigLen == 64);
    EVP_MD_CTX_free(ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if OpenSSL accepts sig over msg under pub, else false.                           */
/* --------------------------------------------------------------------------------------------- */
static bool _Ed25519OSSLVerify(EVP_PKEY *pub, const uint8_t *msg, size_t msgLen,
                                const uint8_t sig[64])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int r;
    SSF_ASSERT(ctx != NULL);
    SSF_ASSERT(EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pub) == 1);
    r = EVP_DigestVerify(ctx, sig, 64, msg, msgLen);
    EVP_MD_CTX_free(ctx);
    return (r == 1);
}

/* --------------------------------------------------------------------------------------------- */
/* Computes with OpenSSL the public key of seed.                                                 */
/* --------------------------------------------------------------------------------------------- */
static void _Ed25519OSSLPubFromSeed(const uint8_t seed[32], uint8_t pubOut[32])
{
    EVP_PKEY *priv = _Ed25519OSSLPrivFromSeed(seed);
    size_t pubLen = 32;
    SSF_ASSERT(EVP_PKEY_get_raw_public_key(priv, pubOut, &pubLen) == 1);
    SSF_ASSERT(pubLen == 32);
    EVP_PKEY_free(priv);
}

/* --------------------------------------------------------------------------------------------- */
/* Checks SSF against OpenSSL on random seeds and messages in every sign / verify direction.     */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyEd25519AgainstOpenSSL(uint16_t iters)
{
    uint16_t iter;

    SSF_UT_PRINTF("--- ssfed25519 OpenSSL cross-check (%u iters, bidirectional) ---\n",
           (unsigned)iters);

    for (iter = 0; iter < iters; iter++)
    {
        uint8_t seed[32];
        uint8_t msg[256];
        size_t  msgLen;
        uint8_t pubSSF[32];
        uint8_t pubOSSL[32];
        uint8_t sigSSF[64];
        uint8_t sigOSSL[64];

        /* Random seed and random message of length 0..255. */
        SSF_ASSERT(RAND_bytes(seed, 32) == 1);
        SSF_ASSERT(RAND_bytes(msg, sizeof(msg)) == 1);
        msgLen = (size_t)(msg[0]);  /* arbitrary 0..255 */

        /* === Pubkey-from-seed must match byte-for-byte === */
        SSFEd25519PubKeyFromSeed(seed, pubSSF);
        _Ed25519OSSLPubFromSeed(seed, pubOSSL);
        SSF_ASSERT(memcmp(pubSSF, pubOSSL, 32) == 0);

        /* === SSF signs -> OpenSSL verifies === */
        SSF_ASSERT(SSFEd25519Sign(seed, pubSSF, msg, msgLen, sigSSF) == true);
        {
            EVP_PKEY *opub = _Ed25519OSSLPubFromBytes(pubSSF);
            SSF_ASSERT(_Ed25519OSSLVerify(opub, msg, msgLen, sigSSF) == true);
            EVP_PKEY_free(opub);
        }

        /* === OpenSSL signs (deterministic per RFC 8032, so byte-equal to SSF) === */
        {
            EVP_PKEY *opriv = _Ed25519OSSLPrivFromSeed(seed);
            _Ed25519OSSLSign(opriv, msg, msgLen, sigOSSL);
            EVP_PKEY_free(opriv);
        }
        SSF_ASSERT(memcmp(sigSSF, sigOSSL, 64) == 0);

        /* === SSF verifies the OpenSSL-produced sig === */
        SSF_ASSERT(SSFEd25519Verify(pubSSF, msg, msgLen, sigOSSL) == true);

        /* === Negative: a 1-bit flip in the sig must be rejected by both sides === */
        sigSSF[(iter % 64u)] ^= 0x01u;
        SSF_ASSERT(SSFEd25519Verify(pubSSF, msg, msgLen, sigSSF) == false);
        {
            EVP_PKEY *opub = _Ed25519OSSLPubFromBytes(pubSSF);
            SSF_ASSERT(_Ed25519OSSLVerify(opub, msg, msgLen, sigSSF) == false);
            EVP_PKEY_free(opub);
        }
    }

    SSF_UT_PRINTF("--- end ssfed25519 OpenSSL cross-check ---\n");
}
#endif /* SSF_ED25519_OSSL_VERIFY */

/* --------------------------------------------------------------------------------------------- */
/* Checks sign / verify / mutation rejection for 0..2048-byte messages from a SHA-512 chain.     */
/* --------------------------------------------------------------------------------------------- */
static void _Ed25519SelfFuzz(uint16_t iters)
{
    uint8_t state[64];
    uint16_t iter;

    SSF_UT_PRINTF("--- ssfed25519 self-fuzz (%u iters, deterministic) ---\n", (unsigned)iters);

    /* Fixed master state -- any nonzero pattern is fine; the SHA-512 chain mixes thoroughly. */
    memset(state, 0xA5u, sizeof(state));

    for (iter = 0; iter < iters; iter++)
    {
        uint8_t seed[32];
        uint8_t pubKey[32];
        uint8_t sig[64];
        static uint8_t msg[2048];
        size_t msgLen;
        uint8_t origByte;
        size_t flipPos;

        /* Advance state := SHA-512(state || iter). */
        {
            uint8_t in[66];
            memcpy(in, state, 64);
            in[64] = (uint8_t)(iter);
            in[65] = (uint8_t)(iter >> 8);
            SSFSHA512(in, sizeof(in), state, 64);
        }

        /* Derive seed from low 32 bytes of state, msgLen from bytes 32..33 mod (2048+1). */
        memcpy(seed, state, 32);
        msgLen = (((size_t)state[32] << 8) | (size_t)state[33]) % (sizeof(msg) + 1u);

        /* Fill msg with deterministic bytes by chaining SHA-512(state || chunkIdx) into msg. */
        {
            size_t filled = 0;
            uint16_t chunkIdx = 0;
            uint8_t chunk[64];
            while (filled < msgLen)
            {
                uint8_t fillIn[66];
                size_t take;
                memcpy(fillIn, state, 64);
                fillIn[64] = (uint8_t)(chunkIdx);
                fillIn[65] = (uint8_t)(chunkIdx >> 8);
                SSFSHA512(fillIn, sizeof(fillIn), chunk, 64);
                take = msgLen - filled;
                if (take > sizeof(chunk)) take = sizeof(chunk);
                memcpy(&msg[filled], chunk, take);
                filled += take;
                chunkIdx++;
            }
        }

        /* Round-trip: sign, verify. Both must succeed. */
        SSFEd25519PubKeyFromSeed(seed, pubKey);
        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, msg, msgLen, sig) == true);
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, msgLen, sig) == true);

        /* Mutation 1: flip a sig byte at a deterministic position. */
        flipPos = (size_t)state[34] % 64u;
        origByte = sig[flipPos];
        sig[flipPos] ^= 0x55u;
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, msgLen, sig) == false);
        sig[flipPos] = origByte;

        /* Mutation 2: flip a pubKey byte (other point, non-canonical y or low order all reject) */
        flipPos = (size_t)state[35] % 32u;
        origByte = pubKey[flipPos];
        pubKey[flipPos] ^= 0x55u;
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, msgLen, sig) == false);
        pubKey[flipPos] = origByte;

        /* Mutation 3: flip a msg byte (only when msgLen > 0). */
        if (msgLen > 0u)
        {
            flipPos = (((size_t)state[36] << 8) | (size_t)state[37]) % msgLen;
            origByte = msg[flipPos];
            msg[flipPos] ^= 0x55u;
            SSF_ASSERT(SSFEd25519Verify(pubKey, msg, msgLen, sig) == false);
            msg[flipPos] = origByte;
        }
    }

    SSF_UT_PRINTF("--- end ssfed25519 self-fuzz ---\n");
}

/* --------------------------------------------------------------------------------------------- */
/* Converts the first outLen * 2 hex digits of hex to outLen bytes at out.                       */
/* --------------------------------------------------------------------------------------------- */
static void _HexToBytes(const char *hex, uint8_t *out, size_t outLen)
{
    size_t i;
    for (i = 0; i < outLen; i++)
    {
        uint8_t hi = (hex[i * 2] >= 'a') ? (uint8_t)((hex[i * 2] - 'a') + 10) :
                     (hex[i * 2] >= 'A') ? (uint8_t)((hex[i * 2] - 'A') + 10) :
                     (uint8_t)(hex[i * 2] - '0');
        uint8_t lo = (hex[(i * 2) + 1] >= 'a') ? (uint8_t)((hex[(i * 2) + 1] - 'a') + 10) :
                     (hex[(i * 2) + 1] >= 'A') ? (uint8_t)((hex[(i * 2) + 1] - 'A') + 10) :
                     (uint8_t)(hex[(i * 2) + 1] - '0');

        out[i] = (uint8_t)((hi << 4) | lo);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfed25519 external interface.                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFEd25519UnitTest(void)
{
    /* ---- OPTIMIZE ED-O1: scalar reduce / multiply-add mod L edge cases vs Python oracles ---- */
    {
        static const uint8_t _lBytes[32] = {
            0xEDu, 0xD3u, 0xF5u, 0x5Cu, 0x1Au, 0x63u, 0x12u, 0x58u,
            0xD6u, 0x9Cu, 0xF7u, 0xA2u, 0xDEu, 0xF9u, 0xDEu, 0x14u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x10u
        };
        static const uint8_t _rAllOnes[32] = {
            0x00u, 0x0Fu, 0x9Cu, 0x44u, 0xE3u, 0x11u, 0x06u, 0xA4u,
            0x47u, 0x93u, 0x85u, 0x68u, 0xA7u, 0x1Bu, 0x0Eu, 0xD0u,
            0x65u, 0xBEu, 0xF5u, 0x17u, 0xD2u, 0x73u, 0xECu, 0xCEu,
            0x3Du, 0x9Au, 0x30u, 0x7Cu, 0x1Bu, 0x41u, 0x99u, 0x03u
        };
        static const uint8_t _rMixed[32] = {
            0xB0u, 0x34u, 0xF5u, 0xDAu, 0x21u, 0x20u, 0xA9u, 0xEBu,
            0xB6u, 0xC1u, 0x21u, 0x0Eu, 0x20u, 0xACu, 0x7Cu, 0x13u,
            0x1Eu, 0xDFu, 0xFAu, 0x0Bu, 0xE9u, 0x39u, 0x76u, 0xE7u,
            0x1Eu, 0x4Du, 0x18u, 0xBEu, 0x8Du, 0xA0u, 0xCCu, 0x09u
        };
        static const uint8_t _mAllOnes[32] = {
            0xD1u, 0x4Du, 0xF9u, 0x13u, 0x89u, 0x43u, 0x2Cu, 0x25u,
            0xADu, 0x60u, 0xFFu, 0x97u, 0x91u, 0xB9u, 0xFDu, 0x1Du,
            0x67u, 0xBEu, 0xF5u, 0x17u, 0xD2u, 0x73u, 0xECu, 0xCEu,
            0x3Du, 0x9Au, 0x30u, 0x7Cu, 0x1Bu, 0x41u, 0x99u, 0x03u
        };
        static const uint8_t _mA[32] = {
            0xB1u, 0x68u, 0xDEu, 0x3Au, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x2Eu, 0x1Du, 0x3Cu, 0x5Fu, 0x00u, 0x00u, 0x00u
        };
        static const uint8_t _mB[32] = {
            0x90u, 0x56u, 0xF8u, 0x58u, 0x67u, 0x4Cu, 0xA5u, 0x5Au,
            0x05u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x40u
        };
        static const uint8_t _mC[32] = {
            0xEBu, 0xD3u, 0xF5u, 0x5Cu, 0x1Au, 0x63u, 0x12u, 0x58u,
            0xD6u, 0x9Cu, 0xF7u, 0xA2u, 0xDEu, 0xF9u, 0xDEu, 0x14u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x10u
        };
        static const uint8_t _mExp[32] = {
            0x7Eu, 0x73u, 0x07u, 0x12u, 0x70u, 0x06u, 0xB1u, 0x20u,
            0x0Cu, 0xBFu, 0x52u, 0xE2u, 0x44u, 0xE8u, 0x78u, 0x35u,
            0x2Du, 0xEAu, 0x24u, 0xEBu, 0x20u, 0x26u, 0x3Du, 0xDCu,
            0xC5u, 0xB6u, 0x31u, 0xC9u, 0x51u, 0xDDu, 0x37u, 0x05u
        };
        uint8_t buf[64];
        uint8_t a[32];
        uint8_t b[32];
        uint8_t c[32];
        uint8_t out[32];
        uint8_t lm1[32];
        uint16_t k;
        uint16_t carry;

        /* lm1 = L - 1 (L's low byte is 0xED, so no borrow) */
        memcpy(lm1, _lBytes, 32);
        lm1[0]--;

        /* reduce(0) = 0 */
        memset(buf, 0, sizeof(buf));
        _SSFEd25519ScReduceForTest(buf);
        for (k = 0u; k < 64u; k++) SSF_ASSERT(buf[k] == 0u);

        /* reduce(L - 1) = L - 1 */
        memset(buf, 0, sizeof(buf));
        memcpy(buf, lm1, 32);
        _SSFEd25519ScReduceForTest(buf);
        SSF_ASSERT(memcmp(buf, lm1, 32) == 0);
        for (k = 32u; k < 64u; k++) SSF_ASSERT(buf[k] == 0u);

        /* reduce(L) = 0 */
        memset(buf, 0, sizeof(buf));
        memcpy(buf, _lBytes, 32);
        _SSFEd25519ScReduceForTest(buf);
        for (k = 0u; k < 32u; k++) SSF_ASSERT(buf[k] == 0u);

        /* reduce(2^252) = 2^252: bit 252 (byte 31 bit 4) survives */
        memset(buf, 0, sizeof(buf));
        buf[31] = 0x10u;
        _SSFEd25519ScReduceForTest(buf);
        for (k = 0u; k < 31u; k++) SSF_ASSERT(buf[k] == 0u);
        SSF_ASSERT(buf[31] == 0x10u);

        /* reduce(6 * L - 1) = L - 1: 6 * L - 1 = 5 * L + (L - 1), built bytewise */
        memset(buf, 0, sizeof(buf));
        carry = 0u;
        for (k = 0u; k < 32u; k++)
        {
            carry = (uint16_t)(carry + (6u * (uint16_t)_lBytes[k]));
            buf[k] = (uint8_t)carry;
            carry >>= 8;
        }
        buf[32] = (uint8_t)carry;
        buf[0]--;
        _SSFEd25519ScReduceForTest(buf);
        SSF_ASSERT(memcmp(buf, lm1, 32) == 0);

        /* reduce(2^512 - 1) */
        memset(buf, 0xFF, sizeof(buf));
        _SSFEd25519ScReduceForTest(buf);
        SSF_ASSERT(memcmp(buf, _rAllOnes, 32) == 0);

        /* The upper half, which held the rest of the secret nonce hash, is cleared */
        for (k = 32u; k < 64u; k++) SSF_ASSERT(buf[k] == 0u);

        /* reduce(2^511 + 2^260 + 12345) */
        memset(buf, 0, sizeof(buf));
        buf[0] = 0x39u;
        buf[1] = 0x30u;
        buf[32] = 0x10u;
        buf[63] = 0x80u;
        _SSFEd25519ScReduceForTest(buf);
        SSF_ASSERT(memcmp(buf, _rMixed, 32) == 0);

        /* muladd((2^256 - 1), (2^256 - 1), (2^256 - 1)) */
        memset(a, 0xFF, 32);
        memset(b, 0xFF, 32);
        memset(c, 0xFF, 32);
        _SSFEd25519ScMulAddForTest(out, a, b, c);
        SSF_ASSERT(memcmp(out, _mAllOnes, 32) == 0);

        /* muladd(L - 1, L - 1, L - 1) = (L - 1) * L = 0 mod L */
        _SSFEd25519ScMulAddForTest(out, lm1, lm1, lm1);
        for (k = 0u; k < 32u; k++) SSF_ASSERT(out[k] == 0u);

        /* muladd(0, 0, L - 1) = L - 1 */
        memset(a, 0, 32);
        memset(b, 0, 32);
        _SSFEd25519ScMulAddForTest(out, a, b, lm1);
        SSF_ASSERT(memcmp(out, lm1, 32) == 0);

        /* muladd with a clamped-style 2^254 + ... operand, c = L - 2 */
        _SSFEd25519ScMulAddForTest(out, _mA, _mB, _mC);
        SSF_ASSERT(memcmp(out, _mExp, 32) == 0);

        /* out may alias an input, as Sign's S = h * a + r does not but a caller could */
        memcpy(a, _mA, 32);
        _SSFEd25519ScMulAddForTest(a, a, _mB, _mC);
        SSF_ASSERT(memcmp(a, _mExp, 32) == 0);
    }

    /* ---- AUDIT E-1: Mul second-fold carry (r + 38c >= 2^256), via test-only wrappers ---- */
    {
        static const uint8_t feA[32] = {
            0x0Fu, 0x11u, 0xCCu, 0xEAu, 0xFEu, 0x34u, 0x75u, 0xF0u,
            0xC0u, 0xD9u, 0x41u, 0x4Cu, 0xE9u, 0x6Fu, 0x6Cu, 0xBEu,
            0x90u, 0x47u, 0x80u, 0x28u, 0xEFu, 0x43u, 0x8Au, 0x6Au,
            0x97u, 0xF4u, 0x9Fu, 0x90u, 0x4Fu, 0x51u, 0x13u, 0x18u
        };
        static const uint8_t feB[32] = {
            0x33u, 0x74u, 0x9Du, 0xB5u, 0x57u, 0xF2u, 0x0Du, 0xA6u,
            0xBCu, 0xA7u, 0x16u, 0x5Au, 0x68u, 0x78u, 0x32u, 0x37u,
            0xE1u, 0x71u, 0x7Fu, 0x08u, 0x25u, 0x5Bu, 0x00u, 0x82u,
            0x5Cu, 0x8Bu, 0x45u, 0x3Bu, 0xC5u, 0x1Du, 0xCFu, 0x7Fu
        };
        /* y whose y^2 hit the dropped carry; RFC 8032 decodes it, the defect rejected it. */
        static const uint8_t yFail[32] = {
            0xDBu, 0xA1u, 0x3Eu, 0x72u, 0xA7u, 0xEBu, 0xA4u, 0x8Du,
            0x5Eu, 0xA1u, 0xD6u, 0xB1u, 0xD4u, 0x36u, 0x3Du, 0x1Fu,
            0x5Du, 0xFBu, 0xE3u, 0xC0u, 0xD8u, 0x3Au, 0x29u, 0x72u,
            0x1Eu, 0x9Au, 0x06u, 0x9Fu, 0xC5u, 0x0Fu, 0xDBu, 0x59u
        };
        static const uint8_t xFail[32] = {
            0x9Au, 0x2Eu, 0xBEu, 0x1Au, 0x7Bu, 0xABu, 0xBDu, 0x71u,
            0x17u, 0x8Du, 0x7Bu, 0x31u, 0xDCu, 0x9Fu, 0xDEu, 0xA9u,
            0xBDu, 0xDFu, 0x5Cu, 0x06u, 0x7Au, 0x03u, 0x2Du, 0xBEu,
            0x3Du, 0x58u, 0x1Cu, 0x2Du, 0xA9u, 0xACu, 0xCFu, 0x32u
        };
        /* y whose y^2 hit the dropped carry; the defect decoded it to the wrong x. */
        static const uint8_t yWrong[32] = {
            0x18u, 0xA2u, 0x03u, 0xB3u, 0x87u, 0x46u, 0x68u, 0x15u,
            0xDCu, 0xF8u, 0x6Bu, 0x1Au, 0x42u, 0x6Bu, 0x0Eu, 0x6Au,
            0x98u, 0x8Au, 0x5Du, 0x43u, 0xF3u, 0xC3u, 0x07u, 0x2Cu,
            0x1Eu, 0x55u, 0x3Fu, 0x37u, 0x7Bu, 0x54u, 0xDFu, 0x6Bu
        };
        static const uint8_t xWrong[32] = {
            0x74u, 0xAEu, 0x2Bu, 0xD2u, 0x93u, 0x85u, 0xF7u, 0xE7u,
            0xC8u, 0x75u, 0xA3u, 0xA7u, 0x5Du, 0x4Bu, 0x55u, 0x64u,
            0xAEu, 0x8Eu, 0x58u, 0x93u, 0xFAu, 0xD8u, 0x91u, 0x12u,
            0x91u, 0x52u, 0x2Fu, 0x10u, 0x2Au, 0xACu, 0xD1u, 0x76u
        };
        uint8_t expect[32];
        uint8_t out[32];

        /* a * b mod p == 0x43 (the defect returned 0x1d). */
        memset(expect, 0, sizeof(expect));
        expect[0] = 0x43u;
        _SSFEd25519FeMulForTest(out, feA, feB);
        SSF_ASSERT(memcmp(out, expect, sizeof(expect)) == 0);

        SSF_ASSERT(_SSFEd25519GeDecodeForTest(out, yFail) == true);
        SSF_ASSERT(memcmp(out, xFail, sizeof(xFail)) == 0);
        SSF_ASSERT(_SSFEd25519GeDecodeForTest(out, yWrong) == true);
        SSF_ASSERT(memcmp(out, xWrong, sizeof(xWrong)) == 0);
    }

    /* ---- AUDIT E-3: FeIsZero on x = 2^31 must not negate INT32_MIN (seen under UBSan) ---- */
    {
        static const uint8_t yX2pow31[32] = {
            0x87u, 0xD9u, 0x9Cu, 0xADu, 0x33u, 0x29u, 0xDDu, 0xF0u,
            0xC1u, 0xC1u, 0xADu, 0xB2u, 0xC4u, 0x7Au, 0x50u, 0x47u,
            0x34u, 0x95u, 0x6Au, 0xD5u, 0xF0u, 0x76u, 0xD8u, 0x20u,
            0x87u, 0x7Bu, 0xB6u, 0xD6u, 0x32u, 0xC9u, 0x5Eu, 0x26u
        };
        uint8_t xGot[32];
        uint8_t xWant[32];

        memset(xWant, 0, sizeof(xWant));
        xWant[3] = 0x80u; /* x = 2^31, little-endian */
        SSF_ASSERT(_SSFEd25519GeDecodeForTest(xGot, yX2pow31) == true);
        SSF_ASSERT(memcmp(xGot, xWant, sizeof(xWant)) == 0);
    }

    /* ---- RFC 8032 Test Vector 1: empty message ---- */
    {
        uint8_t seed[32];
        uint8_t expectedPub[32];
        uint8_t expectedSig[64];
        uint8_t pubKey[32];
        uint8_t sig[64];

        _HexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                     seed, 32);
        _HexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                     expectedPub, 32);
        _HexToBytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                     expectedSig, 64);

        /* Derive public key */
        SSFEd25519PubKeyFromSeed(seed, pubKey);
        SSF_ASSERT(memcmp(pubKey, expectedPub, 32) == 0);

        /* Sign empty message */
        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, NULL, 0, sig) == true);
        SSF_ASSERT(memcmp(sig, expectedSig, 64) == 0);

        /* Verify */
        SSF_ASSERT(SSFEd25519Verify(pubKey, NULL, 0, sig) == true);

        /* Verify fails with wrong pubkey */
        pubKey[0] ^= 0x01u;
        SSF_ASSERT(SSFEd25519Verify(pubKey, NULL, 0, sig) == false);
    }

    /* ---- RFC 8032 Test Vector 2: 1-byte message ---- */
    {
        uint8_t seed[32];
        uint8_t expectedPub[32];
        uint8_t expectedSig[64];
        uint8_t pubKey[32];
        uint8_t sig[64];
        uint8_t msg[] = { 0x72u };

        _HexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                     seed, 32);
        _HexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                     expectedPub, 32);
        _HexToBytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                     expectedSig, 64);

        SSFEd25519PubKeyFromSeed(seed, pubKey);
        SSF_ASSERT(memcmp(pubKey, expectedPub, 32) == 0);

        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, msg, sizeof(msg), sig) == true);
        SSF_ASSERT(memcmp(sig, expectedSig, 64) == 0);

        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg), sig) == true);

        /* Verify fails with wrong message */
        msg[0] = 0x73u;
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg), sig) == false);
    }

    /* ---- RFC 8032 Test Vector 3: 2-byte message ---- */
    {
        uint8_t seed[32];
        uint8_t expectedPub[32];
        uint8_t expectedSig[64];
        uint8_t pubKey[32];
        uint8_t sig[64];
        uint8_t msg[] = { 0xAFu, 0x82u };

        _HexToBytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                     seed, 32);
        _HexToBytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                     expectedPub, 32);
        _HexToBytes("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                     expectedSig, 64);

        SSFEd25519PubKeyFromSeed(seed, pubKey);
        SSF_ASSERT(memcmp(pubKey, expectedPub, 32) == 0);

        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, msg, sizeof(msg), sig) == true);
        SSF_ASSERT(memcmp(sig, expectedSig, 64) == 0);

        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg), sig) == true);
    }

    /* ---- RFC 8032 Sec. 7.1 Test Vector 4: 1023-byte message (long-message handling) ---- */
    {
        static uint8_t tv4Msg[1023];
        uint8_t seed[32];
        uint8_t expectedPub[32];
        uint8_t expectedSig[64];
        uint8_t pubKey[32];
        uint8_t sig[64];

        _HexToBytes("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
                     seed, 32);
        _HexToBytes("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
                     expectedPub, 32);
        _HexToBytes("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
                     "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
                     expectedSig, 64);
        _HexToBytes(
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
            "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
            "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
            "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
            "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
            "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
            "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
            "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
            "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
            "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
            "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
            "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
            "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
            "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
            "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
            "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
            "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
            "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
            "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
            "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
            "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
            "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
            "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
            "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
            "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
            "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
            "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
            "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
            "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
            "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
            "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
            "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
            tv4Msg, sizeof(tv4Msg));

        SSFEd25519PubKeyFromSeed(seed, pubKey);
        SSF_ASSERT(memcmp(pubKey, expectedPub, 32) == 0);

        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, tv4Msg, sizeof(tv4Msg), sig) == true);
        SSF_ASSERT(memcmp(sig, expectedSig, 64) == 0);

        SSF_ASSERT(SSFEd25519Verify(pubKey, tv4Msg, sizeof(tv4Msg), sig) == true);
    }

    /* ---- KeyGen round-trip ---- */
    {
        uint8_t seed[32];
        uint8_t pubKey[32];
        uint8_t pubKey2[32];
        uint8_t sig[64];
        const uint8_t msg[] = "Hello Ed25519";

        SSF_ASSERT(SSFEd25519KeyGen(seed, pubKey) == true);

        /* Derive again should match */
        SSFEd25519PubKeyFromSeed(seed, pubKey2);
        SSF_ASSERT(memcmp(pubKey, pubKey2, 32) == 0);

        /* Sign and verify */
        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, msg, sizeof(msg) - 1u, sig) == true);
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg) - 1u, sig) == true);

        /* Corrupted signature fails */
        sig[0] ^= 0x01u;
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg) - 1u, sig) == false);

        /* All-zero signature fails */
        memset(sig, 0, 64);
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg) - 1u, sig) == false);
    }

    /* ---- A1 regression: y = p + 1 (non-canonical identity) rejected, RFC 8032 Sec. 5.1.3 ---- */
    {
        uint8_t noncanonPub[32];
        uint8_t sig[64];

        memset(noncanonPub, 0xFFu, 32);
        noncanonPub[0] = 0xEEu; /* low byte of (p + 1) = 0xEE */
        noncanonPub[31] = 0x7Fu; /* sign bit cleared -> y_raw = 2^255 - 18 */

        memset(sig, 0, 64);
        sig[0] = 0x01u; /* R = canonical identity encoding (y=1, x=0), S = 0 */

        SSF_ASSERT(SSFEd25519Verify(noncanonPub, NULL, 0, sig) == false);
    }

    /* ---- Decode rejects Y = 1 (X = 0) with the sign bit set: RFC 8032 Sec. 5.1.3 step 4 ---- */
    {
        uint8_t badPub[32];
        uint8_t sig[64];

        memset(badPub, 0, 32);
        badPub[0] = 0x01u; /* Y = 1 (LE), giving X = 0 */
        badPub[31] = 0x80u; /* sign bit set */
        memset(sig, 0, 64);
        SSF_ASSERT(SSFEd25519Verify(badPub, NULL, 0, sig) == false);
    }

    /* ---- A4 regression: 256 KiB round-trip through the chunked SHA-512 update helper ---- */
    {
        static uint8_t bigMsg[256u * 1024u];
        uint8_t seed[32];
        uint8_t pubKey[32];
        uint8_t sig[64];
        size_t i;

        for (i = 0; i < sizeof(bigMsg); i++) bigMsg[i] = (uint8_t)(i * 31u + 7u);

        SSF_ASSERT(SSFEd25519KeyGen(seed, pubKey) == true);
        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, bigMsg, sizeof(bigMsg), sig) == true);
        SSF_ASSERT(SSFEd25519Verify(pubKey, bigMsg, sizeof(bigMsg), sig) == true);

        /* Flip one byte deep in the message -- verify must reject. */
        bigMsg[sizeof(bigMsg) / 2u] ^= 0x01u;
        SSF_ASSERT(SSFEd25519Verify(pubKey, bigMsg, sizeof(bigMsg), sig) == false);
    }

    /* ---- B3 regression: verify-after-sign makes Sign fail on a mismatched pubKey ---- */
    {
        uint8_t seed[32];
        uint8_t pubKey[32];
        uint8_t badPub[32];
        uint8_t sig[64];
        const uint8_t msg[] = "fault-injected pubkey";

        SSF_ASSERT(SSFEd25519KeyGen(seed, pubKey) == true);

        memcpy(badPub, pubKey, 32);
        badPub[15] ^= 0x55u; /* simulate single-bit-class fault on stored A */

        /* Verify-after-sign detects the mismatch: Sign returns false and wipes sig */
        SSF_ASSERT(SSFEd25519Sign(seed, badPub, msg, sizeof(msg) - 1u, sig) == false);

        /* sig must be wiped to all zeros on failure (no partial signature leaked) */
        {
            size_t i;
            uint8_t orBits = 0u;
            for (i = 0; i < 64; i++) orBits |= sig[i];
            SSF_ASSERT(orBits == 0u);
        }
    }

#if SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB == 1
    /* ---- B1 regression: Sign scrubs the deep stack region below it before returning ---- */
    {
        uint8_t seed[32];
        uint8_t pubKey[32];
        uint8_t sig[64];
        const uint8_t msg[] = "stack scrub probe";
        size_t hitsAfter;

        SSF_ASSERT(SSFEd25519KeyGen(seed, pubKey) == true);

        _SSFEd25519UTPolluteStack(_SSFED25519_UT_SENTINEL);
        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, msg, sizeof(msg) - 1u, sig) == true);
        hitsAfter = _SSFEd25519UTCountSentinel(_SSFED25519_UT_SENTINEL);

        /* No scrub leaves thousands; allow frame-layout residue (more on MSVC /RTC1 + /GS) */
        SSF_UT_PRINTF("--- ssfed25519 Sign scrub residue %u bytes ---\n", (unsigned)hitsAfter);
#if _SSFED25519_UT_STACK_BOUNDS == 1
#if defined(_MSC_VER)
        SSF_ASSERT(hitsAfter < 512u);
#else
        SSF_ASSERT(hitsAfter < 64u);
#endif
#endif /* _SSFED25519_UT_STACK_BOUNDS */
    }
#endif /* SSF_ED25519_CONFIG_ENABLE_STACK_SCRUB */

    /* ---- AUDIT X-2/E-4: Sign's peak stack ~2-3 KiB, set by the verify-after-sign chain ---- */
    {
        uint8_t seed[32];
        uint8_t pubKey[32];
        uint8_t sig[64];
        const uint8_t msg[] = "stack high-water probe";
        size_t used;

        SSF_ASSERT(SSFEd25519KeyGen(seed, pubKey) == true);

        _SSFEd25519UTPolluteDeep(_SSFED25519_UT_SENTINEL);
        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, msg, sizeof(msg) - 1u, sig) == true);
        used = _SSFEd25519UTStackUsed(_SSFED25519_UT_SENTINEL);
        SSF_UT_PRINTF("--- ssfed25519 Sign peak stack ~%u bytes ---\n", (unsigned)used);
        SSF_ASSERT(used > 0u);
#if _SSFED25519_UT_STACK_BOUNDS == 1
        SSF_ASSERT(used < 4096u);
#endif
    }

    /* ---- A3 regression: identity pubKey with (R = identity, S = 0) forgery is rejected ---- */
    {
        uint8_t identityPub[32];
        uint8_t sig[64];

        memset(identityPub, 0, 32);
        identityPub[0] = 0x01u; /* canonical (y=1, sign=0) */

        memset(sig, 0, 64);
        sig[0] = 0x01u;            /* R = canonical identity, S = 0 */

        SSF_ASSERT(SSFEd25519Verify(identityPub, NULL, 0, sig) == false);
    }

    /* ---- D3 coverage: all 8 canonical low-order point encodings are rejected ---- */
    {
        static const uint8_t lowOrderEncodings[8][32] = {
            /* (y=1, x=0) -- identity, sign 0 (covered above; included for completeness). */
            { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            /* (y=p-1, x=0) -- order 2, sign 0. */
            { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
            /* (y=0, x=+sqrt(-1)) -- order 4, sign 0. */
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            /* (y=0, x=-sqrt(-1)) -- order 4, sign 1. */
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80 },
            /* Order-8 point #1, sign 0. */
            { 0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
              0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
              0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
              0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05 },
            /* Order-8 point #1, sign 1. */
            { 0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
              0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
              0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
              0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x85 },
            /* Order-8 point #2, sign 0. */
            { 0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
              0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
              0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
              0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a },
            /* Order-8 point #2, sign 1. */
            { 0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
              0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
              0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
              0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0xfa },
        };
        size_t i;
        uint8_t sig[64];
        const uint8_t msg[] = "low-order forgery probe";

        memset(sig, 0, 64);
        sig[0] = 0x01u;            /* R = canonical identity, S = 0 -- the easiest forgery shape */

        for (i = 0; i < 8; i++)
        {
            SSF_ASSERT(SSFEd25519Verify(lowOrderEncodings[i], msg, sizeof(msg) - 1u, sig)
                       == false);
            SSF_ASSERT(SSFEd25519Verify(lowOrderEncodings[i], NULL, 0, sig) == false);
        }
    }

    /* Deterministic sign / verify / mutation fuzz up to 2 KiB messages (no OpenSSL needed) */
    _Ed25519SelfFuzz(256u);

    /* === Wycheproof Ed25519 verify: 88 valid + 62 invalid (field-arithmetic edge cases) === */
    {
        #include "wycheproof_ed25519.h"
        uint16_t i;
        uint16_t pass = 0;
        uint16_t mismatches = 0;
        uint16_t acceptableSkipped = 0;

        SSF_UT_PRINTF("--- Wycheproof Ed25519 verify (%u tests) ---\n",
               (unsigned)SSF_WYCHEPROOF_ED25519_NTESTS);
        for (i = 0; i < (uint16_t)SSF_WYCHEPROOF_ED25519_NTESTS; i++)
        {
            const _SSFWycheproofEd25519Test_t *t = &_wp_Ed25519_tests[i];
            bool got;

            if (t->sigLen != 64u)
            {
                /* Verify takes a fixed 64-byte sig, so a wrong-length vector must be invalid */
                if (t->expectedValid)
                {
                    mismatches++;
                    SSF_UT_PRINTF("  tcId %4u: expected valid but sig is %u bytes\n",
                           (unsigned)t->tcId, (unsigned)t->sigLen);
                }
                else pass++;
                continue;
            }

            got = SSFEd25519Verify(t->pubKey, t->msg, t->msgLen, t->sig);

            if (t->acceptable) { acceptableSkipped++; continue; }

            /* Did Verify agree with the expected result? */
            if ((t->expectedValid && got) || ((!t->expectedValid) && (!got)))
            {
                /* Yes, count a pass */
                pass++;
            }
            else
            {
                /* No, count and report the mismatch */
                mismatches++;
                SSF_UT_PRINTF("  tcId %4u: expected %s, got %s\n",
                       (unsigned)t->tcId,
                       t->expectedValid ? "valid" : "invalid",
                       got ? "valid" : "invalid");
            }
        }
        SSF_UT_PRINTF("--- Wycheproof Ed25519: %u pass, %u acceptable, %u mismatches ---\n",
               (unsigned)pass, (unsigned)acceptableSkipped, (unsigned)mismatches);
        SSF_ASSERT(mismatches == 0u);
    }

#if SSF_ED25519_OSSL_VERIFY == 1
    /* OpenSSL cross-check catches nonce, encoding and decode divergence */
    _VerifyEd25519AgainstOpenSSL(64u);

#endif
}
#endif /* SSF_CONFIG_ED25519_UNIT_TEST */
