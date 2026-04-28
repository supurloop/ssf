/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfed25519_ut.c                                                                               */
/* Provides unit tests for the ssfed25519 Ed25519 module.                                        */
/* Test vectors from RFC 8032 Section 7.1.                                                       */
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
#include <string.h>
#include <stdio.h>
#include "ssfassert.h"
#include "ssfed25519.h"
#include "ssfsha2.h"

/* Cross-validate Ed25519 sign / verify / pubkey-derivation against OpenSSL on host builds where */
/* libcrypto is linked. Same gating pattern as ssfecdsa_ut.c.                                     */
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

/* --------------------------------------------------------------------------------------------- */
/* Stack scrub probe helpers (B1 regression). The polluter writes a sentinel pattern into a deep */
/* stack frame, returns (frame is reclaimed but bytes persist), then Sign runs at the same call  */
/* depth. After Sign, the scanner allocates a similarly-sized deep frame at the same depth and   */
/* counts surviving sentinel bytes. A correctly scrubbed Sign overwrites the sentinel via its    */
/* deep zero-fill; without scrub, most of the polluted region (which Sign's natural frames don't */
/* touch) remains.                                                                                 */
/* --------------------------------------------------------------------------------------------- */
#define _SSFED25519_UT_STACK_PROBE_SIZE (4096u)

__attribute__((noinline))
static void _SSFEd25519UTPolluteStack(uint8_t pattern)
{
    volatile uint8_t buf[_SSFED25519_UT_STACK_PROBE_SIZE];
    size_t i;
    for (i = 0; i < sizeof(buf); i++) buf[i] = pattern;
    /* Volatile write blocks DCE; barrier-style inline asm prevents the buffer being elided. */
    __asm__ __volatile__("" : : "r"(buf) : "memory");
}

__attribute__((noinline))
static size_t _SSFEd25519UTCountSentinel(uint8_t pattern)
{
    volatile uint8_t buf[_SSFED25519_UT_STACK_PROBE_SIZE];
    size_t hits = 0;
    size_t i;
    /* Read the buffer's pre-existing stack contents BEFORE writing it, so we observe what    */
    /* the previous frame at this depth left behind.                                            */
    for (i = 0; i < sizeof(buf); i++)
    {
        if (buf[i] == pattern) hits++;
    }
    /* Use buf so the compiler can't elide the read. */
    __asm__ __volatile__("" : : "r"(buf) : "memory");
    return hits;
}

#if SSF_ED25519_OSSL_VERIFY == 1
/* --------------------------------------------------------------------------------------------- */
/* Ed25519 OpenSSL cross-check helpers.                                                           */
/* OpenSSL exposes Ed25519 only through the EVP one-shot API: a 32-byte seed becomes an opaque    */
/* EVP_PKEY via EVP_PKEY_new_raw_private_key, and signing is EVP_DigestSign / verifying is        */
/* EVP_DigestVerify with NULL md (per RFC 8032 the hash is built into the scheme).                */
/* --------------------------------------------------------------------------------------------- */

/* Build an OpenSSL EVP_PKEY private key from a 32-byte seed. */
static EVP_PKEY *_Ed25519OSSLPrivFromSeed(const uint8_t seed[32])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    SSF_ASSERT(pkey != NULL);
    return pkey;
}

/* Build an OpenSSL EVP_PKEY public key from a 32-byte SSF pubKey. */
static EVP_PKEY *_Ed25519OSSLPubFromBytes(const uint8_t pub[32])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    SSF_ASSERT(pkey != NULL);
    return pkey;
}

/* Sign with OpenSSL: returns 64-byte sig in out. */
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

/* Verify with OpenSSL: returns true iff the signature is accepted. */
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

/* Derive the public key OpenSSL would compute from the same seed. Used to byte-compare against  */
/* SSFEd25519PubKeyFromSeed.                                                                      */
static void _Ed25519OSSLPubFromSeed(const uint8_t seed[32], uint8_t pubOut[32])
{
    EVP_PKEY *priv = _Ed25519OSSLPrivFromSeed(seed);
    size_t pubLen = 32;
    SSF_ASSERT(EVP_PKEY_get_raw_public_key(priv, pubOut, &pubLen) == 1);
    SSF_ASSERT(pubLen == 32);
    EVP_PKEY_free(priv);
}

/* --------------------------------------------------------------------------------------------- */
/* Random fuzz: per iteration draw a random seed and message, then exercise every cross-direction.*/
/* If any divergence appears (SSF and OpenSSL disagree on pubkey, signature, or verify outcome)   */
/* the assertion fires.                                                                           */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyEd25519AgainstOpenSSL(uint16_t iters)
{
    uint16_t iter;

    printf("--- ssfed25519 OpenSSL cross-check (%u iters, bidirectional) ---\n",
           (unsigned)iters);

    for (iter = 0; iter < iters; iter++)
    {
        uint8_t seed[32];
        uint8_t msg[256];
        size_t  msgLen;
        uint8_t pubSSF[32], pubOSSL[32];
        uint8_t sigSSF[64], sigOSSL[64];

        /* Random seed and random message of length 0..255. */
        SSF_ASSERT(RAND_bytes(seed, 32) == 1);
        SSF_ASSERT(RAND_bytes(msg, sizeof(msg)) == 1);
        msgLen = (size_t)(msg[0]);  /* arbitrary 0..255 */

        /* === Pubkey-from-seed must match byte-for-byte === */
        SSFEd25519PubKeyFromSeed(seed, pubSSF);
        _Ed25519OSSLPubFromSeed(seed, pubOSSL);
        SSF_ASSERT(memcmp(pubSSF, pubOSSL, 32) == 0);

        /* === SSF signs → OpenSSL verifies === */
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

    printf("--- end ssfed25519 OpenSSL cross-check ---\n");
}
#endif /* SSF_ED25519_OSSL_VERIFY */

/* --------------------------------------------------------------------------------------------- */
/* SSF-internal deterministic fuzz. Runs without OpenSSL, exercising sign / verify / mutation     */
/* rejection across a wider range of message lengths than the OpenSSL fuzz (which caps msg at     */
/* 255 bytes). State is advanced by chained SHA-512 from a fixed master seed, so failures are     */
/* deterministically reproducible across runs.                                                    */
/* --------------------------------------------------------------------------------------------- */
static void _Ed25519SelfFuzz(uint16_t iters)
{
    uint8_t state[64];
    uint16_t iter;

    printf("--- ssfed25519 self-fuzz (%u iters, deterministic) ---\n", (unsigned)iters);

    /* Fixed master state — any nonzero pattern is fine; the SHA-512 chain mixes thoroughly. */
    memset(state, 0xA5u, sizeof(state));

    for (iter = 0; iter < iters; iter++)
    {
        uint8_t seed[32], pubKey[32], sig[64];
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

        /* Mutation 2: flip a pubKey byte. After A1 / A3 a perturbed pubKey may decode to a       */
        /* different valid point, fail the y < p canonical check, or land on a low-order point — */
        /* all three rejection paths are valid here.                                              */
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

    printf("--- end ssfed25519 self-fuzz ---\n");
}

/* --------------------------------------------------------------------------------------------- */
/* Helper: convert hex string to bytes.                                                          */
/* --------------------------------------------------------------------------------------------- */
static void _HexToBytes(const char *hex, uint8_t *out, size_t outLen)
{
    size_t i;
    for (i = 0; i < outLen; i++)
    {
        uint8_t hi = (hex[i * 2] >= 'a') ? (uint8_t)(hex[i * 2] - 'a' + 10) :
                     (hex[i * 2] >= 'A') ? (uint8_t)(hex[i * 2] - 'A' + 10) :
                     (uint8_t)(hex[i * 2] - '0');
        uint8_t lo = (hex[i * 2 + 1] >= 'a') ? (uint8_t)(hex[i * 2 + 1] - 'a' + 10) :
                     (hex[i * 2 + 1] >= 'A') ? (uint8_t)(hex[i * 2 + 1] - 'A' + 10) :
                     (uint8_t)(hex[i * 2 + 1] - '0');
        out[i] = (uint8_t)((hi << 4) | lo);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* SSFEd25519UnitTest                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFEd25519UnitTest(void)
{
    /* ---- RFC 8032 Test Vector 1: empty message ---- */
    {
        uint8_t seed[32], expectedPub[32], expectedSig[64];
        uint8_t pubKey[32], sig[64];

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
        uint8_t seed[32], expectedPub[32], expectedSig[64];
        uint8_t pubKey[32], sig[64];
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
        uint8_t seed[32], expectedPub[32], expectedSig[64];
        uint8_t pubKey[32], sig[64];
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

    /* ---- RFC 8032 §7.1 Test Vector 4: 1023-byte message ---- */
    /* The named long-message vector. Catches buffer-handling bugs in long messages that the     */
    /* short TV1–TV3 vectors miss; complements the OpenSSL cross-check with a hardcoded RFC      */
    /* reference value that doesn't depend on libcrypto being linked.                             */
    {
        static uint8_t tv4Msg[1023];
        uint8_t seed[32], expectedPub[32], expectedSig[64];
        uint8_t pubKey[32], sig[64];

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
        uint8_t seed[32], pubKey[32], pubKey2[32], sig[64];
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

    /* ---- A1 regression: non-canonical pubkey y must be rejected (RFC 8032 §5.1.3). */
    /* Construct a pubkey whose 255-bit y interpretation is y = p + 1 = 2^255 - 18,    */
    /* a non-canonical encoding of the canonical y = 1 (the curve identity, with x=0). */
    /* The chosen signature R||S = (canonical identity encoding)||0 mathematically     */
    /* satisfies the verify equation [S]B - [k]A = identity once A is decoded as the   */
    /* identity, so a decoder that silently accepts the non-canonical y would return   */
    /* true here. RFC 8032 requires this to fail.                                      */
    {
        uint8_t noncanonPub[32];
        uint8_t sig[64];

        memset(noncanonPub, 0xFFu, 32);
        noncanonPub[0]  = 0xEEu;   /* low byte of (p + 1) = 0xEE */
        noncanonPub[31] = 0x7Fu;   /* sign bit cleared -> y_raw = 2^255 - 18 */

        memset(sig, 0, 64);
        sig[0] = 0x01u;            /* R = canonical identity encoding (y=1, x=0) */
                                   /* S = 0 (32 zero bytes) */

        SSF_ASSERT(SSFEd25519Verify(noncanonPub, NULL, 0, sig) == false);
    }

    /* ---- A4 regression: long message round-trip exercises chunked SHA-512 update.  */
    /* Cannot allocate >4 GiB on a host to trip the actual size_t->uint32_t truncation */
    /* bug, but a 256 KiB message with byte-level corruption detection at least proves */
    /* the rewritten chunking helper preserves the single-call hash semantics on every */
    /* code path Sign and Verify exercise.                                              */
    {
        static uint8_t bigMsg[256u * 1024u];
        uint8_t seed[32], pubKey[32], sig[64];
        size_t i;

        for (i = 0; i < sizeof(bigMsg); i++) bigMsg[i] = (uint8_t)(i * 31u + 7u);

        SSF_ASSERT(SSFEd25519KeyGen(seed, pubKey) == true);
        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, bigMsg, sizeof(bigMsg), sig) == true);
        SSF_ASSERT(SSFEd25519Verify(pubKey, bigMsg, sizeof(bigMsg), sig) == true);

        /* Flip one byte deep in the message — verify must reject. */
        bigMsg[sizeof(bigMsg) / 2u] ^= 0x01u;
        SSF_ASSERT(SSFEd25519Verify(pubKey, bigMsg, sizeof(bigMsg), sig) == false);
    }

    /* ---- B3 regression: verify-after-sign rejects mismatched pubKey. */
    /* If a fault flips a bit in the long-term pubKey blob (or the caller stores a corrupted    */
    /* (seed, pubKey) pair), the produced signature uses the seed-derived scalar a but the      */
    /* challenge hash incorporates the corrupted A — verifiers reject the signature. Sign       */
    /* should detect this internally and refuse to release the bad signature.                   */
    {
        uint8_t seed[32], pubKey[32], badPub[32], sig[64];
        const uint8_t msg[] = "fault-injected pubkey";

        SSF_ASSERT(SSFEd25519KeyGen(seed, pubKey) == true);

        memcpy(badPub, pubKey, 32);
        badPub[15] ^= 0x55u;          /* simulate single-bit-class fault on stored A */

        /* Pre-fix: Sign returns true (no internal check) and emits a sig that fails verify.    */
        /* Post-fix: verify-after-sign detects the mismatch, Sign returns false, sig is wiped.  */
        SSF_ASSERT(SSFEd25519Sign(seed, badPub, msg, sizeof(msg) - 1u, sig) == false);

        /* sig must be wiped to all zeros on failure (no partial signature leaked).             */
        {
            size_t i;
            uint8_t orBits = 0u;
            for (i = 0; i < 64; i++) orBits |= sig[i];
            SSF_ASSERT(orBits == 0u);
        }
    }

    /* ---- B1 regression: Sign performs a deep-stack scrub before returning. */
    /* Sentinel is written into a deep frame; Sign runs at the same call depth and its scrub   */
    /* helper must zero a generous deeper region. The post-Sign scanner allocates a fresh frame */
    /* at the same depth and reads its uninitialised contents — those contents reflect what     */
    /* the previous frame at that depth (the scrub helper) wrote. After scrub, the sentinel     */
    /* count must drop to zero. Without scrub, Sign's natural frames overwrite only a small     */
    /* portion of the sentinel region, so most sentinel bytes survive.                           */
    {
        uint8_t seed[32], pubKey[32], sig[64];
        const uint8_t msg[] = "stack scrub probe";
        size_t hitsAfter;

        SSF_ASSERT(SSFEd25519KeyGen(seed, pubKey) == true);

        _SSFEd25519UTPolluteStack(0xCCu);
        SSF_ASSERT(SSFEd25519Sign(seed, pubKey, msg, sizeof(msg) - 1u, sig) == true);
        hitsAfter = _SSFEd25519UTCountSentinel(0xCCu);

        /* Tolerance: the scanner's own frame layout (return addr, saved registers) may differ */
        /* from the polluter's by a handful of bytes, so allow a small residue. The pre-fix    */
        /* failure mode leaves thousands of sentinel bytes, well above this threshold.         */
        SSF_ASSERT(hitsAfter < 64u);
    }

    /* ---- A3 regression: low-order pubkey signature attack must be rejected. */
    /* The identity (y=1, x=0) is canonically encoded as {0x01, 0x00 ×31}, passes A1's y < p   */
    /* check, and decodes successfully — but it has order 1 (or 8 at most for any low-order     */
    /* point), which means [k]·A = identity for every challenge k modulo a small factor.       */
    /* With sig = (R=identity, S=0), the verify equation [S]B - [k]A = identity - identity =   */
    /* identity reconstructs identity bytes equal to R bytes, so without a low-order check     */
    /* every message verifies under the identity public key. Per Chalkias et al. "Taming the   */
    /* many EdDSAs" §5, verifiers must reject these pubkeys.                                    */
    {
        uint8_t identityPub[32];
        uint8_t sig[64];

        memset(identityPub, 0, 32);
        identityPub[0] = 0x01u;   /* canonical (y=1, sign=0) */

        memset(sig, 0, 64);
        sig[0] = 0x01u;            /* R = canonical identity, S = 0 */

        SSF_ASSERT(SSFEd25519Verify(identityPub, NULL, 0, sig) == false);
    }

    /* ---- D3 coverage: every canonical low-order point encoding must be rejected. */
    /* The full set of 8 low-order points on edwards25519 (cofactor 8). After A1's y < p check */
    /* removes the non-canonical encodings of (0, 0) and (0, p-1) from the libsodium 11-entry  */
    /* blocklist, exactly 8 canonical encodings remain — all listed here with their sign-bit   */
    /* variants. The [8]A check inside Verify must reject every one regardless of signature.   */
    {
        static const uint8_t lowOrderEncodings[8][32] = {
            /* (y=1, x=0) — identity, sign 0 (covered above; included for completeness). */
            { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            /* (y=p-1, x=0) — order 2, sign 0. */
            { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
            /* (y=0, x=+sqrt(-1)) — order 4, sign 0. */
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            /* (y=0, x=-sqrt(-1)) — order 4, sign 1. */
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
        sig[0] = 0x01u;            /* R = canonical identity, S = 0 — the easiest forgery shape */

        for (i = 0; i < 8; i++)
        {
            SSF_ASSERT(SSFEd25519Verify(lowOrderEncodings[i], msg, sizeof(msg) - 1u, sig)
                       == false);
            SSF_ASSERT(SSFEd25519Verify(lowOrderEncodings[i], NULL, 0, sig) == false);
        }
    }

    /* SSF-internal deterministic fuzz. Independent of OpenSSL — exercises sign / verify /     */
    /* mutation rejection across longer messages (up to 2 KiB) than the OpenSSL fuzz covers,    */
    /* and is reproducible because the state stream is derived from a fixed master seed.         */
    _Ed25519SelfFuzz(256u);

#if SSF_ED25519_OSSL_VERIFY == 1
    /* Comprehensive OpenSSL cross-check: random seeds, random messages, bidirectional sign /  */
    /* verify, and pubkey-from-seed byte equality. Catches deterministic-nonce bugs, encoding  */
    /* mistakes, and edge-case decode bugs that internal round-trip tests miss.                */
    _VerifyEd25519AgainstOpenSSL(64u);
#endif
}
#endif /* SSF_CONFIG_ED25519_UNIT_TEST */
