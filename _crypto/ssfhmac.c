/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhmac.c                                                                                     */
/* Provides HMAC (RFC 2104) keyed-hash message authentication code implementation.               */
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
#include "ssfassert.h"
#include "ssfhmac.h"
#include "ssfcrypt.h"
#include "ssfusexport.h"

/* --------------------------------------------------------------------------------------------- */
/* Module defines.                                                                               */
/* --------------------------------------------------------------------------------------------- */
#define SSF_HMAC_CONTEXT_MAGIC (0x484D4143ul)   /* 'HMAC' -- set by Begin, cleared by DeInit. */

/* Compile-time bounds checks via typedef-array idiom (size becomes -1 on failure). */
typedef char _ssf_hmac_sa_block_sha1_256_fits[(64u  <= SSF_HMAC_MAX_BLOCK_SIZE)  ? 1 : -1];
typedef char _ssf_hmac_sa_block_sha384_512_fits[(128u <= SSF_HMAC_MAX_BLOCK_SIZE) ? 1 : -1];
typedef char _ssf_hmac_sa_hash_max_fits[(64u  <= SSF_HMAC_MAX_HASH_SIZE)         ? 1 : -1];

/* --------------------------------------------------------------------------------------------- */
/* Returns the block size in bytes for the given hash algorithm.                                 */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFHMACGetBlockSize(SSFHMACHash_t hash)
{
    SSF_REQUIRE((hash > SSF_HMAC_HASH_MIN) && (hash < SSF_HMAC_HASH_MAX));

    switch (hash)
    {
    case SSF_HMAC_HASH_SHA1:   return 64u;
    case SSF_HMAC_HASH_SHA256: return 64u;
    case SSF_HMAC_HASH_SHA384: return 128u;
    case SSF_HMAC_HASH_SHA512: return 128u;
    default: SSF_ASSERT(false); return 0;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the output (hash) size in bytes for the given hash algorithm.                         */
/* --------------------------------------------------------------------------------------------- */
size_t SSFHMACGetHashSize(SSFHMACHash_t hash)
{
    SSF_REQUIRE((hash > SSF_HMAC_HASH_MIN) && (hash < SSF_HMAC_HASH_MAX));

    switch (hash)
    {
    case SSF_HMAC_HASH_SHA1:   return 20u;
    case SSF_HMAC_HASH_SHA256: return 32u;
    case SSF_HMAC_HASH_SHA384: return 48u;
    case SSF_HMAC_HASH_SHA512: return 64u;
    default: SSF_ASSERT(false); return 0;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Hash dispatch: Begin                                                                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFHMACHashBegin(SSFHMACContext_t *ctx)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE((ctx->hash > SSF_HMAC_HASH_MIN) && (ctx->hash < SSF_HMAC_HASH_MAX));

    switch (ctx->hash)
    {
    case SSF_HMAC_HASH_SHA1:   SSFSHA1Begin(&ctx->hashCtx.sha1);     break;
    case SSF_HMAC_HASH_SHA256: SSFSHA256Begin(&ctx->hashCtx.sha2_32); break;
    case SSF_HMAC_HASH_SHA384: SSFSHA2_64Begin(&ctx->hashCtx.sha2_64, 384, 0); break;
    case SSF_HMAC_HASH_SHA512: SSFSHA512Begin(&ctx->hashCtx.sha2_64); break;
    default: SSF_ASSERT(false); break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Hash dispatch: feed a single chunk whose length already fits in uint32_t.                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFHMACHashUpdateChunk(SSFHMACContext_t *ctx, const uint8_t *data, uint32_t chunk)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE((ctx->hash > SSF_HMAC_HASH_MIN) && (ctx->hash < SSF_HMAC_HASH_MAX));
    SSF_REQUIRE((data != NULL) || (chunk == 0u));

    switch (ctx->hash)
    {
    case SSF_HMAC_HASH_SHA1:   SSFSHA1Update(&ctx->hashCtx.sha1, data, chunk);     break;
    case SSF_HMAC_HASH_SHA256: SSFSHA256Update(&ctx->hashCtx.sha2_32, data, chunk); break;
    case SSF_HMAC_HASH_SHA384: SSFSHA2_64Update(&ctx->hashCtx.sha2_64, data, chunk); break;
    case SSF_HMAC_HASH_SHA512: SSFSHA512Update(&ctx->hashCtx.sha2_64, data, chunk); break;
    default: SSF_ASSERT(false); break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Hash dispatch: chunk a size_t-sized input into uint32_t-bounded SHA Update calls.             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFHMACHashUpdate(SSFHMACContext_t *ctx, const uint8_t *data, size_t len)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE((ctx->hash > SSF_HMAC_HASH_MIN) && (ctx->hash < SSF_HMAC_HASH_MAX));
    SSF_REQUIRE((data != NULL) || (len == 0u));

#if SIZE_MAX > UINT32_MAX
    /* On 64-bit size_t hosts, peel off UINT32_MAX-sized chunks (loop never runs on 32-bit). */
    while (len > (size_t)UINT32_MAX)
    {
        _SSFHMACHashUpdateChunk(ctx, data, UINT32_MAX);
        data += (size_t)UINT32_MAX;
        len  -= (size_t)UINT32_MAX;
    }
#endif
    if (len > 0u)
    {
        _SSFHMACHashUpdateChunk(ctx, data, (uint32_t)len);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Hash dispatch: End                                                                            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFHMACHashEnd(SSFHMACContext_t *ctx, uint8_t *out, size_t outSize)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE((ctx->hash > SSF_HMAC_HASH_MIN) && (ctx->hash < SSF_HMAC_HASH_MAX));
    SSF_REQUIRE(out != NULL);

    switch (ctx->hash)
    {
    case SSF_HMAC_HASH_SHA1:   SSFSHA1End(&ctx->hashCtx.sha1, out);                         break;
    case SSF_HMAC_HASH_SHA256: SSFSHA256End(&ctx->hashCtx.sha2_32, out, (uint32_t)outSize); break;
    case SSF_HMAC_HASH_SHA384: SSFSHA2_64End(&ctx->hashCtx.sha2_64, out, (uint32_t)outSize); break;
    case SSF_HMAC_HASH_SHA512: SSFSHA512End(&ctx->hashCtx.sha2_64, out, (uint32_t)outSize); break;
    default: SSF_ASSERT(false); break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes an incremental HMAC context (RFC 2104 steps 1-4).                                 */
/* --------------------------------------------------------------------------------------------- */
void SSFHMACBegin(SSFHMACContext_t *ctx, SSFHMACHash_t hash, const uint8_t *key, size_t keyLen)
{
    size_t blockSize;
    size_t hashSize;
    uint8_t keyPrime[SSF_HMAC_MAX_BLOCK_SIZE];
    uint8_t iKeyPad[SSF_HMAC_MAX_BLOCK_SIZE];
    size_t i;

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic == 0u);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(keyLen > 0u);
    SSF_REQUIRE((hash > SSF_HMAC_HASH_MIN) && (hash < SSF_HMAC_HASH_MAX));

    ctx->hash = hash;
    blockSize = _SSFHMACGetBlockSize(hash);
    hashSize = SSFHMACGetHashSize(hash);

    /* Step 1: If key > blockSize hash it to K' of length hashSize, else K' = zero-padded key. */
    memset(keyPrime, 0, blockSize);
    if (keyLen > blockSize)
    {
        /* Hash the long key */
        SSFHMACContext_t tmpCtx;
        tmpCtx.hash = hash;
        _SSFHMACHashBegin(&tmpCtx);
        _SSFHMACHashUpdate(&tmpCtx, key, keyLen);
        _SSFHMACHashEnd(&tmpCtx, keyPrime, hashSize);
    }
    else
    {
        memcpy(keyPrime, key, keyLen);
    }

    /* Step 2: Compute iKeyPad = K' XOR 0x36 and oKeyPad = K' XOR 0x5C */
/* Disable false positive Visual Studio Code Analysis warning */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
    for (i = 0; i < blockSize; i++)
    {
        iKeyPad[i] = keyPrime[i] ^ 0x36u;
        ctx->oKeyPad[i] = keyPrime[i] ^ 0x5Cu;
    }
#ifdef _WIN32
#pragma warning(pop)
#endif

    /* Step 3: Start the inner hash: H(iKeyPad || ...) */
    _SSFHMACHashBegin(ctx);
    _SSFHMACHashUpdate(ctx, iKeyPad, blockSize);

    /* Zeroize key-derived stack state. oKeyPad lives in ctx until SSFHMACDeInit. */
    SSFCryptSecureZero(keyPrime, sizeof(keyPrime));
    SSFCryptSecureZero(iKeyPad, sizeof(iKeyPad));

    /* Mark the context valid last so any earlier assert leaves magic unset. */
    ctx->magic = SSF_HMAC_CONTEXT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Feeds message data into the HMAC computation.                                                 */
/* --------------------------------------------------------------------------------------------- */
void SSFHMACUpdate(SSFHMACContext_t *ctx, const uint8_t *data, size_t dataLen)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic == SSF_HMAC_CONTEXT_MAGIC);
    SSF_REQUIRE((data != NULL) || (dataLen == 0));

    _SSFHMACHashUpdate(ctx, data, dataLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Finalizes the HMAC computation and produces the MAC output (RFC 2104 steps 5-7).              */
/* --------------------------------------------------------------------------------------------- */
void SSFHMACEnd(SSFHMACContext_t *ctx, uint8_t *macOut, size_t macOutSize)
{
    size_t blockSize;
    size_t hashSize;
    uint8_t innerHash[SSF_HMAC_MAX_HASH_SIZE];

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic == SSF_HMAC_CONTEXT_MAGIC);
    SSF_REQUIRE(macOut != NULL);

    hashSize = SSFHMACGetHashSize(ctx->hash);
    blockSize = _SSFHMACGetBlockSize(ctx->hash);

    /* Strict equality: HMAC writes exactly hashSize; truncation is the caller's job. */
    SSF_REQUIRE(macOutSize == hashSize);

    /* Step 5: Finalize the inner hash */
    _SSFHMACHashEnd(ctx, innerHash, hashSize);

    /* Step 6: Compute the outer hash: H(oKeyPad || innerHash) */
    _SSFHMACHashBegin(ctx);
    _SSFHMACHashUpdate(ctx, ctx->oKeyPad, blockSize);
    _SSFHMACHashUpdate(ctx, innerHash, hashSize);

    /* Step 7: Finalize the outer hash */
    _SSFHMACHashEnd(ctx, macOut, macOutSize);

    /* innerHash is derived from the key -- clear before going out of scope. */
    SSFCryptSecureZero(innerHash, sizeof(innerHash));
}

/* --------------------------------------------------------------------------------------------- */
/* Securely zeroize an HMAC context.                                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFHMACDeInit(SSFHMACContext_t *ctx)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic == SSF_HMAC_CONTEXT_MAGIC);
    SSFCryptSecureZero(ctx, sizeof(*ctx));
}

/* --------------------------------------------------------------------------------------------- */
/* Single-call HMAC.                                                                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFHMAC(SSFHMACHash_t hash, const uint8_t *key, size_t keyLen,
             const uint8_t *msg, size_t msgLen,
             uint8_t *macOut, size_t macOutSize)
{
    SSFHMACContext_t ctx = {0};

    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(keyLen > 0u);
    SSF_REQUIRE((msg != NULL) || (msgLen == 0));
    SSF_REQUIRE(macOut != NULL);
    SSF_REQUIRE((hash > SSF_HMAC_HASH_MIN) && (hash < SSF_HMAC_HASH_MAX));
    SSF_REQUIRE(macOutSize == SSFHMACGetHashSize(hash));

    SSFHMACBegin(&ctx, hash, key, keyLen);
    SSFHMACUpdate(&ctx, msg, msgLen);
    SSFHMACEnd(&ctx, macOut, macOutSize);
    SSFHMACDeInit(&ctx);
    return true;
}

#if SSF_CONFIG_HMAC_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Test hook: feed data through the chunking loop with a caller-supplied chunk max.              */
/* --------------------------------------------------------------------------------------------- */
void _SSFHMACTestHookUpdateChunked(SSFHMACContext_t *ctx, const uint8_t *data, size_t dataLen,
                                   uint32_t chunkMax)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic == SSF_HMAC_CONTEXT_MAGIC);
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(chunkMax > 0u);

    while (dataLen > 0u)
    {
        uint32_t chunk;
        if (dataLen > (size_t)chunkMax)
        {
            chunk = chunkMax;
        }
        else
        {
            chunk = (uint32_t)dataLen;
        }
        _SSFHMACHashUpdateChunk(ctx, data, chunk);
        data += chunk;
        dataLen -= chunk;
    }
}
#endif /* SSF_CONFIG_HMAC_UNIT_TEST */

