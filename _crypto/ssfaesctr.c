/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfaesctr.c                                                                                   */
/* Provides AES-CTR (counter mode) confidentiality-only stream cipher per NIST SP 800-38A §6.5.  */
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
#include "ssfaes.h"
#include "ssfaesctr.h"
#include "ssfcrypt.h"

/* --------------------------------------------------------------------------------------------- */
/* Module defines.                                                                               */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AESCTR_CONTEXT_MAGIC (0x41435452ul)     /* 'ACTR' — set by Begin, cleared by DeInit. */

/* --------------------------------------------------------------------------------------------- */
/* Compile-time bounds checks: ks[] and counter[] are sized to SSF_AESCTR_BLOCK_SIZE; the keystream */
/* generation passes 16-byte buffers to SSFAESBlockEncrypt. key[] is sized to                   */
/* SSF_AESCTR_KEY_MAX_SIZE. typedef-array idiom (size becomes -1 on failure) is used in place of */
/* _Static_assert because the cross-test toolchain matrix predates universal C11 support.        */
/* --------------------------------------------------------------------------------------------- */
typedef char _ssf_aesctr_sa_block_size[(SSF_AESCTR_BLOCK_SIZE == 16u) ? 1 : -1];
typedef char _ssf_aesctr_sa_key_max[(SSF_AESCTR_KEY_MAX_SIZE >= 32u) ? 1 : -1];

/* --------------------------------------------------------------------------------------------- */
/* Increment the 128-bit counter as a big-endian integer. NIST SP 800-38A §B.1 standard counter  */
/* function T = T + 1 mod 2^128. Matches WolfSSL's wc_AesCtrEncrypt counter convention.          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESCTRIncCounter(uint8_t counter[SSF_AESCTR_BLOCK_SIZE])
{
    int i;

    for (i = (int)SSF_AESCTR_BLOCK_SIZE - 1; i >= 0; i--)
    {
        counter[i]++;
        if (counter[i] != 0u) break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Generate the next 16-byte keystream block by encrypting the current counter, then increment.  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESCTRNextKeystream(SSFAESCTRContext_t *ctx)
{
    SSFAESXXXBlockEncrypt(ctx->counter, SSF_AESCTR_BLOCK_SIZE,
                          ctx->ks, SSF_AESCTR_BLOCK_SIZE,
                          ctx->key, ctx->keyLen);
    _SSFAESCTRIncCounter(ctx->counter);
    ctx->ksOff = 0u;
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes an incremental AES-CTR context with key and initial counter.                      */
/* --------------------------------------------------------------------------------------------- */
void SSFAESCTRBegin(SSFAESCTRContext_t *ctx, const uint8_t *key, size_t keyLen,
                    const uint8_t *iv)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic != SSF_AESCTR_CONTEXT_MAGIC);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE((keyLen == 16u) || (keyLen == 24u) || (keyLen == 32u));
    SSF_REQUIRE(iv != NULL);

    memcpy(ctx->key, key, keyLen);
    ctx->keyLen = keyLen;
    memcpy(ctx->counter, iv, SSF_AESCTR_BLOCK_SIZE);
    /* ksOff == BLOCK_SIZE means "no buffered keystream"; the first Crypt call will refill. */
    ctx->ksOff = SSF_AESCTR_BLOCK_SIZE;

    /* Mark valid last so that any earlier assert leaves magic unset and subsequent Crypt /     */
    /* DeInit calls fail loudly.                                                                */
    ctx->magic = SSF_AESCTR_CONTEXT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Encrypts or decrypts (CTR is symmetric) len bytes from in into out, in-place safe.            */
/* --------------------------------------------------------------------------------------------- */
void SSFAESCTRCrypt(SSFAESCTRContext_t *ctx, const uint8_t *in, uint8_t *out, size_t len)
{
    size_t take;
    size_t i;

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic == SSF_AESCTR_CONTEXT_MAGIC);
    SSF_REQUIRE((in != NULL) || (len == 0u));
    SSF_REQUIRE((out != NULL) || (len == 0u));

    while (len > 0u)
    {
        /* Is the keystream buffer empty? */
        if (ctx->ksOff >= SSF_AESCTR_BLOCK_SIZE)
        {
            /* Yes, generate the next keystream block. */
            _SSFAESCTRNextKeystream(ctx);
        }

        /* How many bytes can we consume from this keystream block? */
        take = SSF_AESCTR_BLOCK_SIZE - ctx->ksOff;
        if (take > len) take = len;

        for (i = 0; i < take; i++)
        {
            out[i] = (uint8_t)(in[i] ^ ctx->ks[ctx->ksOff + i]);
        }

        ctx->ksOff += take;
        in  += take;
        out += take;
        len -= take;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Securely zeroizes an AES-CTR context.                                                         */
/* --------------------------------------------------------------------------------------------- */
void SSFAESCTRDeInit(SSFAESCTRContext_t *ctx)
{
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->magic == SSF_AESCTR_CONTEXT_MAGIC);

    SSFCryptSecureZero(ctx, sizeof(*ctx));
}

/* --------------------------------------------------------------------------------------------- */
/* Single-call AES-CTR encryption/decryption.                                                    */
/* --------------------------------------------------------------------------------------------- */
void SSFAESCTR(const uint8_t *key, size_t keyLen, const uint8_t *iv,
               const uint8_t *in, uint8_t *out, size_t len)
{
    SSFAESCTRContext_t ctx = {0};

    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE((keyLen == 16u) || (keyLen == 24u) || (keyLen == 32u));
    SSF_REQUIRE(iv != NULL);
    SSF_REQUIRE((in != NULL) || (len == 0u));
    SSF_REQUIRE((out != NULL) || (len == 0u));

    SSFAESCTRBegin(&ctx, key, keyLen, iv);
    SSFAESCTRCrypt(&ctx, in, out, len);
    SSFAESCTRDeInit(&ctx);
}
