/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsha2.c                                                                                     */
/* Provides SHA2 interface: SHA256, SHA224, SHA512, SHA384, SHA512/224, or SHA512/256            */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2021 Supurloop Software LLC                                                         */
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
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfsha2.h"
#include "ssfcrypt.h"
#include "ssfusexport.h"

/* --------------------------------------------------------------------------------------------- */
/* Local defines                                                                                 */
/* --------------------------------------------------------------------------------------------- */
#define RR(x, n, b) ((x >> n) | (x << (b - n)))
#define RR32(x, n) RR(x, n, 32)
#define RR64(x, n) RR(x, n, 64)

#define SSF_SHA256_MIN_PAD_SIZE_BYTES (sizeof(uint64_t) + 1)
#define SSF_SHA256_HASH_SIZE_BYTES (32u)
#define SSF_SHA256_BLOCK_SIZE_BYTES (64u)
#define SSF_SHA256_MIN_PADDABLE_SIZE_BYTES (SSF_SHA256_BLOCK_SIZE_BYTES - \
                                            SSF_SHA256_MIN_PAD_SIZE_BYTES)

#define SSF_SHA512_MIN_PAD_SIZE_BYTES ((sizeof(uint64_t) << 1) + 1)
#define SSF_SHA512_HASH_SIZE_BYTES (64u)
#define SSF_SHA512_INTERNAL_SIZE_BYTES (80u)
#define SSF_SHA512_BLOCK_SIZE_BYTES (128u)
#define SSF_SHA512_MIN_PADDABLE_SIZE_BYTES (SSF_SHA512_BLOCK_SIZE_BYTES - \
                                            SSF_SHA512_MIN_PAD_SIZE_BYTES)

#define SSF_SHA2_32_CONTEXT_MAGIC (0x32C01984ul)
#define SSF_SHA2_64_CONTEXT_MAGIC (0x64C05172ul)

/* --------------------------------------------------------------------------------------------- */
/* Local variables                                                                               */
/* --------------------------------------------------------------------------------------------- */
/* SHA2_32 */
static const uint32_t k_32[64] =
{
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* SHA2_64 */
static const uint64_t k_64[SSF_SHA512_INTERNAL_SIZE_BYTES] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

/* --------------------------------------------------------------------------------------------- */
/* Computes SHA256 or SHA224 on in buffer, result placed in out buffer.                          */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_32(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outSize,
                uint16_t hashBitSize)
{
    SSFSHA2_32Context_t context;

    SSF_ASSERT(in != NULL);
    SSF_ASSERT(out != NULL);
    SSF_ASSERT((hashBitSize == 256) || (hashBitSize == 224));
    SSF_ASSERT(outSize >= (uint32_t)(hashBitSize >> 3));

    SSFSHA2_32Begin(&context, hashBitSize);
    SSFSHA2_32Update(&context, in, inLen);
    SSFSHA2_32End(&context, out, outSize);
}

/* --------------------------------------------------------------------------------------------- */
/* Computes SHA512, SHA384, SHA512/224, or SHA512/256 on in buffer, result placed in out buffer. */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_64(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outSize,
                uint16_t hashBitSize, uint16_t truncationBitSize)
{
    SSFSHA2_64Context_t context;

    SSF_ASSERT(in != NULL);
    SSF_ASSERT(out != NULL);
    SSF_ASSERT(((hashBitSize == 512) && ((truncationBitSize == 0) || (truncationBitSize == 256) ||
                                         (truncationBitSize == 224))) ||
               ((hashBitSize == 384) && (truncationBitSize == 0)));
    if (((hashBitSize == 512) && (truncationBitSize == 0)) || (hashBitSize == 384))
    { SSF_ASSERT(outSize >= (uint32_t)(hashBitSize >> 3)); }
    else SSF_ASSERT(outSize >= (uint32_t)(truncationBitSize >> 3));

    SSFSHA2_64Begin(&context, hashBitSize, truncationBitSize);
    SSFSHA2_64Update(&context, in, inLen);
    SSFSHA2_64End(&context, out, outSize);
}

/* --------------------------------------------------------------------------------------------- */
/* Processes one 64-byte block, updating the SHA256 or SHA224 running hash state hs[0..7].       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSHA2_32Block(uint32_t *hs, const uint8_t *block)
{
    uint32_t a, b, c, d, e, f, g, hh;
    uint32_t ch, temp1, maj, temp2;
    uint32_t s0, s1;
    uint32_t i, j;
    uint32_t w[SSF_SHA256_BLOCK_SIZE_BYTES];

    for (i = 0; i < 16; i++)
    {
        j = i << 2;
        memcpy(&w[i], &block[j], sizeof(uint32_t));
        w[i] = ntohl(w[i]);
    }

    for (i = 16; i < SSF_SHA256_BLOCK_SIZE_BYTES; i++)
    {
        s0 = (RR32(w[i - 15], 7)) ^ (RR32(w[i - 15], 18)) ^ (w[i - 15] >> 3);
        s1 = (RR32(w[i - 2], 17)) ^ (RR32(w[i - 2], 19)) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = hs[0]; b = hs[1]; c = hs[2]; d = hs[3]; e = hs[4]; f = hs[5]; g = hs[6]; hh = hs[7];

    for (i = 0; i < SSF_SHA256_BLOCK_SIZE_BYTES; i++)
    {
        s1 = (RR32(e, 6)) ^ (RR32(e, 11)) ^ (RR32(e, 25));
        ch = (e & f) ^ (~e & g);
        temp1 = hh + s1 + ch + k_32[i] + w[i];
        s0 = (RR32(a, 2)) ^ (RR32(a, 13)) ^ (RR32(a, 22));
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = s0 + maj;

        hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }

    hs[0] += a; hs[1] += b; hs[2] += c; hs[3] += d; hs[4] += e; hs[5] += f; hs[6] += g; hs[7] += hh;
}

/* --------------------------------------------------------------------------------------------- */
/* Processes one 128-byte block, updating the SHA512/384/512-224/512-256 running hash state.     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSHA2_64Block(uint64_t *hs, const uint8_t *block)
{
    uint64_t a, b, c, d, e, f, g, hh;
    uint64_t ch, temp1, maj, temp2;
    uint64_t s0, s1;
    uint32_t i, j;
    uint64_t w[SSF_SHA512_INTERNAL_SIZE_BYTES];

    for (i = 0; i < 16; i++)
    {
        j = i << 3;
        memcpy(&w[i], &block[j], sizeof(uint64_t)); w[i] = ntohll(w[i]);
    }

    for (i = 16; i < 80; i++)
    {
        s0 = (RR64(w[i - 15], 1)) ^ (RR64(w[i - 15], 8)) ^ (w[i - 15] >> 7);
        s1 = (RR64(w[i - 2], 19)) ^ (RR64(w[i - 2], 61)) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = hs[0]; b = hs[1]; c = hs[2]; d = hs[3]; e = hs[4]; f = hs[5]; g = hs[6]; hh = hs[7];

    for (i = 0; i < 80; i++)
    {
        s1 = (RR64(e, 14)) ^ (RR64(e, 18)) ^ (RR64(e, 41));
        ch = (e & f) ^ (~e & g);
        temp1 = hh + s1 + ch + k_64[i] + w[i];
        s0 = (RR64(a, 28)) ^ (RR64(a, 34)) ^ (RR64(a, 39));
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = s0 + maj;

        hh = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }

    hs[0] += a; hs[1] += b; hs[2] += c; hs[3] += d; hs[4] += e; hs[5] += f; hs[6] += g; hs[7] += hh;
}

/* --------------------------------------------------------------------------------------------- */
/* Begins a SHA256 or SHA224 incremental hash context.                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_32Begin(SSFSHA2_32Context_t *context, uint16_t hashBitSize)
{
    SSF_ASSERT(context != NULL);
    SSF_ASSERT((hashBitSize == 256) || (hashBitSize == 224));

    memset(context, 0, sizeof(SSFSHA2_32Context_t));
    context->hashBitSize = hashBitSize;

    if (hashBitSize == 256)
    {
        /* SHA-256 */
        context->h[0] = 0x6a09e667; context->h[1] = 0xbb67ae85;
        context->h[2] = 0x3c6ef372; context->h[3] = 0xa54ff53a;
        context->h[4] = 0x510e527f; context->h[5] = 0x9b05688c;
        context->h[6] = 0x1f83d9ab; context->h[7] = 0x5be0cd19;
    }
    else
    {
        /* SHA-224 */
        context->h[0] = 0xc1059ed8; context->h[1] = 0x367cd507;
        context->h[2] = 0x3070dd17; context->h[3] = 0xf70e5939;
        context->h[4] = 0xffc00b31; context->h[5] = 0x68581511;
        context->h[6] = 0x64f98fa7; context->h[7] = 0xbefa4fa4;
    }
    context->magic = SSF_SHA2_32_CONTEXT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Feeds a chunk of input data into a SHA256 or SHA224 incremental hash context.                 */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_32Update(SSFSHA2_32Context_t *context, const uint8_t *in, uint32_t inLen)
{
    uint32_t copyLen;

    SSF_ASSERT(context != NULL);
    SSF_ASSERT(context->magic == SSF_SHA2_32_CONTEXT_MAGIC);
    SSF_ASSERT((in != NULL) || (inLen == 0));

    while (inLen > 0)
    {
        copyLen = SSF_SHA256_BLOCK_SIZE_BYTES - context->bufLen;
        if (copyLen > inLen) copyLen = inLen;

        memcpy(&context->buf[context->bufLen], in, copyLen);
        context->bufLen += copyLen;
        context->totalBits += ((uint64_t)copyLen) << 3;
        in += copyLen;
        inLen -= copyLen;

        if (context->bufLen == SSF_SHA256_BLOCK_SIZE_BYTES)
        {
            _SSFSHA2_32Block(context->h, context->buf);
            context->bufLen = 0;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Ends a SHA256 or SHA224 incremental hash, writing the digest to out.                          */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_32End(SSFSHA2_32Context_t *context, uint8_t *out, uint32_t outSize)
{
    uint8_t pad[SSF_SHA256_BLOCK_SIZE_BYTES];
    uint64_t totalBits;
    uint32_t tmp;

    SSF_ASSERT(context != NULL);
    SSF_ASSERT(context->magic == SSF_SHA2_32_CONTEXT_MAGIC);
    SSF_ASSERT(out != NULL);
    SSF_ASSERT(outSize >= (uint32_t)(context->hashBitSize >> 3));

    totalBits = context->totalBits;

    /* Build final padded block(s) from the partial buffer */
    memcpy(pad, context->buf, context->bufLen);
    memset(&pad[context->bufLen], 0, sizeof(pad) - context->bufLen);

    if (context->bufLen > SSF_SHA256_MIN_PADDABLE_SIZE_BYTES)
    {
        /* Padding splits across two blocks */
        pad[context->bufLen] = 0x80;
        _SSFSHA2_32Block(context->h, pad);
        memset(pad, 0, sizeof(pad));
    }
    else
    {
        pad[context->bufLen] = 0x80;
    }

    /* Append big-endian message bit length in last 8 bytes of pad */
    SSF_PUTU64BE(&pad[SSF_SHA256_BLOCK_SIZE_BYTES - 8], totalBits);
    _SSFSHA2_32Block(context->h, pad);

    /* Accumulate hash into out buffer */
    tmp = htonl(context->h[0]); memcpy(&out[0],  &tmp, sizeof(uint32_t));
    tmp = htonl(context->h[1]); memcpy(&out[4],  &tmp, sizeof(uint32_t));
    tmp = htonl(context->h[2]); memcpy(&out[8],  &tmp, sizeof(uint32_t));
    tmp = htonl(context->h[3]); memcpy(&out[12], &tmp, sizeof(uint32_t));
    tmp = htonl(context->h[4]); memcpy(&out[16], &tmp, sizeof(uint32_t));
    tmp = htonl(context->h[5]); memcpy(&out[20], &tmp, sizeof(uint32_t));
    tmp = htonl(context->h[6]); memcpy(&out[24], &tmp, sizeof(uint32_t));
    if (context->hashBitSize != 224)
    {
        tmp = htonl(context->h[7]);
        memcpy(&out[28], &tmp, sizeof(uint32_t));
    }

    /* Zeroize pad -- it holds trailing message bytes and the encoded bit length. */
    SSFCryptSecureZero(pad, sizeof(pad));

    /* Invalidate context to prevent reuse without re-init */
    SSFCryptSecureZero(context, sizeof(SSFSHA2_32Context_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Begins a SHA512, SHA384, SHA512/224, or SHA512/256 incremental hash context.                  */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_64Begin(SSFSHA2_64Context_t *context, uint16_t hashBitSize, uint16_t truncationBitSize)
{
    SSF_ASSERT(context != NULL);
    SSF_ASSERT(((hashBitSize == 512) && ((truncationBitSize == 0) || (truncationBitSize == 256) ||
                                         (truncationBitSize == 224))) ||
               ((hashBitSize == 384) && (truncationBitSize == 0)));

    memset(context, 0, sizeof(SSFSHA2_64Context_t));
    context->hashBitSize = hashBitSize;
    context->truncationBitSize = truncationBitSize;

    if ((hashBitSize == 512) && (truncationBitSize == 0))
    {
        /* SHA-512 */
        context->h[0] = 0x6a09e667f3bcc908; context->h[1] = 0xbb67ae8584caa73b;
        context->h[2] = 0x3c6ef372fe94f82b; context->h[3] = 0xa54ff53a5f1d36f1;
        context->h[4] = 0x510e527fade682d1; context->h[5] = 0x9b05688c2b3e6c1f;
        context->h[6] = 0x1f83d9abfb41bd6b; context->h[7] = 0x5be0cd19137e2179;
    }
    else if (hashBitSize == 384)
    {
        /* SHA-384 */
        context->h[0] = 0xcbbb9d5dc1059ed8; context->h[1] = 0x629a292a367cd507;
        context->h[2] = 0x9159015a3070dd17; context->h[3] = 0x152fecd8f70e5939;
        context->h[4] = 0x67332667ffc00b31; context->h[5] = 0x8eb44a8768581511;
        context->h[6] = 0xdb0c2e0d64f98fa7; context->h[7] = 0x47b5481dbefa4fa4;
    }
    else if (truncationBitSize == 256)
    {
        /* SHA-512/256 */
        context->h[0] = 0x22312194FC2BF72C; context->h[1] = 0x9F555FA3C84C64C2;
        context->h[2] = 0x2393B86B6F53B151; context->h[3] = 0x963877195940EABD;
        context->h[4] = 0x96283EE2A88EFFE3; context->h[5] = 0xBE5E1E2553863992;
        context->h[6] = 0x2B0199FC2C85B8AA; context->h[7] = 0x0EB72DDC81C52CA2;
    }
    else
    {
        /* SHA-512/224 */
        context->h[0] = 0x8C3D37C819544DA2; context->h[1] = 0x73E1996689DCD4D6;
        context->h[2] = 0x1DFAB7AE32FF9C82; context->h[3] = 0x679DD514582F9FCF;
        context->h[4] = 0x0F6D2B697BD44DA8; context->h[5] = 0x77E36F7304C48942;
        context->h[6] = 0x3F9D85A86A1D36C8; context->h[7] = 0x1112E6AD91D692A1;
    }
    context->magic = SSF_SHA2_64_CONTEXT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Feeds a chunk of input data into a SHA512/384/512-224/512-256 incremental hash context.       */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_64Update(SSFSHA2_64Context_t *context, const uint8_t *in, uint32_t inLen)
{
    uint32_t copyLen;

    SSF_ASSERT(context != NULL);
    SSF_ASSERT(context->magic == SSF_SHA2_64_CONTEXT_MAGIC);
    SSF_ASSERT((in != NULL) || (inLen == 0));

    while (inLen > 0)
    {
        copyLen = SSF_SHA512_BLOCK_SIZE_BYTES - context->bufLen;
        if (copyLen > inLen) copyLen = inLen;

        memcpy(&context->buf[context->bufLen], in, copyLen);
        context->bufLen += copyLen;
        context->totalBits += ((uint64_t)copyLen) << 3;
        in += copyLen;
        inLen -= copyLen;

        if (context->bufLen == SSF_SHA512_BLOCK_SIZE_BYTES)
        {
            _SSFSHA2_64Block(context->h, context->buf);
            context->bufLen = 0;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Ends a SHA512, SHA384, SHA512/224, or SHA512/256 incremental hash, writing digest to out.     */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_64End(SSFSHA2_64Context_t *context, uint8_t *out, uint32_t outSize)
{
    uint8_t pad[SSF_SHA512_BLOCK_SIZE_BYTES];
    uint64_t totalBits;
    uint64_t tmp;

    SSF_ASSERT(context != NULL);
    SSF_ASSERT(context->magic == SSF_SHA2_64_CONTEXT_MAGIC);
    SSF_ASSERT(out != NULL);
    if (((context->hashBitSize == 512) && (context->truncationBitSize == 0)) ||
        (context->hashBitSize == 384))
    { SSF_ASSERT(outSize >= (uint32_t)(context->hashBitSize >> 3)); }
    else SSF_ASSERT(outSize >= (uint32_t)(context->truncationBitSize >> 3));

    totalBits = context->totalBits;

    /* Build final padded block(s) from the partial buffer */
    memcpy(pad, context->buf, context->bufLen);
    memset(&pad[context->bufLen], 0, sizeof(pad) - context->bufLen);

    if (context->bufLen > SSF_SHA512_MIN_PADDABLE_SIZE_BYTES)
    {
        /* Padding splits across two blocks */
        pad[context->bufLen] = 0x80;
        _SSFSHA2_64Block(context->h, pad);
        memset(pad, 0, sizeof(pad));
    }
    else
    {
        pad[context->bufLen] = 0x80;
    }

    /* Append big-endian message bit length in last 16 bytes of pad (upper 8 bytes already zero). */
    SSF_PUTU64BE(&pad[SSF_SHA512_BLOCK_SIZE_BYTES - 8], totalBits);
    _SSFSHA2_64Block(context->h, pad);

    /* Accumulate hash into out buffer */
    tmp = htonll(context->h[0]); memcpy(&out[0],  &tmp, sizeof(uint64_t));
    tmp = htonll(context->h[1]); memcpy(&out[8],  &tmp, sizeof(uint64_t));
    tmp = htonll(context->h[2]); memcpy(&out[16], &tmp, sizeof(uint64_t));
    tmp = htonll(context->h[3]);
    if (context->truncationBitSize == 224)
    {
        memcpy(&out[24], &tmp, 4);
    }
    else memcpy(&out[24], &tmp, sizeof(uint64_t));
    if (context->truncationBitSize == 0)
    {
        tmp = htonll(context->h[4]); memcpy(&out[32], &tmp, sizeof(uint64_t));
        tmp = htonll(context->h[5]); memcpy(&out[40], &tmp, sizeof(uint64_t));
    }
    if ((context->hashBitSize == 512) && (context->truncationBitSize == 0))
    {
        tmp = htonll(context->h[6]); memcpy(&out[48], &tmp, sizeof(uint64_t));
        tmp = htonll(context->h[7]); memcpy(&out[56], &tmp, sizeof(uint64_t));
    }

    /* Zeroize pad -- it holds trailing message bytes and the encoded bit length. */
    SSFCryptSecureZero(pad, sizeof(pad));

    /* Invalidate context to prevent reuse without re-init */
    SSFCryptSecureZero(context, sizeof(SSFSHA2_64Context_t));
}

