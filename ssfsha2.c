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
#include <stdbool.h>
#include "ssfport.h"
#include "ssfassert.h"

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
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t h0, h1, h2, h3, h4, h5, h6, h7;
    uint32_t ch, temp1, maj, temp2;
    uint32_t s0, s1;
    uint32_t i, j;
    uint32_t w[SSF_SHA256_BLOCK_SIZE_BYTES];
    uint8_t pad[SSF_SHA256_BLOCK_SIZE_BYTES];

    bool isPadded = false;
    bool isSplit = false;
    uint32_t offset = 0;
    const uint8_t* pin = in;
    uint64_t inBits = ((uint64_t)inLen) << 3;

    SSF_ASSERT(in != NULL);
    SSF_ASSERT(out != NULL);
    SSF_ASSERT((hashBitSize == 256) || (hashBitSize == 224));
    SSF_ASSERT(outSize >= (uint32_t) (hashBitSize >> 3));

    /* Initialize */
    if (hashBitSize == 256)
    {
        /* SHA-256 */
        h0 = 0x6a09e667; h1 = 0xbb67ae85; h2 = 0x3c6ef372; h3 = 0xa54ff53a;
        h4 = 0x510e527f; h5 = 0x9b05688c; h6 = 0x1f83d9ab; h7 = 0x5be0cd19;
    }
    else
    {
        /* SHA-224 */
        h0 = 0xc1059ed8; h1 = 0x367cd507; h2 = 0x3070dd17; h3 = 0xf70e5939;
        h4 = 0xffc00b31; h5 = 0x68581511; h6 = 0x64f98fa7; h7 = 0xbefa4fa4;
    }

    /* Iterate over 512-bit chunks adding padding at end */
    do 
    {
        /* Pad? */
        if (inLen >= SSF_SHA256_BLOCK_SIZE_BYTES)
        {
            /* No, just process in data */
            inLen -= SSF_SHA256_BLOCK_SIZE_BYTES;
        }
        else
        {
            /* Yes, initialize pad buffer with in buffer */
            memset(&pad[inLen], 0, sizeof(pad) - inLen);
            memcpy(pad, &in[offset], inLen);

            /* Room for pad in current block? */
            if (inLen > SSF_SHA256_MIN_PADDABLE_SIZE_BYTES)
            {
                /* No, need to add whole additional 512-bit block; pad split across 2 blocks */
                pad[inLen] = 0x80;
                isSplit = true;
            }
            else
            {
                /* Yes, add the pad */
                if (!isSplit) pad[inLen] = 0x80;
                pad[SSF_SHA256_BLOCK_SIZE_BYTES - 1] = (uint8_t)(inBits & 0xff);
                pad[SSF_SHA256_BLOCK_SIZE_BYTES - 2] = (uint8_t)((inBits & 0xff00) >> 8);
                pad[SSF_SHA256_BLOCK_SIZE_BYTES - 3] = (uint8_t)((inBits & 0xff0000) >> 16);
                pad[SSF_SHA256_BLOCK_SIZE_BYTES - 4] = (uint8_t)((inBits & 0xff000000) >> 24);
                pad[SSF_SHA256_BLOCK_SIZE_BYTES - 5] = (uint8_t)((inBits & 0xff00000000) >> 32);
                isPadded = true;
            }
            pin = pad;
            inLen = 0;
            offset = 0;
        }

        /* Initialize w[0-15] with data */
        for (i = 0; i < 16; i++)
        {
            j = i << 2;

            // memcpy and ntohll???
            memcpy(&w[i], &pin[j + offset], sizeof(uint32_t));
            w[i] = ntohl(w[i]);
        }
    
        /* Extend */
        for (i = 16; i < SSF_SHA256_BLOCK_SIZE_BYTES; i++)
        {
            s0 = (RR32(w[i-15], 7)) ^ (RR32(w[i-15], 18)) ^ (w[i-15] >> 3);
            s1 = (RR32(w[i-2], 17)) ^ (RR32(w[i-2], 19)) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        a = h0; b = h1; c = h2; d = h3; e = h4; f = h5; g = h6; h = h7;

        /* Compression */
        for (i = 0; i < SSF_SHA256_BLOCK_SIZE_BYTES; i++)
        {
            s1 = (RR32(e, 6)) ^ (RR32(e, 11)) ^ (RR32(e, 25));
            ch = (e & f) ^ (~e & g);
            temp1 = h + s1 + ch + k_32[i] + w[i];
            s0 = (RR32(a, 2)) ^ (RR32(a, 13)) ^ (RR32(a, 22));
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = s0 + maj;

            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
        }

        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
        offset += SSF_SHA256_BLOCK_SIZE_BYTES;
    } while (!isPadded);

    /* Accumulate hash into out buffer */
    h0 = htonl(h0); memcpy(&out[0], &h0, sizeof(uint32_t));
    h1 = htonl(h1); memcpy(&out[4], &h1, sizeof(uint32_t));
    h2 = htonl(h2); memcpy(&out[8], &h2, sizeof(uint32_t));
    h3 = htonl(h3); memcpy(&out[12], &h3, sizeof(uint32_t));
    h4 = htonl(h4); memcpy(&out[16], &h4, sizeof(uint32_t));
    h5 = htonl(h5); memcpy(&out[20], &h5, sizeof(uint32_t));
    h6 = htonl(h6); memcpy(&out[24], &h6, sizeof(uint32_t));
    if (hashBitSize != 224) { h7 = htonl(h7); memcpy(&out[28], &h7, sizeof(uint32_t)); }
}

/* --------------------------------------------------------------------------------------------- */
/* Computes SHA512, SHA384, SHA512/224, or SHA512/256 on in buffer, result placed in out buffer. */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_64(const uint8_t* in, uint32_t inLen, uint8_t* out, uint32_t outSize,
                uint16_t hashBitSize, uint16_t truncationBitSize)
{
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t h0, h1, h2, h3, h4, h5, h6, h7;
    uint64_t ch, temp1, maj, temp2;
    uint64_t s0, s1;
    uint32_t i, j;
    uint64_t w[SSF_SHA512_INTERNAL_SIZE_BYTES];
    uint8_t pad[SSF_SHA512_BLOCK_SIZE_BYTES];

    bool isPadded = false;
    bool isSplit = false;
    uint32_t offset = 0;
    const uint8_t* pin = in;
    uint64_t inBits = ((uint64_t)inLen) << 3;

    SSF_ASSERT(in != NULL);
    SSF_ASSERT(out != NULL);
    SSF_ASSERT(((hashBitSize == 512) && ((truncationBitSize == 0) || (truncationBitSize == 256) ||
                                         (truncationBitSize == 224))) ||
               ((hashBitSize == 384) && (truncationBitSize == 0)));
    if (((hashBitSize == 512) && (truncationBitSize == 0)) || (hashBitSize == 384))
    { SSF_ASSERT(outSize >= (uint32_t)(hashBitSize >> 3)); }
    else SSF_ASSERT(outSize >= (uint32_t)(truncationBitSize >> 3));

    /* Initialize */
    if ((hashBitSize == 512) && (truncationBitSize == 0))
    {
        /* SHA-512 */
        h0 = 0x6a09e667f3bcc908; h1 = 0xbb67ae8584caa73b;
        h2 = 0x3c6ef372fe94f82b; h3 = 0xa54ff53a5f1d36f1;
        h4 = 0x510e527fade682d1; h5 = 0x9b05688c2b3e6c1f;
        h6 = 0x1f83d9abfb41bd6b; h7 = 0x5be0cd19137e2179;
    }
    else if (hashBitSize == 384)
    {
        /* SHA-384 */
        h0 = 0xcbbb9d5dc1059ed8; h1 = 0x629a292a367cd507;
        h2 = 0x9159015a3070dd17; h3 = 0x152fecd8f70e5939;
        h4 = 0x67332667ffc00b31; h5 = 0x8eb44a8768581511;
        h6 = 0xdb0c2e0d64f98fa7; h7 = 0x47b5481dbefa4fa4;
    }
    else if (truncationBitSize == 256)
    {
        /* SHA-512/256 */
        h0 = 0x22312194FC2BF72C; h1 = 0x9F555FA3C84C64C2;
        h2 = 0x2393B86B6F53B151; h3 = 0x963877195940EABD;
        h4 = 0x96283EE2A88EFFE3; h5 = 0xBE5E1E2553863992;
        h6 = 0x2B0199FC2C85B8AA; h7 = 0x0EB72DDC81C52CA2;
    }
    else
    {
        /* SHA-512/224 */
        h0 = 0x8C3D37C819544DA2; h1 = 0x73E1996689DCD4D6;
        h2 = 0x1DFAB7AE32FF9C82; h3 = 0x679DD514582F9FCF;
        h4 = 0x0F6D2B697BD44DA8; h5 = 0x77E36F7304C48942;
        h6 = 0x3F9D85A86A1D36C8; h7 = 0x1112E6AD91D692A1;
    }

    /* Iterate over 512-bit chunks adding padding at end */
    do
    {
        /* Pad? */
        if (inLen >= SSF_SHA512_BLOCK_SIZE_BYTES)
        {
            /* No, just process in data */
            inLen -= SSF_SHA512_BLOCK_SIZE_BYTES;
        }
        else
        {
            /* Yes, initialize pad buffer with in buffer */
            memset(&pad[inLen], 0, sizeof(pad) - inLen);
            memcpy(pad, &in[offset], inLen);

            /* Room for pad in current block? */
            if (inLen > SSF_SHA512_MIN_PADDABLE_SIZE_BYTES)
            {
                /* No, need to add whole additional 512-bit block; pad split across 2 blocks */
                pad[inLen] = 0x80;
                isSplit = true;
            }
            else
            {
                /* Yes, add the pad */
                if (!isSplit) pad[inLen] = 0x80;
                pad[SSF_SHA512_BLOCK_SIZE_BYTES - 1] = (uint8_t)(inBits & 0xff);
                pad[SSF_SHA512_BLOCK_SIZE_BYTES - 2] = (uint8_t)((inBits & 0xff00) >> 8);
                pad[SSF_SHA512_BLOCK_SIZE_BYTES - 3] = (uint8_t)((inBits & 0xff0000) >> 16);
                pad[SSF_SHA512_BLOCK_SIZE_BYTES - 4] = (uint8_t)((inBits & 0xff000000) >> 24);
                pad[SSF_SHA512_BLOCK_SIZE_BYTES - 5] = (uint8_t)((inBits & 0xff00000000) >> 32);
                isPadded = true;
            }
            pin = pad;
            inLen = 0;
            offset = 0;
        }

        /* Initialize w[0-15] with data */
        for (i = 0; i < 16; i++)
        {
            j = i << 3;
            memcpy(&w[i], &pin[j + offset], sizeof(uint64_t)); w[i] = ntohll(w[i]);
        }

        /* Extend */
        for (i = 16; i < 80; i++)
        {
            s0 = (RR64(w[i - 15], 1)) ^ (RR64(w[i - 15], 8)) ^ (w[i - 15] >> 7);
            s1 = (RR64(w[i - 2], 19)) ^ (RR64(w[i - 2], 61)) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        a = h0; b = h1; c = h2; d = h3; e = h4; f = h5; g = h6; h = h7;

        /* Compression */
        for (i = 0; i < 80; i++)
        {
            s1 = (RR64(e, 14)) ^ (RR64(e, 18)) ^ (RR64(e, 41));
            ch = (e & f) ^ (~e & g);
            temp1 = h + s1 + ch + k_64[i] + w[i];
            s0 = (RR64(a, 28)) ^ (RR64(a, 34)) ^ (RR64(a, 39));
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = s0 + maj;

            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
        }

        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
        offset += SSF_SHA512_BLOCK_SIZE_BYTES;
    } while (!isPadded);

    /* Accumulate hash into out buffer */
    h0 = htonll(h0); memcpy(&out[0], &h0, sizeof(uint64_t));
    h1 = htonll(h1); memcpy(&out[8], &h1, sizeof(uint64_t));
    h2 = htonll(h2); memcpy(&out[16], &h2, sizeof(uint64_t));
    h3 = htonll(h3);
    if (truncationBitSize == 224)
    {
        memcpy(&out[24], &h3, 4);
    }
    else memcpy(&out[24], &h3, sizeof(uint64_t));
    if (truncationBitSize == 0)
    {
        h4 = htonll(h4); memcpy(&out[32], &h4, sizeof(uint64_t));
        h5 = htonll(h5); memcpy(&out[40], &h5, sizeof(uint64_t));
    }
    if ((hashBitSize == 512) && (truncationBitSize == 0))
    {
        h6 = htonll(h6); memcpy(&out[48], &h6, sizeof(uint64_t));
        h7 = htonll(h7); memcpy(&out[56], &h7, sizeof(uint64_t));
    }
}
