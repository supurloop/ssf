/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfaesccm.c                                                                                   */
/* Provides AES-CCM (Counter with CBC-MAC) authenticated encryption (RFC 3610, SP 800-38C).     */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#include "ssfaes.h"
#include "ssfaesccm.h"

/* --------------------------------------------------------------------------------------------- */
/* XOR 16 bytes: dst ^= src                                                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESCCMXorBlock(uint8_t *dst, const uint8_t *src)
{
    uint32_t i;
    for (i = 0; i < SSF_AESCCM_BLOCK_SIZE; i++) dst[i] ^= src[i];
}

/* --------------------------------------------------------------------------------------------- */
/* Encrypt a single 16-byte block using the AES key.                                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESCCMEncBlock(const uint8_t *key, size_t keyLen,
                               const uint8_t *in, uint8_t *out)
{
    SSFAESXXXBlockEncrypt(in, SSF_AESCCM_BLOCK_SIZE, out, SSF_AESCCM_BLOCK_SIZE, key, keyLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Formats the B_0 block (RFC 3610 section 2.2).                                                 */
/*   Byte 0: flags = (aadPresent ? 0x40 : 0) | ((t-2)/2 << 3) | (L-1)                          */
/*   Bytes 1..nonceLen: nonce                                                                    */
/*   Bytes nonceLen+1..15: plaintext length encoded big-endian in L bytes                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESCCMFormatB0(uint8_t b0[SSF_AESCCM_BLOCK_SIZE],
                               const uint8_t *nonce, size_t nonceLen,
                               size_t aadLen, size_t ptLen, size_t tagLen)
{
    uint32_t L = (uint32_t)(15u - nonceLen);
    uint32_t i;

    memset(b0, 0, SSF_AESCCM_BLOCK_SIZE);

    /* Flags byte */
    b0[0] = (uint8_t)(((aadLen > 0) ? 0x40u : 0x00u) |
                       (((tagLen - 2u) / 2u) << 3) |
                       (L - 1u));

    /* Nonce */
    memcpy(&b0[1], nonce, nonceLen);

    /* Plaintext length in L bytes, big-endian */
    {
        size_t q = ptLen;
        for (i = 0; i < L; i++)
        {
            b0[15u - i] = (uint8_t)(q & 0xFFu);
            q >>= 8;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Formats counter block A_i (RFC 3610 section 2.3).                                             */
/*   Byte 0: flags = L-1                                                                        */
/*   Bytes 1..nonceLen: nonce                                                                    */
/*   Bytes nonceLen+1..15: counter i encoded big-endian in L bytes                               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESCCMFormatCtr(uint8_t a[SSF_AESCCM_BLOCK_SIZE],
                                const uint8_t *nonce, size_t nonceLen, uint32_t counter)
{
    uint32_t L = (uint32_t)(15u - nonceLen);
    uint32_t i;

    memset(a, 0, SSF_AESCCM_BLOCK_SIZE);
    a[0] = (uint8_t)(L - 1u);
    memcpy(&a[1], nonce, nonceLen);

    /* Counter in L bytes, big-endian */
    {
        uint32_t c = counter;
        for (i = 0; i < L; i++)
        {
            a[15u - i] = (uint8_t)(c & 0xFFu);
            c >>= 8;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Computes CBC-MAC tag T over (B_0 || AAD || plaintext) per RFC 3610 section 2.2.               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESCCMComputeTag(const uint8_t *key, size_t keyLen,
                                 const uint8_t *nonce, size_t nonceLen,
                                 const uint8_t *aad, size_t aadLen,
                                 const uint8_t *data, size_t dataLen,
                                 size_t tagLen,
                                 uint8_t *tagOut)
{
    uint8_t x[SSF_AESCCM_BLOCK_SIZE];
    uint8_t b[SSF_AESCCM_BLOCK_SIZE];
    uint32_t pos;

    /* Process B_0 */
    _SSFAESCCMFormatB0(b, nonce, nonceLen, aadLen, dataLen, tagLen);
    _SSFAESCCMEncBlock(key, keyLen, b, x);

    /* Process AAD if present */
    if (aadLen > 0)
    {
        /* Encode AAD length (only support aadLen < 0xFF00 = 65280) */
        memset(b, 0, SSF_AESCCM_BLOCK_SIZE);
        b[0] = (uint8_t)((aadLen >> 8) & 0xFFu);
        b[1] = (uint8_t)(aadLen & 0xFFu);
        pos = 2;

        /* Fill the rest of the first block with AAD data */
        {
            size_t chunk = aadLen;
            if (chunk > (SSF_AESCCM_BLOCK_SIZE - 2u)) chunk = SSF_AESCCM_BLOCK_SIZE - 2u;
            memcpy(&b[pos], aad, chunk);
            pos = 0; /* reset for subsequent blocks */
            _SSFAESCCMXorBlock(x, b);
            _SSFAESCCMEncBlock(key, keyLen, x, x);

            /* Process remaining AAD blocks */
            {
                size_t aadDone = chunk;
                while (aadDone < aadLen)
                {
                    memset(b, 0, SSF_AESCCM_BLOCK_SIZE);
                    chunk = aadLen - aadDone;
                    if (chunk > SSF_AESCCM_BLOCK_SIZE) chunk = SSF_AESCCM_BLOCK_SIZE;
                    memcpy(b, &aad[aadDone], chunk);
                    _SSFAESCCMXorBlock(x, b);
                    _SSFAESCCMEncBlock(key, keyLen, x, x);
                    aadDone += chunk;
                }
            }
        }
    }

    /* Process plaintext/data blocks */
    {
        size_t done = 0;
        while (done < dataLen)
        {
            size_t chunk = dataLen - done;
            if (chunk > SSF_AESCCM_BLOCK_SIZE) chunk = SSF_AESCCM_BLOCK_SIZE;
            memset(b, 0, SSF_AESCCM_BLOCK_SIZE);
            memcpy(b, &data[done], chunk);
            _SSFAESCCMXorBlock(x, b);
            _SSFAESCCMEncBlock(key, keyLen, x, x);
            done += chunk;
        }
    }

    /* Tag is the first tagLen bytes of x */
    memcpy(tagOut, x, tagLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Applies CTR mode encryption/decryption and encrypts/decrypts the tag using S_0.               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFAESCCMCtr(const uint8_t *key, size_t keyLen,
                          const uint8_t *nonce, size_t nonceLen,
                          const uint8_t *in, size_t inLen,
                          uint8_t *out,
                          const uint8_t *tagIn, uint8_t *tagOut, size_t tagLen)
{
    uint8_t a[SSF_AESCCM_BLOCK_SIZE];
    uint8_t s[SSF_AESCCM_BLOCK_SIZE];
    uint32_t counter = 1;
    size_t done = 0;

    /* Encrypt/decrypt the data using S_1, S_2, ... */
    while (done < inLen)
    {
        size_t chunk = inLen - done;
        uint32_t j;
        if (chunk > SSF_AESCCM_BLOCK_SIZE) chunk = SSF_AESCCM_BLOCK_SIZE;

        _SSFAESCCMFormatCtr(a, nonce, nonceLen, counter);
        _SSFAESCCMEncBlock(key, keyLen, a, s);

        for (j = 0; j < (uint32_t)chunk; j++)
        {
            out[done + j] = in[done + j] ^ s[j];
        }

        done += chunk;
        counter++;
    }

    /* Encrypt/decrypt the tag using S_0 */
    _SSFAESCCMFormatCtr(a, nonce, nonceLen, 0);
    _SSFAESCCMEncBlock(key, keyLen, a, s);
    {
        uint32_t j;
        for (j = 0; j < (uint32_t)tagLen; j++)
        {
            tagOut[j] = tagIn[j] ^ s[j];
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Encrypt and authenticate.                                                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFAESCCMEncrypt(const uint8_t *pt, size_t ptLen,
                      const uint8_t *nonce, size_t nonceLen,
                      const uint8_t *aad, size_t aadLen,
                      const uint8_t *key, size_t keyLen,
                      uint8_t *tag, size_t tagSize,
                      uint8_t *ct, size_t ctSize)
{
    uint8_t cbcTag[SSF_AESCCM_BLOCK_SIZE];

    SSF_REQUIRE((pt != NULL) || (ptLen == 0));
    SSF_REQUIRE(nonce != NULL);
    SSF_REQUIRE((nonceLen >= 7u) && (nonceLen <= 13u));
    SSF_REQUIRE((aad != NULL) || (aadLen == 0));
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE((keyLen == 16u) || (keyLen == 24u) || (keyLen == 32u));
    SSF_REQUIRE(tag != NULL);
    SSF_REQUIRE((tagSize >= 4u) && (tagSize <= 16u) && ((tagSize & 1u) == 0));
    SSF_REQUIRE((ct != NULL) || (ptLen == 0));
    SSF_REQUIRE(ctSize >= ptLen);

    /* Step 1: Compute CBC-MAC tag over (B_0 || AAD || plaintext) */
    _SSFAESCCMComputeTag(key, keyLen, nonce, nonceLen, aad, aadLen, pt, ptLen, tagSize, cbcTag);

    /* Step 2: CTR encrypt the plaintext and encrypt the tag with S_0 */
    _SSFAESCCMCtr(key, keyLen, nonce, nonceLen, pt, ptLen, ct, cbcTag, tag, tagSize);
}

/* --------------------------------------------------------------------------------------------- */
/* Decrypt and verify.                                                                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFAESCCMDecrypt(const uint8_t *ct, size_t ctLen,
                      const uint8_t *nonce, size_t nonceLen,
                      const uint8_t *aad, size_t aadLen,
                      const uint8_t *key, size_t keyLen,
                      const uint8_t *tag, size_t tagLen,
                      uint8_t *pt, size_t ptSize)
{
    uint8_t decTag[SSF_AESCCM_BLOCK_SIZE];
    uint8_t cbcTag[SSF_AESCCM_BLOCK_SIZE];

    SSF_REQUIRE((ct != NULL) || (ctLen == 0));
    SSF_REQUIRE(nonce != NULL);
    SSF_REQUIRE((nonceLen >= 7u) && (nonceLen <= 13u));
    SSF_REQUIRE((aad != NULL) || (aadLen == 0));
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE((keyLen == 16u) || (keyLen == 24u) || (keyLen == 32u));
    SSF_REQUIRE(tag != NULL);
    SSF_REQUIRE((tagLen >= 4u) && (tagLen <= 16u) && ((tagLen & 1u) == 0));
    SSF_REQUIRE((pt != NULL) || (ctLen == 0));
    SSF_REQUIRE(ptSize >= ctLen);

    /* Step 1: CTR decrypt the ciphertext and decrypt the tag */
    _SSFAESCCMCtr(key, keyLen, nonce, nonceLen, ct, ctLen, pt, tag, decTag, tagLen);

    /* Step 2: Compute CBC-MAC tag over (B_0 || AAD || decrypted plaintext) */
    _SSFAESCCMComputeTag(key, keyLen, nonce, nonceLen, aad, aadLen, pt, ctLen, tagLen, cbcTag);

    /* Step 3: Compare tags */
    {
        uint32_t diff = 0;
        uint32_t i;
        for (i = 0; i < (uint32_t)tagLen; i++)
        {
            diff |= (uint32_t)(cbcTag[i] ^ decTag[i]);
        }
        if (diff != 0)
        {
            /* Authentication failed: zero the plaintext */
            memset(pt, 0, ctLen);
            return false;
        }
    }
    return true;
}
