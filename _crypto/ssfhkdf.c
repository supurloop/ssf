/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhkdf.c                                                                                     */
/* Provides HKDF (RFC 5869) HMAC-based key derivation function implementation.                   */
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
#include "ssfhkdf.h"
#include "ssfcrypt.h"

/* --------------------------------------------------------------------------------------------- */
/* Extract: PRK = HMAC-Hash(salt, IKM)                                                           */
/* RFC 5869 section 2.2                                                                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFHKDFExtract(SSFHMACHash_t hash,
                    const uint8_t *salt, size_t saltLen,
                    const uint8_t *ikm, size_t ikmLen,
                    uint8_t *prkOut, size_t prkOutSize)
{
    size_t hashSize;
    uint8_t zeroSalt[SSF_HMAC_MAX_HASH_SIZE];

    SSF_REQUIRE(ikm != NULL);
    SSF_REQUIRE(prkOut != NULL);
    SSF_REQUIRE((hash > SSF_HMAC_HASH_MIN) && (hash < SSF_HMAC_HASH_MAX));

    hashSize = SSFHMACGetHashSize(hash);
    SSF_REQUIRE(prkOutSize >= hashSize);

    /* If salt is not provided, use a zero-filled salt of HashLen bytes (RFC 5869 section 2.2) */
    if (salt == NULL || saltLen == 0)
    {
        memset(zeroSalt, 0, hashSize);
        salt = zeroSalt;
        saltLen = hashSize;
    }

    /* PRK = HMAC-Hash(salt, IKM) — HMAC writes exactly hashSize bytes; any caller-supplied */
    /* tail in prkOut beyond hashSize is left as-is (RFC 5869: PRK length is HashLen). */
    return SSFHMAC(hash, salt, saltLen, ikm, ikmLen, prkOut, hashSize);
}

/* --------------------------------------------------------------------------------------------- */
/* Expand: OKM = HKDF-Expand(PRK, info, L)                                                      */
/* RFC 5869 section 2.3                                                                          */
/*                                                                                               */
/* N = ceil(L/HashLen)                                                                           */
/* T = T(1) || T(2) || ... || T(N)                                                              */
/* T(0) = empty                                                                                  */
/* T(i) = HMAC-Hash(PRK, T(i-1) || info || i)    for i = 1..N, where i is a single byte         */
/* OKM = first L bytes of T                                                                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFHKDFExpand(SSFHMACHash_t hash,
                   const uint8_t *prk, size_t prkLen,
                   const uint8_t *info, size_t infoLen,
                   uint8_t *okmOut, size_t okmLen)
{
    size_t hashSize;
    size_t n;
    size_t done = 0;
    uint8_t tPrev[SSF_HMAC_MAX_HASH_SIZE];
    uint8_t tCurr[SSF_HMAC_MAX_HASH_SIZE];
    SSFHMACContext_t ctx = {0};
    size_t i;

    SSF_REQUIRE(prk != NULL);
    SSF_REQUIRE(okmOut != NULL);
    SSF_REQUIRE((hash > SSF_HMAC_HASH_MIN) && (hash < SSF_HMAC_HASH_MAX));
    SSF_REQUIRE((info != NULL) || (infoLen == 0));

    hashSize = SSFHMACGetHashSize(hash);
    SSF_REQUIRE(prkLen >= hashSize);
    SSF_REQUIRE(okmLen <= 255u * hashSize);

    if (okmLen == 0) return true;

    /* N = ceil(okmLen / hashSize) */
    n = (okmLen + hashSize - 1u) / hashSize;

    for (i = 1; i <= n; i++)
    {
        uint8_t iByte = (uint8_t)i;
        size_t copyLen;

        SSFHMACBegin(&ctx, hash, prk, prkLen);

        /* T(i-1): for i > 1, feed the previous hash block */
        if (i > 1u)
        {
            SSFHMACUpdate(&ctx, tPrev, hashSize);
        }

        /* info */
        if (info != NULL && infoLen > 0)
        {
            SSFHMACUpdate(&ctx, info, infoLen);
        }

        /* Single-byte counter i */
        SSFHMACUpdate(&ctx, &iByte, 1);

        SSFHMACEnd(&ctx, tCurr, hashSize);

        /* Copy to output */
        copyLen = okmLen - done;
        if (copyLen > hashSize) copyLen = hashSize;
        memcpy(&okmOut[done], tCurr, copyLen);
        done += copyLen;

        /* Save for next iteration */
        memcpy(tPrev, tCurr, hashSize);

        /* Clear magic so the next iteration's Begin sees a fresh context. The DeInit also */
        /* zeroizes the key-derived stack state held inside ctx.                           */
        SSFHMACDeInit(&ctx);
    }

    SSFCryptSecureZero(tPrev, sizeof(tPrev));
    SSFCryptSecureZero(tCurr, sizeof(tCurr));

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Combined Extract + Expand.                                                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFHKDF(SSFHMACHash_t hash,
             const uint8_t *salt, size_t saltLen,
             const uint8_t *ikm, size_t ikmLen,
             const uint8_t *info, size_t infoLen,
             uint8_t *okmOut, size_t okmLen)
{
    uint8_t prk[SSF_HMAC_MAX_HASH_SIZE];
    size_t hashSize;
    bool ok;

    hashSize = SSFHMACGetHashSize(hash);

    if (!SSFHKDFExtract(hash, salt, saltLen, ikm, ikmLen, prk, sizeof(prk))) return false;
    ok = SSFHKDFExpand(hash, prk, hashSize, info, infoLen, okmOut, okmLen);
    SSFCryptSecureZero(prk, sizeof(prk));
    return ok;
}
