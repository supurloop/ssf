/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfstrb.c                                                                                     */
/* Provides safe C string buffer interfaces.                                                     */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2025 Supurloop Software LLC                                                         */
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
#include "ssfstrb.h"

#define SSF_STR_MAGIC (0x43735472)

/* --------------------------------------------------------------------------------------------- */
/* Initializes strinf buffer with cstr buffer.                                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufInit(SSFCStrBuf_t* sbOut, SSFCStr_t cstr, size_t cstrSize, bool isConst, bool isHeap)
{
    size_t i;
    char *tmp = cstr;

    SSF_REQUIRE(sbOut != NULL);
    SSF_REQUIRE(sbOut->ptr == NULL);
    SSF_REQUIRE(sbOut->len == 0);
    SSF_REQUIRE(sbOut->size == 0);
    SSF_REQUIRE(sbOut->magic == 0);
    SSF_REQUIRE(cstr != NULL);
    SSF_REQUIRE(cstrSize != 0);
    SSF_REQUIRE(cstrSize <= SSF_STRB_MAX_SIZE);

    /* Is string buffer a constant? */
    if (isConst)
    {
        /* Yes, ensure const str is NULL terminated */
        for (i = 0; i < cstrSize; i++)
        {
            if (cstr[i] == 0) break;
        }
        if (i == cstrSize) return false;
        sbOut->len = i;
    }
    else
    {
        /* No, ensure NULL termination and keep whatever string is in cstr */
        cstr[cstrSize - 1] = 0;
        sbOut->len = strlen(cstr);
    }

    /* Should string buffer be allocated from heap? */
    if (isHeap)
    {
        /* Yes, try to allocate and copy cstr into it */
        tmp = (char *)SSF_MALLOC(cstrSize);
        if (tmp == NULL) return false;
        memcpy(tmp, cstr, cstrSize);
    }

    sbOut->ptr = tmp;
    sbOut->size = cstrSize;
    sbOut->isConst = isConst;
    sbOut->isHeap = isHeap;
    sbOut->magic = SSF_STR_MAGIC;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes strbuf struct.                                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFStrBufDeInit(SSFCStrBuf_t *sbOut)
{
    SSF_REQUIRE(sbOut != NULL);
    SSF_REQUIRE(sbOut->ptr != NULL);
    SSF_REQUIRE(sbOut->len < sbOut->size);
    SSF_REQUIRE((sbOut->size > 0) && (sbOut->size <= SSF_STRB_MAX_SIZE));
    SSF_REQUIRE(sbOut->magic == SSF_STR_MAGIC);
    if (sbOut->isConst) SSF_REQUIRE(sbOut->isHeap == false);

    if (sbOut->isHeap) { SSF_FREE(sbOut->ptr); }
    memset(sbOut, 0, sizeof(SSFCStrBuf_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns length of string in string buffer.                                                    */
/* --------------------------------------------------------------------------------------------- */
size_t SSFStrBufLen(const SSFCStrBuf_t *sb)
{
    SSF_REQUIRE(sb != NULL);
    SSF_REQUIRE(sb->ptr != NULL);
    SSF_REQUIRE(sb->len < sb->size);
    SSF_REQUIRE(sb->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(sb->ptr[sb->len] == 0);

    return sb->len;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns size of string in string buffer.                                                      */
/* --------------------------------------------------------------------------------------------- */
size_t SSFStrBufSize(const SSFCStrBuf_t *sb)
{
    SSF_REQUIRE(sb != NULL);
    SSF_REQUIRE(sb->ptr != NULL);
    SSF_REQUIRE(sb->len < sb->size);
    SSF_REQUIRE(sb->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(sb->ptr[sb->len] == 0);

    return sb->size;
}

/* --------------------------------------------------------------------------------------------- */
/* Sets entire string buffer and len to 0.                                                       */
/* --------------------------------------------------------------------------------------------- */
void SSFStrBufClr(SSFCStrBuf_t *sbOut)
{
    SSF_REQUIRE(sbOut != NULL);
    SSF_REQUIRE(sbOut->ptr != NULL);
    SSF_REQUIRE(sbOut->len < sbOut->size);
    SSF_REQUIRE(sbOut->magic == SSF_STR_MAGIC);

    memset(sbOut->ptr, 0, sbOut->size);
    sbOut->len = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if src fully catted to dst with NULL terminator, else false.                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufCat(SSFCStrBuf_t* dstOut, const SSFCStrBuf_t* src)
{
    SSF_REQUIRE(dstOut != NULL);
    SSF_REQUIRE(dstOut->ptr != NULL);
    SSF_REQUIRE(dstOut->len < dstOut->size);
    SSF_REQUIRE(dstOut->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(dstOut->ptr[dstOut->len] == 0);
    SSF_REQUIRE(src != NULL);
    SSF_REQUIRE(src->ptr != NULL);
    SSF_REQUIRE(src->len < src->size);
    SSF_REQUIRE(src->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(src->ptr[src->len] == 0);

    /* Will src fully cat to dst? */
    if ((dstOut->len + src->len) >= dstOut->size) return false;

    /* Perform cat, update out len, and NULL terminate dst */
    memcpy(&dstOut->ptr[dstOut->len], src->ptr, src->len);
    dstOut->len += src->len;
    dstOut->ptr[dstOut->len] = 0;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if src fully copied to dst with NULL terminator, else false.                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufCpy(SSFCStrBuf_t* dstOut, const SSFCStrBuf_t* src)
{
    SSF_REQUIRE(dstOut != NULL);
    SSF_REQUIRE(dstOut->ptr != NULL);
    SSF_REQUIRE(dstOut->len < dstOut->size);
    SSF_REQUIRE(dstOut->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(dstOut->ptr[dstOut->len] == 0);
    SSF_REQUIRE(src != NULL);
    SSF_REQUIRE(src->ptr != NULL);
    SSF_REQUIRE(src->len < src->size);
    SSF_REQUIRE(src->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(src->ptr[src->len] == 0);

    /* Will src fully cpy to dst? */
    if (src->len >= dstOut->size) return false;

    /* Perform cpy, update out len, and NULL terminate dst */
    memcpy(dstOut->ptr, src->ptr, src->len);
    dstOut->len = src->len;
    dstOut->ptr[dstOut->len] = 0;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if both strings exactly match, else false.                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufCmp(const SSFCStrBuf_t* sb1, const SSFCStrBuf_t* sb2)
{
    SSF_REQUIRE(sb1 != NULL);
    SSF_REQUIRE(sb1->ptr != NULL);
    SSF_REQUIRE(sb1->len < sb1->size);
    SSF_REQUIRE(sb1->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(sb1->ptr[sb1->len] == 0);
    SSF_REQUIRE(sb2 != NULL);
    SSF_REQUIRE(sb2->ptr != NULL);
    SSF_REQUIRE(sb2->len < sb2->size);
    SSF_REQUIRE(sb2->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(sb2->ptr[sb2->len] == 0);

    /* Same length? */
    if (sb1->len != sb2->len) return false;

    /* Match exactly? */
    return memcmp(sb1->ptr, sb2->ptr, sb1->len + 1) == 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Converts sb to desired case.                                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFStrBufToCase(SSFCStrBuf_t *dstOut, SSFStrBufCase_t toCase)
{
    #define SSFSTR_UPPER_LOWER_DELTA ((int8_t)('a' - 'A'))
    char *ptr;
    size_t len;

    SSF_REQUIRE(dstOut != NULL);
    SSF_REQUIRE(dstOut->ptr != NULL);
    SSF_REQUIRE(dstOut->len < dstOut->size);
    SSF_REQUIRE(dstOut->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(dstOut->ptr[dstOut->len] == 0);
    SSF_REQUIRE((toCase > SSF_STRB_CASE_MIN) && (toCase < SSF_STRB_CASE_MAX));

    ptr = dstOut->ptr;
    len = dstOut->len;
    switch(toCase)
    {
        case SSF_STRB_CASE_LOWER:
            while (len > 0)
            {
                if ((*ptr >= 'A') && (*ptr <= 'Z')) (*ptr) += SSFSTR_UPPER_LOWER_DELTA;
                ptr++;
                len--;
            }
            break;
        case SSF_STRB_CASE_UPPER:
            while (len > 0)
            {
                if ((*ptr >= 'a') && (*ptr <= 'z')) (*ptr) -= SSFSTR_UPPER_LOWER_DELTA;
                ptr++;
                len--;
            }
            break;
        default:
            SSF_ERROR();
            break;
    }
}
