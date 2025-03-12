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
/* Returns true if sbOut is initialized with valid cstrBuf, else false.                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufInit(SSFCStrBuf_t *sbOut, SSFCStr_t cstrBuf, size_t cstrBufSize, bool cstrBufClear)
{
    size_t i;

    SSF_REQUIRE(sbOut != NULL);
    SSF_REQUIRE(sbOut->ptr == NULL);
    SSF_REQUIRE(sbOut->ptrConst == NULL);
    SSF_REQUIRE(sbOut->len == 0);
    SSF_REQUIRE(sbOut->size == 0);
    SSF_REQUIRE(sbOut->magic == 0);
    SSF_REQUIRE(cstrBuf != NULL);
    SSF_REQUIRE(cstrBufSize != 0);
    SSF_REQUIRE(cstrBufSize <= SSF_STRB_MAX_SIZE);

    /* User requests to clear cstrBuf? */
    if (cstrBufClear)
    {
        /* Yes, clear cstrbuf */
        memset(cstrBuf, 0, cstrBufSize);
        sbOut->len = 0;
    }
    else
    {
        /* No, ensure str is NULL terminated */
        for (i = 0; i < cstrBufSize; i++)
        {
            if (cstrBuf[i] == 0) break;
        }
        if (i == cstrBufSize) return false;
        sbOut->len = i;
    }

    sbOut->ptr = cstrBuf;
    sbOut->size = cstrBufSize;
    sbOut->isConst = false;
    sbOut->isHeap = false;
    sbOut->magic = SSF_STR_MAGIC;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if sbOut is initialized with valid strBufConst, else false.                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufInitConst(SSFCStrBuf_t *sbOut, SSFCStrIn_t strBufConst, size_t strBufConstSize)
{
    size_t i;

    SSF_REQUIRE(sbOut != NULL);
    SSF_REQUIRE(sbOut->ptr == NULL);
    SSF_REQUIRE(sbOut->ptrConst == NULL);
    SSF_REQUIRE(sbOut->len == 0);
    SSF_REQUIRE(sbOut->size == 0);
    SSF_REQUIRE(sbOut->magic == 0);
    SSF_REQUIRE(strBufConst != NULL);
    SSF_REQUIRE(strBufConstSize != 0);
    SSF_REQUIRE(strBufConstSize <= SSF_STRB_MAX_SIZE);

    /* Ensure str is NULL terminated */
    for (i = 0; i < strBufConstSize; i++)
    {
        if (strBufConst[i] == 0) break;
    }
    if (i == strBufConstSize) return false;
    sbOut->len = i;

    sbOut->ptrConst = strBufConst;
    sbOut->size = strBufConstSize;
    sbOut->isConst = true;
    sbOut->isHeap = false;
    sbOut->magic = SSF_STR_MAGIC;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if sbOut is initialized from heap with cstrInitialOpt, else false.               */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufInitHeap(SSFCStrBuf_t *sbOut, SSFCStrIn_t cstrInitialOpt, size_t cstrInitialSize,
                       size_t cstrHeapSize, bool cstrHeapClear)
{
    size_t i;
    char *tmp;
    size_t len = 0;

    SSF_REQUIRE(sbOut != NULL);
    SSF_REQUIRE(sbOut->ptr == NULL);
    SSF_REQUIRE(sbOut->ptrConst == NULL);
    SSF_REQUIRE(sbOut->len == 0);
    SSF_REQUIRE(sbOut->size == 0);
    SSF_REQUIRE(sbOut->magic == 0);
    SSF_REQUIRE(((cstrInitialOpt != NULL) && (cstrInitialSize > 0) &&
                 (cstrInitialSize <= SSF_STRB_MAX_SIZE)) ||
                (cstrInitialOpt == NULL && cstrInitialSize == 0));
    SSF_REQUIRE(cstrHeapSize != 0);
    SSF_REQUIRE(cstrHeapSize <= SSF_STRB_MAX_SIZE);

    /* Is initial string supplied? */
    if (cstrInitialOpt != NULL)
    {
        /* Yes, ensure initial str is NULL terminated */
        for (i = 0; i < cstrInitialSize; i++)
        {
            if (cstrInitialOpt[i] == 0) break;
        }
        if (i == cstrInitialSize) return false;
        len = i;
        
        /* Can initial str fit into requested heap size? */
        if ((len + 1) > cstrHeapSize) return false;
    }

    /* Yes, try to allocate and copy initial cstr into it if supplied, else clear */
    tmp = (char *)SSF_MALLOC(cstrHeapSize);
    if (tmp == NULL) return false;

    /* Initial string? */
    if (cstrInitialOpt != NULL)
    {
        /* Yes, copy initial string into buffer */
        memcpy(tmp, cstrInitialOpt, len + 1);

        /* Clear remainder of heap buffer? */
        if (cstrHeapClear)
        { memset(&tmp[len + 1], 0, cstrHeapSize - (len + 1)); }
    }
    /* Clear heap buffer? */
    else if (cstrHeapClear)
    { memset(tmp, 0, cstrHeapSize); }
    else
    /* Set NULL terminator */
    { 
        SSF_ASSERT(len == 0);
        tmp[len] = 0; 
    }

    sbOut->ptr = tmp;
    sbOut->len = len;
    sbOut->size = cstrHeapSize;
    sbOut->isConst = false;
    sbOut->isHeap = true;
    sbOut->magic = SSF_STR_MAGIC;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if sbOut is initialized from heap with cstrInitial, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufInitHeapConst(SSFCStrBuf_t *sbOut, SSFCStrIn_t cstrInitial, size_t cstrInitialSize,
                            size_t cstrHeapSize, bool cstrHeapClear)
{
    size_t i;
    char *tmp;
    size_t len = 0;

    SSF_REQUIRE(sbOut != NULL);
    SSF_REQUIRE(sbOut->ptr == NULL);
    SSF_REQUIRE(sbOut->ptrConst == NULL);
    SSF_REQUIRE(sbOut->len == 0);
    SSF_REQUIRE(sbOut->size == 0);
    SSF_REQUIRE(sbOut->magic == 0);
    SSF_REQUIRE(cstrInitial != NULL);
    SSF_REQUIRE(cstrInitialSize > 0);
    SSF_REQUIRE(cstrInitialSize <= SSF_STRB_MAX_SIZE);
    SSF_REQUIRE(cstrHeapSize != 0);
    SSF_REQUIRE(cstrHeapSize <= SSF_STRB_MAX_SIZE);

    /* Ensure initial str is NULL terminated */
    for (i = 0; i < cstrInitialSize; i++)
    {
        if (cstrInitial[i] == 0) break;
    }
    if (i == cstrInitialSize) return false;
    len = i;
    
    /* Can initial str fit into requested heap size? */
    if ((len + 1) > cstrHeapSize) return false;

    /* Yes, try to allocate and copy initial cstr into it if supplied, else clear */
    tmp = (char *)SSF_MALLOC(cstrHeapSize);
    if (tmp == NULL) return false;

    /* Yes, copy initial string into buffer */
    memcpy(tmp, cstrInitial, len + 1);

    /* Clear remainder of heap buffer? */
    if (cstrHeapClear)
    { memset(&tmp[len + 1], 0, cstrHeapSize - (len + 1)); }

    sbOut->ptr = tmp;
    sbOut->len = len;
    sbOut->size = cstrHeapSize;
    sbOut->isConst = true;
    sbOut->isHeap = true;
    sbOut->magic = SSF_STR_MAGIC;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes strbuf struct.                                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFStrBufDeInit(SSFCStrBuf_t *sbOut)
{
    SSF_REQUIRE(sbOut != NULL);
    SSF_REQUIRE(((sbOut->ptr != NULL) && (sbOut->ptrConst == NULL)) ||
                ((sbOut->ptr == NULL) && (sbOut->ptrConst != NULL)));
    SSF_REQUIRE(sbOut->len < sbOut->size);
    SSF_REQUIRE((sbOut->size > 0) && (sbOut->size <= SSF_STRB_MAX_SIZE));
    SSF_REQUIRE(sbOut->magic == SSF_STR_MAGIC);

    if (sbOut->isHeap)
    {
        SSF_ASSERT(sbOut->ptr != NULL);
        SSF_FREE(sbOut->ptr);
    }
    memset(sbOut, 0, sizeof(SSFCStrBuf_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns length of string in string buffer.                                                    */
/* --------------------------------------------------------------------------------------------- */
size_t SSFStrBufLen(const SSFCStrBuf_t *sb)
{
    const char *tmp;

    SSF_REQUIRE(sb != NULL);
    SSF_REQUIRE(((sb->ptr != NULL) && (sb->ptrConst == NULL)) ||
                ((sb->ptr == NULL) && (sb->ptrConst != NULL)));
    SSF_REQUIRE(sb->len < sb->size);
    SSF_REQUIRE(sb->magic == SSF_STR_MAGIC);
    tmp = sb->ptr;
    if (tmp == NULL) tmp = sb->ptrConst;
    SSF_REQUIRE(tmp[sb->len] == 0);

    return sb->len;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns size of string in string buffer.                                                      */
/* --------------------------------------------------------------------------------------------- */
size_t SSFStrBufSize(const SSFCStrBuf_t *sb)
{
    const char *tmp;

    SSF_REQUIRE(sb != NULL);
    SSF_REQUIRE(((sb->ptr != NULL) && (sb->ptrConst == NULL)) ||
                ((sb->ptr == NULL) && (sb->ptrConst != NULL)));
    SSF_REQUIRE(sb->len < sb->size);
    SSF_REQUIRE(sb->magic == SSF_STR_MAGIC);
    tmp = sb->ptr;
    if (tmp == NULL) tmp = sb->ptrConst;
    SSF_REQUIRE(tmp[sb->len] == 0);

    return sb->size;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if string buffer is a constant else false.                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufIsConst(const SSFCStrBuf_t *sb)
{
    const char *tmp;

    SSF_REQUIRE(sb != NULL);
    SSF_REQUIRE(((sb->ptr != NULL) && (sb->ptrConst == NULL)) ||
                ((sb->ptr == NULL) && (sb->ptrConst != NULL)));
    SSF_REQUIRE(sb->len < sb->size);
    SSF_REQUIRE(sb->magic == SSF_STR_MAGIC);
    tmp = sb->ptr;
    if (tmp == NULL) tmp = sb->ptrConst;
    SSF_REQUIRE(tmp[sb->len] == 0);

    return sb->isConst;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if string buffer allocated from heap, else false.                                */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufIsHeap(const SSFCStrBuf_t *sb)
{
    const char *tmp;

    SSF_REQUIRE(sb != NULL);
    SSF_REQUIRE(((sb->ptr != NULL) && (sb->ptrConst == NULL)) ||
                ((sb->ptr == NULL) && (sb->ptrConst != NULL)));
    SSF_REQUIRE(sb->len < sb->size);
    SSF_REQUIRE(sb->magic == SSF_STR_MAGIC);
    tmp = sb->ptr;
    if (tmp == NULL) tmp = sb->ptrConst;
    SSF_REQUIRE(tmp[sb->len] == 0);

    return sb->isHeap;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if string buffer is valid else false.                                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufIsValid(const SSFCStrBuf_t *sb)
{
    const char *tmp;

    if (sb == NULL) return false;
    if (((sb->ptr != NULL) && (sb->ptrConst != NULL)) ||
        ((sb->ptr == NULL) && (sb->ptrConst == NULL))) return false;
    if (sb->size > SSF_STRB_MAX_SIZE) return false;
    if (sb->len >= sb->size) return false;
    if (sb->magic != SSF_STR_MAGIC) return false;
    tmp = sb->ptr;
    if (tmp == NULL)
    {
        if (sb->isConst == false) return false;
        tmp = sb->ptrConst;
    }
    if (tmp[sb->len] != 0) return false;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns pointer to string buffer's string.                                                    */
/* --------------------------------------------------------------------------------------------- */
const char *SSFStrBufPtr(const SSFCStrBuf_t *sb)
{
    const char *tmp;

    SSF_REQUIRE(sb != NULL);
    SSF_REQUIRE(((sb->ptr != NULL) && (sb->ptrConst == NULL)) ||
                ((sb->ptr == NULL) && (sb->ptrConst != NULL)));
    SSF_REQUIRE(sb->len < sb->size);
    SSF_REQUIRE(sb->magic == SSF_STR_MAGIC);
    tmp = sb->ptr;
    if (tmp == NULL) tmp = sb->ptrConst;
    SSF_REQUIRE(tmp[sb->len] == 0);

    return tmp;
}

/* --------------------------------------------------------------------------------------------- */
/* Sets entire string buffer and len to 0.                                                       */
/* --------------------------------------------------------------------------------------------- */
void SSFStrBufClr(SSFCStrBuf_t *sbOut)
{
    SSF_REQUIRE(sbOut != NULL);
    SSF_REQUIRE((sbOut->ptr != NULL) && (sbOut->ptrConst == NULL));
    SSF_REQUIRE(sbOut->len < sbOut->size);
    SSF_REQUIRE(sbOut->isConst == false);
    SSF_REQUIRE(sbOut->magic == SSF_STR_MAGIC);

    memset(sbOut->ptr, 0, sbOut->size);
    sbOut->len = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if src fully catted to dst with NULL terminator, else false.                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufCat(SSFCStrBuf_t *dstOut, const SSFCStrBuf_t *src)
{
    const char *tmp;

    SSF_REQUIRE(dstOut != NULL);
    SSF_REQUIRE((dstOut->ptr != NULL) && (dstOut->ptrConst == NULL));
    SSF_REQUIRE(dstOut->len < dstOut->size);
    SSF_REQUIRE(dstOut->isConst == false);
    SSF_REQUIRE(dstOut->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(dstOut->ptr[dstOut->len] == 0);
    SSF_REQUIRE(dstOut != src);
    SSF_REQUIRE(src != NULL);
    SSF_REQUIRE(((src->ptr != NULL) && (src->ptrConst == NULL)) ||
                ((src->ptr == NULL) && (src->ptrConst != NULL)));
    SSF_REQUIRE(src->len < src->size);
    SSF_REQUIRE(src->magic == SSF_STR_MAGIC);
    tmp = src->ptr;
    if (tmp == NULL) tmp = src->ptrConst;
    SSF_REQUIRE(tmp[src->len] == 0);
    SSF_REQUIRE(dstOut->ptr != src->ptr);

    /* Will src fully cat to dst? */
    if ((dstOut->len + src->len) >= dstOut->size) return false;

    /* Perform cat, update out len, and NULL terminate dst */
    memcpy(&dstOut->ptr[dstOut->len], tmp, src->len);
    dstOut->len += src->len;
    dstOut->ptr[dstOut->len] = 0;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if src fully copied to dst with NULL terminator, else false.                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufCpy(SSFCStrBuf_t *dstOut, const SSFCStrBuf_t *src)
{
    const char *tmp;

    SSF_REQUIRE(dstOut != NULL);
    SSF_REQUIRE((dstOut->ptr != NULL) && (dstOut->ptrConst == NULL));
    SSF_REQUIRE(dstOut->len < dstOut->size);
    SSF_REQUIRE(dstOut->isConst == false);
    SSF_REQUIRE(dstOut->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(dstOut->ptr[dstOut->len] == 0);
    SSF_REQUIRE(dstOut != src);
    SSF_REQUIRE(src != NULL);
    SSF_REQUIRE(((src->ptr != NULL) && (src->ptrConst == NULL)) ||
                ((src->ptr == NULL) && (src->ptrConst != NULL)));
    SSF_REQUIRE(src->len < src->size);
    SSF_REQUIRE(src->magic == SSF_STR_MAGIC);
    tmp = src->ptr;
    if (tmp == NULL) tmp = src->ptrConst;
    SSF_REQUIRE(tmp[src->len] == 0);

    /* Will src fully cpy to dst? */
    if (src->len >= dstOut->size) return false;

    /* Perform cpy, update out len, and NULL terminate dst */
    tmp = src->ptr;
    if (tmp == NULL) tmp = src->ptrConst;
    memcpy(dstOut->ptr, tmp, src->len);
    dstOut->len = src->len;
    dstOut->ptr[dstOut->len] = 0;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if both strings exactly match, else false.                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufCmp(const SSFCStrBuf_t *sb1, const SSFCStrBuf_t *sb2)
{
    const char *tmp1;
    const char *tmp2;

    SSF_REQUIRE(sb1 != NULL);
    SSF_REQUIRE(((sb1->ptr != NULL) && (sb1->ptrConst == NULL)) ||
                ((sb1->ptr == NULL) && (sb1->ptrConst != NULL)));
    SSF_REQUIRE(sb1->len < sb1->size);
    SSF_REQUIRE(sb1->magic == SSF_STR_MAGIC);
    tmp1 = sb1->ptr;
    if (tmp1 == NULL) tmp1 = sb1->ptrConst;
    SSF_REQUIRE(tmp1[sb1->len] == 0);
    SSF_REQUIRE(sb1 != sb2);
    SSF_REQUIRE(sb2 != NULL);
    SSF_REQUIRE(((sb2->ptr != NULL) && (sb2->ptrConst == NULL)) ||
                ((sb2->ptr == NULL) && (sb2->ptrConst != NULL)));
    SSF_REQUIRE(sb2->len < sb2->size);
    SSF_REQUIRE(sb2->magic == SSF_STR_MAGIC);
    tmp2 = sb2->ptr;
    if (tmp2 == NULL) tmp2 = sb2->ptrConst;
    SSF_REQUIRE(tmp2[sb2->len] == 0);

    /* Same length? */
    if (sb1->len != sb2->len) return false;

    /* Match exactly? */
    return memcmp(tmp1, tmp2, sb1->len + 1) == 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Converts sb to desired case.                                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFStrBufToCase(SSFCStrBuf_t *sbOut, SSFStrBufCase_t toCase)
{
    #define SSFSTR_UPPER_LOWER_DELTA ((int8_t)('a' - 'A'))
    char *ptr;
    size_t len;

    SSF_REQUIRE(sbOut != NULL);
    SSF_REQUIRE((sbOut->ptr != NULL) && (sbOut->ptrConst == NULL));
    SSF_REQUIRE(sbOut->len < sbOut->size);
    SSF_REQUIRE(sbOut->isConst == false);
    SSF_REQUIRE(sbOut->magic == SSF_STR_MAGIC);
    SSF_REQUIRE(sbOut->ptr[sbOut->len] == 0);
    SSF_REQUIRE((toCase > SSF_STRB_CASE_MIN) && (toCase < SSF_STRB_CASE_MAX));

    ptr = sbOut->ptr;
    len = sbOut->len;
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
