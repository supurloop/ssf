/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfstrb.h                                                                                     */
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
#ifndef SSF_STRB_H_INCLUDE
#define SSF_STRB_H_INCLUDE

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Public Defines                                                                                */
/* --------------------------------------------------------------------------------------------- */
typedef struct
{
    char *ptr;
    size_t len;
    size_t size;
    uint32_t magic;
    bool isConst;
    bool isHeap;
} SSFCStrBuf_t;

typedef enum
{
    SSF_STRB_CASE_MIN = -1,
    SSF_STRB_CASE_LOWER,
    SSF_STRB_CASE_UPPER,
    SSF_STRB_CASE_MAX,
} SSFStrBufCase_t;

/* --------------------------------------------------------------------------------------------- */
/* Public Interface                                                                              */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrBufInit(SSFCStrBuf_t *sbOut, SSFCStr_t cstr, size_t cstrSize, bool isConst, bool isHeap);
#define SSFStrBufInitVar(sbOut, cstr, cstrSize) SSFStrBufInit(sbOut, cstr, cstrSize, false, false)
#define SSFStrBufInitVarMalloc(sbOut, cstr, cstrSize) SSFStrBufInit(sbOut, cstr, cstrSize, false, true)
#define SSFStrBufInitConst(sbOut, cstr) SSFStrBufInit(sbOut, cstr, sizeof(cstr), true, false)
void SSFStrBufDeInit(SSFCStrBuf_t *sbOut);
size_t SSFStrBufLen(const SSFCStrBuf_t *sb);
size_t SSFStrBufSize(const SSFCStrBuf_t *sb);
void SSFStrBufClr(SSFCStrBuf_t *sbOut);
bool SSFStrBufCat(SSFCStrBuf_t *dstOut, const SSFCStrBuf_t *src);
bool SSFStrBufCpy(SSFCStrBuf_t *dstOut, const SSFCStrBuf_t *src);
bool SSFStrBufCmp(const SSFCStrBuf_t *sb1, const SSFCStrBuf_t *sb2);
void SSFStrBufToCase(SSFCStrBuf_t *dstOut, SSFStrBufCase_t toCase);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_STRB_UNIT_TEST == 1
void SSFStrBufUnitTest(void);
#endif /* SSF_CONFIG_STRB_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_STRB_H_INCLUDE */

