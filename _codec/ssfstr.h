/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfstr.h                                                                                      */
/* Provides safe C string interfaces.                                                            */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2023 Supurloop Software LLC                                                         */
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
#ifndef SSF_STR_H_INCLUDE
#define SSF_STR_H_INCLUDE

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
#define SSF_STR_MAX_SIZE ((size_t)(1024ull * 1024ull))

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
    SSF_STR_CASE_MIN = -1,
    SSF_STR_CASE_LOWER,
    SSF_STR_CASE_UPPER,
    SSF_STR_CASE_MAX,
} SSFStrCase_t;


/* --------------------------------------------------------------------------------------------- */
/* Public Interface                                                                              */
/* --------------------------------------------------------------------------------------------- */
bool SSFStrInit(SSFCStrBuf_t *sbOut, const SSFCStr_t cstr, size_t cstrSize, bool isConst);
#define SSFStrInitBuf(sbOut, cstr, cstrSize) SSFStrInit(sbOut, cstr, cstrSize, false)
#define SSFStrInitConst(sbOut, cstr) SSFStrInit(sbOut, cstr, sizeof(cstr), true)
bool SSFStrInitHeap(SSFCStrBuf_t* sbOut, size_t size, const SSFCStr_t initCstr, size_t initCstrSize);
void SSFStrDeInit(SSFCStrBuf_t *sbOut);
size_t SSFStrLen(const SSFCStrBuf_t *sb);
void SSFStrClr(SSFCStrBuf_t* sbOut);
bool SSFStrCat(SSFCStrBuf_t *dstOut, const SSFCStrBuf_t *src);
bool SSFStrCpy(SSFCStrBuf_t* dstOut, const SSFCStrBuf_t* src);
bool SSFStrCmp(const SSFCStrBuf_t* sb1, const SSFCStrBuf_t* sb2);
void SSFStrToCase(SSFCStrBuf_t* dstOut, SSFStrCase_t toCase);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_STR_UNIT_TEST == 1
void SSFStrUnitTest(void);
#endif /* SSF_CONFIG_STR_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_STR_H_INCLUDE */

