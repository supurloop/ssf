/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssf.h                                                                                         */
/* Provides core framework definitions.                                                          */
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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_H_INCLUDE
#define SSF_H_INCLUDE
#include <string.h>

/* --------------------------------------------------------------------------------------------- */
/* Macros and typedefs                                                                           */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define SSF_MIN(x, y) (((x) < (y)) ? (x) : (y))

typedef const char *SSFCStrIn_t;
typedef char *SSFCStrOut_t;

/* Use to suppress unused parameter warnings */
#define SSF_UNUSED(x) ssfUnused = (void *)x
extern void *ssfUnused;

#if SSF_CONFIG_UNIT_TEST == 1
    #include <setjmp.h>
extern jmp_buf ssfUnitTestMark;
extern int ssfUnitTestJmpRet;

    #define SSF_ASSERT_TEST(t) do { \
    ssfUnitTestJmpRet = setjmp(ssfUnitTestMark); \
    if (ssfUnitTestJmpRet == 0) {t;} \
    if (ssfUnitTestJmpRet != -1) { \
        printf("SSF Assertion: %s:%u\r\n", __FILE__, __LINE__); \
        for(;;); } \
    memset(ssfUnitTestMark, 0, sizeof(ssfUnitTestMark)); } while (0)

#endif /* SSF_CONFIG_UNIT_TEST */
#endif /* SSF_H_INCLUDE */

