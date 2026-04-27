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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_H_INCLUDE
#define SSF_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* --------------------------------------------------------------------------------------------- */
/* Macros and typedefs                                                                           */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define SSF_MIN(x, y) (((x) < (y)) ? (x) : (y))
#define SSF_MAX_NEXT_TIMEOUT ((SSFPortTick_t)(-1))
#define SSFIsDigit(c) ((c) >= '0' && (c) <= '9')
#define MOD255(m) ((m) % 255)

/* 32-bit left rotate. x must be uint32_t; n must be in [1, 31]. */
#define SSF_ROTL32(x, n) (((x) << (n)) | ((x) >> (32u - (n))))

/* Byte-buffer <-> integer serialization helpers used by cryptographic code.
 * Bit-shifts make these independent of host byte order; each TU gets its own
 * inlined copy. p points at 4 bytes (U32) or 8 bytes (U64) the caller has
 * already sized. */

static inline uint32_t SSF_GETU32LE(const uint8_t *p)
{
    return  (uint32_t)p[0]        | ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void SSF_PUTU32LE(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v      );
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void SSF_PUTU64LE(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v      );
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static inline uint32_t SSF_GETU32BE(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static inline void SSF_PUTU32BE(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v      );
}

static inline uint64_t SSF_GETU64BE(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] <<  8) |  (uint64_t)p[7];
}

static inline void SSF_PUTU64BE(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >>  8);
    p[7] = (uint8_t)(v      );
}

typedef const char *SSFCStrIn_t;
typedef char *SSFCStrOut_t;
typedef void (*SSFVoidFn_t)(void); /* Generic function pointer type */

/* Use to suppress unused parameter warnings */
#define SSF_UNUSED_PTR(x) ssfUnusedPtr = (void *)(x)
#define SSF_UNUSED_INT(x) ssfUnusedInt = (uint64_t)(x)
extern void *ssfUnusedPtr;
extern uint64_t ssfUnusedInt;

#if SSF_CONFIG_UNIT_TEST == 1
    #include <setjmp.h>
extern jmp_buf ssfUnitTestMark;
extern int ssfUnitTestJmpRet;

    #define SSF_ASSERT_TEST(t) do { \
    ssfUnitTestJmpRet = setjmp(ssfUnitTestMark); \
    if (ssfUnitTestJmpRet == 0) {t;} \
    if (ssfUnitTestJmpRet != -1) { \
        printf("SSF Assertion Test: %s:%u\r\n", __FILE__, (unsigned int)__LINE__); \
        exit(1); } \
    memset(ssfUnitTestMark, 0, sizeof(ssfUnitTestMark)); } while (0)

#endif /* SSF_CONFIG_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_H_INCLUDE */
