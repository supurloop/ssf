/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfport.h                                                                                     */
/* Provides port interface.                                                                      */
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
#ifndef SSF_PORT_H_INCLUDE
#define SSF_PORT_H_INCLUDE

#include "Windows.h"
#include "ssfassert.h"

/* --------------------------------------------------------------------------------------------- */
/* MAX/MIN macros                                                                                */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define SSF_MIN(x, y) (((x) < (y)) ? (x) : (y))

/* --------------------------------------------------------------------------------------------- */
/* Enable/disable unit tests                                                                     */
/* --------------------------------------------------------------------------------------------- */
#define SSF_CONFIG_BFIFO_UNIT_TEST (1u)
#define SSF_CONFIG_LL_UNIT_TEST (1u)
#define SSF_CONFIG_MPOOL_UNIT_TEST (1u)
#define SSF_CONFIG_JSON_UNIT_TEST (1u)
#define SSF_CONFIG_BASE64_UNIT_TEST (1u)
#define SSF_CONFIG_HEX_UNIT_TEST (1u)
#define SSF_CONFIG_FCSUM_UNIT_TEST (1u)

/* If any unit test is enabled then enable unit test mode */
#if SSF_CONFIG_BFIFO_UNIT_TEST == 1 || \
    SSF_CONFIG_LL_UNIT_TEST == 1 || \
    SSF_CONFIG_MPOOL_UNIT_TEST == 1 || \
    SSF_CONFIG_JSON_UNIT_TEST == 1 || \
    SSF_CONFIG_BASE64_UNIT_TEST == 1 || \
    SSF_CONFIG_HEX_UNIT_TEST == 1 || \
    SSF_CONFIG_FCSUM_UNIT_TEST == 1
#define SSF_CONFIG_UNIT_TEST (1u)
#else
#define SSF_CONFIG_UNIT_TEST (0u)
#endif

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfbfifo's byte fifo interface                                                      */
/* --------------------------------------------------------------------------------------------- */
#define SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE (255UL)

#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY         (0u) /* Can this be defined differently? */
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255         (1u)
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1 (2u)

#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE (SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255)
#define SSF_BFIFO_MULTI_BYTE_ENABLE                     (1u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfmpool's memory pool interface                                                    */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MPOOL_DEBUG (1u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfjson's parser limits                                                             */
/* --------------------------------------------------------------------------------------------- */
#define SSF_JSON_CONFIG_MAX_IN_DEPTH (4u)
#define SSF_JSON_CONFIG_MAX_IN_LEN  (2047u)
#define SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE (1u)
#define SSF_JSON_CONFIG_ENABLE_FLOAT_GEN (1u)
#define SSF_JSON_CONFIG_ENABLE_UPDATE (1u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfsm's state machine interface                                                     */
/* --------------------------------------------------------------------------------------------- */
#define SSF_SM_MAX_ACTIVE_EVENTS (3u)
#define SSF_SM_MAX_ACTIVE_TIMERS (3u)

enum SSFSMList
{
    SSF_SM_TEST1,
    SSF_SM_JSON,
    SSF_SM_END
};

enum SSFSMEventList
{
    SSF_SM_EVENT_ENTRY,
    SSF_SM_EVENT_EXIT,
    SSF_SM_EVENT_1,
    SSF_SM_EVENT_2,
    SSF_SM_JSON_BYTE,
    SSF_SM_EVENT_END
};

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
__declspec(noreturn) void SSFPortAssert(const char* file, uint32_t line);
#define SSFSMGetTick64() GetTickCount64()

/* Use to suppress unused parameter warnings */
#define SSF_UNUSED(x) ssfUnused = (void *)x
extern void* ssfUnused;

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

#endif /* SSF_PORT_H_INCLUDE */
