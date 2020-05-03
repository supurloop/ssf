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

// TODOS
// use _ for static vars and functions
// SSFJsonGetString escaped len is wrong
// Make SSFJsonWhitespace() a macro?
// Get rid of gotos in json.

/* --------------------------------------------------------------------------------------------- */
/* Platform specific tick configuration                                                          */
/* --------------------------------------------------------------------------------------------- */

/* Define SSFPortTick_t as unsigned 64-bit integer */
typedef uint64_t SSFPortTick_t;

/* Define the number of system ticks per second */
#define SSF_TICKS_PER_SEC (1000u)

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
#define SSF_CONFIG_SM_UNIT_TEST (1u)

/* If any unit test is enabled then enable unit test mode */
#if SSF_CONFIG_BFIFO_UNIT_TEST == 1 || \
    SSF_CONFIG_LL_UNIT_TEST == 1 || \
    SSF_CONFIG_MPOOL_UNIT_TEST == 1 || \
    SSF_CONFIG_JSON_UNIT_TEST == 1 || \
    SSF_CONFIG_BASE64_UNIT_TEST == 1 || \
    SSF_CONFIG_HEX_UNIT_TEST == 1 || \
    SSF_CONFIG_FCSUM_UNIT_TEST == 1 || \
    SSF_CONFIG_SM_UNIT_TEST == 1
#define SSF_CONFIG_UNIT_TEST (1u)
#else
#define SSF_CONFIG_UNIT_TEST (0u)
#endif

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfbfifo's byte fifo interface                                                      */
/* --------------------------------------------------------------------------------------------- */

/* Define the maximum fifo size. */
#define SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE (255UL)

#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY         (0u)
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255         (1u)
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1 (2u)

/* Define the allowed runtime fifo size. */
/* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY allows any fifo size up to
   SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE. */
/* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255 allows only fifo sizes of 255. */
/* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1 allows fifo sizes that are power of 2 minus 1
   up to SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE. */
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE (SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255)

/* Enable or disable the multi-byte fifo interface. */
#define SSF_BFIFO_MULTI_BYTE_ENABLE                     (1u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfmpool's memory pool interface                                                    */
/* --------------------------------------------------------------------------------------------- */
#define SSF_MPOOL_DEBUG (1u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfjson's parser limits                                                             */
/* --------------------------------------------------------------------------------------------- */
/* Define the maximum parse depth, each opening { or [ starts a new depth level. */
#define SSF_JSON_CONFIG_MAX_IN_DEPTH (4u)

/* Define the maximum JSON string length to be parsed. */
#define SSF_JSON_CONFIG_MAX_IN_LEN  (2047u)

/* Allow parser to se floating point to convert numbers. */
#define SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE (1u)

/* Allow generator to print floats. */
#define SSF_JSON_CONFIG_ENABLE_FLOAT_GEN (1u)

/* Enable interface that can update specific fields in a JSON string. */
#define SSF_JSON_CONFIG_ENABLE_UPDATE (1u)

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfsm's state machine interface                                                     */
/* --------------------------------------------------------------------------------------------- */
/* Maximum number of simultaneously queued events for all state machines. */
#define SSF_SM_MAX_ACTIVE_EVENTS (3u)

/* Maximum number of simultaneously running timers for all state machines. */
#define SSF_SM_MAX_ACTIVE_TIMERS (3u)

/* Defines the state machine identifers. */
enum SSFSMList
{
#if SSF_CONFIG_SM_UNIT_TEST == 1
    SSF_SM_UNIT_TEST_1,
    SSF_SM_UNIT_TEST_2,
#endif /* SSF_CONFIG_SM_UNIT_TEST */
    SSF_SM_END
};

/* Defines the event identifiers for all state machines. */
enum SSFSMEventList
{
    SSF_SM_EVENT_ENTRY,
    SSF_SM_EVENT_EXIT,
#if SSF_CONFIG_SM_UNIT_TEST == 1
    SSF_SM_EVENT_UT1_1,
    SSF_SM_EVENT_UT1_2,
    SSF_SM_EVENT_UT2_1,
    SSF_SM_EVENT_UT2_2,
    SSF_SM_EVENT_UTX_1,
    SSF_SM_EVENT_UTX_2,
#endif /* SSF_CONFIG_SM_UNIT_TEST */
    SSF_SM_EVENT_END
};

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
__declspec(noreturn) void SSFPortAssert(const char* file, uint32_t line);
#define SSFSMGetTick64() GetTickCount64()

#include "ssf.h"
#endif /* SSF_PORT_H_INCLUDE */
