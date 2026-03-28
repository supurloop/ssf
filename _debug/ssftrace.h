/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftrace.h                                                                                    */
/* Provides a high performance debug trace interface.                                            */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
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
#ifndef SSF_TRACE_INCLUDE_H
#define SSF_TRACE_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "ssfport.h"
#include "ssfbfifo.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
typedef struct
{
    SSFBFifo_t fifo;
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSFMutex_t mutex;
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
} SSFTrace_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFTraceInit(SSFTrace_t *trace, uint32_t traceSize, uint8_t *buffer, uint32_t bufferSize);
void SSFTraceDeInit(SSFTrace_t *trace);
bool SSFTraceGetByte(SSFTrace_t *trace, uint8_t *data);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
#define SSF_TRACE_PUT_BYTE(trace, u8) { \
    SSF_MUTEX_ACQUIRE((trace)->mutex); \
    if (SSF_BFIFO_IS_FULL(&((trace)->fifo))) { \
        SSF_BFIFO_PURGE_BYTE(&((trace)->fifo)); \
    } \
    SSF_BFIFO_PUT_BYTE(&((trace)->fifo), u8); \
    SSF_MUTEX_RELEASE((trace)->mutex); \
}
#else /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
#define SSF_TRACE_PUT_BYTE(trace, u8) { \
    if (SSF_BFIFO_IS_FULL(&((trace)->fifo))) { \
        SSF_BFIFO_PURGE_BYTE(&((trace)->fifo)); \
    } \
    SSF_BFIFO_PUT_BYTE(&((trace)->fifo), u8); \
}
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

#define SSF_TRACE_PUT_BYTES(trace, u8Ptr, len) { \
    while (len > 0) { \
        SSF_TRACE_PUT_BYTE(trace, *u8Ptr); \
        u8Ptr++; \
        len--; \
    } \
}

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_TRACE_UNIT_TEST == 1
void SSFTraceUnitTest(void);
#endif /* SSF_CONFIG_TRACE_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_TRACE_INCLUDE_H */

