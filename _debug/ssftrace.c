/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftrace.c                                                                                    */
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
#include <stdint.h>
#include <stdbool.h>
#include "ssfassert.h"
#include "ssfport.h"
#include "ssftrace.h"

/* --------------------------------------------------------------------------------------------- */
/* Initializes a trace buffer.                                                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFTraceInit(SSFTrace_t *trace, uint32_t traceSize, uint8_t *buffer, uint32_t bufferSize)
{
    SSF_REQUIRE(trace != NULL);
    SSF_REQUIRE(buffer != NULL);
    SSF_REQUIRE(traceSize > 0);
    SSF_REQUIRE(bufferSize > 0);

    SSFBFifoInit(&(trace->fifo), traceSize, buffer, bufferSize);
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_MUTEX_INIT(trace->mutex);
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes a trace buffer.                                                                 */
/* --------------------------------------------------------------------------------------------- */
void SSFTraceDeInit(SSFTrace_t *trace)
{
    SSF_REQUIRE(trace != NULL);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_MUTEX_DEINIT(trace->mutex);
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
    SSFBFifoDeInit(&(trace->fifo));
    memset(trace, 0, sizeof(SSFTrace_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if byte read and stored to data, else false.                                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFTraceGetByte(SSFTrace_t *trace, uint8_t *data)
{
    bool retVal = false;

    SSF_REQUIRE(trace != NULL);
    SSF_REQUIRE(data != NULL);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_MUTEX_ACQUIRE((trace)->mutex);
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

    if (SSF_BFIFO_IS_EMPTY(&((trace)->fifo)) == false)
    {
        SSF_BFIFO_GET_BYTE(&((trace)->fifo), *data);
        retVal = true;
    }

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_MUTEX_RELEASE((trace)->mutex);
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

    return retVal;
}

