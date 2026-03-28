/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftrace_ut.c                                                                                 */
/* Provides unit tests for ssftrace's debug trace interface.                                     */
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
#include <string.h>
#include "ssftrace.h"
#include "ssfport.h"

#if SSF_CONFIG_TRACE_UNIT_TEST == 1
    #if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255
        #define STR_TEST_TRACE_SIZE (SSF_BFIFO_255)
    #elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
        #define STR_TEST_TRACE_SIZE (511UL)
    #elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY
        #define STR_TEST_TRACE_SIZE (333667UL)
    #endif /* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE */

    #define STR_TEST_NUM_TRACES (2u)

static SSFTrace_t _strTraces[STR_TEST_NUM_TRACES];
static uint8_t _strBuffers[STR_TEST_NUM_TRACES][STR_TEST_TRACE_SIZE + (1UL)];

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssftrace's external interface.                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFTraceUnitTest(void)
{
    uint8_t outByte;
    uint32_t j;
    SSFTrace_t traceZero;

    /* Test SSFTraceInit assertions */
    SSF_ASSERT_TEST(SSFTraceInit(NULL, STR_TEST_TRACE_SIZE, _strBuffers[0],
                                 STR_TEST_TRACE_SIZE + (1UL)));
    SSF_ASSERT_TEST(SSFTraceInit(&_strTraces[0], STR_TEST_TRACE_SIZE, NULL,
                                 STR_TEST_TRACE_SIZE + (1UL)));
    SSF_ASSERT_TEST(SSFTraceInit(&_strTraces[0], STR_TEST_TRACE_SIZE, _strBuffers[0], 0));

    /* Test SSFTraceDeInit assertions */
    SSF_ASSERT_TEST(SSFTraceDeInit(NULL));

    /* Initialize traces and verify underlying FIFO is empty */
    for (j = 0; j < STR_TEST_NUM_TRACES; j++)
    {
        SSFTraceInit(&_strTraces[j], STR_TEST_TRACE_SIZE, _strBuffers[j],
                     STR_TEST_TRACE_SIZE + (1UL));
        SSF_ASSERT(SSFBFifoIsEmpty(&_strTraces[j].fifo) == true);
        SSF_ASSERT(SSFBFifoIsFull(&_strTraces[j].fifo) == false);
        SSF_ASSERT(SSFBFifoSize(&_strTraces[j].fifo) == STR_TEST_TRACE_SIZE);
        SSF_ASSERT(SSFBFifoLen(&_strTraces[j].fifo) == 0);
        SSF_ASSERT(SSFBFifoUnused(&_strTraces[j].fifo) == STR_TEST_TRACE_SIZE);
    }

    /* Double init should assert (underlying FIFO is already initialized) */
    SSF_ASSERT_TEST(SSFTraceInit(&_strTraces[0], STR_TEST_TRACE_SIZE, _strBuffers[0],
                                 STR_TEST_TRACE_SIZE + (1UL)));

    /* Put and get one byte at a time through underlying FIFO until wrap occurs */
    for (j = 0; j < STR_TEST_TRACE_SIZE * (2UL); j++)
    {
        SSF_ASSERT(SSFBFifoIsEmpty(&_strTraces[0].fifo) == true);
        SSF_ASSERT(SSFBFifoIsFull(&_strTraces[0].fifo) == false);
        SSF_ASSERT(SSFBFifoLen(&_strTraces[0].fifo) == 0);
        SSF_ASSERT(SSFBFifoUnused(&_strTraces[0].fifo) == STR_TEST_TRACE_SIZE);

        SSFBFifoPutByte(&_strTraces[0].fifo, (uint8_t)(j + 1));

        SSF_ASSERT(SSFBFifoIsEmpty(&_strTraces[0].fifo) == false);
        SSF_ASSERT(SSFBFifoIsFull(&_strTraces[0].fifo) == false);
        SSF_ASSERT(SSFBFifoLen(&_strTraces[0].fifo) == 1);
        SSF_ASSERT(SSFBFifoUnused(&_strTraces[0].fifo) == (STR_TEST_TRACE_SIZE - 1));

        outByte = 0;
        SSF_ASSERT(SSFBFifoPeekByte(&_strTraces[0].fifo, &outByte) == true);
        SSF_ASSERT(outByte == (uint8_t)(j + 1));
        SSF_ASSERT(SSFBFifoLen(&_strTraces[0].fifo) == 1);

        outByte = 0;
        SSF_ASSERT(SSFBFifoGetByte(&_strTraces[0].fifo, &outByte) == true);
        SSF_ASSERT(outByte == (uint8_t)(j + 1));
    }

    /* Fill underlying FIFO to capacity */
    SSF_ASSERT(SSFBFifoIsEmpty(&_strTraces[0].fifo) == true);
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSFBFifoPutByte(&_strTraces[0].fifo, (uint8_t)(j + 0x10));
        SSF_ASSERT(SSFBFifoLen(&_strTraces[0].fifo) == (j + 1));
    }
    SSF_ASSERT(SSFBFifoIsFull(&_strTraces[0].fifo) == true);
    SSF_ASSERT(SSFBFifoIsEmpty(&_strTraces[0].fifo) == false);
    SSF_ASSERT(SSFBFifoLen(&_strTraces[0].fifo) == STR_TEST_TRACE_SIZE);
    SSF_ASSERT(SSFBFifoUnused(&_strTraces[0].fifo) == 0);

    /* Empty underlying FIFO and verify data integrity */
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        outByte = 0;
        SSF_ASSERT(SSFBFifoGetByte(&_strTraces[0].fifo, &outByte) == true);
        SSF_ASSERT(outByte == (uint8_t)(j + 0x10));
    }
    SSF_ASSERT(SSFBFifoIsEmpty(&_strTraces[0].fifo) == true);
    SSF_ASSERT(SSFBFifoIsFull(&_strTraces[0].fifo) == false);
    SSF_ASSERT(SSFBFifoLen(&_strTraces[0].fifo) == 0);
    SSF_ASSERT(SSFBFifoUnused(&_strTraces[0].fifo) == STR_TEST_TRACE_SIZE);

    /* Fill/empty/fill/empty: data integrity across wrap-around */
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSFBFifoPutByte(&_strTraces[0].fifo, (uint8_t)(j + 0x20));
    }
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSF_ASSERT(SSFBFifoGetByte(&_strTraces[0].fifo, &outByte));
        SSF_ASSERT(outByte == (uint8_t)(j + 0x20));
    }
    /* Second fill/empty with head/tail at mid-buffer position */
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSFBFifoPutByte(&_strTraces[0].fifo, (uint8_t)(j + 0x30));
    }
    SSF_ASSERT(SSFBFifoIsFull(&_strTraces[0].fifo));
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSF_ASSERT(SSFBFifoGetByte(&_strTraces[0].fifo, &outByte));
        SSF_ASSERT(outByte == (uint8_t)(j + 0x30));
    }
    SSF_ASSERT(SSFBFifoIsEmpty(&_strTraces[0].fifo));

    /* Verify second trace instance is independent */
    SSFBFifoPutByte(&_strTraces[1].fifo, 0xAA);
    SSF_ASSERT(SSFBFifoIsEmpty(&_strTraces[0].fifo) == true);
    SSF_ASSERT(SSFBFifoIsEmpty(&_strTraces[1].fifo) == false);
    SSF_ASSERT(SSFBFifoLen(&_strTraces[1].fifo) == 1);
    outByte = 0;
    SSF_ASSERT(SSFBFifoGetByte(&_strTraces[1].fifo, &outByte) == true);
    SSF_ASSERT(outByte == 0xAA);
    SSF_ASSERT(SSFBFifoIsEmpty(&_strTraces[1].fifo) == true);

    /* Deinit all traces and verify zeroed */
    memset(&traceZero, 0, sizeof(traceZero));
    for (j = 0; j < STR_TEST_NUM_TRACES; j++)
    {
        SSFTraceDeInit(&_strTraces[j]);
        SSF_ASSERT(memcmp(&_strTraces[j], &traceZero, sizeof(traceZero)) == 0);
    }
}
#endif /* SSF_CONFIG_TRACE_UNIT_TEST */
