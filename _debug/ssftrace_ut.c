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
    SSF_ASSERT_TEST(SSFTraceInit(&_strTraces[0], 0, _strBuffers[0],
                                 STR_TEST_TRACE_SIZE + (1UL)));
    SSF_ASSERT_TEST(SSFTraceInit(&_strTraces[0], STR_TEST_TRACE_SIZE, _strBuffers[0], 0));

    /* Test SSFTraceDeInit assertions */
    SSF_ASSERT_TEST(SSFTraceDeInit(NULL));

    /* Test SSFTraceGetByte assertions */
    SSF_ASSERT_TEST(SSFTraceGetByte(NULL, &outByte));
    SSF_ASSERT_TEST(SSFTraceGetByte(&_strTraces[0], NULL));

    /* Initialize traces and verify empty via SSFTraceGetByte */
    for (j = 0; j < STR_TEST_NUM_TRACES; j++)
    {
        SSFTraceInit(&_strTraces[j], STR_TEST_TRACE_SIZE, _strBuffers[j],
                     STR_TEST_TRACE_SIZE + (1UL));
        SSF_ASSERT(SSFTraceGetByte(&_strTraces[j], &outByte) == false);
    }

    /* Double init should assert (underlying FIFO is already initialized) */
    SSF_ASSERT_TEST(SSFTraceInit(&_strTraces[0], STR_TEST_TRACE_SIZE, _strBuffers[0],
                                 STR_TEST_TRACE_SIZE + (1UL)));

    /* Put and get one byte at a time via trace API until wrap occurs */
    for (j = 0; j < STR_TEST_TRACE_SIZE * (2UL); j++)
    {
        SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == false);

        SSF_TRACE_PUT_BYTE(&_strTraces[0], (uint8_t)(j + 1));

        outByte = 0;
        SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == true);
        SSF_ASSERT(outByte == (uint8_t)(j + 1));

        SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == false);
    }

    /* Fill trace to capacity via SSF_TRACE_PUT_BYTE */
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSF_TRACE_PUT_BYTE(&_strTraces[0], (uint8_t)(j + 0x10));
    }

    /* Empty trace and verify data integrity via SSFTraceGetByte */
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        outByte = 0;
        SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == true);
        SSF_ASSERT(outByte == (uint8_t)(j + 0x10));
    }
    SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == false);

    /* SSF_TRACE_PUT_BYTE auto-discards oldest byte when full */
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSF_TRACE_PUT_BYTE(&_strTraces[0], (uint8_t)(j + 0x20));
    }
    /* Trace is now full; put one more byte which should discard oldest (0x20) */
    SSF_TRACE_PUT_BYTE(&_strTraces[0], 0xFF);
    /* First byte out should be 0x21 (second byte originally put) */
    outByte = 0;
    SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == true);
    SSF_ASSERT(outByte == 0x21);
    /* Drain remaining original bytes */
    for (j = 2; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == true);
        SSF_ASSERT(outByte == (uint8_t)(j + 0x20));
    }
    /* Last byte should be the overflow byte */
    SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == true);
    SSF_ASSERT(outByte == 0xFF);
    SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == false);

    /* Fill/empty/fill/empty: data integrity across wrap-around */
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSF_TRACE_PUT_BYTE(&_strTraces[0], (uint8_t)(j + 0x30));
    }
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == true);
        SSF_ASSERT(outByte == (uint8_t)(j + 0x30));
    }
    /* Second fill/empty with head/tail at mid-buffer position */
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSF_TRACE_PUT_BYTE(&_strTraces[0], (uint8_t)(j + 0x40));
    }
    for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
    {
        SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == true);
        SSF_ASSERT(outByte == (uint8_t)(j + 0x40));
    }
    SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == false);

    /* SSF_TRACE_PUT_BYTES: put multiple bytes and verify */
    {
        uint8_t *p;
        uint32_t n;
        const uint8_t msg[] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5};

        p = (uint8_t *)msg;
        n = sizeof(msg);
        SSF_TRACE_PUT_BYTES(&_strTraces[0], p, n);
        for (j = 0; j < sizeof(msg); j++)
        {
            outByte = 0;
            SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == true);
            SSF_ASSERT(outByte == msg[j]);
        }
        SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == false);
    }

    /* SSF_TRACE_PUT_BYTES: auto-discard when more bytes than capacity */
    {
        uint8_t putBuf[STR_TEST_TRACE_SIZE + 3];
        uint8_t *p;
        uint32_t n;

        for (j = 0; j < sizeof(putBuf); j++) { putBuf[j] = (uint8_t)(j + 0x50); }
        p = putBuf;
        n = sizeof(putBuf);
        SSF_TRACE_PUT_BYTES(&_strTraces[0], p, n);
        /* Only last STR_TEST_TRACE_SIZE bytes should remain (oldest 3 discarded) */
        for (j = 0; j < STR_TEST_TRACE_SIZE; j++)
        {
            outByte = 0;
            SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == true);
            SSF_ASSERT(outByte == (uint8_t)(j + 3 + 0x50));
        }
        SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == false);
    }

    /* Verify second trace instance is independent */
    SSF_TRACE_PUT_BYTE(&_strTraces[1], 0xAA);
    SSF_ASSERT(SSFTraceGetByte(&_strTraces[0], &outByte) == false);
    outByte = 0;
    SSF_ASSERT(SSFTraceGetByte(&_strTraces[1], &outByte) == true);
    SSF_ASSERT(outByte == 0xAA);
    SSF_ASSERT(SSFTraceGetByte(&_strTraces[1], &outByte) == false);

    /* Deinit all traces and verify zeroed */
    memset(&traceZero, 0, sizeof(traceZero));
    for (j = 0; j < STR_TEST_NUM_TRACES; j++)
    {
        SSFTraceDeInit(&_strTraces[j]);
        SSF_ASSERT(memcmp(&_strTraces[j], &traceZero, sizeof(traceZero)) == 0);
    }
}
#endif /* SSF_CONFIG_TRACE_UNIT_TEST */
