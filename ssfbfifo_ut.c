/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbfifo_ut.c                                                                                 */
/* Provides unit tests for ssfbfifo's byte fifo interface.                                       */
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
#include "ssfbfifo.h"
#include "ssfport.h"

#if SSF_CONFIG_BFIFO_UNIT_TEST == 1
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255
#define SSF_TEST_BFIFO_SIZE (SSF_BFIFO_255)
#elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
#define SSF_TEST_BFIFO_SIZE (511UL)
#elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY
#define SSF_TEST_BFIFO_SIZE (333667UL)
#endif /* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE */

#define SBF_TEST_NUM_FIFOS (2u)
static SSFBFifo_t _sbfFifos[SBF_TEST_NUM_FIFOS];
static uint8_t _sbfBuffers[SBF_TEST_NUM_FIFOS][SSF_TEST_BFIFO_SIZE + (1UL)];
#if SSF_BFIFO_MULTI_BYTE_ENABLE == 1
static uint8_t _sbfReadBuf[SSF_TEST_BFIFO_SIZE];
#endif /* SSF_BFIFO_MULTI_BYTE_ENABLE */

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfbfifo's external interface.                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFBFifoUnitTest(void)
{
    uint8_t outByte;
    uint32_t i;
    uint32_t j;
#if SSF_BFIFO_MULTI_BYTE_ENABLE == 1
    uint32_t outLen;
#endif /* SSF_BFIFO_MULTI_BYTE_ENABLE */

    /* Test assertions */
    SSF_ASSERT_TEST(SSFBFifoInit(NULL, SSF_TEST_BFIFO_SIZE, _sbfBuffers[0], SSF_TEST_BFIFO_SIZE + (1UL)));
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE != SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY
    SSF_ASSERT_TEST(SSFBFifoInit(&_sbfFifos[0], SSF_TEST_BFIFO_SIZE - 1, _sbfBuffers[0], SSF_TEST_BFIFO_SIZE + (1UL)));
#endif /* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE */
    SSF_ASSERT_TEST(SSFBFifoInit(&_sbfFifos[0], 0, _sbfBuffers[0], SSF_TEST_BFIFO_SIZE + (1UL)));
    SSF_ASSERT_TEST(SSFBFifoInit(&_sbfFifos[0], SSF_TEST_BFIFO_SIZE, NULL, SSF_TEST_BFIFO_SIZE + (1UL)));
    SSF_ASSERT_TEST(SSFBFifoInit(&_sbfFifos[0], SSF_TEST_BFIFO_SIZE, _sbfBuffers[0], SSF_TEST_BFIFO_SIZE));
    SSF_ASSERT_TEST(SSFBFifoInit(&_sbfFifos[0], SSF_TEST_BFIFO_SIZE, _sbfBuffers[0], 0));
    
    SSF_ASSERT_TEST(SSFBFifoPutByte(NULL, 0));
    SSF_ASSERT_TEST(SSFBFifoPutByte(&_sbfFifos[0], 0));

    SSF_ASSERT_TEST(SSFBFifoPeekByte(NULL, &outByte));
    SSF_ASSERT_TEST(SSFBFifoPeekByte(&_sbfFifos[0], NULL));
    SSF_ASSERT_TEST(SSFBFifoPeekByte(&_sbfFifos[0], &outByte));

    SSF_ASSERT_TEST(SSFBFifoGetByte(NULL, &outByte));
    SSF_ASSERT_TEST(SSFBFifoGetByte(&_sbfFifos[0], NULL));
    SSF_ASSERT_TEST(SSFBFifoGetByte(&_sbfFifos[0], &outByte));

    SSF_ASSERT_TEST(SSFBFifoIsEmpty(NULL));
    SSF_ASSERT_TEST(SSFBFifoIsEmpty(&_sbfFifos[0]));

    SSF_ASSERT_TEST(SSFBFifoIsFull(NULL));
    SSF_ASSERT_TEST(SSFBFifoIsFull(&_sbfFifos[0]));

    SSF_ASSERT_TEST(SSFBFifoSize(NULL));
    SSF_ASSERT_TEST(SSFBFifoSize(&_sbfFifos[0]));

    SSF_ASSERT_TEST(SSFBFifoLen(NULL));
    SSF_ASSERT_TEST(SSFBFifoLen(&_sbfFifos[0]));

#if SSF_BFIFO_MULTI_BYTE_ENABLE == 1
    SSF_ASSERT_TEST(SSFBFifoPutBytes(&_sbfFifos[0], "a", 1));
    SSF_ASSERT_TEST(SSFBFifoPeekBytes(&_sbfFifos[0], _sbfReadBuf, 0, &outLen));
    SSF_ASSERT_TEST(SSFBFifoGetBytes(&_sbfFifos[0], _sbfReadBuf, 0, &outLen));
#endif /* SSF_BFIFO_MULTI_BYTE_ENABLE */

    /* Initialization */
    for (i = 0; i < SBF_TEST_NUM_FIFOS; i++)
    {
        SSFBFifoInit(&_sbfFifos[i], SSF_TEST_BFIFO_SIZE, _sbfBuffers[i], SSF_TEST_BFIFO_SIZE + (1UL));
        SSF_ASSERT_TEST(SSFBFifoInit(&_sbfFifos[i], SSF_TEST_BFIFO_SIZE, _sbfBuffers[i], SSF_TEST_BFIFO_SIZE + (1UL)));
        SSF_ASSERT(SSFBFifoPeekByte(&_sbfFifos[i], &outByte) == false);
        SSF_ASSERT(SSFBFifoGetByte(&_sbfFifos[i], &outByte) == false);
        SSF_ASSERT(SSFBFifoIsEmpty(&_sbfFifos[i]) == true);
        SSF_ASSERT(SSFBFifoIsFull(&_sbfFifos[i]) == false);
        SSF_ASSERT(SSF_BFIFO_IS_EMPTY(&_sbfFifos[i]) == true);
        SSF_ASSERT(SSF_BFIFO_IS_FULL(&_sbfFifos[i]) == false);
        SSF_ASSERT(SSFBFifoSize(&_sbfFifos[i]) == SSF_TEST_BFIFO_SIZE);
        SSF_ASSERT(SSFBFifoLen(&_sbfFifos[i]) == 0);
    }

    /* Put and get one byte until wrap occurs */
    for (i = 0; i < SBF_TEST_NUM_FIFOS; i++)
    {
        for (j = 0; j < SSF_TEST_BFIFO_SIZE * (2UL); j++)
        {
            SSF_ASSERT(SSFBFifoPeekByte(&_sbfFifos[i], &outByte) == false);
            SSF_ASSERT(SSFBFifoGetByte(&_sbfFifos[i], &outByte) == false);
            SSF_ASSERT(SSFBFifoIsEmpty(&_sbfFifos[i]) == true);
            SSF_ASSERT(SSFBFifoIsFull(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSF_BFIFO_IS_EMPTY(&_sbfFifos[i]) == true);
            SSF_ASSERT(SSF_BFIFO_IS_FULL(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSFBFifoSize(&_sbfFifos[i]) == SSF_TEST_BFIFO_SIZE);
            SSF_ASSERT(SSFBFifoLen(&_sbfFifos[i]) == 0);

            if (i == 0) SSFBFifoPutByte(&_sbfFifos[i], (uint8_t) (j + 1));
            else SSF_BFIFO_PUT_BYTE(&_sbfFifos[i], (uint8_t)(j + 1));

            SSF_ASSERT(SSFBFifoIsEmpty(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSFBFifoIsFull(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSF_BFIFO_IS_EMPTY(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSF_BFIFO_IS_FULL(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSFBFifoSize(&_sbfFifos[i]) == SSF_TEST_BFIFO_SIZE);
            SSF_ASSERT(SSFBFifoLen(&_sbfFifos[i]) == 1);
            outByte = (uint8_t) j;
            SSF_ASSERT(SSFBFifoPeekByte(&_sbfFifos[i], &outByte) == true);
            SSF_ASSERT(outByte == (uint8_t) (j + 1));
            SSF_ASSERT(SSFBFifoLen(&_sbfFifos[i]) == 1);
            outByte = (uint8_t) j;
            if (i == 0) SSF_ASSERT(SSFBFifoGetByte(&_sbfFifos[i], &outByte) == true);
            else SSF_BFIFO_GET_BYTE(&_sbfFifos[i], outByte);
            SSF_ASSERT(outByte == (uint8_t) (j + 1));
        }
    }

    /* Fill and empty until wrap occurs */
    for (i = 0; i < SBF_TEST_NUM_FIFOS; i++)
    {
        /* Verify Empty */
        SSF_ASSERT(SSFBFifoPeekByte(&_sbfFifos[i], &outByte) == false);
        SSF_ASSERT(SSFBFifoGetByte(&_sbfFifos[i], &outByte) == false);
        SSF_ASSERT(SSFBFifoIsEmpty(&_sbfFifos[i]) == true);
        SSF_ASSERT(SSFBFifoIsFull(&_sbfFifos[i]) == false);
        SSF_ASSERT(SSF_BFIFO_IS_EMPTY(&_sbfFifos[i]) == true);
        SSF_ASSERT(SSF_BFIFO_IS_FULL(&_sbfFifos[i]) == false);
        SSF_ASSERT(SSFBFifoSize(&_sbfFifos[i]) == SSF_TEST_BFIFO_SIZE);
        SSF_ASSERT(SSFBFifoLen(&_sbfFifos[i]) == 0);
        SSF_ASSERT_TEST(SSF_BFIFO_GET_BYTE(&_sbfFifos[i], outByte));

        /* Fill */
        for (j = 0; j < SSF_TEST_BFIFO_SIZE - 1; j++)
        {
            if (i == 0) SSFBFifoPutByte(&_sbfFifos[i], (uint8_t)(j + 1));
            else SSF_BFIFO_PUT_BYTE(&_sbfFifos[i], (uint8_t)(j + 1));
            SSF_ASSERT(SSFBFifoIsEmpty(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSFBFifoIsFull(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSF_BFIFO_IS_EMPTY(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSF_BFIFO_IS_FULL(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSFBFifoSize(&_sbfFifos[i]) == SSF_TEST_BFIFO_SIZE);
            SSF_ASSERT(SSFBFifoLen(&_sbfFifos[i]) == (j + 1));
        }
        if (i == 0) SSFBFifoPutByte(&_sbfFifos[i], (uint8_t)(j + 1));
        else SSF_BFIFO_PUT_BYTE(&_sbfFifos[i], (uint8_t)(j + 1));

        /* Verify full */
        SSF_ASSERT(SSFBFifoIsEmpty(&_sbfFifos[i]) == false);
        SSF_ASSERT(SSFBFifoIsFull(&_sbfFifos[i]) == true);
        SSF_ASSERT(SSF_BFIFO_IS_EMPTY(&_sbfFifos[i]) == false);
        SSF_ASSERT(SSF_BFIFO_IS_FULL(&_sbfFifos[i]) == true);
        SSF_ASSERT(SSFBFifoSize(&_sbfFifos[i]) == SSF_TEST_BFIFO_SIZE);
        SSF_ASSERT(SSFBFifoLen(&_sbfFifos[i]) == SSF_TEST_BFIFO_SIZE);
        outByte = (uint8_t)j;
        SSF_ASSERT(SSFBFifoPeekByte(&_sbfFifos[i], &outByte) == true);
        SSF_ASSERT(outByte == 1);
        SSF_ASSERT(SSFBFifoLen(&_sbfFifos[i]) == SSF_TEST_BFIFO_SIZE);

        /* Empty */
        for (j = 0; j < SSF_TEST_BFIFO_SIZE - 1; j++)
        {
            outByte = (uint8_t)j;
            if (i == 0) SSF_ASSERT(SSFBFifoGetByte(&_sbfFifos[i], &outByte) == true);
            else SSF_BFIFO_GET_BYTE(&_sbfFifos[i], outByte);
            SSF_ASSERT(outByte == (uint8_t)(j + 1));
            SSF_ASSERT(SSFBFifoIsEmpty(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSFBFifoIsFull(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSF_BFIFO_IS_EMPTY(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSF_BFIFO_IS_FULL(&_sbfFifos[i]) == false);
            SSF_ASSERT(SSFBFifoSize(&_sbfFifos[i]) == SSF_TEST_BFIFO_SIZE);
            SSF_ASSERT(SSFBFifoLen(&_sbfFifos[i]) == (SSF_TEST_BFIFO_SIZE - j - 1));
        }
        if (i == 0) SSF_ASSERT(SSFBFifoGetByte(&_sbfFifos[i], &outByte) == true);
        else SSF_BFIFO_GET_BYTE(&_sbfFifos[i], outByte);

        /* Verify Empty */
        SSF_ASSERT(SSFBFifoPeekByte(&_sbfFifos[i], &outByte) == false);
        SSF_ASSERT(SSFBFifoGetByte(&_sbfFifos[i], &outByte) == false);
        SSF_ASSERT(SSFBFifoIsEmpty(&_sbfFifos[i]) == true);
        SSF_ASSERT(SSFBFifoIsFull(&_sbfFifos[i]) == false);
        SSF_ASSERT(SSF_BFIFO_IS_EMPTY(&_sbfFifos[i]) == true);
        SSF_ASSERT(SSF_BFIFO_IS_FULL(&_sbfFifos[i]) == false);
        SSF_ASSERT(SSFBFifoSize(&_sbfFifos[i]) == SSF_TEST_BFIFO_SIZE);
        SSF_ASSERT(SSFBFifoLen(&_sbfFifos[i]) == 0);
        SSF_ASSERT_TEST(SSF_BFIFO_GET_BYTE(&_sbfFifos[i], outByte));
    }

#if SSF_BFIFO_MULTI_BYTE_ENABLE == 1
    SSF_ASSERT_TEST(SSFBFifoPutBytes(NULL, "a", 1));
    SSF_ASSERT_TEST(SSFBFifoPutBytes(&_sbfFifos[0], NULL, 1));
    SSF_ASSERT_TEST(SSFBFifoPeekBytes(NULL, _sbfReadBuf, 0, &outLen));
    SSF_ASSERT_TEST(SSFBFifoPeekBytes(&_sbfFifos[0], NULL, 0, &outLen));
    SSF_ASSERT_TEST(SSFBFifoPeekBytes(&_sbfFifos[0], _sbfReadBuf, 0, NULL));
    SSF_ASSERT_TEST(SSFBFifoGetBytes(NULL, _sbfReadBuf, 0, &outLen));
    SSF_ASSERT_TEST(SSFBFifoGetBytes(&_sbfFifos[0], NULL, 0, &outLen));
    SSF_ASSERT_TEST(SSFBFifoGetBytes(&_sbfFifos[0], _sbfReadBuf, 0, NULL));

    SSFBFifoPutBytes(&_sbfFifos[0], "a", 1);
    outLen = 0x12345678;
    memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
    SSF_ASSERT(SSFBFifoPeekBytes(&_sbfFifos[0], _sbfReadBuf, 0, &outLen) == true);
    SSF_ASSERT(outLen == 0);
    outLen = 0x12345678;
    memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
    SSF_ASSERT(SSFBFifoGetBytes(&_sbfFifos[0], _sbfReadBuf, 0, &outLen) == true);
    SSF_ASSERT(outLen == 0);
    outLen = 0x12345678;
    memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
    SSF_ASSERT(SSFBFifoPeekBytes(&_sbfFifos[0], _sbfReadBuf, 1, &outLen) == true);
    SSF_ASSERT(outLen == 1);
    SSF_ASSERT(memcmp(_sbfReadBuf, "a", outLen) == 0);
    outLen = 0x12345678;
    memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
    SSF_ASSERT(SSFBFifoGetBytes(&_sbfFifos[0], _sbfReadBuf, 1, &outLen) == true);
    SSF_ASSERT(outLen == 1);
    SSF_ASSERT(memcmp(_sbfReadBuf, "a", outLen) == 0);
    SSF_ASSERT(SSFBFifoPeekBytes(&_sbfFifos[0], _sbfReadBuf, 1, &outLen) == false);
    SSF_ASSERT(SSFBFifoGetBytes(&_sbfFifos[0], _sbfReadBuf, 1, &outLen) == false);

    SSFBFifoPutBytes(&_sbfFifos[0], "123456", 7);
    outLen = 0x12345678;
    memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
    SSF_ASSERT(SSFBFifoPeekBytes(&_sbfFifos[0], _sbfReadBuf, 1, &outLen) == true);
    SSF_ASSERT(outLen == 1);
    SSF_ASSERT(memcmp(_sbfReadBuf, "1", outLen) == 0);
    outLen = 0x12345678;
    memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
    SSF_ASSERT(SSFBFifoGetBytes(&_sbfFifos[0], _sbfReadBuf, 1, &outLen) == true);
    SSF_ASSERT(outLen == 1);
    SSF_ASSERT(memcmp(_sbfReadBuf, "1", outLen) == 0);
    outLen = 0x12345678;
    memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
    SSF_ASSERT(SSFBFifoPeekBytes(&_sbfFifos[0], _sbfReadBuf, 10, &outLen) == true);
    SSF_ASSERT(outLen == 6);
    SSF_ASSERT(memcmp(_sbfReadBuf, "23456", outLen) == 0);
    outLen = 0x12345678;
    memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
    SSF_ASSERT(SSFBFifoGetBytes(&_sbfFifos[0], _sbfReadBuf, 10, &outLen) == true);
    SSF_ASSERT(outLen == 6);
    SSF_ASSERT(memcmp(_sbfReadBuf, "23456", outLen) == 0);

    for (i = 0; i < sizeof(_sbfReadBuf); i++) _sbfReadBuf[i] = (uint8_t) i;
    SSFBFifoPutBytes(&_sbfFifos[0], _sbfReadBuf, sizeof(_sbfReadBuf));
    outLen = 0x12345678;
    memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
    SSF_ASSERT(SSFBFifoPeekBytes(&_sbfFifos[0], _sbfReadBuf, sizeof(_sbfReadBuf), &outLen) == true);
    SSF_ASSERT(outLen == sizeof(_sbfReadBuf));
    for (i = 0; i < sizeof(_sbfReadBuf); i++) SSF_ASSERT(_sbfReadBuf[i] == (uint8_t) i);
    outLen = 0x12345678;
    memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
    SSF_ASSERT(SSFBFifoGetBytes(&_sbfFifos[0], _sbfReadBuf, sizeof(_sbfReadBuf), &outLen) == true);
    SSF_ASSERT(outLen == sizeof(_sbfReadBuf));
    for (i = 0; i < sizeof(_sbfReadBuf); i++) SSF_ASSERT(_sbfReadBuf[i] == (uint8_t) i);

    for (i = 0; i < (sizeof(_sbfReadBuf) << 1); i++)
    {
        SSFBFifoPutBytes(&_sbfFifos[0], "123456", 7);
        outLen = 0x12345678;
        memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
        SSF_ASSERT(SSFBFifoPeekBytes(&_sbfFifos[0], _sbfReadBuf, 8, &outLen) == true);
        SSF_ASSERT(outLen == 7);
        SSF_ASSERT(memcmp(_sbfReadBuf, "123456", outLen) == 0);
        outLen = 0x12345678;
        memset(_sbfReadBuf, 0xcc, sizeof(_sbfReadBuf));
        SSF_ASSERT(SSFBFifoGetBytes(&_sbfFifos[0], _sbfReadBuf, 8, &outLen) == true);
        SSF_ASSERT(outLen == 7);
        SSF_ASSERT(memcmp(_sbfReadBuf, "123456", outLen) == 0);
    }
#endif /* SSF_BFIFO_MULTI_BYTE_ENABLE */

    printf("SSF BFIFO UNIT TEST DONE!\r\n");
}
#endif /* SSF_CONFIG_BFIFO_UNIT_TEST */

