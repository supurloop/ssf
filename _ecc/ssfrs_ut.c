/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfrs_ut.c                                                                                    */
/* Provides unit tests for ssfrs's Reed Solomon encoder/decoder interface.                       */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2021 Supurloop Software LLC                                                         */
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
#include <stdio.h>
#include <stdlib.h>
#include "ssfrs.h"
#include "ssfport.h"
#include "ssfassert.h"

#if SSF_CONFIG_RS_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfrs's external interface.                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFRSUnitTest(void)
{
    /* Iterators */
    uint16_t msgLen;
    uint8_t chunkSize;
    uint8_t eccSize;
    uint16_t i;
    uint16_t j;

    srand((unsigned int)SSFPortGetTick64());

    /* Buffers */
    uint8_t msg[SSF_RS_MAX_MESSAGE_SIZE + (SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS)];
    uint8_t msgCopy[SSF_RS_MAX_MESSAGE_SIZE];
    uint8_t eccBuf[SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS];
    uint16_t eccBufLen;
    uint16_t len;
    uint16_t numChunks;
    uint32_t byteErrorsCorrected;

    /* Totals */
    uint32_t totalEncodeDecode = 0;

    /* Verify that API assertions are functioning */
    SSF_ASSERT_TEST(SSFRSEncode(NULL, SSF_RS_MAX_MESSAGE_SIZE, eccBuf, (uint16_t)sizeof(eccBuf),
                                &eccBufLen, SSF_RS_MAX_SYMBOLS, SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSEncode(msg, 0, eccBuf, (uint16_t)sizeof(eccBuf),
                                &eccBufLen, SSF_RS_MAX_SYMBOLS, SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSEncode(msg, SSF_RS_MAX_MESSAGE_SIZE, NULL, (uint16_t)sizeof(eccBuf),
                                &eccBufLen, SSF_RS_MAX_SYMBOLS, SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSEncode(msg, SSF_RS_MAX_MESSAGE_SIZE, eccBuf, SSF_RS_MAX_SYMBOLS - 1,
                                &eccBufLen, SSF_RS_MAX_SYMBOLS, SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSEncode(msg, SSF_RS_MAX_MESSAGE_SIZE, eccBuf, (uint16_t)sizeof(eccBuf),
                                NULL, SSF_RS_MAX_SYMBOLS, SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSEncode(msg, SSF_RS_MAX_MESSAGE_SIZE, eccBuf, (uint16_t)sizeof(eccBuf),
                                &eccBufLen, 0, SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSEncode(msg, SSF_RS_MAX_MESSAGE_SIZE, eccBuf, (uint16_t)sizeof(eccBuf),
                                &eccBufLen, SSF_RS_MAX_SYMBOLS + 1, SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSEncode(msg, SSF_RS_MAX_MESSAGE_SIZE, eccBuf, (uint16_t)sizeof(eccBuf),
                                &eccBufLen, SSF_RS_MAX_SYMBOLS, 0));
    SSF_ASSERT_TEST(SSFRSEncode(msg, SSF_RS_MAX_MESSAGE_SIZE, eccBuf, (uint16_t)sizeof(eccBuf),
                                &eccBufLen, SSF_RS_MAX_SYMBOLS, SSF_RS_MAX_CHUNK_SIZE + 1));
    SSF_ASSERT_TEST(SSFRSEncode(msg, SSF_RS_MAX_MESSAGE_SIZE, eccBuf, (uint16_t)sizeof(eccBuf),
                                &eccBufLen, SSF_RS_MAX_SYMBOLS-1, SSF_RS_MAX_CHUNK_SIZE));

    SSF_ASSERT_TEST(SSFRSDecode(NULL, SSF_RS_MAX_MESSAGE_SIZE, &len, SSF_RS_MAX_SYMBOLS,
                                SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSDecode(msg, 0, &len, SSF_RS_MAX_SYMBOLS,
                                SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSDecode(msg, SSF_RS_MAX_MESSAGE_SIZE, NULL, SSF_RS_MAX_SYMBOLS,
                                SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSDecode(msg, SSF_RS_MAX_MESSAGE_SIZE, &len, 0,
                                SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSDecode(msg, SSF_RS_MAX_MESSAGE_SIZE, &len, SSF_RS_MAX_SYMBOLS + 1,
                                SSF_RS_MAX_CHUNK_SIZE));
    SSF_ASSERT_TEST(SSFRSDecode(msg, SSF_RS_MAX_MESSAGE_SIZE, &len, SSF_RS_MAX_SYMBOLS,
                                0));
    SSF_ASSERT_TEST(SSFRSDecode(msg, SSF_RS_MAX_MESSAGE_SIZE, &len, SSF_RS_MAX_SYMBOLS,
                                SSF_RS_MAX_CHUNK_SIZE + 1));
    SSF_ASSERT_TEST(SSFRSDecode(msg, SSF_RS_MAX_MESSAGE_SIZE, &len, SSF_RS_MAX_SYMBOLS - 1,
                                SSF_RS_MAX_CHUNK_SIZE));

    /* Always seed with 0 so that pseudo random values are consistent between runs to aid debug */
    srand(0);

    /* Iterate over all possible message combinations and check for successful encode/decode */
    for (msgLen = 1; msgLen <= SSF_RS_MAX_MESSAGE_SIZE; msgLen++)
    {
        for (chunkSize = 1; (chunkSize <= SSF_RS_MAX_CHUNK_SIZE) && (chunkSize != 0); chunkSize++)
        {
            for (eccSize = 2; eccSize <= SSF_RS_MAX_SYMBOLS; eccSize+=2)
            {
                /* Compute the number of chunks */
                numChunks = (uint16_t)(msgLen / chunkSize);
                if (msgLen % chunkSize != 0) numChunks++;

                /* Skip if chunkSize not valid for msgLen */
                if (numChunks > SSF_RS_MAX_CHUNKS) continue;

                /* Proceed with encoding/decoding */
                totalEncodeDecode++;

                /* Generate a random message of msgLen length, and make a copy */
                for (i = 0; i < msgLen; i++)
                {
                    msg[i] = msgCopy[i] = (uint8_t) rand();
                }
                
                /* Encode the message */
                SSFRSEncode(msg, msgLen, eccBuf, (uint16_t)sizeof(eccBuf), &eccBufLen, eccSize,
                            chunkSize);

                /* Tack on the ECC to the end of the message */
                memcpy(&msg[msgLen], eccBuf, eccBufLen);

                /* Flip all the bits in eccSize/2 bytes of each chunk to sim max correctable err */
                byteErrorsCorrected = 0;
                for (i = 0; i < numChunks; i++)
                {
                    for (j = 0; j < (eccSize >> 1); j++)
                    {
                        /* Is there enough message to corrupt? */
                        if (j < (msgLen - (i * chunkSize)))
                        {
                            /* Yes, corrupt message byte */
                            msg[(i * chunkSize) + j] ^= (uint8_t)0xff;
                        }
                        else
                        {
                            /* No, corrupt ecc symbol byte */
                            msg[(i * chunkSize) + (i * eccSize) + j] ^= (uint8_t)0xff;
                        }
                        byteErrorsCorrected += 1;
                    }
                }
                SSF_ASSERT(byteErrorsCorrected == (uint32_t)((eccSize >> 1) * numChunks));

                /* Decode the error containing message */
                SSF_ASSERT(SSFRSDecode(msg, msgLen + (eccSize * numChunks), &len, eccSize,
                                       chunkSize));
                SSF_ASSERT(len == msgLen);
                SSF_ASSERT(memcmp(msg, msgCopy, msgLen) == 0);
            }
        }
    }
}
#endif /* SSF_CONFIG_RS_UNIT_TEST */
