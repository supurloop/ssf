/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftlv_ut.c                                                                                   */
/* Provides TLV interface unit test.                                                             */
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
#include <stdio.h>
#include <malloc.h>
#include "ssftlv.h"
#include "ssfassert.h"

/* Unit tests variable length TLV with 3 and 4 byte length values */
#define SSF_TLV_ENABLE_EXTENDED_UNIT_TEST (1u)

typedef struct SSFTLVUT 
{
    SSFTLVVar_t tag;
    const uint8_t *val;
    SSFTLVVar_t valLen;
    uint32_t bufLenChange;

} SSFTLVUT_t;

#if SSF_TLV_ENABLE_FIXED_MODE == 1
static const SSFTLVUT_t _SSFTLVUT[] = 
{
    {0, "hello", 5, 7},
    {64, "world", 5, 7},
    {127, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 84, 86}
};
#else /* SSF_TLV_ENABLE_FIXED_MODE */
static const SSFTLVUT_t _SSFTLVUT[] = 
{
    {0, "hello", 5, 7},
    {64, "world", 5, 8},
    {16384, "!", 1, 5},
    {4194304, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 71, 77}
};
#endif /* SSF_TLV_ENABLE_FIXED_MODE */

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on TLV external interface.                                                 */
/* --------------------------------------------------------------------------------------------- */
void SSFTLVUnitTest(void)
{
    SSFTLV_t tlv;
    uint8_t buf[100];
    uint8_t val[100];
#if SSF_TLV_ENABLE_EXTENDED_UNIT_TEST == 1 && SSF_TLV_ENABLE_FIXED_MODE == 0
    SSFTLV_t tlvLong;
    uint8_t* bufLong = malloc(sizeof(uint8_t)*4210697);
    SSF_ASSERT(bufLong != NULL);
    uint8_t* valLong = malloc(sizeof(uint8_t)*4210697);
    SSF_ASSERT(valLong != NULL);
#endif /* SSF_TLV_ENABLE_EXTENDED_UNIT_TEST */
    SSFTLVVar_t valLen;
    uint8_t *valPtr;
    uint32_t i, expectedBufLen;

    SSF_ASSERT_TEST(SSFTLVInit(NULL, buf, sizeof(buf), 0));
    SSF_ASSERT_TEST(SSFTLVInit(&tlv, NULL, sizeof(buf), 0));
    SSF_ASSERT_TEST(SSFTLVInit(&tlv, buf, sizeof(buf), sizeof(buf) + 1));

    SSFTLVInit(&tlv, buf, sizeof(buf), 0);

    SSF_ASSERT_TEST(SSFTLVPut(NULL, 0, (const uint8_t*)"error", 5));
    SSF_ASSERT_TEST(SSFTLVPut(&tlv, 0, NULL, 0));
    
    valLen = -1;
    SSF_ASSERT_TEST(SSFTLVGet(NULL, 0, 0, val, sizeof(val), &valLen));
    SSF_ASSERT_TEST(SSFTLVGet(&tlv, 0, 0, NULL, sizeof(val), &valLen));
    SSF_ASSERT_TEST(SSFTLVGet(&tlv, 0, 0, val, sizeof(val), NULL));

    valLen = -1;
    SSF_ASSERT_TEST(SSFTLVFind(NULL, 0, 0, &valPtr, &valLen));
    SSF_ASSERT_TEST(SSFTLVFind(&tlv, 0, 0, NULL, &valLen));
    SSF_ASSERT_TEST(SSFTLVFind(&tlv, 0, 0, &valPtr, NULL));

#if SSF_TLV_ENABLE_FIXED_MODE == 0
    SSF_ASSERT_TEST(SSFTLVPut(&tlv, 1073741825ul, (const uint8_t*)"error", 5));
    SSF_ASSERT_TEST(SSFTLVPut(&tlv, 0, (const uint8_t*)"error", 1073741825ul));

    SSF_ASSERT_TEST(SSFTLVGet(&tlv, 1073741825ul, 0, val, sizeof(val), &valLen));
#endif /* SSF_TLV_ENABLE_FIXED_MODE */

    expectedBufLen = 0;
    for (i = 0; i < sizeof(_SSFTLVUT) / sizeof(SSFTLVUT_t); i++) 
    {
        SSF_ASSERT(SSFTLVPut(&tlv, _SSFTLVUT[i].tag, _SSFTLVUT[i].val, _SSFTLVUT[i].valLen));
        expectedBufLen += _SSFTLVUT[i].bufLenChange;
        SSF_ASSERT(tlv.bufLen == expectedBufLen);

        valLen = -1;
        SSF_ASSERT(SSFTLVFind(&tlv, _SSFTLVUT[i].tag, 0, &valPtr, &valLen));
        SSF_ASSERT(memcmp(valPtr, _SSFTLVUT[i].val, _SSFTLVUT[i].valLen) == 0);
        SSF_ASSERT(valLen == _SSFTLVUT[i].valLen);

        valLen = -1;
        SSF_ASSERT(SSFTLVGet(&tlv, _SSFTLVUT[i].tag, 0, val, sizeof(val), &valLen));
        SSF_ASSERT(memcmp(val, _SSFTLVUT[i].val, _SSFTLVUT[i].valLen) == 0);
        SSF_ASSERT(valLen == _SSFTLVUT[i].valLen);
    }

#if SSF_TLV_ENABLE_FIXED_MODE == 1
    SSF_ASSERT(SSFTLVPut(&tlv, 127, (const uint8_t*)"a", 1) == false);
#else
    SSF_ASSERT(SSFTLVPut(&tlv, 64, (const uint8_t*)"!", 1) == false);
    SSF_ASSERT(tlv.bufLen == 97);

    SSF_ASSERT(SSFTLVPut(&tlv, 63, (const uint8_t*)"!", 1));
    SSF_ASSERT(tlv.bufLen == 100);

    SSF_ASSERT(SSFTLVPut(&tlv, 63, (const uint8_t*)"!", 1) == false);
    SSF_ASSERT(SSFTLVPut(&tlv, 64, (const uint8_t*)"!", 1) == false);   
#endif /* SSF_TLV_ENABLE_FIXED_MODE */

#if SSF_TLV_ENABLE_EXTENDED_UNIT_TEST == 1 && SSF_TLV_ENABLE_FIXED_MODE == 0
    SSFTLVInit(&tlvLong, bufLong, 4210697, 0);

    memset(valLong, 'a', 4210697);

    SSF_ASSERT(SSFTLVPut(&tlvLong, 0, valLong, 16384));
    SSF_ASSERT(tlvLong.bufLen == 16388);

    SSF_ASSERT(SSFTLVPut(&tlvLong, 1, valLong, 4194304));
    SSF_ASSERT(tlvLong.bufLen == 4210697);

    valLen = -1;
    SSF_ASSERT(SSFTLVFind(&tlvLong, 0, 0, &valPtr, &valLen));
    SSF_ASSERT(memcmp(valPtr, valLong, 16384) == 0);
    SSF_ASSERT(valLen == 16384);

    valLen = -1;
    SSF_ASSERT(SSFTLVFind(&tlvLong, 1, 0, &valPtr, &valLen));
    SSF_ASSERT(memcmp(valPtr, valLong, 4194304) == 0);
    SSF_ASSERT(valLen == 4194304);

    if (valLong != NULL) { free(valLong); }
    if (bufLong != NULL) { free(bufLong); }
#endif /* SSF_TLV_ENABLE_EXTENDED_UNIT_TEST */
}
