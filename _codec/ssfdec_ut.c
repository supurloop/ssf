/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfdec_ut.c                                                                                   */
/* Unit test for integer to decimal string conversion interface.                                 */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2022 Supurloop Software LLC                                                         */
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
#include "ssfport.h"
#include "ssfdec.h"

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on integer to decimal string external interface.                           */
/* --------------------------------------------------------------------------------------------- */
void SSFDecUnitTest(void)
{
    int64_t i;
    int32_t i32;
    uint32_t u32;
    size_t len;
    char str1[30];
    char str2[30];
    uint8_t minFieldWidth;
    uint16_t r = 1;

    /* Test assertions */
    SSF_ASSERT_TEST(SSFDecIntToStr(0, NULL, 1));
    SSF_ASSERT_TEST(SSFDecUIntToStr(0, NULL, 1));
    SSF_ASSERT_TEST(SSFDecIntToStrPadded(0, NULL, 1, 4, '0'));
    SSF_ASSERT_TEST(SSFDecIntToStrPadded(0, str1, sizeof(str1), 0, '0'));
    SSF_ASSERT_TEST(SSFDecIntToStrPadded(0, str1, sizeof(str1), 1, '0'));
    SSF_ASSERT_TEST(SSFDecUIntToStrPadded(0, NULL, 1, 4, '0'));
    SSF_ASSERT_TEST(SSFDecUIntToStrPadded(0, str1, sizeof(str1), 0, '0'));
    SSF_ASSERT_TEST(SSFDecUIntToStrPadded(0, str1, sizeof(str1), 1, '0'));

    /* Test SSFDecIntToStr() && SSFDecUIntToStr() */
    for (i = -2147483648; i < 2147483648; i += r)
    {
#if SSF_DEC_EXHAUSTIVE_UNIT_TEST == 0
        r = rand() % 2048;
#endif
        i32 = (int32_t)i;
        snprintf(str1, sizeof(str1), "%d", i32);
        len = SSFDecIntToStr(i32, str2, sizeof(str2));
        SSF_ASSERT(len != 0);
        SSF_ASSERT(str1[len - 1] != 0);
        SSF_ASSERT(str1[len] == 0);
        SSF_ASSERT(memcmp(str1, str2, len + 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i32, str2, 0) == 0);
        SSF_ASSERT(SSFDecIntToStr(i32, str2, len - 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i32, str2, len) == 0);
        SSF_ASSERT(SSFDecIntToStr(i32, str2, len + 1) != 0);

        u32 = (uint32_t)i;
        snprintf(str1, sizeof(str1), "%u", u32);
        len = SSFDecUIntToStr(u32, str2, sizeof(str2));
        SSF_ASSERT(len != 0);
        SSF_ASSERT(str1[len - 1] != 0);
        SSF_ASSERT(str1[len] == 0);
        SSF_ASSERT(memcmp(str1, str2, len + 1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u32, str2, 0) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u32, str2, len - 1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u32, str2, len) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u32, str2, len + 1) != 0);
    }

    /* Test SSFDecIntToStr() && SSFDecUIntToStr() */
    for (i = -2147483648; i < 2147483648; i += r)
    {
#if SSF_DEC_EXHAUSTIVE_UNIT_TEST == 0
        r = rand() % 2048;
#endif
        for (minFieldWidth = 2; minFieldWidth <= 12; minFieldWidth++)
        {
            i32 = (int32_t)i;
            /* Note: Some systems output warnings if format specifiers are not const strings */
            switch (minFieldWidth)
            {
                case 2:
                    snprintf(str1, sizeof(str1), "%02d", i32);
                    break;
                case 3:
                    snprintf(str1, sizeof(str1), "%03d", i32);
                    break;
                case 4:
                    snprintf(str1, sizeof(str1), "%04d", i32);
                    break;
                case 5:
                    snprintf(str1, sizeof(str1), "%05d", i32);
                    break;
                case 6:
                    snprintf(str1, sizeof(str1), "%06d", i32);
                    break;
                case 7:
                    snprintf(str1, sizeof(str1), "%07d", i32);
                    break;
                case 8:
                    snprintf(str1, sizeof(str1), "%08d", i32);
                    break;
                case 9:
                    snprintf(str1, sizeof(str1), "%09d", i32);
                    break;
                case 10:
                    snprintf(str1, sizeof(str1), "%010d", i32);
                    break;
                case 11:
                    snprintf(str1, sizeof(str1), "%011d", i32);
                    break;
                case 12:
                    snprintf(str1, sizeof(str1), "%012d", i32);
                    break;
                default:
                    SSF_ERROR();
                    break;
            }
            len = SSFDecIntToStrPadded(i32, str2, sizeof(str2), minFieldWidth, '0');
            SSF_ASSERT(len != 0);
            SSF_ASSERT(str1[len - 1] != 0);
            SSF_ASSERT(str1[len] == 0);
            SSF_ASSERT(memcmp(str1, str2, len + 1) == 0);
            SSF_ASSERT(SSFDecIntToStrPadded(i32, str2, 0, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecIntToStrPadded(i32, str2, len - 1, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecIntToStrPadded(i32, str2, len, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecIntToStrPadded(i32, str2, len + 1, minFieldWidth, '0') != 0);

            u32 = (uint32_t)i;
            /* Note: Some systems output warnings if format specifiers are not const strings */
            switch (minFieldWidth)
            {
                case 2:
                    snprintf(str1, sizeof(str1), "%02u", u32);
                    break;
                case 3:
                    snprintf(str1, sizeof(str1), "%03u", u32);
                    break;
                case 4:
                    snprintf(str1, sizeof(str1), "%04u", u32);
                    break;
                case 5:
                    snprintf(str1, sizeof(str1), "%05u", u32);
                    break;
                case 6:
                    snprintf(str1, sizeof(str1), "%06u", u32);
                    break;
                case 7:
                    snprintf(str1, sizeof(str1), "%07u", u32);
                    break;
                case 8:
                    snprintf(str1, sizeof(str1), "%08u", u32);
                    break;
                case 9:
                    snprintf(str1, sizeof(str1), "%09u", u32);
                    break;
                case 10:
                    snprintf(str1, sizeof(str1), "%010u", u32);
                    break;
                case 11:
                    snprintf(str1, sizeof(str1), "%011u", u32);
                    break;
                case 12:
                    snprintf(str1, sizeof(str1), "%012u", u32);
                    break;
                default:
                    SSF_ERROR();
                    break;
            }
            len = SSFDecUIntToStrPadded(u32, str2, sizeof(str2), minFieldWidth, '0');
            SSF_ASSERT(len != 0);
            SSF_ASSERT(str1[len - 1] != 0);
            SSF_ASSERT(str1[len] == 0);
            SSF_ASSERT(memcmp(str1, str2, len + 1) == 0);
            SSF_ASSERT(SSFDecUIntToStrPadded(u32, str2, 0, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecUIntToStrPadded(u32, str2, len - 1, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecUIntToStrPadded(u32, str2, len, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecUIntToStrPadded(u32, str2, len + 1, minFieldWidth, '0') != 0);
        }
    }
}
