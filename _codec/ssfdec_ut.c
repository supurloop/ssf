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
    int64_t i64;
    uint64_t u64;
    uint64_t lastu64;
    size_t len1;
    size_t len2;
    char str1[48];
    char str2[48];
    uint8_t minFieldWidth;
    uint64_t r = 1;

    srand((unsigned int)SSFPortGetTick64());

    /* Test assertions */
    SSF_ASSERT_TEST(SSFDecIntToStr(0, NULL, 1));
    SSF_ASSERT_TEST(SSFDecUIntToStr(0, NULL, 1));
    SSF_ASSERT_TEST(SSFDecIntToStrPadded(0, NULL, 1, 4, '0'));
    SSF_ASSERT_TEST(SSFDecIntToStrPadded(0, str1, sizeof(str1), 0, '0'));
    SSF_ASSERT_TEST(SSFDecIntToStrPadded(0, str1, sizeof(str1), 1, '0'));
    SSF_ASSERT_TEST(SSFDecUIntToStrPadded(0, NULL, 1, 4, '0'));
    SSF_ASSERT_TEST(SSFDecUIntToStrPadded(0, str1, sizeof(str1), 0, '0'));
    SSF_ASSERT_TEST(SSFDecUIntToStrPadded(0, str1, sizeof(str1), 1, '0'));

    /* Test boundary conditions of SSFDecIntToStr() */
    i64 = 1;
    for (i = 0; i < 19; i++)
    {
        len1 = snprintf(str1, sizeof(str1), "%lld", (long long int)i64);
        len2 = SSFDecIntToStr(i64, str2, sizeof(str2));
        SSF_ASSERT(len2 != 0);
        SSF_ASSERT(len1 == len2);
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
        SSF_ASSERT(str1[len1 - 1] != 0);
#ifdef _WIN32
#pragma warning(pop)
#endif
        SSF_ASSERT(str1[len1] == 0);
        SSF_ASSERT(memcmp(str1, str2, len1 + 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64, str2, 0) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64, str2, len1 - 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64, str2, len1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64, str2, len1 + 1) != 0);

        len1 = snprintf(str1, sizeof(str1), "%lld", (long long int)(i64 - 1));
        len2 = SSFDecIntToStr(i64 - 1, str2, sizeof(str2));
        SSF_ASSERT(len2 != 0);
        SSF_ASSERT(len1 == len2);
        SSF_ASSERT(str1[len1 - 1] != 0);
        SSF_ASSERT(str1[len1] == 0);
        SSF_ASSERT(memcmp(str1, str2, len1 + 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64 - 1, str2, 0) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64 - 1, str2, len1 - 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64 - 1, str2, len1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64 - 1, str2, len1 + 1) != 0);

        len1 = snprintf(str1, sizeof(str1), "%lld", (long long int)-i64);
        len2 = SSFDecIntToStr(-i64, str2, sizeof(str2));
        SSF_ASSERT(len2 != 0);
        SSF_ASSERT(len1 == len2);
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
        SSF_ASSERT(str1[len1 - 1] != 0);
#ifdef _WIN32
#pragma warning(pop)
#endif
        SSF_ASSERT(str1[len1] == 0);
        SSF_ASSERT(memcmp(str1, str2, len1 + 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(-i64, str2, 0) == 0);
        SSF_ASSERT(SSFDecIntToStr(-i64, str2, len1 - 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(-i64, str2, len1) == 0);
        SSF_ASSERT(SSFDecIntToStr(-i64, str2, len1 + 1) != 0);


        len1 = snprintf(str1, sizeof(str1), "%lld", (long long int)(-i64 + 1));
        len2 = SSFDecIntToStr(-i64 + 1, str2, sizeof(str2));
        SSF_ASSERT(len2 != 0);
        SSF_ASSERT(len1 == len2);
        SSF_ASSERT(str1[len1 - 1] != 0);
        SSF_ASSERT(str1[len1] == 0);
        SSF_ASSERT(memcmp(str1, str2, len1 + 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(-i64 + 1, str2, 0) == 0);
        SSF_ASSERT(SSFDecIntToStr(-i64 + 1, str2, len1 - 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(-i64 + 1, str2, len1) == 0);
        SSF_ASSERT(SSFDecIntToStr(-i64 + 1, str2, len1 + 1) != 0);

        i64 *= 10;
    }

    /* Test boundary conditions of SSFDecUIntToStr() */
    u64 = 1;
    for (i = 0; i <= 19; i++)
    {
        len1 = snprintf(str1, sizeof(str1), "%llu", (long long unsigned int)u64);
        len2 = SSFDecUIntToStr(u64, str2, sizeof(str2));
        SSF_ASSERT(len2 != 0);
        SSF_ASSERT(len1 == len2);
        SSF_ASSERT(str1[len1 - 1] != 0);
        SSF_ASSERT(str1[len1] == 0);
        SSF_ASSERT(memcmp(str1, str2, len1 + 1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64, str2, 0) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64, str2, len1 - 1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64, str2, len1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64, str2, len1 + 1) != 0);


        len1 = snprintf(str1, sizeof(str1), "%llu", (long long unsigned int)(u64 - 1));
        len2 = SSFDecUIntToStr(u64 - 1, str2, sizeof(str2));
        SSF_ASSERT(len2 != 0);
        SSF_ASSERT(len1 == len2);
        SSF_ASSERT(str1[len1 - 1] != 0);
        SSF_ASSERT(str1[len1] == 0);
        SSF_ASSERT(memcmp(str1, str2, len1 + 1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64 - 1, str2, 0) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64 - 1, str2, len1 - 1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64 - 1, str2, len1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64 - 1, str2, len1 + 1) != 0);

        u64 *= 10;
    }

    /* Test SSFDecIntToStr() && SSFDecUIntToStr() */
    lastu64 = 0;
    i = 0;
    for (u64 = 0; u64 >= lastu64; u64 += r)
    {
        if (u64 < 100000ull)
        {
            r = 1;
        }
        else if (u64 < 400000ull)
        {
            r = rand() % 8192ull;
        }
        else if (u64 < 4000000000ull)
        {
            r = rand() % 32768ull;
        }
        else if (u64 < 400000000000000ull)
        {
            r = (rand() % 32768ull) * (rand() % 32768ull) + ( rand() % 32768ull);
        }
        else if (u64 < 1000000000000000000ull)
        {
            r = (((rand() % 32768ull) * (rand() % 32768ull)) * 1000ull) + (rand() % 32768ull);
        }
        else
        {
            r = (((rand() % 32768ull) * (rand() % 32768ull)) * 10000ull) + (rand() % 32768ull);
        }
        lastu64 = u64;

        i64 = (int64_t)u64;
        len1 = snprintf(str1, sizeof(str1), "%lld", (long long int)i64);
        len2 = SSFDecIntToStr(i64, str2, sizeof(str2));
        SSF_ASSERT(len1 != 0);
        SSF_ASSERT(len1 == len2);
        SSF_ASSERT(str1[len1 - 1] != 0);
        SSF_ASSERT(str1[len1] == 0);
        SSF_ASSERT(memcmp(str1, str2, len1 + 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64, str2, 0) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64, str2, len1 - 1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64, str2, len1) == 0);
        SSF_ASSERT(SSFDecIntToStr(i64, str2, len1 + 1) != 0);

        len1 = snprintf(str1, sizeof(str1), "%llu", (long long unsigned int)u64);
        len2 = SSFDecUIntToStr(u64, str2, sizeof(str2));
        SSF_ASSERT(len1 != 0);
        SSF_ASSERT(len1 == len2);
        SSF_ASSERT(str1[len1 - 1] != 0);
        SSF_ASSERT(str1[len1] == 0);
        SSF_ASSERT(memcmp(str1, str2, len1 + 1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64, str2, 0) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64, str2, len1 - 1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64, str2, len1) == 0);
        SSF_ASSERT(SSFDecUIntToStr(u64, str2, len1 + 1) != 0);
    }

    /* Test SSFDecIntToStrPadded() && SSFDecUIntToStrPadded() */
    lastu64 = 0;
    for (u64 = 0; u64 >= lastu64; u64 += r)
    {
        if (u64 < 100000ull)
        {
            r = 1;
        }
        else if (u64 < 400000ull)
        {
            r = rand() % 8192ull;
        }
        else if (u64 < 4000000000ull)
        {
            r = rand() % 32768ull;
        }
        else if (u64 < 400000000000000ull)
        {
            r = (rand() % 32768ull) * (rand() % 32768ull) + ( rand() % 32768ull);
        }
        else if (u64 < 1000000000000000000ull)
        {
            r = (((rand() % 32768ull) * (rand() % 32768ull)) * 1000ull) + (rand() % 32768ull);
        }
        else
        {
            r = (((rand() % 32768ull) * (rand() % 32768ull)) * 10000ull) + (rand() % 32768ull);
        }
        lastu64 = u64;

        i64 = (int64_t)u64;
        for (minFieldWidth = 2; minFieldWidth <= SSF_DEC_MAX_STR_LEN + 2; minFieldWidth++)
        {
            /* Note: Some systems output warnings if format specifiers are not const strings */
            switch (minFieldWidth)
            {
                case 2:
                    len1 = snprintf(str1, sizeof(str1), "%02lld", (long long int)i64);
                    break;
                case 3:
                    len1 = snprintf(str1, sizeof(str1), "%03lld", (long long int)i64);
                    break;
                case 4:
                    len1 = snprintf(str1, sizeof(str1), "%04lld", (long long int)i64);
                    break;
                case 5:
                    len1 = snprintf(str1, sizeof(str1), "%05lld", (long long int)i64);
                    break;
                case 6:
                    len1 = snprintf(str1, sizeof(str1), "%06lld", (long long int)i64);
                    break;
                case 7:
                    len1 = snprintf(str1, sizeof(str1), "%07lld", (long long int)i64);
                    break;
                case 8:
                    len1 = snprintf(str1, sizeof(str1), "%08lld", (long long int)i64);
                    break;
                case 9:
                    len1 = snprintf(str1, sizeof(str1), "%09lld", (long long int)i64);
                    break;
                case 10:
                    len1 = snprintf(str1, sizeof(str1), "%010lld", (long long int)i64);
                    break;
                case 11:
                    len1 = snprintf(str1, sizeof(str1), "%011lld", (long long int)i64);
                    break;
                case 12:
                    len1 = snprintf(str1, sizeof(str1), "%012lld", (long long int)i64);
                    break;
                case 13:
                    len1 = snprintf(str1, sizeof(str1), "%013lld", (long long int)i64);
                    break;
                case 14:
                    len1 = snprintf(str1, sizeof(str1), "%014lld", (long long int)i64);
                    break;
                case 15:
                    len1 = snprintf(str1, sizeof(str1), "%015lld", (long long int)i64);
                    break;
                case 16:
                    len1 = snprintf(str1, sizeof(str1), "%016lld", (long long int)i64);
                    break;
                case 17:
                    len1 = snprintf(str1, sizeof(str1), "%017lld", (long long int)i64);
                    break;
                case 18:
                    len1 = snprintf(str1, sizeof(str1), "%018lld", (long long int)i64);
                    break;
                case 19:
                    len1 = snprintf(str1, sizeof(str1), "%019lld", (long long int)i64);
                    break;
                case 20:
                    len1 = snprintf(str1, sizeof(str1), "%020lld", (long long int)i64);
                    break;
                case 21:
                    len1 = snprintf(str1, sizeof(str1), "%021lld", (long long int)i64);
                    break;
                case 22:
                    len1 = snprintf(str1, sizeof(str1), "%022lld", (long long int)i64);
                    break;
                default:
                    SSF_ERROR();
                    break;
            }
            len2 = SSFDecIntToStrPadded(i64, str2, sizeof(str2), minFieldWidth, '0');
            SSF_ASSERT(len1 != 0);
            SSF_ASSERT(len1 == len2);
            SSF_ASSERT(str1[len1 - 1] != 0);
            SSF_ASSERT(str1[len1] == 0);
            SSF_ASSERT(memcmp(str1, str2, len1 + 1) == 0);
            SSF_ASSERT(SSFDecIntToStrPadded(i64, str2, 0, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecIntToStrPadded(i64, str2, len1 - 1, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecIntToStrPadded(i64, str2, len1, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecIntToStrPadded(i64, str2, len1 + 1, minFieldWidth, '0') != 0);

            /* Note: Some systems output warnings if format specifiers are not const strings */
            switch (minFieldWidth)
            {
                case 2:
                    len1 = snprintf(str1, sizeof(str1), "%02llu", (long long unsigned int)u64);
                    break;
                case 3:
                    len1 = snprintf(str1, sizeof(str1), "%03llu", (long long unsigned int)u64);
                    break;
                case 4:
                    len1 = snprintf(str1, sizeof(str1), "%04llu", (long long unsigned int)u64);
                    break;
                case 5:
                    len1 = snprintf(str1, sizeof(str1), "%05llu", (long long unsigned int)u64);
                    break;
                case 6:
                    len1 = snprintf(str1, sizeof(str1), "%06llu", (long long unsigned int)u64);
                    break;
                case 7:
                    len1 = snprintf(str1, sizeof(str1), "%07llu", (long long unsigned int)u64);
                    break;
                case 8:
                    len1 = snprintf(str1, sizeof(str1), "%08llu", (long long unsigned int)u64);
                    break;
                case 9:
                    len1 = snprintf(str1, sizeof(str1), "%09llu", (long long unsigned int)u64);
                    break;
                case 10:
                    len1 = snprintf(str1, sizeof(str1), "%010llu", (long long unsigned int)u64);
                    break;
                case 11:
                    len1 = snprintf(str1, sizeof(str1), "%011llu", (long long unsigned int)u64);
                    break;
                case 12:
                    len1 = snprintf(str1, sizeof(str1), "%012llu", (long long unsigned int)u64);
                    break;
                case 13:
                    len1 = snprintf(str1, sizeof(str1), "%013llu", (long long unsigned int)u64);
                    break;
                case 14:
                    len1 = snprintf(str1, sizeof(str1), "%014llu", (long long unsigned int)u64);
                    break;
                case 15:
                    len1 = snprintf(str1, sizeof(str1), "%015llu", (long long unsigned int)u64);
                    break;
                case 16:
                    len1 = snprintf(str1, sizeof(str1), "%016llu", (long long unsigned int)u64);
                    break;
                case 17:
                    len1 = snprintf(str1, sizeof(str1), "%017llu", (long long unsigned int)u64);
                    break;
                case 18:
                    len1 = snprintf(str1, sizeof(str1), "%018llu", (long long unsigned int)u64);
                    break;
                case 19:
                    len1 = snprintf(str1, sizeof(str1), "%019llu", (long long unsigned int)u64);
                    break;
                case 20:
                    len1 = snprintf(str1, sizeof(str1), "%020llu", (long long unsigned int)u64);
                    break;
                case 21:
                    len1 = snprintf(str1, sizeof(str1), "%021llu", (long long unsigned int)u64);
                    break;
                case 22:
                    len1 = snprintf(str1, sizeof(str1), "%022llu", (long long unsigned int)u64);
                    break;
                default:
                    SSF_ERROR();
                    break;
            }
            len2 = SSFDecUIntToStrPadded(u64, str2, sizeof(str2), minFieldWidth, '0');
            SSF_ASSERT(len1 != 0);
            SSF_ASSERT(len1 == len2);
            SSF_ASSERT(str1[len1 - 1] != 0);
            SSF_ASSERT(str1[len1] == 0);
            SSF_ASSERT(memcmp(str1, str2, len1 + 1) == 0);
            SSF_ASSERT(SSFDecUIntToStrPadded(u64, str2, 0, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecUIntToStrPadded(u64, str2, len1 - 1, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecUIntToStrPadded(u64, str2, len1, minFieldWidth, '0') == 0);
            SSF_ASSERT(SSFDecUIntToStrPadded(u64, str2, len1 + 1, minFieldWidth, '0') != 0);
        }
    }
}
