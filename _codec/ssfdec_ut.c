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
    int64_t j;
    uint64_t uj;
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
    SSF_ASSERT_TEST(SSFDecStrToInt(NULL, &i));
    SSF_ASSERT_TEST(SSFDecStrToInt("-1", NULL));
    SSF_ASSERT_TEST(SSFDecStrToUInt(NULL, &u64));
    SSF_ASSERT_TEST(SSFDecStrToUInt("-1", NULL));

    /* Test boundary conditions of SSFDecStrToInt() */
    for (j = -1000000; j < 1000000; j++)
    {
        i = j + 1;
        snprintf(str1, sizeof(str1), "%lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), " %lld", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "\t%lld", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), " \t%lld", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "\t %lld", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "\t\t%lld", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "  %lld", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "%lld ", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "%llda", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "%lld[", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);

        snprintf(str1, sizeof(str1), "a%lld", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i) == false);
        snprintf(str1, sizeof(str1), "+%lld", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i) == false);
        snprintf(str1, sizeof(str1), "]%lld", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i) == false);
        snprintf(str1, sizeof(str1), " ] %lld", j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i) == false);
    }
    i = 42;
    SSF_ASSERT(SSFDecStrToInt("-9223372036854775808", &i));
    SSF_ASSERT(i < 0);
    u64 = (uint64_t)-i;
    SSF_ASSERT(u64 == 9223372036854775808ull);
    i = 42;
    SSF_ASSERT(SSFDecStrToInt(" \t -9223372036854775808", &i));
    SSF_ASSERT(i < 0);
    u64 = (uint64_t)-i;
    SSF_ASSERT(u64 == 9223372036854775808ull);
    i = 42;
    SSF_ASSERT(SSFDecStrToInt(" \t -9223372036854775808a", &i));
    SSF_ASSERT(i < 0);
    u64 = (uint64_t)-i;
    SSF_ASSERT(u64 == 9223372036854775808ull);

    i = 42;
    SSF_ASSERT(SSFDecStrToInt("9223372036854775807", &i));
    SSF_ASSERT(i == 9223372036854775807ull);
    i = 42;
    SSF_ASSERT(SSFDecStrToInt(" \t 9223372036854775807", &i));
    SSF_ASSERT(i == 9223372036854775807ull);
    i = 42;
    SSF_ASSERT(SSFDecStrToInt(" \t 9223372036854775807a", &i));
    SSF_ASSERT(i == 9223372036854775807ull);
    SSF_ASSERT(SSFDecStrToInt("9223372036854775808", &i) == false);
    SSF_ASSERT(SSFDecStrToInt("9323372036854775807", &i) == false);
    SSF_ASSERT(SSFDecStrToInt("-92233720368547758070", &i) == false);
    SSF_ASSERT(SSFDecStrToInt("-9223372036854775809", &i) == false);
    SSF_ASSERT(SSFDecStrToInt("-9923372036854775809", &i) == false);
    SSF_ASSERT(SSFDecStrToInt("-9923372036854775809", &i) == false);
    SSF_ASSERT(SSFDecStrToInt("-922337203685477580.9e1", &i) == false);
    i = 42;
    SSF_ASSERT(SSFDecStrToInt("-922337203685477580.8e1", &i));
    SSF_ASSERT(i < 0);
    u64 = (uint64_t)-i;
    SSF_ASSERT(u64 == 9223372036854775808ull);
    SSF_ASSERT(SSFDecStrToInt("922337203685477580.8e1", &i) == false);
    i = 42;
    SSF_ASSERT(SSFDecStrToInt("922337203685477580.7e1", &i));
    SSF_ASSERT(i == 9223372036854775807ull);

    /* Test boundary conditions of SSFDecStrToUInt() */
    for (uj = 0; uj < 1000000; uj++)
    {
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "%llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), " %llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "\t%llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), " \t%llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "\t %llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "\t\t%llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "  %llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "%llu ", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "%llua", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "%llu]", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);

        snprintf(str1, sizeof(str1), "a%llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64) == false);
        snprintf(str1, sizeof(str1), "+%llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64) == false);
        snprintf(str1, sizeof(str1), "]%llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64) == false);
        snprintf(str1, sizeof(str1), " ] %llu", uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64) == false);
    }
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("18446744073709551615", &u64));
    SSF_ASSERT(u64 == 18446744073709551615ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("1844674407370955161.5E01", &u64));
    SSF_ASSERT(u64 == 18446744073709551615ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt(" \t 18446744073709551615", &u64));
    SSF_ASSERT(u64 == 18446744073709551615ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt(" \t 18446744073709551615a", &u64));
    SSF_ASSERT(u64 == 18446744073709551615ull);
    SSF_ASSERT(SSFDecStrToUInt("-18446744073709551615", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("18446744073709551616", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("184467440737095516.16e2", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("28446744073709551615", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("2844674407370955161e1", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("90446744073709551615", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("9044674407370955161.5e1", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("9044674407370955161.5e1", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("184467440737095516150", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("184467440737095516.150e03", &u64) == false);

    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("0.32", &i64));
    SSF_ASSERT(i64 == 0ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.32", &i64));
    SSF_ASSERT(i64 == 12ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.52", &i64));
    SSF_ASSERT(i64 == 12ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12e0", &i64));
    SSF_ASSERT(i64 == 12ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12e1", &i64));
    SSF_ASSERT(i64 == 120ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.1e1", &i64));
    SSF_ASSERT(i64 == 121ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.134567e1", &i64));
    SSF_ASSERT(i64 == 121ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.134567e5", &i64));
    SSF_ASSERT(i64 == 1213456ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.134567E+5", &i64));
    SSF_ASSERT(i64 == 1213456ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.1e5", &i64));
    SSF_ASSERT(i64 == 1210000ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.19e5", &i64));
    SSF_ASSERT(i64 == 1219000ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.19e+5", &i64));
    SSF_ASSERT(i64 == 1219000ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-5", &i64));
    SSF_ASSERT(i64 == 0ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-6", &i64));
    SSF_ASSERT(i64 == 0ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-4", &i64));
    SSF_ASSERT(i64 == 1ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-3", &i64));
    SSF_ASSERT(i64 == 12ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-2", &i64));
    SSF_ASSERT(i64 == 126ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-1", &i64));
    SSF_ASSERT(i64 == 1267ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-0", &i64));
    SSF_ASSERT(i64 == 12679ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e+0", &i64));
    SSF_ASSERT(i64 == 12679ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e0", &i64));
    SSF_ASSERT(i64 == 12679ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("0.32", &i64));
    SSF_ASSERT(i64 == 0ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.32", &i64));
    SSF_ASSERT(i64 == 12ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.52", &i64));
    SSF_ASSERT(i64 == 12ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12e0", &i64));
    SSF_ASSERT(i64 == 12ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12e1", &i64));
    SSF_ASSERT(i64 == 120ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.1e1", &i64));
    SSF_ASSERT(i64 == 121ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.134567e1", &i64));
    SSF_ASSERT(i64 == 121ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.134567e5", &i64));
    SSF_ASSERT(i64 == 1213456ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.134567E+5", &i64));
    SSF_ASSERT(i64 == 1213456ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.1e5", &i64));
    SSF_ASSERT(i64 == 1210000ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.19e5", &i64));
    SSF_ASSERT(i64 == 1219000ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12.19e+5", &i64));
    SSF_ASSERT(i64 == 1219000ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-5", &i64));
    SSF_ASSERT(i64 == 0ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-6", &i64));
    SSF_ASSERT(i64 == 0ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-4", &i64));
    SSF_ASSERT(i64 == 1ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-3", &i64));
    SSF_ASSERT(i64 == 12ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-2", &i64));
    SSF_ASSERT(i64 == 126ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-1", &i64));
    SSF_ASSERT(i64 == 1267ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e-0", &i64));
    SSF_ASSERT(i64 == 12679ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e+0", &i64));
    SSF_ASSERT(i64 == 12679ull);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("12679.19e0", &i64));
    SSF_ASSERT(i64 == 12679ull);

    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-0.32", &i64));
    SSF_ASSERT(i64 == 0ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12.32", &i64));
    SSF_ASSERT(i64 == -12ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12.52", &i64));
    SSF_ASSERT(i64 == -12ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12e0", &i64));
    SSF_ASSERT(i64 == -12ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12e1", &i64));
    SSF_ASSERT(i64 == -120ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12.1e1", &i64));
    SSF_ASSERT(i64 == -121ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12.134567e1", &i64));
    SSF_ASSERT(i64 == -121ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12.134567e5", &i64));
    SSF_ASSERT(i64 == -1213456ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12.134567E+5", &i64));
    SSF_ASSERT(i64 == -1213456ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12.1e5", &i64));
    SSF_ASSERT(i64 == -1210000ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12.19e5", &i64));
    SSF_ASSERT(i64 == -1219000ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12.19e+5", &i64));
    SSF_ASSERT(i64 == -1219000ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12679.19e-5", &i64));
    SSF_ASSERT(i64 == 0ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12679.19e-6", &i64));
    SSF_ASSERT(i64 == 0ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12679.19e-4", &i64));
    SSF_ASSERT(i64 == -1ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12679.19e-3", &i64));
    SSF_ASSERT(i64 == -12ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12679.19e-2", &i64));
    SSF_ASSERT(i64 == -126ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12679.19e-02", &i64));
    SSF_ASSERT(i64 == -126ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12679.19e-1", &i64));
    SSF_ASSERT(i64 == -1267ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12679.19e-0", &i64));
    SSF_ASSERT(i64 == -12679ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12679.19e+0", &i64));
    SSF_ASSERT(i64 == -12679ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("-12679.19e0", &i64));
    SSF_ASSERT(i64 == -12679ll);

    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("0.32", &u64));
    SSF_ASSERT(u64 == 0ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12.32", &u64));
    SSF_ASSERT(u64 == 12ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12.52", &u64));
    SSF_ASSERT(u64 == 12ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12e0", &u64));
    SSF_ASSERT(u64 == 12ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12e1", &u64));
    SSF_ASSERT(u64 == 120ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12.1e1", &u64));
    SSF_ASSERT(u64 == 121ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12.134567e1", &u64));
    SSF_ASSERT(u64 == 121ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12.134567e5", &u64));
    SSF_ASSERT(u64 == 1213456ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12.134567E+5", &u64));
    SSF_ASSERT(u64 == 1213456ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12.1e5", &u64));
    SSF_ASSERT(u64 == 1210000ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12.19e05", &u64));
    SSF_ASSERT(u64 == 1219000ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12.19e+5", &u64));
    SSF_ASSERT(u64 == 1219000ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12679.19e-5", &u64));
    SSF_ASSERT(u64 == 0ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12679.19e-6", &u64));
    SSF_ASSERT(u64 == 0ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12679.19e-4", &u64));
    SSF_ASSERT(u64 == 1ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12679.19e-3", &u64));
    SSF_ASSERT(u64 == 12ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12679.19e-2", &u64));
    SSF_ASSERT(u64 == 126ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12679.19e-1", &u64));
    SSF_ASSERT(u64 == 1267ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12679.19e-0", &u64));
    SSF_ASSERT(u64 == 12679ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12679.19e+0", &u64));
    SSF_ASSERT(u64 == 12679ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("12679.19e0", &u64));
    SSF_ASSERT(u64 == 12679ull);

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
