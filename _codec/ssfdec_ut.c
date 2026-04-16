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
        snprintf(str1, sizeof(str1), " %lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "\t%lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), " \t%lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "\t %lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "\t\t%lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "  %lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "%lld ", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "%llda", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);
        i = j + 1;
        snprintf(str1, sizeof(str1), "%lld[", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i));
        SSF_ASSERT(i == j);

        snprintf(str1, sizeof(str1), "a%lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i) == false);
        snprintf(str1, sizeof(str1), "+%lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i) == false);
        snprintf(str1, sizeof(str1), "]%lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i) == false);
        snprintf(str1, sizeof(str1), " ] %lld", (long long int)j);
        SSF_ASSERT(SSFDecStrToInt(str1, &i) == false);
    }
    i = 42;
    SSF_ASSERT(SSFDecStrToInt("-9223372036854775808", &i));
    SSF_ASSERT(i < 0);
    i++;
    u64 = (uint64_t)-i;
    u64++;
    SSF_ASSERT(u64 == 9223372036854775808ull);
    i = 42;
    SSF_ASSERT(SSFDecStrToInt(" \t -9223372036854775808", &i));
    SSF_ASSERT(i < 0);
    i++;
    u64 = (uint64_t)-i;
    u64++;
    SSF_ASSERT(u64 == 9223372036854775808ull);
    i = 42;
    SSF_ASSERT(SSFDecStrToInt(" \t -9223372036854775808a", &i));
    SSF_ASSERT(i < 0);
    i++;
    u64 = (uint64_t)-i;
    u64++;
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
    i++;
    u64 = (uint64_t)-i;
    u64++;
    SSF_ASSERT(u64 == 9223372036854775808ull);
    SSF_ASSERT(SSFDecStrToInt("922337203685477580.8e1", &i) == false);
    i = 42;
    SSF_ASSERT(SSFDecStrToInt("922337203685477580.7e1", &i));
    SSF_ASSERT(i == 9223372036854775807ull);

    /* Test boundary conditions of SSFDecStrToUInt() */
    for (uj = 0; uj < 1000000; uj++)
    {
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "%llu", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), " %llu", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "\t%llu", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), " \t%llu", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "\t %llu", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "\t\t%llu", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "  %llu", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "%llu ", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "%llua", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);
        u64 = uj + 1;
        snprintf(str1, sizeof(str1), "%llu]", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64));
        SSF_ASSERT(u64 == uj);

        snprintf(str1, sizeof(str1), "a%llu", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64) == false);
        snprintf(str1, sizeof(str1), "+%llu", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64) == false);
        snprintf(str1, sizeof(str1), "]%llu", (unsigned long long int)uj);
        SSF_ASSERT(SSFDecStrToUInt(str1, &u64) == false);
        snprintf(str1, sizeof(str1), " ] %llu", (unsigned long long int)uj);
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

    /* Verify _SSFDecStrToUInt overflow check does not reject valid 20-digit values where the */
    /* first 19 digits are below the threshold but the last digit is > '5'. */
    SSF_ASSERT(SSFDecStrToUInt("10000000000000000006", &u64));
    SSF_ASSERT(u64 == 10000000000000000006ull);
    SSF_ASSERT(SSFDecStrToUInt("10000000000000000009", &u64));
    SSF_ASSERT(u64 == 10000000000000000009ull);
    SSF_ASSERT(SSFDecStrToUInt("18446744073709551609", &u64));
    SSF_ASSERT(u64 == 18446744073709551609ull);

    /* Verify _SSFDecStrToInt overflow check does not reject valid 19-digit values where the */
    /* first 18 digits are below the threshold but the last digit is > '7' (positive) or > '8' */
    /* (negative). */
    SSF_ASSERT(SSFDecStrToInt("1000000000000000008", &i64));
    SSF_ASSERT(i64 == 1000000000000000008ll);
    SSF_ASSERT(SSFDecStrToInt("1000000000000000009", &i64));
    SSF_ASSERT(i64 == 1000000000000000009ll);
    SSF_ASSERT(SSFDecStrToInt("9223372036854775798", &i64));
    SSF_ASSERT(i64 == 9223372036854775798ll);
    SSF_ASSERT(SSFDecStrToInt("-1000000000000000009", &i64));
    SSF_ASSERT(i64 == -1000000000000000009ll);
    SSF_ASSERT(SSFDecStrToInt("-9223372036854775799", &i64));
    SSF_ASSERT(i64 == -9223372036854775799ll);

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

    /* SSFDecStrToInt/SSFDecStrToUInt with empty and whitespace-only strings */
    SSF_ASSERT(SSFDecStrToInt("", &i64) == false);
    SSF_ASSERT(SSFDecStrToInt(" ", &i64) == false);
    SSF_ASSERT(SSFDecStrToInt("\t", &i64) == false);
    SSF_ASSERT(SSFDecStrToInt(" \t ", &i64) == false);
    SSF_ASSERT(SSFDecStrToUInt("", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt(" ", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("\t", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt(" \t ", &u64) == false);

    /* SSFDecStrToInt with just a minus sign (no digits) */
    SSF_ASSERT(SSFDecStrToInt("-", &i64) == false);
    SSF_ASSERT(SSFDecStrToInt("- ", &i64) == false);
    SSF_ASSERT(SSFDecStrToInt(" -", &i64) == false);

    /* SSFDecStrToXInt with exponent marker but no digits after */
    SSF_ASSERT(SSFDecStrToInt("1e", &i64) == false);
    SSF_ASSERT(SSFDecStrToInt("1E", &i64) == false);
    SSF_ASSERT(SSFDecStrToInt("1e+", &i64) == false);
    SSF_ASSERT(SSFDecStrToInt("1e-", &i64) == false);
    SSF_ASSERT(SSFDecStrToUInt("1e", &u64) == false);

    /* SSFDecIntToStr with INT64_MIN */
    len1 = SSFDecIntToStr(-9223372036854775807ll - 1, str2, sizeof(str2));
    SSF_ASSERT(len1 != 0);
    SSF_ASSERT(memcmp(str2, "-9223372036854775808", len1 + 1) == 0);

    /* SSFDecUIntToStr with UINT64_MAX */
    len1 = SSFDecUIntToStr(18446744073709551615ull, str2, sizeof(str2));
    SSF_ASSERT(len1 != 0);
    SSF_ASSERT(memcmp(str2, "18446744073709551615", len1 + 1) == 0);

    /* SSFDecIntToStr/SSFDecUIntToStr with strSize=1 returns 0 (no room for digit + null) */
    SSF_ASSERT(SSFDecIntToStr(0, str2, 1) == 0);
    SSF_ASSERT(SSFDecIntToStr(5, str2, 1) == 0);
    SSF_ASSERT(SSFDecIntToStr(-1, str2, 1) == 0);
    SSF_ASSERT(SSFDecUIntToStr(0, str2, 1) == 0);
    SSF_ASSERT(SSFDecUIntToStr(9, str2, 1) == 0);
    /* strSize=2 fits single digit + null */
    SSF_ASSERT(SSFDecIntToStr(0, str2, 2) == 1);
    SSF_ASSERT(str2[0] == '0');
    SSF_ASSERT(SSFDecUIntToStr(9, str2, 2) == 1);
    SSF_ASSERT(str2[0] == '9');

    /* SSFDecStrToUInt with simple negative input */
    SSF_ASSERT(SSFDecStrToUInt("-1", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("-0", &u64) == false);

    /* SSFDecStrToXInt with zero in various formats */
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("0.0", &i64));
    SSF_ASSERT(i64 == 0ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("0e0", &i64));
    SSF_ASSERT(i64 == 0ll);
    i64 = 42;
    SSF_ASSERT(SSFDecStrToInt("0.0e0", &i64));
    SSF_ASSERT(i64 == 0ll);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("0.0", &u64));
    SSF_ASSERT(u64 == 0ull);
    u64 = 42;
    SSF_ASSERT(SSFDecStrToUInt("0e0", &u64));
    SSF_ASSERT(u64 == 0ull);

    /* SSFDecStrToXInt with base overflow during unsigned exponent scaling */
    SSF_ASSERT(SSFDecStrToUInt("2e19", &u64) == false);
    SSF_ASSERT(SSFDecStrToUInt("9e18", &u64) == true);
    SSF_ASSERT(u64 == 9000000000000000000ull);
    SSF_ASSERT(SSFDecStrToInt("1e18", &i64) == true);
    SSF_ASSERT(i64 == 1000000000000000000ll);
    SSF_ASSERT(SSFDecStrToInt("1e19", &i64) == false);

    /* SSFDecIntToStrPadded with negative values */
    /* minFieldWidth includes the '-' sign, so -5 w/minFieldWidth=4 → "-005" (len=4) */
    len1 = SSFDecIntToStrPadded(-5, str2, sizeof(str2), 4, '0');
    SSF_ASSERT(len1 == 4);
    SSF_ASSERT(memcmp(str2, "-005", 4) == 0);
    len1 = SSFDecIntToStrPadded(-123, str2, sizeof(str2), 4, '0');
    SSF_ASSERT(len1 == 4);
    SSF_ASSERT(memcmp(str2, "-123", 4) == 0);
    len1 = SSFDecIntToStrPadded(-1234, str2, sizeof(str2), 4, '0');
    SSF_ASSERT(len1 == 5);
    SSF_ASSERT(memcmp(str2, "-1234", 5) == 0);
    len1 = SSFDecIntToStrPadded(-12345, str2, sizeof(str2), 4, '0');
    SSF_ASSERT(len1 == 6);
    SSF_ASSERT(memcmp(str2, "-12345", 6) == 0);
    /* -5 w/minFieldWidth=5 → "-0005" (len=5) */
    len1 = SSFDecIntToStrPadded(-5, str2, sizeof(str2), 5, '0');
    SSF_ASSERT(len1 == 5);
    SSF_ASSERT(memcmp(str2, "-0005", 5) == 0);
    /* Negative padded with insufficient strSize */
    SSF_ASSERT(SSFDecIntToStrPadded(-5, str2, 4, 4, '0') == 0);
    SSF_ASSERT(SSFDecIntToStrPadded(-5, str2, 5, 4, '0') == 4);

    /* SSFDecUIntToStrPadded returns 0 when minFieldWidth >= strSize */
    SSF_ASSERT(SSFDecUIntToStrPadded(1, str2, 3, 3, '0') == 0);
    SSF_ASSERT(SSFDecUIntToStrPadded(1, str2, 3, 4, '0') == 0);
    SSF_ASSERT(SSFDecUIntToStrPadded(1, str2, 4, 3, '0') == 3);
    SSF_ASSERT(memcmp(str2, "001", 4) == 0);

    /* ---- SSFDecOctetsToStr ---- */
    {
        char ostr[32];
        uint8_t octets4[4] = { 192u, 168u, 1u, 10u };
        uint8_t octets1[1] = { 0u };
        uint8_t octets6[6] = { 0u, 17u, 34u, 51u, 68u, 85u };

        /* Basic IPv4-style dotted decimal */
        SSF_ASSERT(SSFDecOctetsToStr(octets4, 4, '.', ostr, sizeof(ostr)) == 12);
        SSF_ASSERT(memcmp(ostr, "192.168.1.10", 13) == 0);

        /* Single octet */
        SSF_ASSERT(SSFDecOctetsToStr(octets1, 1, '.', ostr, sizeof(ostr)) == 1);
        SSF_ASSERT(memcmp(ostr, "0", 2) == 0);

        /* 6 octets with colon separator */
        SSF_ASSERT(SSFDecOctetsToStr(octets6, 6, ':', ostr, sizeof(ostr)) == 16);
        SSF_ASSERT(memcmp(ostr, "0:17:34:51:68:85", 17) == 0);

        /* All 255s */
        {
            uint8_t octetsMax[4] = { 255u, 255u, 255u, 255u };
            SSF_ASSERT(SSFDecOctetsToStr(octetsMax, 4, '.', ostr, sizeof(ostr)) == 15);
            SSF_ASSERT(memcmp(ostr, "255.255.255.255", 16) == 0);
        }

        /* All 0s */
        {
            uint8_t octetsZero[4] = { 0u, 0u, 0u, 0u };
            SSF_ASSERT(SSFDecOctetsToStr(octetsZero, 4, '.', ostr, sizeof(ostr)) == 7);
            SSF_ASSERT(memcmp(ostr, "0.0.0.0", 8) == 0);
        }

        /* Buffer too small */
        SSF_ASSERT(SSFDecOctetsToStr(octets4, 4, '.', ostr, 12) == 0);
        SSF_ASSERT(SSFDecOctetsToStr(octets4, 4, '.', ostr, 13) == 12);

        /* Exact fit: "0.0" needs 4 bytes (3 chars + null) */
        {
            uint8_t octets2[2] = { 0u, 0u };
            SSF_ASSERT(SSFDecOctetsToStr(octets2, 2, '.', ostr, 4) == 3);
            SSF_ASSERT(memcmp(ostr, "0.0", 4) == 0);
            SSF_ASSERT(SSFDecOctetsToStr(octets2, 2, '.', ostr, 3) == 0);
        }

        /* Assert tests */
        SSF_ASSERT_TEST(SSFDecOctetsToStr(NULL, 4, '.', ostr, sizeof(ostr)));
        SSF_ASSERT_TEST(SSFDecOctetsToStr(octets4, 0, '.', ostr, sizeof(ostr)));
        SSF_ASSERT_TEST(SSFDecOctetsToStr(octets4, 4, '.', NULL, sizeof(ostr)));
        SSF_ASSERT_TEST(SSFDecOctetsToStr(octets4, 4, '.', ostr, 0));
    }

    /* ---- SSFDecStrToOctets ---- */
    {
        uint8_t octets[8];
        uint8_t numOctets;

        /* Basic IPv4-style dotted decimal */
        SSF_ASSERT(SSFDecStrToOctets("192.168.1.10", '.', octets, sizeof(octets),
                                     &numOctets) == true);
        SSF_ASSERT(numOctets == 4);
        SSF_ASSERT(octets[0] == 192u);
        SSF_ASSERT(octets[1] == 168u);
        SSF_ASSERT(octets[2] == 1u);
        SSF_ASSERT(octets[3] == 10u);

        /* Single octet */
        SSF_ASSERT(SSFDecStrToOctets("0", '.', octets, sizeof(octets), &numOctets) == true);
        SSF_ASSERT(numOctets == 1);
        SSF_ASSERT(octets[0] == 0u);

        /* All 255s */
        SSF_ASSERT(SSFDecStrToOctets("255.255.255.255", '.', octets, sizeof(octets),
                                     &numOctets) == true);
        SSF_ASSERT(numOctets == 4);
        SSF_ASSERT(octets[0] == 255u);
        SSF_ASSERT(octets[1] == 255u);
        SSF_ASSERT(octets[2] == 255u);
        SSF_ASSERT(octets[3] == 255u);

        /* Colon separator */
        SSF_ASSERT(SSFDecStrToOctets("10:20:30", ':', octets, sizeof(octets),
                                     &numOctets) == true);
        SSF_ASSERT(numOctets == 3);
        SSF_ASSERT(octets[0] == 10u);
        SSF_ASSERT(octets[1] == 20u);
        SSF_ASSERT(octets[2] == 30u);

        /* Value > 255 */
        SSF_ASSERT(SSFDecStrToOctets("256.0.0.0", '.', octets, sizeof(octets),
                                     &numOctets) == false);

        /* Leading zeros rejected */
        SSF_ASSERT(SSFDecStrToOctets("01.2.3.4", '.', octets, sizeof(octets),
                                     &numOctets) == false);
        SSF_ASSERT(SSFDecStrToOctets("1.02.3.4", '.', octets, sizeof(octets),
                                     &numOctets) == false);
        SSF_ASSERT(SSFDecStrToOctets("1.2.03.4", '.', octets, sizeof(octets),
                                     &numOctets) == false);
        SSF_ASSERT(SSFDecStrToOctets("1.2.3.04", '.', octets, sizeof(octets),
                                     &numOctets) == false);

        /* Trailing characters */
        SSF_ASSERT(SSFDecStrToOctets("1.2.3.4x", '.', octets, sizeof(octets),
                                     &numOctets) == false);

        /* Trailing separator */
        SSF_ASSERT(SSFDecStrToOctets("1.2.3.4.", '.', octets, sizeof(octets),
                                     &numOctets) == false);

        /* Empty string */
        SSF_ASSERT(SSFDecStrToOctets("", '.', octets, sizeof(octets), &numOctets) == false);

        /* Missing octet */
        SSF_ASSERT(SSFDecStrToOctets("1..3.4", '.', octets, sizeof(octets),
                                     &numOctets) == false);

        /* Output buffer too small */
        SSF_ASSERT(SSFDecStrToOctets("1.2.3.4", '.', octets, 3, &numOctets) == false);
        SSF_ASSERT(SSFDecStrToOctets("1.2.3.4", '.', octets, 4, &numOctets) == true);
        SSF_ASSERT(numOctets == 4);

        /* Round trip: encode then decode */
        {
            char rtStr[32];
            uint8_t rtOctets[4] = { 10u, 0u, 0u, 1u };
            uint8_t rtOut[4];
            uint8_t rtNum;

            SSF_ASSERT(SSFDecOctetsToStr(rtOctets, 4, '.', rtStr, sizeof(rtStr)) > 0);
            SSF_ASSERT(SSFDecStrToOctets(rtStr, '.', rtOut, sizeof(rtOut), &rtNum) == true);
            SSF_ASSERT(rtNum == 4);
            SSF_ASSERT(memcmp(rtOctets, rtOut, 4) == 0);
        }

        /* Assert tests */
        SSF_ASSERT_TEST(SSFDecStrToOctets(NULL, '.', octets, sizeof(octets), &numOctets));
        SSF_ASSERT_TEST(SSFDecStrToOctets("1.2", '.', NULL, sizeof(octets), &numOctets));
        SSF_ASSERT_TEST(SSFDecStrToOctets("1.2", '.', octets, 0, &numOctets));
        SSF_ASSERT_TEST(SSFDecStrToOctets("1.2", '.', octets, sizeof(octets), NULL));
    }
}
