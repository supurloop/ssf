/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfstrb_ut.h                                                                                  */
/* Provides safe C string buffer interface unit test.                                            */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2025 Supurloop Software LLC                                                         */
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
#include "ssfstrb.h"

#if SSF_CONFIG_STRB_UNIT_TEST == 1

#define SSF_STR_MAGIC (0x43735472)

/* --------------------------------------------------------------------------------------------- */
/* Asserts if ssfstr unit test fails.                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFStrBufUnitTest(void)
{
#define SSFSTR_UNIT_TEST_BUF_SIZE (257u)
    size_t s1Len;
    char dst[SSFSTR_UNIT_TEST_BUF_SIZE];
    char check[SSFSTR_UNIT_TEST_BUF_SIZE];
    size_t i;
    SSFCStrBuf_t sbDst;
    SSFCStrBuf_t sbCheck;
    const SSFCStr_t helloStr = "hello";
    char *tmp;
    size_t tlen;
    uint32_t tmagic;

    memset(&sbDst, 0, sizeof(sbDst));
    memset(&sbCheck, 0, sizeof(sbCheck));

    /* Test SSFStrBufInit() */
    SSF_ASSERT_TEST(SSFStrBufInit(NULL, dst, sizeof(dst), false, false));
    sbDst.ptr = (char*)1;
    SSF_ASSERT_TEST(SSFStrBufInit(&sbDst, dst, sizeof(dst), false, false));
    sbDst.ptr = NULL;
    sbDst.len = 1;
    SSF_ASSERT_TEST(SSFStrBufInit(&sbDst, dst, sizeof(dst), false, false));
    sbDst.len = 0;
    sbDst.magic = 1;
    SSF_ASSERT_TEST(SSFStrBufInit(&sbDst, dst, sizeof(dst), false, false));
    sbDst.magic = 0;
    sbDst.size = 1;
    SSF_ASSERT_TEST(SSFStrBufInit(&sbDst, dst, sizeof(dst), false, false));
    sbDst.size = 0;
    SSF_ASSERT_TEST(SSFStrBufInit(&sbDst, NULL, sizeof(dst), false, false));
    SSF_ASSERT_TEST(SSFStrBufInit(&sbDst, dst, 0, false, false));
    SSF_ASSERT_TEST(SSFStrBufInit(&sbDst, dst, SSF_STRB_MAX_SIZE + 1, false, false));

    memset(&sbDst, 0, sizeof(sbDst));
    memcpy(dst, "hello", 6);
    SSF_ASSERT(SSFStrBufInit(&sbDst, dst, sizeof(dst), false, false));
    SSF_ASSERT(sbDst.isConst == false);
    SSF_ASSERT(sbDst.isHeap == false);
    SSF_ASSERT(sbDst.ptr == dst);
    SSF_ASSERT(sbDst.len == 5);
    SSF_ASSERT(sbDst.size == sizeof(dst));
    SSF_ASSERT(sbDst.magic == SSF_STR_MAGIC);

    memset(&sbDst, 0, sizeof(sbDst));
    memcpy(dst, "", 1);
    SSF_ASSERT(SSFStrBufInit(&sbDst, dst, sizeof(dst), false, false));
    SSF_ASSERT(sbDst.isConst == false);
    SSF_ASSERT(sbDst.isHeap == false);
    SSF_ASSERT(sbDst.ptr == dst);
    SSF_ASSERT(sbDst.len == 0);
    SSF_ASSERT(sbDst.size == sizeof(dst));
    SSF_ASSERT(sbDst.magic == SSF_STR_MAGIC);

    memset(&sbDst, 0, sizeof(sbDst));
    memset(dst, 1, sizeof(dst));
    SSF_ASSERT(SSFStrBufInit(&sbDst, dst, sizeof(dst), false, false));
    SSF_ASSERT(sbDst.isConst == false);
    SSF_ASSERT(sbDst.isHeap == false);
    SSF_ASSERT(sbDst.ptr == dst);
    SSF_ASSERT(sbDst.len == sizeof(dst) - 1);
    SSF_ASSERT(sbDst.size == sizeof(dst));
    SSF_ASSERT(sbDst.magic == SSF_STR_MAGIC);

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitConst(&sbDst, "helloStr"));
    SSF_ASSERT(sbDst.isConst == true);
    SSF_ASSERT(sbDst.isHeap == false);
    SSF_ASSERT(memcmp(sbDst.ptr, "helloStr", 9) == 0);
    SSF_ASSERT(sbDst.len == strlen("helloStr"));
    SSF_ASSERT(sbDst.size == strlen("helloStr") + 1);
    SSF_ASSERT(sbDst.magic == SSF_STR_MAGIC);

    /* Test SSFStrBufDeInit() */
    memset(&sbCheck, 0, sizeof(sbCheck));
    SSF_ASSERT(memcmp(&sbCheck, &sbDst, sizeof(sbCheck)) != 0);
    SSFStrBufDeInit(&sbDst);
    SSF_ASSERT(memcmp(&sbCheck, &sbDst, sizeof(sbCheck)) == 0);

    memset(&sbDst, 0, sizeof(sbDst));
    memset(dst, 1, sizeof(dst));
    SSF_ASSERT(SSFStrBufInitVarMalloc(&sbDst, dst, sizeof(dst)));
    SSF_ASSERT(sbDst.isConst == false);
    SSF_ASSERT(sbDst.isHeap == true);
    SSF_ASSERT(sbDst.ptr != dst);
    SSF_ASSERT(memcmp(sbDst.ptr, dst, sizeof(dst)) == 0);
    SSF_ASSERT(sbDst.len == sizeof(dst) - 1);
    SSF_ASSERT(sbDst.size == sizeof(dst));
    SSF_ASSERT(sbDst.magic == SSF_STR_MAGIC);

    /* Test SSFStrBufDeInit() */
    memset(&sbCheck, 0, sizeof(sbCheck));
    SSF_ASSERT(memcmp(&sbCheck, &sbDst, sizeof(sbCheck)) != 0);
    SSFStrBufDeInit(&sbDst);
    SSF_ASSERT(memcmp(&sbCheck, &sbDst, sizeof(sbCheck)) == 0);

    /* Test SSFStrBufLen() and SSFStrBufSize() */
    SSF_ASSERT_TEST(SSFStrBufLen(NULL));

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitConst(&sbDst, "helloStr"));
    sbDst.ptr = NULL;
    SSF_ASSERT_TEST(SSFStrBufLen(&sbDst));

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitConst(&sbDst, "helloStr"));
    sbDst.len = sbDst.size;
    SSF_ASSERT_TEST(SSFStrBufLen(&sbDst));

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitConst(&sbDst, "helloStr"));
    sbDst.magic = 1;
    SSF_ASSERT_TEST(SSFStrBufLen(&sbDst));

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitVar(&sbDst, dst, sizeof(dst)));
    sbDst.ptr[sbDst.len] = 1;
    SSF_ASSERT_TEST(SSFStrBufLen(&sbDst));

    SSF_ASSERT_TEST(SSFStrBufSize(NULL));

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitConst(&sbDst, "helloStr"));
    sbDst.ptr = NULL;
    SSF_ASSERT_TEST(SSFStrBufSize(&sbDst));

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitConst(&sbDst, "helloStr"));
    sbDst.len = sbDst.size;
    SSF_ASSERT_TEST(SSFStrBufSize(&sbDst));

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitConst(&sbDst, "helloStr"));
    sbDst.magic = 1;
    SSF_ASSERT_TEST(SSFStrBufSize(&sbDst));

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitVar(&sbDst, dst, sizeof(dst)));
    sbDst.ptr[sbDst.len] = 1;
    SSF_ASSERT_TEST(SSFStrBufSize(&sbDst));

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitConst(&sbDst, ""));
    SSF_ASSERT(SSFStrBufLen(&sbDst) == 0);
    SSF_ASSERT(SSFStrBufSize(&sbDst) == 1);
    SSFStrBufDeInit(&sbDst);

    memset(&sbDst, 0, sizeof(sbDst));
    SSF_ASSERT(SSFStrBufInitConst(&sbDst, "1234567890"));
    SSF_ASSERT(SSFStrBufLen(&sbDst) == 10);
    SSF_ASSERT(SSFStrBufSize(&sbDst) == 11);
    SSFStrBufDeInit(&sbDst);

    memset(&sbDst, 0, sizeof(sbDst));
    memset(dst, 1, sizeof(dst));
    SSF_ASSERT(SSFStrBufInitVar(&sbDst, dst, sizeof(dst)));
    SSF_ASSERT(SSFStrBufLen(&sbDst) == sizeof(dst) - 1);
    SSF_ASSERT(SSFStrBufSize(&sbDst) == sizeof(dst));
    SSFStrBufDeInit(&sbDst);

    memset(&sbDst, 0, sizeof(sbDst));
    memset(dst, 2, sizeof(dst));
    SSF_ASSERT(SSFStrBufInitVarMalloc(&sbDst, dst, sizeof(dst)));
    SSF_ASSERT(SSFStrBufLen(&sbDst) == sizeof(dst) - 1);
    SSF_ASSERT(SSFStrBufSize(&sbDst) == sizeof(dst));
    SSFStrBufDeInit(&sbDst);

    /* Test SSFStrBufClr() */
    SSF_ASSERT_TEST(SSFStrBufClr(NULL));
    SSF_ASSERT(SSFStrBufInitVarMalloc(&sbDst, dst, sizeof(dst)));
    tmp = sbDst.ptr;
    sbDst.ptr = NULL;
    SSF_ASSERT_TEST(SSFStrBufClr(&sbDst));
    sbDst.ptr = tmp;
    tlen = sbDst.len;
    sbDst.len = sbDst.size;
    SSF_ASSERT_TEST(SSFStrBufClr(&sbDst));
    sbDst.len = tlen;
    tmagic = sbDst.magic;
    sbDst.magic = 1;
    SSF_ASSERT_TEST(SSFStrBufClr(&sbDst));
    sbDst.magic = tmagic;
    memset(sbDst.ptr, 0x01, sizeof(dst));
    sbDst.len = sizeof(dst) - 1;
    SSFStrBufClr(&sbDst);
    for (i = 0; i < sbDst.size; i++)
    {
        SSF_ASSERT(sbDst.ptr[i] == 0);
    }
    SSF_ASSERT(sbDst.len == 0);

#if 0

    /* Test SSFStrBufCat() */
    SSF_ASSERT_TEST(SSFStrBufCat(NULL, 4, &s1Len, "src", 4));
    SSF_ASSERT_TEST(SSFStrBufCat("dst", 4, NULL, "src", 4));
    SSF_ASSERT_TEST(SSFStrBufCat("dst", 4, &s1Len, NULL, 4));
    SSF_ASSERT(SSFStrBufCat("1234", 4, &s1Len, "src", 4) == false);
    SSF_ASSERT(SSFStrBufCat("dst", 4, &s1Len, "1234", 4) == false);
    memcpy(dst, "123", 4);
    dst[5] = 0x55;
    SSF_ASSERT(SSFStrBufCat(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "", 4));
    SSF_ASSERT(SSFStrBufCat(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "1", 4) == false);
    s1Len = 0;
    SSF_ASSERT(SSFStrBufCat(dst, SSF_MIN(5, sizeof(dst)), &s1Len, "1", 4));
    SSF_ASSERT(s1Len == 4);
    SSF_ASSERT(memcmp(dst, "1231", 5) == 0);
    SSF_ASSERT(dst[5] == 0x55);

    /* Test SSFStrBufCpy() */
    SSF_ASSERT_TEST(SSFStrBufCpy(NULL, 4, &s1Len, "src", 4));
    SSF_ASSERT_TEST(SSFStrBufCpy("dst", 4, NULL, "src", 4));
    SSF_ASSERT_TEST(SSFStrBufCpy("dst", 4, &s1Len, NULL, 4));
    SSF_ASSERT(SSFStrBufCpy("1234", 4, &s1Len, "src", 4) == false);
    SSF_ASSERT(SSFStrBufCpy("dst", 4, &s1Len, "1234", 4) == false);
    memcpy(dst, "123", 4);
    dst[4] = 0x55;
    SSF_ASSERT(SSFStrBufCpy(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "4567", 5) == false);
    s1Len = 0;
    SSF_ASSERT(SSFStrBufCpy(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "456", 4));
    SSF_ASSERT(s1Len == 3);
    SSF_ASSERT(memcmp(dst, "456", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    s1Len = 0;
    SSF_ASSERT(SSFStrBufCpy(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "7", 4));
    SSF_ASSERT(s1Len == 1);
    SSF_ASSERT(memcmp(dst, "7", 2) == 0);
    SSF_ASSERT(dst[4] == 0x55);

    /* Test SSFStrBufCmp() */
    SSF_ASSERT_TEST(SSFStrBufCmp(NULL, 2, "s2", 2));
    SSF_ASSERT_TEST(SSFStrBufCmp("s1", 2, NULL, 2));
    SSF_ASSERT(SSFStrBufCmp("\x01", 0, "\x00", 1) == false);
    SSF_ASSERT(SSFStrBufCmp("\x01", 1, "\x00", 0) == false);
    SSF_ASSERT(SSFStrBufCmp("\x01", 1, "\x00", 1) == false);
    SSF_ASSERT(SSFStrBufCmp("\x01", 1, "\x01", 1) == false);
    SSF_ASSERT(SSFStrBufCmp("\x01", 2, "\x01", 1) == false);
    SSF_ASSERT(SSFStrBufCmp("\x01", 2, "\x01", 2));
    SSF_ASSERT(SSFStrBufCmp("\x01", 2, "\x01\x02", 3) == false);
    SSF_ASSERT(SSFStrBufCmp("\x01\x02", 3, "\x01", 3) == false);
    SSF_ASSERT(SSFStrBufCmp("abc", 4, "abc", 4));
    SSF_ASSERT(SSFStrBufCmp("abc", 400, "abc", 400));
    SSF_ASSERT(SSFStrBufCmp("abc", 400, "Abc", 400) == false);
    SSF_ASSERT(SSFStrBufCmp("abc", 400, "aBc", 400) == false);
    SSF_ASSERT(SSFStrBufCmp("abc", 400, "abC", 400) == false);
    SSF_ASSERT(SSFStrBufCmp("Abc", 400, "abc", 400) == false);
    SSF_ASSERT(SSFStrBufCmp("aBc", 400, "abc", 400) == false);
    SSF_ASSERT(SSFStrBufCmp("abC", 400, "abc", 400) == false);
    SSF_ASSERT(SSFStrBufCmp("abc1", 400, "abc", 400) == false);
    SSF_ASSERT(SSFStrBufCmp("abc", 400, "abc1", 400) == false);

    /* Test SSFStrBufToCase() */
    SSF_ASSERT_TEST(SSFStrBufToCase(NULL, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_LOWER));
    SSF_ASSERT_TEST(SSFStrBufToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_MIN));
    SSF_ASSERT_TEST(SSFStrBufToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_MAX));
    memcpy(dst, "abc", 4);
    dst[4] = 0x55;
    SSF_ASSERT(SSFStrBufToCase(dst, SSF_MIN(3, sizeof(dst)), SSF_STRB_CASE_LOWER) == false);
    SSF_ASSERT(SSFStrBufToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_LOWER) == true);
    SSF_ASSERT(memcmp(dst, "abc", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    SSF_ASSERT(SSFStrBufToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_UPPER) == true);
    SSF_ASSERT(memcmp(dst, "ABC", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    SSF_ASSERT(SSFStrBufToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_UPPER) == true);
    SSF_ASSERT(memcmp(dst, "ABC", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    SSF_ASSERT(SSFStrBufToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_LOWER) == true);
    SSF_ASSERT(memcmp(dst, "abc", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    memcpy(dst, "A@Z", 4);
    SSF_ASSERT(SSFStrBufToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_LOWER) == true);
    SSF_ASSERT(memcmp(dst, "a@z", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    SSF_ASSERT(SSFStrBufToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_UPPER) == true);
    SSF_ASSERT(memcmp(dst, "A@Z", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    memcpy(dst, "[`{", 4);
    SSF_ASSERT(SSFStrBufToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_LOWER) == true);
    SSF_ASSERT(memcmp(dst, "[`{", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    SSF_ASSERT(SSFStrBufToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STRB_CASE_UPPER) == true);
    SSF_ASSERT(memcmp(dst, "[`{", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);

    for (i = 0; i < sizeof(dst); i++)
    {
        dst[i] = (i + 1) & 0xff;
    }
    SSF_ASSERT(SSFStrBufToCase(dst, sizeof(dst), SSF_STRB_CASE_LOWER) == true);
    for (i = 0; i < sizeof(check); i++)
    {
        check[i] = (i + 1) & 0xff;
        if ((check[i] >= 'A') && (check[i] <= 'Z')) check[i] += 32;
    }
    SSF_ASSERT(memcmp(dst, check, sizeof(dst)) == 0);
    SSF_ASSERT(dst[sizeof(dst) - 1] == 1);

    SSF_ASSERT(SSFStrBufToCase(dst, sizeof(dst), SSF_STRB_CASE_UPPER) == true);
    for (i = 0; i < sizeof(check); i++)
    {
        check[i] = (i + 1) & 0xff;
        if ((check[i] >= 'a') && (check[i] <= 'z')) check[i] -= 32;
    }
    SSF_ASSERT(memcmp(dst, check, sizeof(dst)) == 0);
    SSF_ASSERT(dst[sizeof(dst) - 1] == 1);
#endif
}
#endif /* SSF_CONFIG_STRB_UNIT_TEST */

