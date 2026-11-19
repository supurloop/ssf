/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfstr.h                                                                                      */
/* Provides safe C string interface unit test.                                                   */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2023 Supurloop Software LLC                                                         */
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
#include "ssfstr.h"

#if SSF_CONFIG_STR_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Asserts if ssfstr unit test fails.                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFStrUnitTest(void)
{
#define SSFSTR_UNIT_TEST_BUF_SIZE (257u)
    size_t s1Len;
    char dst[SSFSTR_UNIT_TEST_BUF_SIZE];
    SSFCStrIn_t tok;
    char check[SSFSTR_UNIT_TEST_BUF_SIZE];
    SSFCStrIn_t matchStrOptOut;
    size_t i;
    size_t len;
    size_t tokSize;

    /* Test SSFStrISValid() */
    SSF_ASSERT(SSFStrIsValid(NULL, 1) == false);
    SSF_ASSERT(SSFStrIsValid("abc", 0) == false);
    SSF_ASSERT(SSFStrIsValid("abc", 1) == false);
    SSF_ASSERT(SSFStrIsValid("abc", 2) == false);
    SSF_ASSERT(SSFStrIsValid("abc", 3) == false);
    SSF_ASSERT(SSFStrIsValid("abc", 4) == true);
    SSF_ASSERT(SSFStrIsValid("", 1) == true);

    /* Test SSFStrLen() */
    SSF_ASSERT_TEST(SSFStrLen(NULL, 1, &s1Len));
    SSF_ASSERT_TEST(SSFStrLen("a", 1, NULL));
    s1Len = 10;
    SSF_ASSERT(SSFStrLen("", 10, &s1Len));
    SSF_ASSERT(s1Len == 0);
    s1Len = 10;
    SSF_ASSERT(SSFStrLen("", 1, &s1Len));
    SSF_ASSERT(s1Len == 0);
    SSF_ASSERT(SSFStrLen("a", 1, &s1Len) == false);
    SSF_ASSERT(SSFStrLen("", 0, &s1Len) == false);
    s1Len = 0;
    SSF_ASSERT(SSFStrLen("1", 10, &s1Len));
    SSF_ASSERT(s1Len == 1);
    s1Len = 10;
    SSF_ASSERT(SSFStrLen("123456789", 10, &s1Len));
    SSF_ASSERT(s1Len == 9);
    SSF_ASSERT(SSFStrLen("1234567890", 10, &s1Len) == false);

    /* Test SSFStrCat() */
    SSF_ASSERT_TEST(SSFStrCat(NULL, 4, &s1Len, "src", 4));
    SSF_ASSERT_TEST(SSFStrCat("dst", 4, &s1Len, NULL, 4));
    SSF_ASSERT(SSFStrCat("1234", 4, &s1Len, "src", 4) == false);
    SSF_ASSERT(SSFStrCat("dst", 4, &s1Len, "1234", 4) == false);
    memcpy(dst, "123", 4);
    dst[5] = 0x55;
    SSF_ASSERT(SSFStrCat(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "", 4));
    SSF_ASSERT(SSFStrCat(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "1", 4) == false);
    s1Len = 0;
    SSF_ASSERT(SSFStrCat(dst, SSF_MIN(5, sizeof(dst)), &s1Len, "1", 4));
    SSF_ASSERT(s1Len == 4);
    SSF_ASSERT(memcmp(dst, "1231", 5) == 0);
    SSF_ASSERT(dst[5] == 0x55);

    /* AUDIT STR-2: SSFStrStr never reads past cstrSize or substrSize, even with no NUL; run */
    /* under ASan to catch the old one-byte over-read. AUDIT STR-6: every false clears the   */
    /* match output.                                                                         */
    {
        static const char hay[3] = { 'a', 'b', 'c' };
        static const char one[1] = { 'a' };

        matchStrOptOut = hay;
        SSF_ASSERT(SSFStrStr(hay, sizeof(hay), &matchStrOptOut, "cd", 3) == false);
        SSF_ASSERT(matchStrOptOut == NULL);
        SSF_ASSERT(SSFStrStr(hay, sizeof(hay), &matchStrOptOut, "bc", 3));
        SSF_ASSERT(matchStrOptOut == &hay[1]);
        SSF_ASSERT(SSFStrStr(hay, sizeof(hay), &matchStrOptOut, "abcd", 5) == false);
        SSF_ASSERT(SSFStrStr(&hay[2], 1u, &matchStrOptOut, "c", 2));
        SSF_ASSERT(matchStrOptOut == &hay[2]);
        SSF_ASSERT(SSFStrStr(&hay[2], 0u, NULL, "x", 2) == false);
        SSF_ASSERT(SSFStrStr(hay, sizeof(hay), NULL, "a", 0u) == false);

        /* STR-6: a mismatch on the last byte takes the early return; it must clear the output */
        matchStrOptOut = hay;
        SSF_ASSERT(SSFStrStr(one, sizeof(one), &matchStrOptOut, "x", 2) == false);
        SSF_ASSERT(matchStrOptOut == NULL);
    }

    /* AUDIT STR-3: the length output of SSFStrCpy / SSFStrCat is optional, as documented */
    {
        char small[3];

        memcpy(small, "xy", 3);
        SSF_ASSERT(SSFStrCpy(small, sizeof(small), NULL, "hello", 6) == false);
        SSF_ASSERT(memcmp(small, "xy", 3) == 0);
        SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), NULL, "abc", 4));
        SSF_ASSERT(memcmp(dst, "abc", 4) == 0);
        SSF_ASSERT(SSFStrCat(dst, sizeof(dst), NULL, "de", 3));
        SSF_ASSERT(memcmp(dst, "abcde", 6) == 0);
        SSF_ASSERT(SSFStrCat(small, sizeof(small), NULL, "z", 2) == false);
        SSF_ASSERT(memcmp(small, "xy", 3) == 0);
    }

    /* Test SSFStrCpy() */
    SSF_ASSERT_TEST(SSFStrCpy(NULL, 4, &s1Len, "src", 4));
    SSF_ASSERT_TEST(SSFStrCpy("dst", 4, &s1Len, NULL, 4));
    SSF_ASSERT(SSFStrCpy(dst, 0, &s1Len, "src", 4) == false);
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "1234", 4) == false);
    SSF_ASSERT(SSFStrCpy(dst, 1, &s1Len, "1234", 5) == false);
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "1234", 5));
    memcpy(dst, "123", 4);
    dst[4] = 0x55;
    SSF_ASSERT(SSFStrCpy(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "4567", 5) == false);
    s1Len = 0;
    SSF_ASSERT(SSFStrCpy(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "456", 4));
    SSF_ASSERT(s1Len == 3);
    SSF_ASSERT(memcmp(dst, "456", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    s1Len = 0;
    SSF_ASSERT(SSFStrCpy(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "7", 4));
    SSF_ASSERT(s1Len == 1);
    SSF_ASSERT(memcmp(dst, "7", 2) == 0);
    SSF_ASSERT(dst[4] == 0x55);

    /* Test SSFStrCmp() */
    SSF_ASSERT_TEST(SSFStrCmp(NULL, 2, "s2", 2));
    SSF_ASSERT_TEST(SSFStrCmp("s1", 2, NULL, 2));
    SSF_ASSERT(SSFStrCmp("\x01", 0, "\x00", 1) == false);
    SSF_ASSERT(SSFStrCmp("\x01", 1, "\x00", 0) == false);
    SSF_ASSERT(SSFStrCmp("\x01", 1, "\x00", 1) == false);
    SSF_ASSERT(SSFStrCmp("\x01", 1, "\x01", 1) == false);
    SSF_ASSERT(SSFStrCmp("\x01", 2, "\x01", 1) == false);
    SSF_ASSERT(SSFStrCmp("\x01", 2, "\x01", 2));
    SSF_ASSERT(SSFStrCmp("\x01", 2, "\x01\x02", 3) == false);
    SSF_ASSERT(SSFStrCmp("\x01\x02", 3, "\x01", 3) == false);
    SSF_ASSERT(SSFStrCmp("abc", 4, "abc", 4));
    SSF_ASSERT(SSFStrCmp("abc", 400, "abc", 400));
    SSF_ASSERT(SSFStrCmp("abc", 400, "Abc", 400) == false);
    SSF_ASSERT(SSFStrCmp("abc", 400, "aBc", 400) == false);
    SSF_ASSERT(SSFStrCmp("abc", 400, "abC", 400) == false);
    SSF_ASSERT(SSFStrCmp("Abc", 400, "abc", 400) == false);
    SSF_ASSERT(SSFStrCmp("aBc", 400, "abc", 400) == false);
    SSF_ASSERT(SSFStrCmp("abC", 400, "abc", 400) == false);
    SSF_ASSERT(SSFStrCmp("abc1", 400, "abc", 400) == false);
    SSF_ASSERT(SSFStrCmp("abc", 400, "abc1", 400) == false);

    /* Test SSFStrToCase() */
    SSF_ASSERT_TEST(SSFStrToCase(NULL, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_LOWER));
    SSF_ASSERT_TEST(SSFStrToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_MIN));
    SSF_ASSERT_TEST(SSFStrToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_MAX));
    memcpy(dst, "abc", 4);
    dst[4] = 0x55;
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(3, sizeof(dst)), SSF_STR_CASE_LOWER) == false);
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_LOWER) == true);
    SSF_ASSERT(memcmp(dst, "abc", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_UPPER) == true);
    SSF_ASSERT(memcmp(dst, "ABC", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_UPPER) == true);
    SSF_ASSERT(memcmp(dst, "ABC", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_LOWER) == true);
    SSF_ASSERT(memcmp(dst, "abc", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    memcpy(dst, "A@Z", 4);
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_LOWER) == true);
    SSF_ASSERT(memcmp(dst, "a@z", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_UPPER) == true);
    SSF_ASSERT(memcmp(dst, "A@Z", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    memcpy(dst, "[`{", 4);
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_LOWER) == true);
    SSF_ASSERT(memcmp(dst, "[`{", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(4, sizeof(dst)), SSF_STR_CASE_UPPER) == true);
    SSF_ASSERT(memcmp(dst, "[`{", 4) == 0);
    SSF_ASSERT(dst[4] == 0x55);

    for (i = 0; i < sizeof(dst); i++)
    {
        dst[i] = (i + 1) & 0xff;
    }
    SSF_ASSERT(SSFStrToCase(dst, sizeof(dst), SSF_STR_CASE_LOWER) == true);
    for (i = 0; i < sizeof(check); i++)
    {
        check[i] = (i + 1) & 0xff;
        if ((check[i] >= 'A') && (check[i] <= 'Z')) check[i] += 32;
    }
    SSF_ASSERT(memcmp(dst, check, sizeof(dst)) == 0);
    SSF_ASSERT(dst[sizeof(dst) - 1] == 1);

    SSF_ASSERT(SSFStrToCase(dst, sizeof(dst), SSF_STR_CASE_UPPER) == true);
    for (i = 0; i < sizeof(check); i++)
    {
        check[i] = (i + 1) & 0xff;
        if ((check[i] >= 'a') && (check[i] <= 'z')) check[i] -= 32;
    }
    SSF_ASSERT(memcmp(dst, check, sizeof(dst)) == 0);
    SSF_ASSERT(dst[sizeof(dst) - 1] == 1);

    /* Test SSFStrStr() */
    SSF_ASSERT_TEST(SSFStrStr(NULL, 7, NULL, "substr", 7));
    SSF_ASSERT_TEST(SSFStrStr(NULL, 7, &matchStrOptOut, "substr", 7));
    SSF_ASSERT_TEST(SSFStrStr("string", 7, NULL, NULL, 7));
    SSF_ASSERT_TEST(SSFStrStr("string", 7, &matchStrOptOut, NULL, 7));

    SSF_ASSERT(SSFStrStr("string", 7, NULL, "substr", 7) == false);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr("string", 7, &matchStrOptOut, "substr", 7) == false);
    SSF_ASSERT(matchStrOptOut == NULL);

    SSF_ASSERT(SSFStrCpy(check, sizeof(check), &s1Len, "substrstring", 13));
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 7));
    SSF_ASSERT(SSFStrStr(check, 14, NULL, "substr", 8));
    SSF_ASSERT(SSFStrStr(check, 12, NULL, "substr", 7));
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 6) == false);
    SSF_ASSERT(SSFStrStr(check, 0, NULL, "substr", 7) == false);
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 0) == false);
    SSF_ASSERT(SSFStrStr("subsubstr", 10, NULL, "substr", 7));

    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 7));
    SSF_ASSERT(matchStrOptOut == &check[0]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 14, &matchStrOptOut, "substr", 8));
    SSF_ASSERT(matchStrOptOut == &check[0]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 12, &matchStrOptOut, "substr", 7));
    SSF_ASSERT(matchStrOptOut == &check[0]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 6) == false);
    SSF_ASSERT(matchStrOptOut == NULL);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 0, &matchStrOptOut, "substr", 7) == false);
    SSF_ASSERT(matchStrOptOut == NULL);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 0) == false);
    SSF_ASSERT(matchStrOptOut == NULL);

    SSF_ASSERT(SSFStrCpy(check, sizeof(check), &s1Len, "strsubsubstr", 13));
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 7));
    SSF_ASSERT(SSFStrStr(check, 14, NULL, "substr", 8));
    SSF_ASSERT(SSFStrStr(check, 12, NULL, "substr", 7));
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 6) == false);
    SSF_ASSERT(SSFStrStr(check, 0, NULL, "substr", 7) == false);
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 0) == false);

    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 7));
    SSF_ASSERT(matchStrOptOut == &check[6]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 14, &matchStrOptOut, "substr", 8));
    SSF_ASSERT(matchStrOptOut == &check[6]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 12, &matchStrOptOut, "substr", 7));
    SSF_ASSERT(matchStrOptOut == &check[6]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 6) == false);
    SSF_ASSERT(matchStrOptOut == NULL);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 0, &matchStrOptOut, "substr", 7) == false);
    SSF_ASSERT(matchStrOptOut == NULL);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 0) == false);
    SSF_ASSERT(matchStrOptOut == NULL);

    SSF_ASSERT(SSFStrCpy(check, sizeof(check), &s1Len, "substsubstrr", 13));
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 7));
    SSF_ASSERT(SSFStrStr(check, 14, NULL, "substr", 8));
    SSF_ASSERT(SSFStrStr(check, 12, NULL, "substr", 7));
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 6) == false);
    SSF_ASSERT(SSFStrStr(check, 0, NULL, "substr", 7) == false);
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 0) == false);

    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 7));
    SSF_ASSERT(matchStrOptOut == &check[5]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 14, &matchStrOptOut, "substr", 8));
    SSF_ASSERT(matchStrOptOut == &check[5]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 12, &matchStrOptOut, "substr", 7));
    SSF_ASSERT(matchStrOptOut == &check[5]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 6) == false);
    SSF_ASSERT(matchStrOptOut == NULL);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 0, &matchStrOptOut, "substr", 7) == false);
    SSF_ASSERT(matchStrOptOut == NULL);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 0) == false);
    SSF_ASSERT(matchStrOptOut == NULL);

    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr("xb", 3, &matchStrOptOut, "ab", 3) == false);
    SSF_ASSERT(matchStrOptOut == NULL);

    /* "abc" is NOT in "xbc": same substr[0]-skip, longer pattern. */
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr("xbc", 4, &matchStrOptOut, "abc", 4) == false);
    SSF_ASSERT(matchStrOptOut == NULL);

    SSF_ASSERT(SSFStrCpy(check, sizeof(check), &s1Len, "abba", 5));
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 5, &matchStrOptOut, "aba", 4) == false);
    SSF_ASSERT(matchStrOptOut == NULL);

    SSF_ASSERT(SSFStrCpy(check, sizeof(check), &s1Len, "ax", 3));
    matchStrOptOut = NULL;
    SSF_ASSERT(SSFStrStr(check, 3, &matchStrOptOut, "x", 2) == true);
    SSF_ASSERT(matchStrOptOut == &check[1]);

    SSF_ASSERT(SSFStrCpy(check, sizeof(check), &s1Len, "ab", 3));
    matchStrOptOut = NULL;
    SSF_ASSERT(SSFStrStr(check, 3, &matchStrOptOut, "b", 2) == true);
    SSF_ASSERT(matchStrOptOut == &check[1]);

    SSF_ASSERT(SSFStrCpy(check, sizeof(check), &s1Len, "aaz", 4));
    matchStrOptOut = NULL;
    SSF_ASSERT(SSFStrStr(check, 4, &matchStrOptOut, "z", 2) == true);
    SSF_ASSERT(matchStrOptOut == &check[2]);

    /* Test SSFStrStr() - fuzz test against C library strstr() */
    {
        char srchBuf[65];
        char matchBuf[65];
        size_t srchLen;
        size_t matchLen;
        size_t iter;
        size_t k;
        const char *libResult;
        bool ssfResult;
        const char *ssfMatchOut;
        static const char fuzzCharset[3] = {'a', 'b', 'c'};

        srand(1u);

        for (srchLen = 1; srchLen <= 64; srchLen++)
        {
            for (iter = 0; iter < 4096; iter++)
            {
                /* Build random search string of length srchLen */
                for (k = 0; k < srchLen; k++) srchBuf[k] = fuzzCharset[rand() % 3];
                srchBuf[srchLen] = '\0';

                for (matchLen = 1; matchLen <= 64; matchLen++)
                {
                    /* Build random match string of length matchLen */
                    for (k = 0; k < matchLen; k++) matchBuf[k] = fuzzCharset[rand() % 3];
                    matchBuf[matchLen] = '\0';

                    /* Get reference result from C library strstr() */
                    libResult = strstr(srchBuf, matchBuf);

                    /* Get SSFStrStr result */
                    ssfMatchOut = NULL;
                    ssfResult = SSFStrStr(srchBuf, srchLen + 1, &ssfMatchOut,
                                         matchBuf, matchLen + 1);

                    if (libResult != NULL)
                    {
                        /* strstr found a match; SSFStrStr must find the same location */
                        SSF_ASSERT(ssfResult == true);
                        SSF_ASSERT(ssfMatchOut == libResult);
                    }
                    else
                    {
                        /* strstr found no match; SSFStrStr must agree */
                        SSF_ASSERT(ssfResult == false);
                        SSF_ASSERT(ssfMatchOut == NULL);
                    }
                }
            }
        }
    }

    /* Test SSFStrTok() (AUDIT STR-1/3/4/5: in/out source size, final token returns true, */
    /* an oversize token is not consumed, optional length, empty token on false)           */
    #define _TOK_START(_str) do { \
        SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, (_str), sizeof(_str))); \
        tok = dst; tokSize = sizeof(_str); \
    } while (0)
    #define _TOK_NEXT(_expect, _token, _pos) do { \
        memset(check, 0x55, sizeof(check)); \
        len = 99u; \
        SSF_ASSERT(SSFStrTok(&tok, &tokSize, check, sizeof(check), &len, " ,", 3) == (_expect)); \
        SSF_ASSERT((strlen(check) == strlen(_token)) && (strcmp(check, (_token)) == 0)); \
        SSF_ASSERT(len == strlen(_token)); \
        SSF_ASSERT(tok == &dst[(_pos)]); \
        SSF_ASSERT(tokSize == (tokSizeStart - (size_t)(_pos))); \
    } while (0)

    tokSize = sizeof(dst);
    tok = NULL;
    SSF_ASSERT_TEST(SSFStrTok(NULL, &tokSize, check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT_TEST(SSFStrTok(&tok, &tokSize, check, sizeof(check), &len, " ,", 3));
    tok = dst;
    SSF_ASSERT_TEST(SSFStrTok(&tok, NULL, check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT_TEST(SSFStrTok(&tok, &tokSize, NULL, sizeof(check), &len, " ,", 3));
    SSF_ASSERT_TEST(SSFStrTok(&tok, &tokSize, check, 0, &len, " ,", 3));
    SSF_ASSERT_TEST(SSFStrTok(&tok, &tokSize, check, sizeof(check), &len, NULL, 3));

    {
        size_t tokSizeStart;

        /* The source size is a hard cap that shrinks as input is consumed: "abcdef" bounded */
        /* to 3 bytes yields the final token "abc", then end of input, never reading dst[3] */
        SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "abcdef", 7));
        tok = dst; tokSize = 3u; tokSizeStart = 3u;
        _TOK_NEXT(true, "abc", 3);
        _TOK_NEXT(false, "", 3);

        /* Empty input, and a zero source size: end of input, nothing consumed */
        _TOK_START(""); tokSizeStart = sizeof("");
        _TOK_NEXT(false, "", 0);
        tok = dst; tokSize = 0u; tokSizeStart = 0u;
        _TOK_NEXT(false, "", 0);

        /* No delimiter: the whole string is the final token, returned with true */
        _TOK_START("substsubstrr"); tokSizeStart = sizeof("substsubstrr");
        _TOK_NEXT(true, "substsubstrr", 12);
        _TOK_NEXT(false, "", 12);

        /* Two tokens, either delimiter; the last one has no trailing delimiter */
        _TOK_START("subst,ubstrr"); tokSizeStart = sizeof("subst,ubstrr");
        _TOK_NEXT(true, "subst", 6);
        _TOK_NEXT(true, "ubstrr", 12);
        _TOK_NEXT(false, "", 12);
        _TOK_START("subst ubstrr"); tokSizeStart = sizeof("subst ubstrr");
        _TOK_NEXT(true, "subst", 6);
        _TOK_NEXT(true, "ubstrr", 12);
        _TOK_NEXT(false, "", 12);

        /* A character that is not a delimiter stays in the token */
        _TOK_START("subst!ubstrr"); tokSizeStart = sizeof("subst!ubstrr");
        _TOK_NEXT(true, "subst!ubstrr", 12);
        _TOK_NEXT(false, "", 12);

        /* Leading and trailing delimiters: a leading one gives an empty token; a trailing one */
        /* ends the last token and no empty token follows it                                */
        _TOK_START(",substubstr "); tokSizeStart = sizeof(",substubstr ");
        _TOK_NEXT(true, "", 1);
        _TOK_NEXT(true, "substubstr", 12);
        _TOK_NEXT(false, "", 12);
        _TOK_START(","); tokSizeStart = sizeof(",");
        _TOK_NEXT(true, "", 1);
        _TOK_NEXT(false, "", 1);
        _TOK_START(", ,"); tokSizeStart = sizeof(", ,");
        _TOK_NEXT(true, "", 1);
        _TOK_NEXT(true, "", 2);
        _TOK_NEXT(true, "", 3);
        _TOK_NEXT(false, "", 3);
        _TOK_START("a,,b"); tokSizeStart = sizeof("a,,b");
        _TOK_NEXT(true, "a", 2);
        _TOK_NEXT(true, "", 3);
        _TOK_NEXT(true, "b", 4);
        _TOK_NEXT(false, "", 4);

        /* Single-character tokens */
        _TOK_START("0,1 2,3"); tokSizeStart = sizeof("0,1 2,3");
        _TOK_NEXT(true, "0", 2);
        _TOK_NEXT(true, "1", 4);
        _TOK_NEXT(true, "2", 6);
        _TOK_NEXT(true, "3", 7);
        _TOK_NEXT(false, "", 7);
    }
    #undef _TOK_START
    #undef _TOK_NEXT

    /* AUDIT STR-1: a source with no NUL, bounded only by its size, is never over-read. The */
    /* old fixed cstrSize let the second call scan past the end of these 7 bytes.           */
    {
        static const char raw[7] = { 'o', 'n', 'e', ',', 't', 'w', 'o' };
        SSFCStrIn_t rp = raw;
        size_t rs = sizeof(raw);

        SSF_ASSERT(SSFStrTok(&rp, &rs, check, sizeof(check), &len, ",", 2));
        SSF_ASSERT((len == 3u) && (strcmp(check, "one") == 0) && (rs == 3u));
        SSF_ASSERT(SSFStrTok(&rp, &rs, check, sizeof(check), &len, ",", 2));
        SSF_ASSERT((len == 3u) && (strcmp(check, "two") == 0) && (rs == 0u));
        SSF_ASSERT(rp == &raw[7]);
        SSF_ASSERT(SSFStrTok(&rp, &rs, check, sizeof(check), &len, ",", 2) == false);
    }

    /* AUDIT STR-4: the documented example loop sees all three tokens */
    {
        static const char src[] = "one,two,three";
        static const char *expect[] = { "one", "two", "three" };
        SSFCStrIn_t pos = src;
        size_t posSize = sizeof(src);
        char token[16];
        size_t n = 0;

        while (SSFStrTok(&pos, &posSize, token, sizeof(token), &len, ",", sizeof(",")))
        {
            SSF_ASSERT(n < 3u);
            SSF_ASSERT((strcmp(token, expect[n]) == 0) && (len == strlen(expect[n])));
            n++;
        }
        SSF_ASSERT(n == 3u);
        SSF_ASSERT((posSize == 1u) && (*pos == 0));
    }

    /* AUDIT STR-3: the token length output is optional */
    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "ab,c", 5));
    tokSize = 5u;
    SSF_ASSERT(SSFStrTok(&tok, &tokSize, check, sizeof(check), NULL, ",", 2));
    SSF_ASSERT((strcmp(check, "ab") == 0) && (tok == &dst[3]) && (tokSize == 2u));

    /* SSFStrCpy with empty source string */
    memset(dst, 0x55, sizeof(dst));
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "", 1));
    SSF_ASSERT(s1Len == 0);
    SSF_ASSERT(dst[0] == 0);

    /* SSFStrCat onto empty destination */
    memset(dst, 0, 1);
    dst[1] = 0x55;
    SSF_ASSERT(SSFStrCat(dst, SSF_MIN(6, sizeof(dst)), &s1Len, "hello", 6));
    SSF_ASSERT(s1Len == 5);
    SSF_ASSERT(memcmp(dst, "hello", 6) == 0);
    /* Cat onto empty with exact fit */
    memset(dst, 0, 1);
    SSF_ASSERT(SSFStrCat(dst, SSF_MIN(4, sizeof(dst)), &s1Len, "abc", 4));
    SSF_ASSERT(s1Len == 3);
    SSF_ASSERT(memcmp(dst, "abc", 4) == 0);
    /* Cat onto empty with 1 byte short */
    memset(dst, 0, 1);
    SSF_ASSERT(SSFStrCat(dst, SSF_MIN(3, sizeof(dst)), &s1Len, "abc", 4) == false);

    /* SSFStrCmp comparing two empty strings */
    SSF_ASSERT(SSFStrCmp("", 1, "", 1));
    SSF_ASSERT(SSFStrCmp("", 1, "a", 2) == false);
    SSF_ASSERT(SSFStrCmp("a", 2, "", 1) == false);

    /* SSFStrToCase with empty string */
    memcpy(dst, "", 1);
    dst[1] = 0x55;
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(1, sizeof(dst)), SSF_STR_CASE_LOWER));
    SSF_ASSERT(dst[0] == 0);
    SSF_ASSERT(dst[1] == 0x55);
    SSF_ASSERT(SSFStrToCase(dst, SSF_MIN(1, sizeof(dst)), SSF_STR_CASE_UPPER));
    SSF_ASSERT(dst[0] == 0);
    SSF_ASSERT(dst[1] == 0x55);

    /* AUDIT STR-5: a token too big for the token buffer returns false and is not consumed, */
    /* so a larger buffer can retry it; the token buffer is left empty, never stale         */
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "hello,world", 12));
    tok = dst;
    tokSize = 12u;
    memcpy(check, "zz", 3);
    SSF_ASSERT(SSFStrTok(&tok, &tokSize, check, 3, &len, ",", 2) == false);
    SSF_ASSERT((len == 0u) && (check[0] == 0) && (tok == dst) && (tokSize == 12u));
    SSF_ASSERT(SSFStrTok(&tok, &tokSize, check, 6, &len, ",", 2));
    SSF_ASSERT((len == 5u) && (memcmp(check, "hello", 6) == 0) && (tok == &dst[6]));
    SSF_ASSERT(SSFStrTok(&tok, &tokSize, check, 6, &len, ",", 2));
    SSF_ASSERT((len == 5u) && (memcmp(check, "world", 6) == 0) && (tokSize == 1u));
    SSF_ASSERT(SSFStrTok(&tok, &tokSize, check, 6, &len, ",", 2) == false);

    /* SSFStrStr with substr longer than cstr */
    SSF_ASSERT(SSFStrStr("ab", 3, NULL, "abcdef", 7) == false);
    matchStrOptOut = (SSFCStrIn_t)1;
    SSF_ASSERT(SSFStrStr("ab", 3, &matchStrOptOut, "abcdef", 7) == false);
    SSF_ASSERT(matchStrOptOut == NULL);

    /* SSFStrCat exactly filling the buffer */
    memcpy(dst, "hi", 3);
    dst[3] = 0x55;
    SSF_ASSERT(SSFStrCat(dst, SSF_MIN(6, sizeof(dst)), &s1Len, "abc", 4));
    SSF_ASSERT(s1Len == 5);
    SSF_ASSERT(memcmp(dst, "hiabc", 6) == 0);
    /* One more byte would overflow */
    memcpy(dst, "hi", 3);
    SSF_ASSERT(SSFStrCat(dst, SSF_MIN(5, sizeof(dst)), &s1Len, "abc", 4) == false);

    /* ---- SSFStrCharToLower: exhaustive ---- */
    {
        /* Every uppercase letter maps to its lowercase equivalent */
        SSF_ASSERT(SSFStrCharToLower('A') == 'a');
        SSF_ASSERT(SSFStrCharToLower('B') == 'b');
        SSF_ASSERT(SSFStrCharToLower('C') == 'c');
        SSF_ASSERT(SSFStrCharToLower('D') == 'd');
        SSF_ASSERT(SSFStrCharToLower('E') == 'e');
        SSF_ASSERT(SSFStrCharToLower('F') == 'f');
        SSF_ASSERT(SSFStrCharToLower('G') == 'g');
        SSF_ASSERT(SSFStrCharToLower('H') == 'h');
        SSF_ASSERT(SSFStrCharToLower('I') == 'i');
        SSF_ASSERT(SSFStrCharToLower('J') == 'j');
        SSF_ASSERT(SSFStrCharToLower('K') == 'k');
        SSF_ASSERT(SSFStrCharToLower('L') == 'l');
        SSF_ASSERT(SSFStrCharToLower('M') == 'm');
        SSF_ASSERT(SSFStrCharToLower('N') == 'n');
        SSF_ASSERT(SSFStrCharToLower('O') == 'o');
        SSF_ASSERT(SSFStrCharToLower('P') == 'p');
        SSF_ASSERT(SSFStrCharToLower('Q') == 'q');
        SSF_ASSERT(SSFStrCharToLower('R') == 'r');
        SSF_ASSERT(SSFStrCharToLower('S') == 's');
        SSF_ASSERT(SSFStrCharToLower('T') == 't');
        SSF_ASSERT(SSFStrCharToLower('U') == 'u');
        SSF_ASSERT(SSFStrCharToLower('V') == 'v');
        SSF_ASSERT(SSFStrCharToLower('W') == 'w');
        SSF_ASSERT(SSFStrCharToLower('X') == 'x');
        SSF_ASSERT(SSFStrCharToLower('Y') == 'y');
        SSF_ASSERT(SSFStrCharToLower('Z') == 'z');

        /* Every lowercase letter is unchanged */
        SSF_ASSERT(SSFStrCharToLower('a') == 'a');
        SSF_ASSERT(SSFStrCharToLower('b') == 'b');
        SSF_ASSERT(SSFStrCharToLower('m') == 'm');
        SSF_ASSERT(SSFStrCharToLower('z') == 'z');

        /* Every digit is unchanged */
        SSF_ASSERT(SSFStrCharToLower('0') == '0');
        SSF_ASSERT(SSFStrCharToLower('1') == '1');
        SSF_ASSERT(SSFStrCharToLower('5') == '5');
        SSF_ASSERT(SSFStrCharToLower('9') == '9');

        /* Common symbols and whitespace unchanged */
        SSF_ASSERT(SSFStrCharToLower(' ') == ' ');
        SSF_ASSERT(SSFStrCharToLower('\t') == '\t');
        SSF_ASSERT(SSFStrCharToLower('\n') == '\n');
        SSF_ASSERT(SSFStrCharToLower('\r') == '\r');
        SSF_ASSERT(SSFStrCharToLower('\0') == '\0');
        SSF_ASSERT(SSFStrCharToLower('!') == '!');
        SSF_ASSERT(SSFStrCharToLower('@') == '@');
        SSF_ASSERT(SSFStrCharToLower('[') == '[');
        SSF_ASSERT(SSFStrCharToLower('{') == '{');
        SSF_ASSERT(SSFStrCharToLower('~') == '~');
        SSF_ASSERT(SSFStrCharToLower('/') == '/');
        SSF_ASSERT(SSFStrCharToLower('-') == '-');
        SSF_ASSERT(SSFStrCharToLower('_') == '_');
        SSF_ASSERT(SSFStrCharToLower('.') == '.');

        /* Boundary chars adjacent to A-Z range are unchanged */
        SSF_ASSERT(SSFStrCharToLower('@') == '@');  /* 0x40, one before 'A' */
        SSF_ASSERT(SSFStrCharToLower('[') == '[');  /* 0x5B, one after 'Z' */

        /* Full 0-255 sweep: every char either converts or is unchanged */
        {
            int c;
            for (c = 0; c < 256; c++)
            {
                char result = SSFStrCharToLower((char)c);
                if (c >= 'A' && c <= 'Z')
                {
                    SSF_ASSERT(result == (char)(c + ('a' - 'A')));
                }
                else
                {
                    SSF_ASSERT(result == (char)c);
                }
            }
        }
    }

    /* ---- SSFStrCharToUpper: exhaustive ---- */
    {
        /* Every lowercase letter maps to its uppercase equivalent */
        SSF_ASSERT(SSFStrCharToUpper('a') == 'A');
        SSF_ASSERT(SSFStrCharToUpper('b') == 'B');
        SSF_ASSERT(SSFStrCharToUpper('c') == 'C');
        SSF_ASSERT(SSFStrCharToUpper('d') == 'D');
        SSF_ASSERT(SSFStrCharToUpper('e') == 'E');
        SSF_ASSERT(SSFStrCharToUpper('f') == 'F');
        SSF_ASSERT(SSFStrCharToUpper('g') == 'G');
        SSF_ASSERT(SSFStrCharToUpper('h') == 'H');
        SSF_ASSERT(SSFStrCharToUpper('i') == 'I');
        SSF_ASSERT(SSFStrCharToUpper('j') == 'J');
        SSF_ASSERT(SSFStrCharToUpper('k') == 'K');
        SSF_ASSERT(SSFStrCharToUpper('l') == 'L');
        SSF_ASSERT(SSFStrCharToUpper('m') == 'M');
        SSF_ASSERT(SSFStrCharToUpper('n') == 'N');
        SSF_ASSERT(SSFStrCharToUpper('o') == 'O');
        SSF_ASSERT(SSFStrCharToUpper('p') == 'P');
        SSF_ASSERT(SSFStrCharToUpper('q') == 'Q');
        SSF_ASSERT(SSFStrCharToUpper('r') == 'R');
        SSF_ASSERT(SSFStrCharToUpper('s') == 'S');
        SSF_ASSERT(SSFStrCharToUpper('t') == 'T');
        SSF_ASSERT(SSFStrCharToUpper('u') == 'U');
        SSF_ASSERT(SSFStrCharToUpper('v') == 'V');
        SSF_ASSERT(SSFStrCharToUpper('w') == 'W');
        SSF_ASSERT(SSFStrCharToUpper('x') == 'X');
        SSF_ASSERT(SSFStrCharToUpper('y') == 'Y');
        SSF_ASSERT(SSFStrCharToUpper('z') == 'Z');

        /* Every uppercase letter is unchanged */
        SSF_ASSERT(SSFStrCharToUpper('A') == 'A');
        SSF_ASSERT(SSFStrCharToUpper('B') == 'B');
        SSF_ASSERT(SSFStrCharToUpper('M') == 'M');
        SSF_ASSERT(SSFStrCharToUpper('Z') == 'Z');

        /* Every digit is unchanged */
        SSF_ASSERT(SSFStrCharToUpper('0') == '0');
        SSF_ASSERT(SSFStrCharToUpper('1') == '1');
        SSF_ASSERT(SSFStrCharToUpper('5') == '5');
        SSF_ASSERT(SSFStrCharToUpper('9') == '9');

        /* Common symbols and whitespace unchanged */
        SSF_ASSERT(SSFStrCharToUpper(' ') == ' ');
        SSF_ASSERT(SSFStrCharToUpper('\t') == '\t');
        SSF_ASSERT(SSFStrCharToUpper('\n') == '\n');
        SSF_ASSERT(SSFStrCharToUpper('\r') == '\r');
        SSF_ASSERT(SSFStrCharToUpper('\0') == '\0');
        SSF_ASSERT(SSFStrCharToUpper('!') == '!');
        SSF_ASSERT(SSFStrCharToUpper('@') == '@');
        SSF_ASSERT(SSFStrCharToUpper('[') == '[');
        SSF_ASSERT(SSFStrCharToUpper('{') == '{');
        SSF_ASSERT(SSFStrCharToUpper('~') == '~');
        SSF_ASSERT(SSFStrCharToUpper('/') == '/');
        SSF_ASSERT(SSFStrCharToUpper('-') == '-');
        SSF_ASSERT(SSFStrCharToUpper('_') == '_');
        SSF_ASSERT(SSFStrCharToUpper('.') == '.');

        /* Boundary chars adjacent to a-z range are unchanged */
        SSF_ASSERT(SSFStrCharToUpper('`') == '`');  /* 0x60, one before 'a' */
        SSF_ASSERT(SSFStrCharToUpper('{') == '{');  /* 0x7B, one after 'z' */

        /* Full 0-255 sweep: every char either converts or is unchanged */
        {
            int c;
            for (c = 0; c < 256; c++)
            {
                char result = SSFStrCharToUpper((char)c);
                if (c >= 'a' && c <= 'z')
                {
                    SSF_ASSERT(result == (char)(c - ('a' - 'A')));
                }
                else
                {
                    SSF_ASSERT(result == (char)c);
                }
            }
        }
    }

    /* ---- SSFStrCharToLower/ToUpper round-trip ---- */
    {
        int c;
        for (c = 0; c < 256; c++)
        {
            /* Lower then upper of any alpha char returns the uppercase original */
            if (c >= 'A' && c <= 'Z')
            {
                SSF_ASSERT(SSFStrCharToUpper(SSFStrCharToLower((char)c)) == (char)c);
            }
            /* Upper then lower of any alpha char returns the lowercase original */
            if (c >= 'a' && c <= 'z')
            {
                SSF_ASSERT(SSFStrCharToLower(SSFStrCharToUpper((char)c)) == (char)c);
            }
            /* Non-alpha chars survive both directions unchanged */
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
            {
                SSF_ASSERT(SSFStrCharToLower((char)c) == (char)c);
                SSF_ASSERT(SSFStrCharToUpper((char)c) == (char)c);
            }
        }
    }

    /* SSFStrStr: post-mismatch reset path where remaining haystack is exactly 1 byte and the   */
    /* match has not been found. Existing tests pass null-terminated haystacks so the loop      */
    /* exits via *cstr == 0 before reaching the cstrSize <= 1 check at ssfstr.c:262. Pass an    */
    /* unterminated 2-char buffer that mismatches throughout: after one iteration cstrSize is   */
    /* 1, no terminator seen, and the next iter trips the explicit reject.                       */
    /* The function early-returns at line 262 without writing matchStrOptOut, so just confirm   */
    /* the return value -- testing matchOut here would observe stack garbage.                    */
    SSF_ASSERT(SSFStrStr("xx", 2, NULL, "abc", 4) == false);
}
#endif /* SSF_CONFIG_STR_UNIT_TEST */

