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
    int32_t len;

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
    SSF_ASSERT_TEST(SSFStrCat("dst", 4, NULL, "src", 4));
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

    /* Test SSFStrCpy() */
    SSF_ASSERT_TEST(SSFStrCpy(NULL, 4, &s1Len, "src", 4));
    SSF_ASSERT_TEST(SSFStrCpy("dst", 4, NULL, "src", 4));
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
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 6));
    SSF_ASSERT(SSFStrStr(check, 0, NULL, "substr", 7) == false);
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 0) == false);

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
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 6));
    SSF_ASSERT(matchStrOptOut == &check[0]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 0, &matchStrOptOut, "substr", 7) == false);
    SSF_ASSERT(matchStrOptOut == NULL);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 0) == false);
    SSF_ASSERT(matchStrOptOut == NULL);

    SSF_ASSERT(SSFStrCpy(check, sizeof(check), &s1Len, "stringsubstr", 13));
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 7));
    SSF_ASSERT(SSFStrStr(check, 14, NULL, "substr", 8));
    SSF_ASSERT(SSFStrStr(check, 12, NULL, "substr", 7));
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 6));
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
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 6));
    SSF_ASSERT(matchStrOptOut == &check[6]);
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
    SSF_ASSERT(SSFStrStr(check, 13, NULL, "substr", 6));
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
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 6));
    SSF_ASSERT(matchStrOptOut == &check[5]);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 0, &matchStrOptOut, "substr", 7) == false);
    SSF_ASSERT(matchStrOptOut == NULL);
    matchStrOptOut = "abc";
    SSF_ASSERT(SSFStrStr(check, 13, &matchStrOptOut, "substr", 0) == false);
    SSF_ASSERT(matchStrOptOut == NULL);

    /* Test SSFStrTok() */
    tok = NULL;
    SSF_ASSERT_TEST(SSFStrTok(NULL, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT_TEST(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    tok = dst;
    SSF_ASSERT_TEST(SSFStrTok(&tok, sizeof(dst), NULL, sizeof(check), &len, " ,", 3));
    SSF_ASSERT_TEST(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), NULL, " ,", 3));
    SSF_ASSERT_TEST(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, NULL, 3));

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "", 1));
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3) == false);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 0);
    SSF_ASSERT(memcmp("", check, 1) == 0);

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "", 1));
    SSF_ASSERT(SSFStrTok(&tok, 0, check, sizeof(check), &len, " ,", 3) == false);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 0);
    SSF_ASSERT(memcmp("", check, 1) == 0);

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "", 1));
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, 0, &len, " ,", 3) == false);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == -1);
    SSF_ASSERT(memcmp("", check, 1) == 0);

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "substsubstrr", 13));
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3) == false);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 12);
    SSF_ASSERT(memcmp("substsubstrr", check, 13) == 0);

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "subst,ubstrr", 13));
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[6]);
    SSF_ASSERT(len == 5);
    SSF_ASSERT(memcmp("subst", check, 6) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3) == false);
    SSF_ASSERT(tok == &dst[12]);
    SSF_ASSERT(len == 6);
    SSF_ASSERT(memcmp("ubstrr", check, 6) == 0);

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "subst ubstrr", 13));
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[6]);
    SSF_ASSERT(len == 5);
    SSF_ASSERT(memcmp("subst", check, 6) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3) == false);
    SSF_ASSERT(tok == &dst[12]);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 6);
    SSF_ASSERT(memcmp("ubstrr", check, 7) == 0);

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "subst!ubstrr", 13));
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3) == false);
    SSF_ASSERT(tok == &dst[12]);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 12);
    SSF_ASSERT(memcmp("subst!ubstrr", check, 13) == 0);

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, ",substubstr ", 13));
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[1]);
    SSF_ASSERT(*tok == 's');
    SSF_ASSERT(len == 0);
    SSF_ASSERT(memcmp("", check, 0) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[12]);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 10);
    SSF_ASSERT(memcmp("substubstr", check, 11) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3) == false);
    SSF_ASSERT(tok == &dst[12]);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 0);

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, ",", 2));
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[1]);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 0);
    SSF_ASSERT(memcmp("", check, 0) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3) == false);
    SSF_ASSERT(tok == &dst[1]);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 0);

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, ", ,", 4));
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[1]);
    SSF_ASSERT(*tok == ' ');
    SSF_ASSERT(len == 0);
    SSF_ASSERT(memcmp("", check, 0) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[2]);
    SSF_ASSERT(*tok == ',');
    SSF_ASSERT(len == 0);
    SSF_ASSERT(memcmp("", check, 0) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[3]);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 0);
    SSF_ASSERT(memcmp("", check, 0) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3) == false);
    SSF_ASSERT(tok == &dst[3]);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 0);

    tok = dst;
    SSF_ASSERT(SSFStrCpy(dst, sizeof(dst), &s1Len, "0,1 2,3", 8));
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[2]);
    SSF_ASSERT(*tok == '1');
    SSF_ASSERT(len == 1);
    SSF_ASSERT(memcmp("0", check, 0) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[4]);
    SSF_ASSERT(*tok == '2');
    SSF_ASSERT(len == 1);
    SSF_ASSERT(memcmp("1", check, 0) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3));
    SSF_ASSERT(tok == &dst[6]);
    SSF_ASSERT(*tok == '3');
    SSF_ASSERT(len == 1);
    SSF_ASSERT(memcmp("2", check, 0) == 0);
    SSF_ASSERT(SSFStrTok(&tok, sizeof(dst), check, sizeof(check), &len, " ,", 3) == false);
    SSF_ASSERT(tok == &dst[7]);
    SSF_ASSERT(*tok == 0);
    SSF_ASSERT(len == 1);
    SSF_ASSERT(memcmp("3", check, 0) == 0);
}
#endif /* SSF_CONFIG_STR_UNIT_TEST */

