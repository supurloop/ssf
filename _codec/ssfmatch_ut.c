/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmatch_ut.c                                                                                 */
/* Provides unit tests for ssfmatch's pattern matching interface.                                */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
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
#include "ssfmatch.h"
#include "ssfport.h"

#if SSF_CONFIG_MATCH_UNIT_TEST == 1

/* --------------------------------------------------------------------------------------------- */
/* Returns true if s matches glob p by plain recursion; a reference for tiny exhaustive inputs.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFMatchUTGlobRef(const char *p, const char *s, bool ci)
{
    char a;
    char b;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(s != NULL);

    if (*p == '\0') return (*s == '\0');
    if (*p == '*')
    {
        return (_SSFMatchUTGlobRef(p + 1, s, ci) ||
                ((*s != '\0') && _SSFMatchUTGlobRef(p, s + 1, ci)));
    }
    if (*s == '\0') return false;
    a = *p;
    b = *s;
    /* Is the match case-insensitive and is the pattern char upper case? */
    if (ci && (a >= 'A') && (a <= 'Z'))
    {
        /* Yes, fold it to lower case */
        a = (char)(a + ('a' - 'A'));
    }
    /* Is the match case-insensitive and is the subject char upper case? */
    if (ci && (b >= 'A') && (b <= 'Z'))
    {
        /* Yes, fold it to lower case */
        b = (char)(b + ('a' - 'A'));
    }
    /* Is the pattern char a literal that differs from the subject char? */
    if ((*p != '?') && (a != b))
    {
        /* Yes, mismatch */
        return false;
    }
    return _SSFMatchUTGlobRef(p + 1, s + 1, ci);
}

void SSFMatchUnitTest(void)
{
    SSFMatchParam_t params[4];
    uint32_t numParams;

    /* ---- Assert tests ---- */
    SSF_ASSERT_TEST(SSFMatchStrI(NULL, "test"));
    SSF_ASSERT_TEST(SSFMatchStrI("test", NULL));
    SSF_ASSERT_TEST(SSFMatchStrNI(NULL, "test", 4));
    SSF_ASSERT_TEST(SSFMatchStrNI("test", NULL, 4));
    SSF_ASSERT_TEST(SSFMatchGlob(NULL, "test"));
    SSF_ASSERT_TEST(SSFMatchGlob("test", NULL));
    SSF_ASSERT_TEST(SSFMatchGlobI(NULL, "test"));
    SSF_ASSERT_TEST(SSFMatchGlobI("test", NULL));
    SSF_ASSERT_TEST(SSFMatchPath(NULL, "/test", params, 4, &numParams));
    SSF_ASSERT_TEST(SSFMatchPath("/test", NULL, params, 4, &numParams));
    SSF_ASSERT_TEST(SSFMatchPath("/test", "/test", params, 4, NULL));
    /* A NULL params array is only allowed when its size is 0 */
    SSF_ASSERT_TEST(SSFMatchPath("/test", "/test", NULL, 4, &numParams));
    SSF_ASSERT_TEST(SSFMatchPath("/test", "/test", NULL, 1, &numParams));

    /* ---- SSFMatchStrI ---- */
    SSF_ASSERT(SSFMatchStrI("hello", "hello") == true);
    SSF_ASSERT(SSFMatchStrI("Hello", "hello") == true);
    SSF_ASSERT(SSFMatchStrI("HELLO", "hello") == true);
    SSF_ASSERT(SSFMatchStrI("HeLLo", "hEllO") == true);
    SSF_ASSERT(SSFMatchStrI("hello", "world") == false);
    SSF_ASSERT(SSFMatchStrI("hello", "hell") == false);
    SSF_ASSERT(SSFMatchStrI("hell", "hello") == false);
    SSF_ASSERT(SSFMatchStrI("", "") == true);
    SSF_ASSERT(SSFMatchStrI("a", "") == false);
    SSF_ASSERT(SSFMatchStrI("Content-Type", "content-type") == true);
    SSF_ASSERT(SSFMatchStrI("device.LOCAL", "DEVICE.local") == true);
    SSF_ASSERT(SSFMatchStrI("", "a") == false);

    /* Only ASCII A-Z folds: these pairs differ only in bit 5 and must not compare equal */
    SSF_ASSERT(SSFMatchStrI("[", "{") == false);
    SSF_ASSERT(SSFMatchStrI("@", "`") == false);
    SSF_ASSERT(SSFMatchStrI("a[b", "A{B") == false);
    SSF_ASSERT(SSFMatchStrI("^", "~") == false);

    /* Non-ASCII bytes are compared literally, never folded */
    {
        const char *hi1 = "\xC3\x89";   /* UTF-8 U+00C9 */
        const char *hi2 = "\xC3\xA9";   /* UTF-8 U+00E9 */
        SSF_ASSERT(SSFMatchStrI(hi1, hi1) == true);
        SSF_ASSERT(SSFMatchStrI(hi1, hi2) == false);
        SSF_ASSERT(SSFMatchStrNI(hi1, hi2, 2u) == false);
    }

    /* ---- SSFMatchStrNI ---- */
    SSF_ASSERT(SSFMatchStrNI("hello", "HELLO", 5) == true);
    SSF_ASSERT(SSFMatchStrNI("hello", "HELLX", 4) == true);
    SSF_ASSERT(SSFMatchStrNI("hello", "HELLX", 5) == false);
    SSF_ASSERT(SSFMatchStrNI("abc", "ABC", 0) == true);

    /* POSIX strncasecmp semantics: stop at the first terminator, never read past it */
    {
        char a[10] = { 'h','e','l','l','o', 0, 'A','A','A','A' };
        char b[10] = { 'h','e','l','l','o', 0, 'B','B','B','B' };
        /* Both end at position 5 with equal prefix, bytes after the terminator are ignored */
        SSF_ASSERT(SSFMatchStrNI(a, b, 10u) == true);
    }
    /* C-strings shorter than len still compare correctly when equal. */
    SSF_ASSERT(SSFMatchStrNI("abc", "abc", 10u) == true);
    SSF_ASSERT(SSFMatchStrNI("abc", "ABC", 10u) == true);
    /* One terminator before the other -> different lengths, not equal. */
    SSF_ASSERT(SSFMatchStrNI("ab",  "abc", 3u)  == false);
    SSF_ASSERT(SSFMatchStrNI("abc", "ab",  3u)  == false);

    /* Prefix compare: one string ends at len, other continues (x509 SAN/name constraints) */
    SSF_ASSERT(SSFMatchStrNI("abc", "abcd", 3u) == true);
    SSF_ASSERT(SSFMatchStrNI("abcd", "abc", 3u) == true);
    SSF_ASSERT(SSFMatchStrNI("abc", "abcd", 4u) == false);
    SSF_ASSERT(SSFMatchStrNI("abcd", "abc", 4u) == false);

    /* Mismatch on the first char with len 1; both empty with len > 0 */
    SSF_ASSERT(SSFMatchStrNI("a", "b", 1u) == false);
    SSF_ASSERT(SSFMatchStrNI("a", "B", 1u) == false);
    SSF_ASSERT(SSFMatchStrNI("", "", 5u) == true);
    SSF_ASSERT(SSFMatchStrNI("", "a", 5u) == false);
    SSF_ASSERT(SSFMatchStrNI("a", "", 5u) == false);

    /* Bit-5 pairs that are not letters must not fold */
    SSF_ASSERT(SSFMatchStrNI("[", "{", 1u) == false);
    SSF_ASSERT(SSFMatchStrNI("host@", "HOST`", 5u) == false);

    /* Unterminated buffers compare exactly len bytes, as the x509 SAN matcher uses it on DER */
    {
        char der[4] = { 'E', 'x', 'A', 'M' };
        SSF_ASSERT(SSFMatchStrNI(der, "exam", 4u) == true);
        SSF_ASSERT(SSFMatchStrNI("EXAM", der, 4u) == true);
        SSF_ASSERT(SSFMatchStrNI(der, "exan", 4u) == false);
        SSF_ASSERT(SSFMatchStrNI(der, "exa", 4u) == false);
    }

    /* ---- SSFMatchGlob ---- */
    /* Exact match */
    SSF_ASSERT(SSFMatchGlob("hello", "hello") == true);
    SSF_ASSERT(SSFMatchGlob("hello", "world") == false);

    /* ? matches single char */
    SSF_ASSERT(SSFMatchGlob("h?llo", "hello") == true);
    SSF_ASSERT(SSFMatchGlob("h?llo", "hallo") == true);
    SSF_ASSERT(SSFMatchGlob("h?llo", "hllo") == false);
    SSF_ASSERT(SSFMatchGlob("???", "abc") == true);
    SSF_ASSERT(SSFMatchGlob("???", "ab") == false);
    SSF_ASSERT(SSFMatchGlob("???", "abcd") == false);

    /* * matches any sequence */
    SSF_ASSERT(SSFMatchGlob("*", "anything") == true);
    SSF_ASSERT(SSFMatchGlob("*", "") == true);
    SSF_ASSERT(SSFMatchGlob("hello*", "hello") == true);
    SSF_ASSERT(SSFMatchGlob("hello*", "helloworld") == true);
    SSF_ASSERT(SSFMatchGlob("*world", "helloworld") == true);
    SSF_ASSERT(SSFMatchGlob("*world", "world") == true);
    SSF_ASSERT(SSFMatchGlob("*world", "worldx") == false);
    SSF_ASSERT(SSFMatchGlob("h*o", "ho") == true);
    SSF_ASSERT(SSFMatchGlob("h*o", "hello") == true);
    SSF_ASSERT(SSFMatchGlob("h*o", "helloworld") == false);

    /* Combined */
    SSF_ASSERT(SSFMatchGlob("*.txt", "file.txt") == true);
    SSF_ASSERT(SSFMatchGlob("*.txt", "file.doc") == false);
    SSF_ASSERT(SSFMatchGlob("test_?.*", "test_1.c") == true);
    SSF_ASSERT(SSFMatchGlob("test_?.*", "test_12.c") == false);
    SSF_ASSERT(SSFMatchGlob("**", "anything") == true);

    /* Empty patterns */
    SSF_ASSERT(SSFMatchGlob("", "") == true);
    SSF_ASSERT(SSFMatchGlob("", "x") == false);

    /* Case sensitive */
    SSF_ASSERT(SSFMatchGlob("Hello", "hello") == false);
    SSF_ASSERT(SSFMatchGlob("Hello", "Hello") == true);

    /* Literal pattern and string of different lengths */
    SSF_ASSERT(SSFMatchGlob("hello", "hell") == false);
    SSF_ASSERT(SSFMatchGlob("hell", "hello") == false);
    SSF_ASSERT(SSFMatchGlob("ab*", "ac") == false);

    /* Backtracking: '*' must retry after a partial literal match further along */
    SSF_ASSERT(SSFMatchGlob("*abc", "ababc") == true);
    SSF_ASSERT(SSFMatchGlob("*abc", "abab") == false);
    SSF_ASSERT(SSFMatchGlob("a*z", "abc") == false);
    SSF_ASSERT(SSFMatchGlob("*a*b", "xaxbxab") == true);
    SSF_ASSERT(SSFMatchGlob("*a*b", "xaxbxa") == false);
    SSF_ASSERT(SSFMatchGlob("a*b*c", "abbc") == true);
    SSF_ASSERT(SSFMatchGlob("a*b*c", "acb") == false);
    SSF_ASSERT(SSFMatchGlob("*ab*ab", "abab") == true);
    SSF_ASSERT(SSFMatchGlob("*ab*ab", "aba") == false);

    /* '?' after a '*' that has consumed the rest of the string */
    SSF_ASSERT(SSFMatchGlob("*?", "") == false);
    SSF_ASSERT(SSFMatchGlob("*?", "a") == true);
    SSF_ASSERT(SSFMatchGlob("?*", "") == false);
    SSF_ASSERT(SSFMatchGlob("?*", "a") == true);
    SSF_ASSERT(SSFMatchGlob("*a", "") == false);
    SSF_ASSERT(SSFMatchGlob("a*", "") == false);
    SSF_ASSERT(SSFMatchGlob("*??", "a") == false);
    SSF_ASSERT(SSFMatchGlob("*??", "ab") == true);
    SSF_ASSERT(SSFMatchGlob("*??", "abc") == true);
    SSF_ASSERT(SSFMatchGlob("*?*", "") == false);
    SSF_ASSERT(SSFMatchGlob("*?*", "abc") == true);
    SSF_ASSERT(SSFMatchGlob("?*?", "a") == false);
    SSF_ASSERT(SSFMatchGlob("?*?", "ab") == true);

    /* No bracket expressions or escapes: '[', ']' and '\' are ordinary literals */
    SSF_ASSERT(SSFMatchGlob("[a]", "[a]") == true);
    SSF_ASSERT(SSFMatchGlob("[a]", "a") == false);
    SSF_ASSERT(SSFMatchGlob("[!a]", "b") == false);
    /* '\' literal then '*' wildcard */
    SSF_ASSERT(SSFMatchGlob("\\*", "\\x") == true);
    /* '\' does not escape the '*' */
    SSF_ASSERT(SSFMatchGlob("\\*", "*") == false);
    /* '?' still needs one char */
    SSF_ASSERT(SSFMatchGlob("\\?", "\\") == false);
    SSF_ASSERT(SSFMatchGlob("\\?", "\\\\") == true);

    /* '*' and '?' in the string are ordinary characters */
    SSF_ASSERT(SSFMatchGlob("a?c", "a*c") == true);
    SSF_ASSERT(SSFMatchGlob("a?c", "a?c") == true);
    SSF_ASSERT(SSFMatchGlob("abc", "a*c") == false);
    SSF_ASSERT(SSFMatchGlob("a*c", "a?c") == true);

    /* Non-ASCII bytes match literally and count as individual chars */
    {
        const char *hi1 = "\xC3\x89";
        const char *hi2 = "\xC3\xA9";
        SSF_ASSERT(SSFMatchGlob(hi1, hi1) == true);
        SSF_ASSERT(SSFMatchGlob(hi1, hi2) == false);
        SSF_ASSERT(SSFMatchGlobI(hi1, hi2) == false);
        SSF_ASSERT(SSFMatchGlob("?", hi1) == false);
        SSF_ASSERT(SSFMatchGlob("??", hi1) == true);
        SSF_ASSERT(SSFMatchGlob("*", hi1) == true);
    }

    /* ---- SSFMatchGlobI ---- */
    SSF_ASSERT(SSFMatchGlobI("Hello", "hello") == true);
    SSF_ASSERT(SSFMatchGlobI("H*O", "hello") == true);
    SSF_ASSERT(SSFMatchGlobI("*.TXT", "file.txt") == true);

    /* Negative cases: the I variant must still reject real mismatches */
    SSF_ASSERT(SSFMatchGlobI("Hello", "world") == false);
    SSF_ASSERT(SSFMatchGlobI("h?llo", "hllo") == false);
    SSF_ASSERT(SSFMatchGlobI("*.TXT", "file.doc") == false);
    SSF_ASSERT(SSFMatchGlobI("hello", "hell") == false);
    SSF_ASSERT(SSFMatchGlobI("", "x") == false);
    SSF_ASSERT(SSFMatchGlobI("", "") == true);

    /* Mixed case on both sides, with wildcards and backtracking under folding */
    SSF_ASSERT(SSFMatchGlobI("hElLo*", "HELLOworld") == true);
    SSF_ASSERT(SSFMatchGlobI("*ABC", "xaBabC") == true);
    SSF_ASSERT(SSFMatchGlobI("*ABC", "xaBab") == false);
    SSF_ASSERT(SSFMatchGlobI("A?C", "a-C") == true);
    SSF_ASSERT(SSFMatchGlobI("[A]", "[a]") == true);

    /* Folding is letters only: bit-5 pairs that are not letters stay distinct */
    SSF_ASSERT(SSFMatchGlobI("[", "{") == false);
    SSF_ASSERT(SSFMatchGlobI("a@b", "A`B") == false);
    SSF_ASSERT(SSFMatchGlobI("*@", "x`") == false);

    /* ---- AUDIT MATCH-2: glob has no '*' cap and runs in O(len * patLen) time ---- */
    {
        static char big[4097];
        static char pat[64];
        static const char patAlpha[] = { 'a', 'b', '*', '?', 'A' };
        static const char strAlpha[] = { 'a', 'b', 'A' };
        char sp[8];
        char ss[8];
        uint32_t i;
        uint32_t k;
        uint32_t pl;
        uint32_t sl;
        uint32_t pCount;
        uint32_t sCount;
        uint32_t pCode;
        uint32_t sCode;
        uint32_t digits;

        /* Five or more '*' runs match (the removed cap refused these) */
        SSF_ASSERT(SSFMatchGlob("*a*b*c*d*e", "abcde") == true);
        SSF_ASSERT(SSFMatchGlobI("*A*B*C*D*E", "xaxbxcxdxe") == true);
        SSF_ASSERT(SSFMatchGlobI("*A*B*C*D*E", "xaxbxcxdxex") == false);
        SSF_ASSERT(SSFMatchGlob("*a*b*c*d*e", "abcd") == false);
        for (i = 0; i < 20u; i++)
        {
            pat[(2u * i)] = '*';
            pat[(2u * i) + 1u] = '?';
        }
        pat[40] = '\0';
        SSF_ASSERT(SSFMatchGlob(pat, "abcdefghijklmnopqrst") == true);
        SSF_ASSERT(SSFMatchGlob(pat, "abcdefghijklmnopqrs") == false);

        /* Near-miss subjects that took the recursive matcher minutes finish immediately */
        memset(big, 'a', sizeof(big) - 1u);
        big[sizeof(big) - 1u] = '\0';
        SSF_ASSERT(SSFMatchGlob("*a*a*a*b", big) == false);
        SSF_ASSERT(SSFMatchGlobI("*a*a*a*a*a*a*a*a*a*a*b", big) == false);
        SSF_ASSERT(SSFMatchGlob("*a*a*a*a*a*a*a*a*a*a*a", big) == true);
        big[sizeof(big) - 2u] = 'b';
        SSF_ASSERT(SSFMatchGlob("*a*a*a*b", big) == true);
        SSF_ASSERT(SSFMatchGlob("*a*a*a*bb", big) == false);

        /* Exhaustive vs reference: patterns <= 4 chars of a,b,*,?,A; subjects <= 4 of a,b,A */
        for (pl = 0; pl <= 4u; pl++)
        {
            pCount = 1u;
            for (k = 0; k < pl; k++) pCount *= 5u;
            for (pCode = 0; pCode < pCount; pCode++)
            {
                digits = pCode;
                for (k = 0; k < pl; k++)
                {
                    sp[k] = patAlpha[digits % 5u];
                    digits /= 5u;
                }
                sp[pl] = '\0';
                for (sl = 0; sl <= 4u; sl++)
                {
                    sCount = 1u;
                    for (k = 0; k < sl; k++) sCount *= 3u;
                    for (sCode = 0; sCode < sCount; sCode++)
                    {
                        digits = sCode;
                        for (k = 0; k < sl; k++)
                        {
                            ss[k] = strAlpha[digits % 3u];
                            digits /= 3u;
                        }
                        ss[sl] = '\0';
                        SSF_ASSERT(SSFMatchGlob(sp, ss) == _SSFMatchUTGlobRef(sp, ss, false));
                        SSF_ASSERT(SSFMatchGlobI(sp, ss) == _SSFMatchUTGlobRef(sp, ss, true));
                    }
                }
            }
        }
    }

    /* ---- SSFMatchPath ---- */
    /* Exact match */
    SSF_ASSERT(SSFMatchPath("/api/status", "/api/status", params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 0);

    /* Mismatch */
    SSF_ASSERT(SSFMatchPath("/api/status", "/api/config", params, 4, &numParams) == false);

    /* Single param */
    SSF_ASSERT(SSFMatchPath("/api/sensors/{id}", "/api/sensors/42", params, 4,
               &numParams) == true);
    SSF_ASSERT(numParams == 1);
    SSF_ASSERT(params[0].nameLen == 2);
    SSF_ASSERT(params[0].name[0] == 'i' && params[0].name[1] == 'd');
    SSF_ASSERT(params[0].valueLen == 2);
    SSF_ASSERT(params[0].value[0] == '4' && params[0].value[1] == '2');

    /* Multiple params */
    SSF_ASSERT(SSFMatchPath("/api/{ver}/sensors/{id}", "/api/v1/sensors/7", params, 4,
               &numParams) == true);
    SSF_ASSERT(numParams == 2);
    SSF_ASSERT(params[0].valueLen == 2);
    SSF_ASSERT(params[0].value[0] == 'v' && params[0].value[1] == '1');
    SSF_ASSERT(params[1].valueLen == 1);
    SSF_ASSERT(params[1].value[0] == '7');

    /* Trailing query string */
    SSF_ASSERT(SSFMatchPath("/api/sensors", "/api/sensors?limit=10", params, 4,
               &numParams) == true);
    SSF_ASSERT(numParams == 0);

    /* Path too short */
    SSF_ASSERT(SSFMatchPath("/api/sensors/{id}", "/api/sensors", params, 4,
               &numParams) == false);

    /* Path too long */
    SSF_ASSERT(SSFMatchPath("/api/sensors", "/api/sensors/42", params, 4,
               &numParams) == false);

    /* No output params (just match) */
    SSF_ASSERT(SSFMatchPath("/api/{id}", "/api/1", NULL, 0, &numParams) == true);
    SSF_ASSERT(numParams == 1);

    /* Empty placeholder name '{}' is malformed - reject. */
    SSF_ASSERT(SSFMatchPath("{}",        "x",       params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/api/{}",   "/api/42", params, 4, &numParams) == false);
    /* Single-character name is still valid. */
    SSF_ASSERT(SSFMatchPath("/{a}",      "/1",      params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u);
    SSF_ASSERT(params[0].nameLen == 1u && params[0].name[0] == 'a');

    /* A placeholder binds one non-empty segment: an empty value is a mismatch in every position */
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/",          params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/?x=1",      params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/?",         params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id}/b",   "/a//b",        params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/{x}/{y}",    "/1//",         params, 4, &numParams) == false);
    /* Non-empty values in the same positions still match */
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/7?x=1",     params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 1u && params[0].value[0] == '7');
    SSF_ASSERT(SSFMatchPath("/a/{id}/b",   "/a/7/b",       params, 4, &numParams) == true);

    /* RFC 3986 Sec. 3.3: '#' always starts the fragment, so it ends matching exactly like '?' */
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/42#frag",   params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 2u);
    SSF_ASSERT(params[0].value[0] == '4' && params[0].value[1] == '2');
    SSF_ASSERT(SSFMatchPath("/a",          "/a#x",         params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 0u);
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/#frag",     params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/7?x=1#f",   params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 1u);

    /* Failure contract: *numParamsOut is 0 after every false return; literal mismatch */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/b/1",         params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);
    /* Path too short */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id}/{x}", "/a/1",         params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);
    /* Path too long */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/1/2",       params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);
    /* Unterminated placeholder */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id",      "/a/1",         params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);
    /* Empty placeholder name */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{}",       "/a/1",         params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);
    /* Empty value */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/",          params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);
    /* Unterminated placeholder never reached */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id",      "/a/",          params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);
    /* Query reached with pattern left over */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/b",        "/a?x",         params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);
    /* Literal left over after placeholder */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/{n}.json",   "/foo.json",    params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);

    /* Overflow: match succeeds, all counted, first paramsOutOptSize stored, rest untouched */
    {
        SSFMatchParam_t few[3];
        SSFCStrIn_t sentinel = "sentinel";

        few[2].name = sentinel;
        few[2].nameLen = 0xDEADu;
        few[2].value = sentinel;
        few[2].valueLen = 0xBEEFu;
        SSF_ASSERT(SSFMatchPath("/{a}/{b}/{c}", "/1/2/3", few, 2, &numParams) == true);
        SSF_ASSERT(numParams == 3u);
        /* This is how a caller detects overflow */
        SSF_ASSERT(numParams > 2u);
        SSF_ASSERT(few[0].nameLen == 1u && few[0].name[0] == 'a');
        SSF_ASSERT(few[0].valueLen == 1u && few[0].value[0] == '1');
        SSF_ASSERT(few[1].nameLen == 1u && few[1].name[0] == 'b');
        SSF_ASSERT(few[1].valueLen == 1u && few[1].value[0] == '2');
        SSF_ASSERT(few[2].name == sentinel && few[2].nameLen == 0xDEADu);
        SSF_ASSERT(few[2].value == sentinel && few[2].valueLen == 0xBEEFu);

        /* Size 1 stores only the first */
        few[1].name = sentinel;
        few[1].nameLen = 0xDEADu;
        few[1].value = sentinel;
        few[1].valueLen = 0xBEEFu;
        SSF_ASSERT(SSFMatchPath("/{a}/{b}/{c}", "/1/2/3", few, 1, &numParams) == true);
        SSF_ASSERT(numParams == 3u);
        SSF_ASSERT(few[0].valueLen == 1u && few[0].value[0] == '1');
        SSF_ASSERT(few[1].name == sentinel && few[1].nameLen == 0xDEADu);
        SSF_ASSERT(few[1].value == sentinel && few[1].valueLen == 0xBEEFu);

        /* Size 0 with NULL counts everything */
        SSF_ASSERT(SSFMatchPath("/{a}/{b}/{c}", "/1/2/3", NULL, 0, &numParams) == true);
        SSF_ASSERT(numParams == 3u);

        /* An overflowed placeholder is still validated: empty value fails, count is zeroed */
        numParams = 99u;
        SSF_ASSERT(SSFMatchPath("/{a}/{b}/{c}", "/1/2/", few, 2, &numParams) == false);
        SSF_ASSERT(numParams == 0u);
        numParams = 99u;
        SSF_ASSERT(SSFMatchPath("/{a}/{b}/{}", "/1/2/3", few, 2, &numParams) == false);
        SSF_ASSERT(numParams == 0u);
        numParams = 99u;
        SSF_ASSERT(SSFMatchPath("/{a}/{b}/{c", "/1/2/3", NULL, 0, &numParams) == false);
        SSF_ASSERT(numParams == 0u);
    }

    /* Zero-copy: names point into the pattern string, values into the path string */
    {
        const char *pat = "/api/{ver}/sensors/{id}";
        const char *path = "/api/v1/sensors/7";

        SSF_ASSERT(SSFMatchPath(pat, path, params, 4, &numParams) == true);
        SSF_ASSERT(numParams == 2u);
        SSF_ASSERT(params[0].name == &pat[6]);
        SSF_ASSERT(params[0].nameLen == 3u);
        SSF_ASSERT(params[0].name[0] == 'v' && params[0].name[1] == 'e');
        SSF_ASSERT(params[0].name[2] == 'r');
        SSF_ASSERT(params[0].value == &path[5]);
        SSF_ASSERT(params[0].valueLen == 2u);
        SSF_ASSERT(params[1].name == &pat[20]);
        SSF_ASSERT(params[1].nameLen == 2u);
        SSF_ASSERT(params[1].name[0] == 'i' && params[1].name[1] == 'd');
        SSF_ASSERT(params[1].value == &path[16]);
        SSF_ASSERT(params[1].valueLen == 1u);

        /* Long names and values are bound in full */
        pat = "/{averyveryverylongparametername}";
        path = "/0123456789abcdefghijklmnopqrstuvwxyz";
        SSF_ASSERT(SSFMatchPath(pat, path, params, 4, &numParams) == true);
        SSF_ASSERT(numParams == 1u);
        SSF_ASSERT(params[0].name == &pat[2] && params[0].nameLen == 30u);
        SSF_ASSERT(params[0].value == &path[1] && params[0].valueLen == 36u);
    }

    /* Byte-literal: no percent-decoding, and literals are case-sensitive */
    SSF_ASSERT(SSFMatchPath("/{a}",        "/%2F",         params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 3u && params[0].value[0] == '%');
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/x.y-z~1_2%20", params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 12u);
    SSF_ASSERT(SSFMatchPath("/API",        "/api",         params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/A/1",         params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/%2F",        "/%2f",         params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/%2F",        "/%2F",         params, 4, &numParams) == true);

    /* '{' and '}' are only special in the pattern; a value may contain them */
    SSF_ASSERT(SSFMatchPath("/{a}",        "/{x}",         params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 3u && params[0].value[0] == '{');
    /* A '}' with no opening '{' is a pattern literal */
    SSF_ASSERT(SSFMatchPath("/a}",         "/a}",          params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 0u);
    SSF_ASSERT(SSFMatchPath("/a}",         "/a",           params, 4, &numParams) == false);
    /* The value swallows a following '}' so the extra pattern literal is left unmatched */
    SSF_ASSERT(SSFMatchPath("/{a}}",       "/x}",          params, 4, &numParams) == false);

    /* Empty pattern and empty path */
    SSF_ASSERT(SSFMatchPath("",            "",             params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 0u);
    SSF_ASSERT(SSFMatchPath("",            "?x=1",         params, 4, &numParams) == true);
    SSF_ASSERT(SSFMatchPath("",            "#f",           params, 4, &numParams) == true);
    SSF_ASSERT(SSFMatchPath("",            "/",            params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("",            "a",            params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/",           "",             params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/",           "/",            params, 4, &numParams) == true);
    SSF_ASSERT(SSFMatchPath("/",           "/?",           params, 4, &numParams) == true);
    SSF_ASSERT(SSFMatchPath("a",           "",             params, 4, &numParams) == false);

    /* Placeholder at the very start of the pattern */
    SSF_ASSERT(SSFMatchPath("{a}",         "",             params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("{a}",         "?x",           params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("{a}",         "x",            params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 1u && params[0].value[0] == 'x');
    SSF_ASSERT(SSFMatchPath("{a}",         "xyz?q",        params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 3u);
    SSF_ASSERT(SSFMatchPath("{a}/b",       "x/b",          params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 1u);
    SSF_ASSERT(SSFMatchPath("{a}/b",       "/b",           params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("{a}/{b}",     "x/y",          params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 2u);

    /* Placeholder binds the whole segment: literal text after it never matches, before can */
    SSF_ASSERT(SSFMatchPath("/{n}.json",   "/foo.json",    params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/{a}-{b}",    "/1-2",         params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/{a}{b}",     "/12",          params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/{a}/x",      "/1x",          params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/file{ext}",  "/filetxt",     params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 3u && params[0].value[0] == 't');
    SSF_ASSERT(SSFMatchPath("/file{ext}",  "/file",        params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/file{ext}",  "/file/txt",    params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/v{n}/{id}",  "/v1/7",        params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 2u && params[0].valueLen == 1u && params[0].value[0] == '1');

    /* Bare '?' or '#' terminators and trailing slashes */
    SSF_ASSERT(SSFMatchPath("/a",          "/a?",          params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 0u);
    SSF_ASSERT(SSFMatchPath("/a",          "/a#",          params, 4, &numParams) == true);
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/7?",        params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 1u);
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/7#",        params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 1u && params[0].valueLen == 1u);
    SSF_ASSERT(SSFMatchPath("/a",          "/a/",          params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/",         "/a",           params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/",         "/a/",          params, 4, &numParams) == true);
    SSF_ASSERT(SSFMatchPath("/a/",         "/a/?x",        params, 4, &numParams) == true);
    SSF_ASSERT(SSFMatchPath("/a/",         "/a/#x",        params, 4, &numParams) == true);
    SSF_ASSERT(SSFMatchPath("/a/{id}/",    "/a/1/",        params, 4, &numParams) == true);
    SSF_ASSERT(SSFMatchPath("/a/{id}/",    "/a/1",         params, 4, &numParams) == false);

    /* '?' or '#' in the pattern is a literal and matches only itself */
    SSF_ASSERT(SSFMatchPath("/a?b",        "/a?b",         params, 4, &numParams) == true);
    SSF_ASSERT(SSFMatchPath("/a?b",        "/a",           params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a?b",        "/a?c",         params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a#b",        "/a#b",         params, 4, &numParams) == true);

    /* Query or fragment reached while the pattern still has segments left */
    SSF_ASSERT(SSFMatchPath("/a/b",        "/a?x",         params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a?x=1",       params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a#f",         params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id}/{x}", "/a/1?x",       params, 4, &numParams) == false);

    /* ---- AUDIT MATCH-5: a placeholder name holding '/', '{', '?' or '#' is malformed ---- */
    SSF_ASSERT(SSFMatchPath("/a/{id/{x}", "/a/7", params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);
    SSF_ASSERT(SSFMatchPath("/a/{id/b}", "/a/7", params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id{x}", "/a/7", params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id?}", "/a/7", params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id#}", "/a/7", params, 4, &numParams) == false);
    SSF_ASSERT(SSFMatchPath("/a/{id/x}", "/a/7", NULL, 0, &numParams) == false);
    /* Other name bytes are still accepted as is */
    SSF_ASSERT(SSFMatchPath("/a/{my-id_2.x}", "/a/7", params, 4, &numParams) == true);
    SSF_ASSERT((numParams == 1u) && (params[0].nameLen == 9u));
    SSF_ASSERT(SSFMatchPath("/a/{id}/{x}", "/a/7/8", params, 4, &numParams) == true);
    SSF_ASSERT(numParams == 2u);
}
#endif /* SSF_CONFIG_MATCH_UNIT_TEST */
