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

    /* ---- SSFMatchGlobI ---- */
    SSF_ASSERT(SSFMatchGlobI("Hello", "hello") == true);
    SSF_ASSERT(SSFMatchGlobI("H*O", "hello") == true);
    SSF_ASSERT(SSFMatchGlobI("*.TXT", "file.txt") == true);

    /* ---- Glob wildcard limit: over SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS '*' runs fails ---- */
    {
        char pat[(3u * SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS) + 4u];
        char str[SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS + 2u];
        uint32_t i;
        size_t n;

        /* Exactly the limit matches */
        n = 0;
        for (i = 0; i < SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS; i++)
        {
            pat[n++] = '*';
            pat[n++] = 'a';
            str[i] = 'a';
        }
        pat[n] = '\0';
        str[SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS] = '\0';
        SSF_ASSERT(SSFMatchGlob(pat, str) == true);
        SSF_ASSERT(SSFMatchGlobI(pat, str) == true);

        /* A run of consecutive '*' counts as one wildcard, so this is still within the limit */
        n = 0;
        for (i = 0; i < SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS; i++)
        {
            pat[n++] = '*';
            pat[n++] = '*';
            pat[n++] = 'a';
        }
        pat[n] = '\0';
        SSF_ASSERT(SSFMatchGlob(pat, str) == true);

        /* One over the limit never matches, even though the pattern otherwise would */
        n = 0;
        for (i = 0; i <= SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS; i++)
        {
            pat[n++] = '*';
            pat[n++] = 'a';
            str[i] = 'a';
        }
        pat[n] = '\0';
        str[SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS + 1u] = '\0';
        SSF_ASSERT(SSFMatchGlob(pat, str) == false);
        SSF_ASSERT(SSFMatchGlobI(pat, str) == false);

        /* Over the limit with a trailing '*' is rejected before the trailing-star shortcut */
        pat[n - 1u] = '*';
        SSF_ASSERT(SSFMatchGlob(pat, str) == false);
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

    /* Failure contract: *numParamsOut is 0 after every false return */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/b/1",         params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);                                   /* literal mismatch */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id}/{x}", "/a/1",         params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);                                   /* path too short */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/1/2",       params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);                                   /* path too long */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id",      "/a/1",         params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);                                   /* unterminated placeholder */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{}",       "/a/1",         params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);                                   /* empty placeholder name */
    numParams = 99u;
    SSF_ASSERT(SSFMatchPath("/a/{id}",     "/a/",          params, 4, &numParams) == false);
    SSF_ASSERT(numParams == 0u);                                   /* empty value */
}
#endif /* SSF_CONFIG_MATCH_UNIT_TEST */
