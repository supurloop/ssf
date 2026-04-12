/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfargv_ut.c                                                                                  */
/* Provides unit test for command line string to gobj parser interface.                          */
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfll.h"
#include "ssfgobj.h"
#include "ssfargv.h"

#if SSF_CONFIG_ARGV_UNIT_TEST == 1

#define SSF_ARGV_UT_MAX_OPTS (4u)
#define SSF_ARGV_UT_MAX_ARGS (4u)
#define SSF_ARGV_UT_OUT_STR_SIZE (64u)

/* --------------------------------------------------------------------------------------------- */
/* Returns the cmd, opts or args child gobj for the supplied parsed root gobj.                   */
/* --------------------------------------------------------------------------------------------- */
static SSFGObj_t *_SSFArgvUTFindChild(SSFGObj_t *gobj, SSFCStrIn_t labelCStr)
{
    SSFGObj_t *gobjParent = NULL;
    SSFGObj_t *gobjChild = NULL;
    char *path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(labelCStr != NULL);

    memset(path, 0, sizeof(path));
    path[0] = (char *)labelCStr;
    if (SSFGObjFindPath(gobj, (SSFCStrIn_t *)path, &gobjParent, &gobjChild) == false) return NULL;
    return gobjChild;
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts that the parsed cmd string matches the supplied expected cmd string.                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFArgvUTCheckCmd(SSFGObj_t *gobj, SSFCStrIn_t expectedCmd)
{
    SSFGObj_t *gobjCmd;
    char outStr[SSF_ARGV_UT_OUT_STR_SIZE];

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(expectedCmd != NULL);

    gobjCmd = _SSFArgvUTFindChild(gobj, SSF_ARGV_CMD_STR);
    SSF_ASSERT(gobjCmd != NULL);
    SSF_ASSERT(SSFGObjGetType(gobjCmd) == SSF_OBJ_TYPE_STR);
    SSF_ASSERT(SSFGObjGetString(gobjCmd, outStr, sizeof(outStr)));
    SSF_ASSERT(strcmp(outStr, expectedCmd) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts that the parsed args array contains the supplied number of expected args in order.   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFArgvUTCheckArgs(SSFGObj_t *gobj, const char * const *expectedArgs,
                                size_t expectedNumArgs)
{
    SSFGObj_t *gobjArgs;
    SSFGObj_t *gobjArg;
    SSFGObj_t *gobjParent;
    char outStr[SSF_ARGV_UT_OUT_STR_SIZE];
    char *path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];
    size_t i;

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE((expectedArgs != NULL) || (expectedNumArgs == 0));

    gobjArgs = _SSFArgvUTFindChild(gobj, SSF_ARGV_ARGS_STR);
    SSF_ASSERT(gobjArgs != NULL);
    SSF_ASSERT(SSFGObjGetType(gobjArgs) == SSF_OBJ_TYPE_ARRAY);
    SSF_ASSERT(SSFLLLen(&gobjArgs->children) == expectedNumArgs);

    for (i = 0; i < expectedNumArgs; i++)
    {
        memset(path, 0, sizeof(path));
        path[0] = (char *)SSF_ARGV_ARGS_STR;
        path[1] = (char *)&i;
        gobjParent = NULL;
        gobjArg = NULL;
        SSF_ASSERT(SSFGObjFindPath(gobj, (SSFCStrIn_t *)path, &gobjParent, &gobjArg));
        SSF_ASSERT(gobjArg != NULL);
        SSF_ASSERT(SSFGObjGetType(gobjArg) == SSF_OBJ_TYPE_STR);
        SSF_ASSERT(SSFGObjGetString(gobjArg, outStr, sizeof(outStr)));
        SSF_ASSERT(strcmp(outStr, expectedArgs[i]) == 0);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts that the parsed opts object contains an opt with the supplied label and value.       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFArgvUTCheckOpt(SSFGObj_t *gobj, SSFCStrIn_t expectedOpt, SSFCStrIn_t expectedValue)
{
    SSFGObj_t *gobjOpts;
    SSFGObj_t *gobjOpt;
    SSFGObj_t *gobjParent = NULL;
    char outStr[SSF_ARGV_UT_OUT_STR_SIZE];
    char *path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(expectedOpt != NULL);
    SSF_REQUIRE(expectedValue != NULL);

    gobjOpts = _SSFArgvUTFindChild(gobj, SSF_ARGV_OPTS_STR);
    SSF_ASSERT(gobjOpts != NULL);
    SSF_ASSERT(SSFGObjGetType(gobjOpts) == SSF_OBJ_TYPE_OBJECT);

    memset(path, 0, sizeof(path));
    path[0] = (char *)SSF_ARGV_OPTS_STR;
    path[1] = (char *)expectedOpt;
    gobjOpt = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, (SSFCStrIn_t *)path, &gobjParent, &gobjOpt));
    SSF_ASSERT(gobjOpt != NULL);
    SSF_ASSERT(SSFGObjGetType(gobjOpt) == SSF_OBJ_TYPE_STR);
    SSF_ASSERT(SSFGObjGetString(gobjOpt, outStr, sizeof(outStr)));
    SSF_ASSERT(strcmp(outStr, expectedValue) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts that the parsed opts object contains the supplied number of opts.                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFArgvUTCheckNumOpts(SSFGObj_t *gobj, size_t expectedNumOpts)
{
    SSFGObj_t *gobjOpts;

    SSF_REQUIRE(gobj != NULL);

    gobjOpts = _SSFArgvUTFindChild(gobj, SSF_ARGV_OPTS_STR);
    SSF_ASSERT(gobjOpts != NULL);
    SSF_ASSERT(SSFGObjGetType(gobjOpts) == SSF_OBJ_TYPE_OBJECT);
    SSF_ASSERT(SSFLLLen(&gobjOpts->children) == expectedNumOpts);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on command line argv parser external interface.                            */
/* --------------------------------------------------------------------------------------------- */
void SSFArgvUnitTest(void)
{
    SSFGObj_t *gobj = NULL;
    SSFGObj_t *gobjBad = (SSFGObj_t *)1;
    const char *args1[] = { "arg1" };
    const char *args2[] = { "arg1", "arg2" };
    const char *args3[] = { "arg1", "arg2", "arg3" };
    const char *argsEsc[] = { "arg with spaces" };
    const char *argsBs[] = { "a\\b" };
    const char *argsBsMulti[] = { "a\\\\b" };
    const char *argsMix[] = { "hello world\\foo" };
    const char *argsLeadTrail[] = { " leading", "trailing ", " both " };
    const char *args4[] = { "a1", "a2", "a3", "a4" };

    /* Test SSFArgvInit() parameter validation */
    SSF_ASSERT_TEST(SSFArgvInit(NULL, 0, &gobj, SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    SSF_ASSERT_TEST(SSFArgvInit("cmd", sizeof("cmd"), NULL, SSF_ARGV_UT_MAX_OPTS,
                                SSF_ARGV_UT_MAX_ARGS));
    SSF_ASSERT_TEST(SSFArgvInit("cmd", sizeof("cmd"), &gobjBad, SSF_ARGV_UT_MAX_OPTS,
                                SSF_ARGV_UT_MAX_ARGS));

    /* Test SSFArgvDeInit() parameter validation */
    SSF_ASSERT_TEST(SSFArgvDeInit(NULL));
    SSF_ASSERT_TEST(SSFArgvDeInit(&gobj));

    /* Test parsing of cmd only */
    gobj = NULL;
    SSF_ASSERT(SSFArgvInit("cmd", sizeof("cmd"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, NULL, 0);
    SSFArgvDeInit(&gobj);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing of cmd with single arg */
    SSF_ASSERT(SSFArgvInit("cmd arg1", sizeof("cmd arg1"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, args1, sizeof(args1) / sizeof(args1[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing of cmd with multiple args */
    SSF_ASSERT(SSFArgvInit("cmd arg1 arg2", sizeof("cmd arg1 arg2"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, args2, sizeof(args2) / sizeof(args2[0]));
    SSFArgvDeInit(&gobj);

    SSF_ASSERT(SSFArgvInit("cmd arg1 arg2 arg3", sizeof("cmd arg1 arg2 arg3"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, args3, sizeof(args3) / sizeof(args3[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing of cmd with single value-less opt (//opt form) */
    SSF_ASSERT(SSFArgvInit("cmd //opt1", sizeof("cmd //opt1"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 1);
    _SSFArgvUTCheckOpt(gobj, "opt1", "");
    _SSFArgvUTCheckArgs(gobj, NULL, 0);
    SSFArgvDeInit(&gobj);

    /* Test parsing of cmd with single opt with value (/opt arg form) */
    SSF_ASSERT(SSFArgvInit("cmd /opt1 val1", sizeof("cmd /opt1 val1"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 1);
    _SSFArgvUTCheckOpt(gobj, "opt1", "val1");
    _SSFArgvUTCheckArgs(gobj, NULL, 0);
    SSFArgvDeInit(&gobj);

    /* Test parsing of cmd with mix of opts with and without values */
    SSF_ASSERT(SSFArgvInit("cmd //opt1 /opt2 val2", sizeof("cmd //opt1 /opt2 val2"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 2);
    _SSFArgvUTCheckOpt(gobj, "opt1", "");
    _SSFArgvUTCheckOpt(gobj, "opt2", "val2");
    _SSFArgvUTCheckArgs(gobj, NULL, 0);
    SSFArgvDeInit(&gobj);

    /* Test parsing of cmd with mix of opts and args */
    SSF_ASSERT(SSFArgvInit("cmd /opt1 val1 arg1", sizeof("cmd /opt1 val1 arg1"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 1);
    _SSFArgvUTCheckOpt(gobj, "opt1", "val1");
    _SSFArgvUTCheckArgs(gobj, args1, sizeof(args1) / sizeof(args1[0]));
    SSFArgvDeInit(&gobj);

    SSF_ASSERT(SSFArgvInit("cmd //opt1 arg1 /opt2 val2 arg2",
                           sizeof("cmd //opt1 arg1 /opt2 val2 arg2"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 2);
    _SSFArgvUTCheckOpt(gobj, "opt1", "");
    _SSFArgvUTCheckOpt(gobj, "opt2", "val2");
    _SSFArgvUTCheckArgs(gobj, args2, sizeof(args2) / sizeof(args2[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing succeeds with multiple trailing whitespace chars */
    SSF_ASSERT(SSFArgvInit("cmd arg1  ", sizeof("cmd arg1  "), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, args1, sizeof(args1) / sizeof(args1[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing succeeds with multiple spaces between cmd and arg (main loop SKIP_WHITESPACE) */
    SSF_ASSERT(SSFArgvInit("cmd   arg1", sizeof("cmd   arg1"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, args1, sizeof(args1) / sizeof(args1[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing succeeds with multiple spaces between two args */
    SSF_ASSERT(SSFArgvInit("cmd arg1   arg2", sizeof("cmd arg1   arg2"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, args2, sizeof(args2) / sizeof(args2[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing succeeds at exactly maxArgs capacity */
    SSF_ASSERT(SSFArgvInit("cmd a1 a2 a3 a4", sizeof("cmd a1 a2 a3 a4"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, args4, sizeof(args4) / sizeof(args4[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing succeeds at exactly maxOpts capacity */
    SSF_ASSERT(SSFArgvInit("cmd //o1 //o2 //o3 //o4", sizeof("cmd //o1 //o2 //o3 //o4"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 4);
    _SSFArgvUTCheckOpt(gobj, "o1", "");
    _SSFArgvUTCheckOpt(gobj, "o2", "");
    _SSFArgvUTCheckOpt(gobj, "o3", "");
    _SSFArgvUTCheckOpt(gobj, "o4", "");
    _SSFArgvUTCheckArgs(gobj, NULL, 0);
    SSFArgvDeInit(&gobj);

    /* Test parsing succeeds with maxOpts == 0 when no opts are supplied. The opts gobj's       */
    /* children linked list is not initialized when maxOpts == 0, so its length cannot be       */
    /* queried; only its existence and type are checked.                                        */
    SSF_ASSERT(SSFArgvInit("cmd arg1", sizeof("cmd arg1"), &gobj, 0, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    SSF_ASSERT(SSFGObjGetType(_SSFArgvUTFindChild(gobj, SSF_ARGV_OPTS_STR)) == SSF_OBJ_TYPE_OBJECT);
    _SSFArgvUTCheckArgs(gobj, args1, sizeof(args1) / sizeof(args1[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing succeeds with maxArgs == 0 when no args are supplied. The args gobj's       */
    /* children linked list is not initialized when maxArgs == 0, so its length cannot be       */
    /* queried; only its existence and type are checked.                                        */
    SSF_ASSERT(SSFArgvInit("cmd //opt1", sizeof("cmd //opt1"), &gobj, SSF_ARGV_UT_MAX_OPTS, 0));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 1);
    _SSFArgvUTCheckOpt(gobj, "opt1", "");
    SSF_ASSERT(SSFGObjGetType(_SSFArgvUTFindChild(gobj, SSF_ARGV_ARGS_STR)) == SSF_OBJ_TYPE_ARRAY);
    SSFArgvDeInit(&gobj);

    /* Test parsing of cmd with leading whitespace */
    SSF_ASSERT(SSFArgvInit("  cmd", sizeof("  cmd"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, NULL, 0);
    SSFArgvDeInit(&gobj);

    /* Test parsing of arg with backslash escaped spaces (\ becomes literal space) */
    SSF_ASSERT(SSFArgvInit("cmd arg\\ with\\ spaces", sizeof("cmd arg\\ with\\ spaces"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, argsEsc, sizeof(argsEsc) / sizeof(argsEsc[0]));
    SSFArgvDeInit(&gobj);

    /* Test that an arg can start with '-' (the '-' character is no longer a special option    */
    /* specifier; only '/' is).                                                                 */
    {
        const char *argsDash[] = { "-dash-arg" };
        SSF_ASSERT(SSFArgvInit("cmd -dash-arg", sizeof("cmd -dash-arg"), &gobj,
                               SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
        _SSFArgvUTCheckCmd(gobj, "cmd");
        _SSFArgvUTCheckNumOpts(gobj, 0);
        _SSFArgvUTCheckArgs(gobj, argsDash, sizeof(argsDash) / sizeof(argsDash[0]));
        SSFArgvDeInit(&gobj);
    }

    /* Test that an arg can contain '/' in any position other than the first. A first-char    */
    /* '/' would be parsed as an option specifier; '/' embedded in the middle or at the end   */
    /* of an arg is just a regular printable character.                                       */
    {
        const char *argsSlash[] = { "path/to/file" };
        SSF_ASSERT(SSFArgvInit("cmd path/to/file", sizeof("cmd path/to/file"), &gobj,
                               SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
        _SSFArgvUTCheckCmd(gobj, "cmd");
        _SSFArgvUTCheckNumOpts(gobj, 0);
        _SSFArgvUTCheckArgs(gobj, argsSlash, sizeof(argsSlash) / sizeof(argsSlash[0]));
        SSFArgvDeInit(&gobj);
    }

    /* Test that an arg cannot start with '/' (the parser treats it as an option specifier    */
    /* and then fails because the option has no following value).                              */
    SSF_ASSERT(SSFArgvInit("cmd /path/to/file", sizeof("cmd /path/to/file"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test that a leading '/' in an arg can be escaped with '\' so the arg is parsed as     */
    /* beginning with '/' rather than as an option specifier. This is the behavior implied   */
    /* by the grammar comment at the top of ssfargv.c ("leading '/' escaped by '\'") but is  */
    /* NOT implemented by the current SSF_ARG_FIND_ARG macro — the macro only recognizes     */
    /* '\ ' and '\\' as valid escape sequences and treats '\/' as a parse error. This test   */
    /* will FAIL against the current implementation and is intended as a TDD-style witness   */
    /* for the missing '\/' escape support.                                                   */
    {
        const char *argsEscSlash[] = { "/path" };
        SSF_ASSERT(SSFArgvInit("cmd \\/path", sizeof("cmd \\/path"), &gobj,
                               SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
        _SSFArgvUTCheckCmd(gobj, "cmd");
        _SSFArgvUTCheckNumOpts(gobj, 0);
        _SSFArgvUTCheckArgs(gobj, argsEscSlash, sizeof(argsEscSlash) / sizeof(argsEscSlash[0]));
        SSFArgvDeInit(&gobj);
    }

    /* Test parsing of arg with escaped backslash (\\ becomes literal backslash) */
    SSF_ASSERT(SSFArgvInit("cmd a\\\\b", sizeof("cmd a\\\\b"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, argsBs, sizeof(argsBs) / sizeof(argsBs[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing of arg with multiple consecutive escaped backslashes */
    SSF_ASSERT(SSFArgvInit("cmd a\\\\\\\\b", sizeof("cmd a\\\\\\\\b"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, argsBsMulti, sizeof(argsBsMulti) / sizeof(argsBsMulti[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing of arg with mix of escaped space and escaped backslash */
    SSF_ASSERT(SSFArgvInit("cmd hello\\ world\\\\foo", sizeof("cmd hello\\ world\\\\foo"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, argsMix, sizeof(argsMix) / sizeof(argsMix[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing of multiple args where escaped chars are at boundaries */
    SSF_ASSERT(SSFArgvInit("cmd \\ leading trailing\\  \\ both\\ ",
                           sizeof("cmd \\ leading trailing\\  \\ both\\ "), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 0);
    _SSFArgvUTCheckArgs(gobj, argsLeadTrail, sizeof(argsLeadTrail) / sizeof(argsLeadTrail[0]));
    SSFArgvDeInit(&gobj);

    /* Test parsing of opt value with escaped space stores the unescaped value. The arg       */
    /* cannot begin with '/' (that would be parsed as another option), so a relative path    */
    /* without a leading slash is used here.                                                  */
    SSF_ASSERT(SSFArgvInit("cmd /path tmp/my\\ file", sizeof("cmd /path tmp/my\\ file"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 1);
    _SSFArgvUTCheckOpt(gobj, "path", "tmp/my file");
    _SSFArgvUTCheckArgs(gobj, NULL, 0);
    SSFArgvDeInit(&gobj);

    /* Test parsing of opt value with escaped backslash stores the unescaped value */
    SSF_ASSERT(SSFArgvInit("cmd /path C:\\\\tmp", sizeof("cmd /path C:\\\\tmp"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS));
    _SSFArgvUTCheckCmd(gobj, "cmd");
    _SSFArgvUTCheckNumOpts(gobj, 1);
    _SSFArgvUTCheckOpt(gobj, "path", "C:\\tmp");
    _SSFArgvUTCheckArgs(gobj, NULL, 0);
    SSFArgvDeInit(&gobj);

    /* Test parsing fails when arg has a backslash not followed by space or backslash */
    gobj = NULL;
    SSF_ASSERT(SSFArgvInit("cmd a\\b", sizeof("cmd a\\b"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);
    SSF_ASSERT(SSFArgvInit("cmd a\\", sizeof("cmd a\\"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails when arg position contains a non-printable char */
    gobj = NULL;
    SSF_ASSERT(SSFArgvInit("cmd \t", sizeof("cmd \t"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails on bare option specifier with no opt name */
    SSF_ASSERT(SSFArgvInit("cmd /", sizeof("cmd /"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);
    SSF_ASSERT(SSFArgvInit("cmd //", sizeof("cmd //"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails when /opt is missing its required arg at end of input */
    SSF_ASSERT(SSFArgvInit("cmd /opt1", sizeof("cmd /opt1"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails when /opt is followed by another opt instead of its required arg */
    SSF_ASSERT(SSFArgvInit("cmd /opt1 //opt2", sizeof("cmd /opt1 //opt2"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails when too many opts supplied */
    SSF_ASSERT(SSFArgvInit("cmd //o1 //o2 //o3 //o4 //o5", sizeof("cmd //o1 //o2 //o3 //o4 //o5"),
                           &gobj, SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails when too many args supplied */
    SSF_ASSERT(SSFArgvInit("cmd a1 a2 a3 a4 a5", sizeof("cmd a1 a2 a3 a4 a5"), &gobj,
                           SSF_ARGV_UT_MAX_OPTS, SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails on empty command line */
    SSF_ASSERT(SSFArgvInit("", sizeof(""), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails on whitespace-only command line */
    SSF_ASSERT(SSFArgvInit("  ", sizeof("  "), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails when cmd is followed by an invalid (non-separator) char */
    SSF_ASSERT(SSFArgvInit("cmd!", sizeof("cmd!"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails when opt name is followed by an invalid (non-separator) char */
    SSF_ASSERT(SSFArgvInit("cmd //opt!", sizeof("cmd //opt!"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails when maxOpts == 0 and an opt is supplied */
    SSF_ASSERT(SSFArgvInit("cmd //opt1", sizeof("cmd //opt1"), &gobj, 0,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails when maxArgs == 0 and an arg is supplied */
    SSF_ASSERT(SSFArgvInit("cmd arg1", sizeof("cmd arg1"), &gobj, SSF_ARGV_UT_MAX_OPTS,
                           0) == false);
    SSF_ASSERT(gobj == NULL);

    /* Test parsing fails when cmdLineSize is too small to contain the null terminator */
    SSF_ASSERT(SSFArgvInit("cmd", 1, &gobj, SSF_ARGV_UT_MAX_OPTS,
                           SSF_ARGV_UT_MAX_ARGS) == false);
    SSF_ASSERT(gobj == NULL);
}

#endif /* SSF_CONFIG_ARGV_UNIT_TEST */
