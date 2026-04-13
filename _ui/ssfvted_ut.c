/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfvted_ut.c                                                                                  */
/* Provides unit test for ANSI VT100 compatible terminal line editor interface.                  */
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
#include "ssfvted.h"

#if SSF_CONFIG_VTED_UNIT_TEST == 1

#define SSF_VTED_UT_LINE_SIZE    (8u)
#define SSF_VTED_UT_OUT_BUF_SIZE (256u)

/* ssfvted VT100 input sequence bytes (same values are kept private in ssfvted.c)               */
#define SSF_VTED_UT_IN_ESC       ('\x1b')
#define SSF_VTED_UT_IN_CSI       ('[')
#define SSF_VTED_UT_IN_SS3       ('O')
#define SSF_VTED_UT_IN_ESC_UP    ('A')
#define SSF_VTED_UT_IN_ESC_DOWN  ('B')
#define SSF_VTED_UT_IN_ESC_RIGHT ('C')
#define SSF_VTED_UT_IN_ESC_LEFT  ('D')
#define SSF_VTED_UT_IN_BS_ALT    ('\x7f')
#define SSF_VTED_UT_IN_CR        ('\r')
#define SSF_VTED_UT_IN_CTRLC     ('\x03')

/* Capture buffer for the writeStdoutFn callback. */
static uint8_t _ssfVTEdUTOut[SSF_VTED_UT_OUT_BUF_SIZE];
static size_t _ssfVTEdUTOutLen;

/* --------------------------------------------------------------------------------------------- */
/* Captures bytes that ssfvted would write to the terminal.                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFVTEdUTWriteStdout(const uint8_t *data, size_t dataLen)
{
    SSF_REQUIRE(data != NULL);
    SSF_ASSERT((_ssfVTEdUTOutLen + dataLen) <= sizeof(_ssfVTEdUTOut));
    memcpy(&_ssfVTEdUTOut[_ssfVTEdUTOutLen], data, dataLen);
    _ssfVTEdUTOutLen += dataLen;
}

/* --------------------------------------------------------------------------------------------- */
/* Clears the captured writeStdoutFn output between test cases.                                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFVTEdUTOutReset(void)
{
    memset(_ssfVTEdUTOut, 0, sizeof(_ssfVTEdUTOut));
    _ssfVTEdUTOutLen = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the captured writeStdoutFn output exactly matches the supplied bytes.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFVTEdUTOutEquals(const void *expected, size_t expectedLen)
{
    SSF_REQUIRE(expected != NULL);
    return (_ssfVTEdUTOutLen == expectedLen) &&
           (memcmp(_ssfVTEdUTOut, expected, expectedLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Feeds a null-terminated string through SSFVTEdProcessChar() one byte at a time.               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFVTEdUTSendStr(SSFVTEdContext_t *context, const char *str)
{
    SSFVTEdEscCode_t escOut = SSF_VTED_ESC_CODE_MIN;

    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(str != NULL);

    while (*str != 0)
    {
        SSF_ASSERT(SSFVTEdProcessChar(context, (uint8_t)*str, &escOut) == false);
        str++;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Feeds a 3-byte VT100 CSI escape sequence (ESC [ finalByte) through SSFVTEdProcessChar().     */
/* Returns the result of the final SSFVTEdProcessChar() call.                                   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFVTEdUTSendEsc(SSFVTEdContext_t *context, uint8_t code, SSFVTEdEscCode_t *escOut)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(escOut != NULL);

    SSF_ASSERT(SSFVTEdProcessChar(context, SSF_VTED_UT_IN_ESC, escOut) == false);
    SSF_ASSERT(SSFVTEdProcessChar(context, SSF_VTED_UT_IN_CSI, escOut) == false);
    return SSFVTEdProcessChar(context, code, escOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Feeds a 3-byte VT100 SS3 escape sequence (ESC O finalByte) through SSFVTEdProcessChar().     */
/* Used for xterm application cursor keys mode.                                                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFVTEdUTSendSS3(SSFVTEdContext_t *context, uint8_t code, SSFVTEdEscCode_t *escOut)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(escOut != NULL);

    SSF_ASSERT(SSFVTEdProcessChar(context, SSF_VTED_UT_IN_ESC, escOut) == false);
    SSF_ASSERT(SSFVTEdProcessChar(context, SSF_VTED_UT_IN_SS3, escOut) == false);
    return SSFVTEdProcessChar(context, code, escOut);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ANSI VT100 compatible terminal line editor external interface.          */
/* --------------------------------------------------------------------------------------------- */
void SSFVTEdUnitTest(void)
{
    SSFVTEdContext_t ctx;
    SSFVTEdContext_t ctxBad;
    char lineBuf[SSF_VTED_UT_LINE_SIZE];
    SSFVTEdEscCode_t escOut;
    size_t i;

    /* Test SSFVTEdInit() parameter validation */
    memset(&ctx, 0, sizeof(ctx));
    SSF_ASSERT_TEST(SSFVTEdInit(NULL, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout));
    SSF_ASSERT_TEST(SSFVTEdInit(&ctx, NULL, sizeof(lineBuf), _SSFVTEdUTWriteStdout));
    SSF_ASSERT_TEST(SSFVTEdInit(&ctx, lineBuf, 0, _SSFVTEdUTWriteStdout));
    SSF_ASSERT_TEST(SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), NULL));

    /* Test SSFVTEdInit() rejects an already-initialized context */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSF_ASSERT_TEST(SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout));
    SSFVTEdDeInit(&ctx);

    /* Test SSFVTEdDeInit() parameter validation */
    SSF_ASSERT_TEST(SSFVTEdDeInit(NULL));
    memset(&ctxBad, 0, sizeof(ctxBad));
    SSF_ASSERT_TEST(SSFVTEdDeInit(&ctxBad));

    /* Test SSFVTEdProcessChar() parameter validation */
    memset(&ctxBad, 0, sizeof(ctxBad));
    SSF_ASSERT_TEST(SSFVTEdProcessChar(NULL, 'a', &escOut));
    SSF_ASSERT_TEST(SSFVTEdProcessChar(&ctxBad, 'a', &escOut));
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSF_ASSERT_TEST(SSFVTEdProcessChar(&ctx, 'a', NULL));
    SSFVTEdDeInit(&ctx);

    /* Test that SSFVTEdInit() clears context state and line buffer */
    memset(lineBuf, 'X', sizeof(lineBuf));
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSF_ASSERT(ctx.line == lineBuf);
    SSF_ASSERT(ctx.lineSize == sizeof(lineBuf));
    SSF_ASSERT(ctx.line[0] == 0);

    /* Test that SSFVTEdDeInit() clears the magic field */
    SSFVTEdDeInit(&ctx);
    SSF_ASSERT(ctx.magic == 0);

    /* Test SSFVTEdIsInited() parameter validation */
    SSF_ASSERT_TEST(SSFVTEdIsInited(NULL));

    /* Test that SSFVTEdIsInited() reports false on a zeroed context */
    memset(&ctx, 0, sizeof(ctx));
    SSF_ASSERT(SSFVTEdIsInited(&ctx) == false);

    /* Test that SSFVTEdIsInited() reports true after SSFVTEdInit() */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSF_ASSERT(SSFVTEdIsInited(&ctx));

    /* Test that SSFVTEdIsInited() still reports true after SSFVTEdReset() */
    SSFVTEdReset(&ctx);
    SSF_ASSERT(SSFVTEdIsInited(&ctx));

    /* Test that SSFVTEdIsInited() reports false after SSFVTEdDeInit() */
    SSFVTEdDeInit(&ctx);
    SSF_ASSERT(SSFVTEdIsInited(&ctx) == false);

    /* Test that SSFVTEdIsInited() does not mutate the context */
    memset(&ctxBad, 0, sizeof(ctxBad));
    SSF_ASSERT(SSFVTEdIsInited(&ctxBad) == false);
    for (i = 0; i < sizeof(ctxBad); i++)
    {
        SSF_ASSERT(((uint8_t *)&ctxBad)[i] == 0);
    }

    /* Test SSFVTEdReset() parameter validation */
    SSF_ASSERT_TEST(SSFVTEdReset(NULL));
    memset(&ctxBad, 0, sizeof(ctxBad));
    SSF_ASSERT_TEST(SSFVTEdReset(&ctxBad));

    /* Test that SSFVTEdReset() on a freshly initialized context preserves configuration */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSFVTEdReset(&ctx);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    SSF_ASSERT(ctx.line[0] == 0);
    SSF_ASSERT(ctx.line == lineBuf);
    SSF_ASSERT(ctx.lineSize == sizeof(lineBuf));
    SSF_ASSERT(ctx.writeStdoutFn == _SSFVTEdUTWriteStdout);
    SSF_ASSERT(ctx.magic != 0);
    SSFVTEdDeInit(&ctx);

    /* Test that SSFVTEdReset() zeros the entire line buffer, not just the leading byte */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "hello");
    SSF_ASSERT(strcmp(ctx.line, "hello") == 0);
    SSF_ASSERT(ctx.cursor == 5);
    SSF_ASSERT(ctx.lineLen == 5);
    SSFVTEdReset(&ctx);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    for (i = 0; i < sizeof(lineBuf); i++)
    {
        SSF_ASSERT(ctx.line[i] == 0);
    }
    SSF_ASSERT(ctx.magic != 0);
    SSFVTEdDeInit(&ctx);

    /* Test that the editor still functions correctly after SSFVTEdReset() */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    SSFVTEdReset(&ctx);
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, 'X', &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "X") == 0);
    SSF_ASSERT(ctx.cursor == 1);
    SSF_ASSERT(ctx.lineLen == 1);
    SSF_ASSERT(_SSFVTEdUTOutEquals("\x1b[@X", 4));
    SSFVTEdDeInit(&ctx);

    /* Test that SSFVTEdInit() emits the configured VT100 prompt via writeStdoutFn. The      */
    /* captured output should match SSF_VTED_PROMPT_STR exactly (excluding the trailing      */
    /* null terminator), and the line buffer state must be clean (empty, cursor at 0).      */
    memset(&ctx, 0, sizeof(ctx));
    _SSFVTEdUTOutReset();
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSF_ASSERT(_SSFVTEdUTOutEquals(SSF_VTED_PROMPT_STR, sizeof(SSF_VTED_PROMPT_STR) - 1U));
    SSF_ASSERT(ctx.line[0] == 0);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that SSFVTEdReset() emits the configured VT100 prompt via writeStdoutFn. The     */
    /* prompt must be emitted again even if the context had typed content, and the line      */
    /* buffer must be returned to a clean state.                                              */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTOutReset();
    SSFVTEdReset(&ctx);
    SSF_ASSERT(_SSFVTEdUTOutEquals(SSF_VTED_PROMPT_STR, sizeof(SSF_VTED_PROMPT_STR) - 1U));
    SSF_ASSERT(ctx.line[0] == 0);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test SSFVTEdReset() when cursor is past the originally typed end of line      */
    /* (via arrow-right auto-space). The state before reset has cursor and lineLen   */
    /* both extended by the two arrow-rights; reset brings both back to zero.        */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "ab");
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_RIGHT, &escOut);
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_RIGHT, &escOut);
    SSF_ASSERT(strcmp(ctx.line, "ab  ") == 0);
    SSF_ASSERT(ctx.cursor == 4);
    SSF_ASSERT(ctx.lineLen == 4);
    SSFVTEdReset(&ctx);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    SSF_ASSERT(ctx.line[0] == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that multiple SSFVTEdReset() calls in sequence work correctly */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "one");
    SSFVTEdReset(&ctx);
    SSF_ASSERT(ctx.line[0] == 0);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    _SSFVTEdUTSendStr(&ctx, "two");
    SSF_ASSERT(strcmp(ctx.line, "two") == 0);
    SSF_ASSERT(ctx.cursor == 3);
    SSF_ASSERT(ctx.lineLen == 3);
    SSFVTEdReset(&ctx);
    SSF_ASSERT(ctx.line[0] == 0);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    _SSFVTEdUTSendStr(&ctx, "three");
    SSF_ASSERT(strcmp(ctx.line, "three") == 0);
    SSF_ASSERT(ctx.cursor == 5);
    SSF_ASSERT(ctx.lineLen == 5);
    SSFVTEdDeInit(&ctx);

    /* Test inserting a single printable char */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, 'a', &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "a") == 0);
    SSF_ASSERT(ctx.cursor == 1);
    SSF_ASSERT(ctx.lineLen == 1);
    SSF_ASSERT(_SSFVTEdUTOutEquals("\x1b[@a", 4));
    SSFVTEdDeInit(&ctx);

    /* Test inserting multiple chars sequentially */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    SSF_ASSERT(strcmp(ctx.line, "abc") == 0);
    SSF_ASSERT(ctx.cursor == 3);
    SSF_ASSERT(ctx.lineLen == 3);
    SSFVTEdDeInit(&ctx);

    /* Test that non-printable characters are ignored */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, 0x01u, &escOut) == false);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, 0x1fu, &escOut) == false);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, 0x7fu, &escOut) == false);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    SSF_ASSERT(ctx.line[0] == 0);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that insertion is rejected when the buffer is full */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "1234567");
    SSF_ASSERT(strcmp(ctx.line, "1234567") == 0);
    SSF_ASSERT(ctx.cursor == (SSF_VTED_UT_LINE_SIZE - 1));
    SSF_ASSERT(ctx.lineLen == (SSF_VTED_UT_LINE_SIZE - 1));
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, '8', &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "1234567") == 0);
    SSF_ASSERT(ctx.cursor == (SSF_VTED_UT_LINE_SIZE - 1));
    SSF_ASSERT(ctx.lineLen == (SSF_VTED_UT_LINE_SIZE - 1));
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that insertion in the middle of a line shifts trailing chars right */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut);
    SSF_ASSERT(ctx.cursor == 2);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, 'X', &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "abXc") == 0);
    SSF_ASSERT(ctx.cursor == 3);
    SSF_ASSERT(ctx.lineLen == 4);
    SSFVTEdDeInit(&ctx);

    /* Test that backspace at cursor 0 is a no-op */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, '\b', &escOut) == false);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that backspace removes the char before the cursor */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, '\b', &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "ab") == 0);
    SSF_ASSERT(ctx.cursor == 2);
    SSF_ASSERT(ctx.lineLen == 2);
    SSF_ASSERT(_SSFVTEdUTOutEquals("\b\x1b[P", 4));
    SSFVTEdDeInit(&ctx);

    /* Test that backspace in the middle of a line shifts trailing chars left */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abcd");
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut);
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut);
    SSF_ASSERT(ctx.cursor == 2);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, '\b', &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "acd") == 0);
    SSF_ASSERT(ctx.cursor == 1);
    SSF_ASSERT(ctx.lineLen == 3);
    SSFVTEdDeInit(&ctx);

    /* Test that ESC LEFT at cursor 0 is a no-op */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut) == false);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that ESC LEFT moves the cursor left without modifying the line */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "abc") == 0);
    SSF_ASSERT(ctx.cursor == 2);
    SSF_ASSERT(ctx.lineLen == 3);
    SSF_ASSERT(_SSFVTEdUTOutEquals("\x1b[D", 3));
    SSFVTEdDeInit(&ctx);

    /* Test that ESC LEFT at end of line with a trailing space cleans up that space */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_RIGHT, &escOut);
    SSF_ASSERT(strcmp(ctx.line, "abc ") == 0);
    SSF_ASSERT(ctx.cursor == 4);
    SSF_ASSERT(ctx.lineLen == 4);
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "abc") == 0);
    SSF_ASSERT(ctx.cursor == 3);
    SSF_ASSERT(ctx.lineLen == 3);
    SSF_ASSERT(_SSFVTEdUTOutEquals("\x1b[D", 3));
    SSFVTEdDeInit(&ctx);

    /* Test that ESC RIGHT at the end of the buffer is a no-op */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "1234567");
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_RIGHT, &escOut) == false);
    SSF_ASSERT(ctx.cursor == (SSF_VTED_UT_LINE_SIZE - 1));
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that ESC RIGHT past end of line adds a trailing space */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_RIGHT, &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "abc ") == 0);
    SSF_ASSERT(ctx.cursor == 4);
    SSF_ASSERT(ctx.lineLen == 4);
    SSF_ASSERT(_SSFVTEdUTOutEquals("\x1b[C", 3));
    SSFVTEdDeInit(&ctx);

    /* Test that ESC RIGHT within the line moves the cursor without modifying chars */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut);
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut);
    SSF_ASSERT(ctx.cursor == 1);
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_RIGHT, &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "abc") == 0);
    SSF_ASSERT(ctx.cursor == 2);
    SSF_ASSERT(ctx.lineLen == 3);
    SSF_ASSERT(_SSFVTEdUTOutEquals("\x1b[C", 3));
    SSFVTEdDeInit(&ctx);

    /* Test that ESC UP returns the up escape code */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_UP, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_UP);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that ESC DOWN returns the down escape code */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_DOWN, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_DOWN);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that CR on an empty line returns the enter escape code */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CR, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_ENTER);
    SSF_ASSERT(ctx.line[0] == 0);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that CR after typed chars returns the enter escape code without modification */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CR, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_ENTER);
    SSF_ASSERT(strcmp(ctx.line, "abc") == 0);
    SSF_ASSERT(ctx.cursor == 3);
    SSF_ASSERT(ctx.lineLen == 3);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that CR returns the enter escape code when cursor is past the originally typed    */
    /* end of line. Arrow-right past end of line auto-adds trailing spaces, so after the two  */
    /* arrow-rights the line already reads "abc  " with cursor and lineLen both at 5. CR      */
    /* then returns ENTER without further modifying the line.                                 */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_RIGHT, &escOut);
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_RIGHT, &escOut);
    SSF_ASSERT(strcmp(ctx.line, "abc  ") == 0);
    SSF_ASSERT(ctx.cursor == 5);
    SSF_ASSERT(ctx.lineLen == 5);
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CR, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_ENTER);
    SSF_ASSERT(strcmp(ctx.line, "abc  ") == 0);
    SSF_ASSERT(ctx.cursor == 5);
    SSF_ASSERT(ctx.lineLen == 5);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that Ctrl-C on an empty line returns the ctrl-c escape code */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CTRLC, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_CTRLC);
    SSF_ASSERT(ctx.line[0] == 0);
    SSF_ASSERT(ctx.cursor == 0);
    SSF_ASSERT(ctx.lineLen == 0);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that Ctrl-C after typed chars returns the ctrl-c code without modifying the line */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CTRLC, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_CTRLC);
    SSF_ASSERT(strcmp(ctx.line, "abc") == 0);
    SSF_ASSERT(ctx.cursor == 3);
    SSF_ASSERT(ctx.lineLen == 3);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that Ctrl-C with cursor not at end of line still returns ctrl-c unchanged */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut);
    _SSFVTEdUTSendEsc(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut);
    SSF_ASSERT(ctx.cursor == 1);
    SSF_ASSERT(ctx.lineLen == 3);
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CTRLC, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_CTRLC);
    SSF_ASSERT(strcmp(ctx.line, "abc") == 0);
    SSF_ASSERT(ctx.cursor == 1);
    SSF_ASSERT(ctx.lineLen == 3);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that Ctrl-C on a full line returns ctrl-c without modifying the line */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "1234567");
    SSF_ASSERT(ctx.lineLen == (SSF_VTED_UT_LINE_SIZE - 1));
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CTRLC, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_CTRLC);
    SSF_ASSERT(strcmp(ctx.line, "1234567") == 0);
    SSF_ASSERT(ctx.lineLen == (SSF_VTED_UT_LINE_SIZE - 1));
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that Ctrl-C received mid-escape-sequence is consumed as a malformed byte:        */
    /* the partial ESC sequence is abandoned (state back to IDLE), and no CTRLC code is      */
    /* emitted since Ctrl-C is only recognized in the IDLE state.                            */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_ESC);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CTRLC, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    /* A subsequent Ctrl-C from IDLE now correctly emits the code. */
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CTRLC, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_CTRLC);
    SSFVTEdDeInit(&ctx);

    /* Test that an unknown CSI final byte is consumed without output or escape return */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendEsc(&ctx, 'Z', &escOut) == false);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSFVTEdDeInit(&ctx);

    /* Test that a second ESC introducer restarts the pending escape sequence. The first ESC  */
    /* places the decoder in ESC state; the second ESC re-starts in ESC state (no change);    */
    /* then '[' advances to CSI, and 'A' emits UP.                                            */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_ESC);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_ESC);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CSI, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_CSI);
    escOut = SSF_VTED_ESC_CODE_MIN;
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC_UP, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_UP);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSFVTEdDeInit(&ctx);

    /* Test that a lone ESC followed by a non-CSI, non-SS3 byte abandons the sequence. After  */
    /* the abandonment, the decoder is back to IDLE and subsequent printable input inserts    */
    /* normally (the aborting byte itself is silently dropped).                               */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_ESC);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, 'a', &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSF_ASSERT(ctx.line[0] == 0);  /* 'a' was consumed by the decoder, not inserted */
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, 'b', &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "b") == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that the alternate backspace byte (0x7F) is handled as a backspace */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTOutReset();
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_BS_ALT, &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "ab") == 0);
    SSF_ASSERT(ctx.cursor == 2);
    SSF_ASSERT(ctx.lineLen == 2);
    /* Output should still start with 0x08 (real BS), not 0x7F, followed by DCH */
    SSF_ASSERT(_SSFVTEdUTOutEquals("\b\x1b[P", 4));
    SSFVTEdDeInit(&ctx);

    /* Test xterm application cursor keys mode: ESC O A returns the UP escape code */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendSS3(&ctx, SSF_VTED_UT_IN_ESC_UP, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_UP);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test xterm application cursor keys mode: ESC O D is Arrow Left */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendSS3(&ctx, SSF_VTED_UT_IN_ESC_LEFT, &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "abc") == 0);
    SSF_ASSERT(ctx.cursor == 2);
    SSF_ASSERT(ctx.lineLen == 3);
    SSF_ASSERT(_SSFVTEdUTOutEquals("\x1b[D", 3));
    SSFVTEdDeInit(&ctx);

    /* Test that SSFVTEdReset() clears a pending escape decoder state */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC, &escOut) == false);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CSI, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_CSI);
    SSFVTEdReset(&ctx);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    /* After reset a lone 'A' should insert normally, not be consumed as Arrow Up */
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, 'A', &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "A") == 0);
    SSFVTEdDeInit(&ctx);

    /* Test that a new ESC introducer while in CSI state restarts the sequence. Sending       */
    /* ESC [ ESC [ A should put the decoder back into ESC state after the middle ESC and      */
    /* then complete as Arrow Up.                                                              */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC, &escOut) == false);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CSI, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_CSI);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_ESC);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CSI, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_CSI);
    escOut = SSF_VTED_ESC_CODE_MIN;
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC_UP, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_UP);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSFVTEdDeInit(&ctx);

    /* Test xterm application cursor keys mode: ESC O B returns the DOWN escape code */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    escOut = SSF_VTED_ESC_CODE_MIN;
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendSS3(&ctx, SSF_VTED_UT_IN_ESC_DOWN, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_DOWN);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSFVTEdDeInit(&ctx);

    /* Test xterm application cursor keys mode: ESC O C past end adds a trailing space */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTSendStr(&ctx, "abc");
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendSS3(&ctx, SSF_VTED_UT_IN_ESC_RIGHT, &escOut) == false);
    SSF_ASSERT(strcmp(ctx.line, "abc ") == 0);
    SSF_ASSERT(ctx.cursor == 4);
    SSF_ASSERT(ctx.lineLen == 4);
    SSF_ASSERT(_SSFVTEdUTOutEquals("\x1b[C", 3));
    SSFVTEdDeInit(&ctx);

    /* Test that a new ESC introducer while in SS3 state restarts the sequence. Sending      */
    /* ESC O ESC [ A should put the decoder back into ESC state after the middle ESC and     */
    /* then complete as Arrow Up.                                                              */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC, &escOut) == false);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_SS3, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_SS3);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_ESC);
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_CSI, &escOut) == false);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_CSI);
    escOut = SSF_VTED_ESC_CODE_MIN;
    SSF_ASSERT(SSFVTEdProcessChar(&ctx, SSF_VTED_UT_IN_ESC_UP, &escOut) == true);
    SSF_ASSERT(escOut == SSF_VTED_ESC_CODE_UP);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSFVTEdDeInit(&ctx);

    /* Test that an unknown SS3 final byte is consumed without output or escape return */
    SSFVTEdInit(&ctx, lineBuf, sizeof(lineBuf), _SSFVTEdUTWriteStdout);
    _SSFVTEdUTOutReset();
    SSF_ASSERT(_SSFVTEdUTSendSS3(&ctx, 'Z', &escOut) == false);
    SSF_ASSERT(_ssfVTEdUTOutLen == 0);
    SSF_ASSERT(ctx.escState == SSF_VTED_ESC_STATE_IDLE);
    SSFVTEdDeInit(&ctx);
}

#endif /* SSF_CONFIG_VTED_UNIT_TEST */
