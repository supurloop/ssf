/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcli_ut.c                                                                                   */
/* Provides unit test for the CLI framework interface.                                           */
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
#include "ssfgobj.h"
#include "ssfargv.h"
#include "ssfvted.h"
#include "ssfcli.h"

#if SSF_CONFIG_CLI_UNIT_TEST == 1

#define SSF_CLI_UT_LINE_SIZE    (SSF_CLI_MAX_CMD_LINE_SIZE)
#define SSF_CLI_UT_OUT_BUF_SIZE (4096u)
#define SSF_CLI_UT_MAX_CMDS     (4u)
#define SSF_CLI_UT_MAX_CMD_HIST (3u)
#define SSF_CLI_UT_HIST_BUF_SIZE (SSF_CLI_UT_LINE_SIZE * SSF_CLI_UT_MAX_CMD_HIST)

/* --------------------------------------------------------------------------------------------- */
/* Captured stdout from the writeStdoutFn callback                                               */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _ssfCLIUTOut[SSF_CLI_UT_OUT_BUF_SIZE];
static size_t _ssfCLIUTOutLen;

static void _SSFCLIUTWriteStdout(const uint8_t *data, size_t dataLen)
{
    SSF_REQUIRE(data != NULL);
    SSF_ASSERT((_ssfCLIUTOutLen + dataLen) <= sizeof(_ssfCLIUTOut));
    memcpy(&_ssfCLIUTOut[_ssfCLIUTOutLen], data, dataLen);
    _ssfCLIUTOutLen += dataLen;
}

static void _SSFCLIUTOutReset(void)
{
    memset(_ssfCLIUTOut, 0, sizeof(_ssfCLIUTOut));
    _ssfCLIUTOutLen = 0;
}

/* Returns true if the captured output contains needle at any position. */
static bool _SSFCLIUTOutContains(const char *needle)
{
    size_t needleLen;
    size_t i;

    SSF_REQUIRE(needle != NULL);
    needleLen = strlen(needle);
    if (needleLen == 0) return true;
    if (_ssfCLIUTOutLen < needleLen) return false;
    for (i = 0; i <= _ssfCLIUTOutLen - needleLen; i++)
    {
        if (memcmp(&_ssfCLIUTOut[i], needle, needleLen) == 0) return true;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Handler callback tracking                                                                      */
/* --------------------------------------------------------------------------------------------- */
static struct
{
    uint32_t callCount;
    uint32_t lastNumOpts;
    uint32_t lastNumArgs;
    SSFGObj_t *lastCmd;
    SSFGObj_t *lastOpts;
    SSFGObj_t *lastArgs;
    SSFVTEdWriteStdoutFn_t lastWriteFn;
    char lastCmdName[32];
    bool returnValue;
} _ssfCLIUTHandler;

static void _SSFCLIUTHandlerReset(void)
{
    memset(&_ssfCLIUTHandler, 0, sizeof(_ssfCLIUTHandler));
    _ssfCLIUTHandler.returnValue = true;
}

static bool _SSFCLIUTCmdHandler(SSFGObj_t *gobjCmd, uint32_t numOpts, SSFGObj_t *gobjOpts,
                                uint32_t numArgs, SSFGObj_t *gobjArgs,
                                SSFVTEdWriteStdoutFn_t writeStdoutFn)
{
    _ssfCLIUTHandler.callCount++;
    _ssfCLIUTHandler.lastCmd = gobjCmd;
    _ssfCLIUTHandler.lastOpts = gobjOpts;
    _ssfCLIUTHandler.lastArgs = gobjArgs;
    _ssfCLIUTHandler.lastNumOpts = numOpts;
    _ssfCLIUTHandler.lastNumArgs = numArgs;
    _ssfCLIUTHandler.lastWriteFn = writeStdoutFn;
    memset(_ssfCLIUTHandler.lastCmdName, 0, sizeof(_ssfCLIUTHandler.lastCmdName));
    SSFGObjGetString(gobjCmd, _ssfCLIUTHandler.lastCmdName,
                     sizeof(_ssfCLIUTHandler.lastCmdName));
    return _ssfCLIUTHandler.returnValue;
}

/* --------------------------------------------------------------------------------------------- */
/* Feeds a null-terminated string through SSFCLIProcessChar() one byte at a time.                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFCLIUTSendStr(SSFCLIContext_t *context, const char *str)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(str != NULL);
    while (*str != 0)
    {
        SSFCLIProcessChar(context, (uint8_t)*str);
        str++;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Feeds a 3-byte VT100 CSI sequence (ESC [ finalByte) through SSFCLIProcessChar().              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFCLIUTSendCsiEsc(SSFCLIContext_t *context, uint8_t code)
{
    SSF_REQUIRE(context != NULL);
    SSFCLIProcessChar(context, '\x1b');
    SSFCLIProcessChar(context, '[');
    SSFCLIProcessChar(context, code);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on CLI framework external interface.                                       */
/* --------------------------------------------------------------------------------------------- */
void SSFCLIUnitTest(void)
{
    SSFVTEdContext_t vted;
    SSFVTEdContext_t vtedBad;
    SSFCLIContext_t cli;
    SSFCLIContext_t cliBad;
    SSFCLICmd_t cmd;
    SSFCLICmd_t cmd2;
    SSFCLICmd_t cmdBadStr;
    SSFCLICmd_t cmdBadSyntax;
    SSFCLICmd_t cmdBadFn;
    char lineBuf[SSF_CLI_UT_LINE_SIZE];
    uint8_t histBuf[SSF_CLI_UT_HIST_BUF_SIZE];
    SSFGObj_t *gobj = NULL;
    SSFCStrOut_t strOut;
    size_t strLen;

    /* Zero all SSFCLICmd_t locals. Their leading SSFLLItem_t needs ll == NULL before insert,   */
    /* and stack garbage would make SSFLLPutItem() assert.                                      */
    memset(&cmd, 0, sizeof(cmd));
    memset(&cmd2, 0, sizeof(cmd2));
    memset(&cmdBadStr, 0, sizeof(cmdBadStr));
    memset(&cmdBadSyntax, 0, sizeof(cmdBadSyntax));
    memset(&cmdBadFn, 0, sizeof(cmdBadFn));

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIInit() parameter validation                                                    */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&vtedBad, 0, sizeof(vtedBad));
    memset(&cli, 0, sizeof(cli));
    memset(&cliBad, 0, sizeof(cliBad));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);

    /* NULL context */
    SSF_ASSERT_TEST(SSFCLIInit(NULL, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted));
    /* Non-zero magic on context (already inited) */
    cliBad.magic = 1;
    SSF_ASSERT_TEST(SSFCLIInit(&cliBad, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted));
    cliBad.magic = 0;
    /* maxCmds == 0 */
    SSF_ASSERT_TEST(SSFCLIInit(&cli, 0, 0, NULL, 0, &vted));
    /* maxCmds > SSF_CLI_MAX_CMDS */
    SSF_ASSERT_TEST(SSFCLIInit(&cli, SSF_CLI_MAX_CMDS + 1, 0, NULL, 0, &vted));
    /* maxCmdHist > SSF_CLI_MAX_CMD_HIST */
    SSF_ASSERT_TEST(SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, SSF_CLI_MAX_CMD_HIST + 1, histBuf,
                               sizeof(histBuf), &vted));
    /* NULL vtEdCtx */
    SSF_ASSERT_TEST(SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, NULL));
    /* vtEdCtx not inited */
    SSF_ASSERT_TEST(SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vtedBad));
    /* maxCmdHist == 0 but cmdHistBuf != NULL */
    SSF_ASSERT_TEST(SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, histBuf, 0, &vted));
    /* maxCmdHist == 0 but cmdHistBufSize != 0 */
    SSF_ASSERT_TEST(SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 1, &vted));
    /* maxCmdHist > 0 but cmdHistBuf == NULL */
    SSF_ASSERT_TEST(SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, SSF_CLI_UT_MAX_CMD_HIST, NULL,
                               sizeof(histBuf), &vted));
    /* maxCmdHist > 0 but cmdHistBufSize too small */
    SSF_ASSERT_TEST(SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, SSF_CLI_UT_MAX_CMD_HIST, histBuf,
                               sizeof(histBuf) - 1, &vted));

    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIInit() happy path without command history                                      */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted);
    SSF_ASSERT(cli.vtEdCtx == &vted);
    SSF_ASSERT(cli.numCmdHist == 0);
    SSF_ASSERT(cli.cmdHistBuf == NULL);
    SSF_ASSERT(cli.cmdHistBufSize == 0);
    SSF_ASSERT(cli.cmdHistBufIndex == 0);
    SSF_ASSERT(cli.magic != 0);
    SSF_ASSERT(SSFLLIsEmpty(&cli.cmds));
    SSFCLIDeInit(&cli);
    SSF_ASSERT(cli.magic == 0);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIInit() happy path with command history                                         */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    memset(histBuf, 0xAA, sizeof(histBuf));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, SSF_CLI_UT_MAX_CMD_HIST, histBuf, sizeof(histBuf),
               &vted);
    SSF_ASSERT(cli.vtEdCtx == &vted);
    SSF_ASSERT(cli.numCmdHist == SSF_CLI_UT_MAX_CMD_HIST);
    SSF_ASSERT(cli.cmdHistBuf == histBuf);
    SSF_ASSERT(cli.cmdHistBufSize == sizeof(histBuf));
    SSF_ASSERT(cli.cmdHistBufIndex == 0);
    /* SSFCLIInit() must have zeroed the supplied history buffer. */
    {
        size_t j;
        for (j = 0; j < sizeof(histBuf); j++) SSF_ASSERT(histBuf[j] == 0);
    }
    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIDeInit() parameter validation                                                  */
    /* ----------------------------------------------------------------------------------------- */
    memset(&cliBad, 0, sizeof(cliBad));
    SSF_ASSERT_TEST(SSFCLIDeInit(NULL));
    SSF_ASSERT_TEST(SSFCLIDeInit(&cliBad));

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIInitCmd() parameter validation                                                 */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted);

    cmd.cmdStr = "hello";
    cmd.cmdSyntaxStr = "hello - say hello";
    cmd.cmdFn = _SSFCLIUTCmdHandler;

    /* NULL context */
    SSF_ASSERT_TEST(SSFCLIInitCmd(NULL, &cmd));
    /* Uninitialized context */
    SSF_ASSERT_TEST(SSFCLIInitCmd(&cliBad, &cmd));
    /* NULL cmd */
    SSF_ASSERT_TEST(SSFCLIInitCmd(&cli, NULL));
    /* cmd->cmdStr == NULL */
    cmdBadStr = cmd;
    cmdBadStr.cmdStr = NULL;
    SSF_ASSERT_TEST(SSFCLIInitCmd(&cli, &cmdBadStr));
    /* cmd->cmdSyntaxStr == NULL */
    cmdBadSyntax = cmd;
    cmdBadSyntax.cmdSyntaxStr = NULL;
    SSF_ASSERT_TEST(SSFCLIInitCmd(&cli, &cmdBadSyntax));
    /* cmd->cmdFn == NULL */
    cmdBadFn = cmd;
    cmdBadFn.cmdFn = NULL;
    SSF_ASSERT_TEST(SSFCLIInitCmd(&cli, &cmdBadFn));

    /* Happy path: add a command, then remove it */
    SSFCLIInitCmd(&cli, &cmd);
    SSF_ASSERT(SSFLLIsEmpty(&cli.cmds) == false);
    SSFCLIDeInitCmd(&cli, &cmd);
    SSF_ASSERT(SSFLLIsEmpty(&cli.cmds));

    /* SSFCLIInitCmd() when cmd list is full asserts */
    {
        SSFCLICmd_t cmdFill[SSF_CLI_UT_MAX_CMDS];
        uint16_t k;
        SSFCLICmd_t cmdExtra;

        memset(cmdFill, 0, sizeof(cmdFill));
        memset(&cmdExtra, 0, sizeof(cmdExtra));
        for (k = 0; k < SSF_CLI_UT_MAX_CMDS; k++)
        {
            cmdFill[k].cmdStr = "f";
            cmdFill[k].cmdSyntaxStr = "f - fill";
            cmdFill[k].cmdFn = _SSFCLIUTCmdHandler;
            SSFCLIInitCmd(&cli, &cmdFill[k]);
        }
        cmdExtra.cmdStr = "x";
        cmdExtra.cmdSyntaxStr = "x - extra";
        cmdExtra.cmdFn = _SSFCLIUTCmdHandler;
        SSF_ASSERT_TEST(SSFCLIInitCmd(&cli, &cmdExtra));
        for (k = 0; k < SSF_CLI_UT_MAX_CMDS; k++) SSFCLIDeInitCmd(&cli, &cmdFill[k]);
    }

    /* SSFCLIDeInit() with cmds still in the list asserts */
    SSFCLIInitCmd(&cli, &cmd);
    SSF_ASSERT_TEST(SSFCLIDeInit(&cli));
    SSFCLIDeInitCmd(&cli, &cmd);

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIDeInitCmd() parameter validation                                               */
    /* ----------------------------------------------------------------------------------------- */
    SSF_ASSERT_TEST(SSFCLIDeInitCmd(NULL, &cmd));
    SSF_ASSERT_TEST(SSFCLIDeInitCmd(&cliBad, &cmd));
    SSF_ASSERT_TEST(SSFCLIDeInitCmd(&cli, NULL));

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIProcessChar() parameter validation                                             */
    /* ----------------------------------------------------------------------------------------- */
    SSF_ASSERT_TEST(SSFCLIProcessChar(NULL, 'a'));
    SSF_ASSERT_TEST(SSFCLIProcessChar(&cliBad, 'a'));

    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIProcessChar() Ctrl-C resets the line buffer                                    */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted);

    _SSFCLIUTSendStr(&cli, "partial");
    SSF_ASSERT(strcmp(vted.line, "partial") == 0);
    SSF_ASSERT(vted.lineLen == 7);

    _SSFCLIUTOutReset();
    SSFCLIProcessChar(&cli, '\x03');
    SSF_ASSERT(vted.line[0] == 0);
    SSF_ASSERT(vted.lineLen == 0);
    SSF_ASSERT(vted.cursor == 0);

    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIProcessChar() Enter dispatches to the matching command handler                 */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted);
    cmd.cmdStr = "hello";
    cmd.cmdSyntaxStr = "hello - say hello";
    cmd.cmdFn = _SSFCLIUTCmdHandler;
    SSFCLIInitCmd(&cli, &cmd);

    _SSFCLIUTHandlerReset();
    _ssfCLIUTHandler.returnValue = true;
    _SSFCLIUTSendStr(&cli, "hello\r");

    SSF_ASSERT(_ssfCLIUTHandler.callCount == 1);
    SSF_ASSERT(strcmp(_ssfCLIUTHandler.lastCmdName, "hello") == 0);
    SSF_ASSERT(_ssfCLIUTHandler.lastNumOpts == 0);
    SSF_ASSERT(_ssfCLIUTHandler.lastNumArgs == 0);
    SSF_ASSERT(_ssfCLIUTHandler.lastWriteFn == _SSFCLIUTWriteStdout);
    /* The line buffer must have been reset after the command completed. */
    SSF_ASSERT(vted.line[0] == 0);
    SSF_ASSERT(vted.lineLen == 0);

    /* ----------------------------------------------------------------------------------------- */
    /* Test that a command with options and positional args populates the handler's arguments   */
    /* ----------------------------------------------------------------------------------------- */
    _SSFCLIUTHandlerReset();
    _ssfCLIUTHandler.returnValue = true;
    _SSFCLIUTSendStr(&cli, "hello //flag /k val arg1 arg2\r");
    SSF_ASSERT(_ssfCLIUTHandler.callCount == 1);
    SSF_ASSERT(strcmp(_ssfCLIUTHandler.lastCmdName, "hello") == 0);
    SSF_ASSERT(_ssfCLIUTHandler.lastNumOpts == 2);
    SSF_ASSERT(_ssfCLIUTHandler.lastNumArgs == 2);
    SSF_ASSERT(vted.line[0] == 0);
    SSF_ASSERT(vted.lineLen == 0);

    /* ----------------------------------------------------------------------------------------- */
    /* Test that when the handler returns false the syntax string is written to stdout          */
    /* ----------------------------------------------------------------------------------------- */
    _SSFCLIUTHandlerReset();
    _ssfCLIUTHandler.returnValue = false;
    _SSFCLIUTOutReset();
    _SSFCLIUTSendStr(&cli, "hello\r");
    SSF_ASSERT(_ssfCLIUTHandler.callCount == 1);
    SSF_ASSERT(_SSFCLIUTOutContains("hello - say hello"));
    SSF_ASSERT(vted.line[0] == 0);

    SSFCLIDeInitCmd(&cli, &cmd);
    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIProcessChar() Enter with unknown command lists available commands             */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted);
    cmd.cmdStr = "known";
    cmd.cmdSyntaxStr = "known - a known cmd";
    cmd.cmdFn = _SSFCLIUTCmdHandler;
    SSFCLIInitCmd(&cli, &cmd);

    _SSFCLIUTHandlerReset();
    _SSFCLIUTOutReset();
    _SSFCLIUTSendStr(&cli, "other\r");
    /* Handler for 'known' must NOT be called for 'other'. */
    SSF_ASSERT(_ssfCLIUTHandler.callCount == 0);
    /* The command list was emitted so the registered name should appear. */
    SSF_ASSERT(_SSFCLIUTOutContains("known"));
    SSF_ASSERT(_SSFCLIUTOutContains("known - a known cmd"));
    SSF_ASSERT(vted.line[0] == 0);

    SSFCLIDeInitCmd(&cli, &cmd);
    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test Enter with multiple registered commands dispatches only to the matching one         */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted);
    cmd.cmdStr = "one";
    cmd.cmdSyntaxStr = "one - first";
    cmd.cmdFn = _SSFCLIUTCmdHandler;
    cmd2.cmdStr = "two";
    cmd2.cmdSyntaxStr = "two - second";
    cmd2.cmdFn = _SSFCLIUTCmdHandler;
    SSFCLIInitCmd(&cli, &cmd);
    SSFCLIInitCmd(&cli, &cmd2);

    _SSFCLIUTHandlerReset();
    _ssfCLIUTHandler.returnValue = true;
    _SSFCLIUTSendStr(&cli, "two\r");
    SSF_ASSERT(_ssfCLIUTHandler.callCount == 1);
    SSF_ASSERT(strcmp(_ssfCLIUTHandler.lastCmdName, "two") == 0);

    _SSFCLIUTHandlerReset();
    _ssfCLIUTHandler.returnValue = true;
    _SSFCLIUTSendStr(&cli, "one\r");
    SSF_ASSERT(_ssfCLIUTHandler.callCount == 1);
    SSF_ASSERT(strcmp(_ssfCLIUTHandler.lastCmdName, "one") == 0);

    SSFCLIDeInitCmd(&cli, &cmd);
    SSFCLIDeInitCmd(&cli, &cmd2);
    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test Enter with non-empty but unparseable line prints the CLI syntax                     */
    /* A leading '@' is not a valid command-name character so the argv parser rejects the line. */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted);

    _SSFCLIUTOutReset();
    _SSFCLIUTSendStr(&cli, "@\r");
    /* The CLI syntax help text should be in the captured output. */
    SSF_ASSERT(_SSFCLIUTOutContains("<cmd>"));
    SSF_ASSERT(_SSFCLIUTOutContains("<opt>"));
    SSF_ASSERT(_SSFCLIUTOutContains("<DOWN  ARROW>"));
    SSF_ASSERT(vted.line[0] == 0);

    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test Enter on an empty line prints the registered command list                           */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted);
    cmd.cmdStr = "listed";
    cmd.cmdSyntaxStr = "listed - an entry";
    cmd.cmdFn = _SSFCLIUTCmdHandler;
    SSFCLIInitCmd(&cli, &cmd);

    _SSFCLIUTOutReset();
    SSFCLIProcessChar(&cli, '\r');
    SSF_ASSERT(_SSFCLIUTOutContains("listed - an entry"));

    SSFCLIDeInitCmd(&cli, &cmd);
    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test command history save + recall via arrow-up                                          */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    memset(histBuf, 0, sizeof(histBuf));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, SSF_CLI_UT_MAX_CMD_HIST, histBuf, sizeof(histBuf),
               &vted);
    cmd.cmdStr = "alpha";
    cmd.cmdSyntaxStr = "alpha - first";
    cmd.cmdFn = _SSFCLIUTCmdHandler;
    cmd2.cmdStr = "beta";
    cmd2.cmdSyntaxStr = "beta - second";
    cmd2.cmdFn = _SSFCLIUTCmdHandler;
    SSFCLIInitCmd(&cli, &cmd);
    SSFCLIInitCmd(&cli, &cmd2);

    _SSFCLIUTHandlerReset();
    _ssfCLIUTHandler.returnValue = true;
    _SSFCLIUTSendStr(&cli, "alpha\r");
    SSF_ASSERT(_ssfCLIUTHandler.callCount == 1);
    /* History slot 0 now contains "alpha". */
    SSF_ASSERT(strcmp((const char *)&histBuf[0], "alpha") == 0);
    SSF_ASSERT(cli.cmdHistBufIndex == 1);

    _SSFCLIUTSendStr(&cli, "beta\r");
    /* History slot 1 now contains "beta". */
    SSF_ASSERT(strcmp((const char *)&histBuf[SSF_CLI_UT_LINE_SIZE], "beta") == 0);
    SSF_ASSERT(cli.cmdHistBufIndex == 2);

    /* Press UP arrow: should load "beta" into the line buffer. */
    _SSFCLIUTSendCsiEsc(&cli, 'A');
    SSF_ASSERT(strcmp(vted.line, "beta") == 0);
    SSF_ASSERT(vted.lineLen == 4);
    SSF_ASSERT(vted.cursor == 4);
    SSF_ASSERT(cli.cmdHistBufIndex == 1);

    /* Press UP arrow again: should load "alpha". */
    _SSFCLIUTSendCsiEsc(&cli, 'A');
    SSF_ASSERT(strcmp(vted.line, "alpha") == 0);
    SSF_ASSERT(vted.lineLen == 5);
    SSF_ASSERT(vted.cursor == 5);
    SSF_ASSERT(cli.cmdHistBufIndex == 0);

    SSFCLIDeInitCmd(&cli, &cmd);
    SSFCLIDeInitCmd(&cli, &cmd2);
    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test that UP/DOWN arrows are no-ops when command history is disabled                     */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, 0, NULL, 0, &vted);

    _SSFCLIUTSendStr(&cli, "xyz");
    SSF_ASSERT(strcmp(vted.line, "xyz") == 0);
    _SSFCLIUTSendCsiEsc(&cli, 'A');
    SSF_ASSERT(strcmp(vted.line, "xyz") == 0);
    _SSFCLIUTSendCsiEsc(&cli, 'B');
    SSF_ASSERT(strcmp(vted.line, "xyz") == 0);

    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test DOWN arrow with history enabled recalls forward through command history              */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    memset(histBuf, 0, sizeof(histBuf));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, SSF_CLI_UT_MAX_CMD_HIST, histBuf, sizeof(histBuf),
               &vted);
    cmd.cmdStr = "aa";
    cmd.cmdSyntaxStr = "aa - a";
    cmd.cmdFn = _SSFCLIUTCmdHandler;
    cmd2.cmdStr = "bb";
    cmd2.cmdSyntaxStr = "bb - b";
    cmd2.cmdFn = _SSFCLIUTCmdHandler;
    SSFCLIInitCmd(&cli, &cmd);
    SSFCLIInitCmd(&cli, &cmd2);

    _SSFCLIUTHandlerReset();
    _ssfCLIUTHandler.returnValue = true;
    _SSFCLIUTSendStr(&cli, "aa\r");
    _SSFCLIUTSendStr(&cli, "bb\r");
    SSF_ASSERT(cli.cmdHistBufIndex == 2);

    /* UP twice to reach "aa" */
    _SSFCLIUTSendCsiEsc(&cli, 'A');
    SSF_ASSERT(strcmp(vted.line, "bb") == 0);
    _SSFCLIUTSendCsiEsc(&cli, 'A');
    SSF_ASSERT(strcmp(vted.line, "aa") == 0);
    SSF_ASSERT(cli.cmdHistBufIndex == 0);

    /* DOWN once should go forward to "bb" */
    _SSFCLIUTSendCsiEsc(&cli, 'B');
    SSF_ASSERT(strcmp(vted.line, "bb") == 0);
    SSF_ASSERT(cli.cmdHistBufIndex == 1);

    SSFCLIDeInitCmd(&cli, &cmd);
    SSFCLIDeInitCmd(&cli, &cmd2);
    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test UP arrow on completely empty history blanks the line                                 */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    memset(histBuf, 0, sizeof(histBuf));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, SSF_CLI_UT_MAX_CMD_HIST, histBuf, sizeof(histBuf),
               &vted);

    /* Type something, then UP on empty history should blank the line */
    _SSFCLIUTSendStr(&cli, "typed");
    SSF_ASSERT(strcmp(vted.line, "typed") == 0);
    _SSFCLIUTSendCsiEsc(&cli, 'A');
    SSF_ASSERT(vted.line[0] == 0);
    SSF_ASSERT(vted.lineLen == 0);
    SSF_ASSERT(vted.cursor == 0);

    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test DOWN arrow on completely empty history blanks the line                               */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    memset(histBuf, 0, sizeof(histBuf));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, SSF_CLI_UT_MAX_CMD_HIST, histBuf, sizeof(histBuf),
               &vted);

    _SSFCLIUTSendStr(&cli, "typed");
    SSF_ASSERT(strcmp(vted.line, "typed") == 0);
    _SSFCLIUTSendCsiEsc(&cli, 'B');
    SSF_ASSERT(vted.line[0] == 0);
    SSF_ASSERT(vted.lineLen == 0);
    SSF_ASSERT(vted.cursor == 0);

    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test history ring-buffer wrap: oldest entry is overwritten after numCmdHist saves         */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    memset(histBuf, 0, sizeof(histBuf));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, SSF_CLI_UT_MAX_CMD_HIST, histBuf, sizeof(histBuf),
               &vted);
    cmd.cmdStr = "c1";
    cmd.cmdSyntaxStr = "c1 - 1";
    cmd.cmdFn = _SSFCLIUTCmdHandler;
    SSFCLIInitCmd(&cli, &cmd);
    _SSFCLIUTHandlerReset();
    _ssfCLIUTHandler.returnValue = true;

    /* Fill all 3 history slots: c1 → slot 0, c1 → slot 1, c1 → slot 2 */
    _SSFCLIUTSendStr(&cli, "c1\r");
    SSF_ASSERT(cli.cmdHistBufIndex == 1);
    _SSFCLIUTSendStr(&cli, "c1\r");
    SSF_ASSERT(cli.cmdHistBufIndex == 2);
    _SSFCLIUTSendStr(&cli, "c1\r");
    /* Index should wrap to 0 */
    SSF_ASSERT(cli.cmdHistBufIndex == 0);

    /* One more save overwrites slot 0 */
    _SSFCLIUTSendStr(&cli, "c1\r");
    SSF_ASSERT(cli.cmdHistBufIndex == 1);
    SSF_ASSERT(strcmp((const char *)&histBuf[0], "c1") == 0);

    SSFCLIDeInitCmd(&cli, &cmd);
    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test that empty-line Enter with history enabled does NOT save to history                  */
    /* ----------------------------------------------------------------------------------------- */
    memset(&vted, 0, sizeof(vted));
    memset(&cli, 0, sizeof(cli));
    memset(histBuf, 0, sizeof(histBuf));
    SSFVTEdInit(&vted, lineBuf, sizeof(lineBuf), _SSFCLIUTWriteStdout);
    SSFCLIInit(&cli, SSF_CLI_UT_MAX_CMDS, SSF_CLI_UT_MAX_CMD_HIST, histBuf, sizeof(histBuf),
               &vted);

    /* Press Enter on empty line */
    SSFCLIProcessChar(&cli, '\r');
    /* History index must not have advanced; slot 0 must still be empty */
    SSF_ASSERT(cli.cmdHistBufIndex == 0);
    SSF_ASSERT(histBuf[0] == 0);

    SSFCLIDeInit(&cli);
    SSFVTEdDeInit(&vted);

    /* ----------------------------------------------------------------------------------------- */
    /* Test SSFCLIGObjGetOptArgStrRef() parameter validation + happy path                        */
    /* ----------------------------------------------------------------------------------------- */
    gobj = NULL;
    SSF_ASSERT(SSFArgvInit("mycmd /key value //flag arg0 arg1",
                           sizeof("mycmd /key value //flag arg0 arg1"),
                           &gobj, 4, 4));
    {
        SSFGObj_t *gobjOpts = NULL;
        SSFGObj_t *gobjArgs = NULL;
        SSFGObj_t *gobjParent = NULL;
        char *path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];

        memset(path, 0, sizeof(path));
        path[0] = SSF_ARGV_OPTS_CSTR;
        SSF_ASSERT(SSFGObjFindPath(gobj, (SSFCStrIn_t *)path, &gobjParent, &gobjOpts));
        gobjParent = NULL;
        path[0] = SSF_ARGV_ARGS_CSTR;
        SSF_ASSERT(SSFGObjFindPath(gobj, (SSFCStrIn_t *)path, &gobjParent, &gobjArgs));

        /* Parameter validation */
        SSF_ASSERT_TEST(SSFCLIGObjGetOptArgStrRef(NULL, gobjOpts, &strOut, &strLen));
        SSF_ASSERT_TEST(SSFCLIGObjGetOptArgStrRef("key", NULL, &strOut, &strLen));
        SSF_ASSERT_TEST(SSFCLIGObjGetOptArgStrRef("key", gobjOpts, NULL, &strLen));
        SSF_ASSERT_TEST(SSFCLIGObjGetOptArgStrRef("key", gobjOpts, &strOut, NULL));

        /* Happy path: option with arg */
        strOut = NULL;
        strLen = 0;
        SSF_ASSERT(SSFCLIGObjGetOptArgStrRef("key", gobjOpts, &strOut, &strLen));
        SSF_ASSERT(strOut != NULL);
        SSF_ASSERT(strLen == strlen("value"));
        SSF_ASSERT(memcmp(strOut, "value", strLen + 1) == 0);

        /* Value-less option: //flag has dataSize == 1 (just the null), strLen == 0 */
        strOut = NULL;
        strLen = 99;
        SSF_ASSERT(SSFCLIGObjGetOptArgStrRef("flag", gobjOpts, &strOut, &strLen));
        SSF_ASSERT(strOut != NULL);
        SSF_ASSERT(strLen == 0);

        /* Missing option */
        strOut = NULL;
        strLen = 0;
        SSF_ASSERT(SSFCLIGObjGetOptArgStrRef("missing", gobjOpts, &strOut, &strLen) == false);

        /* --------------------------------------------------------------------------------- */
        /* Test SSFCLIGObjGetIsOpt() parameter validation + happy path                       */
        /* --------------------------------------------------------------------------------- */
        SSF_ASSERT_TEST(SSFCLIGObjGetIsOpt(NULL, gobjOpts));
        SSF_ASSERT_TEST(SSFCLIGObjGetIsOpt("flag", NULL));

        /* Happy path: value-less option returns true */
        SSF_ASSERT(SSFCLIGObjGetIsOpt("flag", gobjOpts));
        /* Option that has an argument returns false ('key' has value 'value') */
        SSF_ASSERT(SSFCLIGObjGetIsOpt("key", gobjOpts) == false);
        /* Missing option returns false */
        SSF_ASSERT(SSFCLIGObjGetIsOpt("missing", gobjOpts) == false);

        /* --------------------------------------------------------------------------------- */
        /* Test SSFCLIGObjGetArgStrRef() parameter validation + happy path                   */
        /* --------------------------------------------------------------------------------- */
        SSF_ASSERT_TEST(SSFCLIGObjGetArgStrRef(SSF_CLI_MAX_ARGS, gobjArgs, &strOut, &strLen));
        SSF_ASSERT_TEST(SSFCLIGObjGetArgStrRef(0, NULL, &strOut, &strLen));
        SSF_ASSERT_TEST(SSFCLIGObjGetArgStrRef(0, gobjArgs, NULL, &strLen));
        SSF_ASSERT_TEST(SSFCLIGObjGetArgStrRef(0, gobjArgs, &strOut, NULL));

        /* Happy path: index 0 */
        strOut = NULL;
        strLen = 0;
        SSF_ASSERT(SSFCLIGObjGetArgStrRef(0, gobjArgs, &strOut, &strLen));
        SSF_ASSERT(strOut != NULL);
        SSF_ASSERT(strLen == strlen("arg0"));
        SSF_ASSERT(memcmp(strOut, "arg0", strLen + 1) == 0);

        /* Happy path: index 1 */
        strOut = NULL;
        strLen = 0;
        SSF_ASSERT(SSFCLIGObjGetArgStrRef(1, gobjArgs, &strOut, &strLen));
        SSF_ASSERT(strOut != NULL);
        SSF_ASSERT(strLen == strlen("arg1"));
        SSF_ASSERT(memcmp(strOut, "arg1", strLen + 1) == 0);

        /* Out-of-range index (within SSF_CLI_MAX_ARGS) returns false */
        strOut = NULL;
        strLen = 0;
        SSF_ASSERT(SSFCLIGObjGetArgStrRef(2, gobjArgs, &strOut, &strLen) == false);
    }
    SSFArgvDeInit(&gobj);
}
#endif /* SSF_CONFIG_CLI_UNIT_TEST */
