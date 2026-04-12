/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcli.c                                                                                      */
/* Provides a CLI framework.                                                                     */
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
#include "ssfassert.h"
#include "ssfport.h"
#include "ssf.h"
#include "ssfargv.h"
#include "ssfvted.h"
#include "ssfll.h"
#include "ssfcli.h"
#include "ssfoptions.h"

/* --------------------------------------------------------------------------------------------- */
/* Module defines                                                                                */
/* --------------------------------------------------------------------------------------------- */
#define SSF_CLI_MAGIC (0xa6ec881cu)

#define SSF_CLI_SYNTAX_STR_1  "# <cmd> [(//<opt> | /<opt> <arg> | <arg>)]...\r\n\r\n"
#define SSF_CLI_SYNTAX_STR_2  "  <cmd> - One or more A-Z, a-z, and 0-9 chars\r\n"
#define SSF_CLI_SYNTAX_STR_3  "  <opt> - One or more A-Z, a-z, and 0-9 chars\r\n"
#define SSF_CLI_SYNTAX_STR_4  "  <arg> - One or more printable chars, ' ', '\\', leading '/' escaped by '\\'\r\n\r\n"
#define SSF_CLI_SYNTAX_STR_5  "  <ENTER>       - Run command\r\n"
#define SSF_CLI_SYNTAX_STR_6  "  <DEL>         - Delete char at cursor\r\n"
#define SSF_CLI_SYNTAX_STR_7  "  <BACKSPACE>   - Delete char behind cursor\r\n"
#define SSF_CLI_SYNTAX_STR_8  "  <CTRL-C>      - New prompt\r\n\r\n"
#define SSF_CLI_SYNTAX_STR_9  "  <LEFT  ARROW> - Move cursor left\r\n"
#define SSF_CLI_SYNTAX_STR_10 "  <RIGHT ARROW> - Move cursor right\r\n"
#define SSF_CLI_SYNTAX_STR_11 "  <UP    ARROW> - Show previous command\r\n"
#define SSF_CLI_SYNTAX_STR_12 "  <DOWN  ARROW> - Show next command\r\n"

#define SSF_CLI_SYNTAX_STR_1_SIZE  (sizeof(SSF_CLI_SYNTAX_STR_1) - 1)
#define SSF_CLI_SYNTAX_STR_2_SIZE  (sizeof(SSF_CLI_SYNTAX_STR_2) - 1)
#define SSF_CLI_SYNTAX_STR_3_SIZE  (sizeof(SSF_CLI_SYNTAX_STR_3) - 1)
#define SSF_CLI_SYNTAX_STR_4_SIZE  (sizeof(SSF_CLI_SYNTAX_STR_4) - 1)
#define SSF_CLI_SYNTAX_STR_5_SIZE  (sizeof(SSF_CLI_SYNTAX_STR_5) - 1)
#define SSF_CLI_SYNTAX_STR_6_SIZE  (sizeof(SSF_CLI_SYNTAX_STR_6) - 1)
#define SSF_CLI_SYNTAX_STR_7_SIZE  (sizeof(SSF_CLI_SYNTAX_STR_7) - 1)
#define SSF_CLI_SYNTAX_STR_8_SIZE  (sizeof(SSF_CLI_SYNTAX_STR_8) - 1)
#define SSF_CLI_SYNTAX_STR_9_SIZE  (sizeof(SSF_CLI_SYNTAX_STR_9) - 1)
#define SSF_CLI_SYNTAX_STR_10_SIZE (sizeof(SSF_CLI_SYNTAX_STR_10) - 1)
#define SSF_CLI_SYNTAX_STR_11_SIZE (sizeof(SSF_CLI_SYNTAX_STR_11) - 1)
#define SSF_CLI_SYNTAX_STR_12_SIZE (sizeof(SSF_CLI_SYNTAX_STR_12) - 1)

typedef struct
{
    SSFLLItem_t item;
    SSFCStrOut_t cmdStr;
} SSFCLIHist_t;

/* --------------------------------------------------------------------------------------------- */
/* Displays CLI command line syntax.                                                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFCLIWriteCmdLineSyntax(SSFCLIContext_t *context)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_CLI_MAGIC);
    context->vtEdCtx->writeStdoutFn((const uint8_t*)"\r\n", 2);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_1,
                                    SSF_CLI_SYNTAX_STR_1_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_2,
                                    SSF_CLI_SYNTAX_STR_2_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_3,
                                    SSF_CLI_SYNTAX_STR_3_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_4,
                                    SSF_CLI_SYNTAX_STR_4_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_5,
                                    SSF_CLI_SYNTAX_STR_5_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_6,
                                    SSF_CLI_SYNTAX_STR_6_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_7,
                                    SSF_CLI_SYNTAX_STR_7_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_8,
                                    SSF_CLI_SYNTAX_STR_8_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_9,
                                    SSF_CLI_SYNTAX_STR_9_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_10,
                                    SSF_CLI_SYNTAX_STR_10_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_11,
                                    SSF_CLI_SYNTAX_STR_11_SIZE);
    context->vtEdCtx->writeStdoutFn((const uint8_t *)SSF_CLI_SYNTAX_STR_12,
                                    SSF_CLI_SYNTAX_STR_12_SIZE);
}

/* --------------------------------------------------------------------------------------------- */
/* Displays CLI commands.                                                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFCLIWriteCmds(SSFCLIContext_t *context)
{
    SSFLLItem_t *item;
    SSFLLItem_t *prev;
    SSFCLICmd_t cmd;

    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_CLI_MAGIC);

    context->vtEdCtx->writeStdoutFn((const uint8_t*)"\r\n", 2);

    item = SSF_LL_TAIL(&context->cmds);
    while (item != NULL)
    {
        prev = SSF_LL_PREV_ITEM(item);
        memcpy(&cmd, item, sizeof(cmd)); /* Ensure alignment */
        context->vtEdCtx->writeStdoutFn((const uint8_t *)cmd.cmdStr, strlen(cmd.cmdStr));
        context->vtEdCtx->writeStdoutFn((const uint8_t *)" - ", 3);
        context->vtEdCtx->writeStdoutFn((const uint8_t *)cmd.cmdSyntaxStr,
                                        strlen(cmd.cmdSyntaxStr));
        context->vtEdCtx->writeStdoutFn((const uint8_t *)"\r\n", 2);
        item = prev;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Inits a CLI context.                                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFCLIInit(SSFCLIContext_t *context, uint16_t maxCmds, uint8_t maxCmdHist,
                uint8_t *cmdHistBuf, size_t cmdHistBufSize, SSFVTEdContext_t *vtEdCtx)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == 0);
    SSF_REQUIRE((maxCmds > 0) && (maxCmds <= SSF_CLI_MAX_CMDS));
    SSF_REQUIRE(maxCmdHist <= SSF_CLI_MAX_CMD_HIST);
    SSF_REQUIRE(vtEdCtx != NULL);
    SSF_REQUIRE(SSFVTEdIsInited(vtEdCtx));
    if (maxCmdHist == 0)
    {
        SSF_REQUIRE(cmdHistBuf == NULL);
        SSF_REQUIRE(cmdHistBufSize == 0);
    }
    else
    {
        SSF_REQUIRE(cmdHistBuf != NULL);
        SSF_REQUIRE(cmdHistBufSize >= (vtEdCtx->lineSize * maxCmdHist));
    }

    memset(context, 0, sizeof(SSFCLIContext_t));
    SSFLLInit(&context->cmds, maxCmds);
    context->vtEdCtx = vtEdCtx;
    context->numCmdHist = maxCmdHist;
    context->cmdHistBufSize = cmdHistBufSize;
    context->cmdHistBuf = cmdHistBuf;
    if (context->numCmdHist > 0)
    {
        memset(context->cmdHistBuf, 0, context->cmdHistBufSize);
    }
    context->magic = SSF_CLI_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* DeInits a CLI context.                                                                        */
/* --------------------------------------------------------------------------------------------- */
void SSFCLIDeInit(SSFCLIContext_t *context)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_CLI_MAGIC);

    SSF_ASSERT(SSFLLIsEmpty(&context->cmds));
    SSFLLDeInit(&context->cmds);
    memset(context, 0, sizeof(SSFCLIContext_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Adds a command to a CLI context.                                                              */
/* --------------------------------------------------------------------------------------------- */
void SSFCLIInitCmd(SSFCLIContext_t *context, SSFCLICmd_t *cmd)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_CLI_MAGIC);
    SSF_REQUIRE(cmd != NULL);
    SSF_REQUIRE(cmd->cmdStr != NULL);
    SSF_REQUIRE(cmd->cmdSyntaxStr != NULL);
    SSF_REQUIRE(cmd->cmdFn != NULL);

    SSF_ASSERT(SSFLLIsFull(&context->cmds) == false);
    SSF_LL_FIFO_PUSH(&context->cmds, cmd);
}

/* --------------------------------------------------------------------------------------------- */
/* Removes a command from a CLI context.                                                         */
/* --------------------------------------------------------------------------------------------- */
void SSFCLIDeInitCmd(SSFCLIContext_t *context, SSFCLICmd_t *cmd)
{
    SSFCLICmd_t *cmdOut;

    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_CLI_MAGIC);
    SSF_REQUIRE(cmd != NULL);
    SSF_ASSERT(SSF_LL_GET(&context->cmds, &cmdOut, cmd));
}

/* --------------------------------------------------------------------------------------------- */
/* Processes an input char in a CLI context.                                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFCLIProcessChar(SSFCLIContext_t *context, uint8_t inChar)
{
    SSFVTEdEscCode_t escCode;
    SSFGObj_t *gobj = NULL;

    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_CLI_MAGIC);

    if (SSFVTEdProcessChar(context->vtEdCtx, inChar, &escCode))
    {
        switch (escCode)
        {
        case SSF_VTED_ESC_CODE_CTRLC:
            SSFVTEdReset(context->vtEdCtx);
            break;

        case SSF_VTED_ESC_CODE_ENTER:
            /* Command history tracked? */
            if (context->numCmdHist > 0)
            {
                /* Yes, command entered? */
                if (context->vtEdCtx->line[0] != 0)
                {
                    /* Yes, save the command in history */
                    memcpy(&context->cmdHistBuf[context->cmdHistBufIndex *
                                                context->vtEdCtx->lineSize],
                           context->vtEdCtx->line, context->vtEdCtx->lineSize);
                    context->cmdHistBufIndex++;
                    if (context->cmdHistBufIndex >= context->numCmdHist)
                    { context->cmdHistBufIndex = 0; }
                }
            }

            /* Successfully process the command line? */
            if (SSFArgvInit(context->vtEdCtx->line, context->vtEdCtx->lineSize, &gobj,
                            SSF_CLI_MAX_OPTS, SSF_CLI_MAX_ARGS))
            {
                SSFLLItem_t *item;
                SSFLLItem_t *next;
                SSFCLICmd_t cmd;
                SSFGObj_t *gobjParent = NULL;
                SSFGObj_t *gobjCmd = NULL;
                SSFGObj_t *gobjOpts = NULL;
                SSFGObj_t *gobjArgs = NULL;
                char *path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];

                /* Yes, get command, opts, and args objs */
                memset(path, 0, sizeof(path));
                path[0] = SSF_ARGV_CMD_CSTR;
                SSF_ASSERT(SSFGObjFindPath(gobj, (SSFCStrIn_t *)path, &gobjParent, &gobjCmd));
                gobjParent = NULL;
                path[0] = SSF_ARGV_OPTS_CSTR;
                SSF_ASSERT(SSFGObjFindPath(gobj, (SSFCStrIn_t *)path, &gobjParent, &gobjOpts));
                gobjParent = NULL;
                path[0] = SSF_ARGV_ARGS_CSTR;
                SSF_ASSERT(SSFGObjFindPath(gobj, (SSFCStrIn_t *)path, &gobjParent, &gobjArgs));

                /* Search command list for exactly matching command */
                item = SSF_LL_HEAD(&context->cmds);
                while (item != NULL)
                {
                    next = SSF_LL_NEXT_ITEM(item);
                    memcpy(&cmd, item, sizeof(cmd)); /* Ensure alignment */
                    if (SSFStrCmp(cmd.cmdStr, SSF_CLI_MAX_CMD_LINE_SIZE,
                                 (SSFCStrIn_t)gobjCmd->data, SSF_CLI_MAX_CMD_LINE_SIZE))
                    {
                        /* Run the command */
                        uint32_t numOpts;
                        uint32_t numArgs;

                        SSF_ASSERT(SSFGObjGetObjectLen(gobjOpts, &numOpts));
                        SSF_ASSERT(SSFGObjGetArrayLen(gobjArgs, &numArgs));

                        context->vtEdCtx->writeStdoutFn((const uint8_t*)"\r\n", 2);
                        /* Command successful? */
                        if (cmd.cmdFn(gobjCmd, numOpts, gobjOpts, numArgs, gobjArgs,
                                      context->vtEdCtx->writeStdoutFn) == false)
                        {
                            /* No, print the command syntax */
                            context->vtEdCtx->writeStdoutFn((const uint8_t *)cmd.cmdSyntaxStr,
                                                            strlen(cmd.cmdSyntaxStr));
                        }
                        context->vtEdCtx->writeStdoutFn((const uint8_t*)"\r\n", 2);
                        break;
                    }
                    item = next;
                }
                /* cmd matched? */
                if (item == NULL)
                {
                    /* No, indicate cmd not found */
                    _SSFCLIWriteCmds(context);
                }

                /* Free the parse context and reset the command line */
                SSFArgvDeInit(&gobj);
                SSFVTEdReset(context->vtEdCtx);
            }
            else
            {
                /* No, parse failed */
                /* Did user enter anything? */
                if (context->vtEdCtx->lineLen > 0)
                {
                    /* Yes, display correct CLI syntax */
                    _SSFCLIWriteCmdLineSyntax(context);
                }
                else
                {
                    /* No, display list of commands */
                    _SSFCLIWriteCmds(context);
                }
                SSFVTEdReset(context->vtEdCtx);
            }
            break;

        case SSF_VTED_ESC_CODE_UP:
            /* Command history tracked? */
            if (context->numCmdHist > 0)
            {
                int16_t i = -1;

                /* Yes, look for a non-empty history */
                do
                {
                    i++;
                    context->cmdHistBufIndex--;
                    if (context->cmdHistBufIndex < 0)
                    { context->cmdHistBufIndex = context->numCmdHist - 1; }
                } while ((context->cmdHistBuf[context->cmdHistBufIndex *
                                              context->vtEdCtx->lineSize] == 0) &&
                         (i < context->numCmdHist));

                /* Found non-empty history? */
                if (i != context->numCmdHist)
                {
                    /* Yes, show it */
                    SSFVTEdSet(context->vtEdCtx,
                               (SSFCStrIn_t)&context->cmdHistBuf[context->cmdHistBufIndex *
                                                                 context->vtEdCtx->lineSize],
                               strlen((const char *)
                                      &context->cmdHistBuf[context->cmdHistBufIndex *
                                                           context->vtEdCtx->lineSize]));
                }
                else
                {
                    /* No, blank the line */
                    SSFVTEdSet(context->vtEdCtx, "", 1);
                }
            }
            break;

        case SSF_VTED_ESC_CODE_DOWN:
            /* Command history tracked? */
            if (context->numCmdHist > 0)
            {
                int16_t i = -1;

                /* Yes, look for a non-empty history */
                do
                {
                    i++;
                    context->cmdHistBufIndex++;
                    if (context->cmdHistBufIndex >= context->numCmdHist)
                    { context->cmdHistBufIndex = 0; }
                }  while ((context->cmdHistBuf[context->cmdHistBufIndex *
                                               context->vtEdCtx->lineSize] == 0) &&
                          (i < context->numCmdHist));

                /* Found non-empty history? */
                if (i != context->numCmdHist)
                {
                    /* Yes, show it */
                    SSFVTEdSet(context->vtEdCtx,
                               (SSFCStrIn_t)&context->cmdHistBuf[context->cmdHistBufIndex *
                                                                 context->vtEdCtx->lineSize],
                               strlen((const char *)
                                      &context->cmdHistBuf[context->cmdHistBufIndex *
                                                           context->vtEdCtx->lineSize]));
                }
                else
                {
                    /* No, blank the line */
                    SSFVTEdSet(context->vtEdCtx, "", 1);
                }
            }
            break;

        default:
            break;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if option with arg found and strOut, strLen set, else false.                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFCLIGObjGetOptArgStrRef(SSFCStrOut_t optStr, SSFGObj_t *gobjOpts, SSFCStrOut_t *strOut,
                               size_t *strLen)
{
    SSFGObj_t *gobjParent = NULL;
    SSFGObj_t *gobjArg = NULL;
    char *path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];

    SSF_REQUIRE(optStr != NULL);
    SSF_REQUIRE(gobjOpts != NULL);
    SSF_REQUIRE(strOut != NULL);
    SSF_REQUIRE(strLen != NULL);

    memset(path, 0, sizeof(path));
    path[0] = optStr;
    if (SSFGObjFindPath(gobjOpts, (SSFCStrIn_t *)path, &gobjParent, &gobjArg) == false) return false;

    SSF_ASSERT(gobjArg->dataType == SSF_OBJ_TYPE_STR);
    SSF_ASSERT(gobjArg->data != NULL);
    SSF_ASSERT(gobjArg->dataSize > 0);
    *strOut = gobjArg->data;
    *strLen = gobjArg->dataSize - 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if option with no arg found, else false.                                         */
/* --------------------------------------------------------------------------------------------- */
bool SSFCLIGObjGetIsOpt(SSFCStrOut_t optStr, SSFGObj_t *gobjOpts)
{
    SSFGObj_t *gobjParent = NULL;
    SSFGObj_t *gobjArg = NULL;
    char *path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];

    SSF_REQUIRE(optStr != NULL);
    SSF_REQUIRE(gobjOpts != NULL);

    memset(path, 0, sizeof(path));
    path[0] = optStr;
    if (SSFGObjFindPath(gobjOpts, (SSFCStrIn_t *)path, &gobjParent, &gobjArg) == false) return false;

    SSF_ASSERT(gobjArg->dataType == SSF_OBJ_TYPE_STR);
    SSF_ASSERT(gobjArg->data != NULL);
    SSF_ASSERT(gobjArg->dataSize > 0);
    return (gobjArg->dataSize == 1);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if arg found strOut, strLen set, else false.                                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFCLIGObjGetArgStrRef(size_t argIndex, SSFGObj_t *gobjArgs, SSFCStrOut_t *strOut,
                            size_t *strLen)
{
    SSFGObj_t *gobjParent = NULL;
    SSFGObj_t *gobjArg = NULL;
    char *path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];

    SSF_REQUIRE(argIndex < SSF_CLI_MAX_ARGS);
    SSF_REQUIRE(gobjArgs != NULL);
    SSF_REQUIRE(strOut != NULL);
    SSF_REQUIRE(strLen != NULL);

    memset(path, 0, sizeof(path));
    path[0] = (char *)&argIndex;
    if (SSFGObjFindPath(gobjArgs, (SSFCStrIn_t *)path, &gobjParent, &gobjArg) == false) return false;

    SSF_ASSERT(gobjArg->dataType == SSF_OBJ_TYPE_STR);
    SSF_ASSERT(gobjArg->data != NULL);
    SSF_ASSERT(gobjArg->dataSize > 0);
    *strOut = gobjArg->data;
    *strLen = gobjArg->dataSize - 1;
    return true;
}

