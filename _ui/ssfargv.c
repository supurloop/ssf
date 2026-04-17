/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfargv.c                                                                                     */
/* Parses a command line string into a gobj struct.                                              */
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
/*                                                                                               */
/* <cmd> (//<opt> | /<opt> <arg> | <arg>)...                                                     */
/* cmd - [A-Za-z0-9]+                                                                            */
/* opt - [A-Za-z0-9]+                                                                            */
/* arg - (ASCII printable, ' ', '\', and leading '/' escaped by '\')                             */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "ssfport.h"
#include "ssf.h"
#include "ssfgobj.h"
#include "ssfargv.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_ARGV_ROOT_NUM_CHILDREN (3u)
#define SSF_ARGV_CMD_NUM_CHILDREN (1u)

#define SSF_ARGV_SKIP_WHITESPACE(c) \
    while (*(c) != 0) { if (*(c) == ' ') (c)++; else break; }

#define SSF_ARG_FIND_CMD_NAME(c) \
    while (*(c) != 0) { \
        if (((*(c) >= 'A') && (*(c) <= 'Z')) || \
            ((*(c) >= 'a') && (*(c) <= 'z')) || \
            ((*(c) >= '0') && (*(c) <= '9'))) (c)++; \
        else break; \
    }
#define SSF_ARG_FIND_OPT_NAME(c) SSF_ARG_FIND_CMD_NAME(c)

#define SSF_ARG_FIND_ARG(c) { \
    while (*(c) != 0) { \
        if (*(c) == '\\') { \
            (c)++; \
            if ((*(c) != ' ') && (*(c) != '\\') && (*(c) != '/')) goto SSFArgvInitError; \
            else (c)++; \
        } \
        else if ((*(c) != ' ') && (isprint((unsigned char)*(c)))) (c)++; \
        else if (*(c) == ' ') break; \
        else goto SSFArgvInitError; \
    } \
}

#define SSF_ARGV_IS_SEP(c) if ((*(c) != ' ') && (*(c) != 0)) goto SSFArgvInitError;
#define SSF_ARGV_IS_PARSE_DONE(c) \
    if (*(c) == 0) { \
        retVal = (gobjOptStrTmp == NULL); \
        if (retVal) goto SSFArgvInitExit; \
        goto SSFArgvInitError; \
    }
#define SSF_ARGV_OPT_CHAR '/'

/* --------------------------------------------------------------------------------------------- */
/* Returns true if command line valid and parsed into gobj, else false.                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFArgvInit(SSFCStrIn_t cmdLineStr, size_t cmdLineSize, SSFGObj_t **gobj, uint8_t maxOpts,
                 uint8_t maxArgs)
{
    bool retVal = false;
    SSFGObj_t *gobjCmd = NULL;
    SSFGObj_t *gobjOpts = NULL;
    SSFGObj_t *gobjArgs = NULL;
    SSFGObj_t *gobjCmdTmp = NULL;
    SSFGObj_t *gobjOptsTmp = NULL;
    SSFGObj_t *gobjArgsTmp = NULL;
    SSFGObj_t *gobjOptStr = NULL;
    SSFGObj_t *gobjOptStrTmp = NULL;
    SSFGObj_t *gobjArgStr = NULL;
    SSFCStrOut_t cmdLineCopy = NULL;
    SSFCStrOut_t cursor;
    SSFCStrOut_t marker;
    SSFCStrOut_t tmp;
    size_t len;
    bool isCursorOnSpace;

    SSF_REQUIRE(cmdLineStr != NULL);
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(*gobj == NULL);

    /* Allocate top level ARGV object */
    if (SSFGObjInit(gobj, SSF_ARGV_ROOT_NUM_CHILDREN) == false) goto SSFArgvInitError;

    /* Allocate CMD object */
    if (SSFGObjInit(&gobjCmd, SSF_ARGV_CMD_NUM_CHILDREN) == false) goto SSFArgvInitError;

    /* Allocate OPTS object */
    if (SSFGObjInit(&gobjOpts, maxOpts) == false) goto SSFArgvInitError;

    /* Allocate ARGS object */
    if (SSFGObjInit(&gobjArgs, maxArgs) == false) goto SSFArgvInitError;

    /* Init root obj */
    if (SSFGObjSetObject(*gobj) == false) goto SSFArgvInitError;

    /* Init CMD string */
    if (SSFGObjSetLabel(gobjCmd, SSF_ARGV_CMD_STR) == false) goto SSFArgvInitError;
    if (SSFGObjSetString(gobjCmd, "") == false) goto SSFArgvInitError;

    /* Init OPTS object */
    if (SSFGObjSetLabel(gobjOpts, SSF_ARGV_OPTS_STR) == false) goto SSFArgvInitError;
    if (SSFGObjSetObject(gobjOpts) == false) goto SSFArgvInitError;

    /* Init ARGS object */
    if (SSFGObjSetLabel(gobjArgs, SSF_ARGV_ARGS_STR) == false) goto SSFArgvInitError;
    if (SSFGObjSetArray(gobjArgs) == false) goto SSFArgvInitError;

    /* Insert children into ARGV node */
    if (SSFGObjInsertChild(*gobj, gobjCmd) == false) goto SSFArgvInitError;
    gobjCmdTmp = gobjCmd;
    gobjCmd = NULL;
    if (SSFGObjInsertChild(*gobj, gobjOpts) == false) goto SSFArgvInitError;
    gobjOptsTmp = gobjOpts;
    gobjOpts = NULL;
    if (SSFGObjInsertChild(*gobj, gobjArgs) == false) goto SSFArgvInitError;
    gobjArgsTmp = gobjArgs;
    gobjArgs = NULL;

    /* Copy the command line to make */
    if (SSFStrLen(cmdLineStr, cmdLineSize, &len) == false) goto SSFArgvInitError;
    cmdLineCopy = SSF_MALLOC(len + 1);
    if (cmdLineCopy == NULL) goto SSFArgvInitError;
    memcpy(cmdLineCopy, cmdLineStr, len + 1);

    /* Skip initial whitespace */
    cursor = cmdLineCopy;
    SSF_ARGV_SKIP_WHITESPACE(cursor);

    /* Find a possible CMD match? */
    marker = cursor;
    SSF_ARG_FIND_CMD_NAME(cursor);
    if (marker != cursor)
    {
        /* Yes, if cursor not a seperator then cmd is invalid */
        SSF_ARGV_IS_SEP(cursor);
        isCursorOnSpace = (*cursor == ' ');
        *cursor = 0;
        if (SSFGObjSetString(gobjCmdTmp, marker) == false) goto SSFArgvInitError;
        if (isCursorOnSpace) cursor++;
        SSF_ARGV_IS_PARSE_DONE(cursor);
    }
    /* Must at least have a cmd */
    else goto SSFArgvInitError;

    /* Parse for options and arguments */
    while (*cursor != 0)
    {
        SSF_ARGV_SKIP_WHITESPACE(cursor);
        SSF_ARGV_IS_PARSE_DONE(cursor);

        /* Possible option? */
        if (*cursor == SSF_ARGV_OPT_CHAR)
        {
            bool isOptWithNoArg = (*(cursor + 1) == SSF_ARGV_OPT_CHAR);

            /* Missing argument option? */
            if (gobjOptStrTmp != NULL)  goto SSFArgvInitError;

            /* If option with no arg, advance cursor */
            cursor++;
            if (isOptWithNoArg) cursor++;

            /* Yes, read option name */
            marker = cursor;
            SSF_ARG_FIND_OPT_NAME(cursor)
            if (marker != cursor)
            {
                /* Yes, if cursor not a seperator then opt is invalid */
                SSF_ARGV_IS_SEP(cursor);

                isCursorOnSpace = (*cursor == ' ');
                *cursor = 0;
                if (SSFGObjInit(&gobjOptStr, 0) == false) goto SSFArgvInitError;
                if (SSFGObjSetLabel(gobjOptStr, marker) == false) goto SSFArgvInitError;
                if (SSFGObjSetString(gobjOptStr, "") == false) goto SSFArgvInitError;
                if (SSFGObjInsertChild(gobjOptsTmp, gobjOptStr) == false) goto SSFArgvInitError;
                if (isOptWithNoArg == false) gobjOptStrTmp = gobjOptStr;
                gobjOptStr = NULL;
                if (isCursorOnSpace) cursor++;
                SSF_ARGV_IS_PARSE_DONE(cursor);
            }
            else goto SSFArgvInitError;
        }
        else
        {
            /* Possible argument? */
            /* Yes, read option name */
            marker = cursor;
            SSF_ARG_FIND_ARG(cursor);
            if (marker != cursor)
            {
                /* Yes, if cursor not a seperator then arg is invalid */
                SSF_ARGV_IS_SEP(cursor);
                isCursorOnSpace = (*cursor == ' ');
                *cursor = 0;

                /* Unescape arg */
                tmp = marker;
                while (*tmp != 0)
                {
                    if (*tmp == '\\') { memmove(tmp, tmp + 1, (size_t)(cursor - tmp)); }
                    tmp++;
                }

                /* Looking for opt arg? */
                if (gobjOptStrTmp != NULL)
                {
                    /* Yes, set opt arg */
                    if (SSFGObjSetString(gobjOptStrTmp, marker) == false) goto SSFArgvInitError;
                    gobjOptStrTmp = NULL;
                }
                else
                {
                    /* No, add new arg to args array */
                    if (SSFGObjInit(&gobjArgStr, 0) == false) goto SSFArgvInitError;
                    if (SSFGObjSetString(gobjArgStr, marker) == false) goto SSFArgvInitError;
                    if (SSFGObjInsertChild(gobjArgsTmp, gobjArgStr) == false) goto SSFArgvInitError;
                    gobjArgStr = NULL;
                }
                if (isCursorOnSpace) cursor++;
                SSF_ARGV_IS_PARSE_DONE(cursor);
            }
            else goto SSFArgvInitError;
        }
    }

SSFArgvInitError:
    if (gobjArgStr != NULL) SSFGObjDeInit(&gobjArgStr);
    if (gobjOptStr != NULL) SSFGObjDeInit(&gobjOptStr);
    if (gobjArgs != NULL) SSFGObjDeInit(&gobjArgs);
    if (gobjOpts != NULL) SSFGObjDeInit(&gobjOpts);
    if (gobjCmd != NULL) SSFGObjDeInit(&gobjCmd);
    if (*gobj != NULL) SSFGObjDeInit(gobj);

SSFArgvInitExit:
    if (cmdLineCopy != NULL)
    {
        SSF_FREE(cmdLineCopy);
        cmdLineCopy = NULL;
    }
    return retVal;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinits a gobj allocated by SSFArgvInit().                                                    */
/* --------------------------------------------------------------------------------------------- */
void SSFArgvDeInit(SSFGObj_t **gobj)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(*gobj != NULL);

    SSFGObjDeInit(gobj);
}

