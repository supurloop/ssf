/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfvted.c                                                                                     */
/* Provides a line editor that consumes ANSI/VT100 input escape sequences and emits ANSI/VT100   */
/* output escape sequences to keep an attached terminal display in sync with an internal line    */
/* buffer.                                                                                       */
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
#include <ctype.h>
#include "ssfassert.h"
#include "ssfport.h"
#include "ssf.h"
#include "ssfvted.h"

/* --------------------------------------------------------------------------------------------- */
/* Module Defines                                                                                */
/* --------------------------------------------------------------------------------------------- */
#define SSF_VTED_MAGIC      (0x6ace9108u)
#define SSF_VTED_IN_ESC     ('\x1b')    /* ANSI ESC introducer */
#define SSF_VTED_IN_CSI     ('[')       /* CSI — Control Sequence Introducer (after ESC) */
#define SSF_VTED_IN_SS3     ('O')       /* SS3 — Single Shift 3 (xterm application cursor mode) */
#define SSF_VTED_IN_UP      ('A')       /* CSI/SS3 final byte for Arrow Up */
#define SSF_VTED_IN_DOWN    ('B')       /* CSI/SS3 final byte for Arrow Down */
#define SSF_VTED_IN_RIGHT   ('C')       /* CSI/SS3 final byte for Arrow Right */
#define SSF_VTED_IN_LEFT    ('D')       /* CSI/SS3 final byte for Arrow Left */
#define SSF_VTED_IN_DEL_NUM ('3')       /* CSI parameter digit for the Delete sequence */
#define SSF_VTED_IN_DEL_FIN ('~')       /* CSI final byte for the Delete sequence */
#define SSF_VTED_IN_BS      ('\b')      /* Traditional backspace (0x08) */
#define SSF_VTED_IN_BS_ALT  ('\x7f')    /* Modern terminal backspace (DEL char 0x7F) */
#define SSF_VTED_IN_CR      ('\r')
#define SSF_VTED_IN_CTRLC   ('\x03')

/* --------------------------------------------------------------------------------------------- */
/* Module Data                                                                                   */
/* --------------------------------------------------------------------------------------------- */
const uint8_t _ssfOutEscLeft[] = { '\x1b', '[', 'D' };
const uint8_t _ssfOutEscRight[] = { '\x1b', '[', 'C' };
const uint8_t _ssfOutEscDel[] = { '\x1b', '[', 'P' };
const uint8_t _ssfOutEscBs[] = { '\x1b', '[', 'P' };
const uint8_t _ssfOutEscIns[] = { '\x1b', '[', '@' };
const uint8_t _ssfOutEscClrLine[] = { '\x1b', '[', '2', 'K', '\r'}; /* Resets cursor too */

/* --------------------------------------------------------------------------------------------- */
/* Initializes a line editing context.                                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFVTEdInit(SSFVTEdContext_t *context, SSFCStrOut_t lineBuf, size_t lineSize,
                 SSFVTEdWriteStdoutFn_t writeStdoutFn)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == 0);
    SSF_REQUIRE(lineBuf != 0);
    SSF_REQUIRE(lineSize > 0);
    SSF_REQUIRE(writeStdoutFn != NULL);

    memset(context, 0, sizeof(SSFVTEdContext_t));
    context->line = lineBuf;
    context->lineSize = lineSize;
    context->writeStdoutFn = writeStdoutFn;
    context->magic = SSF_VTED_MAGIC;
    SSFVTEdReset(context);
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes a line editing context.                                                         */
/* --------------------------------------------------------------------------------------------- */
void SSFVTEdDeInit(SSFVTEdContext_t *context)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_VTED_MAGIC);
    memset(context, 0, sizeof(SSFVTEdContext_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if context is inited, else false.                                                */
/* --------------------------------------------------------------------------------------------- */
bool SSFVTEdIsInited(SSFVTEdContext_t *context)
{
    SSF_REQUIRE(context != NULL);
    return (context->magic == SSF_VTED_MAGIC);
}

/* --------------------------------------------------------------------------------------------- */
/* Moves the cursor one position left and optionally clears a trailing auto-added space.        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFVTEdHandleLeft(SSFVTEdContext_t *context)
{
    SSF_REQUIRE(context != NULL);

    /* Cursor not all the way left? */
    if (context->cursor > 0)
    {
        /* Yes, move cursor left */
        context->writeStdoutFn(_ssfOutEscLeft, sizeof(_ssfOutEscLeft));
        /* Trailing space? */
        if ((context->cursor == context->lineLen) &&
            (context->line[context->cursor - 1] == ' '))
        {
            /* Yes, clear the trailing space */
            context->cursor--;
            context->line[context->cursor] = 0;
            context->lineLen = strlen(context->line);
        }
        else context->cursor--;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Moves the cursor one position right and optionally auto-adds a trailing space.               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFVTEdHandleRight(SSFVTEdContext_t *context)
{
    SSF_REQUIRE(context != NULL);

    /* Cursor not all the way right? */
    if (context->cursor < (context->lineSize - 1))
    {
        /* Yes, move cursor right */
        context->writeStdoutFn(_ssfOutEscRight, sizeof(_ssfOutEscRight));
        /* Need to add a space? */
        if ((context->cursor >= context->lineLen) &&
            (context->line[context->cursor] == 0))
        {
            /* Yes, add a space */
            context->line[context->cursor] = ' ';
            context->lineLen = strlen(context->line);
        }
        context->cursor++;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Deletes the char at the cursor and shifts the trailing chars one position left.              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFVTEdHandleDel(SSFVTEdContext_t *context)
{
    SSF_REQUIRE(context != NULL);

    /* Cursor not at end of line? */
    if (context->cursor < (context->lineSize - 1))
    {
        /* Yes, delete char and move remaining chars to the left */
        context->writeStdoutFn(_ssfOutEscDel, sizeof(_ssfOutEscDel));
        memmove(&context->line[context->cursor],
                &context->line[context->cursor + 1],
                (context->lineSize - 1) - context->cursor);
        context->lineLen = strlen(context->line);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Removes the char before the cursor and shifts the trailing chars one position left.          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFVTEdHandleBs(SSFVTEdContext_t *context)
{
    uint8_t bsChar = SSF_VTED_IN_BS;

    SSF_REQUIRE(context != NULL);

    /* Cursor not at beginning? */
    if (context->cursor > 0)
    {
        /* Yes, remove the char and move all trailing chars left */
        context->cursor--;
        memmove(&context->line[context->cursor],
                &context->line[context->cursor + 1],
                (context->lineSize - 1) - context->cursor);
        context->lineLen = strlen(context->line);
        context->writeStdoutFn(&bsChar, sizeof(bsChar));
        context->writeStdoutFn(_ssfOutEscBs, sizeof(_ssfOutEscBs));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Inserts the supplied printable char at the cursor position.                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFVTEdHandlePrintable(SSFVTEdContext_t *context, uint8_t inChar)
{
    SSF_REQUIRE(context != NULL);

    /* Room to insert? */
    if ((context->cursor < (context->lineSize - 1)) &&
        (context->lineLen < (context->lineSize - 1)))
    {
        /* Yes, shift bytes right of cursor 1 byte right and insert new char */
        memmove(&context->line[context->cursor + 1],
                &context->line[context->cursor],
                (context->lineSize - 1) - context->cursor);
        context->line[context->cursor] = inChar;
        context->cursor++;
        context->lineLen = strlen(context->line);
        context->writeStdoutFn(_ssfOutEscIns, sizeof(_ssfOutEscIns));
        context->writeStdoutFn(&inChar, sizeof(inChar));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Sync line with terminal, returns true if unhandled ESC detected + sets codeOut, else false.   */
/* --------------------------------------------------------------------------------------------- */
bool SSFVTEdProcessChar(SSFVTEdContext_t *context, uint8_t inChar, SSFVTEdEscCode_t *escOut)
{
    bool retVal = false;

    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_VTED_MAGIC);
    SSF_REQUIRE(escOut != NULL);
    switch (context->escState)
    {
    case SSF_VTED_ESC_STATE_IDLE:
        /* ESC introducer? */
        if (inChar == SSF_VTED_IN_ESC)
        {
            context->escState = SSF_VTED_ESC_STATE_ESC;
        }
        /* Backspace (0x08 or 0x7F)? */
        else if ((inChar == SSF_VTED_IN_BS) || (inChar == SSF_VTED_IN_BS_ALT))
        {
            _SSFVTEdHandleBs(context);
        }
        /* Enter? */
        else if (inChar == SSF_VTED_IN_CR)
        {
            *escOut = SSF_VTED_ESC_CODE_ENTER;
            retVal = true;
        }
        /* Ctrl-C? */
        else if (inChar == SSF_VTED_IN_CTRLC)
        {
            *escOut = SSF_VTED_ESC_CODE_CTRLC;
            retVal = true;
        }
        /* Printable? */
        else if (isprint(inChar))
        {
            _SSFVTEdHandlePrintable(context, inChar);
        }
        /* Else: silently ignore */
        break;

    case SSF_VTED_ESC_STATE_ESC:
        /* CSI — Control Sequence Introducer */
        if (inChar == SSF_VTED_IN_CSI)
        {
            context->escState = SSF_VTED_ESC_STATE_CSI;
        }
        /* SS3 — xterm application cursor keys mode */
        else if (inChar == SSF_VTED_IN_SS3)
        {
            context->escState = SSF_VTED_ESC_STATE_SS3;
        }
        /* Another ESC restarts the sequence — stay in ESC state */
        else if (inChar == SSF_VTED_IN_ESC)
        {
            /* No state change */
        }
        /* Malformed sequence; abandon */
        else
        {
            context->escState = SSF_VTED_ESC_STATE_IDLE;
        }
        break;

    case SSF_VTED_ESC_STATE_CSI:
        switch (inChar)
        {
        case SSF_VTED_IN_UP:
            *escOut = SSF_VTED_ESC_CODE_UP;
            retVal = true;
            context->escState = SSF_VTED_ESC_STATE_IDLE;
            break;
        case SSF_VTED_IN_DOWN:
            *escOut = SSF_VTED_ESC_CODE_DOWN;
            retVal = true;
            context->escState = SSF_VTED_ESC_STATE_IDLE;
            break;
        case SSF_VTED_IN_RIGHT:
            _SSFVTEdHandleRight(context);
            context->escState = SSF_VTED_ESC_STATE_IDLE;
            break;
        case SSF_VTED_IN_LEFT:
            _SSFVTEdHandleLeft(context);
            context->escState = SSF_VTED_ESC_STATE_IDLE;
            break;
        case SSF_VTED_IN_DEL_NUM:
            /* Intermediate — awaiting '~' to complete the Delete sequence */
            context->escState = SSF_VTED_ESC_STATE_CSI_3;
            break;
        case SSF_VTED_IN_ESC:
            /* Restart */
            context->escState = SSF_VTED_ESC_STATE_ESC;
            break;
        default:
            /* Malformed or unsupported CSI final byte; abandon */
            context->escState = SSF_VTED_ESC_STATE_IDLE;
            break;
        }
        break;

    case SSF_VTED_ESC_STATE_CSI_3:
        /* Expecting '~' to complete ESC [ 3 ~ */
        if (inChar == SSF_VTED_IN_DEL_FIN)
        {
            _SSFVTEdHandleDel(context);
            context->escState = SSF_VTED_ESC_STATE_IDLE;
        }
        else if (inChar == SSF_VTED_IN_ESC)
        {
            context->escState = SSF_VTED_ESC_STATE_ESC;
        }
        else
        {
            context->escState = SSF_VTED_ESC_STATE_IDLE;
        }
        break;

    case SSF_VTED_ESC_STATE_SS3:
        switch (inChar)
        {
        case SSF_VTED_IN_UP:
            *escOut = SSF_VTED_ESC_CODE_UP;
            retVal = true;
            context->escState = SSF_VTED_ESC_STATE_IDLE;
            break;
        case SSF_VTED_IN_DOWN:
            *escOut = SSF_VTED_ESC_CODE_DOWN;
            retVal = true;
            context->escState = SSF_VTED_ESC_STATE_IDLE;
            break;
        case SSF_VTED_IN_RIGHT:
            _SSFVTEdHandleRight(context);
            context->escState = SSF_VTED_ESC_STATE_IDLE;
            break;
        case SSF_VTED_IN_LEFT:
            _SSFVTEdHandleLeft(context);
            context->escState = SSF_VTED_ESC_STATE_IDLE;
            break;
        case SSF_VTED_IN_ESC:
            context->escState = SSF_VTED_ESC_STATE_ESC;
            break;
        default:
            context->escState = SSF_VTED_ESC_STATE_IDLE;
            break;
        }
        break;

    default:
        SSF_ERROR();
        break;
    }
    return retVal;
}

/* --------------------------------------------------------------------------------------------- */
/* Resets the context's line buffer state and escape decoder state, and sync with terminal.      */
/* --------------------------------------------------------------------------------------------- */
void SSFVTEdReset(SSFVTEdContext_t *context)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_VTED_MAGIC);

    memset(context->line, 0, context->lineSize);
    context->cursor = 0;
    context->lineLen = 0;
    context->escState = SSF_VTED_ESC_STATE_IDLE;

    /* Display the prompt. */
    context->writeStdoutFn((const uint8_t *)SSF_VTED_PROMPT_STR, SSF_VTED_PROMPT_STR_SIZE);
}

/* --------------------------------------------------------------------------------------------- */
/* Sets the context's line buffer state and escape decoder state, and sync with terminal.        */
/* --------------------------------------------------------------------------------------------- */
void SSFVTEdSet(SSFVTEdContext_t *context, SSFCStrIn_t cmdStr, size_t cmdStrSize)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_VTED_MAGIC);
    SSF_REQUIRE(cmdStr != NULL);
    SSF_REQUIRE(cmdStrSize <= context->lineSize);

    context->writeStdoutFn(_ssfOutEscClrLine, sizeof(_ssfOutEscClrLine));
    context->writeStdoutFn((const uint8_t *)SSF_VTED_PROMPT_BASE_STR, SSF_VTED_PROMPT_BASE_STR_SIZE);

    memcpy(context->line, cmdStr, cmdStrSize);
    memset(&context->line[cmdStrSize], 0, context->lineSize - cmdStrSize);
    context->lineLen = strlen(context->line);
    context->cursor = context->lineLen;

    /* Display the command. */
    context->writeStdoutFn((const uint8_t *)context->line, context->lineLen);
}

