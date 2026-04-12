/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfvted.h                                                                                     */
/* Provides a line editor that consumes ANSI/VT100 input escape sequences and emits ANSI/VT100  */
/* output escape sequences to keep an attached terminal display in sync with an internal line   */
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
#ifndef SSF_VTED_INCLUDE_H
#define SSF_VTED_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssf.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef enum
{
    SSF_VTED_ESC_CODE_MIN = -1,
    SSF_VTED_ESC_CODE_UP,
    SSF_VTED_ESC_CODE_DOWN,
    SSF_VTED_ESC_CODE_ENTER,
    SSF_VTED_ESC_CODE_CTRLC,
    SSF_VTED_ESC_CODE_MAX
} SSFVTEdEscCode_t;

/* Input escape sequence decoder state.                                                          */
/* Recognized VT100 input sequences:                                                             */
/*     ESC [ A        Arrow Up                                                                   */
/*     ESC [ B        Arrow Down                                                                 */
/*     ESC [ C        Arrow Right                                                                */
/*     ESC [ D        Arrow Left                                                                 */
/*     ESC [ 3 ~      Delete                                                                     */
/*     ESC O A/B/C/D  Arrows (xterm application cursor keys mode)                                */
typedef enum
{
    SSF_VTED_ESC_STATE_IDLE,  /* No escape sequence in progress */
    SSF_VTED_ESC_STATE_ESC,   /* Saw ESC (0x1B), awaiting '[' or 'O' */
    SSF_VTED_ESC_STATE_CSI,   /* Saw ESC [, awaiting final byte or parameter digit */
    SSF_VTED_ESC_STATE_CSI_3, /* Saw ESC [ 3, awaiting '~' to complete the Delete sequence */
    SSF_VTED_ESC_STATE_SS3    /* Saw ESC O, awaiting final byte (xterm application cursor mode) */
} SSFVTEdEscState_t;

typedef void (*SSFVTEdWriteStdoutFn_t)(const uint8_t *data, size_t dataLen);

typedef struct
{
    SSFCStrOut_t line;
    size_t lineLen;
    size_t lineSize;
    size_t cursor;
    SSFVTEdEscState_t escState;
    SSFVTEdWriteStdoutFn_t writeStdoutFn;
    uint32_t magic;
} SSFVTEdContext_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFVTEdInit(SSFVTEdContext_t *context, SSFCStrOut_t lineBuf, size_t lineSize,
                 SSFVTEdWriteStdoutFn_t writeStdoutFn);
void SSFVTEdDeInit(SSFVTEdContext_t *context);
bool SSFVTEdIsInited(SSFVTEdContext_t *context);
bool SSFVTEdProcessChar(SSFVTEdContext_t *context, uint8_t inChar, SSFVTEdEscCode_t *escOut);
void SSFVTEdReset(SSFVTEdContext_t *context);
void SSFVTEdSet(SSFVTEdContext_t *context, SSFCStrIn_t cmdStr, size_t cmdStrSize);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_VTED_UNIT_TEST == 1
void SSFVTEdUnitTest(void);
#endif /* SSF_CONFIG_VTED_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_VTED_INCLUDE_H */

