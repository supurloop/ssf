/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfini.h                                                                                      */
/* Provides parser/generator interface for basic INI file format.                                */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2022 Supurloop Software LLC                                                         */
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
#ifndef SSFINI_H_INCLUDE
#define SSFINI_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef enum
{
    SSF_INI_LF,
    SSF_INI_CRLF,
    SSF_INI_LINE_ENDING_MAX,
} SSFINILineEnd_t;

typedef enum
{
    SSF_INI_BOOL_1_0,
    SSF_INI_BOOL_YES_NO,
    SSF_INI_BOOL_ON_OFF,
    SSF_INI_BOOL_TRUE_FALSE,
    SSF_INI_BOOL_MAX,
} SSFINIBool_t;

typedef enum
{
    SSF_INI_COMMENT_SEMI,
    SSF_INI_COMMENT_HASH,
    SSF_INI_COMMENT_NONE,
    SSF_INI_COMMENT_MAX,
} SSFINIComment_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* Parser */
bool SSFINIIsSectionPresent(SSFCStrIn_t ini, SSFCStrIn_t section);
bool SSFINIIsNameValuePresent(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name,
                              uint8_t index);
bool SSFINIGetStrValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                       SSFCStrOut_t out, size_t outSize, size_t *outLen);
bool SSFINIGetBoolValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                        bool *out);
bool SSFINIGetLongValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                        long int *out);

/* Generator */
bool SSFINIPrintComment(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t text,
                        SSFINIComment_t commentType, SSFINILineEnd_t lineEnding);
bool SSFINIPrintSection(SSFCStrOut_t ini, size_t iniSize, size_t* iniLen, SSFCStrIn_t section,
                        SSFINILineEnd_t lineEnding);
bool SSFINIPrintNameStrValue(SSFCStrOut_t ini, size_t iniSize, size_t* iniLen, SSFCStrIn_t name,
                             SSFCStrIn_t value, SSFINILineEnd_t lineEnding);
bool SSFINIPrintNameBoolValue(SSFCStrOut_t ini, size_t iniSize, size_t* iniLen, SSFCStrIn_t name,
                              bool value, SSFINIBool_t boolType, SSFINILineEnd_t lineEnding);
bool SSFINIPrintNameLongValue(SSFCStrOut_t ini, size_t iniSize, size_t* iniLen, SSFCStrIn_t name,
                              long int value, SSFINILineEnd_t lineEnding);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_INI_UNIT_TEST == 1
void SSFINIUnitTest(void);
#endif /* SSF_CONFIG_INI_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSFINI_H_INCLUDE */

