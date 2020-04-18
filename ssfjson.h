/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfjson.h                                                                                     */
/* Provides JSON parser/generator interface.                                                     */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_JSON_H_INCLUDE
#define SSF_JSON_H_INCLUDE

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Limitations                                                                                   */
/* Parser will accept inputs with duplicate object keys.                                         */
/* Parser will only match first of more than one duplicate object keys.                          */
/* Parser only performs literal path match on object keys.                                       */
// Parser only accepts 8-bit ASCII encoded strings, embedded NULL/0 values terminate input.      */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef enum SSFJsonType
{
    SSF_JSON_TYPE_ERROR,
    SSF_JSON_TYPE_STRING,
    SSF_JSON_TYPE_NUMBER,
    SSF_JSON_TYPE_OBJECT,
    SSF_JSON_TYPE_ARRAY,
    SSF_JSON_TYPE_TRUE,
    SSF_JSON_TYPE_FALSE,
    SSF_JSON_TYPE_NULL,
    SSF_JSON_TYPE_MAX,
} SSFJsonType_t;

typedef bool (*SSFJsonPrintFn_t)(char* js, size_t size, size_t start, size_t* end, void* in);

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* Parser */
bool SSFJsonIsValid(const char* js);
SSFJsonType_t SSFJsonGetType(const char* js, const char** path);
bool SSFJsonGetString(const char* js, const char** path, char* out, size_t outSize, size_t* outLen);
bool SSFJsonGetDouble(const char* js, const char** path, double* out);
bool SSFJsonGetInt(const char* js, const char** path, int32_t* out);
bool SSFJsonGetUInt(const char* js, const char** path, uint32_t* out);
bool SSFJsonGetHex(const char* js, const char** path, uint8_t* out, size_t outSize, size_t* outLen,
                   bool rev);
bool SSFJsonGetBase64(const char* js, const char** path, uint8_t* out, size_t outSize, size_t* outLen);
bool SSFJsonObject(const char* js, size_t* index, size_t* start, size_t* end, const char** path,
                   uint8_t depth, SSFJsonType_t* jt);

/* Generator */
bool SSFJsonPrintString(char* js, size_t size, size_t start, size_t* end, const char* in, bool *comma);
#define SSFJsonPrintTrue(js, size, start, end, comma) \
        SSFJsonPrintCString(js, size, start, end, "true", comma)
#define SSFJsonPrintFalse(js, size, start, end, comma) \
        SSFJsonPrintCString(js, size, start, end, "false", comma)
#define SSFJsonPrintNull(js, size, start, end, comma) \
        SSFJsonPrintCString(js, size, start, end, "null", comma)
bool SSFJsonPrintLabel(char* js, size_t size, size_t start, size_t* end, const char* in, bool *comma);
bool SSFJsonPrintHex(char* js, size_t size, size_t start, size_t* end, const uint8_t* in, size_t inLen,
                           bool rev, bool *comma);
bool SSFJsonPrintBase64(char* jstr, size_t size, size_t start, size_t* end, const uint8_t* in,
                              size_t inLen, bool *comma);
bool SSFJsonPrintDouble(char* js, size_t size, size_t start, size_t* end, double in, bool *comma);
bool SSFJsonPrintInt(char* js, size_t size, size_t start, size_t* end, int32_t in, bool *comma);
bool SSFJsonPrintUInt(char* js, size_t size, size_t start, size_t* end, uint32_t in, bool *comma);
#define SSFJsonPrintObject(js, size, start, end, fn, in, comma) \
        SSFJsonPrint(js, size, start, end, fn, in, "{}", comma)
#define SSFJsonPrintArray(js, size, start, end, fn, in, comma) \
        SSFJsonPrint(js, size, start, end, fn, in, "[]", comma)
bool SSFJsonPrintCString(char* js, size_t size, size_t start, size_t* end, const char* in, bool *comma);
bool SSFJsonPrint(char* js, size_t size, size_t start, size_t* end, SSFJsonPrintFn_t fn, void* in,
                    const char *oc, bool *comma);
bool SSFJsonUpdate(char* js, size_t size, const char** path, SSFJsonPrintFn_t fn);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_JSON_UNIT_TEST == 1
void SSFJsonUnitTest(void);
#endif /* SSF_CONFIG_JSON_UNIT_TEST */

#endif /* SSF_JSON_H_INCLUDE */
