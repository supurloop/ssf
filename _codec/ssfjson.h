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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_JSON_H_INCLUDE
#define SSF_JSON_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Limitations                                                                                   */
/* Parser considers inputs with duplicate object keys valid.                                     */
/* Parser will only match the first of more than one duplicate object key.                       */
/* Parser only performs literal path match on object keys.                                       */
// Parser only accepts 8-bit ASCII encoded strings, embedded NULL/0 values terminate input.      */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef enum
{
    SSF_JSON_TYPE_MIN = -1,
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

#if SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1
typedef enum
{
    SSF_JSON_FLT_FMT_MIN = -1,
    SSF_JSON_FLT_FMT_PREC_0,
    SSF_JSON_FLT_FMT_PREC_1,
    SSF_JSON_FLT_FMT_PREC_2,
    SSF_JSON_FLT_FMT_PREC_3,
    SSF_JSON_FLT_FMT_PREC_4,
    SSF_JSON_FLT_FMT_PREC_5,
    SSF_JSON_FLT_FMT_PREC_6,
    SSF_JSON_FLT_FMT_PREC_7,
    SSF_JSON_FLT_FMT_PREC_8,
    SSF_JSON_FLT_FMT_PREC_9,
    SSF_JSON_FLT_FMT_STD,
    SSF_JSON_FLT_FMT_SHORT,
    SSF_JSON_FLT_FMT_MAX,
} SSFJsonFltFmt_t;
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */

typedef bool (*SSFJsonPrintFn_t)(char *js, size_t size, size_t start, size_t *end, void *in);

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* Parser */
bool SSFJsonIsValid(SSFCStrIn_t js);
SSFJsonType_t SSFJsonGetType(SSFCStrIn_t js, SSFCStrIn_t *path);
bool SSFJsonGetString(SSFCStrIn_t js, SSFCStrIn_t *path, SSFCStrOut_t out, size_t outSize,
                      size_t *outLen);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
bool SSFJsonGetDouble(SSFCStrIn_t js, SSFCStrIn_t *path, double *out);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
bool SSFJsonGetLong(SSFCStrIn_t js, SSFCStrIn_t *path, long int *out);
bool SSFJsonGetULong(SSFCStrIn_t js, SSFCStrIn_t *path, unsigned long int *out);
bool SSFJsonGetHex(SSFCStrIn_t js, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                   size_t *outLen, bool rev);
bool SSFJsonGetBase64(SSFCStrIn_t js, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                      size_t *outLen);
bool SSFJsonObject(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end, SSFCStrIn_t *path,
                   uint8_t depth, SSFJsonType_t *jt);

/* Generator */
bool SSFJsonPrintString(SSFCStrOut_t js, size_t size, size_t start, size_t *end, SSFCStrIn_t in,
                        bool *comma);
#define SSFJsonPrintTrue(js, size, start, end, comma) \
        SSFJsonPrintCString(js, size, start, end, "true", comma)
#define SSFJsonPrintFalse(js, size, start, end, comma) \
        SSFJsonPrintCString(js, size, start, end, "false", comma)
#define SSFJsonPrintNull(js, size, start, end, comma) \
        SSFJsonPrintCString(js, size, start, end, "null", comma)
bool SSFJsonPrintLabel(SSFCStrOut_t js, size_t size, size_t start, size_t *end, SSFCStrIn_t in,
                       bool *comma);
bool SSFJsonPrintHex(SSFCStrOut_t js, size_t size, size_t start, size_t *end, const uint8_t *in,
                     size_t inLen,
                     bool rev, bool *comma);
bool SSFJsonPrintBase64(SSFCStrOut_t jstr, size_t size, size_t start, size_t *end,
                        const uint8_t *in, size_t inLen, bool *comma);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1
bool SSFJsonPrintDouble(SSFCStrOut_t js, size_t size, size_t start, size_t *end, double in,
                        SSFJsonFltFmt_t fmt, bool *comma);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */
bool SSFJsonPrintInt(SSFCStrOut_t js, size_t size, size_t start, size_t *end, int64_t in,
                     bool *comma);
bool SSFJsonPrintUInt(SSFCStrOut_t js, size_t size, size_t start, size_t *end, uint64_t in,
                      bool *comma);
#define SSFJsonPrintObject(js, size, start, end, fn, in, comma) \
        SSFJsonPrint(js, size, start, end, fn, in, "{}", comma)
#define SSFJsonPrintArray(js, size, start, end, fn, in, comma) \
        SSFJsonPrint(js, size, start, end, fn, in, "[]", comma)
bool SSFJsonPrintCString(SSFCStrOut_t js, size_t size, size_t start, size_t *end, SSFCStrIn_t in,
                         bool *comma);
bool SSFJsonPrint(SSFCStrOut_t js, size_t size, size_t start, size_t *end, SSFJsonPrintFn_t fn,
                  void *in, const char *oc, bool *comma);
#if SSF_JSON_CONFIG_ENABLE_UPDATE == 1
bool SSFJsonUpdate(SSFCStrOut_t js, size_t size, SSFCStrIn_t *path, SSFJsonPrintFn_t fn);
#endif /* SSF_JSON_CONFIG_ENABLE_UPDATE */

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_JSON_UNIT_TEST == 1
void SSFJsonUnitTest(void);
#endif /* SSF_CONFIG_JSON_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_JSON_H_INCLUDE */

