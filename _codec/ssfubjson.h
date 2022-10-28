/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfubjson.h                                                                                   */
/* Provides Universal Binary JSON parser/generator interface.                                    */
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
#ifndef SSF_UBJSON_H_INCLUDE
#define SSF_UBJSON_H_INCLUDE

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef enum
{
    SSF_UBJSON_TYPE_MIN = -1,
    SSF_UBJSON_TYPE_ERROR,
    SSF_UBJSON_TYPE_STRING,
    SSF_UBJSON_TYPE_NUMBER_INT8,
    SSF_UBJSON_TYPE_NUMBER_UINT8,
    SSF_UBJSON_TYPE_NUMBER_CHAR,
    SSF_UBJSON_TYPE_NUMBER_INT16,
    SSF_UBJSON_TYPE_NUMBER_INT32,
    SSF_UBJSON_TYPE_NUMBER_INT64,
    SSF_UBJSON_TYPE_NUMBER_FLOAT32,
    SSF_UBJSON_TYPE_NUMBER_FLOAT64,
    SSF_UBJSON_TYPE_NUMBER_HPN,
    SSF_UBJSON_TYPE_OBJECT,
    SSF_UBJSON_TYPE_ARRAY,
    SSF_UBJSON_TYPE_TRUE,
    SSF_UBJSON_TYPE_FALSE,
    SSF_UBJSON_TYPE_NULL,
    SSF_UBJSON_TYPE_MAX,
} SSFUBJsonType_t;

typedef bool (*SSFUBJsonPrintFn_t)(uint8_t *js, size_t size, size_t start, size_t *end,
                                   void *in);

/* Parser */
bool SSFUBJsonIsValid(uint8_t *js, size_t jsLen);
SSFUBJsonType_t SSFUBJsonGetType(uint8_t *js, size_t jsLen, SSFCStrIn_t *path);
bool SSFUBJsonGetString(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, SSFCStrOut_t out,
                        size_t outSize, size_t *outLen);
bool SSFUBJsonGetHex(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                     size_t *outLen, bool rev);
bool SSFUBJsonGetBase64(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                        size_t *outLen);
bool SSFUBJsonGetFloat(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, float *out);
bool SSFUBJsonGetDouble(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, double *out);

#define SSFUBJsonGetInt8(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 1, true)
#define SSFUBJsonGetUInt8(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 1, false)
#define SSFUBJsonGetInt16(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 2, true)
#define SSFUBJsonGetUInt16(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 2, false)
#define SSFUBJsonGetInt32(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 4, true)
#define SSFUBJsonGetUInt32(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 4, false)
#define SSFUBJsonGetInt64(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 8, true)
#define SSFUBJsonGetUInt64(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 8, false)
bool SSFUBJsonGetInt(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, void *out, uint8_t size,
                     bool isSigned);

/* Generator */
#define SSFUBJsonPrintObject(js, size, start, end, fn, in) \
        SSFUBJsonPrint(js, size, start, end, fn, in, "{}")
#define SSFUBJsonPrintArray(js, size, start, end, fn, in) \
        SSFUBJsonPrint(js, size, start, end, fn, in, "[]")
bool SSFUBJsonPrint(uint8_t *js, size_t size, size_t start, size_t *end, SSFUBJsonPrintFn_t fn,
                    void *in, const char *oc);

bool SSFUBJsonPrintLabel(uint8_t *js, size_t size, size_t start, size_t *end, SSFCStrIn_t label);
bool SSFUBJsonPrintArrayOpt(uint8_t *js, size_t size, size_t start, size_t *end,
                            SSFUBJsonPrintFn_t fn, void *in, SSFUBJsonType_t atype, size_t alen);
bool SSFUBJsonPrintString(uint8_t *js, size_t size, size_t start, size_t *end, SSFCStrIn_t in);
bool SSFUBJsonPrintHex(uint8_t *js, size_t size, size_t start, size_t *end, uint8_t *in,
                       size_t inLen, bool rev);
bool SSFUBJsonPrintBase64(uint8_t *js, size_t size, size_t start, size_t *end, uint8_t *in,
                        size_t inLen);

#define SSFUBJsonPrintTrue(js, size, start, end) \
        SSFUBJsonPrintChar(js, size, start, end, 'T')
#define SSFUBJsonPrintFalse(js, size, start, end) \
        SSFUBJsonPrintChar(js, size, start, end, 'F')
#define SSFUBJsonPrintNull(js, size, start, end) \
        SSFUBJsonPrintChar(js, size, start, end, 'Z')
bool SSFUBJsonPrintChar(uint8_t *js, size_t size, size_t start, size_t *end,
                             const char in);

bool SSFUBJsonPrintInt(uint8_t *js, size_t size, size_t start, size_t *end, int64_t in, bool opt);
bool SSFUBJsonPrintFloat(uint8_t *js, size_t size, size_t start, size_t *end, float in);
bool SSFUBJsonPrintDouble(uint8_t *js, size_t size, size_t start, size_t *end, double in);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_UBJSON_UNIT_TEST == 1
void SSFUBJsonUnitTest(void);
#endif /* SSF_CONFIG_UBJSON_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_UBJSON_H_INCLUDE */

