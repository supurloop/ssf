/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfgobj.h                                                                                     */
/* Provides flexible API to r/w/modify structured data & conversion from & to other codecs.      */                                                            */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2024 Supurloop Software LLC                                                         */
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
#ifndef SSF_GOBJ_H_INCLUDE
#define SSF_GOBJ_H_INCLUDE

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfll.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Structs                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef enum
{
    SSF_OBJ_TYPE_MIN = -1,
    SSF_OBJ_TYPE_ERROR,
    SSF_OBJ_TYPE_STRING,
    SSF_OBJ_TYPE_NUMBER_CHAR,
    SSF_OBJ_TYPE_NUMBER_INT8,
    SSF_OBJ_TYPE_NUMBER_UINT8,
    SSF_OBJ_TYPE_NUMBER_INT16,
    SSF_OBJ_TYPE_NUMBER_UINT16,
    SSF_OBJ_TYPE_NUMBER_INT32,
    SSF_OBJ_TYPE_NUMBER_UINT32,
    SSF_OBJ_TYPE_NUMBER_INT64,
    SSF_OBJ_TYPE_NUMBER_UINT64,
    SSF_OBJ_TYPE_NUMBER_FLOAT32,
    SSF_OBJ_TYPE_NUMBER_FLOAT64,
    SSF_OBJ_TYPE_OBJECT,
    SSF_OBJ_TYPE_ARRAY,
    SSF_OBJ_TYPE_TRUE,
    SSF_OBJ_TYPE_FALSE,
    SSF_OBJ_TYPE_NULL,
    SSF_OBJ_TYPE_MAX,
} SSFObjType_t;

typedef struct
{
    SSFLLItem_t item;
    char *labelCStr; /* Label value may not contain 0, but must end with 0 */
    void *data;
#if 0
    union data
    {
        char *cstr;
        sint64_t si;
        uint64_t ui;
    };
#endif
    SSFLL_t peers;
    SSFLL_t children;
    SSFObjType_t dataType;
    size_t dataLen;
    // encoding options type
    //uint32_t magic;
} SSFGObj_t;

typedef struct
{
    SSFLLItem_t item;
    SSFGObj_t* gobj;
    int32_t index;
} SSFGObjPathItem_t;

typedef void (*SSFGObjIterateFn_t)(SSFGObj_t *gobj, SSFLL_t *path, uint8_t depth);

/* --------------------------------------------------------------------------------------------- */
/* Public Interface                                                                              */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjInit(SSFGObj_t **gobj, uint32_t maxPeers, uint32_t maxChildren);
void SSFGObjDeInit(SSFGObj_t **gobj);
bool SSFGObjSetLabel(SSFGObj_t *gobj, SSFCStrIn_t labelCStr);
bool SSFGObjGetLabel(SSFGObj_t *gobj, SSFCStrOut_t labelCStrOut, size_t labelCStrOutSize);
bool SSFGObjSetString(SSFGObj_t *gobj, SSFCStrIn_t valueCStr);
bool SSFGObjGetString(SSFGObj_t *gobj, SSFCStrOut_t labelCStrOut, size_t labelCStrOutSize);
//SSFGObjGetHex
//SSFGObjGetBase64
//SSFGObjGetBin
bool SSFGObjSetInt(SSFGObj_t *gobj, int64_t value);
bool SSFGObjGetInt(SSFGObj_t *gobj, int64_t *valueOut);
bool SSFGObjSetUInt(SSFGObj_t *gobj, uint64_t value);
bool SSFGObjGetUInt(SSFGObj_t *gobj, uint64_t *valueOut);
bool SSFGObjSetDouble(SSFGObj_t *gobj, double value);
bool SSFGObjGetDouble(SSFGObj_t *gobj, double *valueOut);
bool SSFGObjSetObject(SSFGObj_t *gobj);
bool SSFGObjSetArray(SSFGObj_t *gobj);
bool SSFGObjSetTrue(SSFGObj_t *gobj);
bool SSFGObjSetFalse(SSFGObj_t *gobj);
bool SSFGObjSetNull(SSFGObj_t *gobj);
SSFObjType_t SSFGObjGetType(SSFGObj_t *gobj);
size_t SSFGObjGetLen(SSFGObj_t *gobj);

bool SSFGObjInsertPeer(SSFGObj_t *gobjBase, SSFGObj_t *gobj);
bool SSFGObjInsertChild(SSFGObj_t *gobjBase, SSFGObj_t *gobjChild);
bool SSFGObjToJson(SSFCStrOut_t js, size_t size, size_t start, size_t *end, SSFGObj_t *gobj,
                   bool *comma);

void SSFGObjIterate(SSFGObj_t *gobj, SSFGObjIterateFn_t iterateCallback, uint8_t depth);
void SSFGObjPathToString(SSFLL_t *path);

#if 0

SSFGObjIsValid()

SSFGObjSetEncoding()

???
SSFGObjGetLabel()
SSFGObjGetEncoding()
SSFGObjGetString()
SSFGObjGetNumber()
SSFGObjGetBool()
SSFGObjGetNull()
SSFGObjGetArray()
SSFGObjGetObject()
???

SSFJsonToGObj()
SSFUBJsonToGObj()
SSFTLVToGObj()
SSFINIToGObj()

SSFGObjToJson()
SSFGObjToUBJson()
SSFGObjToTLV()
SSFGObjToINI()

Put Get
Insert/remove
alloc
free
#endif
/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
void SSFGObjUnitTest(void);
#endif /* SSF_CONFIG_GOBJ_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_GOBJ_H_INCLUDE */

