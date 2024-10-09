/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfgobj.h                                                                                     */
/* Provides flexible API to r/w/modify structured data & conversion from & to other codecs.      */
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
/* Structs                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef enum
{
    SSF_OBJ_TYPE_MIN = -1,
    SSF_OBJ_TYPE_NONE,
    SSF_OBJ_TYPE_STR,
    SSF_OBJ_TYPE_BIN,
    SSF_OBJ_TYPE_INT,
    SSF_OBJ_TYPE_UINT,
    SSF_OBJ_TYPE_FLOAT,
    SSF_OBJ_TYPE_BOOL,
    SSF_OBJ_TYPE_NULL,
    SSF_OBJ_TYPE_OBJECT,
    SSF_OBJ_TYPE_ARRAY,
    SSF_OBJ_TYPE_MAX,
} SSFObjType_t;

typedef struct
{
    SSFLLItem_t item;
    char *labelCStr;
    void *data;
    SSFLL_t children;
    SSFObjType_t dataType;
    size_t dataSize;
} SSFGObj_t;

typedef struct
{
    SSFLLItem_t item;
    SSFGObj_t *gobj;
    int32_t index;
} SSFGObjPathItem_t;

typedef void (*SSFGObjIterateFn_t)(SSFGObj_t *gobj, SSFLL_t *path);

/* --------------------------------------------------------------------------------------------- */
/* Public Interface                                                                              */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjInit(SSFGObj_t **gobj, uint16_t maxChildren);
void SSFGObjDeInit(SSFGObj_t **gobj);

/* Object label accessors */
bool SSFGObjSetLabel(SSFGObj_t *gobj, SSFCStrIn_t labelCStr);
bool SSFGObjGetLabel(SSFGObj_t *gobj, SSFCStrOut_t labelCStrOut, size_t labelCStrOutSize);

/* Object value accessors */
SSFObjType_t SSFGObjGetType(SSFGObj_t *gobj);
size_t SSFGObjGetSize(SSFGObj_t *gobj);
bool SSFGObjSetNone(SSFGObj_t *gobj);
bool SSFGObjSetString(SSFGObj_t *gobj, SSFCStrIn_t valueCStr);
bool SSFGObjGetString(SSFGObj_t *gobj, SSFCStrOut_t valueCStrOut, size_t labelCStrOutSize);
bool SSFGObjSetInt(SSFGObj_t *gobj, int64_t value);
bool SSFGObjGetInt(SSFGObj_t *gobj, int64_t *valueOut);
bool SSFGObjSetUInt(SSFGObj_t *gobj, uint64_t value);
bool SSFGObjGetUInt(SSFGObj_t *gobj, uint64_t *valueOut);
bool SSFGObjSetFloat(SSFGObj_t *gobj, double value);
bool SSFGObjGetFloat(SSFGObj_t *gobj, double *valueOut);
bool SSFGObjSetBool(SSFGObj_t *gobj, bool value);
bool SSFGObjGetBool(SSFGObj_t *gobj, bool *valueOut);
bool SSFGObjSetBin(SSFGObj_t *gobj, uint8_t *value, size_t valueLen);
bool SSFGObjGetBin(SSFGObj_t *gobj, uint8_t *valueOut, size_t valueSize, size_t *valueLenOutOpt);
bool SSFGObjSetNull(SSFGObj_t *gobj);
bool SSFGObjSetObject(SSFGObj_t *gobj);
bool SSFGObjSetArray(SSFGObj_t *gobj);

/* Object children accessors */
bool SSFGObjInsertChild(SSFGObj_t *gobjParent, SSFGObj_t *gobjChild);
bool SSFGObjRemoveChild(SSFGObj_t *gobjParent, SSFGObj_t *gobjChild);

/* Find and parse */
bool SSFGObjFindPath(SSFGObj_t *gobjRoot, SSFCStrIn_t *path, SSFGObj_t **gobjParentOut,
                     SSFGObj_t **gobjChildOut);
bool SSFGObjIterate(SSFGObj_t *gobj, SSFGObjIterateFn_t iterateCallback);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
void SSFGObjUnitTest(void);
bool SSFGObjIsMemoryBalanced(void);
#endif /* SSF_CONFIG_GOBJ_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_GOBJ_H_INCLUDE */

