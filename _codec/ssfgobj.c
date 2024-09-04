/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfgobj.c                                                                                     */
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
#include <stdint.h>
#include "ssfport.h"
#include "ssfgobj.h"
#include "ssfll.h"
#include "ssfjson.h"

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjInit(SSFGObj_t **gobj, uint32_t maxPeers, uint32_t maxChildren)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(*gobj == NULL);

    *gobj = (SSFGObj_t *)SSF_MALLOC(sizeof(SSFGObj_t));
    if (*gobj == NULL) return false;
    memset(*gobj, 0, sizeof(SSFGObj_t));

    SSFLLInit(&((*gobj)->peers), maxPeers); // can;t set to 0?
    SSFLLInit(&((*gobj)->children), maxChildren); // can't set to 0?

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
void SSFGObjDeInit(SSFGObj_t **gobj)
{
    SSFLLItem_t *item;
    SSFLLItem_t *next;
    //SSFGObj_t *peer = NULL;

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(*gobj != NULL);

    if ((*gobj)->labelCStr != NULL)
    {
        SSF_FREE((*gobj)->labelCStr);
        (*gobj)->labelCStr = NULL;
    }

    if ((*gobj)->data != NULL)
    {
        SSF_FREE((*gobj)->data);
        (*gobj)->data = NULL;
    }

    /* Deinit all children */
    item = SSF_LL_HEAD(&((*gobj)->children));
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        SSFLLGetItem(&((*gobj)->children), &item, SSF_LL_LOC_ITEM, item);
        SSFGObjDeInit((SSFGObj_t**) &item);
        item = next;
    }

    /* Deinit all peers */
    item = SSF_LL_HEAD(&((*gobj)->peers));
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        //memcpy(&peer, item, sizeof(peer));
        SSFLLGetItem(&((*gobj)->peers), &item, SSF_LL_LOC_ITEM, item);
        SSFGObjDeInit((SSFGObj_t**) &item);
        item = next;
    }

    SSFLLDeInit(&((*gobj)->peers));
    SSFLLDeInit(&((*gobj)->children));

    SSF_FREE(*gobj);
    *gobj = NULL;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFGObjSetField(SSFGObj_t *gobj, void **dst, const void *src, size_t srcSize,
                             SSFObjType_t srcType)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(dst != NULL);
    SSF_REQUIRE((src != NULL) || ((src == NULL) && (srcSize == 0)));
    SSF_REQUIRE((srcType > SSF_OBJ_TYPE_MIN) && (srcType < SSF_OBJ_TYPE_MAX));

    if (*dst != NULL)
    {
        SSF_FREE(*dst);
        *dst = NULL;
    }

    if (src != NULL)
    {
        *dst = SSF_MALLOC(srcSize);
        if (*dst == NULL)
        {
            gobj->dataType = SSF_OBJ_TYPE_ERROR;
            return false;
        }
        memcpy(*dst, src, srcSize);
    }
    if (srcType != SSF_OBJ_TYPE_ERROR)
    {
        gobj->dataType = srcType;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetLabel(SSFGObj_t *gobj, SSFCStrIn_t labelCStr)
{
    SSF_REQUIRE(gobj != NULL);

    return _SSFGObjSetField(gobj, &gobj->labelCStr, labelCStr,
                            labelCStr == NULL ? 0 : strlen(labelCStr) + 1, SSF_OBJ_TYPE_ERROR);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetLabel(SSFGObj_t *gobj, SSFCStrOut_t labelCStrOut, size_t labelCStrOutSize)
{
    size_t len;

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(labelCStrOut != NULL);

    if (gobj->labelCStr == NULL) return false;
    len = strlen(gobj->labelCStr) + 1;;
    if (len > labelCStrOutSize) return false;

    memcpy(labelCStrOut, gobj->labelCStr, len);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetString(SSFGObj_t *gobj, SSFCStrOut_t cstrOut, size_t cstrOutSize)
{
    size_t len;

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(cstrOut != NULL);

    if (gobj->dataType != SSF_OBJ_TYPE_STRING) return false;
    SSF_ASSERT(gobj->data != NULL);
    len = strlen((char *)gobj->data) + 1;;
    if (len > cstrOutSize) return false;

    memcpy(cstrOut, gobj->data, len);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetString(SSFGObj_t *gobj, SSFCStrIn_t valueCStr)
{
    SSF_REQUIRE(gobj != NULL);

    return _SSFGObjSetField(gobj, &gobj->data, valueCStr,
                            valueCStr == NULL ? 0 : strlen(valueCStr) + 1, SSF_OBJ_TYPE_STRING);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetUInt(SSFGObj_t *gobj, uint64_t value)
{
    SSF_REQUIRE(gobj != NULL);

    return _SSFGObjSetField(gobj, &gobj->data, &value, sizeof(value), SSF_OBJ_TYPE_NUMBER_UINT64);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetUInt(SSFGObj_t *gobj, uint64_t *valueOut)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(valueOut != NULL);

    if (gobj->dataType != SSF_OBJ_TYPE_NUMBER_UINT64) return false;
    SSF_ASSERT(gobj->data != NULL);
    memcpy(valueOut, gobj->data, sizeof(uint64_t));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetInt(SSFGObj_t *gobj, int64_t value)
{
    SSF_REQUIRE(gobj != NULL);

    return _SSFGObjSetField(gobj, &gobj->data, &value, sizeof(value), SSF_OBJ_TYPE_NUMBER_INT64);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetInt(SSFGObj_t *gobj, int64_t *valueOut)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(valueOut != NULL);

    if (gobj->dataType != SSF_OBJ_TYPE_NUMBER_INT64) return false;
    SSF_ASSERT(gobj->data != NULL);
    memcpy(valueOut, gobj->data, sizeof(int64_t));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetDouble(SSFGObj_t *gobj, double value)
{
    SSF_REQUIRE(gobj != NULL);

    return _SSFGObjSetField(gobj, &gobj->data, &value, sizeof(value), SSF_OBJ_TYPE_NUMBER_FLOAT64);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetDouble(SSFGObj_t *gobj, double *valueOut)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(valueOut != NULL);

    if (gobj->dataType != SSF_OBJ_TYPE_NUMBER_FLOAT64) return false;
    SSF_ASSERT(gobj->data != NULL);
    memcpy(valueOut, gobj->data, sizeof(double));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjInsertPeer(SSFGObj_t *gobjBase, SSFGObj_t *gobjPeer)
{
    SSF_ASSERT(gobjBase != NULL);
    SSF_ASSERT(gobjPeer != NULL);

    if (SSFLLIsFull(&(gobjBase->peers))) return false;
    SSF_LL_STACK_PUSH(&(gobjBase->peers), gobjPeer);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjInsertChild(SSFGObj_t *gobjBase, SSFGObj_t *gobjChild)
{
    SSF_ASSERT(gobjBase != NULL);
    SSF_ASSERT((gobjBase->dataType == SSF_OBJ_TYPE_OBJECT) ||
        (gobjBase->dataType == SSF_OBJ_TYPE_ARRAY));
    SSF_ASSERT(gobjChild != NULL);

    if (SSFLLIsFull(&(gobjBase->children))) return false;
    SSF_LL_STACK_PUSH(&(gobjBase->children), gobjChild);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetObject(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, NULL, 0, SSF_OBJ_TYPE_OBJECT);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetArray(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, NULL, 0, SSF_OBJ_TYPE_ARRAY);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetTrue(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, NULL, 0, SSF_OBJ_TYPE_TRUE);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetFalse(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, NULL, 0, SSF_OBJ_TYPE_FALSE);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetNull(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, NULL, 0, SSF_OBJ_TYPE_NULL);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
SSFObjType_t SSFGObjGetType(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return gobj->dataType;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
//bool SSFGObjToJson(SSFGObj_t *gobj, SSFCStrOut_t cstrOut, size_t cstrOutSize)
bool SSFGObjToJson(SSFCStrOut_t js, size_t size, size_t start, size_t *end, SSFGObj_t *gobj,
                   bool *comma)
{
    SSFLLItem_t *item;
    SSFLLItem_t *next;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(comma != NULL);

    if (gobj->labelCStr != NULL)
    {
        if (!SSFJsonPrintLabel(js, size, start, &start, gobj->labelCStr, comma)) return false;
        *comma = false;
    }
    switch (gobj->dataType)
    {
        case SSF_OBJ_TYPE_STRING:
            SSF_ASSERT(gobj->data != NULL);
            if (!SSFJsonPrintString(js, size, start, &start, (char *)gobj->data, comma)) return false;
            break;
        case SSF_OBJ_TYPE_TRUE:
            {
                SSF_ASSERT(gobj->data == NULL);
                if (!SSFJsonPrintTrue(js, size, start, &start, false)) return false;
            }
            break;
        case SSF_OBJ_TYPE_FALSE:
            {
                SSF_ASSERT(gobj->data == NULL);
                if (!SSFJsonPrintFalse(js, size, start, &start, false)) return false;
            }
            break;
        case SSF_OBJ_TYPE_NULL:
            {
                SSF_ASSERT(gobj->data == NULL);
                if (!SSFJsonPrintNull(js, size, start, &start, false)) return false;
            }
            break;
        case SSF_OBJ_TYPE_NUMBER_UINT64:
            {
                uint64_t ui;

                SSF_ASSERT(gobj->data != NULL);
                memcpy(&ui, gobj->data, sizeof(ui));
                if (!SSFJsonPrintUInt(js, size, start, &start, ui, false)) return false;
            }
            break;
        case SSF_OBJ_TYPE_NUMBER_INT64:
            {
                uint64_t i64;

                SSF_ASSERT(gobj->data != NULL);
                memcpy(&i64, gobj->data, sizeof(i64));
                if (!SSFJsonPrintInt(js, size, start, &start, i64, false)) return false;
            }
            break;
        case SSF_OBJ_TYPE_NUMBER_FLOAT64:
            {
                double d64;

                SSF_ASSERT(gobj->data != NULL);
                memcpy(&d64, gobj->data, sizeof(d64));
                if (!SSFJsonPrintDouble(js, size, start, &start, d64, SSF_JSON_FLT_FMT_STD, false)) return false;
            }
            break;
        case SSF_OBJ_TYPE_OBJECT:
            if (!SSFJsonPrintCString(js, size, start, &start, "{", comma)) return false;
            *comma = false;
            item = SSF_LL_HEAD(&(gobj->children));
            while (item != NULL)
            {
                next = SSF_LL_NEXT_ITEM(item);
                if (!SSFGObjToJson(js, size, start, &start, (SSFGObj_t *)item, comma)) return false;
                *comma = true;
                item = next;
            }
            if (!SSFJsonPrintCString(js, size, start, &start, "}", false)) return false;
            break;
        case SSF_OBJ_TYPE_ARRAY:
            if (!SSFJsonPrintCString(js, size, start, &start, "[", comma)) return false;
            *comma = false;
            item = SSF_LL_HEAD(&(gobj->children));
            while (item != NULL)
            {
                next = SSF_LL_NEXT_ITEM(item);
                if (!SSFGObjToJson(js, size, start, &start, (SSFGObj_t *)item, comma)) return false;
                *comma = true;
                item = next;
            }
            if (!SSFJsonPrintCString(js, size, start, &start, "]", false)) return false;
            *comma = true;
            break;
        default:
            SSF_ERROR();
    };

    item = SSF_LL_HEAD(&(gobj->peers));
    *comma = false;
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        if (!SSFGObjToJson(js, size, start, &start, (SSFGObj_t *)item, comma)) return false;
        item = next;
    }

    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
//static bool 

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
static void _SSFGObjIterate(SSFGObj_t *gobj, SSFGObjIterateFn_t iterateCallback, SSFLL_t *path, uint8_t depth)
{
    SSFLLItem_t *item;
    SSFLLItem_t *next;
    SSFGObjPathItem_t pathItem;
    SSFGObjPathItem_t *tmp;

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(iterateCallback != NULL);

    memset(&pathItem, 0, sizeof(pathItem));
    pathItem.index = -1;

    pathItem.gobj = gobj;
    SSFLLPutItem(path, (SSFLLItem_t*)&pathItem, SSF_LL_LOC_TAIL, NULL);
    iterateCallback(gobj, path, depth);
    SSFLLGetItem(path, (SSFLLItem_t**)&tmp, SSF_LL_LOC_TAIL, NULL);

    item = SSF_LL_HEAD(&(gobj->children));
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        pathItem.gobj = gobj;
        if (gobj->dataType == SSF_OBJ_TYPE_ARRAY)
        {
            pathItem.index++;
        }
        SSFLLPutItem(path, (SSFLLItem_t *)&pathItem, SSF_LL_LOC_TAIL, NULL);
        _SSFGObjIterate((SSFGObj_t*)item, iterateCallback, path, depth + 1);
        SSFLLGetItem(path, (SSFLLItem_t **)&tmp, SSF_LL_LOC_TAIL, NULL);
        item = next;
    }

    item = SSF_LL_HEAD(&(gobj->peers));
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        //pathItem.gobj = gobj;
        //SSFLLPutItem(path, (SSFLLItem_t *)&pathItem, SSF_LL_LOC_TAIL, NULL);
        _SSFGObjIterate((SSFGObj_t*)item, iterateCallback, path, depth + 1);
        //SSFLLGetItem(path, (SSFLLItem_t **)&tmp, SSF_LL_LOC_TAIL, NULL);
        item = next;
    }
}


#define MAX_DEPTH (10u)
/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
void SSFGObjIterate(SSFGObj_t *gobj, SSFGObjIterateFn_t iterateCallback, uint8_t depth)
{
    SSFLL_t path;

    SSFLLInit(&path, MAX_DEPTH);

    _SSFGObjIterate(gobj, iterateCallback, &path, depth);

    SSFLLDeInit(&path);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
void SSFGObjPathToString(SSFLL_t *path)
{
    SSFGObjPathItem_t *pi;
    SSFLLItem_t *item;
    SSFLLItem_t *next;

    SSF_REQUIRE(path != NULL);

    item = SSF_LL_HEAD(path);
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        pi = (SSFGObjPathItem_t *)item;
        if (pi->gobj->labelCStr != NULL)
        {
            printf(".%s", pi->gobj->labelCStr);
            if (pi->index >= 0)
            {
                printf("[%d]", pi->index);
            }
        }
        item = next;
    }
}
