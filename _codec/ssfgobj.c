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

#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Module variables                                                                              */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _ssfgobjTotalAllocations;
static uint32_t _ssfgobjTotalDeallocations;

/* --------------------------------------------------------------------------------------------- */
/* Returns true if number of allocations and deallocations is the same, else false.              */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjIsMemoryBalanced(void)
{
    return _ssfgobjTotalAllocations == _ssfgobjTotalDeallocations;
}
#endif /* SSF_CONFIG_GOBJ_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object is initialize, else false.                                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjInit(SSFGObj_t **gobj, uint16_t maxChildren)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(*gobj == NULL);

    /* Allocate the object */
    *gobj = (SSFGObj_t *)SSF_MALLOC(sizeof(SSFGObj_t));

    /* Return if memory allocation fails */
    if (*gobj == NULL) return false;
#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
    _ssfgobjTotalAllocations++;
#endif

    /* Initialize the object */
    memset(*gobj, 0, sizeof(SSFGObj_t));
    if (maxChildren != 0) SSFLLInit(&((*gobj)->children), maxChildren);

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes an object including its children.                                               */
/* --------------------------------------------------------------------------------------------- */
void SSFGObjDeInit(SSFGObj_t **gobj)
{
    SSFLLItem_t *item;
    SSFLLItem_t *next;

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(*gobj != NULL);

    /* Is a label allocated? */
    if ((*gobj)->labelCStr != NULL)
    {
        /* Yes, free it */
        SSF_FREE((*gobj)->labelCStr);
        (*gobj)->labelCStr = NULL;
#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
        _ssfgobjTotalDeallocations++;
#endif
    }

    /* Is data allocated? */
    if ((*gobj)->data != NULL)
    {
        /* Yes, free it */
        SSF_FREE((*gobj)->data);
        (*gobj)->data = NULL;
#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
        _ssfgobjTotalDeallocations++;
#endif
    }

    /* Deinit all children */
    item = SSF_LL_HEAD(&((*gobj)->children));
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        SSFLLGetItem(&((*gobj)->children), &item, SSF_LL_LOC_ITEM, item);
        SSFGObjDeInit((SSFGObj_t **)&item);
        item = next;
    }

    /* Deinit the child linked list */
    if ((*gobj)->children.size != 0) SSFLLDeInit(&((*gobj)->children));

    /* Free top level object */
    SSF_FREE(*gobj);
    *gobj = NULL;
#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
    _ssfgobjTotalDeallocations++;
#endif
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the type of data held in the object.                                                  */
/* --------------------------------------------------------------------------------------------- */
SSFObjType_t SSFGObjGetType(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return gobj->dataType;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the size of the object's data in bytes.                                               */
/* --------------------------------------------------------------------------------------------- */
size_t SSFGObjGetSize(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return gobj->dataSize;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if field is set, else false.                                                     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFGObjSetField(SSFGObj_t *gobj, void **dst, const void *src, size_t srcSize,
                             SSFObjType_t srcType, bool isLabel)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(dst != NULL);
    SSF_REQUIRE((src != NULL) || ((src == NULL) && (srcSize == 0)));
    SSF_REQUIRE((srcType > SSF_OBJ_TYPE_MIN) && (srcType < SSF_OBJ_TYPE_MAX));

    /* Is field already allocated? */
    if (*dst != NULL)
    {
        /* Yes, free it */
        SSF_FREE(*dst);
        *dst = NULL;
#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
        _ssfgobjTotalDeallocations++;
#endif
    }

    /* Is there data to set to field? */
    if (src != NULL)
    {
        /* Yes, allocate room to set data to field */
        *dst = SSF_MALLOC(srcSize);

        /* Did allocation succeed? */
        if (*dst == NULL)
        {
            /* No, return failure */
            gobj->dataType = SSF_OBJ_TYPE_NONE;
            gobj->dataSize = 0;
            return false;
        }
#if SSF_CONFIG_GOBJ_UNIT_TEST == 1
        _ssfgobjTotalAllocations++;
#endif
        /* Copy data to field */
        memcpy(*dst, src, srcSize);
    }

    /* Conditionally save the user supplied data type */
    if (isLabel == false)
    {
        gobj->dataType = srcType;
        gobj->dataSize = srcSize;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true of the object's label is set, else false.                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetLabel(SSFGObj_t *gobj, SSFCStrIn_t labelCStr)
{
    SSF_REQUIRE(gobj != NULL);

    return _SSFGObjSetField(gobj, (void *)&gobj->labelCStr, labelCStr,
                            labelCStr == NULL ? 0 : strlen(labelCStr) + 1, SSF_OBJ_TYPE_NONE,
                            true);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if C string is copied to user buffer, else false.                                */
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
/* Returns true if none type set successfully, else false.                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetNone(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, NULL, 0, SSF_OBJ_TYPE_NONE, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if data set to string, else false.                                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetString(SSFGObj_t *gobj, SSFCStrIn_t valueCStr)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(valueCStr != NULL);

    return _SSFGObjSetField(gobj, &gobj->data, valueCStr, strlen(valueCStr) + 1, SSF_OBJ_TYPE_STR,
                            false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if data is a string and copied to user buffer, else false.                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetString(SSFGObj_t *gobj, SSFCStrOut_t valueCStrOut, size_t valueCStrOutSize)
{
    size_t len;

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(valueCStrOut != NULL);

    if (gobj->dataType != SSF_OBJ_TYPE_STR) return false;
    SSF_ASSERT(gobj->data != NULL);
    len = strlen((char *)gobj->data) + 1;;
    if (len > valueCStrOutSize) return false;

    memcpy(valueCStrOut, gobj->data, len);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if unsigned integer set successfully, else false.                                */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetUInt(SSFGObj_t *gobj, uint64_t value)
{
    SSF_REQUIRE(gobj != NULL);

    return _SSFGObjSetField(gobj, &gobj->data, &value, sizeof(value), SSF_OBJ_TYPE_UINT, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if unsigned integer copied successfully, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetUInt(SSFGObj_t *gobj, uint64_t *valueOut)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(valueOut != NULL);

    if (gobj->dataType != SSF_OBJ_TYPE_UINT) return false;
    SSF_ASSERT(gobj->data != NULL);
    memcpy(valueOut, gobj->data, sizeof(uint64_t));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if signed integer set successfully, else false.                                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetInt(SSFGObj_t *gobj, int64_t value)
{
    SSF_REQUIRE(gobj != NULL);

    return _SSFGObjSetField(gobj, &gobj->data, &value, sizeof(value), SSF_OBJ_TYPE_INT, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if signed integer copied successfully, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetInt(SSFGObj_t *gobj, int64_t *valueOut)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(valueOut != NULL);

    if (gobj->dataType != SSF_OBJ_TYPE_INT) return false;
    SSF_ASSERT(gobj->data != NULL);
    memcpy(valueOut, gobj->data, sizeof(int64_t));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if float set successfully, else false.                                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetFloat(SSFGObj_t *gobj, double value)
{
    SSF_REQUIRE(gobj != NULL);

    return _SSFGObjSetField(gobj, &gobj->data, &value, sizeof(value), SSF_OBJ_TYPE_FLOAT, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if float copied to user buffer, else false.                                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetFloat(SSFGObj_t *gobj, double *valueOut)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(valueOut != NULL);

    if (gobj->dataType != SSF_OBJ_TYPE_FLOAT) return false;
    SSF_ASSERT(gobj->data != NULL);
    memcpy(valueOut, gobj->data, sizeof(double));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if bool value set successfully, else false.                                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetBool(SSFGObj_t *gobj, bool value)
{
    SSF_REQUIRE(gobj != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, &value, sizeof(bool), SSF_OBJ_TYPE_BOOL, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if bool value copied to value, else false.                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetBool(SSFGObj_t *gobj, bool *valueOut)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(valueOut != NULL);

    if (gobj->dataType != SSF_OBJ_TYPE_BOOL) return false;
    SSF_ASSERT(gobj->data != NULL);
    memcpy(valueOut, gobj->data, sizeof(bool));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if binary value set successfully, else false.                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetBin(SSFGObj_t *gobj, uint8_t *value, size_t valueLen)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(value != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, value, valueLen, SSF_OBJ_TYPE_BIN, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if binary value copied to value, else false.                                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjGetBin(SSFGObj_t *gobj, uint8_t *valueOut, size_t valueSize, size_t *valueLenOutOpt)
{
    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(valueOut != NULL);

    if (gobj->dataType != SSF_OBJ_TYPE_BIN) return false;
    SSF_ASSERT(gobj->data != NULL);
    if (valueSize < gobj->dataSize) return false;
    memcpy(valueOut, gobj->data, gobj->dataSize);
    if (valueLenOutOpt != NULL) *valueLenOutOpt = gobj->dataSize;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if set to NULL type, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetNull(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, NULL, 0, SSF_OBJ_TYPE_NULL, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if set to object type, else false.                                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetObject(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, NULL, 0, SSF_OBJ_TYPE_OBJECT, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if set to array type, else false.                                                */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjSetArray(SSFGObj_t *gobj)
{
    SSF_REQUIRE(gobj != NULL);
    return _SSFGObjSetField(gobj, &gobj->data, NULL, 0, SSF_OBJ_TYPE_ARRAY, false);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if child is inserted into parent, else false.                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjInsertChild(SSFGObj_t *gobjParent, SSFGObj_t *gobjChild)
{
    SSF_REQUIRE(gobjParent != NULL);
    SSF_REQUIRE((gobjParent->dataType == SSF_OBJ_TYPE_OBJECT) ||
                (gobjParent->dataType == SSF_OBJ_TYPE_ARRAY));
    SSF_REQUIRE(gobjChild != NULL);

    if (gobjParent->children.size == 0) return false;
    if (SSFLLIsFull(&(gobjParent->children))) return false;
    SSFLLPutItem(&(gobjParent->children), (SSFLLItem_t *)gobjChild, SSF_LL_LOC_TAIL, NULL);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if child is removed from parent, else false.                                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjRemoveChild(SSFGObj_t *gobjParent, SSFGObj_t *gobjChild)
{
    SSFLLItem_t *item;

    SSF_REQUIRE(gobjParent != NULL);
    SSF_REQUIRE((gobjParent->dataType == SSF_OBJ_TYPE_OBJECT) ||
                (gobjParent->dataType == SSF_OBJ_TYPE_ARRAY));
    SSF_REQUIRE(gobjChild != NULL);

    if (gobjParent->children.size == 0) return false;
    if (SSFLLIsEmpty(&(gobjParent->children))) return false;

    item = SSF_LL_HEAD(&(gobjParent->children));
    while (item != NULL)
    {
        if (item == (SSFLLItem_t *)gobjChild)
        {
            SSFLLGetItem(&(gobjParent->children), &item, SSF_LL_LOC_ITEM, item);
            return true;
        }
        item = SSF_LL_NEXT_ITEM(item);
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object/parent is found in supplied path, else false.                          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFGObjFindPath(SSFGObj_t *gobjRoot, SSFCStrIn_t *path, SSFGObj_t **gobjParentOut,
                             SSFGObj_t **gobjOut, uint8_t depth)
{
    SSFLLItem_t *item;
    size_t cindex = 0;
    size_t pindex = (size_t)-1;
    size_t len;
    bool isPathMatch;

    SSF_REQUIRE(gobjRoot != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(gobjParentOut != NULL);
    SSF_REQUIRE(gobjOut != NULL);
    SSF_REQUIRE(*gobjOut == NULL);

    /* Return if recursing too deeply or path not set */
    if ((depth >= SSF_GOBJ_CONFIG_MAX_IN_DEPTH) || (path[depth] == NULL))
    {
        gobjParentOut = NULL;
        return false;
    }

    /* Is array type? */
    if (gobjRoot->dataType == SSF_OBJ_TYPE_ARRAY)
    {
        /* Yes, decode array index */
        memcpy(&pindex, path[depth], sizeof(size_t));
    }

    /* Object or array type? */
    if ((gobjRoot->dataType == SSF_OBJ_TYPE_OBJECT) || (gobjRoot->dataType == SSF_OBJ_TYPE_ARRAY))
    {
        /* Yes, assume this is the parent of the path object */
        *gobjParentOut = gobjRoot;

        /* Iterate over children */
        item = SSF_LL_HEAD(&(gobjRoot->children));
        while (item != NULL)
        {
            /* Object? */
            if (gobjRoot->dataType == SSF_OBJ_TYPE_OBJECT)
            {
                SSFGObj_t *tmp = (SSFGObj_t *)item;

                /* Yes, path match? */
                isPathMatch = false;
                if (tmp->labelCStr != NULL)
                {
                    len = SSF_MIN(strlen(tmp->labelCStr), strlen(path[depth]));
                    isPathMatch = (strncmp(tmp->labelCStr, path[depth], len + 1) == 0);
                }
            }
            /* No, index match? */
            else { isPathMatch = (cindex == pindex); }

            /* Object or array path match? */
            if (isPathMatch)
            {
                /* Yes, more path to check? */
                if (path[depth + 1] != NULL)
                {
                    /* Yes, recurse and look for path */
                    return _SSFGObjFindPath((SSFGObj_t *)item, path, gobjParentOut, gobjOut,
                                            depth + 1);
                }
                else
                {
                    /* No, found path, return obj and its parent obj */
                    *gobjOut = (SSFGObj_t *)item;
                    return true;
                }
            }
            cindex++;
            item = SSF_LL_NEXT_ITEM(item);
        }
    }
    else
    {
        /* No, is the label set? */
        if (gobjRoot->labelCStr != NULL)
        {
            /* Yes, does it match the path? */
            len = SSF_MIN(strlen(gobjRoot->labelCStr), strlen(path[depth]));
            if (strncmp(gobjRoot->labelCStr, path[depth], len + 1) == 0)
            {
                /* Yes, return the object */
                *gobjOut = gobjRoot;
                return true;
            }
        }
    }
    *gobjParentOut = NULL;
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object/parent is found in supplied path, else false.                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjFindPath(SSFGObj_t *gobjRoot, SSFCStrIn_t *path, SSFGObj_t **gobjParentOut,
                     SSFGObj_t **gobjChildOut)
{
    SSF_REQUIRE(gobjRoot != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(gobjParentOut != NULL);
    SSF_REQUIRE(*gobjParentOut == NULL);
    SSF_REQUIRE(gobjChildOut != NULL);
    SSF_REQUIRE(*gobjChildOut == NULL);

    /* Return if root is not an object or an array type */
    if ((gobjRoot->dataType != SSF_OBJ_TYPE_OBJECT) &&
        (gobjRoot->dataType != SSF_OBJ_TYPE_ARRAY)) return false;

    return _SSFGObjFindPath(gobjRoot, path, gobjParentOut, gobjChildOut, 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Iterates over every node in the object tree and invokes supplied callback with path context.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFGObjIterate(SSFGObj_t *gobj, SSFGObjIterateFn_t iterateCallback, SSFLL_t *path,
                            uint8_t depth)
{
    SSFLLItem_t *item;
    SSFLLItem_t *next;
    SSFGObjPathItem_t pathItem;
    SSFGObjPathItem_t *tmp;

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(iterateCallback != NULL);

    /* Return if depth too much */
    if (depth >= SSF_GOBJ_CONFIG_MAX_IN_DEPTH) return false;

    memset(&pathItem, 0, sizeof(pathItem));
    pathItem.index = -1;

    pathItem.gobj = gobj;
    SSFLLPutItem(path, (SSFLLItem_t *)&pathItem, SSF_LL_LOC_TAIL, NULL);
    iterateCallback(gobj, path);
    SSFLLGetItem(path, (SSFLLItem_t **)&tmp, SSF_LL_LOC_TAIL, NULL);

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
        _SSFGObjIterate((SSFGObj_t *)item, iterateCallback, path, depth + 1);
        SSFLLGetItem(path, (SSFLLItem_t **)&tmp, SSF_LL_LOC_TAIL, NULL);
        item = next;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if iteration successful over every node in the object tree else false            */
/* --------------------------------------------------------------------------------------------- */
bool SSFGObjIterate(SSFGObj_t *gobj, SSFGObjIterateFn_t iterateCallback)
{
    bool retVal;
    SSFLL_t path;

    SSF_REQUIRE(gobj != NULL);
    SSF_REQUIRE(iterateCallback != NULL);

    SSFLLInit(&path, SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1);
    retVal = _SSFGObjIterate(gobj, iterateCallback, &path, 0);
    SSFLLDeInit(&path);

    return retVal;
}

