/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfubjson.c                                                                                   */
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

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ssfport.h"
#include "ssfubjson.h"
#include "ssfhex.h"

/* Limitation - NOOP type not supported */
/* Limitation - Unicode string encoding/decoding & strings embedded with NULLs not supported */

/* TODO - Add printer for float and double */
/* TODO - Add printer for ASCII Hex and Base64 */
/* TODO - Add decoders for ASCII Hex and Base64 */
/* TODO - Parse optimized formatting. */
/* TODO - Print optimized array formatting. */
/* TODO - Write more unit tests */
/* TODO - Rework path definition to allow for 0 values in names, defined array indexes */

#define UBJ_TYPE_NULL 'Z'
#define UBJ_TYPE_NOOP 'N'
#define UBJ_TYPE_TRUE 'T'
#define UBJ_TYPE_FALSE 'F'
#define UBJ_TYPE_INT8 'i'
#define UBJ_TYPE_UINT8 'U'
#define UBJ_TYPE_INT16 'I'
#define UBJ_TYPE_INT32 'l'
#define UBJ_TYPE_INT64 'L'
#define UBJ_TYPE_FLOAT32 'd'
#define UBJ_TYPE_FLOAT64 'D'
#define UBJ_TYPE_CHAR 'C'
#define UBJ_TYPE_HPN 'H'
#define UBJ_TYPE_STRING 'S'
#define UBJ_TYPE_OBJ_OPEN '{'
#define UBJ_TYPE_ARRAY_OPEN '['
#define UBJ_TYPE_ARRAY_OPT '$'
#define UBJ_TYPE_ARRAY_NUM '#'
#define SSF_UBJSON_MAGIC 0x55424A53ul

// dup?
#if 0
#define SSFJsonEsc(j, b) do { j[start] = '\\'; start++; if (start >= size) return false; \
                              j[start] = b;} while (0)
#endif
static bool _SSFUBJsonValue(SSFUBJSONContext_t * context, uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
    SSFCStrIn_t * path, uint8_t depth, SSFUBJsonType_t *jt);

#include "ssfll.h"


void SSFUBJsonMalloc(uint32_t * ctr, uint32_t *total, void** ptr, size_t len)
{
    SSF_REQUIRE(ctr != NULL);
    SSF_REQUIRE(ptr != NULL);

    *ptr = malloc(len);
    SSF_ASSERT(*ptr != NULL);
    (*ctr)++;
    (*total) += len;
}

void SSFUBJsonFree(uint32_t * ctr, uint32_t* total, void* ptr, size_t len)
{
    SSF_REQUIRE(ctr != NULL);
    SSF_REQUIRE(ptr != NULL);

    free(ptr);
    (*ctr)++;
    (*total) -= len;
}

// make this a config option
typedef uint8_t SSF_UBJSON_SIZE_t;

SSF_UBJSON_TYPEDEF_STRUCT {
    SSFLLItem_t item; /* Link to next Name Value pair, must be first */
    uint8_t* name; /* Pointer to Name */
    uint8_t* value; /* Pointer to Value */
    SSFLLItem_t* parent; /* Link to parent */
    SSFLL_t children; /* Link to list of nested children */ //jlh opt ll struct
    SSF_UBJSON_SIZE_t nameLen; /* Length of Name */
    SSF_UBJSON_SIZE_t valueLen; /* Length of Value */
    SSF_UBJSON_SIZE_t type; /* Type of Value */
    SSF_UBJSON_SIZE_t index;
    bool trim;
} SSFUBJSONNode_t;

static void _SSFUBJSONPushNameValue(SSFUBJSONContext_t* context, uint8_t *name, size_t nameLen, uint8_t *value, size_t valueLen,
    SSFUBJsonType_t type, uint8_t depth)
{
    SSFUBJSONNode_t* node;
    static uint8_t lastDepth = 0;
    uint8_t i;
    SSFLLItem_t* item;
    size_t index;

    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(value != NULL);
    SSF_REQUIRE((name != NULL) || ((name == NULL) && (nameLen == 0)));
    SSF_REQUIRE((type < SSF_UBJSON_TYPE_MAX) && (type != SSF_UBJSON_TYPE_ERROR));
    SSF_REQUIRE(depth < SSF_UBJSON_CONFIG_MAX_IN_DEPTH);

    /* Create a new node */
    SSFUBJsonMalloc(&context->mallocs, &context->mallocTotal, &node, sizeof(SSFUBJSONNode_t));
    //node = (SSFUBJSONNode_t*)malloc(sizeof(SSFUBJSONNode_t));
    //SSF_ASSERT(node != NULL);
    memset(node, 0, sizeof(SSFUBJSONNode_t));

    /* Name bigger than a pointer? */
    if (nameLen > sizeof(void*))
    {
        /* Yes, allocate space to save the name */
        SSFUBJsonMalloc(&context->mallocs, &context->mallocTotal, &node->name, nameLen);
        memcpy(node->name, name, nameLen);
    }
    else
    {
        /* No, store value of name in name pointer */
        memcpy(&node->name, name, nameLen);
    }
    node->nameLen = (SSF_UBJSON_SIZE_t) nameLen;

    /* TODO Skip saving values of objects and arrays */
    if (!((type == SSF_UBJSON_TYPE_OBJECT) || (type == SSF_UBJSON_TYPE_ARRAY)))
    {
        /* Name bigger than a pointer? */
        if (valueLen > sizeof(void*))
        {
            /* Yes, allocate space to save the value */
            SSFUBJsonMalloc(&context->mallocs, &context->mallocTotal, &node->value, valueLen);
            memcpy(node->value, value, valueLen);

        }
        else
        {
            /* No, store value of name in name pointer */
            memcpy(&node->value, value, valueLen);
        }
        node->valueLen = (SSF_UBJSON_SIZE_t) valueLen;
    }
    else
    {
        node->valueLen = 0;
    }
    node->type = type;
    //node->depth = depth;

    if ((type == SSF_UBJSON_TYPE_ARRAY) || (type == SSF_UBJSON_TYPE_OBJECT))
    {
        /* Add node to list */
        SSF_LL_FIFO_PUSH(&context->roots[depth], (SSFLLItem_t*)&(node->item));

        /* Roll up children */
        memcpy(&node->children, &context->roots[depth + 1], sizeof(SSFLL_t));
        memset(&context->roots[depth + 1], 0, sizeof(SSFLL_t));

        item = SSF_LL_TAIL(&node->children);
        index = 0;
        while (item != NULL)
        {
            SSFUBJSONNode_t* child;

            child = (SSFUBJSONNode_t*)item;
            child->parent = &node->item;
            child->index = (SSF_UBJSON_SIZE_t) index;
            if (type == SSF_UBJSON_TYPE_ARRAY)
            {
                index++;
            }
            item = SSF_LL_PREV_ITEM(item);
        }
    }
    else
    {
        /* Init roots to depth */
        for (i = 0; i <= depth; i++)
        {
            if (SSFLLIsInited(&context->roots[i]) == false)
            {
                SSFLLInit(&context->roots[i], 20);
            }
        }

        /* Add node to list */
        SSF_LL_FIFO_PUSH(&context->roots[depth], (SSFLLItem_t*)&(node->item));

        /* No children, no parent */
        memset(&node->children, 0, sizeof(SSFLL_t));
        node->parent = NULL;
    }
#if 0    
    printf("-");
    while (nameLen)
    {
        printf("%02X", (char)*name);
        nameLen--;
        name++;
    }
    printf("-");
    while (valueLen)
    {
        printf("%02X,%c", (char)*value, (char)*value);
        valueLen--;
        value++;
    }
    printf("-%d-D%d\r\n", type, depth);
#endif
}

#if 0
void PrintPath(SSFLLItem_t* parent)
{
    char* p;
    size_t l;
    SSFUBJSONNode_t* node;

    node = (SSFUBJSONNode_t*)parent;

    if (node == NULL) return;
    else if (node->parent != NULL) PrintPath(node->parent);
    printf(".");
    if (node->name == NULL)
    {
        printf("%i", node->index);
    }
    else
    {
        l = node->nameLen;
        if (l > sizeof(void*))
        {
            p = (char*)node->name;
        }
        else
        {
            p = (char*)&node->name;
        }
        while (l)
        {
            printf("%c", (char)*p);
            l--;
            p++;
        }
    }
    //printf("^");
}

void PrintRoot(SSFLL_t root)
{
    SSFLLItem_t* item;
    char* p;
    size_t l;

    printf("-------------------------------\r\n");
    item = SSF_LL_TAIL(&root);

    while (item != NULL)
    {
        SSFUBJSONNode_t* node;

        node = (SSFUBJSONNode_t*)item;

        if ((node->type == SSF_UBJSON_TYPE_OBJECT) || (node->type == SSF_UBJSON_TYPE_ARRAY))
        {
            PrintRoot(node->children);
        }

        /* Print path */
        PrintPath(node->parent);

        printf(".");
        if (node->name == NULL)
        {
            printf("%i", node->index);
        }
        else
        {
            l = node->nameLen;
            if (l > sizeof(void*))
            {
                p = (char*)node->name;
            }
            else
            {
                p = (char*)&node->name;
            }
            while (l)
            {
                printf("%c", (char)*p);
                l--;
                p++;
            }
        }
        printf("=");
        l = node->valueLen;
        if (l > sizeof(void*))
        {
            p = (char*)node->value;
        }
        else
        {
            p = (char*)&node->value;
        }
        while (l)
        {
            printf("%02X,%c ", (char)*p, (char)*p);
            l--;
            p++;
        }
        printf("-%d\r\n", node->type);

        item = SSF_LL_PREV_ITEM(item);
    }
}

#endif

/* --------------------------------------------------------------------------------------------- */
/* Returns true if array found, else false; If true returns type/start/end on path index match.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonArray(SSFUBJSONContext_t* context, uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
                            size_t *astart, size_t *aend, SSFCStrIn_t* path, uint8_t depth,
                            SSFUBJsonType_t *jt)
{
    size_t valStart;
    size_t valEnd;
    size_t curIndex = 0;
    size_t pindex = (size_t)-1;
    SSFUBJsonType_t djt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(astart != NULL);
    SSF_REQUIRE(aend != NULL);
    SSF_REQUIRE(depth >= 1);
    SSF_REQUIRE(jt != NULL);

    if (depth >= SSF_UBJSON_CONFIG_MAX_IN_DEPTH) return false;
    if (js[*index] != '[') return false;

    *astart = *index;
    if ((path != NULL) && (path[depth] == NULL)) *start = *index;
    (*index)++; if (*index >= jsLen) return false;

    if ((path != NULL) && (path[depth] != NULL)) memcpy(&pindex, path[depth], sizeof(size_t));

    while (_SSFUBJsonValue(context, js, jsLen, index, &valStart, &valEnd, path, depth, &djt) == true)
    {
        /* Emitter("array", &js[valStart], valEnd - valStart, djt); */
        if (context != NULL)
        {
            _SSFUBJSONPushNameValue(context, NULL, 0, &js[valStart], valEnd - valStart, djt, depth);
        }

        if (pindex == curIndex)
        {
            *start = valStart; *end = valEnd; *jt = djt;
        }
        if (js[*index] == ']') break;
        curIndex++;
    }
    if ((pindex != (size_t)-1) && (pindex > curIndex)) *jt = SSF_UBJSON_TYPE_ERROR;
    if (js[*index] != ']') return false;
    *aend = *index;


    if ((path != NULL) && (path[depth] == NULL))
    {*end = *index; *jt = SSF_UBJSON_TYPE_ARRAY; }
    (*index)++;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if type field found, else false; If true returns type/start/end on path match.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonTypeField(uint8_t *js, size_t jsLen, size_t *index, size_t *fstart,
                              size_t *fend, SSFUBJsonType_t *fjt)
{
    size_t len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(fstart != NULL);
    SSF_REQUIRE(fend != NULL);
    SSF_REQUIRE(fjt != NULL);

    switch (js[*index])
    {
    case UBJ_TYPE_FLOAT32:
        *fjt = SSF_UBJSON_TYPE_NUMBER_FLOAT32; len = sizeof(float);
        goto _ssfubParseInt;
    case UBJ_TYPE_FLOAT64:
        *fjt = SSF_UBJSON_TYPE_NUMBER_FLOAT64; len = sizeof(double);
        goto _ssfubParseInt;
    case UBJ_TYPE_INT16:
        *fjt = SSF_UBJSON_TYPE_NUMBER_INT16; len = sizeof(int16_t);
        goto _ssfubParseInt;
    case UBJ_TYPE_INT32:
        *fjt = SSF_UBJSON_TYPE_NUMBER_INT32; len = sizeof(int32_t);
        goto _ssfubParseInt;
    case UBJ_TYPE_INT64:
        *fjt = SSF_UBJSON_TYPE_NUMBER_INT64; len = sizeof(int64_t);
        goto _ssfubParseInt;
    case UBJ_TYPE_CHAR:
        *fjt = SSF_UBJSON_TYPE_STRING;
        len = sizeof(uint8_t);
        goto _ssfubParseInt;
    case UBJ_TYPE_UINT8:
        *fjt = SSF_UBJSON_TYPE_NUMBER_UINT8; len = sizeof(uint8_t);
        goto _ssfubParseInt;
    case UBJ_TYPE_INT8:
        *fjt = SSF_UBJSON_TYPE_NUMBER_INT8; len = sizeof(int8_t);
        /* Fall through on purpose */
    _ssfubParseInt:
        (*index)++; if (*index >= jsLen) return false;
        *fstart = *index;
        (*index) += len; if (*index >= jsLen) return false;
        *fend = *index;
        return true;
    case UBJ_TYPE_HPN:
#if SSF_UBJSON_CONFIG_HANDLE_HPN_AS_STRING == 0
        return false;
#endif
        /* Fallthough, treat HPN as a string */
    case UBJ_TYPE_STRING:
        {
            size_t tstart;
            size_t tend;
            SSFUBJsonType_t tjt;

            (*index)++; if (*index >= jsLen) return false;
            if (_SSFJsonTypeField(js, jsLen, index, &tstart, &tend, &tjt) == false) return false;
            switch (tjt)
            {
            case SSF_UBJSON_TYPE_NUMBER_INT8:
            case SSF_UBJSON_TYPE_NUMBER_UINT8:
            case SSF_UBJSON_TYPE_NUMBER_CHAR:
                len = js[tstart];
                break;
            default:
                /* Not allowing 16, 32, 64-bit types for name length */
                return false;
            }
            *fstart = *index;
            (*index) += len; if (*index >= jsLen) return false;
            *fend = *index;
            *fjt = SSF_UBJSON_TYPE_STRING;
            return true;
        }
    case UBJ_TYPE_OBJ_OPEN:
        *fjt = SSF_UBJSON_TYPE_OBJECT;
        return true;
    case UBJ_TYPE_ARRAY_OPEN:
        *fjt = SSF_UBJSON_TYPE_ARRAY;
        return true;
    case UBJ_TYPE_TRUE:
        *fjt = SSF_UBJSON_TYPE_TRUE;
        goto _ssfubParseSingle;
    case UBJ_TYPE_FALSE:
        *fjt = SSF_UBJSON_TYPE_FALSE;
        goto _ssfubParseSingle;
    case UBJ_TYPE_NULL:
        *fjt = SSF_UBJSON_TYPE_NULL;
    _ssfubParseSingle:
        (*index)++; if (*index >= jsLen) return false;
        *fstart = *index;
        *fend = *fstart;
        return true;
    default:
        break;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if value found, else false; If true returns type/start/end on path match.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUBJsonValue(SSFUBJSONContext_t* context, uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
    SSFCStrIn_t* path, uint8_t depth, SSFUBJsonType_t *jt)
{
    size_t i;
    size_t astart;
    size_t aend;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    /* Attempt to parse value field */
    if (_SSFJsonTypeField(js, jsLen, index, start, end, jt) == false)
    {return false; }

    i = *index;
    switch (*jt)
    {
    case SSF_UBJSON_TYPE_OBJECT:
        if (SSFUBJsonObject(context, js, jsLen, &i, start, end, path, depth + 1, jt))
        { 
            *index = i; 
            return true; 
        }
        break;
    case SSF_UBJSON_TYPE_ARRAY:
        if (_SSFUBJsonArray(context, js, jsLen, &i, start, end, &astart, &aend, path, depth + 1, jt))
        {
            *start = astart;
            *end = i;
            *index = i;
            return true;
        }
        break;
    case SSF_UBJSON_TYPE_STRING:
    case SSF_UBJSON_TYPE_NUMBER_FLOAT32:
    case SSF_UBJSON_TYPE_NUMBER_FLOAT64:
    case SSF_UBJSON_TYPE_NUMBER_INT8:
    case SSF_UBJSON_TYPE_NUMBER_UINT8:
    case SSF_UBJSON_TYPE_NUMBER_CHAR:
    case SSF_UBJSON_TYPE_NUMBER_INT16:
    case SSF_UBJSON_TYPE_NUMBER_INT32:
    case SSF_UBJSON_TYPE_NUMBER_INT64:
    case SSF_UBJSON_TYPE_TRUE:
    case SSF_UBJSON_TYPE_FALSE:
    case SSF_UBJSON_TYPE_NULL:
        *index = i; return true;
    default:
        break;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if name/value found, else false; If true returns type/start/end on path match.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFJsonNameValue(SSFUBJSONContext_t* context, uint8_t *js, size_t jsLen, size_t *index, size_t *start, size_t *end,
    SSFCStrIn_t* path, uint8_t depth, SSFUBJsonType_t *jt)
{
    size_t valStart;
    size_t valEnd;
    size_t fstart;
    size_t fend;
    size_t len;
    SSFUBJsonType_t fjt;
    SSFUBJsonType_t djt;
    bool retVal;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    /* Attempt to parse name field */
    if (_SSFJsonTypeField(js, jsLen, index, &fstart, &fend, &fjt) == false) return false;
    switch (fjt)
    {
    case SSF_UBJSON_TYPE_NUMBER_INT8:
    case SSF_UBJSON_TYPE_NUMBER_UINT8:
    case SSF_UBJSON_TYPE_NUMBER_CHAR:
        len = js[fstart];
        break;
    default:
        /* Not allowing 16, 32, 64-bit types for name length */
        return false;
    }
    fstart = *index;
    (*index) += len; if (*index >= jsLen) return false;
    fend = *index;

    /* Is path set and do we have a match? */
    if ((path != NULL) && (path[depth] != NULL) &&
        (strncmp(path[depth], (char *)&js[fstart],
                 SSF_MAX(fend - fstart, (size_t)strlen(path[depth]))) == 0))
    {
        /* Yes, keep matching */
        retVal = _SSFUBJsonValue(context, js, jsLen, index, start, end, path, depth, jt);
    }
    else
    {
        /* No, keep parsing */
        retVal = _SSFUBJsonValue(context, js, jsLen, index, &valStart, &valEnd, path, depth, &djt);
        if (retVal && (context != NULL))
        {
            _SSFUBJSONPushNameValue(context, &js[fstart], len, &js[valStart], valEnd - valStart, djt, depth);
        }
    }

    return retVal;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if object found, else false; If true returns type/start/end on path match.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonObject(SSFUBJSONContext_t* context, uint8_t* js, size_t jsLen, size_t* index, size_t* start, size_t* end,
    SSFCStrIn_t* path, uint8_t depth, SSFUBJsonType_t* jt)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(index != NULL);
    SSF_REQUIRE(start != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(jt != NULL);

    if (depth == 0)
    {
        if (jsLen > SSF_UBJSON_CONFIG_MAX_IN_LEN) return false;
        *jt = SSF_UBJSON_TYPE_ERROR;
        *index = 0;
    }
    if (depth >= SSF_UBJSON_CONFIG_MAX_IN_DEPTH) return false;

    if (js[*index] != '{') return false;
    if ((depth != 0) || ((depth == 0) && (path != NULL) && (path[0] == NULL))) *start = *index;
    //if (depth != 0) *start = *index;
    (*index)++; if (*index >= jsLen) return false;

    if (js[*index] != '}')
    {
        if (!_SSFJsonNameValue(context, js, jsLen, index, start, end, path, depth, jt)) return false;
        do
        {
            if (js[*index] == '}') break;
            if (!_SSFJsonNameValue(context, js, jsLen, index, start, end, path, depth, jt)) return false;
        } while (true);
        if (js[*index] != '}') return false;
        (*index)++;
    }
    else
    {
        (*index)++; *end = *index; *jt = SSF_UBJSON_TYPE_OBJECT;
    }
    if (context != NULL) *end = *index;//????jlh
    if (((path != NULL) && (path[depth] == NULL)) ||
        ((depth == 0) && (path != NULL) && (path[0] == NULL)))
    {
        *end = *index; *jt = SSF_UBJSON_TYPE_OBJECT;
    }
    /* If not at end of object then consider it not valid */
    if ((depth == 0) && (*index != jsLen)) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if UBJSON string is valid, else false.                                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonIsValid(uint8_t* js, size_t jsLen)
{
    size_t start;
    size_t end;
    size_t index;
    //size_t ostart;
    ///size_t oend;
    SSFUBJsonType_t jt;
    char* path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];

    SSF_REQUIRE(js != NULL);

    memset(path, 0, sizeof(path));
    if (!SSFUBJsonObject(NULL, js, jsLen, &index, &start, &end, (SSFCStrIn_t*)path, 0,
        &jt)) return false;

    return jt != SSF_UBJSON_TYPE_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SSF_JSON_TYPE_ERROR if JSON string is invalid or path not found, else valid type.     */
/* --------------------------------------------------------------------------------------------- */
SSFUBJsonType_t SSFUBJsonGetType(uint8_t* js, size_t jsLen, SSFCStrIn_t *path)
{
    size_t start;
    size_t end;
    //size_t ostart;
    //size_t oend;
    size_t index;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(path != NULL);

    if (!SSFUBJsonObject(NULL, js, jsLen, &index, &start, &end, path, 0, &jt))
    {
        jt = SSF_UBJSON_TYPE_ERROR;
    }
    return jt;
}
#if 1
/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and copied into buffer w/NULL term., else false.                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetString(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, SSFCStrOut_t out,
                        size_t outSize, size_t *outLen)
{
    size_t start;
    size_t end;
    size_t index;
    size_t len;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(NULL, js, jsLen, &index, &start, &end, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_STRING) return false;
    end--;

    index = 0;
    len = end - start + 1;
    if (outLen != NULL) *outLen = 0;

    while ((len != 0) && (index < (outSize - 1)))
    {
#if 0
        if (js[start] == '\\')
        {
            start++; len--;
            if (len == 0) return false;
            /* Potential escape sequence */
            if (js[start] == '"' || js[start] == '\\' || js[start] == '/')
            {
                out[index] = js[start];
            }
            else if (js[start] == 'n') //jlh bug in json parser!
            { out[index] = '\x0a'; goto nextesc; }
            else if (js[start] == 'r')
            { out[index] = '\x0d'; goto nextesc; }
            else if (js[start] == 't')
            { out[index] = '\x09'; goto nextesc; }
            else if (js[start] == 'f')
            { out[index] = '\x0c'; goto nextesc; }
            else if (js[start] == 'b')
            { out[index] = '\x08'; goto nextesc; }
            else if (js[start] != 'u') return false;

            if (outLen != NULL) (*outLen)++;
            start++; len--;
            if (len < 4) return false;
            if (index >= (outSize - 1 - 2)) return false;
            if (!SSFHexByteToBin((char *)&js[start], (uint8_t *)&out[index])) return false;
            index++;
            if (!SSFHexByteToBin((char *)&js[start + 2], (uint8_t *)&out[index])) return false;
            start += 3; len -= 3;
        }
        else
#endif
        {out[index] = js[start]; }
   // nextesc:
        if (outLen != NULL) (*outLen)++;
        start++; index++; len--;
    }
    if (index < outSize) out[index] = 0;
    return len == 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to float, else false.                                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetFloat(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, float *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFUBJsonType_t jt;
    uint32_t u32;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(NULL, js, jsLen, &index, &start, &end, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_NUMBER_FLOAT32) return false;
    if ((end - start) != sizeof(u32)) return false;
    memcpy(&u32, &js[start], sizeof(u32));
    u32 = ntohl(u32);
    memcpy(out, &u32, sizeof(float));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to double, else false.                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetDouble(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, double *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFUBJsonType_t jt;
    uint64_t u64;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(NULL, js, jsLen, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_UBJSON_TYPE_NUMBER_FLOAT64) return false;
    if ((end - start) != sizeof(u64)) return false;
    memcpy(&u64, &js[start], sizeof(u64));
    u64 = ntohll(u64);
    memcpy(out, &u64, sizeof(double));
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetInt8(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, int8_t *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(NULL, js, jsLen, &index, &start, &end, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_NUMBER_INT8) return false;
    if ((end - start) != sizeof(int8_t)) return false;
    *out = (int8_t)js[start];
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetUInt8(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, uint8_t *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(NULL, js, jsLen, &index, &start, &end, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_NUMBER_UINT8) return false;
    if ((end - start) != sizeof(uint8_t)) return false;
    *out = js[start];
    return true;
}
/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetInt16(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, int16_t *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFUBJsonType_t jt;
    uint16_t u16;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(NULL, js, jsLen, &index, &start, &end, path, 0, &jt)) return false;
    if (jt != SSF_UBJSON_TYPE_NUMBER_INT16) return false;
    if ((end - start) != sizeof(u16)) return false;
    memcpy(&u16, &js[start], sizeof(u16));
    u16 = ntohs(u16);
    *out = (int16_t)u16;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetInt32(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, int32_t *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFUBJsonType_t jt;
    uint32_t u32;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(NULL, js, jsLen, &index, &start, &end, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_NUMBER_INT32) return false;
    if ((end - start) != sizeof(u32)) return false;
    memcpy(&u32, &js[start], sizeof(u32));
    u32 = ntohl(u32);
    *out = (int32_t)u32;
    return true;
}
/* --------------------------------------------------------------------------------------------- */
/* Returns true if found and is converted to int type, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonGetInt64(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, int64_t *out)
{
    size_t index;
    size_t start;
    size_t end;
    SSFUBJsonType_t jt;
    uint64_t u64;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(path != NULL);
    SSF_REQUIRE(path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] == NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFUBJsonObject(NULL, js, jsLen, &index, &start, &end, path, 0, &jt))
    { return false; }
    if (jt != SSF_UBJSON_TYPE_NUMBER_INT64) return false;
    if ((end - start) != sizeof(u64)) return false;
    memcpy(&u64, &js[start], sizeof(u64));
    u64 = ntohll(u64);
    *out = (int64_t)u64;
    return true;
}
#endif
/* --------------------------------------------------------------------------------------------- */
/* Returns true if char added to js, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintUnescChar(uint8_t *js, size_t size, size_t start, size_t *end, const char in)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);

    if (start >= size) return false;
    js[start] = in;
    *end = start + 1;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if all printing added successfully to JSON string, else false.                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrint(uint8_t *js, size_t jsSize, size_t start, size_t *end, SSFUBJsonPrintFn_t fn,
                    void *in, const char *oc)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= jsSize);
    SSF_REQUIRE(end != NULL);

    if ((oc != NULL) && (!SSFUBJsonPrintUnescChar(js, jsSize, start, &start, oc[0]))) return false;
    if ((fn != NULL) && (!fn(js, jsSize, start, &start, in))) return false;
    if ((oc != NULL) && (!SSFUBJsonPrintUnescChar(js, jsSize, start, &start, oc[1]))) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in string added successfully as string, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintCString(uint8_t *js, size_t size, size_t start, size_t *end, SSFCStrIn_t in)
{
    size_t len;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    len = strlen(in);

    /* Only support strings up to 255 bytes */
    if (len > 256) return false;

    /* Always use uint8_t as type for string length */
    js[start] = 'U'; start++; if (start >= size) return false;
    js[start] = (uint8_t)len; start++; if (start >= size) return false;

    while (start < size)
    {
//        if (*in == '\\') SSFJsonEsc(js, '\\');
//        else if (*in == '\"') SSFJsonEsc(js, '\"');
//        else if (*in == '/') SSFJsonEsc(js, '/');
//        else if (*in == '\r') SSFJsonEsc(js, 'r');
//        else if (*in == '\n') SSFJsonEsc(js, 'n');
//        else if (*in == '\t') SSFJsonEsc(js, 't');
//        else if (*in == '\b') SSFJsonEsc(js, 'b');
//        else if (*in == '\f') SSFJsonEsc(js, 'f');
        //else 
//        if (((*in > 0x1f) && (*in < 0x7f)) || (*in == 0))
        {
            js[start] = *in;
        } /* Normal ASCII character */
  //      else
  //      {
  //          if (start + 6 >= size) return false;
  //          js[start] = '\\'; start++;
  //          js[start] = 'u'; start++;
  //          js[start] = '0'; start++;
  //          js[start] = '0'; start++;
  //          snprintf((char *)&js[start], 3, "%02X", (uint8_t)*in);
  //          start++;
  //      }
        if (*in == 0)
        {
            *end = start; return true;
        }
        start++;
        in++;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in string added successfully as string, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintString(uint8_t *js, size_t size, size_t start, size_t *end, SSFCStrIn_t in)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    if (!SSFUBJsonPrintUnescChar(js, size, start, &start, 'S')) return false;
    if (!SSFUBJsonPrintCString(js, size, start, &start, in)) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in label added successfully as string, else false.                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintLabel(uint8_t *js, size_t size, size_t start, size_t *end, SSFCStrIn_t label)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(label != NULL);

    if (label[0] == 0) return false;
    return SSFUBJsonPrintCString(js, size, start, end, label);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if in signed int added successfully to JSON string, else false.                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonPrintInt(uint8_t *js, size_t size, size_t start, size_t *end, int64_t in)
{
    uint8_t type;
    size_t len = 0;
    uint8_t *pi;
    int8_t i8;
    uint8_t ui8;
    int16_t i16;
    int32_t i32;

    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(start <= size);
    SSF_REQUIRE(end != NULL);

    if (in < 128l) type = UBJ_TYPE_INT8;
    else if (in < 256l) type = UBJ_TYPE_UINT8;
    else if (in < 32768l) type = UBJ_TYPE_INT16;
    else if (in < 2147483648ll) type = UBJ_TYPE_INT32;
    else type = UBJ_TYPE_INT64;

    if (!SSFUBJsonPrintUnescChar(js, size, start, &start, type)) return false;
    switch (type)
    {
    case UBJ_TYPE_INT8:
        i8 = (int8_t)in; pi = (uint8_t *)&i8; len = sizeof(i8);
        break;
    case UBJ_TYPE_UINT8:
        ui8 = (uint8_t)in; pi = &ui8; len = sizeof(ui8);
        break;
    case UBJ_TYPE_INT16:
        i16 = (int16_t)in; i16 = htons(i16); pi = (uint8_t *)&i16; len = sizeof(i16);
        break;
    case UBJ_TYPE_INT32:
        i32 = (int32_t)in; i32 = htonl(i32); pi = (uint8_t *)&i32; len = sizeof(i32);
        break;
    case UBJ_TYPE_INT64:
        in = htonll(in); pi = (uint8_t *)&in; len = sizeof(in);
        break;
    default:
        SSF_ERROR();
    };
    if ((start + len) >= size) return false;
    memcpy(&js[start], pi, len);
    *end = start + len;
    return true;
}



/* --------------------------------------------------------------------------------------------- */
/* Returns true if UBJSON string is valid, else false.                                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonContextInitParse(SSFUBJSONContext_t* context, uint8_t* js, size_t jsLen)
{
    size_t start;
    size_t end;
    size_t index;
    SSFUBJsonType_t jt;

    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(jsLen <= SSF_UBJSON_CONFIG_MAX_IN_LEN);
    SSF_REQUIRE(context->magic == SSF_UBJSON_MAGIC);
    SSF_REQUIRE(SSFLLIsInited(&context->roots[0]) == false);

    if (!SSFUBJsonObject(context, js, jsLen, &index, &start, &end, NULL, 0, &jt)) return false;
    return jsLen == index; // jt != SSF_UBJSON_TYPE_ERROR;
}

#if 0
/* --------------------------------------------------------------------------------------------- */
/* Returns true if json is parsed successfully into context, else false.                         */
/* --------------------------------------------------------------------------------------------- */
bool __SSFUBJsonParse(SSFUBJSONContext_t* context, uint8_t* js, size_t jsLen)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(jsLen <= SSF_UBJSON_CONFIG_MAX_IN_LEN);
    SSF_REQUIRE(context->magic == SSF_UBJSON_MAGIC);

    return SSFUBJsonParse(context, js, jsLen);
}
#endif

/* --------------------------------------------------------------------------------------------- */
/* Initializes a context.                                                                        */
/* --------------------------------------------------------------------------------------------- */
void SSFUBJsonInitContext(SSFUBJSONContext_t* context)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic != SSF_UBJSON_MAGIC);

    memset(context, 0, sizeof(SSFUBJSONContext_t));
    context->magic = SSF_UBJSON_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if context inited else false.                                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFUBJsonIsContextInited(SSFUBJSONContext_t* context)
{
    SSF_REQUIRE(context != NULL);

    return context->magic == SSF_UBJSON_MAGIC;
}

bool _SSFUBJsonContextIterate(SSFLL_t *root, SSFCStrIn_t* path, uint8_t depth, SSFUBJsonIterateFn_t callback, void* data)
{
    SSFLLItem_t* item;
//    char pathName[sizeof(void*) + 1];
//    char* p;

    if (SSFLLIsInited(root))
    {
        item = SSF_LL_TAIL(root);
        while (item != NULL)
        {
            SSFUBJSONNode_t* node;

            node = (SSFUBJSONNode_t*)item;

            if (node->nameLen > sizeof(void*))
            {
                path[depth] = (char *)node->name;
            }
            else
            {
                path[depth] = (char *) & (node->name);
            }
            if (SSFLLIsInited(&node->children))
            {
                _SSFUBJsonContextIterate(&node->children, path, depth + 1, callback, data);
            }
            callback(path, data, &node->trim);
#if 0
            SSF_LL_FIFO_POP(root, &item);
            if (node->nameLen > sizeof(void*))
            {
                SSFUBJsonFree(cnt, total, node->name, node->nameLen);
            }
            if (node->valueLen > sizeof(void*))
            {
                SSFUBJsonFree(cnt, total, node->value, node->valueLen);
            }
            SSFUBJsonFree(cnt, total, node, sizeof(SSFUBJSONNode_t));
#endif
            item = SSF_LL_PREV_ITEM(item);
        }
    }
    path[depth] = NULL;
    return true;
}

bool SSFUBJsonContextIterate(SSFUBJSONContext_t* context, SSFUBJsonIterateFn_t callback, void* data)
{
    char* path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];
    uint8_t depth = 0;

    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_UBJSON_MAGIC);

    memset(path, 0, sizeof(path));
    _SSFUBJsonContextIterate(&context->roots[0], path, depth, callback, data);
    return true;
}

void _SSFUBJsonContextDeInitParse(SSFLL_t *root, uint8_t depth, uint32_t *cnt, uint32_t *total)
{
    SSFLLItem_t* item;
    SSFLLItem_t* next;

    if (SSFLLIsInited(root))
    {
        item = SSF_LL_TAIL(root);
        while (item != NULL)
        {
            SSFUBJSONNode_t* node;

            node = (SSFUBJSONNode_t*)item;
            next = SSF_LL_PREV_ITEM(item);

            if (SSFLLIsInited(&node->children))
            {
                _SSFUBJsonContextDeInitParse(&node->children, depth, cnt, total);
            }
            SSF_LL_FIFO_POP(root, &item);
            if (node->nameLen > sizeof(void*))
            {
                SSFUBJsonFree(cnt, total, node->name, node->nameLen);
            }
            if (node->valueLen > sizeof(void*))
            {
                SSFUBJsonFree(cnt, total, node->value, node->valueLen);
            }
            SSFUBJsonFree(cnt, total, node, sizeof(SSFUBJSONNode_t));
            item = next;
        }
    }
    return;
}

void SSFUBJsonContextDeInitParse(SSFUBJSONContext_t* context)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_UBJSON_MAGIC);

    _SSFUBJsonContextDeInitParse(&context->roots[0], 0, &context->frees, &context->mallocTotal);
    SSF_ASSERT(context->mallocs == context->frees);
    SSF_ASSERT(context->mallocTotal == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes a context.                                                                      */
/* --------------------------------------------------------------------------------------------- */
void SSFUBJsonDeInitContext(SSFUBJSONContext_t* context)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_UBJSON_MAGIC);

    SSFUBJsonContextDeInitParse(context);
    memset(context, 0, sizeof(SSFUBJSONContext_t));
}

bool SSFUBJsonPrintUnescBytes(uint8_t* js, size_t size, size_t start, size_t* end, uint8_t *in, size_t inLen)
{
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(end != NULL);
    SSF_REQUIRE(in != NULL);

    while (inLen)
    {
        if (start >= size) return false;
        js[start] = (char) * in;
        start++;
        in++;
        inLen--;
    }
    *end = start;
    return true;
}


bool PrintActualRoot(SSFLL_t root, uint8_t* js, size_t size, size_t* start)
{
    SSFLLItem_t* item;
    uint8_t* p;
    //size_t l;
    //char s[256]; // bad
    //uint64_t in;
    uint8_t len;

    item = SSF_LL_TAIL(&root);
    while (item != NULL)
    {
        SSFUBJSONNode_t* node;

        node = (SSFUBJSONNode_t*)item;
        if (node->trim) goto trimit;
        if (node->name != NULL)
        {
            if (node->nameLen > sizeof(void*))
            {
                p = node->name;
            }
            else
            {
                p =  (uint8_t *) & node->name;
            }

            len = node->nameLen;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t *)"i", 1)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, &len, 1)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, p, node->nameLen)) return false;
        }
        if (node->valueLen > sizeof(void*))
        {
            p = node->value;
        }
        else
        {
            p = (uint8_t *) & node->value;
        }
        len = node->valueLen;
        switch (node->type)
        {
        case SSF_UBJSON_TYPE_STRING:
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"Si", 2)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, &len, 1)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, p, node->valueLen)) return false;
            break;
        case SSF_UBJSON_TYPE_NUMBER_INT8:
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"i", 1)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, p, node->valueLen)) return false;
            break;
        case SSF_UBJSON_TYPE_NUMBER_UINT8:
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"U", 1)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, p, node->valueLen)) return false;
            break;
        case SSF_UBJSON_TYPE_NUMBER_CHAR:
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"C", 1)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, p, node->valueLen)) return false;
            break;
        case SSF_UBJSON_TYPE_NUMBER_INT16:
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"I", 1)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, p, node->valueLen)) return false;
            break;
        case SSF_UBJSON_TYPE_NUMBER_INT32:
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"l", 1)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, p, node->valueLen)) return false;
            break;
        case SSF_UBJSON_TYPE_NUMBER_INT64:
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"L", 1)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, p, node->valueLen)) return false;
            break;
        case SSF_UBJSON_TYPE_NUMBER_FLOAT32:
            SSF_ERROR();
            break;
        case SSF_UBJSON_TYPE_NUMBER_FLOAT64:
            SSF_ERROR();
            break;
        case SSF_UBJSON_TYPE_OBJECT:
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"{", 1)) return false;
            if (!PrintActualRoot(node->children, js, size, start)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"}", 1)) return false;
            break;
        case SSF_UBJSON_TYPE_ARRAY:
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"[", 1)) return false;
            if (!PrintActualRoot(node->children, js, size, start)) return false;
            if (!SSFUBJsonPrintUnescBytes(js, size, *start, start, (uint8_t*)"]", 1)) return false;
            break;
        case SSF_UBJSON_TYPE_TRUE:
            if (SSFUBJsonPrintTrue(js, size, *start, start)) return false;
            break;
        case SSF_UBJSON_TYPE_FALSE:
            if (SSFUBJsonPrintFalse(js, size, *start, start)) return false;
            break;
        case SSF_UBJSON_TYPE_NULL:
            if (SSFUBJsonPrintNull(js, size, *start, start)) return false;
            break;
        default:
            SSF_ERROR();
        }
trimit:
        item = SSF_LL_PREV_ITEM(item);
    }
    return true;
}

bool SSFUBJsonContextGenerate(SSFUBJSONContext_t* context, uint8_t* js, size_t size, size_t* jsLen)
{
    SSF_REQUIRE(context != NULL);
    SSF_REQUIRE(context->magic == SSF_UBJSON_MAGIC);
    SSF_REQUIRE(js != NULL);
    SSF_REQUIRE(jsLen != NULL);

    *jsLen = 0;
    if (!SSFUBJsonPrintUnescBytes(js, size, *jsLen, jsLen, (uint8_t*)"{", 1)) return false;
    if (!PrintActualRoot(context->roots[0], js, size, jsLen)) return false;
    if (!SSFUBJsonPrintUnescBytes(js, size, *jsLen, jsLen, (uint8_t*)"}", 1)) return false;
    return true;
}

