/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfgobj_ut.c                                                                                  */
/* Unit test for flexible API to r/w/modify structured data & conversion from & to other codecs. */
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


/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
void SSFGObjPathToString(SSFLL_t* path)
{
    SSFGObjPathItem_t* pi;
    SSFLLItem_t* item;
    SSFLLItem_t* next;

    SSF_REQUIRE(path != NULL);

    item = SSF_LL_HEAD(path);
    while (item != NULL)
    {
        next = SSF_LL_NEXT_ITEM(item);
        pi = (SSFGObjPathItem_t*)item;
        if (pi->gobj->labelCStr != NULL)
        {
            printf(".%s", pi->gobj->labelCStr);
        }
        if (pi->index >= 0)
        {
            printf("[%d]", pi->index);
        }
        item = next;
    }
}

void iterateCallback(SSFGObj_t* gobj, SSFLL_t* path, uint8_t depth)
{
    SSFObjType_t dataType;

    SSF_UNUSED(depth);
    SSF_REQUIRE(gobj != NULL);

    dataType = SSFGObjGetType(gobj);

    SSFGObjPathToString(path);
    printf(" : ");
    switch (gobj->dataType)
    {
    case SSF_OBJ_TYPE_UINT:
    {
        uint64_t u64;
        SSFGObjGetUInt(gobj, &u64);
        printf("%llud 0x%08llX", u64, u64);
    }
    break;
    default:
        break;
    }
    printf("\r\n");
}

/* --------------------------------------------------------------------------------------------- */
/* Unit test for Generic Object interface, does not return on failure.                           */
/* --------------------------------------------------------------------------------------------- */
void SSFGObjUnitTest(void)
{
    char cStr[20];
    uint8_t bin[32];
    uint8_t binOut[32];
    int64_t i64;
    uint64_t u64;
    double f64;
    bool b;
    size_t binLen;
    SSFGObj_t* gobj = (SSFGObj_t*)1;
    SSFGObj_t* gobjChild1 = NULL;
    SSFGObj_t* gobjChild2 = NULL;
    SSFGObj_t* gobjChild3 = NULL;
    SSFGObj_t* gobjParentOut = NULL;
    SSFGObj_t* gobjChildOut = NULL;
    size_t aidx1;
    size_t aidx2;
    char* path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];

    /* Test SSFGObjInit() and SSFGObjDeInit() */
    SSF_ASSERT_TEST(SSFGObjInit(NULL, 0));
    SSF_ASSERT_TEST(SSFGObjInit(&gobj, 0));

    gobj = NULL;
    SSF_ASSERT(SSFGObjInit(&gobj, 0));
    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    SSF_ASSERT(SSFGObjInit(&gobj, 1));
    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    /* Test SSFGObjGetType() and SSFGObjGetSize() */
    SSF_ASSERT_TEST(SSFGObjGetType(NULL));
    SSF_ASSERT_TEST(SSFGObjGetSize(NULL));

    /* Test SSFGObjSetLabel() and SSFGObjGetLabel() */
    SSF_ASSERT(SSFGObjInit(&gobj, 1));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    SSF_ASSERT_TEST(SSFGObjSetLabel(NULL, "label"));

    SSF_ASSERT(SSFGObjSetLabel(gobj, "label"));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    SSF_ASSERT(SSFGObjGetLabel(gobj, cStr, sizeof(cStr)));
    SSF_ASSERT(strlen(cStr) == 5);
    SSF_ASSERT(memcmp(cStr, "label", 6) == 0);
    memset(cStr, 0, sizeof(cStr));
    SSF_ASSERT(SSFGObjGetLabel(gobj, cStr, 0) == false);
    SSF_ASSERT(SSFGObjGetLabel(gobj, cStr, 5) == false);
    SSF_ASSERT(SSFGObjGetLabel(gobj, cStr, 6));
    SSF_ASSERT(strlen(cStr) == 5);
    SSF_ASSERT(memcmp(cStr, "label", 6) == 0);
    SSF_ASSERT(SSFGObjSetLabel(gobj, NULL));
    SSF_ASSERT(SSFGObjGetLabel(gobj, cStr, 6) == false);
    SSF_ASSERT(SSFGObjSetLabel(gobj, "label"));
    SSF_ASSERT(strlen(cStr) == 5);
    SSF_ASSERT(memcmp(cStr, "label", 6) == 0);
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);

    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    /* Test SSFGObjSetString() and SSFGObjGetString() */
    SSF_ASSERT(SSFGObjInit(&gobj, 1));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    SSF_ASSERT_TEST(SSFGObjSetString(NULL, "value"));

    SSF_ASSERT(SSFGObjSetString(gobj, "value"));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_STR);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 6);
    SSF_ASSERT(SSFGObjGetString(gobj, cStr, sizeof(cStr)));
    SSF_ASSERT(strlen(cStr) == 5);
    SSF_ASSERT(memcmp(cStr, "value", 6) == 0);
    memset(cStr, 0, sizeof(cStr));
    SSF_ASSERT(SSFGObjGetString(gobj, cStr, 0) == false);
    SSF_ASSERT(SSFGObjGetString(gobj, cStr, 5) == false);
    SSF_ASSERT(SSFGObjGetString(gobj, cStr, 6));
    SSF_ASSERT(strlen(cStr) == 5);
    SSF_ASSERT(memcmp(cStr, "value", 6) == 0);
    SSF_ASSERT_TEST(SSFGObjSetString(gobj, NULL));
    SSF_ASSERT(SSFGObjSetNone(gobj));
    SSF_ASSERT(SSFGObjGetString(gobj, cStr, 6) == false);
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    SSF_ASSERT(SSFGObjSetString(gobj, "value"));
    SSF_ASSERT(strlen(cStr) == 5);
    SSF_ASSERT(memcmp(cStr, "value", 6) == 0);
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_STR);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 6);

    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    /* Test SSFGObjSetInt() and SSFGObjGetInt() */
    SSF_ASSERT(SSFGObjInit(&gobj, 1));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);

    SSF_ASSERT_TEST(SSFGObjSetInt(NULL, 0));
    SSF_ASSERT_TEST(SSFGObjGetInt(NULL, &i64));
    SSF_ASSERT_TEST(SSFGObjGetInt(gobj, NULL));

    SSF_ASSERT(SSFGObjSetInt(gobj, 0));
    i64 = 1;
    SSF_ASSERT(SSFGObjGetInt(gobj, &i64));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_INT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(int64_t));
    SSF_ASSERT(i64 == 0);

    SSF_ASSERT(SSFGObjSetInt(gobj, 1));
    i64 = 0;
    SSF_ASSERT(SSFGObjGetInt(gobj, &i64));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_INT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(int64_t));
    SSF_ASSERT(i64 == 1);

    SSF_ASSERT(SSFGObjSetInt(gobj, 9223372036854775807ull));
    i64 = 0;
    SSF_ASSERT(SSFGObjGetInt(gobj, &i64));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_INT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(int64_t));
    SSF_ASSERT(i64 == 9223372036854775807ull);

    SSF_ASSERT(SSFGObjSetInt(gobj, -9223372036854775808ll));
    i64 = 0;
    SSF_ASSERT(SSFGObjGetInt(gobj, &i64));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_INT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(int64_t));
    SSF_ASSERT(i64 == -9223372036854775808ll);

    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    /* Test SSFGObjSetUInt() and SSFGObjGetUInt() */
    SSF_ASSERT(SSFGObjInit(&gobj, 1));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);

    SSF_ASSERT_TEST(SSFGObjSetUInt(NULL, 0));
    SSF_ASSERT_TEST(SSFGObjGetUInt(NULL, &u64));
    SSF_ASSERT_TEST(SSFGObjGetUInt(gobj, NULL));

    SSF_ASSERT(SSFGObjSetUInt(gobj, 0));
    u64 = 1;
    SSF_ASSERT(SSFGObjGetUInt(gobj, &u64));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_UINT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(uint64_t));
    SSF_ASSERT(u64 == 0);

    SSF_ASSERT(SSFGObjSetUInt(gobj, 1));
    u64 = 0;
    SSF_ASSERT(SSFGObjGetUInt(gobj, &u64));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_UINT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(uint64_t));
    SSF_ASSERT(u64 == 1);

    SSF_ASSERT(SSFGObjSetUInt(gobj, 18446744073709551615ull));
    u64 = 0;
    SSF_ASSERT(SSFGObjGetUInt(gobj, &u64));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_UINT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(uint64_t));
    SSF_ASSERT(u64 == 18446744073709551615ull);

    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    /* Test SSFGObjSetFloat() and SSFGObjGetFloat() */
    SSF_ASSERT(SSFGObjInit(&gobj, 1));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);

    SSF_ASSERT_TEST(SSFGObjSetFloat(NULL, 0));
    SSF_ASSERT_TEST(SSFGObjGetFloat(NULL, &f64));
    SSF_ASSERT_TEST(SSFGObjGetFloat(gobj, NULL));

    SSF_ASSERT(SSFGObjSetFloat(gobj, 0));
    f64 = 1.0;
    SSF_ASSERT(SSFGObjGetFloat(gobj, &f64));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_FLOAT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(double));
    SSF_ASSERT(f64 == 0.0);

    SSF_ASSERT(SSFGObjSetFloat(gobj, 1.23));
    f64 = 0.0;
    SSF_ASSERT(SSFGObjGetFloat(gobj, &f64));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_FLOAT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(double));
    SSF_ASSERT(f64 == 1.23);

    SSF_ASSERT(SSFGObjSetFloat(gobj, -1.23));
    f64 = 0.0;
    SSF_ASSERT(SSFGObjGetFloat(gobj, &f64));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_FLOAT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(double));
    SSF_ASSERT(f64 == -1.23);

    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    /* Test SSFGObjSetBool() and SSFGObjGetBool() */
    SSF_ASSERT(SSFGObjInit(&gobj, 1));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);

    SSF_ASSERT_TEST(SSFGObjSetBool(NULL, 0));
    SSF_ASSERT_TEST(SSFGObjGetBool(NULL, &b));
    SSF_ASSERT_TEST(SSFGObjGetBool(gobj, NULL));

    SSF_ASSERT(SSFGObjSetBool(gobj, true));
    b = false;
    SSF_ASSERT(SSFGObjGetBool(gobj, &b));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_BOOL);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(bool));
    SSF_ASSERT(b == true);

    SSF_ASSERT(SSFGObjSetBool(gobj, false));
    b = true;
    SSF_ASSERT(SSFGObjGetBool(gobj, &b));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_BOOL);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(bool));
    SSF_ASSERT(b == false);

    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    /* Test SSFGObjSetNull(), SSFGObjSetObject(), and SSFGObjSetArray() */
    SSF_ASSERT(SSFGObjInit(&gobj, 1));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);

    SSF_ASSERT_TEST(SSFGObjSetNull(NULL));
    SSF_ASSERT_TEST(SSFGObjSetObject(NULL));
    SSF_ASSERT_TEST(SSFGObjSetArray(NULL));

    SSF_ASSERT(SSFGObjSetNull(gobj));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NULL);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);

    SSF_ASSERT(SSFGObjSetObject(gobj));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_OBJECT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);

    SSF_ASSERT(SSFGObjSetArray(gobj));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_ARRAY);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);

    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    /* Test SSFGObjSetBool() and SSFGObjGetBool() */
    SSF_ASSERT(SSFGObjInit(&gobj, 1));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);

    SSF_ASSERT_TEST(SSFGObjSetBin(NULL, bin, sizeof(bin)));
    SSF_ASSERT_TEST(SSFGObjSetBin(gobj, NULL, sizeof(bin)));
    SSF_ASSERT_TEST(SSFGObjGetBin(NULL, binOut, sizeof(binOut), &binLen));
    SSF_ASSERT_TEST(SSFGObjGetBin(gobj, NULL, sizeof(binOut), NULL));

    memset(bin, 0x11, sizeof(bin));
    SSF_ASSERT(SSFGObjSetBin(gobj, bin, sizeof(bin)));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_BIN);
    SSF_ASSERT(SSFGObjGetSize(gobj) == sizeof(bin));
    memset(binOut, 0, sizeof(binOut));
    binLen = 0;
    SSF_ASSERT(SSFGObjGetBin(gobj, binOut, sizeof(binOut), &binLen));
    SSF_ASSERT(binLen == sizeof(bin));
    SSF_ASSERT(memcmp(binOut, bin, sizeof(binOut)) == 0);

    memset(bin, 0x11, sizeof(bin));
    SSF_ASSERT(SSFGObjSetBin(gobj, bin, 0));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_BIN);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    memset(binOut, 0, sizeof(binOut));
    binLen = 1;
    SSF_ASSERT(SSFGObjGetBin(gobj, binOut, sizeof(binOut), &binLen));
    SSF_ASSERT(binLen == 0);
    SSF_ASSERT(memcmp(binOut, bin, 0) == 0);

    memset(bin, 0x11, sizeof(bin));
    SSF_ASSERT(SSFGObjSetBin(gobj, bin, 1));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_BIN);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 1);
    memset(binOut, 0, sizeof(binOut));
    binLen = 0;
    SSF_ASSERT(SSFGObjGetBin(gobj, binOut, sizeof(binOut), NULL));
    SSF_ASSERT(binLen == 0);
    SSF_ASSERT(memcmp(binOut, bin, 1) == 0);

    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    /* Test SSFGObjInsertChild() and SSFGObjRemoveChild() */
    SSF_ASSERT(SSFGObjInit(&gobj, 2));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    SSF_ASSERT(SSFGObjInit(&gobjChild1, 0));
    SSF_ASSERT(SSFGObjGetType(gobjChild1) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobjChild1) == 0);
    SSF_ASSERT(SSFGObjInit(&gobjChild2, 0));
    SSF_ASSERT(SSFGObjGetType(gobjChild2) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobjChild2) == 0);
    SSF_ASSERT(SSFGObjInit(&gobjChild3, 0));
    SSF_ASSERT(SSFGObjGetType(gobjChild3) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobjChild3) == 0);

    SSF_ASSERT_TEST(SSFGObjInsertChild(NULL, gobjChild1));
    SSF_ASSERT_TEST(SSFGObjInsertChild(gobj, gobjChild1));
    SSF_ASSERT(SSFGObjSetObject(gobj));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_OBJECT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    SSF_ASSERT_TEST(SSFGObjInsertChild(gobj, NULL));
    SSF_ASSERT(SSFGObjSetArray(gobj));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_ARRAY);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    SSF_ASSERT_TEST(SSFGObjInsertChild(gobj, NULL));
    SSF_ASSERT(SSFGObjSetNone(gobj));

    SSF_ASSERT_TEST(SSFGObjRemoveChild(NULL, gobjChild1));
    SSF_ASSERT_TEST(SSFGObjRemoveChild(gobj, gobjChild1));
    SSF_ASSERT(SSFGObjSetObject(gobj));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_OBJECT);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    SSF_ASSERT_TEST(SSFGObjRemoveChild(gobj, NULL));
    SSF_ASSERT(SSFGObjSetArray(gobj));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_ARRAY);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    SSF_ASSERT_TEST(SSFGObjRemoveChild(gobj, NULL));
    SSF_ASSERT(SSFGObjSetNone(gobj));

    SSF_ASSERT(SSFGObjSetObject(gobj));
    SSF_ASSERT(SSFGObjInsertChild(gobj, gobjChild1));
    SSF_ASSERT(SSFGObjInsertChild(gobj, gobjChild2));
    SSF_ASSERT(SSFGObjInsertChild(gobj, gobjChild3) == false);
    SSF_ASSERT(SSFGObjRemoveChild(gobj, gobjChild3) == false);
    SSF_ASSERT(SSFGObjRemoveChild(gobj, gobjChild2));
    SSF_ASSERT(SSFGObjRemoveChild(gobj, gobjChild2) == false);
    SSF_ASSERT(SSFGObjInsertChild(gobj, gobjChild3));
    SSF_ASSERT(SSFGObjRemoveChild(gobj, gobjChild1));
    SSF_ASSERT(SSFGObjRemoveChild(gobj, gobjChild1) == false);
    SSF_ASSERT(SSFGObjRemoveChild(gobj, gobjChild3));
    SSF_ASSERT(SSFGObjRemoveChild(gobj, gobjChild3) == false);
    SSF_ASSERT(SSFGObjInsertChild(gobj, gobjChild2));
    SSF_ASSERT(SSFGObjInsertChild(gobj, gobjChild1));
    SSF_ASSERT(SSFGObjInsertChild(gobj, gobjChild3) == false);

    SSFGObjDeInit(&gobj);
    SSFGObjDeInit(&gobjChild3);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

    /* Test SSFGObjFindPath() */
    SSF_ASSERT(SSFGObjInit(&gobj, 3));
    SSF_ASSERT(SSFGObjGetType(gobj) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobj) == 0);
    gobjChild1 = NULL;
    SSF_ASSERT(SSFGObjInit(&gobjChild1, 3));
    SSF_ASSERT(SSFGObjGetType(gobjChild1) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobjChild1) == 0);
    gobjChild2 = NULL;
    SSF_ASSERT(SSFGObjInit(&gobjChild2, 3));
    SSF_ASSERT(SSFGObjGetType(gobjChild2) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobjChild2) == 0);
    gobjChild3 = NULL;
    SSF_ASSERT(SSFGObjInit(&gobjChild3, 3));
    SSF_ASSERT(SSFGObjGetType(gobjChild3) == SSF_OBJ_TYPE_NONE);
    SSF_ASSERT(SSFGObjGetSize(gobjChild3) == 0);

    memset(path, 0, sizeof(path));
    SSF_ASSERT_TEST(SSFGObjFindPath(NULL, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT_TEST(SSFGObjFindPath(gobj, NULL, &gobjParentOut, &gobjChildOut));
    path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH] = (void *)1;
    SSF_ASSERT_TEST(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH] = NULL;
    SSF_ASSERT_TEST(SSFGObjFindPath(gobj, path, NULL, &gobjChildOut));
    gobjParentOut = (void*)1;
    SSF_ASSERT_TEST(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    gobjParentOut = NULL;
    SSF_ASSERT_TEST(SSFGObjFindPath(gobj, path, &gobjParentOut, NULL));
    gobjChildOut = (void*)1;
    SSF_ASSERT_TEST(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    gobjChildOut = NULL;

    /* {c1, c2, c3} */
    SSF_ASSERT(SSFGObjSetObject(gobj));
    SSF_ASSERT(SSFGObjInsertChild(gobj, gobjChild1));
    SSF_ASSERT(SSFGObjInsertChild(gobj, gobjChild2));
    SSF_ASSERT(SSFGObjInsertChild(gobj, gobjChild3));
    SSF_ASSERT(SSFGObjSetLabel(gobjChild1, "child1"));
    SSF_ASSERT(SSFGObjSetLabel(gobjChild2, "child2"));
    SSF_ASSERT(SSFGObjSetLabel(gobjChild3, "child3"));
    SSF_ASSERT(SSFGObjSetInt(gobjChild1, 1));
    SSF_ASSERT(SSFGObjSetInt(gobjChild2, 2));
    SSF_ASSERT(SSFGObjSetInt(gobjChild3, 3));

    path[0] = "child1";
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobj);
    SSF_ASSERT(gobjChildOut == gobjChild1);

    path[0] = "child2";
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobj);
    SSF_ASSERT(gobjChildOut == gobjChild2);

    path[0] = "child3";
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobj);
    SSF_ASSERT(gobjChildOut == gobjChild3);

    path[0] = "child4";
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut) == false);
    SSF_ASSERT(gobjParentOut == NULL);
    SSF_ASSERT(gobjChildOut == NULL);

    /* [c1, c2, c3] */
    SSF_ASSERT(SSFGObjSetArray(gobj));

    path[0] = (char*)&aidx1;
    aidx1 = 0;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobj);
    SSF_ASSERT(gobjChildOut == gobjChild1);

    aidx1 = 1;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobj);
    SSF_ASSERT(gobjChildOut == gobjChild2);

    aidx1 = 2;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobj);
    SSF_ASSERT(gobjChildOut == gobjChild3);

    aidx1 = 3;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut) == false);
    SSF_ASSERT(gobjParentOut == NULL);
    SSF_ASSERT(gobjChildOut == NULL);

    /* {c1:{c2:[c3]}} */
    SSF_ASSERT(SSFGObjRemoveChild(gobj, gobjChild2));
    SSF_ASSERT(SSFGObjRemoveChild(gobj, gobjChild3));
    SSF_ASSERT(SSFGObjSetObject(gobj));
    SSF_ASSERT(SSFGObjSetObject(gobjChild1));
    SSF_ASSERT(SSFGObjInsertChild(gobjChild1, gobjChild2));
    SSF_ASSERT(SSFGObjSetArray(gobjChild2));
    SSF_ASSERT(SSFGObjInsertChild(gobjChild2, gobjChild3));

    path[0] = (char*)"child1";
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobj);
    SSF_ASSERT(gobjChildOut == gobjChild1);

    path[1] = (char*)"child2";
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobjChild1);
    SSF_ASSERT(gobjChildOut == gobjChild2);

    path[2] = (char*)&aidx1;
    aidx1 = 0;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobjChild2);
    SSF_ASSERT(gobjChildOut == gobjChild3);

    aidx1 = 1;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut) == false);
    SSF_ASSERT(gobjParentOut == NULL);
    SSF_ASSERT(gobjChildOut == NULL);

    path[0] = "child2";
    aidx1 = 0;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut) == false);
    SSF_ASSERT(gobjParentOut == NULL);
    SSF_ASSERT(gobjChildOut == NULL);

    path[0] = "child1";
    path[1] = "child3";
    aidx1 = 0;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut) == false);
    SSF_ASSERT(gobjParentOut == NULL);
    SSF_ASSERT(gobjChildOut == NULL);

    /* {c1:[c2:[c3]]} */
    SSF_ASSERT(SSFGObjSetArray(gobjChild1));
    path[0] = "child1";
    path[1] = (char*)&aidx1;
    path[2] = (char*)&aidx2;
    aidx1 = 0;
    aidx2 = 0;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobjChild2);
    SSF_ASSERT(gobjChildOut == gobjChild3);

    aidx2 = 1;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut) == false);
    SSF_ASSERT(gobjParentOut == NULL);
    SSF_ASSERT(gobjChildOut == NULL);

    path[2] = NULL;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobjChild1);
    SSF_ASSERT(gobjChildOut == gobjChild2);

    aidx1 = 1;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut) == false);
    SSF_ASSERT(gobjParentOut == NULL);
    SSF_ASSERT(gobjChildOut == NULL);

    path[1] = NULL;
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut));
    SSF_ASSERT(gobjParentOut == gobj);
    SSF_ASSERT(gobjChildOut == gobjChild1);

    path[0] = "child2";
    gobjParentOut = NULL;
    gobjChildOut = NULL;
    SSF_ASSERT(SSFGObjFindPath(gobj, path, &gobjParentOut, &gobjChildOut) == false);
    SSF_ASSERT(gobjParentOut == NULL);
    SSF_ASSERT(gobjChildOut == NULL);

    /* Test SSFGObjIterate() {c1:[c2:{c3}]} */
    SSFGObjSetObject(gobjChild2);
    SSFGObjSetLabel(gobjChild2, NULL);
    //SSFGObjIterate(gobj, iterateCallback, 0);

    SSFGObjDeInit(&gobj);
    SSF_ASSERT(SSFGObjIsMemoryBalanced());

#if 0
    SSFGObj_t* gobj = NULL;
    SSFGObj_t* gobjPeer = NULL;
    SSFGObj_t* gobjPeer2 = NULL;
    SSFGObj_t* gobjChild = NULL;
    SSFGObj_t* gobjChild2 = NULL;
    uint64_t valueOut;
    int64_t i64;
    double d64;
    char str[2000];
    size_t length;
    bool comma = false;

    SSF_ASSERT(SSFGObjInit(&gobj, 10, 10));
    SSF_ASSERT(SSFGObjSetLabel(gobj, "label"));
    SSF_ASSERT(SSFGObjSetString(gobj, "value"));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobj, &comma));


    SSF_ASSERT(SSFGObjSetUInt(gobj, 0x11223344));
    SSF_ASSERT(SSFGObjGetUInt(gobj, &valueOut));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobj, &comma));


    SSF_ASSERT(SSFGObjInit(&gobjPeer, 10, 10));

    SSF_ASSERT(SSFGObjInsertPeer(gobj, gobjPeer));

    SSF_ASSERT(SSFGObjSetObject(gobjPeer));

    SSF_ASSERT(SSFGObjInit(&gobjChild, 1, 1));
    SSF_ASSERT(SSFGObjSetLabel(gobjChild, "childlabel"));
    SSF_ASSERT(SSFGObjSetUInt(gobjChild, 12345));

    SSF_ASSERT(SSFGObjInit(&gobjChild2, 1, 1));
    SSF_ASSERT(SSFGObjSetLabel(gobjChild2, "childlabel2"));
    SSF_ASSERT(SSFGObjSetUInt(gobjChild2, 67890));

    SSF_ASSERT(SSFGObjInsertChild(gobjPeer, gobjChild));
    SSF_ASSERT(SSFGObjInsertChild(gobjPeer, gobjChild2));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobjChild, &comma));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobjPeer, &comma));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobj, &comma));

    SSF_ASSERT(SSFGObjInit(&gobjPeer2, 1, 1));
    SSF_ASSERT(SSFGObjSetLabel(gobjPeer2, "peerlabel2"));
    SSF_ASSERT(SSFGObjSetInt(gobjPeer2, -11223344));
    SSF_ASSERT(SSFGObjGetInt(gobjPeer2, &i64));
    SSF_ASSERT(SSFGObjInsertPeer(gobjPeer, gobjPeer2));
    gobjPeer2 = NULL;
    SSF_ASSERT(SSFGObjInit(&gobjPeer2, 1, 1));
    SSF_ASSERT(SSFGObjSetLabel(gobjPeer2, "peerlabeldouble2"));
    SSF_ASSERT(SSFGObjSetFloat(gobjPeer2, -1.0987));
    SSF_ASSERT(SSFGObjGetFloat(gobjPeer2, &d64));
    SSF_ASSERT(SSFGObjInsertPeer(gobjPeer, gobjPeer2));
    gobjPeer2 = NULL;
    SSF_ASSERT(SSFGObjInit(&gobjPeer2, 1, 10));
    SSF_ASSERT(SSFGObjSetLabel(gobjPeer2, "peerarray2"));
    SSF_ASSERT(SSFGObjSetArray(gobjPeer2));
    SSF_ASSERT(SSFGObjInsertPeer(gobjPeer, gobjPeer2));
    gobjChild = NULL;
    SSF_ASSERT(SSFGObjInit(&gobjChild, 1, 1));
    SSF_ASSERT(SSFGObjSetUInt(gobjChild, 1));
    SSF_ASSERT(SSFGObjInsertChild(gobjPeer2, gobjChild));

    length = 0;
    comma = false;
    SSF_ASSERT(SSFGObjToJson(str, sizeof(str), length, &length, gobj, &comma));

    SSFGObjIterate(gobj, iterateCallback, 0);


    SSFGObjDeInit(&gobj);

#endif


}