/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfubjson_ut.c                                                                                */
/* Provides Universal Binary JSON parser/generator unit test.                                    */
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
#include "ssfubjson.h"
#include "ssfassert.h"

#define UBJTS_NUM_ITEMS(x, s) (sizeof((x)) / (s))

typedef struct SSFUBJSONUT {
    uint8_t *js;
    size_t jsLen;
    bool isValid;
} SSFUBJSONUT_t;

SSFUBJSONUT_t _ubjs[] = {
    { (uint8_t *)"", 0, false }, /* { */
    { (uint8_t *)"{", 1, false }, /* { */
    { (uint8_t *)"{i\x01" "a[$i#i\x00}", 11, true },  /* */
    { (uint8_t *)"{i\x01" "a[$i#i\x0a\x01]\x03\x04\x05\x06\x07\x08\x09\x0a}", 21, true },  /* */
    { (uint8_t *)"{i\x01" "a[$i#i\x0a\x01\x02\x03\x04\x05\x06\x07\x08\x09]}", 21, true },  /* */
    { (uint8_t *)"{i\x01" "a[#i\x0ai\x01i\x02i\x03i\x04i\x05i\x06i\x07i\x08i\x09i\x0a}", 29, true },  /* */
    { (uint8_t *)"{}", 2, true },  /* {} */
    { (uint8_t *)"{N}", 3, true },  /* {} */
    { (uint8_t *)"{i\x05helloSi\x05worldN}", 18, true },  /* {} */
    { (uint8_t *)"{NN}", 4, true },  /* {} */
    { (uint8_t *)"{NNN}", 5, true },  /* {} */
    { (uint8_t*)"{i\x01y[]}", 7, true },  /* {} */
    { (uint8_t*)"{i\x01y[N]}", 8, true },  /* {} */
    { (uint8_t *)"{i\x01y[i5N]}", 10, true },  /* {} */
    { (uint8_t *)"{i\x01y[Ni6]}", 10, true },  /* {} */
    { (uint8_t *)"{i\x01y[i5Ni6]}", 12, true },  /* {} */
    { (uint8_t *)"{i\x01y[i5NNi6]}", 13, true },  /* {} */
    { (uint8_t *)"{Ni\x01y[Ni5NNi6N]N}", 17, true },  /* {} */
    { (uint8_t *)"{}1", 3, false }, /* {}1 */
#if SSF_UBJSON_CONFIG_HANDLE_HPN_AS_STRING == 0
    { (uint8_t*)"{i\x01sHi\x05" "12345}", 13, false }, /* {"s":"12345"} */
#endif
    { (uint8_t *)"{i\x05helloSi\x05world}", 17, true }, /* {"hello":"world"} */
    { (uint8_t *)"{i\x05helloSi\x05world}1", 18, false }, /* {"hello":"world"}1 */
    { (uint8_t *)"{i\x05helloSi\x05world}", 16, false }, /* {"hello":"world"} */
    { (uint8_t *)"{i\x05helloSi\x05worl}", 16, false }, /* {"hello":"worl"} */
    { (uint8_t *)"{i\x05helloZ}", 10, true }, /* {"hello":null} */
    { (uint8_t *)"{i\x05helloi\x01}", 11, true }, /* {"hello":1}*/
    { (uint8_t *)"{i\x05helloU\x81}", 11, true }, /* {"hello":129}*/
    { (uint8_t *)"{i\x05helloC4}", 11, true }, /* {"hello":"4"} */
    { (uint8_t *)"{i\x05helloI\x01\x00}", 12, true }, /* {"hello":256} */
    { (uint8_t *)"{i\x05helloI\x12" "4}", 12, true }, /* {"hello":4660} */
    { (uint8_t *)"{i\x05helloI\x7F\xFF}", 12, true }, /* {"hello":32767} */
    { (uint8_t *)"{i\x05hellol\x00\x00\x80\x00}", 14, true }, /* {"hello":32768} */
    { (uint8_t *)"{i\x05hellol\x7F\xFF\xFF\xFF}", 14, true }, /* {"hello":2147483647} */
    { (uint8_t *)"{i\x05helloL\x00\x00\x00\x00\x80\x00\x00\x00}", 18, true }, /* {"hello":2147483648} */
    { (uint8_t *)"{i\x05helloT}", 10, true }, /* {"hello":true} */
    { (uint8_t *)"{i\x05helloF}", 10, true }, /* {"hello":false}, */
    { (uint8_t *)"{i\x05hello{}}", 11, true }, /* {"hello":{}} */
    { (uint8_t *)"{i\x05hello{i\03abcSi\x05world}}", 24, true }, /* {"hello":{"abc":"world"}}, */
    { (uint8_t *)"{i\x05hello{i\03numi\x01}}", 18, true }, /* {"hello":{"num":1}}, */
    { (uint8_t *)"{i\x05hello{i\03numU\x81}}", 18, true }, /* {"hello":{"num":129}}, */
    { (uint8_t *)"{i\x05hello{i\03abcC4i\03def{}}}", 25, true }, /* {"hello":{"abc":"4","def":{}}}, */
    { (uint8_t *)"{i\x05hello{i\03abcC4i\03def{i\x01ZZ}}}", 29, true }, /* {"hello":{"abc":"4","def":{"Z":null}}}, */
    { (uint8_t *)"{i\x05hello{i\03abcC4}}", 18, true }, /* {"hello":{"abc":"4"}}, */
    { (uint8_t *)"{i\x05hello{i\03abcI\x01\x00}}", 19, true }, /* {"hello":{"abc":256}}, */
    { (uint8_t *)"{i\x05hello{i\03abcI\x12" "4}}", 19, true }, /* {"hello":{"abc":4660}}, */
    { (uint8_t *)"{i\x05hello{i\03abcI\x7F\xFF}}", 19, true }, /* {"hello":{"abc":32767}}, */
    { (uint8_t *)"{i\x05hello{i\03abcl\x00\x00\x80\x00}}", 21, true }, /* {"hello":{"abc":32768}}, */
    { (uint8_t *)"{i\x05hello{i\03abcl\x7F\xFF\xFF\xFF}}", 21, true }, /* {"hello":{"abc":2147483647}}, */
    { (uint8_t *)"{i\x05hello{i\03abcL\x00\x00\x00\x00\x80\x00\x00\x00}}", 25, true }, /* {"hello":{"abc":2147483648}}, */
    { (uint8_t *)"{i\x05hello{i\03abcT}}", 17, true }, /* {"hello":{"abc":true}}, */
    { (uint8_t *)"{i\x05hello{i\03abcF}}", 17, true }, /* {"hello":{"abc":false}}, */
    { (uint8_t *)"{i\x05hello{i\03abcZ}}", 17, true }, /* {"hello":{"abc":null}}, */
    { (uint8_t *)"{i\x05hellodO\x00\x00\x00}", 14, true }, /* {"hello":2147483648} */
    { (uint8_t *)"{i\x05helloDA\xE0\x00\x00\x1F\x9C\x08" "1}", 18, true }, /* {"hello":2147483900.876} */
    { (uint8_t *)"{i\x05hello[]}", 11, true }, /* {"hello":[]} */
    { (uint8_t *)"{i\x05hello[i\x03]}", 13, true }, /* {"hello":[3]} */
    { (uint8_t *)"{i\x05hello[i\x03i\x04Si\x05world]}", 23, true }, /* {"hello":[3,4,"world"]} */
    { (uint8_t *)"{i\x05hello[i\x03i\x04Si\x05world[]]}", 25, true }, /* {"hello":[3,4,"world",[]]} */
    { (uint8_t *)"{i\x05hello[i\x03i\x04Si\x05world{}]}", 25, true }, /* {"hello":[3,4,"world",{}]} */
    { (uint8_t *)"{i\x05hello[i\x03i\x04Si\x05world{i\x03" "abcT}]}", 31, true }, /* {"hello":[3,4,"world",{"abc":true}]} */
    { (uint8_t*)"{i\x01xiXi\x01" "a{i\x01" "b{i\x01" "ciCi\x01" "diDi\x01w{}}i\x01" "eiE}i\x01" "fiFi\x01I[iP{i\x01qiQ}iSiT]}", 60, true } /*  */
};

typedef struct SSFUBJSONNUM {
    uint8_t *js;
    size_t jsLen;
    SSFUBJsonType_t type;
} SSFUBJSONNUM_t;

SSFUBJSONNUM_t _ubjtsTypeNumber[] =
{
    { (uint8_t *)"{i\x01ni\x7f}", 7, SSF_UBJSON_TYPE_NUMBER_INT8 }, /* {"n":127} */
    { (uint8_t *)"{i\x01nU\x81}", 7, SSF_UBJSON_TYPE_NUMBER_UINT8 }, /* {"n":129} */
    { (uint8_t *)"{i\x01nC4}", 7, SSF_UBJSON_TYPE_STRING }, /* {"n":"4"} */
    { (uint8_t *)"{i\x01nI\x01\x00}", 8, SSF_UBJSON_TYPE_NUMBER_INT16 }, /* {"n":256} */
    { (uint8_t *)"{i\x01nl\x00\x00\x80\x00}", 10, SSF_UBJSON_TYPE_NUMBER_INT32 }, /* {"n":32768} */
    { (uint8_t *)"{i\x01nL\x00\x00\x00\x00\x80\x00\x00\x00}", 14, SSF_UBJSON_TYPE_NUMBER_INT64 }, /* {"n":2147483648} */
    { (uint8_t *)"{i\x01ndO\x00\x00\x00}", 10, SSF_UBJSON_TYPE_NUMBER_FLOAT32 }, /* {"n":2147483648} */
    { (uint8_t *)"{i\x01nDA\xE0\x00\x00\x1F\x9C\x08" "1}", 14, SSF_UBJSON_TYPE_NUMBER_FLOAT64 } /* {"n":2147483900.876} */
};

typedef struct SSFUBJSONGEN {
    uint8_t *js;
    size_t jsLen;
} SSFUBJSONGEN_t;

typedef SSFUBJSONGEN_t SSFUBJSONSTR_t;
SSFUBJSONSTR_t _ubjtsTypeString[] =
{
#if SSF_UBJSON_CONFIG_HANDLE_HPN_AS_STRING == 1
    { (uint8_t*)"{i\x01sHi\x05" "12345}", 13 }, /* {"s":"12345"} */
#endif
    { (uint8_t*)"{i\x01sC4}", 7 }, /* {"s":"4"} */
    { (uint8_t *)"{i\x01sSi\x00}", 8 }, /* {"s":""} */
    { (uint8_t *)"{i\x01sSi\x01z}", 9 }, /* {"s":"z"} */
    { (uint8_t *)"{i\x01sSi\x05world}", 13 } /* {"s":"world"} */
};

typedef SSFUBJSONGEN_t SSFUBJSONOBJ_t;
SSFUBJSONOBJ_t _ubjtsTypeObject[] =
{
    { (uint8_t *)"{i\x01o{}}", 7 }, /* {"o":{}} */
    { (uint8_t *)"{i\x01o{i\x02o2{}}}", 13 } /* {"o":{"o2":{}}} */
};

typedef SSFUBJSONGEN_t SSFUBJSONARR_t;
SSFUBJSONARR_t _ubjtsTypeArray[] =
{
    { (uint8_t *)"{i\x01" "a[]}", 7 }, /* {"a":[]} */
    { (uint8_t *)"{i\x01" "a[Si\x02" "a2]}", 12 } /* {"a":["a2"]}} */
};

uint8_t _ubjOptArray1[] = "{i\x01" "a[#i\x0ai\x01i\x02i\x03i\x04i\x05i\x06i\x07i\x08i\x09i\x0a}";
size_t _ubjOptArray1Len = 29;
uint8_t _ubjOptArray2[] = "{i\x01" "a[$i#i\x0a\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a}";
size_t _ubjOptArray2Len = 21;
uint8_t _ubjOptArray3[] = "{i\x01" "a[$I#i\x0a\x01\x01\x01\x02\x01\x03\x01\x04\x01\x05\x01\x06\x01\x07\x01\x08\x01\x09\x01\x0a}";
size_t _ubjOptArray3Len = 31;

bool _SSFUBJsonPrintFn1(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    char *s = (char *)in;

    if (s == NULL) return false;
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "hello")) return false;
    if (!SSFUBJsonPrintString(js, size, start, &start, s)) return false;
    *end = start;
    return true;
}

bool _SSFUBJsonPrintOptArray(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    size_t *alen = (size_t *)in;
    size_t i;

    for (i = 0; i < *alen; i++)
    {
        if (!SSFUBJsonPrintInt(js, size, start, &start, ((int64_t) i) + 1, true,
                               SSF_UBJSON_TYPE_NUMBER_UINT8)) return false;
        *end = start;
    }
    return true;
}

bool _SSFUBJsonPrintFn2(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    size_t *alen = (size_t*)in;

    if (!SSFUBJsonPrintLabel(js, size, start, &start, "a")) return false;
    if (!SSFUBJsonPrintArrayOpt(js, size, start, &start,
        _SSFUBJsonPrintOptArray, alen, SSF_UBJSON_TYPE_NUMBER_UINT8, *alen)) return false;
    *end = start;
    return true;
}

bool _SSFUBJsonPrintFn3(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    size_t *alen = (size_t*)in;

    SSF_ASSERT(alen != NULL);
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "h")) return false;
    if (!SSFUBJsonPrintHex(js, size, start, &start, (uint8_t *)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        16, false)) return false;
        *end = start;
    return true;
}

bool _SSFUBJsonPrintFn4(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    size_t *alen = (size_t*)in;

    SSF_ASSERT(alen != NULL);
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "b")) return false;
    if (!SSFUBJsonPrintBase64(js, size, start, &start, (uint8_t *)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        16)) return false;
        *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* ssfubjson unit test.                                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFUBJsonUnitTest(void)
{
    uint16_t i;
    uint16_t j;
    char *path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];
    size_t aidx1;
    char outStr[128];
    size_t outStrLen;
    float outFloat;
    double outDouble;
    int8_t outI8;
    uint8_t outU8;
    int16_t outI16;
    uint16_t outU16;
    int32_t outI32;
    uint32_t outU32;
    int64_t outI64;
    uint64_t outU64;
    uint8_t jsOut[128];
    size_t jsOutStart;
    size_t jsOutEnd;
    size_t alen;
    uint8_t *outPtr;
    size_t outPtrLen;

    /* Test interface assertions */
    SSF_ASSERT_TEST(SSFUBJsonIsValid(NULL, 1));
    memset(path, 0, sizeof(path));
    SSF_ASSERT_TEST(SSFUBJsonGetType(NULL, 1, NULL));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = "bad";
    SSF_ASSERT_TEST(SSFUBJsonGetType(NULL, 1, (SSFCStrIn_t *)path));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = NULL;
    SSF_ASSERT_TEST(SSFUBJsonGetString(NULL, 1, (SSFCStrIn_t *)path, outStr, sizeof(outStr), &outStrLen));
    SSF_ASSERT_TEST(SSFUBJsonGetString((uint8_t *)"{}", 1, NULL, outStr, sizeof(outStr), &outStrLen));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = "bad";
    SSF_ASSERT_TEST(SSFUBJsonGetString((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, outStr, sizeof(outStr), &outStrLen));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = NULL;
    SSF_ASSERT_TEST(SSFUBJsonGetString((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, NULL, sizeof(outStr), &outStrLen));
    SSF_ASSERT_TEST(SSFUBJsonGetHex(NULL, 1, (SSFCStrIn_t *)path, jsOut, sizeof(jsOut), &outStrLen, false));
    SSF_ASSERT_TEST(SSFUBJsonGetHex((uint8_t *)"{}", 1, NULL, jsOut, sizeof(jsOut), &outStrLen, false));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = "bad";
    SSF_ASSERT_TEST(SSFUBJsonGetHex((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, jsOut, sizeof(jsOut), &outStrLen, false));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = NULL;
    SSF_ASSERT_TEST(SSFUBJsonGetHex((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, NULL, sizeof(jsOut), &outStrLen, false));
    SSF_ASSERT_TEST(SSFUBJsonGetHex((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, jsOut, sizeof(jsOut), NULL, false));
    SSF_ASSERT_TEST(SSFUBJsonGetBase64(NULL, 1, (SSFCStrIn_t *)path, jsOut, sizeof(jsOut), &outStrLen));
    SSF_ASSERT_TEST(SSFUBJsonGetBase64((uint8_t *)"{}", 1, NULL, jsOut, sizeof(jsOut), &outStrLen));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = "bad";
    SSF_ASSERT_TEST(SSFUBJsonGetBase64((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, jsOut, sizeof(jsOut), &outStrLen));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = NULL;
    SSF_ASSERT_TEST(SSFUBJsonGetBase64((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, NULL, sizeof(jsOut), &outStrLen));
    SSF_ASSERT_TEST(SSFUBJsonGetFloat(NULL, 1, (SSFCStrIn_t *)path, &outFloat));
    SSF_ASSERT_TEST(SSFUBJsonGetFloat((uint8_t *)"{}", 1, NULL, &outFloat));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = "bad";
    SSF_ASSERT_TEST(SSFUBJsonGetFloat((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, &outFloat));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = NULL;
    SSF_ASSERT_TEST(SSFUBJsonGetFloat((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, NULL));
    SSF_ASSERT_TEST(SSFUBJsonGetDouble(NULL, 1, (SSFCStrIn_t *)path, &outDouble));
    SSF_ASSERT_TEST(SSFUBJsonGetDouble((uint8_t *)"{}", 1, NULL, &outDouble));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = "bad";
    SSF_ASSERT_TEST(SSFUBJsonGetDouble((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, &outDouble));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = NULL;
    SSF_ASSERT_TEST(SSFUBJsonGetDouble((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, NULL));
    SSF_ASSERT_TEST(SSFUBJsonGetInt(NULL, 1, (SSFCStrIn_t *)path, &outU8, 1, false));
    SSF_ASSERT_TEST(SSFUBJsonGetInt((uint8_t *)"{}", 1, NULL, &outU8, 1, false));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = "bad";
    SSF_ASSERT_TEST(SSFUBJsonGetInt((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, &outU8, 1, false));
    path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH] = NULL;
    SSF_ASSERT_TEST(SSFUBJsonGetInt((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, NULL, 1, false));
    SSF_ASSERT_TEST(SSFUBJsonGetInt((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, &outU8, 0, false));
    SSF_ASSERT_TEST(SSFUBJsonGetInt((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, &outU8, 3, false));
    SSF_ASSERT_TEST(SSFUBJsonGetInt((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, &outU8, 5, false));
    SSF_ASSERT_TEST(SSFUBJsonGetInt((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, &outU8, 6, false));
    SSF_ASSERT_TEST(SSFUBJsonGetInt((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, &outU8, 7, false));
    SSF_ASSERT_TEST(SSFUBJsonGetInt((uint8_t *)"{}", 1, (SSFCStrIn_t *)path, &outU8, 9, false));
    SSF_ASSERT_TEST(SSFUBJsonPrintChar(NULL, 1, jsOutStart, &jsOutEnd, 'c'));
    SSF_ASSERT_TEST(SSFUBJsonPrintChar(jsOut, 1, jsOutStart, NULL, 'c'));
    SSF_ASSERT_TEST(SSFUBJsonPrintLabel(NULL, sizeof(jsOut), jsOutStart, &jsOutEnd, "label"));
    SSF_ASSERT_TEST(SSFUBJsonPrintLabel(jsOut, sizeof(jsOut), jsOutStart, NULL, "label"));
    SSF_ASSERT_TEST(SSFUBJsonPrintLabel(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, NULL));
    SSF_ASSERT_TEST(SSFUBJsonPrint(NULL, 1, jsOutStart, &jsOutEnd, _SSFUBJsonPrintFn1, NULL, NULL));
    SSF_ASSERT_TEST(SSFUBJsonPrint(jsOut, 1, jsOutStart, NULL, _SSFUBJsonPrintFn1, NULL, NULL));
    SSF_ASSERT_TEST(SSFUBJsonPrintArrayOpt(NULL, sizeof(jsOut), jsOutStart, &jsOutEnd, _SSFUBJsonPrintFn1, NULL, SSF_UBJSON_TYPE_NUMBER_INT8, 1));
    SSF_ASSERT_TEST(SSFUBJsonPrintArrayOpt(jsOut, sizeof(jsOut), jsOutStart, NULL, _SSFUBJsonPrintFn1, NULL, SSF_UBJSON_TYPE_NUMBER_INT8, 1));
    SSF_ASSERT_TEST(SSFUBJsonPrintArrayOpt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, _SSFUBJsonPrintFn1, NULL, SSF_UBJSON_TYPE_NUMBER_FLOAT32, 1));
    SSF_ASSERT_TEST(SSFUBJsonPrintArrayOpt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, _SSFUBJsonPrintFn1, NULL, SSF_UBJSON_TYPE_NUMBER_INT8, 256));
    SSF_ASSERT_TEST(SSFUBJsonPrintString(NULL, sizeof(jsOut), jsOutStart, &jsOutEnd, "str"));
    SSF_ASSERT_TEST(SSFUBJsonPrintString(jsOut, sizeof(jsOut), jsOutStart, NULL, "str"));
    SSF_ASSERT_TEST(SSFUBJsonPrintString(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, NULL));
    SSF_ASSERT_TEST(SSFUBJsonPrintHex(NULL, sizeof(jsOut), jsOutStart, &jsOutEnd, (uint8_t *)"x", 1, false));
    SSF_ASSERT_TEST(SSFUBJsonPrintHex(jsOut, sizeof(jsOut), jsOutStart, NULL, (uint8_t *)"x", 1, false));
    SSF_ASSERT_TEST(SSFUBJsonPrintHex(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, NULL, 1, false));
    SSF_ASSERT_TEST(SSFUBJsonPrintHex(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (uint8_t *)"x", 128, false));
    SSF_ASSERT_TEST(SSFUBJsonPrintBase64(NULL, sizeof(jsOut), jsOutStart, &jsOutEnd, (uint8_t *)"x", 1));
    SSF_ASSERT_TEST(SSFUBJsonPrintBase64(jsOut, sizeof(jsOut), jsOutStart, NULL, (uint8_t *)"x", 1));
    SSF_ASSERT_TEST(SSFUBJsonPrintBase64(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, NULL, 1));
    SSF_ASSERT_TEST(SSFUBJsonPrintBase64(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (uint8_t *)"x", 190));
    SSF_ASSERT_TEST(SSFUBJsonPrintInt(NULL, sizeof(jsOut), jsOutStart, &jsOutEnd, 1, false, 0));
    SSF_ASSERT_TEST(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, NULL, 1, false, 0));
    SSF_ASSERT_TEST(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, 1, false, SSF_UBJSON_TYPE_STRING));
    SSF_ASSERT_TEST(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, 1, true, SSF_UBJSON_TYPE_STRING));
    SSF_ASSERT_TEST(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, 1, true, SSF_UBJSON_TYPE_NUMBER_FLOAT32));
    SSF_ASSERT_TEST(SSFUBJsonPrintFloat(NULL, sizeof(jsOut), jsOutStart, &jsOutEnd, 1.0));
    SSF_ASSERT_TEST(SSFUBJsonPrintFloat(jsOut, sizeof(jsOut), jsOutStart, NULL, 1.0));
    SSF_ASSERT_TEST(SSFUBJsonPrintDouble(NULL, sizeof(jsOut), jsOutStart, &jsOutEnd, 1.0));
    SSF_ASSERT_TEST(SSFUBJsonPrintDouble(jsOut, sizeof(jsOut), jsOutStart, NULL, 1.0));

    /* Parse opt integer arrays */
    memset(path, 0, sizeof(path));
    path[0] = "a";
    path[1] = (char *)&aidx1;
    for (aidx1 = 0;; aidx1++)
    {
        if (SSFUBJsonGetInt8(_ubjOptArray1, _ubjOptArray1Len, (SSFCStrIn_t *)path, &outI8) == false) break;
        SSF_ASSERT(outI8 == (int8_t) (aidx1 + 1));
    }
    SSF_ASSERT(aidx1 == 10);

    memset(path, 0, sizeof(path));
    path[0] = "a";
    path[1] = (char *)&aidx1;
    for (aidx1 = 0;; aidx1++)
    {
        if (SSFUBJsonGetInt8(_ubjOptArray2, _ubjOptArray2Len, (SSFCStrIn_t *)path, &outI8) == false) break;
        SSF_ASSERT(outI8 == (int8_t) (aidx1 + 1));
    }
    SSF_ASSERT(aidx1 == 10);

    path[1] = NULL;
    SSF_ASSERT(SSFUBJsonGetByteArrayPtr(_ubjOptArray2, _ubjOptArray2Len, (SSFCStrIn_t *)path, &outPtr, &outPtrLen));
    SSF_ASSERT(outPtrLen == 10);
    SSF_ASSERT(memcmp(outPtr, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a", outPtrLen) == 0);
    SSF_ASSERT(SSFUBJsonGetByteArrayPtr((uint8_t *)"{i\x01" "a[$i#i\x00}", 11, (SSFCStrIn_t *)path, &outPtr, &outPtrLen));
    SSF_ASSERT(outPtrLen == 0);
    SSF_ASSERT(SSFUBJsonGetByteArrayPtr((uint8_t *)"{i\x01" "a[$i#i\x01]}", 12, (SSFCStrIn_t *)path, &outPtr, &outPtrLen));
    SSF_ASSERT(outPtrLen == 1);
    SSF_ASSERT(*outPtr == ']');

    memset(path, 0, sizeof(path));
    path[0] = "a";
    path[1] = (char*)&aidx1;
    for (aidx1 = 0;; aidx1++)
    {
        if (SSFUBJsonGetInt16(_ubjOptArray3, _ubjOptArray3Len, (SSFCStrIn_t*)path, &outI16) == false) break;
        SSF_ASSERT(outI16 == (int16_t)(aidx1 + 1 + 256));
    }
    SSF_ASSERT(aidx1 == 10);

    memset(path, 0, sizeof(path));
    path[0] = "n";

    /* SSFUBJsonGetInt8() */
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01ni\x01}", 7, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 1l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01ni\x7f}", 7, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 127l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01ni\x80}", 7, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == -128l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01ni\xff}", 7, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == -1l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nU\x01}", 7, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 1l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nU\x7f}", 7, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 127l);
    SSF_ASSERT(false == SSFUBJsonGetInt8((uint8_t *)"{i\x01nU\x80}", 7, (SSFCStrIn_t *)path, &outI8));
    //SSF_ASSERT(outI8 == -128l);
    SSF_ASSERT(false == SSFUBJsonGetInt8((uint8_t *)"{i\x01nU\xff}", 7, (SSFCStrIn_t *)path, &outI8));
    //SSF_ASSERT(outI8 == -1l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nI\x00\x01}", 8, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 1l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nI\x00\x7f}", 8, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 127l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nI\x00\x80}", 8, (SSFCStrIn_t *)path, &outI8) == false);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nI\xff\x7f}", 8, (SSFCStrIn_t *)path, &outI8) == false);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == -128l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nI\xff\xff}", 8, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == -1l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nl\x00\x00\x00\x01}", 10, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 1l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nl\x00\x00\x00\x7f}", 10, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 127l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nl\x00\x00\x00\x80}", 10, (SSFCStrIn_t *)path, &outI8) == false);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nl\xff\xff\xff\x7f}", 10, (SSFCStrIn_t *)path, &outI8) == false);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nl\xff\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == -1l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == -128l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x01}", 14, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 1l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x7f}", 14, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 127l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x80}", 14, (SSFCStrIn_t *)path, &outI8)== false);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x7f}", 14, (SSFCStrIn_t *)path, &outI8) == false);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == -1l);
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x80}", 14, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == -128l);

    /* SSFUBJsonGetUInt8() */
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01ni\x01}", 7, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 1ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01ni\x7f}", 7, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 127ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01ni\x80}", 7, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 128ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01ni\xff}", 7, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 255ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nU\x01}", 7, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 1ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nU\x7f}", 7, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 127ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nU\x80}", 7, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 128ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nU\xff}", 7, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 255ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nI\x00\x01}", 8, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 1ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nI\x00\x7f}", 8, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 127ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nI\x00\x80}", 8, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 128ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nI\x00\xff}", 8, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 255ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nI\xff\x7f}", 8, (SSFCStrIn_t *)path, &outU8) == false);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outU8) == false);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nI\xff\xff}", 8, (SSFCStrIn_t *)path, &outU8) == false);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nl\x00\x00\x00\x01}", 10, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 1ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nl\x00\x00\x00\x7f}", 10, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 127ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nl\x00\x00\x00\x80}", 10, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 128ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nl\x00\x00\x00\xff}", 10, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 255ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nl\xff\xff\xff\x7f}", 10, (SSFCStrIn_t *)path, &outU8) == false);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nl\xff\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outU8) == false);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outU8) == false);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x01}", 14, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 1ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x7f}", 14, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 127ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x80}", 14, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 128ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\xff}", 14, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 255ul);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x7f}", 14, (SSFCStrIn_t *)path, &outU8) == false);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outU8) == false);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x80}", 14, (SSFCStrIn_t *)path, &outU8) == false);

    /* SSFUBJsonGetInt16() */
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01ni\x01}", 7, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 1l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01ni\x7f}", 7, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 127l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01ni\x80}", 7, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -128l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01ni\xff}", 7, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -1l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nU\x01}", 7, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 1l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nU\x7f}", 7, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 127l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nU\x80}", 7, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 128l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nU\xff}", 7, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 255l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nI\x00\x01}", 8, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 1l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nI\x00\x7f}", 8, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 127l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nI\x00\x80}", 8, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 128l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nI\x7f\xff}", 8, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 32767l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nI\xff\x7f}", 8, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -129l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nI\x80\x00}", 8, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -32768l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -128l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nI\xff\xff}", 8, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -1l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nl\x00\x00\x00\x01}", 10, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 1l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nl\x00\x00\x00\x7f}", 10, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 127l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nl\x00\x00\x00\x80}", 10, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 128l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nl\x00\x00\x7f\xff}", 10, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 32767l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nl\xff\xff\x80\x00}", 10, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -32768l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nl\xff\xff\x7f\xff}", 10, (SSFCStrIn_t *)path, &outI16) == false);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nl\x00\x00\x80\x00}", 10, (SSFCStrIn_t *)path, &outI16) == false);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nl\xff\xff\xff\x7f}", 10, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -129l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nl\xff\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -1l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -128l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x01}", 14, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 1l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x7f}", 14, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 127l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x80}", 14, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 128l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x7f\xff}", 14, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 32767l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x80\x00}", 14, (SSFCStrIn_t *)path, &outI16) == false);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x80\x00}", 14, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -32768l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x7f\xff}", 14, (SSFCStrIn_t *)path, &outI16) == false);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x7f}", 14, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -129l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -1l);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x80}", 14, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == -128l);

    /* SSFUBJsonGetUInt16() */
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01ni\x01}", 7, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 1ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01ni\x7f}", 7, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 127ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01ni\x80}", 7, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 128ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01ni\xff}", 7, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 255ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nU\x01}", 7, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 1ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nU\x7f}", 7, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 127ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nU\x80}", 7, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 128ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nU\xff}", 7, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 255ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nI\x00\x01}", 8, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 1ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nI\x00\x7f}", 8, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 127ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nI\x00\x80}", 8, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 128ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nI\x7f\xff}", 8, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 32767ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nI\xff\x7f}", 8, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 65407ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nI\x80\x00}", 8, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 32768ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 65408ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nI\xff\xff}", 8, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 65535ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nl\x00\x00\x00\x01}", 10, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 1ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nl\x00\x00\x00\x7f}", 10, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 127ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nl\x00\x00\x00\x80}", 10, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 128ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nl\x00\x00\x7f\xff}", 10, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 32767ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nl\x00\x00\xff\xff}", 10, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 65535ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nl\xff\xff\x80\x00}", 10, (SSFCStrIn_t *)path, &outU16) == false);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nl\xff\xff\x7f\xff}", 10, (SSFCStrIn_t *)path, &outU16) == false);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nl\x00\x00\x80\x00}", 10, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 32768ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nl\xff\xff\xff\x7f}", 10, (SSFCStrIn_t *)path, &outU16) == false);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nl\xff\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outU16) == false);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 65408ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x01}", 14, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 1ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x7f}", 14, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 127ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x80}", 14, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 128ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x7f\xff}", 14, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 32767ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x80\x00}", 14, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 32768ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\xff\xff}", 14, (SSFCStrIn_t *)path, &outU16));
    SSF_ASSERT(outU16 == 65535ul);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x80\x00}", 14, (SSFCStrIn_t *)path, &outU16) == false);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x7f\xff}", 14, (SSFCStrIn_t *)path, &outU16) == false);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x7f}", 14, (SSFCStrIn_t *)path, &outU16) == false);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outU16) == false);
    SSF_ASSERT(SSFUBJsonGetUInt16((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x80}", 14, (SSFCStrIn_t *)path, &outU16) == false);

    /* SSFUBJsonGetInt32() */
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01ni\x01}", 7, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 1ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01ni\x7f}", 7, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 127ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01ni\x80}", 7, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -128ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01ni\xff}", 7, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -1ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nU\x01}", 7, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 1ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nU\x7f}", 7, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 127ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nU\x80}", 7, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 128ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nU\xff}", 7, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 255ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nI\x00\x01}", 8, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 1ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nI\x00\x7f}", 8, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 127ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nI\x00\x80}", 8, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 128ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nI\x7f\xff}", 8, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 32767ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nI\xff\x7f}", 8, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -129ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nI\x80\x00}", 8, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -32768ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -128ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nI\xff\xff}", 8, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -1ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\x00\x00\x00\x01}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 1ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\x00\x00\x00\x7f}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 127ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\x00\x00\x00\x80}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 128ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\x00\x00\x7f\xff}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 32767ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\xff\xff\x80\x00}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -32768ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\x80\x00\x00\x00}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -2147483648ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\x7f\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 2147483647ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\xff\xff\x7f\xff}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -32769ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\x00\x00\x80\x00}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 32768ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\xff\xff\xff\x7f}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -129ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\xff\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -1ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -128ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x01}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 1ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x7f}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 127ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x80}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 128ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x7f\xff}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 32767ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x80\x00}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 32768ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x80\x00}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -32768ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x7f\xff}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -32769ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\x80\x00\x00\x00}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -2147483648ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\x7f\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outI32) == false);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x7f\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 2147483647ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x80\x00\x00\x00}", 14, (SSFCStrIn_t *)path, &outI32) == false);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x7f}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -129ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -1ll);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x80}", 14, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == -128ll);

    /* SSFUBJsonGetUInt32() */
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01ni\x01}", 7, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 1ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01ni\x7f}", 7, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 127ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01ni\x80}", 7, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 128ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01ni\xff}", 7, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 255ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nU\x01}", 7, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 1ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nU\x7f}", 7, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 127ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nU\x80}", 7, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 128ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nU\xff}", 7, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 255ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nI\x00\x01}", 8, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 1ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nI\x00\x7f}", 8, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 127ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nI\x00\x80}", 8, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 128ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nI\x7f\xff}", 8, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 32767ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nI\xff\x7f}", 8, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 65407ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nI\x80\x00}", 8, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 32768ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 65408ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nI\xff\xff}", 8, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 65535ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\x00\x00\x00\x01}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 1ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\x00\x00\x00\x7f}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 127ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\x00\x00\x00\x80}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 128ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\x00\x00\x7f\xff}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 32767ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\xff\xff\x80\x00}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 4294934528ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\x80\x00\x00\x00}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 2147483648ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\x7f\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 2147483647ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\xff\xff\x7f\xff}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 4294934527ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\x00\x00\x80\x00}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 32768ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\xff\xff\xff\x7f}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 4294967167ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nl\xff\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 4294967295ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x01}", 14, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 1ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x7f}", 14, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 127ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x80}", 14, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 128ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x7f\xff}", 14, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 32767ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x80\x00}", 14, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 32768ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x80\x00}", 14, (SSFCStrIn_t *)path, &outU32) == false);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x7f\xff}", 14, (SSFCStrIn_t *)path, &outU32) == false);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\x80\x00\x00\x00}", 14, (SSFCStrIn_t *)path, &outU32) == false);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\x7f\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outU32) == false);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x7f\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 2147483647ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x80\x00\x00\x00}", 14, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 2147483648ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\x00\x00\x00\x00\xff\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outU32));
    SSF_ASSERT(outU32 == 4294967295ull);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outU32) == false);
    SSF_ASSERT(SSFUBJsonGetUInt32((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x80}", 14, (SSFCStrIn_t *)path, &outU32) == false);

    /* SSFUBJsonGetInt64() */
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01ni\x01}", 7, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 1ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01ni\x7f}", 7, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 127ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01ni\x80}", 7, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -128ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01ni\xff}", 7, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -1ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nU\x01}", 7, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 1ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nU\x7f}", 7, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 127ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nU\x80}", 7, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 128ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nU\xff}", 7, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 255ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nI\x00\x01}", 8, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 1ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nI\x00\x7f}", 8, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 127ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nI\x00\x80}", 8, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 128ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nI\x7f\xff}", 8, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 32767ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nI\xff\x7f}", 8, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -129ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nI\x80\x00}", 8, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -32768ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -128ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nI\xff\xff}", 8, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -1ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\x00\x00\x00\x01}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 1ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\x00\x00\x00\x7f}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 127ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\x00\x00\x00\x80}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 128ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\x00\x00\x7f\xff}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 32767ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\xff\xff\x80\x00}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -32768ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\x80\x00\x00\x00}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -2147483648ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\x7f\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 2147483647ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\xff\xff\x7f\xff}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -32769ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\x00\x00\x80\x00}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 32768ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\xff\xff\xff\x7f}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -129ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nl\xff\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -1ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -128ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x01}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 1ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x7f}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 127ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x80}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 128ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x7f\xff}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 32767ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x80\x00}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 32768ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x80\x00}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -32768ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x7f\xff}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -32769ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\x80\x00\x00\x00}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -2147483648ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\x7f\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x7f\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 2147483647ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x80\x00\x00\x00}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x7f}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -129ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -1ll);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x80}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == -128ll);

    /* SSFUBJsonGetUInt64() */
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01ni\x01}", 7, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 1ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01ni\x7f}", 7, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 127ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01ni\x80}", 7, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 128ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01ni\xff}", 7, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 255ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nU\x01}", 7, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 1ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nU\x7f}", 7, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 127ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nU\x80}", 7, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 128ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nU\xff}", 7, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 255ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nI\x00\x01}", 8, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 1ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nI\x00\x7f}", 8, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 127ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nI\x00\x80}", 8, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 128ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nI\x7f\xff}", 8, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 32767ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nI\xff\x7f}", 8, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 65407ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nI\x80\x00}", 8, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 32768ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nI\xff\x80}", 8, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 65408ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nI\xff\xff}", 8, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 65535ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\x00\x00\x00\x01}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 1ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\x00\x00\x00\x7f}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 127ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\x00\x00\x00\x80}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 128ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\x00\x00\x7f\xff}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 32767ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\xff\xff\x80\x00}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 4294934528ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\x80\x00\x00\x00}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 2147483648ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\x7f\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 2147483647ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\xff\xff\x7f\xff}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 4294934527ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\x00\x00\x80\x00}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 32768ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\xff\xff\xff\x7f}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 4294967167ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nl\xff\xff\xff\xff}", 10, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 4294967295ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x01}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 1ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x7f}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 127ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x00\x80}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 128ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x7f\xff}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 32767ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x00\x00\x80\x00}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 32768ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x80\x00}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\x7f\xff}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\x80\x00\x00\x00}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\x7f\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x7f\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 2147483647ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x80\x00\x00\x00}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 2147483648ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\xff\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(outU64 == 4294967295ull);
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\xff}", 14, (SSFCStrIn_t *)path, &outU64));
    SSF_ASSERT(SSFUBJsonGetUInt64((uint8_t *)"{i\x01nL\xff\xff\xff\xff\xff\xff\xff\x80}", 14, (SSFCStrIn_t *)path, &outU64));

    /* Validate parser can determine if valid */
    for (i = 0; i < (sizeof(_ubjs) / sizeof(SSFUBJSONUT_t)); i++)
    {
        SSF_ASSERT(SSFUBJsonIsValid(_ubjs[i].js, _ubjs[i].jsLen) == _ubjs[i].isValid);
        if (_ubjs[i].isValid)
        {
            SSF_ASSERT(SSFUBJsonIsValid(_ubjs[i].js, _ubjs[i].jsLen + 1) == false);
            if (_ubjs[i].jsLen >= 1)
            {
                for (j = 0; j < _ubjs[i].jsLen; j++)
                {
                    SSF_ASSERT(SSFUBJsonIsValid(_ubjs[i].js, j) == false);
                }
            }
        }
    }

    /* Validate parser on number types */
    memset(path, 0, sizeof(path));
    path[0] = "n";
    for (i = 0; i < UBJTS_NUM_ITEMS(_ubjtsTypeNumber, sizeof(SSFUBJSONNUM_t)); i++)
    {
        SSF_ASSERT(SSFUBJsonGetType(_ubjtsTypeNumber[i].js, _ubjtsTypeNumber[i].jsLen, (SSFCStrIn_t *)path) == _ubjtsTypeNumber[i].type);
    }

    /* Validate parser on string types */
    memset(path, 0, sizeof(path));
    path[0] = "s";
    for (i = 0; i < UBJTS_NUM_ITEMS(_ubjtsTypeString, sizeof(SSFUBJSONSTR_t)); i++)
    {
        SSF_ASSERT(SSFUBJsonGetType(_ubjtsTypeString[i].js, _ubjtsTypeString[i].jsLen, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_STRING);
    }

    /* Validate parser on object types */
    memset(path, 0, sizeof(path));
    path[0] = "o";
    for (i = 0; i < UBJTS_NUM_ITEMS(_ubjtsTypeObject, sizeof(SSFUBJSONOBJ_t)); i++)
    {
        SSF_ASSERT(SSFUBJsonGetType(_ubjtsTypeObject[i].js, _ubjtsTypeObject[i].jsLen, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_OBJECT);
    }
    path[1] = "o2";
    SSF_ASSERT(SSFUBJsonGetType((uint8_t *)"{i\x01o{i\x02o2{}}}", 13, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_OBJECT);

    path[2] = (char *)&aidx1;
    aidx1 = 0;
    SSF_ASSERT(SSFUBJsonGetType((uint8_t *)"{i\x01o{i\x02o2[{}i\x08]}}", 17, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_OBJECT);
    aidx1 = 1;
    SSF_ASSERT(SSFUBJsonGetType((uint8_t *)"{i\x01o{i\x02o2[{}i\x08]}}", 17, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_NUMBER_INT8);

    /* Validate parser on array types */
    memset(path, 0, sizeof(path));
    path[0] = "a";
    for (i = 0; i < UBJTS_NUM_ITEMS(_ubjtsTypeArray, sizeof(SSFUBJSONARR_t)); i++)
    {
        SSF_ASSERT(SSFUBJsonGetType(_ubjtsTypeArray[i].js, _ubjtsTypeArray[i].jsLen, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_ARRAY);
    }
    SSF_ASSERT(SSFUBJsonGetType((uint8_t *)"{i\x01" "a[[]i\x03]}", 11, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_ARRAY);
    path[1] = (char *)&aidx1;
    aidx1 = 0;
    SSF_ASSERT(SSFUBJsonGetType((uint8_t *)"{i\x01" "a[[]i\x03]}", 11, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_ARRAY);
    aidx1 = 1;
    SSF_ASSERT(SSFUBJsonGetType((uint8_t *)"{i\x01" "a[[]i\x03]}", 11, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_NUMBER_INT8);

    /* Validate parser on true, false, null types */
    memset(path, 0, sizeof(path));
    path[0] = "t";
    SSF_ASSERT(SSFUBJsonGetType((uint8_t *)"{i\x01tT}", 6, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_TRUE);
    path[0] = "f";
    SSF_ASSERT(SSFUBJsonGetType((uint8_t *)"{i\x01" "fF}", 6, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_FALSE);
    path[0] = "n";
    SSF_ASSERT(SSFUBJsonGetType((uint8_t *)"{i\x01nZ}", 6, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_NULL);
    SSF_ASSERT(SSFUBJsonGetType((uint8_t *)"{i\x01n}", 5, (SSFCStrIn_t *)path) == SSF_UBJSON_TYPE_ERROR);

    /* Read string types */
    memset(path, 0, sizeof(path));
    path[0] = "s";
    memset(outStr, 0xff, sizeof(outStr));
    outStrLen = sizeof(outStr) + 1;
    SSF_ASSERT(SSFUBJsonGetString((uint8_t *)"{i\x01sSi\x05world}", 13, (SSFCStrIn_t *)path, outStr, sizeof(outStr),
                                  &outStrLen));
    SSF_ASSERT(outStrLen == 5);
    SSF_ASSERT(memcmp(outStr, "world", outStrLen) == 0);
    SSF_ASSERT(outStr[outStrLen] == 0);

    memset(outStr, 0xff, sizeof(outStr));
    outStrLen = sizeof(outStr) + 1;
    SSF_ASSERT(SSFUBJsonGetString((uint8_t *)"{i\x01sSi\x00}", 8, (SSFCStrIn_t *)path, outStr, sizeof(outStr),
                                  &outStrLen));
    SSF_ASSERT(outStrLen == 0);
    SSF_ASSERT(outStr[outStrLen] == 0);

    memset(outStr, 0xff, sizeof(outStr));
    outStrLen = sizeof(outStr) + 1;
    SSF_ASSERT(SSFUBJsonGetString((uint8_t *)"{i\x01sSi\x05w\trld}", 13, (SSFCStrIn_t *)path, outStr, sizeof(outStr),
                                  &outStrLen));
    SSF_ASSERT(outStrLen == 5);
    SSF_ASSERT(memcmp(outStr, "w\trld", outStrLen) == 0);
    SSF_ASSERT(outStr[outStrLen] == 0);

    /* Read float type */
    memset(path, 0, sizeof(path));
    path[0] = "f";
    outFloat = -1;
    SSF_ASSERT(SSFUBJsonGetFloat((uint8_t *)"{i\x01" "fdO\x00\x00\x00}", 10, (SSFCStrIn_t *)path, &outFloat));
    SSF_ASSERT((outFloat >= 2147483647.0) && (outFloat <= 2147483649.0));

    /* Read double type */
    memset(path, 0, sizeof(path));
    path[0] = "d";
    outDouble = -1;
    SSF_ASSERT(SSFUBJsonGetDouble((uint8_t *)"{i\x01" "dDA\xE0\x00\x00\x1F\x9C\x08" "1}", 14, (SSFCStrIn_t *)path, &outDouble));
    SSF_ASSERT((outDouble >= 2147483899.0) && (outDouble <= 2147483901.0));
    SSF_ASSERT(SSFUBJsonGetDouble((uint8_t *)"{i\x01" "ddO\x00\x00\x00}", 10, (SSFCStrIn_t *)path, &outDouble));
    SSF_ASSERT((outDouble >= 2147483647.0) && (outDouble <= 2147483649.0));

    /* Read int types */
    memset(path, 0, sizeof(path));
    path[0] = "n";
    outI8 = -1;
    outU8 = 255;
    outI16 = -1;
    outI32 = -1;
    outI64 = -1;
    SSF_ASSERT(SSFUBJsonGetInt8((uint8_t *)"{i\x01ni\x01}", 7, (SSFCStrIn_t *)path, &outI8));
    SSF_ASSERT(outI8 == 1);
    SSF_ASSERT(SSFUBJsonGetUInt8((uint8_t *)"{i\x01nU\x81}", 7, (SSFCStrIn_t *)path, &outU8));
    SSF_ASSERT(outU8 == 129);
    SSF_ASSERT(SSFUBJsonGetInt16((uint8_t *)"{i\x01nI\x12" "4}", 8, (SSFCStrIn_t *)path, &outI16));
    SSF_ASSERT(outI16 == 0x1234);
    SSF_ASSERT(SSFUBJsonGetInt32((uint8_t *)"{i\x01nl\x7F\xFF\xFF\xFF}", 10, (SSFCStrIn_t *)path, &outI32));
    SSF_ASSERT(outI32 == 0x7fffffffl);
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t *)"{i\x01nL\x00\x00\x00\x00\x80\x00\x00\x00}", 14, (SSFCStrIn_t *)path, &outI64));
    SSF_ASSERT(outI64 == 0x0000000080000000ll);

    memset(path, 0, sizeof(path));
    aidx1 = 0;
    path[0] = (char *)&aidx1;
    SSF_ASSERT(SSFUBJsonGetInt64((uint8_t*)"[U\x12]", 4, (SSFCStrIn_t*)path, &outI64));
    SSF_ASSERT(outI64 == 0x12ll);

    memset(jsOut, 0xff, sizeof(jsOut));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintObject(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, NULL, NULL));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "{}", jsOutEnd) == 0);
    memset(jsOut, 0xff, sizeof(jsOut));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintArray(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, NULL, NULL));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "[]", jsOutEnd) == 0);
    memset(jsOut, 0xff, sizeof(jsOut));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintString(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, "hello"));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd) == false);
    SSF_ASSERT(jsOutEnd == 8);
    SSF_ASSERT(memcmp(jsOut, "SU\x5hello", jsOutEnd) == 0);
    memset(jsOut, 0xff, sizeof(jsOut));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintString(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, ""));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd) == false);
    SSF_ASSERT(jsOutEnd == 3);
    SSF_ASSERT(memcmp(jsOut, "SU\x0", jsOutEnd) == 0);

    memset(jsOut, 0xff, sizeof(jsOut));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintTrue(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd) == false);
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "T", jsOutEnd) == 0);

    memset(jsOut, 0xff, sizeof(jsOut));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintFalse(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd) == false);
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "F", jsOutEnd) == 0);

    memset(jsOut, 0xff, sizeof(jsOut));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintNull(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd) == false);
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "Z", jsOutEnd) == 0);

    memset(jsOut, 0xff, sizeof(jsOut));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintLabel(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, "hello"));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd) == false);
    SSF_ASSERT(jsOutEnd == 7);
    SSF_ASSERT(memcmp(jsOut, "U\x05hello", jsOutEnd) == 0);

    memset(jsOut, 0xff, sizeof(jsOut));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintObject(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, _SSFUBJsonPrintFn1, "world"));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd));
    SSF_ASSERT(jsOutEnd == 17);
    SSF_ASSERT(memcmp(jsOut, "{U\x05helloSU\x05world}", jsOutEnd) == 0);

    memset(jsOut, 0xff, sizeof(jsOut));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)0, false, 0));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "i\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)1, false, 0));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "i\x01", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)127l, false, 0));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "i\x7f", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)128l, false, 0));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "U\x80", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)255l, false, 0));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "U\xff", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)256l, false, 0));
    SSF_ASSERT(jsOutEnd == 3);
    SSF_ASSERT(memcmp(jsOut, "I\x01\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)32767l, false, 0));
    SSF_ASSERT(jsOutEnd == 3);
    SSF_ASSERT(memcmp(jsOut, "I\x7f\xff", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)32768l, false, 0));
    SSF_ASSERT(jsOutEnd == 5);
    SSF_ASSERT(memcmp(jsOut, "l\x00\x00\x80\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)2147483647l, false, 0));
    SSF_ASSERT(jsOutEnd == 5);
    SSF_ASSERT(memcmp(jsOut, "l\x7f\xff\xff\xff", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)2147483648l, false, 0));
    SSF_ASSERT(jsOutEnd == 9);
    SSF_ASSERT(memcmp(jsOut, "L\x00\x00\x00\x00\x80\x00\x00\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)4294967296l, false, 0));
    SSF_ASSERT(jsOutEnd == 9);
    SSF_ASSERT(memcmp(jsOut, "L\x00\x00\x00\x01\x00\x00\x00\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)-1l, false, 0));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "i\xff", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)-128l, false, 0));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "i\x80", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)-129l, false, 0));
    SSF_ASSERT(jsOutEnd == 3);
    SSF_ASSERT(memcmp(jsOut, "I\xff\x7f", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)-32768l, false, 0));
    SSF_ASSERT(jsOutEnd == 3);
    SSF_ASSERT(memcmp(jsOut, "I\x80\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)-32769l, false, 0));
    SSF_ASSERT(jsOutEnd == 5);
    SSF_ASSERT(memcmp(jsOut, "l\xff\xff\x7f\xff", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)-2147483648ll, false, 0));
    SSF_ASSERT(jsOutEnd == 5);
    SSF_ASSERT(memcmp(jsOut, "l\x80\x00\x00\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)-2147483649ll, false, 0));
    SSF_ASSERT(jsOutEnd == 9);
    SSF_ASSERT(memcmp(jsOut, "L\xff\xff\xff\xff\x7f\xff\xff\xff", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)-600l, false, 0));
    SSF_ASSERT(jsOutEnd == 3);
    SSF_ASSERT(memcmp(jsOut, "I\xfd\xa8", jsOutEnd) == 0);

    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)128l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT8) == false);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)0l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT8));
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)1l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT8));
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "\x01", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)127l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT8));
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "\x7f", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)256l, true,
                                 SSF_UBJSON_TYPE_NUMBER_UINT8) == false);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)0l, true,
                                 SSF_UBJSON_TYPE_NUMBER_UINT8));
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)1l, true,
                                 SSF_UBJSON_TYPE_NUMBER_UINT8));
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "\x01", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)127l, true,
                                 SSF_UBJSON_TYPE_NUMBER_UINT8));
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "\x7f", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)128l, true,
                                 SSF_UBJSON_TYPE_NUMBER_UINT8));
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "\x80", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)255l, true,
                                 SSF_UBJSON_TYPE_NUMBER_UINT8));
    SSF_ASSERT(jsOutEnd == 1);
    SSF_ASSERT(memcmp(jsOut, "\xff", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)32768l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT16) == false);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)1l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT16));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "\x00\x01", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)256l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT16));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "\x01\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)32767l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT16));
    SSF_ASSERT(jsOutEnd == 2);
    SSF_ASSERT(memcmp(jsOut, "\x7f\xff", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)2147483648ll, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT32) == false);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)1l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT32));
    SSF_ASSERT(jsOutEnd == 4);
    SSF_ASSERT(memcmp(jsOut, "\x00\x00\x00\x01", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)32768l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT32));
    SSF_ASSERT(jsOutEnd == 4);
    SSF_ASSERT(memcmp(jsOut, "\x00\x00\x80\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)2147483647l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT32));
    SSF_ASSERT(jsOutEnd == 4);
    SSF_ASSERT(memcmp(jsOut, "\x7f\xff\xff\xff", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)1l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT64));
    SSF_ASSERT(jsOutEnd == 8);
    SSF_ASSERT(memcmp(jsOut, "\x00\x00\x00\x00\x00\x00\x00\x01", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)2147483648l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT64));
    SSF_ASSERT(jsOutEnd == 8);
    SSF_ASSERT(memcmp(jsOut, "\x00\x00\x00\x00\x80\x00\x00\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)4294967296l, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT64));
    SSF_ASSERT(jsOutEnd == 8);
    SSF_ASSERT(memcmp(jsOut, "\x00\x00\x00\x01\x00\x00\x00\x00", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)-1, true,
                                 SSF_UBJSON_TYPE_NUMBER_INT64));
    SSF_ASSERT(jsOutEnd == 8);
    SSF_ASSERT(memcmp(jsOut, "\xff\xff\xff\xff\xff\xff\xff\xff", jsOutEnd) == 0);

    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintFloat(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (float)1.23));
    SSF_ASSERT(jsOutEnd == 5);
    SSF_ASSERT(memcmp(jsOut, "d\x3f\x9d\x70\xa4", jsOutEnd) == 0);
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintDouble(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (double) 12341.23));
    SSF_ASSERT(jsOutEnd == 9);
    SSF_ASSERT(memcmp(jsOut, "D\x40\xc8\x1a\x9d\x70\xa3\xd7\x0a", jsOutEnd) == 0);

    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    alen = 9;
    SSF_ASSERT(SSFUBJsonPrintObject(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, _SSFUBJsonPrintFn2, &alen));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd));

    /* ASCII Hex */
    memset(path, 0, sizeof(path));
    path[0] = "h";
    SSF_ASSERT(SSFUBJsonGetHex((uint8_t *)"{U\x01hSU\x0c" "11AA22BB99FE}", 20, (SSFCStrIn_t*) path, jsOut,
        sizeof(jsOut), &outStrLen, false));
    SSF_ASSERT(outStrLen == 6);
    SSF_ASSERT(memcmp(jsOut, "\x11\xAA\x22\xBB\x99\xFE", outStrLen) == 0);

    SSF_ASSERT(SSFUBJsonGetHex((uint8_t*)"{U\x01hSU\x0c" "11AA22BB99FE}", 20, (SSFCStrIn_t*)path, jsOut,
        sizeof(jsOut), &outStrLen, true));
    SSF_ASSERT(outStrLen == 6);
    SSF_ASSERT(memcmp(jsOut, "\xFE\x99\xBB\x22\xAA\x11", outStrLen) == 0);

    SSF_ASSERT(SSFUBJsonGetHex((uint8_t*)"{U\x01hSU\x0c" "11AA22BB99F}", 19, (SSFCStrIn_t*)path, jsOut,
        sizeof(jsOut), &outStrLen, true) == false);

    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    alen = 10;
    SSF_ASSERT(SSFUBJsonPrintObject(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, _SSFUBJsonPrintFn3, &alen));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd));

    /* Base64 */
    memset(path, 0, sizeof(path));
    path[0] = "b";
    SSF_ASSERT(SSFUBJsonGetBase64((uint8_t *)"{U\x01" "bSU\x08" "aGVsbG8=}", 16, (SSFCStrIn_t*) path, jsOut,
        sizeof(jsOut), &outStrLen));
    SSF_ASSERT(outStrLen == 5);
    SSF_ASSERT(memcmp(jsOut, "hello", outStrLen) == 0);

    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    alen = 10;
    SSF_ASSERT(SSFUBJsonPrintObject(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, _SSFUBJsonPrintFn4, &alen));
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd));
}

