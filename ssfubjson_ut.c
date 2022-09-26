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
    { (uint8_t *)"{}", 2, true },  /* {} */
    { (uint8_t *)"{}1", 3, false }, /* {}1 */
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
    { (uint8_t *)"{i\x05hello[i\x03i\x04Si\x05world{i\x03" "abcT}]}", 31, true } /* {"hello":[3,4,"world",{"abc":true}]} */
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
    { (uint8_t *)"{i\x01nC4}", 7, SSF_UBJSON_TYPE_NUMBER_CHAR }, /* {"n":"4"} */
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


bool _SSFUBJsonPrintFn1(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    char *s = (char *)in;

    if (s == NULL) return false;
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "hello")) return false;
    if (!SSFUBJsonPrintString(js, size, start, &start, s)) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* ssfubjson unit test.                                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFUBJsonUnitTest(void)
{
    uint16_t i;
    char *path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];
    size_t aidx1;
    char outStr[16];
    size_t outStrLen;
    float outFloat;
    double outDouble;
    int8_t outI8;
    uint8_t outU8;
    int16_t outI16;
    int32_t outI32;
    int64_t outI64;
    uint8_t jsOut[128];
    size_t jsOutStart;
    size_t jsOutEnd;

    SSF_ASSERT_TEST(SSFUBJsonIsValid(NULL, 0));
    /* Validate parser can determine if valid */
    for (i = 0; i < (sizeof(_ubjs) / sizeof(SSFUBJSONUT_t)); i++)
    {
        SSF_ASSERT(SSFUBJsonIsValid(_ubjs[i].js, _ubjs[i].jsLen) == _ubjs[i].isValid);
        if (_ubjs[i].isValid)
        {
            SSF_ASSERT(SSFUBJsonIsValid(_ubjs[i].js, _ubjs[i].jsLen + 1) == false);
            if (_ubjs[i].jsLen >= 1)
            {
                SSF_ASSERT(SSFUBJsonIsValid(_ubjs[i].js, _ubjs[i].jsLen - 1) == false);
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

    // jlh need more test cases for atr esc sequences.
    memset(outStr, 0xff, sizeof(outStr));
    outStrLen = sizeof(outStr) + 1;
    SSF_ASSERT(SSFUBJsonGetString((uint8_t *)"{i\x01sSi\x06w\\trld}", 14, (SSFCStrIn_t *)path, outStr, sizeof(outStr),
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
    SSF_ASSERT(SSFUBJsonIsValid(jsOut, jsOutEnd) == false);
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
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)0));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)1));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)127l));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)128l));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)255l));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)256l));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)32767l));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)32768l));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)2147483647l));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)2147483648l));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)4294967296l));
    jsOutStart = 0;
    jsOutEnd = (size_t)-1;
    SSF_ASSERT(SSFUBJsonPrintInt(jsOut, sizeof(jsOut), jsOutStart, &jsOutEnd, (int64_t)-1));


}

