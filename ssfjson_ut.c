/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfjson_ut.c                                                                                  */
/* Provides JSON parser/generator interface unit test.                                           */
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
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ssfjson.h"
#include "ssfassert.h"
#include "ssfport.h"

#if SSF_CONFIG_JSON_UNIT_TEST == 1
    #define JTS_NUM_ITEMS(x, s) (sizeof((x)) / (s))
const char *_jtsIsValid[] =
{
    "{}",
    " {}",
    "{} ",
    "{ }",
    " { } ",
    "\n\r\t {\t\n\r }\r \t\n",
    "{\"\":1}",
    "\t{\r\"\"\n: 1\t}\r",
    "\n\r\t {\n\r\t \"\"\n\r\t : 1\n\r\t }\n\r\t ",
    "{\"a\":1.0}",
    "{\"abcdefghijklmnopqrstuvwxyz\":-1.0}",
    "{\"ABCDEFGHIJKLMNOPQRSTUVWXYZ\":-1.0E3}",
    "{\"1234567890\":-1.0E+3}",
    "{\"!@#$%^&*()\":-1.0E-3}",
    "{\"{} []\":-1.05e03}",
    "{\";:<>\":1.05e+036}",
    "{\"data1\":1.05e+00036}",
    "{\",.?`~-_=+|\":1234567890}",
    "{\"\\\\\\/\\n\\r\\t\\b\\f\\\"\":-1234567890}",
    "{\"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\":12345.67890}",
    "{\"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\":-12345.67890}",
    "\n\r\t {\n\r\t \"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\"\n\r\t :\n\r\t -12345.67890\n\r\t }\n\r\t ",
    "{\"A\\u1234\\u5678\\u90ab\\ucdefM\\uABCD\\uEF12\\ua2F0Z\":-12345.67890}",
    "{\"name\":\"\"}",
    "{\"name\":\"value\"}",
    "{\"name\":\"A\\u1234\\u5678\\u90ab\\ucdefM\\uABCD\\uEF12\\ua2F0Z\"}",
    "{\"name\":\"\x013\x02\x03\xfd\xfe\xff\\u12Ab\\\\l\\\"\\n\\r\\t\\b\\fz\\/\"}",
    " { \"name\" : \"\x013\x02\x03\xfd\xfe\xff\\u12Ab\\\\l\\\"\\n\\r\\t\\b\\fz\\/\" } ",
    "{\"name\":true}",
    "{\"name\":\n\r\t true}",
    "{\"name\":true\n\r\t }",
    "{\"name\":\n\r\t true\n\r\t }",
    "{\"name\":false}",
    "{\"name\":\n\r\t false}",
    "{\"name\":false\n\r\t }",
    "{\"name\":\n\r\t false\n\r\t }",
    "{\"name\":null}",
    "{\"name\":\n\r\t null}",
    "{\"name\":null\n\r\t }",
    "{\"name\":\n\r\t null\n\r\t }",
    "{\"name\":[]}",
    "\n\r\t {\n\r\t \"name\"\n\r\t :\n\r\t [\n\r\t ]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :\n\r\t [1\n\r\t ]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :\n\r\t [1]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :\n\r\t [\n\r\t 1]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :\n\r\t [\n\r\t -12345678.09e+02\n\r\t ]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :\n\r\t [\n\r\t -12345678.09e+02,2]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :\n\r\t [\n\r\t -12345678.09e+02,2,\"\"\r]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :\n\r\t [\n\r\t -12345678.09e+02,2,\"\",{},[]\r]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :[-12345678.09e+02,2]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :[-12345678.09e+02,2,\"\"]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :[-12345678.09e+02,2,\"\",{}]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :[-12345678.09e+02,2,\"\",{},[]]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :[{},-12345678.09e+02,2]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :[[],{},-12345678.09e+02,2]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :[\"\",[],{},-12345678.09e+02,2]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :[\n\r\t {},-12345678.09e+02,2]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :[\n\r\t [],{},-12345678.09e+02,2]\n\r\t }",
    "\n\r\t {\n\r\t \"name\"\n\r\t :[\n\r\t \"\",[],{},-12345678.09e+02,2]\n\r\t }",
    "{\"name\":[\"value\",[\"\"],{\"name2\":1},-12345678.09e+02,2]\n\r\t }",
    "{\"name\":[\"value\",\n\r\t [\n\r\t \"astr\"\n\r\t ]\n\r\t ,\n\r\t {\"name2\":1,\"name3\":\"\"\n\r\t }\n\r\t ,\n\r\t -12345678.09e+02,2]\n\r\t }",
};

const char *_jtsIsInvalid[] =
{
    "{\"name\":{\"name2\":1,}}",
    "{\"name\":{\"name2\"}}",
    "",
    "{",
    "}",
    "1{}",
    "{2}",
    "{}3",
    "a\n\r\t {\t\n\r }\r \t\n",
    "\n\rb\t {\t\n\r }\r \t\n",
    "\n\r\t c{\t\n\r }\r \t\n",
    "\n\r\t {d\t\n\r }\r \t\n",
    "\n\r\t {\t\ne\r }\r \t\n",
    "\n\r\t {\t\n\r f}\r \t\n",
    "\n\r\t {\t\n\r }g\r \t\n",
    "\n\r\t {\t\n\r }\r \th\n",
    "\n\r\t {\t\n\r }\r \t\ni",
    "{\"name\"}"
    "{\"name\":}"
    "{\"a\":01.05e-0360}",
    "{\"a\":1.05Ee-0360}",
    "{\"a\":1.0.5E-0360}",
    "{\"a\":105E-03.60}",
    "{\"a\":+1.05e-0360}",
    "{\"a\":1.05f-0360}",
    "{\"a\":1.05e- 0360}",
    "{\"a\":1. 05e-0360}",
    "{\"a\":1.05 e-0360}",
    "{\"a\":1.05e -0360}",
    "{\"\\\":1}",
    "{\"name\":\"\\\"}",
    "{\"name\":\"\\q\"}",
    "{\"name\":\"\\u\"}",
    "{\"name\":\"\\u0\"}",
    "{\"name\":\"\\u01\"}",
    "{\"name\":\"\\u012\"}",
    "{\"name\":\"\\u012z\"}",
    "{\"name\":\"\\ug123\"}",
    "{\"name\":\"\\u0g23\"}",
    "{\"name\":\"\\u01G3\"}",
    "{\"name\":True}",
    "{\"name\":TRUE}",
    "{\"name\":False}",
    "{\"name\":FALSE}",
    "{\"name\":Null}",
    "{\"name\":NULL}",
    "{[]}",
    "{[}",
    "{]}",
    "\n\r\t {\n\r\t [\n\r\t ]\n\r\t }\n\r\t ",
    "{[1 2]}",
    "{[\"1\" \"2\"]}",
    "{[{} {}]}",
    "{[[] []]}",
    "{[1 []]}",
    "{[1,]}",
    "{[1,[],]}",
    "{[,1,[]]}",
    "{[1,[1,3,]]}",
    "{\"name\":{\"name2\"}}",
    "{\"name\":{\"name2\":}}",
    "{\"name\":{\"name2\":1,}}",
    "{\"name\":{,\"name2\":1}}",
    "{\"name\":{\"name2\":1,\"name3\"}}",
    "{\"name\":{\"name2\":1,\"name3\":}}",
    "{\"name\":{\"name2\":1,\"name3\":[],}}",
};

const char *_jtsTypeNumber[] =
{
    "{\"n\":1}",
    "{\"n\":1.0}",
    "{\"n\":-1.0}",
    "{\"n\":1.0e+1}",
    "{\"n\":1.0E-1}",
    "{\"n\":1.0e0020}",
    "{\"n\":1234567890}",
    "{\"n\":-987654321}",
};

const char *_jtsTypeString[] =
{
    "{\"s\":\"\"}",
    "{\"s\":\" \"}",
    "{\"s\":\"value\"}",
    "{\"s\":\"\\\\r\\n\\/\"}",
    "{\"s\":\"\\u01Ae\"}",
    "{\"s\":\"\x01\xff\"}",
    "{\"s\":\"1234567890abcxyzABCXYZ-_+={}[]:;\'\\\"<>,.\\/\"}",
    "{\"s\":\"`~|!@#$%^&*()-987654321\"}",
};

const char *_jtsTypeTrue[] =
{
    "{\"t\":true}",
    "{\"t\": true}",
    "{\"t\":true }",
    "{\"t\": true }",
    "{\"t\":\n\r\ttrue\n\r\t}",
};

const char *_jtsTypeFalse[] =
{
    "{\"f\":false}",
    "{\"f\": false}",
    "{\"f\":false }",
    "{\"f\": false }",
    "{\"f\":\n\r\tfalse\n\r\t}",
};

const char *_jtsTypeNull[] =
{
    "{\"N\":null}",
    "{\"N\": null}",
    "{\"N\":null }",
    "{\"N\": null }",
    "{\"N\":\n\r\tnull\n\r\t}",
};

const char *_jtsTypeEmptyObject[] =
{
    "{}",
    " {}",
    "{} ",
    "{ }",
    " { } ",
    "\n\r\t{\n\r\t}\n\r\t",
    "\n \r\t{\n\r \t}\n\r\t ",
};

const char *_jtsTypeObject[] =
{
    "{\"a\":{}}",
    "{\"a\": {}}",
    "{\"a\":{} }",
    "{\"a\": {} }",
    "{\"a\":{ }}",
    "{\"a\":\n\r\t{\n\r\t}\n\r\t}",
    "{\"a\":{\"\":1}}",
    "{\"a\":{\"\":\"\"}}",
    "{\"a\":{\"\":true}}",
    "{\"a\":{\"\":false}}",
    "{\"a\":{\"\":null}}",
    "{\"a\":{\"\":[]}}",
    "{\"a\":{\"\":{}}}",
    "{\"a\":{\"b\":1}}",
    "{\"a\":{\"b\":\"\"}}",
    "{\"a\":{\"b\":true}}",
    "{\"a\":{\"b\":false}}",
    "{\"a\":{\"b\":null}}",
    "{\"a\":{\"b\":[]}}",
    "{\"a\":{\"b\":{}}}",
    "{\"a\":{\"b\":1.0,\"c\":\"str\",\"d\":true,\"e\":false,\"f\":null,\"\":[],\"g\":{}}}",
    "{\"a\":{\"b\":1.0, \"c\":\"str\", \"d\":true, \"e\":false, \"f\":null, \"\":[], \"g\":{}}}",
    "{\"a\":{\n\r\t\"b\"\n\r\t:\n\r\t1.0,\n\r\t\"c\"\n\r\t:\n\r\t\"str\"\n\r\t,\n\r\t\"d\"\n\r\t:"
    "\n\r\ttrue\n\r\t,\n\r\t\"e\"\n\r\t:\n\r\tfalse\n\r\t, \"f\"\n\r\t:\n\r\tnull\n\r\t,\n\r\t"
    " \"\"\n\r\t:\n\r\t[\n \r\t], \n\r\t\"g\"\n\r\t:\n\r\t{\n\r\t}\n\r\t}\n\r\t}\n\r\t",
    "{\"a\":{\"b\":1.0,\"c\":\"str\",\"d\":true,\"e\":false,\"f\":null,\"\":[1\n\r\t ],\"g\":{}}}",
    "{\"a\":{\"b\":1.0,\"c\":\"str\",\"d\":true,\"e\":false,\"f\":null,\"\":[1],\"g\":{}}}",
    "{\"a\":{\"b\":1.0,\"c\":\"str\",\"d\":true,\"e\":false,\"f\":null,\"\":[1,\"\",true\n\r\t],"
    "\"g\":{}}}",
};

const char *_jtsTypeArray[] =
{
    "{\"a\":[]}",
    "{\"a\": []}",
    "{\"a\":[] }",
    "{\"a\":[ ]}",
    "{\"a\": [ ] }",
    "{\"a\":\n\r\t[\n\r\t]\n\r\t}",
    "{\"a\":\n\r\t [\n\r\t ] \n\r\t}",
    "{\"a\":[1]}",
    "{\"a\":[1,2]}",
    "{\"a\":[1,2,true,false,null,\"\",[],{}]}",
    "{\"a\":[-1.0,2e+4,true,false,null,\"abc\\u1234\\n\",[1],{\"b\":[]}]}",
    "{\"a\": \n\r\t[ \n\r\t-1.0,2e+4 \n\r\t, \n\r\ttrue \n\r\t, \n\r\tfalse \n\r\t, \n\r\tnull "
    "\n\r\t, \n\r\t\"abc\\u1234\\n\" \n\r\t, \n\r\t[ \n\r\t1 \n\r\t] \n\r\t, \n\r\t{ \n\r\t"
    "\"b\" \n\r\t: \n\r\t[ \n\r\t] \n\r\t} \n\r\t] \n\r\t} \n\r\t",
};

const char *_jtsComplex[] =
{
    "{\"b1\":true,\"b2\":false,\"nil1\":null,\"n1\":-1.2e+03,\"s1-\":\"level0\",\"a1\":[],\"a2\":"
    "[true,false,null,1234567890,-98765432,\"\",\"YQ==\",[],{},[1,2,3],{\"hex1\":\"12\","
    "\"hex2\":\"1234567890ABCDEFabcdef\"}],\"obj1\":{},\"obj2\":{\"b64_1\":\"YWI=\","
    "\"b64_2\":\"YWJj\",\"b64_3\":\"MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0"
    "hJSktMTU5PUFFSU1RVVldYWVohQCMkJV4mKigpYH4tXys9e31bXTo7JyI8PiwuLz98XA==\",\"b3\":true,"
    "\"b4\":false,\"nil2\":null,\"array\":[\"A\",\"Z\"],\"objdeep\":{\"hex3\":\"1029384756a1b2"
    "c3d4e5f6\",\"NUMFAR\":-42}}}",
    "\n\r\t {\n\r\t \"b1\"\n\r\t :true,\"b2\":false\n\r\t ,\"nil1\":null,\"n1\":-1.2e+03,\"s1-\":\"level0\",\"a1\":\n\r\t [\n\r\t ]\n\r\t ,\n\r\t \"a2\":"
    "[true,false,\n\r\t null\n\r\t ,1234567890,-98765432,\"\",\"YQ==\",[],{},[1,2,3],{\"hex1\":\"12\","
    "\"hex2\":\"1234567890ABCDEFabcdef\"\n\r\t }\n\r\t ]\n\r\t ,\"obj1\":{},\"obj2\":{\"b64_1\":\"YWI=\","
    "\"b64_2\":\"YWJj\",\"b64_3\":\"MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0"
    "hJSktMTU5PUFFSU1RVVldYWVohQCMkJV4mKigpYH4tXys9e31bXTo7JyI8PiwuLz98XA==\"\n\r\t ,\n\r\t \"b3\":true,\n\r\t "
    "\"b4\":false,\"nil2\":\n\r\t null,\"array\":[\"A\",\"Z\"],\"objdeep\":{\"hex3\":\n\r\t \"1029384756a1b2"
    "c3d4e5f6\",\"NUMFAR\":\n\r\t -42\n\r\t }\n\r\t }\n\r\t }\n\r\t ",
};

char _jsOut[1024];

/* --------------------------------------------------------------------------------------------- */
/* Printer function.                                                                             */
/* --------------------------------------------------------------------------------------------- */
bool p1fn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    SSF_UNUSED(js);
    SSF_UNUSED(size);
    SSF_UNUSED(start);
    SSF_UNUSED(end);
    SSF_UNUSED(in);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Printer function.                                                                             */
/* --------------------------------------------------------------------------------------------- */
bool p2fn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;

    SSF_UNUSED(in);
    if (!SSFJsonPrintLabel(js, size, start, &start, "label", &comma)) return false;
    if (!SSFJsonPrintString(js, size, start, &start, "value", false)) return false;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Printer function.                                                                             */
/* --------------------------------------------------------------------------------------------- */
bool p2fna(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;

    if (!SSFJsonPrintString(js, size, start, &start, "av1", &comma)) return false;
    if (!SSFJsonPrintString(js, size, start, &start, "av2", &comma)) return false;
    if (!SSFJsonPrintTrue(js, size, start, &start, &comma)) return false;
    if (!SSFJsonPrintObject(js, size, start, &start, p2fn, in, &comma)) return false;
    if (!SSFJsonPrintFalse(js, size, start, &start, &comma)) return false;
    if (!SSFJsonPrintNull(js, size, start, &start, &comma)) return false;
#if SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_STD,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_SHORT,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_PREC_0,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_PREC_1,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_PREC_2,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_PREC_3,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_PREC_4,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_PREC_5,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_PREC_6,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_PREC_7,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_PREC_8,
                            &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, -92.8123456789123e3, SSF_JSON_FLT_FMT_PREC_9,
                            &comma)) return false;
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Printer function.                                                                             */
/* --------------------------------------------------------------------------------------------- */
bool p3fn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;
    uint32_t *i = (uint32_t *)in;

    SSF_REQUIRE(i != NULL);

    if (!SSFJsonPrintLabel(js, size, start, &start, "object1", &comma)) return false;
    if (!SSFJsonPrintObject(js, size, start, &start, p2fn, in, false)) return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "hexrev", &comma)) return false;
    if (!SSFJsonPrintHex(js, size, start, &start, (uint8_t *)i, sizeof(uint32_t), true, false)) return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "hex", &comma)) return false;
    if (!SSFJsonPrintHex(js, size, start, &start, (uint8_t *)i, sizeof(uint32_t), false, false)) return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "b64", &comma)) return false;
    if (!SSFJsonPrintBase64(js, size, start, &start, (uint8_t *)i, sizeof(uint32_t), false)) return false;
#if SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1
    if (!SSFJsonPrintLabel(js, size, start, &start, "double", &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, *i, SSF_JSON_FLT_FMT_STD, false)) return false;
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_GEN */
    if (!SSFJsonPrintLabel(js, size, start, &start, "int", &comma)) return false;
    if (!SSFJsonPrintInt(js, size, start, &start, *i, false)) return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "uint", &comma)) return false;
    if (!SSFJsonPrintUInt(js, size, start, &start, *i, false)) return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "array", &comma)) return false;
    if (!SSFJsonPrintArray(js, size, start, &start, p1fn, in, false)) return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "object2", &comma)) return false;
    if (!SSFJsonPrintObject(js, size, start, &start, p1fn, in, false)) return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "object2", &comma)) return false;
    if (!SSFJsonPrintArray(js, size, start, &start, p2fna, in, false)) return false;
    *i = 0xabcdef90;
    *end = start;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Printer function.                                                                             */
/* --------------------------------------------------------------------------------------------- */
bool p4fn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    SSF_UNUSED(in);
    if (!SSFJsonPrintString(js, size, start, &start, "mynewvalue", false)) return false;
    *end = start;
    return true;
}

    #if SSF_JSON_CONFIG_ENABLE_UPDATE == 1
/* --------------------------------------------------------------------------------------------- */
/* Printer function.                                                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFJsonUnitTestUpdate(char *out, size_t outSize, char *path0, char *path1, char *path2,
                           const char *initial, const char *expected)
{
    char *path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];

    memset(out, 0xff, outSize);
    memcpy(out, initial, SSF_MIN(outSize, strlen(initial) + 1));
    memset(path, 0, sizeof(path));
    path[0] = path0;
    path[1] = path1;
    path[2] = path2;
    SSF_ASSERT(SSFJsonUpdate(out, outSize, (SSFCStrIn_t *)path, p4fn) == true);
    SSF_ASSERT(SSFJsonIsValid(out) == true);
    if (expected != NULL) SSF_ASSERT(strncmp(out, expected, outSize) == 0);
}
    #endif /* SSF_JSON_CONFIG_ENABLE_UPDATE */

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfjson's external interface.                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFJsonUnitTest(void)
{
    uint32_t i;
    size_t start;
    size_t end;
    char *path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];

    /* Parsing tests */

    /* Validate parser on valid JSON strings */
    for (i = 0; i < JTS_NUM_ITEMS(_jtsIsValid, sizeof(char *)); i++)
    {
        SSF_ASSERT(SSFJsonIsValid(_jtsIsValid[i]));
    }

    /* Validate parser on invalid JSON strings */
    for (i = 0; i < JTS_NUM_ITEMS(_jtsIsInvalid, sizeof(char *)); i++)
    {
        SSF_ASSERT(!SSFJsonIsValid(_jtsIsInvalid[i]));
    }

    /* Validate parser on number types */
    memset(path, 0, sizeof(path));
    path[0] = "n";
    for (i = 0; i < JTS_NUM_ITEMS(_jtsTypeNumber, sizeof(char *)); i++)
    {
        SSF_ASSERT(SSFJsonGetType(_jtsTypeNumber[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_NUMBER);
    }

    /* Validate parser on string types */
    memset(path, 0, sizeof(path));
    path[0] = "s";
    for (i = 0; i < JTS_NUM_ITEMS(_jtsTypeString, sizeof(char *)); i++)
    {
        SSF_ASSERT(SSFJsonGetType(_jtsTypeString[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
    }

    /* Validate parser on true types */
    memset(path, 0, sizeof(path));
    path[0] = "t";
    for (i = 0; i < JTS_NUM_ITEMS(_jtsTypeTrue, sizeof(char *)); i++)
    {
        SSF_ASSERT(SSFJsonGetType(_jtsTypeTrue[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_TRUE);
    }

    /* Validate parser on false types */
    memset(path, 0, sizeof(path));
    path[0] = "f";
    for (i = 0; i < JTS_NUM_ITEMS(_jtsTypeFalse, sizeof(char *)); i++)
    {
        SSF_ASSERT(SSFJsonGetType(_jtsTypeFalse[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_FALSE);
    }

    /* Validate parser on null types */
    memset(path, 0, sizeof(path));
    path[0] = "N";
    for (i = 0; i < JTS_NUM_ITEMS(_jtsTypeNull, sizeof(char *)); i++)
    {
        SSF_ASSERT(SSFJsonGetType(_jtsTypeNull[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_NULL);
    }

    /* Validate parser on empty objects types */
    memset(path, 0, sizeof(path));
    for (i = 0; i < JTS_NUM_ITEMS(_jtsTypeEmptyObject, sizeof(char *)); i++)
    {
        SSF_ASSERT(SSFJsonGetType(_jtsTypeEmptyObject[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_OBJECT);
    }

    /* Validate parser on object types */
    memset(path, 0, sizeof(path));
    path[0] = "a";
    for (i = 0; i < JTS_NUM_ITEMS(_jtsTypeObject, sizeof(char *)); i++)
    {
        SSF_ASSERT(SSFJsonGetType(_jtsTypeObject[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_OBJECT);
    }

    /* Validate parser on array types */
    memset(path, 0, sizeof(path));
    path[0] = "a";
    for (i = 0; i < JTS_NUM_ITEMS(_jtsTypeArray, sizeof(char *)); i++)
    {
        SSF_ASSERT(SSFJsonGetType(_jtsTypeArray[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_ARRAY);
    }

    /* Validate parser on complex nested JSON */
    memset(path, 0, sizeof(path));
    for (i = 0; i < JTS_NUM_ITEMS(_jtsComplex, sizeof(char *)); i++)
    {
        char strOut[256];
        size_t strOutLen;
        uint8_t binOut[256];
        size_t binOutLen;
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        double d;
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        long int si;
        unsigned long int ui;
        size_t index;
        SSFJsonType_t jtype;
        size_t aidx1;
        size_t aidx2;

        SSF_ASSERT(SSFJsonIsValid(_jtsComplex[i]));

        memset(path, 0, sizeof(path));
        path[0] = "b1";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_TRUE);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_TRUE);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "true", (end - start + 1)) == 0);

        path[0] = "b2";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_FALSE);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_FALSE);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "false", (end - start + 1)) == 0);

        path[0] = "nil1";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_NULL);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_NULL);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "null", (end - start + 1)) == 0);

        path[0] = "n1";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_NUMBER);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == true);
        SSF_ASSERT(d == -1.2e3);
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == true);
        SSF_ASSERT(si == -1200);
#else
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_NUMBER);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "-1.2e+03", (end - start + 1)) == 0);

        path[0] = "s1-";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == true);
        SSF_ASSERT(memcmp(strOut, "level0", 6) == 0);
        SSF_ASSERT(strOutLen == 6);
        SSF_ASSERT(strOutLen == strlen(strOut));
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "\"level0\"", (end - start + 1)) == 0);

        path[0] = "a1";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_ARRAY);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_ARRAY);
        if (i == 0) SSF_ASSERT(memcmp(&_jtsComplex[i][start], "[]", (end - start + 1)) == 0);

        path[0] = "a2";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_ARRAY);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_ARRAY);
        if (i == 0) SSF_ASSERT(memcmp(&_jtsComplex[i][start],
                                      "[true,false,null,1234567890,-98765432,\"\",\"YQ==\",[],{},[1,2,3],{\"hex1\":\"12\",\"hex2\":\"1234567890ABCDEFabcdef\"}]",
                                      (end - start + 1)) == 0);

        memset(path, 0, sizeof(path));
        path[0] = "a2";
        path[1] = (char *)&aidx1;
        aidx1 = 0;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_TRUE);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_TRUE);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "true", (end - start + 1)) == 0);

        aidx1 = 1;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_FALSE);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_FALSE);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "false", (end - start + 1)) == 0);

        aidx1 = 2;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_NULL);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_NULL);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "null", (end - start + 1)) == 0);

        aidx1 = 3;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_NUMBER);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == true);
        SSF_ASSERT(d == 1234567890);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == true);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == true);
        SSF_ASSERT(si == 1234567890);
        SSF_ASSERT(ui == 1234567890);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_NUMBER);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "1234567890", (end - start + 1)) == 0);

        aidx1 = 4;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_NUMBER);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == true);
        SSF_ASSERT(d == -98765432);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == true);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(si == -98765432);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_NUMBER);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "-98765432", (end - start + 1)) == 0);

        aidx1 = 5;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == true);
        SSF_ASSERT(strOutLen == 0);
        SSF_ASSERT(strOut[0] == 0);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        binOutLen = (size_t)-1;
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == true);
        SSF_ASSERT(binOutLen == 0);
        binOutLen = (size_t)-1;
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == true);
        SSF_ASSERT(binOutLen == 0);
        binOutLen = (size_t)-1;
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == true);
        SSF_ASSERT(binOutLen == 0);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "\"\"", (end - start + 1)) == 0);

        aidx1 = 6;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == true);
        SSF_ASSERT(strOutLen == 4);
        SSF_ASSERT(strOutLen == strlen(strOut));
        SSF_ASSERT(memcmp(strOut, "YQ==", 4) == 0);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == true);
        SSF_ASSERT(binOutLen == 1);
        SSF_ASSERT(binOut[0] == 'a');
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "\"YQ==\"", (end - start + 1)) == 0);

        aidx1 = 7;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_ARRAY);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_ARRAY);
        if (i == 0) SSF_ASSERT(memcmp(&_jtsComplex[i][start], "[]", (end - start + 1)) == 0);

        aidx1 = 8;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_OBJECT);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_OBJECT);
        if (i == 0) SSF_ASSERT(memcmp(&_jtsComplex[i][start], "{}", (end - start + 1)) == 0);

        aidx1 = 9;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_ARRAY);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_ARRAY);
        if (i == 0) SSF_ASSERT(memcmp(&_jtsComplex[i][start], "[1,2,3]", (end - start + 1)) == 0);

        path[2] = (char *)&aidx2;
        aidx2 = 0;
        while (true)
        {
            char *anum1[] = { "1", "2", "3" };

            if (SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_ERROR) break;
            SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_NUMBER);
            SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
            SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == true);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
            SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == true);
            SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == true);
            SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
            SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
            SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
            jtype = SSF_JSON_TYPE_MAX;
            SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
            SSF_ASSERT(jtype == SSF_JSON_TYPE_NUMBER);
            SSF_ASSERT(memcmp(&_jtsComplex[i][start], anum1[aidx2], (end - start + 1)) == 0);
            aidx2++;
        }
        SSF_ASSERT(aidx2 == 3);

        aidx1 = 10;
        path[2] = "hex1";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == true);
        SSF_ASSERT(strOutLen == 2);
        SSF_ASSERT(strOutLen == strlen(strOut));
        SSF_ASSERT(memcmp(strOut, "12", 2) == 0);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        binOutLen = 0;
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == true);
        SSF_ASSERT(binOutLen == 1);
        SSF_ASSERT(memcmp(binOut, "\x12", 1) == 0);
        binOutLen = 0;
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == true);
        SSF_ASSERT(binOutLen == 1);
        SSF_ASSERT(memcmp(binOut, "\x12", 1) == 0);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "\"12\"", (end - start + 1)) == 0);

        aidx1 = 10;
        path[2] = "hex2";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == true);
        SSF_ASSERT(strOutLen == 22);
        SSF_ASSERT(strOutLen == strlen(strOut));
        SSF_ASSERT(memcmp(strOut, "1234567890ABCDEFabcdef", 22) == 0);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        binOutLen = 0;
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == true);
        SSF_ASSERT(binOutLen == 11);
        SSF_ASSERT(memcmp(binOut, "\xef\xcd\xab\xef\xcd\xab\x90\x78\x56\x34\x12", 11) == 0);
        binOutLen = 0;
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == true);
        SSF_ASSERT(binOutLen == 11);
        SSF_ASSERT(memcmp(binOut, "\x12\x34\x56\x78\x90\xAB\xCD\xEF\xab\xcd\xef", 11) == 0);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "\"1234567890ABCDEFabcdef\"", (end - start + 1)) == 0);

        memset(path, 0, sizeof(path));
        path[0] = "obj1";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_OBJECT);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_OBJECT);
        if (i == 0) SSF_ASSERT(memcmp(&_jtsComplex[i][start], "{}", (end - start + 1)) == 0);

        path[0] = "obj2";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_OBJECT);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_OBJECT);
        if (i == 0) SSF_ASSERT(memcmp(&_jtsComplex[i][start],
                                      "{\"b64_1\":\"YWI=\","
                                      "\"b64_2\":\"YWJj\",\"b64_3\":\"MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0"
                                      "hJSktMTU5PUFFSU1RVVldYWVohQCMkJV4mKigpYH4tXys9e31bXTo7JyI8PiwuLz98XA==\",\"b3\":true,"
                                      "\"b4\":false,\"nil2\":null,\"array\":[\"A\",\"Z\"],\"objdeep\":{\"hex3\":\"1029384756a1b2"
                                      "c3d4e5f6\",\"NUMFAR\":-42}}", (end - start + 1)) == 0);

        path[1] = "b64_1";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == true);
        SSF_ASSERT(strOutLen == 4);
        SSF_ASSERT(strOutLen == strlen(strOut));
        SSF_ASSERT(memcmp(strOut, "YWI=", 4) == 0);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == true);
        SSF_ASSERT(binOutLen == 2);
        SSF_ASSERT(memcmp(binOut, "ab", binOutLen) == 0);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "\"YWI=\"", (end - start + 1)) == 0);

        path[1] = "b64_2";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == true);
        SSF_ASSERT(strOutLen == 4);
        SSF_ASSERT(strOutLen == strlen(strOut));
        SSF_ASSERT(memcmp(strOut, "YWJj", 4) == 0);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == true);
        SSF_ASSERT(binOutLen == 3);
        SSF_ASSERT(memcmp(binOut, "abc", binOutLen) == 0);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "\"YWJj\"", (end - start + 1)) == 0);

        path[1] = "b64_3";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == true);
        SSF_ASSERT(strOutLen == 128);
        SSF_ASSERT(strOutLen == strlen(strOut));
        SSF_ASSERT(memcmp(strOut, "MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVohQCMkJV4mKigpYH4tXys9e31bXTo7JyI8PiwuLz98XA==", strOutLen) == 0);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == true);
        SSF_ASSERT(binOutLen == 94);
        SSF_ASSERT(memcmp(binOut, "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()`~-_+={}[]:;'\"<>,./?|\\", binOutLen) == 0);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "\"MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVohQCMkJV4mKigpYH4tXys9e31bXTo7JyI8PiwuLz98XA==\"", (end - start + 1)) == 0);

        path[1] = "b3";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_TRUE);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_TRUE);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "true", (end - start + 1)) == 0);

        path[1] = "b4";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_FALSE);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_FALSE);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "false", (end - start + 1)) == 0);

        path[1] = "nil2";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_NULL);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_NULL);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "null", (end - start + 1)) == 0);

        path[1] = "array";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_ARRAY);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_ARRAY);
        if (i == 0) SSF_ASSERT(memcmp(&_jtsComplex[i][start], "[\"A\",\"Z\"]", (end - start + 1)) == 0);

        path[2] = (char *)&aidx1;
        aidx1 = 0;
        while (true)
        {
            char *strs[] = { "A", "Z" };
            char *strsq[] = { "\"A\"", "\"Z\"" };

            if (SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_ERROR) break;
            SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
            SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == true);
            SSF_ASSERT(strOutLen == 1);
            SSF_ASSERT(strOutLen == strlen(strOut));
            SSF_ASSERT(memcmp(strOut, &strs[aidx1], strOutLen));
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
            SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
            SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
            SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
            SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
            SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
            SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
            jtype = SSF_JSON_TYPE_MAX;
            SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
            SSF_ASSERT(jtype == SSF_JSON_TYPE_STRING);
            SSF_ASSERT(memcmp(&_jtsComplex[i][start], strsq[aidx1], (end - start + 1)) == 0);
            aidx1++;
        }
        SSF_ASSERT(aidx1 == 2);

        path[1] = "objdeep";
        path[2] = NULL;
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_OBJECT);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_OBJECT);
        if (i == 0) SSF_ASSERT(memcmp(&_jtsComplex[i][start], "{\"hex3\":\"1029384756a1b2c3d4e5f6\",\"NUMFAR\":-42}", (end - start + 1)) == 0);

        path[2] = "hex3";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == true);
        SSF_ASSERT(strOutLen == 22);
        SSF_ASSERT(strOutLen == strlen(strOut));
        SSF_ASSERT(memcmp(strOut, "1029384756a1b2c3d4e5f6", 22) == 0);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == false);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == false);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        binOutLen = 0;
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == true);
        SSF_ASSERT(binOutLen == 11);
        SSF_ASSERT(memcmp(binOut, "\xf6\xe5\xd4\xc3\xb2\xa1\x56\x47\x38\x29\x10", 11) == 0);
        binOutLen = 0;
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == true);
        SSF_ASSERT(binOutLen == 11);
        SSF_ASSERT(memcmp(binOut, "\x10\x29\x38\x47\x56\xa1\xb2\xc3\xd4\xe5\xf6", 11) == 0);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_STRING);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "\"1029384756a1b2c3d4e5f6\"", (end - start + 1)) == 0);

        path[2] = "NUMFAR";
        SSF_ASSERT(SSFJsonGetType(_jtsComplex[i], (SSFCStrIn_t *)path) == SSF_JSON_TYPE_NUMBER);
        SSF_ASSERT(SSFJsonGetString(_jtsComplex[i], (SSFCStrIn_t *)path, strOut, sizeof(strOut), &strOutLen) == false);
#if SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1
        SSF_ASSERT(SSFJsonGetDouble(_jtsComplex[i], (SSFCStrIn_t *)path, &d) == true);
        SSF_ASSERT(d == -42);
#endif /* SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE */
        SSF_ASSERT(SSFJsonGetLong(_jtsComplex[i], (SSFCStrIn_t *)path, &si) == true);
        SSF_ASSERT(SSFJsonGetULong(_jtsComplex[i], (SSFCStrIn_t *)path, &ui) == false);
        SSF_ASSERT(si == -42);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, true) == false);
        SSF_ASSERT(SSFJsonGetHex(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen, false) == false);
        SSF_ASSERT(SSFJsonGetBase64(_jtsComplex[i], (SSFCStrIn_t *)path, binOut, sizeof(binOut), &binOutLen) == false);
        jtype = SSF_JSON_TYPE_MAX;
        SSF_ASSERT(SSFJsonObject(_jtsComplex[i], &index, &start, &end, (SSFCStrIn_t *)path, 0, &jtype) == true);
        SSF_ASSERT(jtype == SSF_JSON_TYPE_NUMBER);
        SSF_ASSERT(memcmp(&_jtsComplex[i][start], "-42", (end - start + 1)) == 0);
    }

    /* Generator tests */
    i = 0x12345678;
    SSF_ASSERT(SSFJsonPrintObject(_jsOut, sizeof(_jsOut), 0, &end, p3fn, &i, false) == true);
    SSF_ASSERT(SSFJsonIsValid(_jsOut));
    SSF_ASSERT(i == 0xabcdef90);
    SSF_ASSERT(SSFJsonPrintObject(_jsOut, sizeof(_jsOut), 0, &end, p1fn, NULL, false) == true);
    SSF_ASSERT(SSFJsonIsValid(_jsOut));
    SSF_ASSERT(SSFJsonPrintObject(_jsOut, sizeof(_jsOut), 0, &end, p2fn, NULL, false) == true);
    SSF_ASSERT(SSFJsonIsValid(_jsOut));
    SSF_ASSERT(SSFJsonPrintObject(_jsOut, sizeof(_jsOut), 0, &end, p1fn, NULL, false) == true);
    SSF_ASSERT(SSFJsonIsValid(_jsOut));
    i = 0x12345678;
    SSF_ASSERT(SSFJsonPrintObject(_jsOut, sizeof(_jsOut), 0, &end, p3fn, &i, false) == true);
    SSF_ASSERT(SSFJsonIsValid(_jsOut));
    SSF_ASSERT(i == 0xabcdef90);

#if SSF_JSON_CONFIG_ENABLE_UPDATE == 1
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", NULL, NULL,
                          "{}",
                          "{\"l1\":\"mynewvalue\"}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", NULL, NULL,
                          "{\"l1\":{\"l2\":123}}",
                          "{\"l1\":\"mynewvalue\"}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", NULL, NULL,
                          "{\"l2\":123}",
                          "{\"l1\":\"mynewvalue\",\"l2\":123}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", "l2", NULL,
                          "{\"l1\":{\"l2\":\"old\"}}",
                          "{\"l1\":{\"l2\":\"mynewvalue\"}}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", "l2", NULL,
                          "{\"l1\":{\"l2\":\"oldvalueislongerthannew\"}}",
                          "{\"l1\":{\"l2\":\"mynewvalue\"}}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", "l2", NULL,
                          "{\"l1\":{\"l2a\":\"notreplaced\"}}",
                          "{\"l1\":{\"l2\":\"mynewvalue\",\"l2a\":\"notreplaced\"}}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", "l2", NULL,
                          "{\"l1a\":{\"l2a\":\"notreplaced\"}}",
                          "{\"l1\":{\"l2\":\"mynewvalue\"},\"l1a\":{\"l2a\":\"notreplaced\"}}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", "l2", NULL,
                          "{\"l1\":{\"l2a\":123,\"l2\":{\"l3\":\"replaced\"},\"l2b\":456},\"l1a\":789}",
                          "{\"l1\":{\"l2a\":123,\"l2\":\"mynewvalue\",\"l2b\":456},\"l1a\":789}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", "l2", "l3",
                          "{\"l1\":{\"l2a\":123,\"l2\":{\"l3\":\"replaced\"},\"l2b\":456},\"l1a\":789}",
                          "{\"l1\":{\"l2a\":123,\"l2\":{\"l3\":\"mynewvalue\"},\"l2b\":456},\"l1a\":789}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", "l2", "l3",
                          "{\"l1\":{\"l2a\":123,\"l2\":{},\"l2b\":456},\"l1a\":789}",
                          "{\"l1\":{\"l2a\":123,\"l2\":{\"l3\":\"mynewvalue\"},\"l2b\":456},\"l1a\":789}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", "l2", "l3",
                          "{\"l1\":{\"l2a\":123,\"l2b\":456},\"l1a\":789}",
                          "{\"l1\":{\"l2\":{\"l3\":\"mynewvalue\"},\"l2a\":123,\"l2b\":456},\"l1a\":789}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", "l2", "l3",
                          "{\"l1A\":{\"l2a\":123,\"l2b\":456},\"l1a\":789}",
                          "{\"l1\":{\"l2\":{\"l3\":\"mynewvalue\"}},\"l1A\":{\"l2a\":123,\"l2b\":456},\"l1a\":789}");
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "l1", "l2", "l3", _jtsComplex[1], NULL);
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "obj2", "objdeep", "NUMFAR", _jtsComplex[1], NULL);
    SSFJsonUnitTestUpdate(_jsOut, sizeof(_jsOut), "obj2", "objdeep", "hex3", _jtsComplex[1], NULL);
#endif /* SSF_JSON_CONFIG_ENABLE_UPDATE */
}
#endif /* SSF_CONFIG_JSON_UNIT_TEST */

