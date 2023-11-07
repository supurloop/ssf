/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfini_ut.c                                                                                   */
/* Provides unit test for INI parser/generator interface.                                        */
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
#include "ssfini.h"
#include "ssfassert.h"
#include "ssfport.h"

typedef struct
{
    const char *ini;
    const char *section;
    const char *name;
    uint8_t index;

    bool isExpectedSectionPresent;
    bool isExpectedNameValuePresent;
    bool isExpectedStrValue;
    const char *expectedStrValue;
    bool isExpectedBoolValue;
    bool expectedBoolValue;
    bool isExpectedLongValue;
    long int expectedLongValue;
} SSFINIParserUnitTest_t;

static const char _ssfIni1[] = "";
static const char _ssfIni2[] = "\n";
static const char _ssfIni3[] = "\r";
static const char _ssfIni4[] = "\r\n";
static const char _ssfIni5[] = "\t \r\n\t ";
static const char _ssfIni6[] = "name=value";
static const char _ssfIni7[] = "name=value1\nname=value2\n";
static const char _ssfIni8[] = " \t name\t \t=\t\tvalue1  \n   name\t\t\t=value2\r\n\r\n";
static const char _ssfIni9[] = ";comment \r[section]\nname=value1\rname=value2";
static const char _ssfIni10[] = ";comment \r\t [ \tsection\t ]#111\n name\t=value1\r\nname=value2\r";
static const char _ssfIni11[] = ";comment \r\t [ \tsection1\t ]#111\n name\t=value1\r\nname=value2\r[section2]";
static const char _ssfIni12[] = ";comment \r\t [ \tsection1\t ]#111\n name\t=value1\r\nname=value2\r[section2]\nname=\n\rname2=0";
static const char _ssfIni13[] = "name=0";
static const char _ssfIni14[] = "name=1";
static const char _ssfIni15[] = "name= yes\n";
static const char _ssfIni16[] = " name =no";
static const char _ssfIni17[] = "name=\ton\t";
static const char _ssfIni18[] = "name=off\r";
static const char _ssfIni19[] = "name=true";
static const char _ssfIni20[] = "name= false\r\n";
static const char _ssfIni21[] = "[section]\nname=\t0 \r\n";
static const char _ssfIni22[] = "[ section]\nname=  1\t\t\r\n";
static const char _ssfIni23[] = "[\tsection]\nname= Yes\r\n";
static const char _ssfIni24[] = "[section ]\nname\t=nO \r\n";
static const char _ssfIni25[] = "[section\t]\nname=ON\r\n";
static const char _ssfIni26[] = "[section]\n\tname =\tOff \r\n";
static const char _ssfIni27[] = "[section]\n name\t= True\t\r\n";
static const char _ssfIni28[] = "[  section  ]\n name=FALSE\r\n";
static const char _ssfIni29[] = "name=1234567890";
static const char _ssfIni30[] = "name=-1234567890";
static const char _ssfIni31[] = "[section]\nname=1234567890\r\n";
static const char _ssfIni32[] = "[section]\nname =-1234567890\t\r\n";
static const char _ssfIni33[] = "[section]\n\tname =-1234567890 s\r\n";
static const char _ssfIni34[] = "[section]\nname -1234567890\t ;\r\n";
static const char _ssfIni35[] = "\t [\t section \" ] \t 11\nname=-1234567890\n[section2 2] \n \tname\t=\tvalue\t\n[section3]\n\rname=value3\rname2=1234567890-=!@#$%^&*()_+qwertyuiop[]\asdfghjkl;'zxcvbnm,./`~QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>? \n[section2]\nname=value2a\r \r\n";
static const char _ssfIni36[] = "name=";
static const char _ssfIni37[] = "name=\t\t\t   \t \t\t ";
static const char _ssfIni38[] = "\r\r\n  name\t = \t\t\t   \t \t\t \r\n\r\n\n";
static const char _ssfIni39[] = "[section]\nname=";
static const char _ssfIni40[] = "[section]\nname=\t\t\t   \t \t\t ";
static const char _ssfIni41[] = "[section]\n\r\r\n  name\t = \t\t\t   \t \t\t \r\n\r\n\n";

SSFINIParserUnitTest_t _ssfINIParserUT[] =
{
    {_ssfIni1,   NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni1,   "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0},
    {_ssfIni2,   NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni2,   "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0},
    {_ssfIni3,   NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni3,   "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0},
    {_ssfIni4,   NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni4,   "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0},
    {_ssfIni5,   NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni5,   "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0},

    {_ssfIni6,   NULL,          "name",   0,     true,         true,     true,     "value", false,  false, false,  0},
    {_ssfIni6,   NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni6,   NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni6,   NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni6,   "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0},
    {_ssfIni6,   "section",     "name",   1,     false,        false,    false,    "",      false,  false, false,  0},
    {_ssfIni6,   "section",     "name",   255,   false,        false,    false,    "",      false,  false, false,  0},

    {_ssfIni7,   NULL,          "name",   0,     true,         true,     true,     "value1",false,  false, false,  0},
    {_ssfIni7,   NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni7,   NULL,          "name",   1,     true,         true,     true,     "value2",false,  false, false,  0},
    {_ssfIni7,   NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni7,   "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0},
    {_ssfIni7,   "section",     "name",   1,     false,        false,    false,    "",      false,  false, false,  0},
    {_ssfIni7,   "section",     "name",   255,   false,        false,    false,    "",      false,  false, false,  0},

    {_ssfIni8,   NULL,          "name",   0,     true,         true,     true,     "value1",false,  false, false,  0},
    {_ssfIni8,   NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni8,   NULL,          "name",   1,     true,         true,     true,     "value2",false,  false, false,  0},
    {_ssfIni8,   NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni8,   "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0},
    {_ssfIni8,   "section",     "name",   1,     false,        false,    false,    "",      false,  false, false,  0},
    {_ssfIni8,   "section",     "name",   255,   false,        false,    false,    "",      false,  false, false,  0},

    {_ssfIni9,   NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni9,   NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni9,   NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni9,   NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni9,   "section",     "name",   0,     true,         true,     true,     "value1",false,  false, false,  0},
    {_ssfIni9,   "section",     "name",   1,     true,         true,     true,     "value2",false,  false, false,  0},
    {_ssfIni9,   "section",     "name",   2,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni9,   "section",     "name",   255,   true,         false,    false,    "",      false,  false, false,  0},

    {_ssfIni10,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni10,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni10,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni10,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni10,  "section",     "name",   0,     true,         true,     true,     "value1",false,  false, false,  0},
    {_ssfIni10,  "section",     "name",   1,     true,         true,     true,     "value2",false,  false, false,  0},
    {_ssfIni10,  "section",     "name",   2,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni10,  "section",     "name",   255,   true,         false,    false,    "",      false,  false, false,  0},

    {_ssfIni11,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni11,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni11,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni11,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni11,  "section1",    "name",   0,     true,         true,     true,     "value1",false,  false, false,  0},
    {_ssfIni11,  "section1",    "name",   1,     true,         true,     true,     "value2",false,  false, false,  0},
    {_ssfIni11,  "section1",    "name",   2,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni11,  "section1",    "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni11,  "section2",    "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni11,  "section3",    "name",   0,     false,        false,    false,    "",      false,  false, false,  0},

    {_ssfIni12,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni12,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni12,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni12,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni12,  "section1",    "name",   0,     true,         true,     true,     "value1",false,  false, false,  0},
    {_ssfIni12,  "section1",    "name",   1,     true,         true,     true,     "value2",false,  false, false,  0},
    {_ssfIni12,  "section1",    "name",   2,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni12,  "section1",    "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni12,  "section2",    "name",   0,     true,         true,     true,     "",      false,  false, false,  0},
    {_ssfIni12,  "section2",    "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni12,  "section2",    "name2",  0,     true,         true,     true,     "0",     true,   false, true,   0},
    {_ssfIni12,  "section3",    "name",   0,     false,        false,    false,    "",      false,  false, false,  0},

    {_ssfIni13,  NULL,          "name",   0,     true,         true,     true,     "0",     true,   false, true,   0},
    {_ssfIni13,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni13,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni13,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni13,  "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0},

    {_ssfIni14,  NULL,          "name",   0,     true,         true,     true,     "1",     true,   true,  true,   1},
    {_ssfIni14,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni14,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni14,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0},
    {_ssfIni14,  "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0},

    { _ssfIni15,  NULL,          "name",   0,     true,         true,     true,     "yes",   true,   true,  false,  0 },
    { _ssfIni15,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni15,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni15,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni15,  "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0 },

    { _ssfIni16,  NULL,          "name",   0,     true,         true,     true,    "no",     true,   false, false,  0 },
    { _ssfIni16,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni16,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni16,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni16,  "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0 },

    { _ssfIni17,  NULL,          "name",   0,     true,         true,     true,    "on",     true,   true,  false,  0 },
    { _ssfIni17,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni17,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni17,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni17,  "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0 },

    { _ssfIni18,  NULL,          "name",   0,     true,         true,     true,    "off",    true,   false, false,  0 },
    { _ssfIni18,  NULL,          "Name",   0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni18,  NULL,          "NAME",   0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni18,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni18,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni18,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni18,  "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0 },

    { _ssfIni19,  NULL,          "name",   0,     true,         true,     true,     "true",  true,   true,  false,  0 },
    { _ssfIni19,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni19,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni19,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni19,  "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0 },

    { _ssfIni20,  NULL,          "name",   0,     true,         true,     true,    "false",  true,   false, false,  0 },
    { _ssfIni20,  NULL,          "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni20,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni20,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni20,  "section",     "name",   0,     false,        false,    false,    "",      false,  false, false,  0 },

    { _ssfIni21,  "section",     "name",   0,     true,         true,     true,     "0",     true,   false, true,   0 },
    { _ssfIni21,  "section",     "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni21,  "section",     "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni21,  "section",     "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni21,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0 },

    { _ssfIni22,  "section",     "name",   0,     true,         true,     true,     "1",     true,   true,  true,   1 },
    { _ssfIni22,  "section",     "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni22,  "section",     "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni22,  "section",     "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni22,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0 },

    { _ssfIni23,  "section",     "name",   0,     true,         true,     true,     "Yes",   true,   true,  false,  0 },
    { _ssfIni23,  "section",     "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni23,  "section",     "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni23,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni23,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0 },

    { _ssfIni24,  "section",     "name",   0,     true,         true,     true,    "nO",     true,   false, false,  0 },
    { _ssfIni24,  "section",     "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni24,  "section",     "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni24,  "section",     "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni24,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0 },

    { _ssfIni25,  "section",     "name",   0,     true,         true,     true,    "ON",     true,   true,  false,  0 },
    { _ssfIni25,  "section",     "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni25,  "section",     "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni25,  "section",     "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni25,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0 },

    { _ssfIni26,  "section",     "name",   0,     true,         true,     true,    "Off",    true,   false, false,  0 },
    { _ssfIni26,  "section",     "Name",   0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni26,  "section",     "NAME",   0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni26,  "section",     "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni26,  NULL,          "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni26,  NULL,          "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni26,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0 },

    { _ssfIni27,  "section",     "name",   0,     true,         true,     true,     "True",  true,   true,  false,  0 },
    { _ssfIni27,  "section",     "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni27,  "section",     "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni27,  "section",     "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni27,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0 },

    { _ssfIni28,  "section",     "name",   0,     true,         true,     true,    "FALSE",  true,   false, false,  0 },
    { _ssfIni28,  "section",     "name1",  0,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni28,  "section",     "name",   1,     true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni28,  "section",     "name",   255,   true,         false,    false,    "",      false,  false, false,  0 },
    { _ssfIni28,  NULL,          "name",   0,     true,         false,    false,    "",      false,  false, false,  0 },

    { _ssfIni29,  NULL,          "name",   0,     true,         true,     true,     "1234567890", false,  false, true,   1234567890l },
    { _ssfIni29,  NULL,          "name1",  0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni29,  NULL,          "name",   1,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni29,  NULL,          "name",   255,   true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni29,  "section",     "name",   0,     false,        false,    false,    "",           false,  false, false,  0 },
    { _ssfIni29,  "s",           "name",   0,     false,        false,    false,    "",           false,  false, false,  0 },

    { _ssfIni30,  NULL,          "name",   0,     true,         true,     true,     "-1234567890",false,  false, true,   -1234567890l },
    { _ssfIni30,  NULL,          "name1",  0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni30,  NULL,          "name",   1,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni30,  NULL,          "name",   255,   true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni30,  "section",     "name",   0,     false,        false,    false,    "",           false,  false, false,  0 },
    { _ssfIni30,  "s",           "name",   0,     false,        false,    false,    "",           false,  false, false,  0 },

    { _ssfIni31,  "section",     "name",   0,     true,         true,     true,     "1234567890", false,  false, true,   1234567890l },
    { _ssfIni31,  "section",     "name1",  0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni31,  "section",     "name",   1,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni31,  "section",     "name",   255,   true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni31,  NULL,          "name",   0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni31,  "s",           "name",   0,     false,        false,    false,    "",           false,  false, false,  0 },

    { _ssfIni32,  "section",     "name",   0,     true,         true,     true,     "-1234567890",false,  false, true,   -1234567890l },
    { _ssfIni32,  "section",     "name1",  0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni32,  "section",     "name",   1,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni32,  "section",     "name",   255,   true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni32,  NULL,          "name",   0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni32,  "s",           "name",   0,     false,        false,    false,    "",           false,  false, false,  0 },

    { _ssfIni33,  "section",     "name",   0,     true,         true,     true,     "-1234567890",false,  false, true,   -1234567890l },
    { _ssfIni33,  "section",     "name1",  0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni33,  "section",     "name",   1,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni33,  "section",     "name",   255,   true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni33,  NULL,          "name",   0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni33,  "s",           "name",   0,     false,        false,    false,    "",           false,  false, false,  0 },

    { _ssfIni34,  "section",     "name",   0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni34,  "section",     "name1",  0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni34,  "section",     "name",   1,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni34,  "section",     "name",   255,   true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni34,  NULL,          "name",   0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni34,  "s",           "name",   0,     false,        false,    false,    "",           false,  false, false,  0 },

    { _ssfIni35,  "section",     "name",   0,     true,         true,     true,     "-1234567890",false,  false, true,   -1234567890 },
    { _ssfIni35,  "section",     "name",   1,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni35,  "section2",    "name",   0,     true,         true,     true,     "value",      false,  false, false,  0 },
    { _ssfIni35,  "section2",    "name",   1,     true,         true,     true,     "value2a",    false,  false, false,  0 },
    { _ssfIni35,  "section2",    "name",   3,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni35,  "section3",    "name",   0,     true,         true,     true,     "value3",     false,  false, false,  0 },
    { _ssfIni35,  "section3",    "name",   1,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni35,  "section3",    "name2",  0,     true,         true,     true,     "1234567890-=!@#$%^&*()_+qwertyuiop[]\asdfghjkl;'zxcvbnm,./`~QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?", false, false, false, 0 },
    { _ssfIni35,  "section3",    "name2",  1,     true,         false,    false,    "",           false,  false, false,  0 },

    { _ssfIni36,  NULL,          "name",   0,     true,         true,     true,     "",           false,  false, false,  0 },
    { _ssfIni36,  NULL,          "name1",  0,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni36,  NULL,          "name",   1,     true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni36,  NULL,          "name",   255,   true,         false,    false,    "",           false,  false, false,  0 },
    { _ssfIni36,  "section",     "name",   0,     false,        false,    false,    "",           false,  false, false,  0 },
    { _ssfIni36,  "s",           "name",   0,     false,        false,    false,    "",           false,  false, false,  0 },

    { _ssfIni37,  NULL,          "name",   0,     true,         true,     true,     "",           false,  false, false,  0 },
    { _ssfIni38,  NULL,          "name",   0,     true,         true,     true,     "",           false,  false, false,  0 },
    { _ssfIni39,  "section",     "name",   0,     true,         true,     true,     "",           false,  false, false,  0},
    { _ssfIni40,  "section",     "name",   0,     true,         true,     true,     "",           false,  false, false,  0 },
    { _ssfIni41,  "section",     "name",   0,     true,         true,     true,     "",           false,  false, false,  0 },
};

static char _ssfINIBigINI[] = ";text\nname=value\r\n[section]\r\nB0=0\r\nB1=1\r\nBno=no\r\nByes=yes\r\nBoff=off\r\nBon=on\r\nBF=false\r\nBT=true\r\nLI=0\nLIM=-1\nLIL=-1234567890\n";

#if SSF_CONFIG_INI_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on INI parser/generator external interface.                                */
/* --------------------------------------------------------------------------------------------- */
void SSFINIUnitTest(void)
{
    uint32_t i;
    char outStr[256];
    size_t outStrLen;
    size_t outStrLenTemp;
    bool outBool;
    int64_t outLong;
    size_t iniLen;
    char iniStr[1024];
    size_t iniLenLast;

    /* Test Parser */
    SSF_ASSERT_TEST(SSFINIIsSectionPresent(NULL, NULL));
    SSF_ASSERT_TEST(SSFINIIsNameValuePresent(NULL, NULL, "name", 0));
    SSF_ASSERT_TEST(SSFINIIsNameValuePresent("ini", NULL, NULL, 0));
    SSF_ASSERT_TEST(SSFINIGetStrValue(NULL, NULL, "name", 0, outStr, sizeof(outStr), &outStrLen));
    SSF_ASSERT_TEST(SSFINIGetStrValue("ini", NULL, NULL, 0, outStr, sizeof(outStr), &outStrLen));
    SSF_ASSERT_TEST(SSFINIGetStrValue("ini", NULL, "", 0, outStr, sizeof(outStr), &outStrLen));
    SSF_ASSERT_TEST(SSFINIGetStrValue("ini", NULL, "name", 0, NULL, sizeof(outStr), &outStrLen));
    SSF_ASSERT_TEST(SSFINIGetStrValue("ini", NULL, "name", 0, outStr, 0, &outStrLen));
    SSF_ASSERT_TEST(SSFINIGetBoolValue(NULL, NULL, "name", 0, &outBool));
    SSF_ASSERT_TEST(SSFINIGetBoolValue("ini", NULL, "", 0, &outBool));
    SSF_ASSERT_TEST(SSFINIGetBoolValue("ini", NULL, NULL, 0, &outBool));
    SSF_ASSERT_TEST(SSFINIGetBoolValue("ini", NULL, "name", 0, NULL));
    SSF_ASSERT_TEST(SSFINIGetIntValue(NULL, NULL, "name", 0, &outLong));
    SSF_ASSERT_TEST(SSFINIGetIntValue("ini", NULL, NULL, 0, &outLong));
    SSF_ASSERT_TEST(SSFINIGetIntValue("ini", NULL, "", 0, &outLong));
    SSF_ASSERT_TEST(SSFINIGetIntValue("ini", NULL, "name", 0, NULL));

    for (i = 0; i < sizeof(_ssfINIParserUT) / sizeof(SSFINIParserUnitTest_t); i++)
    {
        SSF_ASSERT(SSFINIIsSectionPresent(_ssfINIParserUT[i].ini, _ssfINIParserUT[i].section) ==
                   _ssfINIParserUT[i].isExpectedSectionPresent);
        SSF_ASSERT(SSFINIIsNameValuePresent(_ssfINIParserUT[i].ini, _ssfINIParserUT[i].section,
                                            _ssfINIParserUT[i].name, _ssfINIParserUT[i].index) ==
                   _ssfINIParserUT[i].isExpectedNameValuePresent);
        SSF_ASSERT(SSFINIGetStrValue(_ssfINIParserUT[i].ini, _ssfINIParserUT[i].section,
                                     _ssfINIParserUT[i].name, _ssfINIParserUT[i].index, outStr,
                                     sizeof(outStr), &outStrLen) ==
                   _ssfINIParserUT[i].isExpectedStrValue);
        if (_ssfINIParserUT[i].isExpectedStrValue)
        {
            SSF_ASSERT(SSFINIGetStrValue(_ssfINIParserUT[i].ini, _ssfINIParserUT[i].section,
                                         _ssfINIParserUT[i].name, _ssfINIParserUT[i].index,
                                         outStr, sizeof(outStr), NULL) ==
                       _ssfINIParserUT[i].isExpectedStrValue);
            SSF_ASSERT(strcmp(_ssfINIParserUT[i].expectedStrValue, outStr) == 0);
            SSF_ASSERT(outStrLen == strlen(_ssfINIParserUT[i].expectedStrValue));
            if (outStrLen > 0)
            {
                outStrLenTemp = outStrLen;
                outStrLen = (size_t)-1;
                SSF_ASSERT(SSFINIGetStrValue(_ssfINIParserUT[i].ini, _ssfINIParserUT[i].section,
                                             _ssfINIParserUT[i].name, _ssfINIParserUT[i].index,
                                             outStr, outStrLen, &outStrLen) ==
                           _ssfINIParserUT[i].isExpectedStrValue);
                SSF_ASSERT(outStrLen == outStrLenTemp);
            }
        }
        else
        {
            outStrLen = (size_t)-1;
            SSF_ASSERT(SSFINIGetStrValue(_ssfINIParserUT[i].ini, _ssfINIParserUT[i].section,
                                         _ssfINIParserUT[i].name, _ssfINIParserUT[i].index,
                                         outStr, outStrLen, &outStrLen) == false);
            SSF_ASSERT(outStrLen == ((size_t)-1));
        }
        SSF_ASSERT(SSFINIGetStrValue(_ssfINIParserUT[i].ini, _ssfINIParserUT[i].section,
                                     _ssfINIParserUT[i].name, _ssfINIParserUT[i].index, outStr,
                                     sizeof(outStr), NULL) ==
                   _ssfINIParserUT[i].isExpectedStrValue);
        if (_ssfINIParserUT[i].isExpectedStrValue)
        {
            SSF_ASSERT(strcmp(_ssfINIParserUT[i].expectedStrValue, outStr) == 0);
        }
        SSF_ASSERT(SSFINIGetBoolValue(_ssfINIParserUT[i].ini, _ssfINIParserUT[i].section,
                                      _ssfINIParserUT[i].name, _ssfINIParserUT[i].index,
                                      &outBool) == _ssfINIParserUT[i].isExpectedBoolValue);
        if (_ssfINIParserUT[i].isExpectedBoolValue)
        {
            SSF_ASSERT(_ssfINIParserUT[i].expectedBoolValue == outBool);
        }
        SSF_ASSERT(SSFINIGetIntValue(_ssfINIParserUT[i].ini, _ssfINIParserUT[i].section,
                                      _ssfINIParserUT[i].name, _ssfINIParserUT[i].index,
                                      &outLong) == _ssfINIParserUT[i].isExpectedLongValue);
        if (_ssfINIParserUT[i].isExpectedLongValue)
        {
            SSF_ASSERT(_ssfINIParserUT[i].expectedLongValue == outLong);
        }
    }

    /* Test Generator */
    SSF_ASSERT_TEST(SSFINIPrintComment(NULL, 4, &iniLen, "text", SSF_INI_COMMENT_SEMI, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintComment("ini", 0, &iniLen, "text", SSF_INI_COMMENT_SEMI, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintComment("ini", 4, NULL, "text", SSF_INI_COMMENT_SEMI, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintComment("ini", 4, &iniLen, NULL, SSF_INI_COMMENT_SEMI, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintComment("ini", 4, &iniLen, "text", SSF_INI_COMMENT_MIN, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintComment("ini", 4, &iniLen, "text", SSF_INI_COMMENT_MAX, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintComment("ini", 4, &iniLen, "text", SSF_INI_COMMENT_MAX + 1, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintComment("ini", 4, &iniLen, "text", SSF_INI_COMMENT_SEMI, SSF_INI_LINE_ENDING_MIN));
    SSF_ASSERT_TEST(SSFINIPrintComment("ini", 4, &iniLen, "text", SSF_INI_COMMENT_SEMI, SSF_INI_LINE_ENDING_MAX));
    SSF_ASSERT_TEST(SSFINIPrintComment("ini", 4, &iniLen, "text", SSF_INI_COMMENT_SEMI, SSF_INI_LINE_ENDING_MAX + 1));
    SSF_ASSERT_TEST(SSFINIPrintSection(NULL, 4, &iniLen, "section", SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintSection("ini", 0, &iniLen, "section", SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintSection("ini", 4, NULL, "section", SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintSection("ini", 4, &iniLen, "", SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintSection("ini", 4, &iniLen, NULL, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintSection("ini", 4, &iniLen, "section", SSF_INI_LINE_ENDING_MIN));
    SSF_ASSERT_TEST(SSFINIPrintSection("ini", 4, &iniLen, "section", SSF_INI_LINE_ENDING_MAX));
    SSF_ASSERT_TEST(SSFINIPrintSection("ini", 4, &iniLen, "section", SSF_INI_LINE_ENDING_MAX + 1));
    SSF_ASSERT_TEST(SSFINIPrintNameStrValue(NULL, 4, &iniLen, "name", "value", SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameStrValue("ini", 0, &iniLen, "name", "value", SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameStrValue("ini", 4, NULL, "name", "value", SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameStrValue("ini", 4, &iniLen, "", "value", SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameStrValue("ini", 4, &iniLen, NULL, "value", SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameStrValue("ini", 4, &iniLen, "name", NULL, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameStrValue("ini", 4, &iniLen, "name", "value", SSF_INI_LINE_ENDING_MIN));
    SSF_ASSERT_TEST(SSFINIPrintNameStrValue("ini", 4, &iniLen, "name", "value", SSF_INI_LINE_ENDING_MAX));
    SSF_ASSERT_TEST(SSFINIPrintNameStrValue("ini", 4, &iniLen, "name", "value", SSF_INI_LINE_ENDING_MAX + 1));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue(NULL, 4, &iniLen, "name", true, SSF_INI_BOOL_1_0, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 0, &iniLen, "name", true, SSF_INI_BOOL_1_0, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 4, NULL, "name", true, SSF_INI_BOOL_1_0, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 4, &iniLen, "", true, SSF_INI_BOOL_1_0, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 4, &iniLen, NULL, true, SSF_INI_BOOL_1_0, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 4, &iniLen, "name", true, SSF_INI_BOOL_MIN, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 4, &iniLen, "name", true, SSF_INI_BOOL_MIN, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 4, &iniLen, "name", true, SSF_INI_BOOL_MAX, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 4, &iniLen, "name", true, SSF_INI_BOOL_MAX + 1, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 4, &iniLen, "name", true, SSF_INI_BOOL_1_0, SSF_INI_LINE_ENDING_MIN));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 4, &iniLen, "name", true, SSF_INI_BOOL_1_0, SSF_INI_LINE_ENDING_MAX));
    SSF_ASSERT_TEST(SSFINIPrintNameBoolValue("ini", 4, &iniLen, "name", true, SSF_INI_BOOL_1_0, SSF_INI_LINE_ENDING_MAX + 1));
    SSF_ASSERT_TEST(SSFINIPrintNameIntValue(NULL, 4, &iniLen, "name", 0, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameIntValue("ini", 0, &iniLen, "name", 0, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameIntValue("ini", 4, NULL, "name", 0, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameIntValue("ini", 4, &iniLen, "", 0, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameIntValue("ini", 4, &iniLen, NULL, 0, SSF_INI_LF));
    SSF_ASSERT_TEST(SSFINIPrintNameIntValue("ini", 4, &iniLen, "name", 0, SSF_INI_LINE_ENDING_MIN));
    SSF_ASSERT_TEST(SSFINIPrintNameIntValue("ini", 4, &iniLen, "name", 0, SSF_INI_LINE_ENDING_MAX));
    SSF_ASSERT_TEST(SSFINIPrintNameIntValue("ini", 4, &iniLen, "name", 0, SSF_INI_LINE_ENDING_MAX + 1));

    iniLen = 0;
    SSF_ASSERT(SSFINIPrintComment(iniStr, sizeof(iniStr), &iniLen, "text", SSF_INI_COMMENT_SEMI, SSF_INI_LF));
    SSF_ASSERT(iniLen == 6);
    SSF_ASSERT(strcmp(iniStr, ";text\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintComment(iniStr, sizeof(iniStr), &iniLen, "text", SSF_INI_COMMENT_HASH, SSF_INI_CRLF));
    SSF_ASSERT(iniLen == 7);
    SSF_ASSERT(strcmp(iniStr, "#text\r\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintComment(iniStr, sizeof(iniStr), &iniLen, "text", SSF_INI_COMMENT_NONE, SSF_INI_CRLF));
    SSF_ASSERT(iniLen == 6);
    SSF_ASSERT(strcmp(iniStr, "text\r\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintComment(iniStr, 6, &iniLen, "text", SSF_INI_COMMENT_NONE, SSF_INI_CRLF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintComment(iniStr, 7, &iniLen, "text", SSF_INI_COMMENT_NONE, SSF_INI_CRLF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintComment(iniStr, sizeof(iniStr), &iniLen, "", SSF_INI_COMMENT_NONE, SSF_INI_LF));
    SSF_ASSERT(iniLen == 1);
    SSF_ASSERT(strcmp(iniStr, "\n") == 0);

    iniLen = 0;
    SSF_ASSERT(SSFINIPrintSection(iniStr, sizeof(iniStr), &iniLen, "section", SSF_INI_LF));
    SSF_ASSERT(iniLen == 10);
    SSF_ASSERT(strcmp(iniStr, "[section]\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintSection(iniStr, sizeof(iniStr), &iniLen, "section", SSF_INI_CRLF));
    SSF_ASSERT(iniLen == 11);
    SSF_ASSERT(strcmp(iniStr, "[section]\r\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintSection(iniStr, 11, &iniLen, "section", SSF_INI_CRLF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintSection(iniStr, 12, &iniLen, "section", SSF_INI_CRLF));

    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameStrValue(iniStr, sizeof(iniStr), &iniLen, "name", "value", SSF_INI_LF));
    SSF_ASSERT(iniLen == 11);
    SSF_ASSERT(strcmp(iniStr, "name=value\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameStrValue(iniStr, sizeof(iniStr), &iniLen, "name", "value", SSF_INI_CRLF));
    SSF_ASSERT(iniLen == 12);
    SSF_ASSERT(strcmp(iniStr, "name=value\r\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameStrValue(iniStr, 12, &iniLen, "name", "value", SSF_INI_CRLF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameStrValue(iniStr, 13, &iniLen, "name", "value", SSF_INI_CRLF));

    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "name", false, SSF_INI_BOOL_1_0, SSF_INI_LF));
    SSF_ASSERT(iniLen == 7);
    SSF_ASSERT(strcmp(iniStr, "name=0\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 7, &iniLen, "name", false, SSF_INI_BOOL_1_0, SSF_INI_LF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 8, &iniLen, "name", false, SSF_INI_BOOL_1_0, SSF_INI_LF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "name", true, SSF_INI_BOOL_1_0, SSF_INI_CRLF));
    SSF_ASSERT(iniLen == 8);
    SSF_ASSERT(strcmp(iniStr, "name=1\r\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 8, &iniLen, "name", true, SSF_INI_BOOL_1_0, SSF_INI_CRLF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 9, &iniLen, "name", true, SSF_INI_BOOL_1_0, SSF_INI_CRLF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "name", false, SSF_INI_BOOL_YES_NO, SSF_INI_LF));
    SSF_ASSERT(iniLen == 8);
    SSF_ASSERT(strcmp(iniStr, "name=no\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 8, &iniLen, "name", false, SSF_INI_BOOL_YES_NO, SSF_INI_LF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 9, &iniLen, "name", false, SSF_INI_BOOL_YES_NO, SSF_INI_LF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "name", true, SSF_INI_BOOL_YES_NO, SSF_INI_CRLF));
    SSF_ASSERT(iniLen == 10);
    SSF_ASSERT(strcmp(iniStr, "name=yes\r\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 10, &iniLen, "name", true, SSF_INI_BOOL_YES_NO, SSF_INI_CRLF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 11, &iniLen, "name", true, SSF_INI_BOOL_YES_NO, SSF_INI_CRLF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "name", false, SSF_INI_BOOL_ON_OFF, SSF_INI_LF));
    SSF_ASSERT(iniLen == 9);
    SSF_ASSERT(strcmp(iniStr, "name=off\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 9, &iniLen, "name", false, SSF_INI_BOOL_ON_OFF, SSF_INI_LF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 10, &iniLen, "name", false, SSF_INI_BOOL_ON_OFF, SSF_INI_LF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "name", true, SSF_INI_BOOL_ON_OFF, SSF_INI_CRLF));
    SSF_ASSERT(iniLen == 9);
    SSF_ASSERT(strcmp(iniStr, "name=on\r\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 9, &iniLen, "name", true, SSF_INI_BOOL_ON_OFF, SSF_INI_CRLF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 10, &iniLen, "name", true, SSF_INI_BOOL_ON_OFF, SSF_INI_CRLF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "name", false, SSF_INI_BOOL_TRUE_FALSE, SSF_INI_LF));
    SSF_ASSERT(iniLen == 11);
    SSF_ASSERT(strcmp(iniStr, "name=false\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 11, &iniLen, "name", false, SSF_INI_BOOL_TRUE_FALSE, SSF_INI_LF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 12, &iniLen, "name", false, SSF_INI_BOOL_TRUE_FALSE, SSF_INI_LF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "name", true, SSF_INI_BOOL_TRUE_FALSE, SSF_INI_CRLF));
    SSF_ASSERT(iniLen == 11);
    SSF_ASSERT(strcmp(iniStr, "name=true\r\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 11, &iniLen, "name", true, SSF_INI_BOOL_TRUE_FALSE, SSF_INI_CRLF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, 12, &iniLen, "name", true, SSF_INI_BOOL_TRUE_FALSE, SSF_INI_CRLF));

    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, sizeof(iniStr), &iniLen, "name", 0l, SSF_INI_LF));
    SSF_ASSERT(iniLen == 7);
    SSF_ASSERT(strcmp(iniStr, "name=0\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, 7, &iniLen, "name", 0l, SSF_INI_LF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, 8, &iniLen, "name", 0l, SSF_INI_LF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, sizeof(iniStr), &iniLen, "name", 1l , SSF_INI_LF));
    SSF_ASSERT(iniLen == 7);
    SSF_ASSERT(strcmp(iniStr, "name=1\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, 7, &iniLen, "name", 1l, SSF_INI_LF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, 8, &iniLen, "name", 1l, SSF_INI_LF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, sizeof(iniStr), &iniLen, "name", -1l, SSF_INI_LF));
    SSF_ASSERT(iniLen == 8);
    SSF_ASSERT(strcmp(iniStr, "name=-1\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, 8, &iniLen, "name", -1l, SSF_INI_LF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, 9, &iniLen, "name", -1l, SSF_INI_LF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, sizeof(iniStr), &iniLen, "name", 1234567890l, SSF_INI_CRLF));
    SSF_ASSERT(iniLen == 17);
    SSF_ASSERT(strcmp(iniStr, "name=1234567890\r\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, 17, &iniLen, "name", 1234567890l, SSF_INI_CRLF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, 18, &iniLen, "name", 1234567890l, SSF_INI_CRLF));
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, sizeof(iniStr), &iniLen, "name", -1234567890l, SSF_INI_CRLF));
    SSF_ASSERT(iniLen == 18);
    SSF_ASSERT(strcmp(iniStr, "name=-1234567890\r\n") == 0);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, 18, &iniLen, "name", -1234567890l, SSF_INI_CRLF) == false);
    iniLen = 0;
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, 19, &iniLen, "name", -1234567890l, SSF_INI_CRLF));

    iniLen = 0;
    iniLenLast = iniLen;
    SSF_ASSERT(SSFINIPrintComment(iniStr, sizeof(iniStr), &iniLen, "text", SSF_INI_COMMENT_SEMI, SSF_INI_LF));
    SSF_ASSERT((iniLen - iniLenLast) == 6);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameStrValue(iniStr, sizeof(iniStr), &iniLen, "name", "value", SSF_INI_CRLF));
    SSF_ASSERT((iniLen - iniLenLast) == 12);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintSection(iniStr, sizeof(iniStr), &iniLen, "section", SSF_INI_CRLF));
    SSF_ASSERT((iniLen - iniLenLast) == 11);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "B0", false, SSF_INI_BOOL_1_0, SSF_INI_CRLF));
    SSF_ASSERT((iniLen - iniLenLast) == 6);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "B1", true, SSF_INI_BOOL_1_0, SSF_INI_CRLF));
    SSF_ASSERT((iniLen - iniLenLast) == 6);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "Bno", false, SSF_INI_BOOL_YES_NO, SSF_INI_CRLF));
    SSF_ASSERT((iniLen - iniLenLast) == 8);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "Byes", true, SSF_INI_BOOL_YES_NO, SSF_INI_CRLF));
    SSF_ASSERT((iniLen - iniLenLast) == 10);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "Boff", false, SSF_INI_BOOL_ON_OFF, SSF_INI_CRLF));
    SSF_ASSERT((iniLen - iniLenLast) == 10);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "Bon", true, SSF_INI_BOOL_ON_OFF, SSF_INI_CRLF));
    SSF_ASSERT((iniLen - iniLenLast) == 8);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "BF", false, SSF_INI_BOOL_TRUE_FALSE, SSF_INI_CRLF));
    SSF_ASSERT((iniLen - iniLenLast) == 10);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameBoolValue(iniStr, sizeof(iniStr), &iniLen, "BT", true, SSF_INI_BOOL_TRUE_FALSE, SSF_INI_CRLF));
    SSF_ASSERT((iniLen - iniLenLast) == 9);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, sizeof(iniStr), &iniLen, "LI", 0l, SSF_INI_LF));
    SSF_ASSERT((iniLen - iniLenLast) == 5);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, sizeof(iniStr), &iniLen, "LIM", -1l, SSF_INI_LF));
    SSF_ASSERT((iniLen - iniLenLast) == 7);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
    SSF_ASSERT(SSFINIPrintNameIntValue(iniStr, sizeof(iniStr), &iniLen, "LIL", -1234567890l, SSF_INI_LF));
    SSF_ASSERT((iniLen - iniLenLast) == 16);
    iniLenLast = iniLen;
    SSF_ASSERT(memcmp(iniStr, _ssfINIBigINI, iniLen) == 0);
    SSF_ASSERT(iniStr[iniLen] == 0);
}
#endif /* SSF_CONFIG_INI_UNIT_TEST */
