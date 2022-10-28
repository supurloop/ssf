/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfini.c                                                                                      */
/* Provides parser/generator interface for basic INI file format.                                */
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
/*                                                                                               */
/* INI PARSING RULES                                                                             */
/*                                                                                               */
/* The INI parser is deliberately forgiving and may successfully parse INIs that are "poorly"    */
/* written. The main limitation is the lack of support for quoted fields, which would allow      */
/* Sections, Names, and/or Values to contain whitespace.                                         */
/*                                                                                               */
/* A Line is delimited by a newline ('\n'), carriage return ('\r') or a NULL terminator ('\x00').*/
/* Line continuation using a backslash ('\') as last character in a Line is not supported.       */
/* Escape sequences are not supported; eg. \x20\t is treated as 6 plaintext characters.          */
/* Quotes ('"') are not supported, they are treated as simple chars in a Section, Name, or Value.*/
/* Whitespace (WS) is space ('\x20') or tab ('\t').                                              */
/* WS at the beginning of a Line is ignored.                                                     */
/* Comments begin with a semi-colon (';') or hash ('#').                                         */
/* Comments on their own line are explicitly ignored.                                            */
/* Section declarations begin with an open bracket ('[') and end with a closing bracket (']').   */
/* WS after the Section declaration '[' is ignored.                                              */
/* The Section Name starts after the initial WS, and ends at the ']' or first WS encountered.    */
/* Section Names must be at least 1 character in length.                                         */
/* The remainder of the Section declaration after the ']' is ignored.                            */
/* Section names are case sensitive.                                                             */
/* Name/Value declarations have a Name, equal sign ('='), and a Value.                           */
/* Names must be at least 1 character in length.                                                 */
/* Names are case sensitive.                                                                     */
/* WS following the Name ends the Name field and all characters up to = are ignored.             */
/* The Value field starts after the =.                                                           */
/* WS following the = is ignored.                                                                */
/* Values may be 0 characters in length.                                                         */
/* The Value ends at the first WS or end of line.                                                */
/* Duplicate Section Names are permitted.                                                        */
/* Duplicate Section/Name pairs are permitted, and referenceable with a 0-based index.           */
/* Name/Value pairs before 1st Section declaration, referenced by using NULL for Section string. */
/* A boolean Value is true if the case ignored string Value is "1", "yes", "true", or "on".      */
/* A boolean Value is false if the case ignored string Value is "0", "no", "false", or "off".    */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdlib.h>
#include "ssfport.h"
#include "ssfini.h"

typedef struct
{
    const char *line;
    size_t lineLen;
    const char *section;
    size_t sectionLen;
    const char *name;
    size_t nameLen;
    const char *value;
    size_t valueLen;
} SSFINIContext_t;

/* --------------------------------------------------------------------------------------------- */
/* Returns true if unprocessed line found and context updated, else false.                       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFINIFindNextLine(SSFCStrIn_t ini, SSFINIContext_t *context)
{
    char *eol;
    char *eol2;

    SSF_REQUIRE(ini != NULL);
    SSF_REQUIRE(context != NULL);

    /* Is context initialized? */
    if (context->line == NULL)
    /* No, set line to start of INI */
    { context->line = ini; }
    /* Yes, advance to next potential line */
    else
    {
        context->line += context->lineLen;
        if (*(context->line) != '\x00') context->line++;
    }

    /* Can we find a line terminator? */
    eol = strchr(context->line, '\n');
    eol2 = strchr(context->line, '\r');
    if ((eol == NULL) && (eol2 == NULL))
    {
        /* No, find end of INI */
        eol = strchr(context->line, '\x00');
        SSF_ASSERT(eol != NULL);

        /* If we are already at end of INI, then no new line found */
        if (eol == context->line) return false;

        /* Otherwise there is a final line to process */
        context->lineLen = eol - context->line;
    }
    else
    {
        /* Yes, there is another line to process, update lineLen */
        if ((eol != NULL) && (eol2 != NULL))
        {
            if (eol < eol2) context->lineLen = eol - context->line;
            else context->lineLen = eol2 - context->line;
        }
        else if (eol != NULL) context->lineLen = eol - context->line;
        else context->lineLen = eol2 - context->line;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Advances str past whitespace and compensates strLen accordingly.                              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFINISkipWhiteSpace(SSFCStrIn_t *str, size_t *strLen)
{
    char c;

    SSF_REQUIRE(str != NULL);
    SSF_REQUIRE(*str != NULL);
    SSF_REQUIRE(strLen != NULL);

    /* Advance str when more to look at and current value is WS */
    c = **str;
    while ((*strLen > 0) && ((c == ' ') || (c == '\t')))
    {
        (*str)++;
        (*strLen)--;
        c = **str;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if parsing found a section or name value pair and context updated, else false.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFINIParseSection(SSFINIContext_t *context)
{
    char c = *(context->line);
    const char *line = context->line;
    const char *lineEnd = context->line + context->lineLen;
    size_t lineLen = context->lineLen;
    const char *section;
    const char *endOfName = NULL;

    if (c == '[')
    {
        line++;
        lineLen--;
        _SSFINISkipWhiteSpace(&line, &lineLen);
        section = line;
        while (line <= lineEnd)
        {
            if ((*line == ' ') || (*line == '\t'))
            {
                if (endOfName == NULL) endOfName = line;
            }
            else if (*line == ']')
            {
                /* Found a section */
                context->section = section;
                if (endOfName == NULL) context->sectionLen = line - section;
                else context->sectionLen = endOfName - section;

                /* Reset name/value context */
                context->name = NULL;
                context->nameLen = 0;
                context->value = NULL;
                context->valueLen = 0;
                return true;
            }
            line++;
        }
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if parsing found a section or name value pair else false.                        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFINIParseNameValue(SSFINIContext_t *context)
{
    const char *line = context->line;
    const char *lineEnd = context->line + context->lineLen;
    size_t lineLen = context->lineLen;
    const char *name;
    const char *endOfName = NULL;

    name = line;
    while (line <= lineEnd)
    {
        if ((*line == ' ') || (*line == '\t'))
        {
            if (endOfName == NULL) endOfName = line;
        }
        else if (*line == '=')
        {
            context->name = name;
            if (endOfName == NULL) { context->nameLen = line - name; }
            else { context->nameLen = endOfName - name; }
            line++;
            context->valueLen = 0;
            if (line > lineEnd) return true;

            lineLen = lineEnd - line;
            _SSFINISkipWhiteSpace(&line, &lineLen);
            context->value = line;

            /* Parse value */
            while (line <= lineEnd)
            {
                /* End of value? */
                if ((*line == ' ') || (*line == '\t') || (*line == '\n') || (*line == '\r') ||
                    (*line == '\x00'))
                /* Yes, found white space or end of line */
                { return true; }
                context->valueLen++;
                line++;
            }
            return true;
        }
        line++;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if parsing found a section or name value pair else false.                        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFINIParseLine(SSFINIContext_t *context)
{
    /* Skip all leading WS */
    _SSFINISkipWhiteSpace(&(context->line), &(context->lineLen));

    /* Something in line to process? */
    if (context->lineLen > 0)
    {
        /* Yes, is line a comment? */
        if (*(context->line) == ';' || *(context->line) == '#')
        /* Yes, didn't find a section or name/value pair */
        { return false; }
    }

    /* Is line a [section]? */
    if (_SSFINIParseSection(context) == false)
    {
        /* No, is it a name=value pair? */
        return _SSFINIParseNameValue(context);
    }

    /* Line was a section */
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the section and name/value is found, else false.                              */
/* --------------------------------------------------------------------------------------------- */
bool _SSFINIIsNameValuePresent(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name,
                               uint8_t index, SSFINIContext_t *context)
{
    size_t sectionLen = 0;
    size_t nameLen;

    SSF_REQUIRE(ini != NULL);
    if (section != NULL)
    {
        sectionLen = strlen(section);
        SSF_REQUIRE(sectionLen > 0);
    }
    SSF_REQUIRE(name != NULL);
    nameLen = strlen(name);
    SSF_REQUIRE(nameLen > 0);
    SSF_REQUIRE(context != NULL);

    /* Init context */
    memset(context, 0, sizeof(SSFINIContext_t));

    /* Iterate over lines */
    while (_SSFINIFindNextLine(ini, context))
    {
        /* Found a section or name/value? */
        if (_SSFINIParseLine(context))
        {
            /* Yes, is match in global unnamed section? */
            if ((context->section == NULL) && (section == NULL) && (context->name != NULL) &&
                (nameLen == context->nameLen) && (memcmp(name, context->name, nameLen) == 0))
            {
                /* Yes, is correct index? */
                if (index == 0) { return true; }
                index--;
            }
            /* Is match in named section? */
            else if ((context->section != NULL) && (section != NULL) &&
                (context->sectionLen == sectionLen) &&
                (memcmp(section, context->section, sectionLen) == 0) &&
                (context->name != NULL) && (nameLen == context->nameLen) &&
                (memcmp(name, context->name, nameLen) == 0))
            {
                /* Yes, is correct index? */
                if (index == 0) { return true; }
                index--;
            }
        }
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the section is found, else false.                                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFINIIsSectionPresent(SSFCStrIn_t ini, SSFCStrIn_t section)
{
    SSFINIContext_t context;
    size_t sectionLen;

    SSF_REQUIRE(ini != NULL);
    if (section != NULL)
    {
        sectionLen = strlen(section);
        SSF_REQUIRE(sectionLen > 0);
    }
    /* Every INI has a global section */
    else return true;

    memset(&context, 0, sizeof(context));
    while (_SSFINIFindNextLine(ini, &context))
    {
        /* Parsing find something? */
        if (_SSFINIParseLine(&context))
        {
            /* Yes, section match? */
            if ((context.section != NULL) && (context.sectionLen == sectionLen) &&
                (memcmp(section, context.section, sectionLen) == 0))
            /* Yes, found section */
            { return true; }
        }
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the section with name field is found, else false.                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFINIIsNameValuePresent(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name,
                              uint8_t index)
{
    SSFINIContext_t context;

    SSF_REQUIRE(ini != NULL);
    SSF_REQUIRE(name != NULL);

    return _SSFINIIsNameValuePresent(ini, section, name, index, &context);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the string value of [section].name[index] is found/copied to out, else false. */
/* --------------------------------------------------------------------------------------------- */
bool SSFINIGetStrValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                       SSFCStrOut_t out, size_t outSize, size_t *outLen)
{
    SSFINIContext_t context;

    SSF_REQUIRE(ini != NULL);
    SSF_REQUIRE(name != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outSize >= 1);

    if (_SSFINIIsNameValuePresent(ini, section, name, index, &context) == false) return false;
    if (outLen != NULL) *outLen = context.valueLen;
    if (outSize < (context.valueLen + 1)) return false;
    memcpy(out, context.value, context.valueLen);
    out[context.valueLen] = 0;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if valid bool value of [section].name[index] is found/set to out, else false.    */
/* --------------------------------------------------------------------------------------------- */
bool SSFINIGetBoolValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                        bool *out)
{
    SSFINIContext_t context;
    char lcv[6] = "";
    char *lcvp = lcv;

    SSF_REQUIRE(ini != NULL);
    SSF_REQUIRE(name != NULL);
    SSF_REQUIRE(out != NULL);

    /* Find name/value? */
    if (_SSFINIIsNameValuePresent(ini, section, name, index, &context) == false) return false;

    /* Is value longer than a boolean should be? */
    if (context.valueLen > (sizeof(lcv) - 1)) return false;

    /* Convert value to lowercase */
    memcpy(lcv, context.value, context.valueLen);
    lcv[context.valueLen] = 0;
    while (*lcvp != 0) {
        *lcvp = (char) tolower((int)*lcvp); lcvp++;
    }

    /* Assume value matches a true string */
    *out = true;
    if (strcmp(lcv, "1") == 0) return true;
    if (strcmp(lcv, "yes") == 0) return true;
    if (strcmp(lcv, "true") == 0) return true;
    if (strcmp(lcv, "on") == 0) return true;

    /* Assume value matches a false string */
    *out = false;
    if (strcmp(lcv, "0") == 0) return true;
    if (strcmp(lcv, "no") == 0) return true;
    if (strcmp(lcv, "false") == 0) return true;
    if (strcmp(lcv, "off") == 0) return true;

    /* Was not a valid boolean string */
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if valid long int value in [section].name[index] found/set to out, else false.   */
/* --------------------------------------------------------------------------------------------- */
bool SSFINIGetLongValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                        long int *out)
{
    SSFINIContext_t context;
    char li[32];
    char *endPtr;

    SSF_REQUIRE(ini != NULL);
    SSF_REQUIRE(name != NULL);
    SSF_REQUIRE(out != NULL);

    /* Is name/value found? */
    if (_SSFINIIsNameValuePresent(ini, section, name, index, &context) == false) return false;

    /* Does value length make sense for a long integer? */
    if (context.valueLen == 0) return false;
    if (context.valueLen > (sizeof(li) - 1)) return false;

    /* Try to convert value to long int */
    memcpy(li, context.value, context.valueLen);
    li[context.valueLen] = 0;
    *out = strtol(&li[0], &endPtr, 10);

    /* Did we successfully convert value to a long int? */
    if (endPtr != &li[context.valueLen]) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if comment added to ini, else false. Can be used to add comment strings to INI.  */
/* --------------------------------------------------------------------------------------------- */
bool SSFINIPrintComment(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t text,
                        SSFINIComment_t commentType, SSFINILineEnd_t lineEnding)
{
    size_t textLen;
    size_t newLen = 0;
    size_t remainingLen = 0;

    SSF_REQUIRE(ini != NULL);
    SSF_REQUIRE(iniSize > 0);
    SSF_REQUIRE(iniLen != NULL);
    SSF_REQUIRE(text != NULL);
    SSF_REQUIRE((commentType > SSF_INI_COMMENT_MIN) && (commentType < SSF_INI_COMMENT_MAX));
    SSF_REQUIRE((lineEnding > SSF_INI_LINE_ENDING_MIN) && (lineEnding < SSF_INI_LINE_ENDING_MAX));

    /* Is there any room in ini to add antything else? */
    if ((iniSize - 1) <= *iniLen) return false;

    /* Determine how much can still be added */
    remainingLen = (iniSize - 1) - *iniLen;

    /* Determine how much is to be added to ini */
    textLen = strlen(text);
    newLen += textLen;
    if (commentType != SSF_INI_COMMENT_NONE) newLen += 1;
    if (lineEnding == SSF_INI_LF) newLen += 1;
    else newLen += 2;

    /* Is there room to add requested comment? */
    if (remainingLen < newLen) return false;

    /* Copy comment char to ini */
    if (commentType == SSF_INI_COMMENT_SEMI) { ini[*iniLen] = ';';  }
    else if (commentType == SSF_INI_COMMENT_HASH) { ini[*iniLen] = '#'; }
    if (commentType != SSF_INI_COMMENT_NONE) *iniLen += 1;

    /* Copy text to ini */
    memcpy(&ini[*iniLen], text, textLen);
    *iniLen += textLen;

    /* Add line ending */
    if (lineEnding == SSF_INI_CRLF) { ini[*iniLen] = '\r'; *iniLen += 1; }
    ini[*iniLen] = '\n'; *iniLen += 1; ini[*iniLen] = 0;
    
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if section added to ini, else false.                                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFINIPrintSection(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t section,
                        SSFINILineEnd_t lineEnding)
{
    size_t sectionLen;
    size_t newLen = 0;
    size_t remainingLen = 0;

    SSF_REQUIRE(ini != NULL);
    SSF_REQUIRE(iniSize > 0);
    SSF_REQUIRE(iniLen != NULL);
    SSF_REQUIRE(section != NULL);
    sectionLen = strlen(section);
    SSF_REQUIRE(sectionLen > 0);
    SSF_REQUIRE((lineEnding > SSF_INI_LINE_ENDING_MIN) && (lineEnding < SSF_INI_LINE_ENDING_MAX));

    /* Is there any room in ini to add anything else? */
    if ((iniSize - 1) <= *iniLen) return false;

    /* Determine how much can still be added */
    remainingLen = (iniSize - 1) - *iniLen;

    /* Determine how much is to be added to ini */
    newLen += sectionLen + 2;
    if (lineEnding == SSF_INI_LF) newLen += 1;
    else newLen += 2;

    /* Is there room to add requested comment? */
    if (remainingLen < newLen) return false;

    /* Add section */
    ini[*iniLen] = '[';
    *iniLen += 1;
    memcpy(&ini[*iniLen], section, sectionLen);
    *iniLen += sectionLen;
    ini[*iniLen] = ']';
    *iniLen += 1;

    /* Add line ending */
    if (lineEnding == SSF_INI_CRLF) { ini[*iniLen] = '\r'; *iniLen += 1; }
    ini[*iniLen] = '\n'; *iniLen += 1; ini[*iniLen] = 0;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if name/string value added to ini, else false.                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFINIPrintNameStrValue(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t name,
                             SSFCStrIn_t value, SSFINILineEnd_t lineEnding)
{
    size_t nameLen;
    size_t newLen = 0;
    size_t valueLen = 0;
    size_t remainingLen = 0;

    SSF_REQUIRE(ini != NULL);
    SSF_REQUIRE(iniSize > 0);
    SSF_REQUIRE(iniLen != NULL);
    SSF_REQUIRE(name != NULL);
    nameLen = strlen(name);
    SSF_REQUIRE(nameLen > 0);
    SSF_REQUIRE(value != NULL);
    SSF_REQUIRE((lineEnding > SSF_INI_LINE_ENDING_MIN) && (lineEnding < SSF_INI_LINE_ENDING_MAX));

    /* Is there any room in ini to add antything else? */
    if ((iniSize - 1) <= *iniLen) return false;

    /* Determine how much can still be added */
    remainingLen = (iniSize - 1) - *iniLen;

    /* Determine how much is to be added to ini */
    valueLen = strlen(value);
    newLen += nameLen + valueLen + 1;
    if (lineEnding == SSF_INI_LF) newLen += 1;
    else newLen += 2;

    /* Is there enough room? */
    if (remainingLen < newLen) return false;

    /* Add name and value */
    memcpy(&ini[*iniLen], name, nameLen);
    *iniLen += nameLen;
    ini[*iniLen] = '=';
    *iniLen += 1;
    memcpy(&ini[*iniLen], value, valueLen);
    *iniLen += valueLen;

    /* Add line ending */
    if (lineEnding == SSF_INI_CRLF) { ini[*iniLen] = '\r'; *iniLen += 1; }
    ini[*iniLen] = '\n'; *iniLen += 1; ini[*iniLen] = 0;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if name/bool value added to ini, else false.                                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFINIPrintNameBoolValue(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t name,
                              bool value, SSFINIBool_t boolType, SSFINILineEnd_t lineEnding)
{
    char *bstr = NULL;
    SSF_REQUIRE((boolType > SSF_INI_BOOL_MIN) && (boolType < SSF_INI_BOOL_MAX));
    
    /* Convert boolean value to requested string type */
    switch (boolType)
    {
    case SSF_INI_BOOL_1_0:
        if (value) bstr = "1";
        else bstr = "0";
        break;
    case SSF_INI_BOOL_YES_NO:
        if (value) bstr = "yes";
        else bstr = "no";
        break;
    case SSF_INI_BOOL_ON_OFF:
        if (value) bstr = "on";
        else bstr = "off";
        break;
    case SSF_INI_BOOL_TRUE_FALSE:
        if (value) bstr = "true";
        else bstr = "false";
        break;
    default:
        SSF_ERROR();
    }
    return SSFINIPrintNameStrValue(ini, iniSize, iniLen, name, bstr, lineEnding);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if name/long int value added to ini, else false.                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFINIPrintNameLongValue(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t name,
                              long int value, SSFINILineEnd_t lineEnding)
{
    char nstr[32];
    int len;

    len = snprintf(nstr, sizeof(nstr), "%ld", value);
    if (len < 0) return false;
    if (len >= ((int)sizeof(nstr))) return false;
    return SSFINIPrintNameStrValue(ini, iniSize, iniLen, name, nstr, lineEnding);
}

