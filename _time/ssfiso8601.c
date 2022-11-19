/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfiso8601.c                                                                                  */
/* Provides ISO8601 extended time string parser/generator interface.                             */
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

/* --------------------------------------------------------------------------------------------- */
/* Design and Limitations of ssfiso8601 Interface                                                */
/*                                                                                               */
/* Supported date range: 1970-01-01T00:00:00.000000000Z - 2199-12-31T23:59:59.999999999Z         */
/* Unix time is measured in system ticks (unixSys is seconds is scaled by SSF_TICKS_PER_SEC)     */
/* Unix time is always UTC (Z) time zone.                                                        */
/* Inputs are strictly checked to ensure they represent valid calendar dates.                    */
/*                                                                                               */
/* Only ISO8601 extended format is supported, and only with the following ordered fields:        */
/*   Required Date & Time Field:      YYYY-MM-DDTHH:MM:SS                                        */
/*   Optional Second Precision Field:                    .FFF                                    */
/*                                                       .FFFFFF                                 */
/*                                                       .FFFFFFFFF                              */
/*   Optional Time Zone Field :                                    Z                             */
/*                                                                 +HH                           */
/*                                                                 -HH                           */
/*                                                                 +HH:MM                        */
/*                                                                 -HH:MM                        */
/*                                                                 (no TZ field == local time)   */
/*                                                                                               */
/* The Date and Time field is always in local time, subtracting offset yields UTC time.          */
/* The default fractional second precision is determined by SSF_TICKS_PER_SEC.                   */
/* Fractional seconds may be optionally added when generating an ISO string.                     */
/* 3 digits of pseudo-fractional seconds precision may be added when generating an ISO string.   */
/* Daylight savings is handled by application code adjusting the zoneOffsetMin input as needed.  */
/*                                                                                               */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "ssfport.h"
#include "ssfdtime.h"
#include "ssfiso8601.h"

/* --------------------------------------------------------------------------------------------- */
/* Converts from unixSys to ISO time.                                                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFISO8601UnixToISO(SSFPortTick_t unixSys, bool secPrecision, bool secPseudoPrecision,
                         uint16_t pseudoSecs, SSFISO8601Zone_t zone, int16_t zoneOffsetMin,
                         SSFCStrOut_t outStr, size_t outStrSize)
{
    SSFDTimeStruct_t ts;
    size_t offset = 0;
    char offsetSign = '+';
    int64_t zoneOffsetSys;
    int64_t sunix;
    uint16_t zoneOffsetMinAbs;

    SSF_REQUIRE(outStr != NULL);
#if SSF_DTIME_SYS_PREC == 9
    if (secPrecision) { SSF_REQUIRE((secPseudoPrecision == false) && (pseudoSecs == 0)); }
#else
    SSF_REQUIRE(((secPseudoPrecision == false) && (pseudoSecs == 0)) ||
                ((secPseudoPrecision) && (pseudoSecs < 1000ul)));
#endif
    SSF_REQUIRE((zone > SSF_ISO8601_ZONE_MIN) && (zone < SSF_ISO8601_ZONE_MAX));
    SSF_REQUIRE((zoneOffsetMin > (-((int32_t)SSFDTIME_MIN_IN_DAY))) &&
                (zoneOffsetMin < ((int16_t) SSFDTIME_MIN_IN_DAY)));
    SSF_REQUIRE(outStrSize >= SSFISO8601_MAX_SIZE);

    /* Copy default ISO string to user buffer */
    SSF_ASSERT(outStrSize >= sizeof(SSF_ISO8601_ERR_STR));
    memcpy(outStr, SSF_ISO8601_ERR_STR, sizeof(SSF_ISO8601_ERR_STR));

    /* Need to adjust Unix to local time? */
    if ((zone == SSF_ISO8601_ZONE_LOCAL) || (zone == SSF_ISO8601_ZONE_OFFSET_HH) ||
        (zone == SSF_ISO8601_ZONE_OFFSET_HHMM))
    {
        /* Yes, adjust unix to local time before struct conversion */
        sunix = (int64_t)unixSys;
        zoneOffsetSys = zoneOffsetMin * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC;

        /* Adjust local time within allowed system date limits */
        if (((zoneOffsetSys < 0) &&
             ((sunix + zoneOffsetSys) < ((int64_t)SSFDTIME_UNIX_EPOCH_SYS_MIN))) ||
            ((zoneOffsetSys >= 0) &&
             ((sunix + zoneOffsetSys) > ((int64_t)SSFDTIME_UNIX_EPOCH_SYS_MAX))))
        { return false; }
        unixSys = (uint64_t)(((int64_t)unixSys) + zoneOffsetSys);
        zoneOffsetMinAbs = abs(zoneOffsetMin);
    }

    if (SSFDTimeUnixToStruct(unixSys, &ts, sizeof(ts)) == false) { return false; }

    offset = snprintf(outStr, outStrSize, "%04d-%02d-%02dT%02d:%02d:%02d",
                      (int)(ts.year + SSFDTIME_EPOCH_YEAR), ts.month + 1, ts.day + 1, ts.hour,
                      ts.min, ts.sec);

    /* Request to add system sec precision? */
    if (secPrecision)
    {
#if SSF_DTIME_SYS_PREC == 3
        offset += snprintf(&outStr[offset], outStrSize - offset, ".%03d", ts.fsec);
#elif SSF_DTIME_SYS_PREC == 6
        offset += snprintf(&outStr[offset], outStrSize - offset, ".%06d", ts.fsec);
#elif SSF_DTIME_SYS_PREC == 9
        offset += snprintf(&outStr[offset], outStrSize - offset, ".%09d", ts.fsec);
#endif
    }

    /* Request to add pseudo sec precision? */
    if (secPseudoPrecision)
    {
        offset += snprintf(&outStr[offset], outStrSize - offset, "%03d", pseudoSecs);
    }

    /* Is compact zone offset requested and possible? */
    if ((zone == SSF_ISO8601_ZONE_OFFSET_HH) && ((zoneOffsetMinAbs % SSFDTIME_MIN_IN_HOUR) != 0))
    /* No, must print full zone offset */
    { zone = SSF_ISO8601_ZONE_OFFSET_HHMM; }

    switch(zone)
    {
        case SSF_ISO8601_ZONE_UTC:
            offset += snprintf(&outStr[offset], outStrSize - offset, "Z");
        break;
        case SSF_ISO8601_ZONE_OFFSET_HH:
            if (zoneOffsetMin < 0) { offsetSign = '-'; }
            offset += snprintf(&outStr[offset], outStrSize - offset, "%c%02d", offsetSign,
                               zoneOffsetMinAbs / SSFDTIME_MIN_IN_HOUR);
        break;
        case SSF_ISO8601_ZONE_OFFSET_HHMM:
            if (zoneOffsetMin < 0) { offsetSign = '-'; }
            offset += snprintf(&outStr[offset], outStrSize - offset, "%c%02d:%02d", offsetSign,
                               zoneOffsetMinAbs / SSFDTIME_MIN_IN_HOUR,
                               zoneOffsetMinAbs % SSFDTIME_MIN_IN_HOUR);
        break;
        default:
        break;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Performs conversion from ISO to unixSys time.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFISO8601ISOToUnix(SSFCStrIn_t inStr, SSFPortTick_t *unixSys, int16_t *zoneOffsetMin)
{
    #define YEAR_INDEX (0u)
    #define MONTH_INDEX (5u)
    #define DAY_INDEX (8u)
    #define HOUR_INDEX (11u)
    #define MIN_INDEX (14u)
    #define SEC_INDEX (17u)
    #define FSEC_INDEX (20u)

    const uint32_t _fsecScale[6] = { 10ul, 100ul, 1000ul, 10000ul, 100000ul, 1000000ul };

    SSFDTimeStruct_t ts;
    size_t index;
    size_t numDigs = 0;

    SSF_REQUIRE(inStr != NULL);
    SSF_REQUIRE(unixSys != NULL);
    SSF_REQUIRE(zoneOffsetMin != NULL);

    /* Check that string has min length */
    if (strlen(inStr) < (SSFISO8601_MIN_SIZE - 1)) return false;

    /* Parse year */
    if ((SSFIsDigit(inStr[YEAR_INDEX]) == false) ||
        (SSFIsDigit(inStr[YEAR_INDEX + 1]) == false) ||
        (SSFIsDigit(inStr[YEAR_INDEX + 2]) == false) ||
        (SSFIsDigit(inStr[YEAR_INDEX + 3]) == false) ||
        (inStr[YEAR_INDEX + 4] != '-'))
    { return false; }
    ts.year = (uint16_t)strtoul(inStr, NULL, 10) - SSFDTIME_EPOCH_YEAR;

    /* Parse month */
    if ((SSFIsDigit(inStr[MONTH_INDEX]) == false) ||
        (SSFIsDigit(inStr[MONTH_INDEX + 1]) == false) ||
        (inStr[MONTH_INDEX + 2] != '-'))
    { return false; }
    ts.month = ((uint16_t)strtoul(&inStr[MONTH_INDEX], NULL, 10)) - 1u;

    /* Parse day */
    if ((SSFIsDigit(inStr[DAY_INDEX]) == false) ||
        (SSFIsDigit(inStr[DAY_INDEX + 1]) == false) ||
        (inStr[DAY_INDEX + 2] != 'T'))
    { return false; }
    ts.day = ((uint16_t)strtoul(&inStr[DAY_INDEX], NULL, 10)) - 1u;

    /* Parse hour */
    if ((SSFIsDigit(inStr[HOUR_INDEX]) == false) ||
        (SSFIsDigit(inStr[HOUR_INDEX + 1]) == false) ||
        (inStr[HOUR_INDEX + 2] != ':'))
    { return false; }
    ts.hour = ((uint16_t)strtoul(&inStr[HOUR_INDEX], NULL, 10));

    /* Parse minute */
    if ((SSFIsDigit(inStr[MIN_INDEX]) == false) ||
        (SSFIsDigit(inStr[MIN_INDEX + 1]) == false) ||
        (inStr[MIN_INDEX + 2] != ':'))
    { return false; }
    ts.min = ((uint16_t)strtoul(&inStr[MIN_INDEX], NULL, 10));

    /* Parse second */
    if ((SSFIsDigit(inStr[SEC_INDEX]) == false) ||
        (SSFIsDigit(inStr[SEC_INDEX + 1]) == false) ||
        ((inStr[SEC_INDEX + 2] != 0) && (inStr[SEC_INDEX + 2] != '.') &&
         (inStr[SEC_INDEX + 2] != '-') && (inStr[SEC_INDEX + 2] != '+') &&
         (inStr[SEC_INDEX + 2] != 'Z')))
    { return false; }
    ts.sec = ((uint16_t)strtoul(&inStr[SEC_INDEX], NULL, 10));

    /* Remaining fields are optional, try to parse them */
    index = SEC_INDEX + 2;

    /* Fractional seconds? */
    if (inStr[index] == '.')
    {
        while (numDigs <= 9)
        {
            index++;
            if (SSFIsDigit(inStr[index])) numDigs++;
            else break;
        }
        if ((numDigs == 0) || (numDigs > 9)) return false;
        if ((inStr[index] != 0) && (inStr[index] != '-') && (inStr[index] != '+'))
        { return false; }
#if SSF_ISO8601_ALLOW_FSEC_TRUNC == 0
        if (numDigs > SSF_DTIME_SYS_PREC) return false;
#endif
        ts.fsec = ((uint32_t)strtoul(&inStr[FSEC_INDEX], NULL, 10));
        if (numDigs < SSF_DTIME_SYS_PREC)
        {
            SSF_ASSERT((SSF_DTIME_SYS_PREC - numDigs - 1) <
                       (sizeof(_fsecScale)/(sizeof(uint32_t))));
            ts.fsec *= _fsecScale[SSF_DTIME_SYS_PREC - numDigs - 1];
        }
        else if (numDigs > SSF_DTIME_SYS_PREC)
        {
            SSF_ASSERT((numDigs - SSF_DTIME_SYS_PREC - 1) <
                       (sizeof(_fsecScale)/(sizeof(uint32_t))));
            ts.fsec /= _fsecScale[numDigs - SSF_DTIME_SYS_PREC - 1];
        }
    }
    else { ts.fsec = 0; }

    /* Zone field? */
    if (inStr[index] == 'Z')
    {
        (*zoneOffsetMin) = 0;
        index++;
    }
    else if ((inStr[index] == '-') || (inStr[index] == '+'))
    {
        bool isSigned = (inStr[index] == '-');
        uint8_t hour;
        uint8_t min = 0;

        /* Parse hour offset */
        index++;
        if ((SSFIsDigit(inStr[index]) == false) ||
            (SSFIsDigit(inStr[index + 1]) == false) ||
            ((inStr[index + 2] != ':') && (inStr[index + 2] != 0)))
        { return false; }
        hour = ((uint8_t)strtoul(&inStr[index], NULL, 10));

        /* Parse min offset */
        index += 2;
        if (inStr[index] == ':')
        {
            index++;
            if ((SSFIsDigit(inStr[index]) == false) ||
                (SSFIsDigit(inStr[index + 1]) == false) ||
                (inStr[index + 2] != 0))
            { return false; }
            min = ((uint8_t)strtoul(&inStr[index], NULL, 10));
            index += 2;
        }

        (*zoneOffsetMin) = (hour * SSFDTIME_MIN_IN_HOUR) + min;
        if (isSigned) { (*zoneOffsetMin) = -(*zoneOffsetMin); }
    }
    /* ISO string in in local time, not possible to compute unixSys time */
    else
    {
#if SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX == 1
        (*zoneOffsetMin) = SSFISO8601_INVALID_ZONE_OFFSET;
#else
        return false;
#endif
    }

    /* Must be at end of ISO string */
    if (inStr[index] != 0) return false;

    /* Init a time struct and convert to unixSys time */
    if (SSFDTimeStructInit(&ts, ts.year, ts.month, ts.day, ts.hour, ts.min, ts.sec,
                           ts.fsec) == false)
    { return false; }
    if (SSFDTimeStructToUnix(&ts, unixSys) == false) { return false; }

    return true;
}
