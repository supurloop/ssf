/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfiso8601_ut.c                                                                               */
/* Unit tests ISO8601 extended time string parser/generator interface.                           */
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
#include <time.h>
#include "ssfport.h"
#include "ssfdtime.h"
#include "ssfiso8601.h"

#if SSF_ISO8601_EXHAUSTIVE_UNIT_TEST == 1
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
#ifndef _WIN32
#include <pthread.h>
#include <unistd.h>
#endif /* _WIN32 */
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
#endif /* SSF_ISO8601_EXHAUSTIVE_UNIT_TEST */

/* Number of fractional second widths tested, 1 to 9 digits */
#define SSF_ISO8601_UT_NUM_FRAC_WIDTHS (9u)

#if SSF_ISO8601_EXHAUSTIVE_UNIT_TEST == 0
/* Widest fraction value count swept fully by the reduced test */
#define SSF_ISO8601_UT_FRAC_FULL_MAX (10000000ul)
/* Prime stride used to sample fraction widths too large to sweep fully */
#define SSF_ISO8601_UT_FRAC_STRIDE (997ul)
#endif /* SSF_ISO8601_EXHAUSTIVE_UNIT_TEST */

/* Count of distinct fraction values for each fraction width */
static const uint32_t _ssfISO8601UTFracLim[SSF_ISO8601_UT_NUM_FRAC_WIDTHS] =
{
    10ul, 100ul, 1000ul, 10000ul, 100000ul, 1000000ul, 10000000ul, 100000000ul, 1000000000ul
};

#if SSF_ISO8601_EXHAUSTIVE_UNIT_TEST == 1
/* Upper bound on worker threads used by the exhaustive test */
#define SSF_ISO8601_UT_MAX_THREADS (64u)

typedef enum
{
    SSF_ISO8601_UT_WORK_MIN = -1,
    SSF_ISO8601_UT_WORK_FRAC,
    SSF_ISO8601_UT_WORK_SEC,
    SSF_ISO8601_UT_WORK_MAX
} SSFISO8601UTWork_t;

typedef struct
{
    SSFISO8601UTWork_t work;
    uint32_t numDigsIdx;
    uint64_t start;
    uint64_t end;
} SSFISO8601UTSlice_t;
#endif /* SSF_ISO8601_EXHAUSTIVE_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Checks that a numDigsIdx + 1 digit fraction string parses to the expected unixSys.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFISO8601UTFracCheck(uint32_t numDigsIdx, uint32_t frac)
{
    SSFPortTick_t unixSys;
    int16_t zoneOffsetMin;
    char isoStr[SSFISO8601_MAX_SIZE];

    SSF_REQUIRE(numDigsIdx < SSF_ISO8601_UT_NUM_FRAC_WIDTHS);
    SSF_REQUIRE(frac < _ssfISO8601UTFracLim[numDigsIdx]);

    unixSys = SSFDTIME_UNIX_EPOCH_SYS_MAX + 1;
    zoneOffsetMin = SSFISO8601_INVALID_ZONE_OFFSET + 10;
    switch(numDigsIdx)
    {
        case 0:
            snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%01luZ",
                     (unsigned long)frac);
        break;
        case 1:
            snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%02luZ",
                     (unsigned long)frac);
        break;
        case 2:
            snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%03luZ",
                     (unsigned long)frac);
        break;
        case 3:
            snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%04luZ",
                     (unsigned long)frac);
        break;
        case 4:
            snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%05luZ",
                     (unsigned long)frac);
        break;
        case 5:
            snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%06luZ",
                     (unsigned long)frac);
        break;
        case 6:
            snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%07luZ",
                     (unsigned long)frac);
        break;
        case 7:
            snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%08luZ",
                     (unsigned long)frac);
        break;
        case 8:
            snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%09luZ",
                     (unsigned long)frac);
        break;
        default:
        SSF_ERROR();
    }
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSys, &zoneOffsetMin));

    switch(numDigsIdx)
    {
        case 0:
            SSF_ASSERT(unixSys == ((SSFPortTick_t)frac * (SSF_TICKS_PER_SEC / 10ul)));
        break;
        case 1:
            SSF_ASSERT(unixSys == ((SSFPortTick_t)frac * (SSF_TICKS_PER_SEC / 100ul)));
        break;
        case 2:
            SSF_ASSERT(unixSys == ((SSFPortTick_t)frac * (SSF_TICKS_PER_SEC / 1000ul)));
        break;
        case 3:
#if SSF_DTIME_SYS_PREC == 3
            SSF_ASSERT(unixSys == (frac / 10ul));
#else
            SSF_ASSERT(unixSys == ((SSFPortTick_t)frac * (SSF_TICKS_PER_SEC / 10000ul)));
#endif
        break;
        case 4:
#if SSF_DTIME_SYS_PREC == 3
            SSF_ASSERT(unixSys == (frac / 100ul));
#else
SSF_ASSERT(unixSys == ((SSFPortTick_t)frac * (SSF_TICKS_PER_SEC / 100000ul)));
#endif
break;
        case 5:
#if SSF_DTIME_SYS_PREC == 3
            SSF_ASSERT(unixSys == (frac / 1000ul));
#else
SSF_ASSERT(unixSys == ((SSFPortTick_t)frac * (SSF_TICKS_PER_SEC / 1000000ul)));
#endif
break;
        case 6:
#if SSF_DTIME_SYS_PREC == 3
            SSF_ASSERT(unixSys == (frac / 10000ul));
#elif SSF_DTIME_SYS_PREC == 6
            SSF_ASSERT(unixSys == (frac / 10ul));
#else
SSF_ASSERT(unixSys == ((SSFPortTick_t)frac * (SSF_TICKS_PER_SEC / 10000000ul)));
#endif
break;
        case 7:
#if SSF_DTIME_SYS_PREC == 3
            SSF_ASSERT(unixSys == (frac / 100000ul));
#elif SSF_DTIME_SYS_PREC == 6
            SSF_ASSERT(unixSys == (frac / 100ul));
#else
SSF_ASSERT(unixSys == ((SSFPortTick_t)frac * (SSF_TICKS_PER_SEC / 100000000ul)));
#endif
break;
        case 8:
#if SSF_DTIME_SYS_PREC == 3
            SSF_ASSERT(unixSys == (frac / 1000000ul));
#elif SSF_DTIME_SYS_PREC == 6
            SSF_ASSERT(unixSys == (frac / 1000ul));
#else
SSF_ASSERT(unixSys == ((SSFPortTick_t)frac * (SSF_TICKS_PER_SEC / 1000000000ul)));
#endif
break;
        default:
        SSF_ERROR();
    }
    SSF_ASSERT(zoneOffsetMin == 0);
}

#if SSF_ISO8601_EXHAUSTIVE_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Checks unixSec round trips through every zone format the exhaustive test covers.              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFISO8601UTSecCheck(uint64_t unixSec)
{
    SSFPortTick_t unixSys;
    SSFPortTick_t unixSysOut;
    int16_t zoneOffsetMin;
    uint16_t hour;
    uint16_t minute;
    uint32_t i;
    int8_t sign;
    char isoStr[SSFISO8601_MAX_SIZE];

    SSF_REQUIRE(unixSec <= SSFDTIME_UNIX_EPOCH_SEC_MAX);

    unixSys = (SSFPortTick_t)unixSec * SSF_TICKS_PER_SEC;
    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                   sizeof(isoStr)));
    SSF_ASSERT(SSFIsDigit(isoStr[0]));
    SSF_ASSERT(SSFIsDigit(isoStr[1]));
    SSF_ASSERT(SSFIsDigit(isoStr[2]));
    SSF_ASSERT(SSFIsDigit(isoStr[3]));
    SSF_ASSERT(isoStr[4] == '-');
    SSF_ASSERT(SSFIsDigit(isoStr[5]));
    SSF_ASSERT(SSFIsDigit(isoStr[6]));
    SSF_ASSERT(isoStr[7] == '-');
    SSF_ASSERT(SSFIsDigit(isoStr[8]));
    SSF_ASSERT(SSFIsDigit(isoStr[9]));
    SSF_ASSERT(isoStr[10] == 'T');
    SSF_ASSERT(SSFIsDigit(isoStr[11]));
    SSF_ASSERT(SSFIsDigit(isoStr[12]));
    SSF_ASSERT(isoStr[13] == ':');
    SSF_ASSERT(SSFIsDigit(isoStr[14]));
    SSF_ASSERT(SSFIsDigit(isoStr[15]));
    SSF_ASSERT(isoStr[16] == ':');
    SSF_ASSERT(SSFIsDigit(isoStr[17]));
    SSF_ASSERT(SSFIsDigit(isoStr[18]));
    SSF_ASSERT(isoStr[19] == 'Z');
    SSF_ASSERT(isoStr[20] == 0);
    unixSysOut = SSFDTIME_UNIX_EPOCH_SYS_MAX + 1;
    zoneOffsetMin = SSFDTIME_MIN_IN_DAY + 2;
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(unixSys == unixSysOut);
    SSF_ASSERT(zoneOffsetMin == 0);

    for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
    {
        if (hour == 2) hour = SSF_TS_HOUR_MAX - 1;
        for (i = 0; i < 2; i++)
        {
            if (i == 0) sign = 1;
            else sign = -1;
            if (((sign == -1) && (unixSys < ((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR *
                                             SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC))) ||
                ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) < ((SSFPortTick_t)hour *
                                 SSFDTIME_MIN_IN_HOUR * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC)))
            {
                /* Offset not in valid date range */
                SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                               SSF_ISO8601_ZONE_OFFSET_HH, hour *
                                               SSFDTIME_MIN_IN_HOUR * sign, isoStr,
                                               sizeof(isoStr)) == false);
            }
            else
            {
                SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                               SSF_ISO8601_ZONE_OFFSET_HH, hour *
                                               SSFDTIME_MIN_IN_HOUR * sign, isoStr,
                                               sizeof(isoStr)));
                SSF_ASSERT(SSFIsDigit(isoStr[0]));
                SSF_ASSERT(SSFIsDigit(isoStr[1]));
                SSF_ASSERT(SSFIsDigit(isoStr[2]));
                SSF_ASSERT(SSFIsDigit(isoStr[3]));
                SSF_ASSERT(isoStr[4] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[5]));
                SSF_ASSERT(SSFIsDigit(isoStr[6]));
                SSF_ASSERT(isoStr[7] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[8]));
                SSF_ASSERT(SSFIsDigit(isoStr[9]));
                SSF_ASSERT(isoStr[10] == 'T');
                SSF_ASSERT(SSFIsDigit(isoStr[11]));
                SSF_ASSERT(SSFIsDigit(isoStr[12]));
                SSF_ASSERT(isoStr[13] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[14]));
                SSF_ASSERT(SSFIsDigit(isoStr[15]));
                SSF_ASSERT(isoStr[16] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[17]));
                SSF_ASSERT(SSFIsDigit(isoStr[18]));
                if ((sign == 1) || (hour == 0)) SSF_ASSERT(isoStr[19] == '+');
                else SSF_ASSERT(isoStr[19] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[20]));
                SSF_ASSERT(SSFIsDigit(isoStr[21]));
                SSF_ASSERT(isoStr[22] == 0);
                unixSysOut = SSFDTIME_UNIX_EPOCH_SYS_MAX + 1;
                zoneOffsetMin = SSFDTIME_MIN_IN_DAY + 2;
                SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
                SSF_ASSERT(unixSys == unixSysOut);
                SSF_ASSERT(zoneOffsetMin == (int16_t)((hour * SSFDTIME_MIN_IN_HOUR) * sign));
            }
        }
    }

    for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
    {
        if (hour == 2) hour = SSF_TS_HOUR_MAX - 1;
        for (minute = 0; minute <= SSF_TS_MIN_MAX; minute += SSF_TS_MIN_MAX)
        {
            for (i = 0; i < 2; i++)
            {
                if (i == 0) sign = 1;
                else sign = -1;
                if (((sign == -1) && (unixSys < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) +
                                                 minute) * SSFDTIME_SEC_IN_MIN) *
                                                 SSF_TICKS_PER_SEC))) ||
                    ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) <
                                    (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                    SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC)))
                {
                    /* Offset not in valid date range */
                    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                                   SSF_ISO8601_ZONE_OFFSET_HHMM,
                                                   ((hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                                   sign, isoStr, sizeof(isoStr)) == false);
                }
                else
                {
                    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                                   SSF_ISO8601_ZONE_OFFSET_HHMM,
                                                   ((hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                                   sign, isoStr, sizeof(isoStr)));
                    SSF_ASSERT(SSFIsDigit(isoStr[0]));
                    SSF_ASSERT(SSFIsDigit(isoStr[1]));
                    SSF_ASSERT(SSFIsDigit(isoStr[2]));
                    SSF_ASSERT(SSFIsDigit(isoStr[3]));
                    SSF_ASSERT(isoStr[4] == '-');
                    SSF_ASSERT(SSFIsDigit(isoStr[5]));
                    SSF_ASSERT(SSFIsDigit(isoStr[6]));
                    SSF_ASSERT(isoStr[7] == '-');
                    SSF_ASSERT(SSFIsDigit(isoStr[8]));
                    SSF_ASSERT(SSFIsDigit(isoStr[9]));
                    SSF_ASSERT(isoStr[10] == 'T');
                    SSF_ASSERT(SSFIsDigit(isoStr[11]));
                    SSF_ASSERT(SSFIsDigit(isoStr[12]));
                    SSF_ASSERT(isoStr[13] == ':');
                    SSF_ASSERT(SSFIsDigit(isoStr[14]));
                    SSF_ASSERT(SSFIsDigit(isoStr[15]));
                    SSF_ASSERT(isoStr[16] == ':');
                    SSF_ASSERT(SSFIsDigit(isoStr[17]));
                    SSF_ASSERT(SSFIsDigit(isoStr[18]));
                    if ((sign == 1) || ((hour == 0) && (minute == 0)))
                    { SSF_ASSERT(isoStr[19] == '+'); }
                    else SSF_ASSERT(isoStr[19] == '-');
                    SSF_ASSERT(SSFIsDigit(isoStr[20]));
                    SSF_ASSERT(SSFIsDigit(isoStr[21]));
                    SSF_ASSERT(isoStr[22] == ':');
                    SSF_ASSERT(SSFIsDigit(isoStr[23]));
                    SSF_ASSERT(SSFIsDigit(isoStr[24]));
                    SSF_ASSERT(isoStr[25] == 0);
                    unixSysOut = SSFDTIME_UNIX_EPOCH_SYS_MAX + 1;
                    zoneOffsetMin = SSFDTIME_MIN_IN_DAY + 2;
                    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
                    SSF_ASSERT(unixSys == unixSysOut);
                    SSF_ASSERT(zoneOffsetMin == (int16_t)(((hour * SSFDTIME_MIN_IN_HOUR) +
                                                          minute) * sign));
                }
            }
        }
    }
#if SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX == 1
    for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
    {
        if (hour == 2) hour = SSF_TS_HOUR_MAX - 1;
        for (minute = 0; minute <= SSF_TS_MIN_MAX; minute += SSF_TS_MIN_MAX)
        {
            for (i = 0; i < 2; i++)
            {
                if (i == 0) sign = 1;
                else sign = -1;
                if (((sign == -1) && (unixSys < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) +
                                                minute) * SSFDTIME_SEC_IN_MIN) *
                                                SSF_TICKS_PER_SEC))) ||
                    ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) <
                                    (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                    SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC)))
                {
                    /* Offset not in valid date range */
                    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                                   SSF_ISO8601_ZONE_OFFSET_HHMM,
                                                   ((hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                                   sign, isoStr, sizeof(isoStr)) == false);
                }
                else
                {
                    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                                   SSF_ISO8601_ZONE_LOCAL,
                                                   ((hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                                   sign, isoStr, sizeof(isoStr)));
                    SSF_ASSERT(SSFIsDigit(isoStr[0]));
                    SSF_ASSERT(SSFIsDigit(isoStr[1]));
                    SSF_ASSERT(SSFIsDigit(isoStr[2]));
                    SSF_ASSERT(SSFIsDigit(isoStr[3]));
                    SSF_ASSERT(isoStr[4] == '-');
                    SSF_ASSERT(SSFIsDigit(isoStr[5]));
                    SSF_ASSERT(SSFIsDigit(isoStr[6]));
                    SSF_ASSERT(isoStr[7] == '-');
                    SSF_ASSERT(SSFIsDigit(isoStr[8]));
                    SSF_ASSERT(SSFIsDigit(isoStr[9]));
                    SSF_ASSERT(isoStr[10] == 'T');
                    SSF_ASSERT(SSFIsDigit(isoStr[11]));
                    SSF_ASSERT(SSFIsDigit(isoStr[12]));
                    SSF_ASSERT(isoStr[13] == ':');
                    SSF_ASSERT(SSFIsDigit(isoStr[14]));
                    SSF_ASSERT(SSFIsDigit(isoStr[15]));
                    SSF_ASSERT(isoStr[16] == ':');
                    SSF_ASSERT(SSFIsDigit(isoStr[17]));
                    SSF_ASSERT(SSFIsDigit(isoStr[18]));
                    SSF_ASSERT(isoStr[19] == 0);
                    unixSysOut = SSFDTIME_UNIX_EPOCH_SYS_MAX + 1;
                    zoneOffsetMin = SSFDTIME_MIN_IN_DAY + 2;
                    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
                    unixSysOut -= ((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                  SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC) * sign;
                    SSF_ASSERT(unixSys == unixSysOut);
                    SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
                }
            }
        }
    }
#endif /* SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX */
}

/* --------------------------------------------------------------------------------------------- */
/* Runs every check in the slice's [start, end) range on the calling thread.                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFISO8601UTRunSlice(const SSFISO8601UTSlice_t *slice)
{
    uint64_t n;

    SSF_REQUIRE(slice != NULL);
    SSF_REQUIRE(slice->work > SSF_ISO8601_UT_WORK_MIN);
    SSF_REQUIRE(slice->work < SSF_ISO8601_UT_WORK_MAX);
    SSF_REQUIRE(slice->numDigsIdx < SSF_ISO8601_UT_NUM_FRAC_WIDTHS);
    SSF_REQUIRE(slice->start <= slice->end);

    /* Is the slice a fractional second sweep? */
    if (slice->work == SSF_ISO8601_UT_WORK_FRAC)
    {
        /* Yes, check each fraction value in the slice */
        SSF_REQUIRE(slice->end <= _ssfISO8601UTFracLim[slice->numDigsIdx]);
        for (n = slice->start; n < slice->end; n++)
        { _SSFISO8601UTFracCheck(slice->numDigsIdx, (uint32_t)n); }
    }
    else
    {
        /* No, check each unix second in the slice */
        SSF_REQUIRE(slice->end <= (SSFDTIME_UNIX_EPOCH_SEC_MAX + 1ull));
        for (n = slice->start; n < slice->end; n++) { _SSFISO8601UTSecCheck(n); }
    }
}

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
/* --------------------------------------------------------------------------------------------- */
/* Thread entry point that runs the slice passed in arg.                                         */
/* --------------------------------------------------------------------------------------------- */
#ifdef _WIN32
static DWORD WINAPI _SSFISO8601UTThread(LPVOID arg)
#else /* _WIN32 */
static void *_SSFISO8601UTThread(void *arg)
#endif /* _WIN32 */
{
    SSF_REQUIRE(arg != NULL);

    _SSFISO8601UTRunSlice((const SSFISO8601UTSlice_t *)arg);
#ifdef _WIN32
    return 0;
#else /* _WIN32 */
    return NULL;
#endif /* _WIN32 */
}
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

/* --------------------------------------------------------------------------------------------- */
/* Returns the online CPU count clamped to [1, SSF_ISO8601_UT_MAX_THREADS].                      */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFISO8601UTThreadCount(void)
{
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    uint64_t n;

    GetSystemInfo(&sysInfo);
    n = (uint64_t)sysInfo.dwNumberOfProcessors;
#else /* _WIN32 */
    long cpus;
    uint64_t n;

    cpus = sysconf(_SC_NPROCESSORS_ONLN);
    n = (cpus < 1) ? 1u : (uint64_t)cpus;
#endif /* _WIN32 */
    if (n < 1u) n = 1u;
    if (n > SSF_ISO8601_UT_MAX_THREADS) n = SSF_ISO8601_UT_MAX_THREADS;
    return (uint32_t)n;
#else /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
    return 1u;
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
}

/* --------------------------------------------------------------------------------------------- */
/* Splits [start, end) into one slice per CPU, runs them concurrently, and waits for all.        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFISO8601UTParallel(SSFISO8601UTWork_t work, uint32_t numDigsIdx, uint64_t start,
                                  uint64_t end)
{
    SSFISO8601UTSlice_t slices[SSF_ISO8601_UT_MAX_THREADS];
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
#ifdef _WIN32
    HANDLE threads[SSF_ISO8601_UT_MAX_THREADS];
#else /* _WIN32 */
    pthread_t threads[SSF_ISO8601_UT_MAX_THREADS];
#endif /* _WIN32 */
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
    uint32_t numSlices;
    uint32_t k;
    uint64_t span;

    SSF_REQUIRE(work > SSF_ISO8601_UT_WORK_MIN);
    SSF_REQUIRE(work < SSF_ISO8601_UT_WORK_MAX);
    SSF_REQUIRE(numDigsIdx < SSF_ISO8601_UT_NUM_FRAC_WIDTHS);
    SSF_REQUIRE(start < end);

    numSlices = _SSFISO8601UTThreadCount();
    if ((end - start) < numSlices) numSlices = (uint32_t)(end - start);
    span = (end - start) / numSlices;
    for (k = 0; k < numSlices; k++)
    {
        slices[k].work = work;
        slices[k].numDigsIdx = numDigsIdx;
        slices[k].start = start + (span * k);
        slices[k].end = (k == (numSlices - 1u)) ? end : (start + (span * (k + 1u)));
    }

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    for (k = 1; k < numSlices; k++)
    {
#ifdef _WIN32
        threads[k] = CreateThread(NULL, 0, _SSFISO8601UTThread, &slices[k], 0, NULL);
        SSF_ASSERT(threads[k] != NULL);
#else /* _WIN32 */
        SSF_ASSERT(pthread_create(&threads[k], NULL, _SSFISO8601UTThread, &slices[k]) == 0);
#endif /* _WIN32 */
    }
    _SSFISO8601UTRunSlice(&slices[0]);
    for (k = 1; k < numSlices; k++)
    {
#ifdef _WIN32
        SSF_ASSERT(WaitForSingleObject(threads[k], INFINITE) == WAIT_OBJECT_0);
        SSF_ASSERT(CloseHandle(threads[k]));
#else /* _WIN32 */
        SSF_ASSERT(pthread_join(threads[k], NULL) == 0);
#endif /* _WIN32 */
    }
#else /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
    for (k = 0; k < numSlices; k++) { _SSFISO8601UTRunSlice(&slices[k]); }
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */
}
#endif /* SSF_ISO8601_EXHAUSTIVE_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Unit tests the ssfiso8601 interface.                                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFISO8601UnitTest(void)
{
    SSFPortTick_t unixSys, unixSysOut;
    int16_t zoneOffsetMin;
    uint16_t hour;
    uint16_t minute;
    uint32_t i;
    uint32_t ii;
    uint32_t j;
    uint32_t jmax;
    int8_t sign;
    char isoStr[SSFISO8601_MAX_SIZE] = "";

    srand((unsigned int)SSFPortGetTick64());

    /* Test Assertions */
#if SSF_DTIME_SYS_PREC != 9
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 1, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                        sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, true, 1000, SSF_ISO8601_ZONE_UTC, 0,
                                        isoStr, sizeof(isoStr)));
#endif
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_MIN, 0, isoStr,
                                        sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_MAX, 0, isoStr,
                                        sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 1, isoStr,
                                        sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH,
                                        -(int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH,
                                        (int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM,
                                        -(int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM,
                                        (int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_LOCAL,
                                        -(int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_LOCAL,
                                        (int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, NULL,
                                        sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                        sizeof(isoStr) - 1));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                        0));

    SSF_ASSERT_TEST(SSFISO8601ISOToUnix(NULL, &unixSys, &zoneOffsetMin));
    SSF_ASSERT_TEST(SSFISO8601ISOToUnix(isoStr, NULL, &zoneOffsetMin));
    SSF_ASSERT_TEST(SSFISO8601ISOToUnix(isoStr, &unixSys, NULL));

    /* Test the failure cases for SSFISO8601UnixToISO() */
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HH, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HHMM, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0,
                                   SSF_ISO8601_ZONE_LOCAL, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HH, 1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HHMM, 1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0,
                                   SSF_ISO8601_ZONE_LOCAL, 1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HH, -1, isoStr, sizeof(isoStr)) == false);
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HHMM, -1, isoStr, sizeof(isoStr)) == false);
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0,
                                   SSF_ISO8601_ZONE_LOCAL, -1, isoStr, sizeof(isoStr)) == false);

    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX + 1, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HH, 0, isoStr, sizeof(isoStr)) == false);
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HH, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HHMM, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0,
                                   SSF_ISO8601_ZONE_LOCAL, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HH, -1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HHMM, -1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0,
                                   SSF_ISO8601_ZONE_LOCAL, -1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HH, 1, isoStr, sizeof(isoStr)) == false);
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0,
                                   SSF_ISO8601_ZONE_OFFSET_HHMM, 1, isoStr, sizeof(isoStr)) == false);
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0,
                                   SSF_ISO8601_ZONE_LOCAL, 1, isoStr, sizeof(isoStr)) == false);

    /* Test sec precsion conversions for SSFISO8601ISOToUnix() */
    zoneOffsetMin = SSFISO8601_INVALID_ZONE_OFFSET + 10;
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00Z", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(unixSys == 0);
    SSF_ASSERT(zoneOffsetMin == 0);

    jmax = 1;
    for (i = 0; i < SSF_ISO8601_UT_NUM_FRAC_WIDTHS; i++)
    {
        jmax = jmax * 10;
#if SSF_ISO8601_EXHAUSTIVE_UNIT_TEST == 1
        _SSFISO8601UTParallel(SSF_ISO8601_UT_WORK_FRAC, i, 0, jmax);
#else /* SSF_ISO8601_EXHAUSTIVE_UNIT_TEST */
        /* Is this fraction width small enough to sweep every value? */
        if (jmax <= SSF_ISO8601_UT_FRAC_FULL_MAX)
        {
            /* Yes, check every fraction value */
            for (j = 0; j < jmax; j++) { _SSFISO8601UTFracCheck(i, j); }
        }
        else
        {
            /* No, check a strided sample plus each 10^k - 1 and 10^k boundary */
            for (j = 0; j < jmax; j += SSF_ISO8601_UT_FRAC_STRIDE) { _SSFISO8601UTFracCheck(i, j); }
            for (j = 1; j < jmax; j *= 10)
            {
                _SSFISO8601UTFracCheck(i, j - 1);
                _SSFISO8601UTFracCheck(i, j);
            }
            _SSFISO8601UTFracCheck(i, jmax - 1);
        }
#endif /* SSF_ISO8601_EXHAUSTIVE_UNIT_TEST */
    }

    /* Test that SSFISO8601UnixToISO() with SSF_ISO8601_ZONE_OFFSET_HH prints minutes if needed */
    for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
    {
        for (i = 0; i < 2; i++)
        {
            if (i == 0) sign = 1;
            else sign = -1;
            unixSys = SSFDTIME_UNIX_EPOCH_SYS_MIN + (((SSFPortTick_t)hour + 1) *
                                                     SSFDTIME_MIN_IN_HOUR * SSFDTIME_SEC_IN_MIN *
                                                     SSF_TICKS_PER_SEC * 2);
            SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH,
                                           (hour * SSFDTIME_MIN_IN_HOUR) * sign, isoStr,
                                           sizeof(isoStr)));
            SSF_ASSERT(strlen(isoStr) == 22);

            SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH,
                                           ((hour * SSFDTIME_MIN_IN_HOUR) + 1) * sign, isoStr,
                                           sizeof(isoStr)));
            SSF_ASSERT(strlen(isoStr) == 25);

            SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH,
                                           ((hour * SSFDTIME_MIN_IN_HOUR) - 1) * sign, isoStr,
                                           sizeof(isoStr)));
            SSF_ASSERT(strlen(isoStr) == 25);
        }
    }

    /* Test a few obvious gotcha dates */
    unixSys = SSFDTIME_UNIX_EPOCH_SYS_MIN;
    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                   sizeof(isoStr)));
    SSF_ASSERT(memcmp(isoStr, "1970-01-01T00:00:00Z", 21) == 0);
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(unixSys == unixSysOut);
    SSF_ASSERT(zoneOffsetMin == 0);

    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_LOCAL, 0, isoStr,
                                   sizeof(isoStr)));
    SSF_ASSERT(memcmp(isoStr, "1970-01-01T00:00:00", 20) == 0);
#if SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX == 1
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(unixSys == unixSysOut);
    SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
#else
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin) == false);
#endif

    unixSys = SSFDTIME_UNIX_EPOCH_SYS_MAX;
    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                   sizeof(isoStr)));
    SSF_ASSERT(memcmp(isoStr, "2199-12-31T23:59:59Z", 21) == 0);
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(unixSys == (unixSysOut + SSF_TS_FSEC_MAX));
    SSF_ASSERT(zoneOffsetMin == 0);

    unixSys = SSFDTIME_UNIX_EPOCH_SYS_MAX;
    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr,
        sizeof(isoStr)));
#if SSF_DTIME_SYS_PREC == 3
    SSF_ASSERT(memcmp(isoStr, "2199-12-31T23:59:59.999Z", 24) == 0);
#elif SSF_DTIME_SYS_PREC == 6
    SSF_ASSERT(memcmp(isoStr, "2199-12-31T23:59:59.999999Z", 27) == 0);
#else
    SSF_ASSERT(memcmp(isoStr, "2199-12-31T23:59:59.999999999Z", 30) == 0);
#endif
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(unixSys == unixSysOut);
    SSF_ASSERT(zoneOffsetMin == 0);

    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_LOCAL, 0,
                                   isoStr, sizeof(isoStr)));
    SSF_ASSERT(memcmp(isoStr, "2199-12-31T23:59:59", 20) == 0);
#if SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX == 1
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(unixSys == (unixSysOut + SSF_TS_FSEC_MAX));
    SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
#else
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin) == false);
#endif

    /* Test failure cases for SSFISO8601ISOToUnix() */
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-02-29T00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59Z ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234567", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345678", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456789", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1+01", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12+01", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123+01", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234+01", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345+01", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456+01", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234567+01", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345678+01", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456789+01", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1+01:02", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12+01:02", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123+01:02", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234+01:02", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345+01:02", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456+01:02", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234567+01:02", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345678+01:02", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456789+01:02", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59+01", &unixSys, &zoneOffsetMin));

    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1Z ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234567 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345678 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456789 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1+01 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12+01 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123+01 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234+01 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345+01 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456+01 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234567+01 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345678+01 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456789+01 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1+01:02 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12+01:02 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123+01:02 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234+01:02 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345+01:02 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456+01:02 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.1234567+01:02 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.12345678+01:02 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.123456789+01:02 ", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59+01 ", &unixSys, &zoneOffsetMin) == false);

    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59-01", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59+01:02", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59-01:02", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59-00:01", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00+00:01", &unixSys, &zoneOffsetMin) == false);

    SSF_ASSERT(SSFISO8601ISOToUnix("", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("21", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("219", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-1", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-3", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T2", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:5", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:5", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59+", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("a199-12-31T23:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2a99-12-31T23:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("21a9-12-31T23:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("219a-12-31T23:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199a12-31T23:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-a2-31T23:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-1a-31T23:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12a31T23:59:59", &unixSys, &zoneOffsetMin) == false);

    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-a1T23:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-3aT23:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31a23:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31Ta3:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T2a:59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23a59:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:a9:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:5a:59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59a59", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:a9", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:5a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.0a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.0a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.00a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.0000a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.00000a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.0000000a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.00000000a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000a", &unixSys, &zoneOffsetMin) == false);

    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.a+", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.0a+0", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.0a+00", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.00a+00:", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000a+00:0", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.0000a+00:00", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.00000a-", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000a-0", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.0000000a-00", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.00000000a-00:", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000a-00:0", &unixSys, &zoneOffsetMin) == false);

    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000+a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000+0a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000+00a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000+00:a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000+00:0a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000+00:00a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000-a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000-0a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000-00a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000-00:a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000-00:0a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59.000000000-00:00a", &unixSys, &zoneOffsetMin) == false);

    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59+a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59+0a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59+00a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59+00:a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59+00:0a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59+00:00a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59-a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59-0a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59-00a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59-00:a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59-00:0a", &unixSys, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2199-12-31T23:59:59-00:00a", &unixSys, &zoneOffsetMin) == false);

    /* Test sec precision */
    for (unixSys = 0; unixSys < SSF_TICKS_PER_SEC; unixSys++)
    {
        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                       sizeof(isoStr)));
        SSF_ASSERT(SSFIsDigit(isoStr[0]));
        SSF_ASSERT(SSFIsDigit(isoStr[1]));
        SSF_ASSERT(SSFIsDigit(isoStr[2]));
        SSF_ASSERT(SSFIsDigit(isoStr[3]));
        SSF_ASSERT(isoStr[4] == '-');
        SSF_ASSERT(SSFIsDigit(isoStr[5]));
        SSF_ASSERT(SSFIsDigit(isoStr[6]));
        SSF_ASSERT(isoStr[7] == '-');
        SSF_ASSERT(SSFIsDigit(isoStr[8]));
        SSF_ASSERT(SSFIsDigit(isoStr[9]));
        SSF_ASSERT(isoStr[10] == 'T');
        SSF_ASSERT(SSFIsDigit(isoStr[11]));
        SSF_ASSERT(SSFIsDigit(isoStr[12]));
        SSF_ASSERT(isoStr[13] == ':');
        SSF_ASSERT(SSFIsDigit(isoStr[14]));
        SSF_ASSERT(SSFIsDigit(isoStr[15]));
        SSF_ASSERT(isoStr[16] == ':');
        SSF_ASSERT(SSFIsDigit(isoStr[17]));
        SSF_ASSERT(SSFIsDigit(isoStr[18]));
        SSF_ASSERT(isoStr[19] == '.');
#if SSF_DTIME_SYS_PREC == 3
        SSF_ASSERT(SSFIsDigit(isoStr[20]));
        SSF_ASSERT(SSFIsDigit(isoStr[21]));
        SSF_ASSERT(SSFIsDigit(isoStr[22]));
        SSF_ASSERT(isoStr[23] == 'Z');
        SSF_ASSERT(isoStr[24] == 0);
        i = strtoul(&isoStr[20], NULL, 10);
        SSF_ASSERT(i == unixSys);
#elif SSF_DTIME_SYS_PREC == 6
        SSF_ASSERT(SSFIsDigit(isoStr[20]));
        SSF_ASSERT(SSFIsDigit(isoStr[21]));
        SSF_ASSERT(SSFIsDigit(isoStr[22]));
        SSF_ASSERT(SSFIsDigit(isoStr[23]));
        SSF_ASSERT(SSFIsDigit(isoStr[24]));
        SSF_ASSERT(SSFIsDigit(isoStr[25]));
        SSF_ASSERT(isoStr[26] == 'Z');
        SSF_ASSERT(isoStr[27] == 0);
#else
        SSF_ASSERT(SSFIsDigit(isoStr[20]));
        SSF_ASSERT(SSFIsDigit(isoStr[21]));
        SSF_ASSERT(SSFIsDigit(isoStr[22]));
        SSF_ASSERT(SSFIsDigit(isoStr[23]));
        SSF_ASSERT(SSFIsDigit(isoStr[24]));
        SSF_ASSERT(SSFIsDigit(isoStr[25]));
        SSF_ASSERT(SSFIsDigit(isoStr[26]));
        SSF_ASSERT(SSFIsDigit(isoStr[27]));
        SSF_ASSERT(SSFIsDigit(isoStr[28]));
        SSF_ASSERT(isoStr[29] == 'Z');
        SSF_ASSERT(isoStr[30] == 0);
#endif
        SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
        SSF_ASSERT(unixSys == unixSysOut);
    }

    for (unixSys = 0; unixSys < SSF_TICKS_PER_SEC; unixSys++)
    {
        for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
        {
            SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, false, 0, SSF_ISO8601_ZONE_OFFSET_HH,
                                           hour * SSFDTIME_MIN_IN_HOUR, isoStr, sizeof(isoStr)));
            SSF_ASSERT(SSFIsDigit(isoStr[0]));
            SSF_ASSERT(SSFIsDigit(isoStr[1]));
            SSF_ASSERT(SSFIsDigit(isoStr[2]));
            SSF_ASSERT(SSFIsDigit(isoStr[3]));
            SSF_ASSERT(isoStr[4] == '-');
            SSF_ASSERT(SSFIsDigit(isoStr[5]));
            SSF_ASSERT(SSFIsDigit(isoStr[6]));
            SSF_ASSERT(isoStr[7] == '-');
            SSF_ASSERT(SSFIsDigit(isoStr[8]));
            SSF_ASSERT(SSFIsDigit(isoStr[9]));
            SSF_ASSERT(isoStr[10] == 'T');
            SSF_ASSERT(SSFIsDigit(isoStr[11]));
            SSF_ASSERT(SSFIsDigit(isoStr[12]));
            SSF_ASSERT(isoStr[13] == ':');
            SSF_ASSERT(SSFIsDigit(isoStr[14]));
            SSF_ASSERT(SSFIsDigit(isoStr[15]));
            SSF_ASSERT(isoStr[16] == ':');
            SSF_ASSERT(SSFIsDigit(isoStr[17]));
            SSF_ASSERT(SSFIsDigit(isoStr[18]));
            SSF_ASSERT(isoStr[19] == '.');
    #if SSF_DTIME_SYS_PREC == 3
            SSF_ASSERT(SSFIsDigit(isoStr[20]));
            SSF_ASSERT(SSFIsDigit(isoStr[21]));
            SSF_ASSERT(SSFIsDigit(isoStr[22]));
            SSF_ASSERT(isoStr[23] == '+');
            SSF_ASSERT(SSFIsDigit(isoStr[24]));
            SSF_ASSERT(SSFIsDigit(isoStr[25]));
            SSF_ASSERT(isoStr[26] == 0);
            SSF_ASSERT(unixSys == strtoul(&isoStr[20], NULL, 10));
    #elif SSF_DTIME_SYS_PREC == 6
            SSF_ASSERT(SSFIsDigit(isoStr[20]));
            SSF_ASSERT(SSFIsDigit(isoStr[21]));
            SSF_ASSERT(SSFIsDigit(isoStr[22]));
            SSF_ASSERT(SSFIsDigit(isoStr[23]));
            SSF_ASSERT(SSFIsDigit(isoStr[24]));
            SSF_ASSERT(SSFIsDigit(isoStr[25]));
            SSF_ASSERT(isoStr[26] == '+');
            SSF_ASSERT(SSFIsDigit(isoStr[27]));
            SSF_ASSERT(SSFIsDigit(isoStr[28]));
            SSF_ASSERT(isoStr[29] == 0);
            SSF_ASSERT(unixSys == strtoul(&isoStr[20], NULL, 10));
    #else
            SSF_ASSERT(SSFIsDigit(isoStr[20]));
            SSF_ASSERT(SSFIsDigit(isoStr[21]));
            SSF_ASSERT(SSFIsDigit(isoStr[22]));
            SSF_ASSERT(SSFIsDigit(isoStr[23]));
            SSF_ASSERT(SSFIsDigit(isoStr[24]));
            SSF_ASSERT(SSFIsDigit(isoStr[25]));
            SSF_ASSERT(SSFIsDigit(isoStr[26]));
            SSF_ASSERT(SSFIsDigit(isoStr[27]));
            SSF_ASSERT(SSFIsDigit(isoStr[28]));
            SSF_ASSERT(isoStr[29] == '+');
            SSF_ASSERT(SSFIsDigit(isoStr[30]));
            SSF_ASSERT(SSFIsDigit(isoStr[31]));
            SSF_ASSERT(isoStr[32] == 0);
            SSF_ASSERT(unixSys == strtoul(&isoStr[20], NULL, 10));
    #endif
            SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
            SSF_ASSERT(unixSys == unixSysOut);
            SSF_ASSERT(zoneOffsetMin == (int16_t)(hour * SSFDTIME_MIN_IN_HOUR));
        }
    }

    for (unixSys = 0; unixSys < SSF_TICKS_PER_SEC; unixSys++)
    {
        for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
        {
            for (minute = 0; minute <= SSF_TS_MIN_MAX; minute++)
            {
                SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, false, 0,
                                               SSF_ISO8601_ZONE_OFFSET_HHMM,
                                               (hour * SSFDTIME_MIN_IN_HOUR) + minute, isoStr,
                                               sizeof(isoStr)));
                SSF_ASSERT(SSFIsDigit(isoStr[0]));
                SSF_ASSERT(SSFIsDigit(isoStr[1]));
                SSF_ASSERT(SSFIsDigit(isoStr[2]));
                SSF_ASSERT(SSFIsDigit(isoStr[3]));
                SSF_ASSERT(isoStr[4] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[5]));
                SSF_ASSERT(SSFIsDigit(isoStr[6]));
                SSF_ASSERT(isoStr[7] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[8]));
                SSF_ASSERT(SSFIsDigit(isoStr[9]));
                SSF_ASSERT(isoStr[10] == 'T');
                SSF_ASSERT(SSFIsDigit(isoStr[11]));
                SSF_ASSERT(SSFIsDigit(isoStr[12]));
                SSF_ASSERT(isoStr[13] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[14]));
                SSF_ASSERT(SSFIsDigit(isoStr[15]));
                SSF_ASSERT(isoStr[16] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[17]));
                SSF_ASSERT(SSFIsDigit(isoStr[18]));
                SSF_ASSERT(isoStr[19] == '.');
        #if SSF_DTIME_SYS_PREC == 3
                SSF_ASSERT(SSFIsDigit(isoStr[20]));
                SSF_ASSERT(SSFIsDigit(isoStr[21]));
                SSF_ASSERT(SSFIsDigit(isoStr[22]));
                SSF_ASSERT(isoStr[23] == '+');
                SSF_ASSERT(SSFIsDigit(isoStr[24]));
                SSF_ASSERT(SSFIsDigit(isoStr[25]));
                SSF_ASSERT(isoStr[26] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[27]));
                SSF_ASSERT(SSFIsDigit(isoStr[28]));
                SSF_ASSERT(isoStr[29] == 0);
                SSF_ASSERT(unixSys == strtoul(&isoStr[20], NULL, 10));
        #elif SSF_DTIME_SYS_PREC == 6
                SSF_ASSERT(SSFIsDigit(isoStr[20]));
                SSF_ASSERT(SSFIsDigit(isoStr[21]));
                SSF_ASSERT(SSFIsDigit(isoStr[22]));
                SSF_ASSERT(SSFIsDigit(isoStr[23]));
                SSF_ASSERT(SSFIsDigit(isoStr[24]));
                SSF_ASSERT(SSFIsDigit(isoStr[25]));
                SSF_ASSERT(isoStr[26] == '+');
                SSF_ASSERT(SSFIsDigit(isoStr[27]));
                SSF_ASSERT(SSFIsDigit(isoStr[28]));
                SSF_ASSERT(isoStr[29] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[30]));
                SSF_ASSERT(SSFIsDigit(isoStr[31]));
                SSF_ASSERT(isoStr[32] == 0);
                SSF_ASSERT(unixSys == strtoul(&isoStr[20], NULL, 10));
        #else
                SSF_ASSERT(SSFIsDigit(isoStr[20]));
                SSF_ASSERT(SSFIsDigit(isoStr[21]));
                SSF_ASSERT(SSFIsDigit(isoStr[22]));
                SSF_ASSERT(SSFIsDigit(isoStr[23]));
                SSF_ASSERT(SSFIsDigit(isoStr[24]));
                SSF_ASSERT(SSFIsDigit(isoStr[25]));
                SSF_ASSERT(SSFIsDigit(isoStr[26]));
                SSF_ASSERT(SSFIsDigit(isoStr[27]));
                SSF_ASSERT(SSFIsDigit(isoStr[28]));
                SSF_ASSERT(isoStr[29] == '+');
                SSF_ASSERT(SSFIsDigit(isoStr[30]));
                SSF_ASSERT(SSFIsDigit(isoStr[31]));
                SSF_ASSERT(isoStr[32] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[33]));
                SSF_ASSERT(SSFIsDigit(isoStr[34]));
                SSF_ASSERT(isoStr[35] == 0);
                SSF_ASSERT(unixSys == strtoul(&isoStr[20], NULL, 10));
        #endif
                SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
                SSF_ASSERT(unixSys == unixSysOut);
                SSF_ASSERT(zoneOffsetMin == (int16_t)((hour * SSFDTIME_MIN_IN_HOUR) + minute));
            }
        }
    }

    for (unixSys = 0; unixSys < SSF_TICKS_PER_SEC; unixSys++)
    {
        for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
        {
            for (minute = 0; minute <= SSF_TS_MIN_MAX; minute++)
            {
                SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, false, 0, SSF_ISO8601_ZONE_LOCAL,
                                               (hour * SSFDTIME_MIN_IN_HOUR) + minute, isoStr,
                                               sizeof(isoStr)));
                SSF_ASSERT(SSFIsDigit(isoStr[0]));
                SSF_ASSERT(SSFIsDigit(isoStr[1]));
                SSF_ASSERT(SSFIsDigit(isoStr[2]));
                SSF_ASSERT(SSFIsDigit(isoStr[3]));
                SSF_ASSERT(isoStr[4] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[5]));
                SSF_ASSERT(SSFIsDigit(isoStr[6]));
                SSF_ASSERT(isoStr[7] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[8]));
                SSF_ASSERT(SSFIsDigit(isoStr[9]));
                SSF_ASSERT(isoStr[10] == 'T');
                SSF_ASSERT(SSFIsDigit(isoStr[11]));
                SSF_ASSERT(SSFIsDigit(isoStr[12]));
                SSF_ASSERT(isoStr[13] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[14]));
                SSF_ASSERT(SSFIsDigit(isoStr[15]));
                SSF_ASSERT(isoStr[16] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[17]));
                SSF_ASSERT(SSFIsDigit(isoStr[18]));
                SSF_ASSERT(isoStr[19] == '.');
        #if SSF_DTIME_SYS_PREC == 3
                SSF_ASSERT(SSFIsDigit(isoStr[20]));
                SSF_ASSERT(SSFIsDigit(isoStr[21]));
                SSF_ASSERT(SSFIsDigit(isoStr[22]));
                SSF_ASSERT(isoStr[23] == 0);
                SSF_ASSERT(unixSys == strtoul(&isoStr[20], NULL, 10));
        #elif SSF_DTIME_SYS_PREC == 6
                SSF_ASSERT(SSFIsDigit(isoStr[20]));
                SSF_ASSERT(SSFIsDigit(isoStr[21]));
                SSF_ASSERT(SSFIsDigit(isoStr[22]));
                SSF_ASSERT(SSFIsDigit(isoStr[23]));
                SSF_ASSERT(SSFIsDigit(isoStr[24]));
                SSF_ASSERT(SSFIsDigit(isoStr[25]));
                SSF_ASSERT(isoStr[26] == 0);
                SSF_ASSERT(unixSys == strtoul(&isoStr[20], NULL, 10));
        #else
                SSF_ASSERT(SSFIsDigit(isoStr[20]));
                SSF_ASSERT(SSFIsDigit(isoStr[21]));
                SSF_ASSERT(SSFIsDigit(isoStr[22]));
                SSF_ASSERT(SSFIsDigit(isoStr[23]));
                SSF_ASSERT(SSFIsDigit(isoStr[24]));
                SSF_ASSERT(SSFIsDigit(isoStr[25]));
                SSF_ASSERT(SSFIsDigit(isoStr[26]));
                SSF_ASSERT(SSFIsDigit(isoStr[27]));
                SSF_ASSERT(SSFIsDigit(isoStr[28]));
                SSF_ASSERT(isoStr[29] == 0);
                SSF_ASSERT(unixSys == strtoul(&isoStr[20], NULL, 10));
        #endif
                SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
                SSF_ASSERT(unixSys == (unixSysOut - ((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) +
                                                     minute) * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC)));
                SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
            }
        }
    }

    /* Test pseudo sec precision */
    unixSys = 0;
    for (i = 0; i < 1000; i++)
    {
        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, true, (uint16_t)i, SSF_ISO8601_ZONE_UTC, 0,
                                       isoStr, sizeof(isoStr)));
        SSF_ASSERT(SSFIsDigit(isoStr[0]));
        SSF_ASSERT(SSFIsDigit(isoStr[1]));
        SSF_ASSERT(SSFIsDigit(isoStr[2]));
        SSF_ASSERT(SSFIsDigit(isoStr[3]));
        SSF_ASSERT(isoStr[4] == '-');
        SSF_ASSERT(SSFIsDigit(isoStr[5]));
        SSF_ASSERT(SSFIsDigit(isoStr[6]));
        SSF_ASSERT(isoStr[7] == '-');
        SSF_ASSERT(SSFIsDigit(isoStr[8]));
        SSF_ASSERT(SSFIsDigit(isoStr[9]));
        SSF_ASSERT(isoStr[10] == 'T');
        SSF_ASSERT(SSFIsDigit(isoStr[11]));
        SSF_ASSERT(SSFIsDigit(isoStr[12]));
        SSF_ASSERT(isoStr[13] == ':');
        SSF_ASSERT(SSFIsDigit(isoStr[14]));
        SSF_ASSERT(SSFIsDigit(isoStr[15]));
        SSF_ASSERT(isoStr[16] == ':');
        SSF_ASSERT(SSFIsDigit(isoStr[17]));
        SSF_ASSERT(SSFIsDigit(isoStr[18]));
        SSF_ASSERT(isoStr[19] == '.');
#if SSF_DTIME_SYS_PREC == 3
        SSF_ASSERT(SSFIsDigit(isoStr[20]));
        SSF_ASSERT(SSFIsDigit(isoStr[21]));
        SSF_ASSERT(SSFIsDigit(isoStr[22]));
        SSF_ASSERT(isoStr[23] == 'Z');
        SSF_ASSERT(isoStr[24] == 0);
        SSF_ASSERT(i == strtoul(&isoStr[20], NULL, 10));
#elif SSF_DTIME_SYS_PREC == 6
        SSF_ASSERT(SSFIsDigit(isoStr[20]));
        SSF_ASSERT(SSFIsDigit(isoStr[21]));
        SSF_ASSERT(SSFIsDigit(isoStr[22]));
        SSF_ASSERT(SSFIsDigit(isoStr[23]));
        SSF_ASSERT(SSFIsDigit(isoStr[24]));
        SSF_ASSERT(SSFIsDigit(isoStr[25]));
        SSF_ASSERT(isoStr[26] == 'Z');
        SSF_ASSERT(isoStr[27] == 0);
        SSF_ASSERT(i == strtoul(&isoStr[23], NULL, 10));
#endif
        SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
        SSF_ASSERT((unixSys + i) == unixSysOut);
    }

    unixSys = 0;
    for (i = 0; i < 1000; i++)
    {
        for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
        {
            SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, true, (uint16_t)i,
                                           SSF_ISO8601_ZONE_OFFSET_HH, hour * SSFDTIME_MIN_IN_HOUR,
                                           isoStr, sizeof(isoStr)));
            SSF_ASSERT(SSFIsDigit(isoStr[0]));
            SSF_ASSERT(SSFIsDigit(isoStr[1]));
            SSF_ASSERT(SSFIsDigit(isoStr[2]));
            SSF_ASSERT(SSFIsDigit(isoStr[3]));
            SSF_ASSERT(isoStr[4] == '-');
            SSF_ASSERT(SSFIsDigit(isoStr[5]));
            SSF_ASSERT(SSFIsDigit(isoStr[6]));
            SSF_ASSERT(isoStr[7] == '-');
            SSF_ASSERT(SSFIsDigit(isoStr[8]));
            SSF_ASSERT(SSFIsDigit(isoStr[9]));
            SSF_ASSERT(isoStr[10] == 'T');
            SSF_ASSERT(SSFIsDigit(isoStr[11]));
            SSF_ASSERT(SSFIsDigit(isoStr[12]));
            SSF_ASSERT(isoStr[13] == ':');
            SSF_ASSERT(SSFIsDigit(isoStr[14]));
            SSF_ASSERT(SSFIsDigit(isoStr[15]));
            SSF_ASSERT(isoStr[16] == ':');
            SSF_ASSERT(SSFIsDigit(isoStr[17]));
            SSF_ASSERT(SSFIsDigit(isoStr[18]));
            SSF_ASSERT(isoStr[19] == '.');
    #if SSF_DTIME_SYS_PREC == 3
            SSF_ASSERT(SSFIsDigit(isoStr[20]));
            SSF_ASSERT(SSFIsDigit(isoStr[21]));
            SSF_ASSERT(SSFIsDigit(isoStr[22]));
            SSF_ASSERT(isoStr[23] == '+');
            SSF_ASSERT(SSFIsDigit(isoStr[24]));
            SSF_ASSERT(SSFIsDigit(isoStr[25]));
            SSF_ASSERT(isoStr[26] == 0);
            SSF_ASSERT(i == strtoul(&isoStr[20], NULL, 10));
    #elif SSF_DTIME_SYS_PREC == 6
            SSF_ASSERT(SSFIsDigit(isoStr[20]));
            SSF_ASSERT(SSFIsDigit(isoStr[21]));
            SSF_ASSERT(SSFIsDigit(isoStr[22]));
            SSF_ASSERT(SSFIsDigit(isoStr[23]));
            SSF_ASSERT(SSFIsDigit(isoStr[24]));
            SSF_ASSERT(SSFIsDigit(isoStr[25]));
            SSF_ASSERT(isoStr[26] == 'Z');
            SSF_ASSERT(isoStr[27] == 0);
            SSF_ASSERT(i == strtoul(&isoStr[23], NULL, 10));
    #endif
            SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
            SSF_ASSERT((unixSys + i) == unixSysOut);
            SSF_ASSERT(zoneOffsetMin == (int16_t)(hour * SSFDTIME_MIN_IN_HOUR));
        }
    }

    unixSys = 0;
    for (i = 0; i < 1000; i++)
    {
        for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
        {
            for (minute = 0; minute <= SSF_TS_MIN_MAX; minute++)
            {
                SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, true, (uint16_t)i,
                                               SSF_ISO8601_ZONE_OFFSET_HHMM,
                                               (hour * SSFDTIME_MIN_IN_HOUR) + minute, isoStr,
                                               sizeof(isoStr)));
                SSF_ASSERT(SSFIsDigit(isoStr[0]));
                SSF_ASSERT(SSFIsDigit(isoStr[1]));
                SSF_ASSERT(SSFIsDigit(isoStr[2]));
                SSF_ASSERT(SSFIsDigit(isoStr[3]));
                SSF_ASSERT(isoStr[4] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[5]));
                SSF_ASSERT(SSFIsDigit(isoStr[6]));
                SSF_ASSERT(isoStr[7] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[8]));
                SSF_ASSERT(SSFIsDigit(isoStr[9]));
                SSF_ASSERT(isoStr[10] == 'T');
                SSF_ASSERT(SSFIsDigit(isoStr[11]));
                SSF_ASSERT(SSFIsDigit(isoStr[12]));
                SSF_ASSERT(isoStr[13] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[14]));
                SSF_ASSERT(SSFIsDigit(isoStr[15]));
                SSF_ASSERT(isoStr[16] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[17]));
                SSF_ASSERT(SSFIsDigit(isoStr[18]));
                SSF_ASSERT(isoStr[19] == '.');
        #if SSF_DTIME_SYS_PREC == 3
                SSF_ASSERT(SSFIsDigit(isoStr[20]));
                SSF_ASSERT(SSFIsDigit(isoStr[21]));
                SSF_ASSERT(SSFIsDigit(isoStr[22]));
                SSF_ASSERT(isoStr[23] == '+');
                SSF_ASSERT(SSFIsDigit(isoStr[24]));
                SSF_ASSERT(SSFIsDigit(isoStr[25]));
                SSF_ASSERT(isoStr[26] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[27]));
                SSF_ASSERT(SSFIsDigit(isoStr[28]));
                SSF_ASSERT(isoStr[29] == 0);
                SSF_ASSERT(i == strtoul(&isoStr[20], NULL, 10));
        #elif SSF_DTIME_SYS_PREC == 6
                SSF_ASSERT(SSFIsDigit(isoStr[20]));
                SSF_ASSERT(SSFIsDigit(isoStr[21]));
                SSF_ASSERT(SSFIsDigit(isoStr[22]));
                SSF_ASSERT(SSFIsDigit(isoStr[23]));
                SSF_ASSERT(SSFIsDigit(isoStr[24]));
                SSF_ASSERT(SSFIsDigit(isoStr[25]));
                SSF_ASSERT(isoStr[26] == 'Z');
                SSF_ASSERT(isoStr[27] == 0);
                SSF_ASSERT(i == strtoul(&isoStr[23], NULL, 10));
        #endif
                SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
                SSF_ASSERT((unixSys + i) == unixSysOut);
                SSF_ASSERT(zoneOffsetMin == (int16_t)((hour * SSFDTIME_MIN_IN_HOUR) + minute));
            }
        }
    }

    unixSys = 0;
    for (i = 0; i < 1000; i++)
    {
        for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
        {
            for (minute = 0; minute <= SSF_TS_MIN_MAX; minute++)
            {
                SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, true, (uint16_t)i,
                                               SSF_ISO8601_ZONE_LOCAL,
                                               (hour * SSFDTIME_MIN_IN_HOUR) + minute, isoStr,
                                               sizeof(isoStr)));
                SSF_ASSERT(SSFIsDigit(isoStr[0]));
                SSF_ASSERT(SSFIsDigit(isoStr[1]));
                SSF_ASSERT(SSFIsDigit(isoStr[2]));
                SSF_ASSERT(SSFIsDigit(isoStr[3]));
                SSF_ASSERT(isoStr[4] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[5]));
                SSF_ASSERT(SSFIsDigit(isoStr[6]));
                SSF_ASSERT(isoStr[7] == '-');
                SSF_ASSERT(SSFIsDigit(isoStr[8]));
                SSF_ASSERT(SSFIsDigit(isoStr[9]));
                SSF_ASSERT(isoStr[10] == 'T');
                SSF_ASSERT(SSFIsDigit(isoStr[11]));
                SSF_ASSERT(SSFIsDigit(isoStr[12]));
                SSF_ASSERT(isoStr[13] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[14]));
                SSF_ASSERT(SSFIsDigit(isoStr[15]));
                SSF_ASSERT(isoStr[16] == ':');
                SSF_ASSERT(SSFIsDigit(isoStr[17]));
                SSF_ASSERT(SSFIsDigit(isoStr[18]));
                SSF_ASSERT(isoStr[19] == '.');
                SSF_ASSERT(SSFIsDigit(isoStr[20]));
                SSF_ASSERT(SSFIsDigit(isoStr[21]));
                SSF_ASSERT(SSFIsDigit(isoStr[22]));
                SSF_ASSERT(isoStr[23] == 0);
                SSF_ASSERT(i == strtoul(&isoStr[20], NULL, 10));
                SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
                SSF_ASSERT((unixSys + i) == (unixSysOut - ((((SSFPortTick_t)hour *
                                                             SSFDTIME_MIN_IN_HOUR) + minute) *
                                                             SSFDTIME_SEC_IN_MIN *
                                                             SSF_TICKS_PER_SEC)));
                SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
            }
        }
    }

    /* Test sec precision and pseudo-sec precision simultaneously */
    unixSys = 0;
    for (i = 0; i < 1000; i++)
    {
        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, true, (uint16_t)i, SSF_ISO8601_ZONE_UTC, 0,
                                       isoStr, sizeof(isoStr)));
        SSF_ASSERT(SSFIsDigit(isoStr[0]));
        SSF_ASSERT(SSFIsDigit(isoStr[1]));
        SSF_ASSERT(SSFIsDigit(isoStr[2]));
        SSF_ASSERT(SSFIsDigit(isoStr[3]));
        SSF_ASSERT(isoStr[4] == '-');
        SSF_ASSERT(SSFIsDigit(isoStr[5]));
        SSF_ASSERT(SSFIsDigit(isoStr[6]));
        SSF_ASSERT(isoStr[7] == '-');
        SSF_ASSERT(SSFIsDigit(isoStr[8]));
        SSF_ASSERT(SSFIsDigit(isoStr[9]));
        SSF_ASSERT(isoStr[10] == 'T');
        SSF_ASSERT(SSFIsDigit(isoStr[11]));
        SSF_ASSERT(SSFIsDigit(isoStr[12]));
        SSF_ASSERT(isoStr[13] == ':');
        SSF_ASSERT(SSFIsDigit(isoStr[14]));
        SSF_ASSERT(SSFIsDigit(isoStr[15]));
        SSF_ASSERT(isoStr[16] == ':');
        SSF_ASSERT(SSFIsDigit(isoStr[17]));
        SSF_ASSERT(SSFIsDigit(isoStr[18]));
        SSF_ASSERT(isoStr[19] == '.');
#if SSF_DTIME_SYS_PREC == 3
        SSF_ASSERT(SSFIsDigit(isoStr[20]));
        SSF_ASSERT(SSFIsDigit(isoStr[21]));
        SSF_ASSERT(SSFIsDigit(isoStr[22]));
        SSF_ASSERT(SSFIsDigit(isoStr[23]));
        SSF_ASSERT(SSFIsDigit(isoStr[24]));
        SSF_ASSERT(SSFIsDigit(isoStr[25]));
        SSF_ASSERT(isoStr[26] == 'Z');
        SSF_ASSERT(isoStr[27] == 0);
        SSF_ASSERT(i == strtoul(&isoStr[23], NULL, 10));
#elif SSF_DTIME_SYS_PREC == 6
        SSF_ASSERT(SSFIsDigit(isoStr[20]));
        SSF_ASSERT(SSFIsDigit(isoStr[21]));
        SSF_ASSERT(SSFIsDigit(isoStr[22]));
        SSF_ASSERT(SSFIsDigit(isoStr[23]));
        SSF_ASSERT(SSFIsDigit(isoStr[24]));
        SSF_ASSERT(SSFIsDigit(isoStr[25]));
        SSF_ASSERT(SSFIsDigit(isoStr[26]));
        SSF_ASSERT(SSFIsDigit(isoStr[27]));
        SSF_ASSERT(SSFIsDigit(isoStr[28]));
        SSF_ASSERT(isoStr[29] == 'Z');
        SSF_ASSERT(isoStr[30] == 0);
        SSF_ASSERT(i == strtoul(&isoStr[26], NULL, 10));
#endif
#if SSF_ISO8601_ALLOW_FSEC_TRUNC == 1
        SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
        SSF_ASSERT(unixSys == unixSysOut);
#else
        SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin) == false);
#endif
    }

#if SSF_ISO8601_EXHAUSTIVE_UNIT_TEST == 1
    _SSFISO8601UTParallel(SSF_ISO8601_UT_WORK_SEC, 0, SSFDTIME_UNIX_EPOCH_SEC_MIN,
                          SSFDTIME_UNIX_EPOCH_SEC_MAX + 1ull);
#endif /* SSF_ISO8601_EXHAUSTIVE_UNIT_TEST */

    /* Fuzz test */
    for(ii = 0; ii < 10000; ii++)
    {
        unixSys = ii;
        for (j = 0; j < sizeof(unixSys); j++)
        {
            unixSys += rand();
            unixSys <<= sizeof(unixSys);
        }
        unixSys %= (SSFDTIME_UNIX_EPOCH_SYS_MAX + 1);
        unixSys = unixSys / SSF_TICKS_PER_SEC * SSF_TICKS_PER_SEC;

        if (ii == 0) unixSys = SSFDTIME_UNIX_EPOCH_SYS_MIN;
        else if (ii == 1) unixSys = SSFDTIME_UNIX_EPOCH_SYS_MAX;

        if (unixSys < (SSFDTIME_UNIX_EPOCH_SYS_MIN + (SSFDTIME_MIN_IN_DAY * SSFDTIME_SEC_IN_MIN *
                                                      SSF_TICKS_PER_SEC)))
        {
            unixSys = (SSFDTIME_UNIX_EPOCH_SYS_MIN + (SSFDTIME_MIN_IN_DAY * SSFDTIME_SEC_IN_MIN *
                                                      SSF_TICKS_PER_SEC));
        }
        if (unixSys > (SSFDTIME_UNIX_EPOCH_SYS_MAX - (SSFDTIME_MIN_IN_DAY * SSFDTIME_SEC_IN_MIN *
                                                      SSF_TICKS_PER_SEC)) - (SSF_TICKS_PER_SEC - 1))
        {
            unixSys = (SSFDTIME_UNIX_EPOCH_SYS_MAX - (SSFDTIME_MIN_IN_DAY * SSFDTIME_SEC_IN_MIN *
                                                      SSF_TICKS_PER_SEC) - (SSF_TICKS_PER_SEC - 1));
        }

        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                       sizeof(isoStr)));
        SSF_ASSERT(SSFIsDigit(isoStr[0]));
        SSF_ASSERT(SSFIsDigit(isoStr[1]));
        SSF_ASSERT(SSFIsDigit(isoStr[2]));
        SSF_ASSERT(SSFIsDigit(isoStr[3]));
        SSF_ASSERT(isoStr[4] == '-');
        SSF_ASSERT(SSFIsDigit(isoStr[5]));
        SSF_ASSERT(SSFIsDigit(isoStr[6]));
        SSF_ASSERT(isoStr[7] == '-');
        SSF_ASSERT(SSFIsDigit(isoStr[8]));
        SSF_ASSERT(SSFIsDigit(isoStr[9]));
        SSF_ASSERT(isoStr[10] == 'T');
        SSF_ASSERT(SSFIsDigit(isoStr[11]));
        SSF_ASSERT(SSFIsDigit(isoStr[12]));
        SSF_ASSERT(isoStr[13] == ':');
        SSF_ASSERT(SSFIsDigit(isoStr[14]));
        SSF_ASSERT(SSFIsDigit(isoStr[15]));
        SSF_ASSERT(isoStr[16] == ':');
        SSF_ASSERT(SSFIsDigit(isoStr[17]));
        SSF_ASSERT(SSFIsDigit(isoStr[18]));
        SSF_ASSERT(isoStr[19] == 'Z');
        SSF_ASSERT(isoStr[20] == 0);
        unixSysOut = SSFDTIME_UNIX_EPOCH_SYS_MAX + 1;
        zoneOffsetMin = SSFDTIME_MIN_IN_DAY + 2;
        SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
        SSF_ASSERT(unixSys == unixSysOut);
        SSF_ASSERT(zoneOffsetMin == 0);

        for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
        {
            for (i = 0; i < 2; i++)
            {
                if (i == 0) sign = 1;
                else sign = -1;
                if (((sign == -1) && (unixSys < ((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR *
                                                 SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC))) ||
                    ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) <
                                    ((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR *
                                    SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC)))
                {
                    /* Offset not in valid date range */
                    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                                   SSF_ISO8601_ZONE_OFFSET_HH,
                                                   hour * SSFDTIME_MIN_IN_HOUR * sign, isoStr,
                                                   sizeof(isoStr)) == false);
                }
                else
                {
                    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                                   SSF_ISO8601_ZONE_OFFSET_HH, hour *
                                                   SSFDTIME_MIN_IN_HOUR * sign, isoStr,
                                                   sizeof(isoStr)));
                    SSF_ASSERT(SSFIsDigit(isoStr[0]));
                    SSF_ASSERT(SSFIsDigit(isoStr[1]));
                    SSF_ASSERT(SSFIsDigit(isoStr[2]));
                    SSF_ASSERT(SSFIsDigit(isoStr[3]));
                    SSF_ASSERT(isoStr[4] == '-');
                    SSF_ASSERT(SSFIsDigit(isoStr[5]));
                    SSF_ASSERT(SSFIsDigit(isoStr[6]));
                    SSF_ASSERT(isoStr[7] == '-');
                    SSF_ASSERT(SSFIsDigit(isoStr[8]));
                    SSF_ASSERT(SSFIsDigit(isoStr[9]));
                    SSF_ASSERT(isoStr[10] == 'T');
                    SSF_ASSERT(SSFIsDigit(isoStr[11]));
                    SSF_ASSERT(SSFIsDigit(isoStr[12]));
                    SSF_ASSERT(isoStr[13] == ':');
                    SSF_ASSERT(SSFIsDigit(isoStr[14]));
                    SSF_ASSERT(SSFIsDigit(isoStr[15]));
                    SSF_ASSERT(isoStr[16] == ':');
                    SSF_ASSERT(SSFIsDigit(isoStr[17]));
                    SSF_ASSERT(SSFIsDigit(isoStr[18]));
                    if ((sign == 1) || (hour == 0)) SSF_ASSERT(isoStr[19] == '+');
                    else SSF_ASSERT(isoStr[19] == '-');
                    SSF_ASSERT(SSFIsDigit(isoStr[20]));
                    SSF_ASSERT(SSFIsDigit(isoStr[21]));
                    SSF_ASSERT(isoStr[22] == 0);
                    unixSysOut = SSFDTIME_UNIX_EPOCH_SYS_MAX + 1;
                    zoneOffsetMin = SSFDTIME_MIN_IN_DAY + 2;
                    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
                    SSF_ASSERT(unixSys == unixSysOut);
                    SSF_ASSERT(zoneOffsetMin == (int16_t)((hour * SSFDTIME_MIN_IN_HOUR) * sign));
                }
            }
        }

        for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
        {
            for (minute = 0; minute <= SSF_TS_MIN_MAX; minute++)
            {
                for (i = 0; i < 2; i++)
                {
                    if (i == 0) sign = 1;
                    else sign = -1;
                    if (((sign == -1) && (unixSys < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) +
                                                     minute) * SSFDTIME_SEC_IN_MIN) *
                                                     SSF_TICKS_PER_SEC))) ||
                        ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) <
                                        (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                        SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC)))
                    {
                        /* Offset not in valid date range */
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                                       SSF_ISO8601_ZONE_OFFSET_HHMM,
                                                       ((hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                                       sign, isoStr, sizeof(isoStr)) == false);
                    }
                    else
                    {
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                                       SSF_ISO8601_ZONE_OFFSET_HHMM,
                                                       ((hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                                       sign, isoStr, sizeof(isoStr)));
                        SSF_ASSERT(SSFIsDigit(isoStr[0]));
                        SSF_ASSERT(SSFIsDigit(isoStr[1]));
                        SSF_ASSERT(SSFIsDigit(isoStr[2]));
                        SSF_ASSERT(SSFIsDigit(isoStr[3]));
                        SSF_ASSERT(isoStr[4] == '-');
                        SSF_ASSERT(SSFIsDigit(isoStr[5]));
                        SSF_ASSERT(SSFIsDigit(isoStr[6]));
                        SSF_ASSERT(isoStr[7] == '-');
                        SSF_ASSERT(SSFIsDigit(isoStr[8]));
                        SSF_ASSERT(SSFIsDigit(isoStr[9]));
                        SSF_ASSERT(isoStr[10] == 'T');
                        SSF_ASSERT(SSFIsDigit(isoStr[11]));
                        SSF_ASSERT(SSFIsDigit(isoStr[12]));
                        SSF_ASSERT(isoStr[13] == ':');
                        SSF_ASSERT(SSFIsDigit(isoStr[14]));
                        SSF_ASSERT(SSFIsDigit(isoStr[15]));
                        SSF_ASSERT(isoStr[16] == ':');
                        SSF_ASSERT(SSFIsDigit(isoStr[17]));
                        SSF_ASSERT(SSFIsDigit(isoStr[18]));
                        if ((sign == 1) || ((hour == 0) && (minute == 0)))
                        { SSF_ASSERT(isoStr[19] == '+'); }
                        else SSF_ASSERT(isoStr[19] == '-');
                        SSF_ASSERT(SSFIsDigit(isoStr[20]));
                        SSF_ASSERT(SSFIsDigit(isoStr[21]));
                        SSF_ASSERT(isoStr[22] == ':');
                        SSF_ASSERT(SSFIsDigit(isoStr[23]));
                        SSF_ASSERT(SSFIsDigit(isoStr[24]));
                        SSF_ASSERT(isoStr[25] == 0);
                        unixSysOut = SSFDTIME_UNIX_EPOCH_SYS_MAX + 1;
                        zoneOffsetMin = SSFDTIME_MIN_IN_DAY + 2;
                        SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
                        SSF_ASSERT(unixSys == unixSysOut);
                        SSF_ASSERT(zoneOffsetMin == (int16_t)(((hour * SSFDTIME_MIN_IN_HOUR) +
                                                              minute) * sign));
                    }
                }
            }
        }
#if SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX == 1
        for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
        {
            for (minute = 0; minute <= SSF_TS_MIN_MAX; minute++)
            {
                for (i = 0; i < 2; i++)
                {
                    if (i == 0) sign = 1;
                    else sign = -1;
                    if (((sign == -1) && (unixSys < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) +
                                                     minute) * SSFDTIME_SEC_IN_MIN) *
                                                     SSF_TICKS_PER_SEC))) ||
                        ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) <
                                        (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                        SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC)))
                    {
                        /* Offset not in valid date range */
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                                       SSF_ISO8601_ZONE_OFFSET_HHMM,
                                                       ((hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                                       sign, isoStr, sizeof(isoStr)) == false);
                    }
                    else
                    {
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0,
                                                       SSF_ISO8601_ZONE_LOCAL,
                                                       ((hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                                       sign, isoStr, sizeof(isoStr)));
                        SSF_ASSERT(SSFIsDigit(isoStr[0]));
                        SSF_ASSERT(SSFIsDigit(isoStr[1]));
                        SSF_ASSERT(SSFIsDigit(isoStr[2]));
                        SSF_ASSERT(SSFIsDigit(isoStr[3]));
                        SSF_ASSERT(isoStr[4] == '-');
                        SSF_ASSERT(SSFIsDigit(isoStr[5]));
                        SSF_ASSERT(SSFIsDigit(isoStr[6]));
                        SSF_ASSERT(isoStr[7] == '-');
                        SSF_ASSERT(SSFIsDigit(isoStr[8]));
                        SSF_ASSERT(SSFIsDigit(isoStr[9]));
                        SSF_ASSERT(isoStr[10] == 'T');
                        SSF_ASSERT(SSFIsDigit(isoStr[11]));
                        SSF_ASSERT(SSFIsDigit(isoStr[12]));
                        SSF_ASSERT(isoStr[13] == ':');
                        SSF_ASSERT(SSFIsDigit(isoStr[14]));
                        SSF_ASSERT(SSFIsDigit(isoStr[15]));
                        SSF_ASSERT(isoStr[16] == ':');
                        SSF_ASSERT(SSFIsDigit(isoStr[17]));
                        SSF_ASSERT(SSFIsDigit(isoStr[18]));
                        SSF_ASSERT(isoStr[19] == 0);
                        unixSysOut = SSFDTIME_UNIX_EPOCH_SYS_MAX + 1;
                        zoneOffsetMin = SSFDTIME_MIN_IN_DAY + 2;
                        SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
                        unixSysOut -= ((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) *
                                      SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC) * sign;
                        SSF_ASSERT(unixSys == unixSysOut);
                        SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
                    }
                }
            }
        }
#endif /* SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX */
    }

    /* secPseudoPrecision: generates .XXX pseudo fractional seconds */
    SSF_ASSERT(SSFISO8601UnixToISO(0, false, true, 123, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                   sizeof(isoStr)));
    SSF_ASSERT(memcmp(isoStr, "1970-01-01T00:00:00.123Z", 24) == 0);
    SSF_ASSERT(SSFISO8601UnixToISO(0, false, true, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                   sizeof(isoStr)));
    SSF_ASSERT(memcmp(isoStr, "1970-01-01T00:00:00.000Z", 24) == 0);
    SSF_ASSERT(SSFISO8601UnixToISO(0, false, true, 999, SSF_ISO8601_ZONE_UTC, 0, isoStr,
                                   sizeof(isoStr)));
    SSF_ASSERT(memcmp(isoStr, "1970-01-01T00:00:00.999Z", 24) == 0);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00.123Z", &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(zoneOffsetMin == 0);

    /* Malformed/short ISO strings return false */
    SSF_ASSERT(SSFISO8601ISOToUnix("", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:0", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970/01/01T00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01 00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00-00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00-00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("197X-01-01T00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-0X-01T00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-0XT00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1969-01-01T00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("2200-01-01T00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-13-01T00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-00-01T00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-00T00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-32T00:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T24:00:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:60:00Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:60Z", &unixSysOut, &zoneOffsetMin) == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00.Z", &unixSysOut, &zoneOffsetMin) == false);

    /* Negative zone offset value verification */
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-02T00:00:00-05", &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(zoneOffsetMin == -300);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-02T00:00:00-05:30", &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(zoneOffsetMin == -330);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T05:00:00+05", &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(zoneOffsetMin == 300);
    SSF_ASSERT(unixSysOut == 0);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T05:30:00+05:30", &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(zoneOffsetMin == 330);
    SSF_ASSERT(unixSysOut == 0);

    /* Fractional seconds: 10+ digits trips the numDigs > 9 reject (ssfiso8601.c:281). */
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00.1234567890Z",
                                    &unixSysOut, &zoneOffsetMin) == false);

    /* Timezone hour: non-digit at position 0 / 1 of "+HH". */
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00+X5", &unixSysOut, &zoneOffsetMin)
               == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00+0X", &unixSysOut, &zoneOffsetMin)
               == false);

    /* Timezone min: non-digit at position 0 / 1 of "+HH:MM". */
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00+05:X0", &unixSysOut, &zoneOffsetMin)
               == false);
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00+05:0X", &unixSysOut, &zoneOffsetMin)
               == false);

    /* Timezone hour out of range. */
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00+25:00", &unixSysOut, &zoneOffsetMin)
               == false);

    /* Timezone min out of range. */
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00+05:60", &unixSysOut, &zoneOffsetMin)
               == false);
}
