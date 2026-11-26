/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfdtime_ut.c                                                                                 */
/* Unit tests Unix system tick time to date time struct conversion interface.                    */
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
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
#include "ssffcsum.h"
#endif

static const uint8_t _utDaysInMonth[SSFDTIME_MONTHS_IN_YEAR] =
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/* --------------------------------------------------------------------------------------------- */
/* Unit tests the ssfdtime interface.                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFDTimeUnitTest(void)
{
    uint16_t lc;
    uint32_t i;
    uint8_t j;
    uint32_t fsec;
    time_t dtimer;
#ifdef _WIN32
    struct tm tm;
#endif /* _WIN32 */
    struct tm *dtm;
    SSFDTimeStruct_t ts;
    SSFDTimeStruct_t tsi;
    SSFDTimeStruct_t tsc;
    SSFPortTick_t unixSys;
    SSFPortTick_t unixSysOut;
#if SSF_DTIME_EXHAUSTIVE_UNIT_TEST == 1
    SSFPortTick_t unixSysMin = SSFDTIME_UNIX_EPOCH_SYS_MIN;
    SSFPortTick_t unixSysMax = SSFDTIME_UNIX_EPOCH_SYS_MAX;
#endif

    srand((unsigned int)SSFPortGetTick64());

    /* Verify interface assertions */
    SSF_ASSERT_TEST(SSFDTimeStructInit(NULL, 1970 - SSFDTIME_EPOCH_YEAR, 0, 0, 0, 0, 0, 0));
    SSF_ASSERT_TEST(SSFDTimeUnixToStruct(0, NULL, sizeof(ts)));
    SSF_ASSERT_TEST(SSFDTimeUnixToStruct(0, &ts, sizeof(ts) - 1));
    SSF_ASSERT_TEST(SSFDTimeUnixToStruct(0, &ts, sizeof(ts) + 1));
    SSF_ASSERT_TEST(SSFDTimeUnixToStruct(0, &ts, 0));
    memset(&ts, 0, sizeof(ts));
    SSF_ASSERT_TEST(SSFDTimeStructToUnix(NULL, &unixSys));
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    ts.magic = 1;
    SSF_ASSERT_TEST(SSFDTimeStructToUnix(&ts, &unixSys));
    ts.magic = 0;
#endif
    SSF_ASSERT_TEST(SSFDTimeStructToUnix(&ts, NULL));
    SSF_ASSERT_TEST(SSFDTimeIsLeapYear(SSF_TS_YEAR_MAX + 1));
    SSF_ASSERT_TEST(SSFDTimeDaysInMonth(SSF_TS_YEAR_MAX + 1, 0));
    SSF_ASSERT_TEST(SSFDTimeDaysInMonth(0, SSF_TS_MONTH_MAX + 1));

    /* Test SSFDTimeDaysInMonth() */
    lc = 2;
    for (tsi.year = 0; tsi.year <= SSF_TS_YEAR_MAX; tsi.year++)
    {
        for (j = 0; j < SSFDTIME_MONTHS_IN_YEAR; j++)
        {
            /* February? */
            if (j == SSF_DTIME_MONTH_FEB)
            {
                /* Yes, is it a leap year? */
                if (((lc & 0x03) == 0) && (lc != 132))
                {
                    /* Yes, leap year */
                    SSF_ASSERT(SSFDTimeDaysInMonth(tsi.year, j) == _utDaysInMonth[j]);
                }
                else
                {
                    /* No, not leap year */
                    SSF_ASSERT(SSFDTimeDaysInMonth(tsi.year, j) == (_utDaysInMonth[j] - 1));
                }
            }
            else
            {
                /* No, not February */
                SSF_ASSERT(SSFDTimeDaysInMonth(tsi.year, j) == (_utDaysInMonth[j] - 1));
            }
        }
        lc++;
    }

    /* Test SSFDTimeIsLeapYear() */
    lc = 2;
    for (tsi.year = 0; tsi.year <= SSF_TS_YEAR_MAX; tsi.year++)
    {
        /* Leap year? */
        if (((lc & 0x03) == 0) && (lc != 132))
        {
            /* Yes, leap year */
            SSF_ASSERT(SSFDTimeIsLeapYear(tsi.year));
        }
        else
        {
            /* No, not leap year */
            SSF_ASSERT(SSFDTimeIsLeapYear(tsi.year) == false);
        }
        lc++;
    }

    /* Test fsec behavior */
    for (fsec = 0; fsec <= SSF_TS_FSEC_MAX; fsec++)
    {
        ts.fsec = fsec + 1;
        SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, 0, 0, fsec));
        SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSys));
        SSF_ASSERT((unixSys % (SSF_TS_FSEC_MAX + 1)) == fsec);
        SSF_ASSERT(SSFDTimeUnixToStruct(unixSys, &tsc, sizeof(tsc)));
        SSF_ASSERT(ts.fsec == tsc.fsec);
    }

    /* Test SSFDTimeStructInit() */
    SSF_ASSERT(SSFDTimeStructInit(&ts, SSF_TS_YEAR_MAX + 1, 0, 0, 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_TS_MONTH_MAX + 1, 0, 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_JAN,
                                  _utDaysInMonth[SSF_DTIME_MONTH_JAN], 0, 0, 0, 0) == false);
    for (tsi.year = 0; tsi.year <= SSF_TS_YEAR_MAX; tsi.year++)
    {
        SSF_ASSERT(SSFDTimeStructInit(&ts, tsi.year, SSF_DTIME_MONTH_FEB,
                                      (_utDaysInMonth[SSF_DTIME_MONTH_FEB] +
                                      (uint8_t)(SSFDTimeIsLeapYear(tsi.year))), 0, 0, 0, 0) ==
                                      false);
    }
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_MAR,
                                  _utDaysInMonth[SSF_DTIME_MONTH_MAR], 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_APR,
                                  _utDaysInMonth[SSF_DTIME_MONTH_APR], 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_MAY,
                                  _utDaysInMonth[SSF_DTIME_MONTH_MAY], 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_JUN,
                                  _utDaysInMonth[SSF_DTIME_MONTH_JUN], 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_JUL,
                                  _utDaysInMonth[SSF_DTIME_MONTH_JUL], 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_AUG,
                                  _utDaysInMonth[SSF_DTIME_MONTH_AUG], 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_SEP,
                                  _utDaysInMonth[SSF_DTIME_MONTH_SEP], 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_OCT,
                                  _utDaysInMonth[SSF_DTIME_MONTH_OCT], 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_NOV,
                                  _utDaysInMonth[SSF_DTIME_MONTH_NOV], 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, SSF_DTIME_MONTH_DEC,
                                  _utDaysInMonth[SSF_DTIME_MONTH_DEC], 0, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, SSF_TS_HOUR_MAX + 1, 0, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, SSF_TS_MIN_MAX + 1, 0, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, 0, SSF_TS_SEC_MAX + 1, 0) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, 0, 0, SSF_TS_FSEC_MAX + 1) == false);

    /* Fuzz test for SSFDTimeStructInit() */
    for (i = 0; i < 10000000ull; i++)
    {
        tsi.year = rand() % (SSF_TS_YEAR_MAX + 1);
        tsi.month = rand() % (SSF_TS_MONTH_MAX + 1);
        /* February of a leap year? */
        if (SSFDTimeIsLeapYear(tsi.year) && (tsi.month == SSF_DTIME_MONTH_FEB))
        {
            /* Yes, allow day 29 */
            tsi.day = rand() % (_utDaysInMonth[tsi.month]);
        }
        else
        {
            /* No, exclude the last day of the table month */
            tsi.day = rand() % (_utDaysInMonth[tsi.month] - 1);
        }
        tsi.hour = rand() % (SSF_TS_HOUR_MAX + 1);
        tsi.min = rand() % (SSF_TS_MIN_MAX + 1);
        tsi.sec = rand() % (SSF_TS_SEC_MAX + 1);
        tsi.fsec = rand() % (SSF_TS_FSEC_MAX + 1);

        /* Ensure min and max tested */
        if (i == 0)
        {
            tsi.year = 0;
            tsi.month = 0;
            tsi.day = 0;
            tsi.hour = 0;
            tsi.min = 0;
            tsi.sec = 0;
            tsi.fsec = 0;
        }
        else if (i == 1)
        {
            tsi.year = SSF_TS_YEAR_MAX;
            tsi.month = SSF_TS_MONTH_MAX;
            tsi.day = SSF_TS_DAY_MAX;
            tsi.hour = SSF_TS_HOUR_MAX;
            tsi.min = SSF_TS_MIN_MAX;
            tsi.sec = SSF_TS_SEC_MAX;
            tsi.fsec = SSF_TS_FSEC_MAX;
        }

        memset(&ts, 0x55, sizeof(ts));
        SSF_ASSERT(SSFDTimeStructInit(&ts, tsi.year, tsi.month, tsi.day,
                                        tsi.hour, tsi.min, tsi.sec,
                                        tsi.fsec));
        SSF_ASSERT(tsi.fsec == ts.fsec);
        SSF_ASSERT(tsi.sec == ts.sec);
        SSF_ASSERT(tsi.min == ts.min);
        SSF_ASSERT(tsi.hour == ts.hour);
        SSF_ASSERT(tsi.day == ts.day);
        SSF_ASSERT(tsi.month == ts.month);
        SSF_ASSERT(tsi.year == ts.year);
        //SSF_ASSERT(tsi.yday == ts.yday);
        //SSF_ASSERT(tsi.wday == ts.wday);
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
        memcpy(&tsi, &ts, sizeof(ts));
        tsi.magic = 0;
        tsi.magic = SSFFCSum16((uint8_t *)&tsi, sizeof(tsi), SSF_FCSUM_INITIAL);
        SSF_ASSERT(tsi.magic == ts.magic);
#endif
    }

#if SSF_DTIME_EXHAUSTIVE_UNIT_TEST == 1
    memset(&tsi, 0x55, sizeof(tsi));
    tsi.fsec = 0;
    tsi.wday = SSFDTIME_EPOCH_DAY;
    for (tsi.year = 0; tsi.year <= SSF_TS_YEAR_MAX; tsi.year++)
    {
        tsi.yday = 0;
        for (tsi.month = 0; tsi.month <= SSF_TS_MONTH_MAX; tsi.month++)
        {
            for (tsi.day = 0; tsi.day <= (uint8_t)((_utDaysInMonth[tsi.month] +
                                         (uint8_t)(SSFDTimeIsLeapYear(tsi.year) &&
                                         (tsi.month == SSF_DTIME_MONTH_FEB))) - 1);
                                         tsi.day++)
            {
                for (tsi.hour = 0; tsi.hour <= SSF_TS_HOUR_MAX; tsi.hour++)
                {
                    for (tsi.min = 0; tsi.min <= SSF_TS_MIN_MAX; tsi.min++)
                    {
                        for (tsi.sec = 0; tsi.sec <= SSF_TS_SEC_MAX; tsi.sec++)
                        {
                            memset(&ts, 0x55, sizeof(ts));
                            SSF_ASSERT(SSFDTimeStructInit(&ts, tsi.year, tsi.month, tsi.day,
                                                          tsi.hour, tsi.min, tsi.sec,
                                                          tsi.fsec));
                            SSF_ASSERT(tsi.fsec == ts.fsec);
                            SSF_ASSERT(tsi.sec == ts.sec);
                            SSF_ASSERT(tsi.min == ts.min);
                            SSF_ASSERT(tsi.hour == ts.hour);
                            SSF_ASSERT(tsi.day == ts.day);
                            SSF_ASSERT(tsi.month == ts.month);
                            SSF_ASSERT(tsi.year == ts.year);
                            SSF_ASSERT(tsi.yday == ts.yday);
                            SSF_ASSERT(tsi.wday == ts.wday);
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
                            tsi.magic = 0;
                            SSF_ASSERT(SSFFCSum16((uint8_t *)&tsi, sizeof(tsi),
                                                  SSF_FCSUM_INITIAL) == ts.magic);
#endif
                        }
                    }
                }
                tsi.wday++;
                tsi.wday %= (SSF_DTIME_WDAY_MAX + 1);
                tsi.yday++;
            }
        }
    }
#endif

    /* Basic tests for SSFDTimeUnixToStruct() */
    SSF_ASSERT(SSFDTimeUnixToStruct(SSFDTIME_UNIX_EPOCH_SYS_MAX, &ts, sizeof(ts)) == true);
    SSF_ASSERT(SSFDTimeUnixToStruct(SSFDTIME_UNIX_EPOCH_SYS_MAX + 1, &ts, sizeof(ts)) == false);

    /* Basic tests for SSFDTimeStructToUnix() */
    /* WARNING: DON'T CHANGE STRUCT VALUES IN APP CODE, THIS IS ONLY DONE FOR UNIT TESTING */
    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, 0, 0, 0));
    ts.year = SSF_TS_YEAR_MAX + 1;
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    ts.magic = 0;
    ts.magic = SSFFCSum16((uint8_t *)&ts, sizeof(ts), SSF_FCSUM_INITIAL);
#endif
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSys) == false);

    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, 0, 0, 0));
    ts.month = SSF_TS_MONTH_MAX + 1;
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    ts.magic = 0;
    ts.magic = SSFFCSum16((uint8_t *)&ts, sizeof(ts), SSF_FCSUM_INITIAL);
#endif
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSys) == false);

    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, 0, 0, 0));
    for (ts.year = 0; ts.year <= SSF_TS_YEAR_MAX; ts.year++)
    {
        for (ts.month = 0; ts.month <= SSF_TS_MONTH_MAX; ts.month++)
        {
            ts.day = (_utDaysInMonth[ts.month] +
                      (uint8_t)(SSFDTimeIsLeapYear(ts.year) && (ts.month == SSF_DTIME_MONTH_FEB)))
                     - 1;
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
            ts.magic = 0;
            ts.magic = SSFFCSum16((uint8_t *)&ts, sizeof(ts), SSF_FCSUM_INITIAL);
#endif
            SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSys));
        }
    }

    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, 0, 0, 0));
    ts.hour = SSF_TS_HOUR_MAX + 1;
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    ts.magic = 0;
    ts.magic = SSFFCSum16((uint8_t *)&ts, sizeof(ts), SSF_FCSUM_INITIAL);
#endif
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSys) == false);

    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, 0, 0, 0));
    ts.min = SSF_TS_MIN_MAX + 1;
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    ts.magic = 0;
    ts.magic = SSFFCSum16((uint8_t *)&ts, sizeof(ts), SSF_FCSUM_INITIAL);
#endif
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSys) == false);

    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, 0, 0, 0));
    ts.sec = SSF_TS_SEC_MAX + 1;
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    ts.magic = 0;
    ts.magic = SSFFCSum16((uint8_t *)&ts, sizeof(ts), SSF_FCSUM_INITIAL);
#endif
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSys) == false);

    SSF_ASSERT(SSFDTimeStructInit(&ts, 0, 0, 0, 0, 0, 0, 0));
    ts.fsec = SSF_TS_FSEC_MAX + 1;
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    ts.magic = 0;
    ts.magic = SSFFCSum16((uint8_t *)&ts, sizeof(ts), SSF_FCSUM_INITIAL);
#endif
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSys) == false);

    /* Fuzz test for SSFDTimeUnixToStruct() and SSFDTimeStructToUnix() */
    for (i = 0; i < 10000000ull; i++)
    {
        unixSys = i;
        for (j = 0; j < sizeof(unixSys); j++)
        {
            unixSys += rand();
            unixSys <<= sizeof(unixSys);
        }
        unixSys %= (SSFDTIME_UNIX_EPOCH_SYS_MAX + 1);

        /* Ensure min and max tested */
        if (i == 0) { unixSys = SSFDTIME_UNIX_EPOCH_SYS_MIN; }
        else if (i == 1) { unixSys = SSFDTIME_UNIX_EPOCH_SYS_MAX; }

        /* Convert unixSys to time struct */
        SSF_ASSERT(SSFDTimeUnixToStruct(unixSys, &ts, sizeof(ts)));

        /* Get gmtime() conversion */
        dtimer = (time_t)(unixSys / SSF_TICKS_PER_SEC);

#if UINTPTR_MAX == UINT32_MAX
        /* A 32-bit time_t cannot represent dates past 2038, so skip them */
        if ((unixSys / SSF_TICKS_PER_SEC) > (((uint32_t)-1) >> 1)) { continue; }
#endif

#ifdef _WIN32
        gmtime_s(&tm, &dtimer);
        dtm = &tm;
#else /* _WIN32 */
        dtm = gmtime(&dtimer);
#endif /* _WIN32 */
        /* Assert they are the same */
        SSF_ASSERT(ts.sec == dtm->tm_sec);
        SSF_ASSERT(ts.min == dtm->tm_min);
        SSF_ASSERT(ts.hour == dtm->tm_hour);
        SSF_ASSERT(ts.day == (dtm->tm_mday - 1));
        SSF_ASSERT(ts.month == dtm->tm_mon);
        SSF_ASSERT((ts.year + SSFDTIME_EPOCH_YEAR) == (uint16_t)(dtm->tm_year + 1900));
        SSF_ASSERT(ts.wday == dtm->tm_wday);
        SSF_ASSERT(ts.yday == dtm->tm_yday);

        /* Convert struct to unixSys time, must match original unixSys time */
        SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSysOut));
        SSF_ASSERT(unixSys == unixSysOut);
    }

    /* Known date: 1970-01-01T00:00:00 = epoch 0, Thursday */
    SSF_ASSERT(SSFDTimeUnixToStruct(0, &ts, sizeof(ts)));
    SSF_ASSERT(ts.year == 0);
    SSF_ASSERT(ts.month == SSF_DTIME_MONTH_JAN);
    SSF_ASSERT(ts.day == 0);
    SSF_ASSERT(ts.hour == 0);
    SSF_ASSERT(ts.min == 0);
    SSF_ASSERT(ts.sec == 0);
    SSF_ASSERT(ts.wday == SSF_DTIME_WDAY_THU);
    SSF_ASSERT(ts.yday == 0);
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSysOut));
    SSF_ASSERT(unixSysOut == 0);

    /* Known date: 2000-01-01T00:00:00Z = year 30, Saturday */
    SSF_ASSERT(SSFDTimeStructInit(&ts, 30, SSF_DTIME_MONTH_JAN, 0, 0, 0, 0, 0));
    SSF_ASSERT(ts.wday == SSF_DTIME_WDAY_SAT);
    SSF_ASSERT(ts.yday == 0);
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSysOut));
    SSF_ASSERT(SSFDTimeUnixToStruct(unixSysOut, &tsc, sizeof(tsc)));
    SSF_ASSERT(tsc.year == 30);
    SSF_ASSERT(tsc.month == SSF_DTIME_MONTH_JAN);
    SSF_ASSERT(tsc.day == 0);
    SSF_ASSERT(tsc.wday == SSF_DTIME_WDAY_SAT);

    /* Leap day: 2000-02-29 (year 30 is leap) */
    SSF_ASSERT(SSFDTimeIsLeapYear(30));
    SSF_ASSERT(SSFDTimeStructInit(&ts, 30, SSF_DTIME_MONTH_FEB, 28, 12, 0, 0, 0));
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSysOut));
    SSF_ASSERT(SSFDTimeUnixToStruct(unixSysOut, &tsc, sizeof(tsc)));
    SSF_ASSERT(tsc.year == 30);
    SSF_ASSERT(tsc.month == SSF_DTIME_MONTH_FEB);
    SSF_ASSERT(tsc.day == 28);
    SSF_ASSERT(tsc.hour == 12);

    /* Year 2100 (non-leap century) round-trip: 2100-03-01 */
    SSF_ASSERT(SSFDTimeIsLeapYear(2100 - SSFDTIME_EPOCH_YEAR) == false);
    SSF_ASSERT(SSFDTimeStructInit(&ts, (uint16_t)(2100 - SSFDTIME_EPOCH_YEAR),
                                  SSF_DTIME_MONTH_MAR, 0, 0, 0, 0, 0));
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSysOut));
    SSF_ASSERT(SSFDTimeUnixToStruct(unixSysOut, &tsc, sizeof(tsc)));
    SSF_ASSERT(tsc.year == (2100 - SSFDTIME_EPOCH_YEAR));
    SSF_ASSERT(tsc.month == SSF_DTIME_MONTH_MAR);
    SSF_ASSERT(tsc.day == 0);
    /* Feb 29 should be invalid for 2100 (non-leap) */
    SSF_ASSERT(SSFDTimeStructInit(&ts, (uint16_t)(2100 - SSFDTIME_EPOCH_YEAR),
                                  SSF_DTIME_MONTH_FEB, 28, 0, 0, 0, 0) == false);

    /* End-of-range: 2199-12-31T23:59:59 */
    SSF_ASSERT(SSFDTimeStructInit(&ts, SSF_TS_YEAR_MAX, SSF_DTIME_MONTH_DEC, 30, 23, 59, 59, 0));
    SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSysOut));
    SSF_ASSERT(SSFDTimeUnixToStruct(unixSysOut, &tsc, sizeof(tsc)));
    SSF_ASSERT(tsc.year == SSF_TS_YEAR_MAX);
    SSF_ASSERT(tsc.month == SSF_DTIME_MONTH_DEC);
    SSF_ASSERT(tsc.day == 30);
    SSF_ASSERT(tsc.hour == 23);
    SSF_ASSERT(tsc.min == 59);
    SSF_ASSERT(tsc.sec == 59);

#if SSF_DTIME_EXHAUSTIVE_UNIT_TEST == 1
    /* Exhaustive test for SSFDTimeUnixToStruct() && SSFDTimeStructToUnix() */
    /* Iterate over every possible second in supported date range, verify against gmtime() */
    for (unixSys = unixSysMin; unixSys < unixSysMax; unixSys += SSF_TICKS_PER_SEC)
    {
        /* Convert unixSys to time struct */
        SSF_ASSERT(SSFDTimeUnixToStruct(unixSys, &ts, sizeof(ts)));

        /* Get gmtime() conversion */
        dtimer = (time_t)(unixSys / SSF_TICKS_PER_SEC);
#ifdef _WIN32
        gmtime_s(&tm, &dtimer);
        dtm = &tm;
#else /* _WIN32 */
        dtm = gmtime(&dtimer);
#endif /* _WIN32 */

        /* Assert they are the same */
        SSF_ASSERT(ts.sec == dtm->tm_sec);
        SSF_ASSERT(ts.min == dtm->tm_min);
        SSF_ASSERT(ts.hour == dtm->tm_hour);
        SSF_ASSERT(ts.day == (dtm->tm_mday - 1));
        SSF_ASSERT(ts.month == dtm->tm_mon);
        SSF_ASSERT((ts.year + SSFDTIME_EPOCH_YEAR) == (uint16_t)(dtm->tm_year + 1900));
        SSF_ASSERT(ts.wday == dtm->tm_wday);
        SSF_ASSERT(ts.yday == dtm->tm_yday);

        /* Convert struct to unixSys time, must match original unixSys time */
        SSF_ASSERT(SSFDTimeStructToUnix(&ts, &unixSysOut));
        SSF_ASSERT(unixSys == unixSysOut);
    }
#endif /* SSF_DTIME_EXHAUSTIVE_UNIT_TEST */

    /* DTIME-01/02: every supported day against an independent days-to-civil */
    {
        uint32_t day;
        uint32_t lastDay = (uint32_t)((SSFDTIME_UNIX_EPOCH_SYS_MAX / SSF_TICKS_PER_SEC) / 86400ull);
        static const struct
        {
            uint16_t y;
            uint8_t m;
            uint8_t d;
            uint16_t yday;
        } edges[] = {
            { 1970u, 0u, 0u, 0u }, { 1972u, 1u, 28u, 59u }, { 1972u, 2u, 0u, 60u },
            { 1973u, 2u, 0u, 59u }, { 2000u, 1u, 28u, 59u }, { 2099u, 11u, 30u, 364u },
            { 2100u, 1u, 27u, 58u }, { 2100u, 2u, 0u, 59u }, { 2104u, 1u, 28u, 59u },
            { 2199u, 0u, 0u, 0u }, { 2199u, 11u, 30u, 364u } };

        for (day = 0u; day <= lastDay; day++)
        {
            /* Hinnant's days_from_civil inverse over the proleptic Gregorian calendar */
            uint32_t z = day + 719468u;
            uint32_t era = z / 146097u;
            uint32_t doe = z - (era * 146097u);
            uint32_t yoe = (doe - (doe / 1460u) + (doe / 36524u) - (doe / 146096u)) / 365u;
            uint32_t doy = doe - ((365u * yoe) + (yoe / 4u) - (yoe / 100u));
            uint32_t mp = ((5u * doy) + 2u) / 153u;
            uint32_t d = doy - (((153u * mp) + 2u) / 5u);
            uint32_t m = (mp < 10u) ? (mp + 2u) : (mp - 10u);
            uint32_t y = yoe + (era * 400u) + ((m <= 1u) ? 1u : 0u);

            unixSys = ((SSFPortTick_t)day * 86400ull) * SSF_TICKS_PER_SEC;
            SSF_ASSERT(SSFDTimeUnixToStruct((unixSys + SSF_TICKS_PER_SEC) - 1u, &ts, sizeof(ts)));
            SSF_ASSERT((ts.year + SSFDTIME_EPOCH_YEAR) == y);
            SSF_ASSERT(ts.month == m);
            SSF_ASSERT(ts.day == d);
            SSF_ASSERT(ts.wday == ((day + 4u) % 7u));
            SSF_ASSERT(SSFDTimeStructInit(&tsi, ts.year, ts.month, ts.day, 0u, 0u, 0u, 0u));
            SSF_ASSERT((tsi.yday == ts.yday) && (tsi.wday == ts.wday));
            SSF_ASSERT(SSFDTimeStructToUnix(&tsi, &unixSysOut));
            SSF_ASSERT(unixSysOut == unixSys);
        }

        /* Named edges: leap days, 1 March around them, 2100 (not leap), the last day */
        for (lc = 0u; lc < (uint16_t)(sizeof(edges) / sizeof(edges[0])); lc++)
        {
            SSF_ASSERT(SSFDTimeStructInit(&tsi, (uint16_t)(edges[lc].y - SSFDTIME_EPOCH_YEAR),
                                          edges[lc].m, edges[lc].d, 23u, 59u, 59u, 0u));
            SSF_ASSERT(tsi.yday == edges[lc].yday);
            SSF_ASSERT(SSFDTimeStructToUnix(&tsi, &unixSysOut));
            SSF_ASSERT(SSFDTimeUnixToStruct(unixSysOut, &ts, sizeof(ts)));
            SSF_ASSERT((ts.year == tsi.year) && (ts.month == edges[lc].m) &&
                       (ts.day == edges[lc].d) && (ts.yday == edges[lc].yday));
        }
        /* No 29 February 2100 */
        SSF_ASSERT(SSFDTimeStructInit(&tsi, (uint16_t)(2100u - SSFDTIME_EPOCH_YEAR), 1u, 28u,
                                      0u, 0u, 0u, 0u) == false);
    }
}
