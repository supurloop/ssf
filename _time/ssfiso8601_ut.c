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

#if SSF_ISO8601_EXHAUSTIVE_UNIT_TEST == 0
#warning Not running exhaustive ssfiso8601 unit tests; test coverage reduced.
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
    SSFPortTick_t unixSysMin = SSFDTIME_UNIX_EPOCH_SYS_MIN;
    SSFPortTick_t unixSysMax = SSFDTIME_UNIX_EPOCH_SYS_MAX;

    srand((unsigned int)SSFPortGetTick64());

    /* Test Assertions */
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 1, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, true, 1000, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_MIN, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_MAX, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 1, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, -(int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, (int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, -(int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, (int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_LOCAL, -(int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_LOCAL, (int16_t)SSFDTIME_MIN_IN_DAY, isoStr, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, NULL, sizeof(isoStr)));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr) - 1));
    SSF_ASSERT_TEST(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr, 0));

    SSF_ASSERT_TEST(SSFISO8601ISOToUnix(NULL, &unixSys, &zoneOffsetMin));
    SSF_ASSERT_TEST(SSFISO8601ISOToUnix(isoStr, NULL, &zoneOffsetMin));
    SSF_ASSERT_TEST(SSFISO8601ISOToUnix(isoStr, &unixSys, NULL));

    /* Test the failure cases for SSFISO8601UnixToISO() */
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0, SSF_ISO8601_ZONE_LOCAL, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, 1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, 1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0, SSF_ISO8601_ZONE_LOCAL, 1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, -1, isoStr, sizeof(isoStr)) == false);
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, -1, isoStr, sizeof(isoStr)) == false);
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MIN, false, false, 0, SSF_ISO8601_ZONE_LOCAL, -1, isoStr, sizeof(isoStr)) == false);


    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX + 1, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, 0, isoStr, sizeof(isoStr)) == false);
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0, SSF_ISO8601_ZONE_LOCAL, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, -1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, -1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0, SSF_ISO8601_ZONE_LOCAL, -1, isoStr, sizeof(isoStr)));
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, 1, isoStr, sizeof(isoStr)) == false);
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, 1, isoStr, sizeof(isoStr)) == false);
    SSF_ASSERT(SSFISO8601UnixToISO(SSFDTIME_UNIX_EPOCH_SYS_MAX, false, false, 0, SSF_ISO8601_ZONE_LOCAL, 1, isoStr, sizeof(isoStr)) == false);

    /* Test sec precsion conversions for SSFISO8601ISOToUnix() */
    zoneOffsetMin = SSFISO8601_INVALID_ZONE_OFFSET + 10;
    SSF_ASSERT(SSFISO8601ISOToUnix("1970-01-01T00:00:00Z", &unixSys, &zoneOffsetMin));
    SSF_ASSERT(unixSys == 0);
    SSF_ASSERT(zoneOffsetMin == 0);

    jmax = 1;
    for (i = 0; i < 9; i++)
    {
        jmax = jmax * 10;
        for (j = 0; j < jmax; j++)
        {
            switch(i)
            {
                case 0:
                    snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%01uZ", j);
                break;
                case 1:
                    snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%02uZ", j);
                break;
                case 2:
                    snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%03uZ", j);
                break;
                case 3:
                    snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%04uZ", j);
                break;
                case 4:
                    snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%05uZ", j);
                break;
                case 5:
                    snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%06uZ", j);
                break;
                case 6:
                    snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%07uZ", j);
                break;
                case 7:
                    snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%08uZ", j);
                break;
                case 8:
                    snprintf(isoStr, sizeof(isoStr), "1970-01-01T00:00:00.%09uZ", j);
                break;
                default:
                SSF_ERROR();
            }
            SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSys, &zoneOffsetMin));

            switch(i)
            {
                case 0:
                    SSF_ASSERT(unixSys == ((SSFPortTick_t)j * 100ul));
                break;
                case 1:
                    SSF_ASSERT(unixSys == ((SSFPortTick_t)j * 10ul));
                break;
                case 2:
                    SSF_ASSERT(unixSys == j);
                break;
                case 3:
                    SSF_ASSERT(unixSys == (j / 10ul));
                break;
                case 4:
                    SSF_ASSERT(unixSys == (j / 100ul));
                break;
                case 5:
                    SSF_ASSERT(unixSys == (j / 1000ul));
                break;
                case 6:
                    SSF_ASSERT(unixSys == (j / 10000ul));
                break;
                case 7:
                    SSF_ASSERT(unixSys == (j / 100000ul));
                break;
                case 8:
                    SSF_ASSERT(unixSys == (j / 1000000ul));
                break;
                default:
                SSF_ERROR();
            }
            SSF_ASSERT(zoneOffsetMin == 0);
        }
    }

    /* Test that SSFISO8601UnixToISO() with SSF_ISO8601_ZONE_OFFSET_HH prints minutes if not even hour */
    for (hour = 0; hour <= SSF_TS_HOUR_MAX; hour++)
    {
        for (i = 0; i < 2; i++)
        {
            if (i == 0) sign = 1;
            else sign = -1;
            unixSys = SSFDTIME_UNIX_EPOCH_SYS_MIN + (((SSFPortTick_t)hour + 1) * SSFDTIME_MIN_IN_HOUR * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC * 2);
            SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, (hour * SSFDTIME_MIN_IN_HOUR) * sign, isoStr, sizeof(isoStr)));
            SSF_ASSERT(strlen(isoStr) == 22);

            SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, ((hour * SSFDTIME_MIN_IN_HOUR) + 1) * sign, isoStr, sizeof(isoStr)));
            SSF_ASSERT(strlen(isoStr) == 25);

            SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, ((hour * SSFDTIME_MIN_IN_HOUR) - 1) * sign, isoStr, sizeof(isoStr)));
            SSF_ASSERT(strlen(isoStr) == 25);
        }
    }

    /* Test a few obvious gotcha dates */
    unixSys = SSFDTIME_UNIX_EPOCH_SYS_MIN;
    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(memcmp(isoStr, "1970-01-01T00:00:00Z", 21) == 0);
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(unixSys == unixSysOut);
    SSF_ASSERT(zoneOffsetMin == 0);

    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_LOCAL, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(memcmp(isoStr, "1970-01-01T00:00:00", 20) == 0);
#if SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX == 1
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(unixSys == unixSysOut);
    SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
#else
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin) == false);
#endif

    unixSys = SSFDTIME_UNIX_EPOCH_SYS_MAX;
    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr)));
    SSF_ASSERT(memcmp(isoStr, "2199-12-31T23:59:59Z", 21) == 0);
    SSF_ASSERT(SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin));
    SSF_ASSERT(unixSys == (unixSysOut + SSF_TS_FSEC_MAX));
    SSF_ASSERT(zoneOffsetMin == 0);

    unixSys = SSFDTIME_UNIX_EPOCH_SYS_MAX;
    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr)));
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

    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_LOCAL, 0, isoStr, sizeof(isoStr)));
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
        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr)));
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
            SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, hour * SSFDTIME_MIN_IN_HOUR, isoStr, sizeof(isoStr)));
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
                SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, (hour * SSFDTIME_MIN_IN_HOUR) + minute, isoStr, sizeof(isoStr)));
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
                SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, false, 0, SSF_ISO8601_ZONE_LOCAL, (hour * SSFDTIME_MIN_IN_HOUR) + minute, isoStr, sizeof(isoStr)));
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
                SSF_ASSERT(unixSys == (unixSysOut - ((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC)));
                SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
            }
        }
    }

    /* Test pseudo sec precision */
    unixSys = 0;
    for (i = 0; i < 1000; i++)
    {
        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, true, (uint16_t)i, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr)));
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
            SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, true, (uint16_t)i, SSF_ISO8601_ZONE_OFFSET_HH, hour * SSFDTIME_MIN_IN_HOUR, isoStr, sizeof(isoStr)));
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
                SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, true, (uint16_t)i, SSF_ISO8601_ZONE_OFFSET_HHMM, (hour * SSFDTIME_MIN_IN_HOUR) + minute, isoStr, sizeof(isoStr)));
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
                SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, true, (uint16_t)i, SSF_ISO8601_ZONE_LOCAL, (hour * SSFDTIME_MIN_IN_HOUR) + minute, isoStr, sizeof(isoStr)));
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
                SSF_ASSERT((unixSys + i) == (unixSysOut - ((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC)));
                SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
            }
        }
    }

    /* Test sec precision and pseudo-sec precision simultaneously */
    unixSys = 0;
    for (i = 0; i < 1000; i++)
    {
        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, true, true, (uint16_t)i, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr)));
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
    for(unixSys = unixSysMin; unixSys < unixSysMax; unixSys+=SSF_TICKS_PER_SEC)
    {
        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr)));
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
                if (((sign == -1) && (unixSys < ((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC))) ||
                    ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) < ((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC)))
                {
                    /* Offset not in valid date range */
                    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, hour * SSFDTIME_MIN_IN_HOUR * sign, isoStr, sizeof(isoStr)) == false);
                }
                else
                {
                    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, hour * SSFDTIME_MIN_IN_HOUR * sign, isoStr, sizeof(isoStr)));
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
                    if (((sign == -1) && (unixSys < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC))) ||
                        ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC)))
                    {
                        /* Offset not in valid date range */
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, ((hour * SSFDTIME_MIN_IN_HOUR) + minute) * sign, isoStr, sizeof(isoStr)) == false);
                    }
                    else
                    {
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, ((hour * SSFDTIME_MIN_IN_HOUR) + minute) * sign, isoStr, sizeof(isoStr)));
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
                        if ((sign == 1) || ((hour == 0) && (minute == 0))) SSF_ASSERT(isoStr[19] == '+');
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
                        SSF_ASSERT(zoneOffsetMin == (int16_t)(((hour * SSFDTIME_MIN_IN_HOUR) + minute) * sign));
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
                    if (((sign == -1) && (unixSys < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC))) ||
                        ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC)))
                    {
                        /* Offset not in valid date range */
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, ((hour * SSFDTIME_MIN_IN_HOUR) + minute) * sign, isoStr, sizeof(isoStr)) == false);
                    }
                    else
                    {
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_LOCAL, ((hour * SSFDTIME_MIN_IN_HOUR) + minute) * sign, isoStr, sizeof(isoStr)));
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
                        unixSysOut -= ((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC) * sign;
                        SSF_ASSERT(unixSys == unixSysOut);
                        SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
                    }
                }
            }
        }
#endif /* SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX */
    }
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
        
        if (unixSys < (SSFDTIME_UNIX_EPOCH_SYS_MIN + (SSFDTIME_MIN_IN_DAY * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC)))
        {
            unixSys = (SSFDTIME_UNIX_EPOCH_SYS_MIN + (SSFDTIME_MIN_IN_DAY * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC));
        }
        if (unixSys > (SSFDTIME_UNIX_EPOCH_SYS_MAX - (SSFDTIME_MIN_IN_DAY * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC)) - (SSF_TICKS_PER_SEC - 1))
        {
            unixSys = (SSFDTIME_UNIX_EPOCH_SYS_MAX - (SSFDTIME_MIN_IN_DAY * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC) - (SSF_TICKS_PER_SEC - 1));
        }

        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr)));
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
                if (((sign == -1) && (unixSys < ((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC))) ||
                    ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) < ((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC)))
                {
                    /* Offset not in valid date range */
                    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, hour * SSFDTIME_MIN_IN_HOUR * sign, isoStr, sizeof(isoStr)) == false);
                }
                else
                {
                    SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HH, hour * SSFDTIME_MIN_IN_HOUR * sign, isoStr, sizeof(isoStr)));
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
                    if (((sign == -1) && (unixSys < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC))) ||
                        ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC)))
                    {
                        /* Offset not in valid date range */
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, ((hour * SSFDTIME_MIN_IN_HOUR) + minute) * sign, isoStr, sizeof(isoStr)) == false);
                    }
                    else
                    {
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, ((hour * SSFDTIME_MIN_IN_HOUR) + minute) * sign, isoStr, sizeof(isoStr)));
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
                        if ((sign == 1) || ((hour == 0) && (minute == 0))) SSF_ASSERT(isoStr[19] == '+');
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
                        SSF_ASSERT(zoneOffsetMin == (int16_t)(((hour * SSFDTIME_MIN_IN_HOUR) + minute) * sign));
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
                    if (((sign == -1) && (unixSys < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC))) ||
                        ((sign == 1) && (SSFDTIME_UNIX_EPOCH_SYS_MAX - unixSys) < (((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN) * SSF_TICKS_PER_SEC)))
                    {
                        /* Offset not in valid date range */
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_OFFSET_HHMM, ((hour * SSFDTIME_MIN_IN_HOUR) + minute) * sign, isoStr, sizeof(isoStr)) == false);
                    }
                    else
                    {
                        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_LOCAL, ((hour * SSFDTIME_MIN_IN_HOUR) + minute) * sign, isoStr, sizeof(isoStr)));
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
                        unixSysOut -= ((((SSFPortTick_t)hour * SSFDTIME_MIN_IN_HOUR) + minute) * SSFDTIME_SEC_IN_MIN * SSF_TICKS_PER_SEC) * sign;
                        SSF_ASSERT(unixSys == unixSysOut);
                        SSF_ASSERT(zoneOffsetMin == SSFISO8601_INVALID_ZONE_OFFSET);
                    }
                }
            }
        }
#endif /* SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX */
    }
}
