/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfdtime.c                                                                                    */
/* Provides Unix system tick time to date time struct conversion interface.                      */
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
/* Design and Limitations of ssfdate Interface                                                   */
/*                                                                                               */
/* Supported date range: 1970-01-01T00:00:00.000000000Z - 2199-12-31T23:59:59.999999999Z         */
/* Unix time is measured in system ticks (unixSys is seconds scaled by SSF_TICKS_PER_SEC)        */
/* Unix time is always UTC (Z) time zone, other zones are handled by the ssfios8601 interface.   */
/* Unix time does not account for leap seconds, it only accounts for leap years.                 */
/* It is assumed that the RTC is periodically updated from an external time source, such as NTP. */
/* Inputs are strictly checked to ensure they represent valid calendar dates.                    */
/* System ticks (SSF_TICKS_PER_SEC) must be 1000, 1000000, or 1000000000.                        */
/*                                                                                               */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfdtime.h"
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
#include "ssffcsum.h"
#endif

/* --------------------------------------------------------------------------------------------- */
/* Module defines.                                                                               */
/* --------------------------------------------------------------------------------------------- */
#if (SSF_TICKS_PER_SEC != 1000ull) && \
    (SSF_TICKS_PER_SEC != 1000000ull) && \
    (SSF_TICKS_PER_SEC != 1000000000ull)
#error SSF - Time module requires SSF_TICKS_PER_SEC in ms, us, or ns.
#endif

#define SSFDTIME_NON_LEAP_YEAR (2100u)
#define SSFDTIME_IS_LEAP_YEAR(y) (((((y) + 2) & 0x03) == 0) && \
                                 ((y) != (SSFDTIME_NON_LEAP_YEAR - SSFDTIME_EPOCH_YEAR)))
#define SSFDTIME_SEC_IN_HOUR (3600ul)
#define SSFDTIME_HRS_IN_DAY (24u)
#define SSFDTIME_DAYS_IN_WEEK (7u)
#define SSFDTIME_SEC_IN_DAY (86400ul)
#define SSFDTIME_DAYS_IN_YEAR (365ul)
#define SSFDTIME_DAYS_IN_LEAP_YEAR (366ul)
#define SSFDTIME_SEC_IN_YEAR (31536000ull)
#define SSFDTIME_SEC_IN_LEAP_YEAR (31622400ull)

#define SSFDTIME_MONTH_DAY(m) { \
    if (unixDays < _daysInMonth[m]) { \
        ts->month = m; \
        ts->day = (uint8_t)unixDays; \
        return; } \
        unixDays -= _daysInMonth[m]; }

#define SSF_DTIME_STRUCT_CHECK_YEAR(y) \
    if ((y) > SSF_TS_YEAR_MAX) return false;
#define SSF_DTIME_STRUCT_CHECK_MONTH(m) \
    if ((m) > SSF_TS_MONTH_MAX) return false;
#define SSF_DTIME_STRUCT_CHECK_DAY(y, m, d) \
    if (((m) == 1) && (SSFDTIME_IS_LEAP_YEAR(y))) { \
        if ((d) > _daysInMonth[m]) return false; } \
    else if ((d) >= _daysInMonth[m]) return false;
#define SSF_DTIME_STRUCT_CHECK_HOUR(h) \
    if ((h) > SSF_TS_HOUR_MAX) return false;
#define SSF_DTIME_STRUCT_CHECK_MIN(m) \
    if ((m) > SSF_TS_MIN_MAX) return false;
#define SSF_DTIME_STRUCT_CHECK_SEC(s) \
    if ((s) > SSF_TS_SEC_MAX) return false;
#define SSF_DTIME_STRUCT_CHECK_FSEC(f) \
    if ((f) > SSF_TS_FSEC_MAX) return false;
#define SSF_DTIME_STRUCT_CHECK_WDAY(d) \
    if ((d) > SSF_TS_DAYOFWEEK_MAX) return false;
#define SSF_DTIME_STRUCT_CHECK_YDAY(y, d) \
    if (SSFDTIME_IS_LEAP_YEAR(y)) { if ((d) > SSF_TS_DAYOFYEAR_LEAP_MAX) return false; } \
    else { if ((d) > SSF_TS_DAYOFYEAR_MAX) return false; }

/* --------------------------------------------------------------------------------------------- */
/* Module variables.                                                                             */
/* --------------------------------------------------------------------------------------------- */
static const uint8_t _daysInMonth[SSFDTIME_MONTHS_IN_YEAR] =
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
static const uint16_t _daysInMonthAcc[SSFDTIME_MONTHS_IN_YEAR - 1] =
    { 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
static const uint32_t _unixDaysToYear[SSFDTIME_NUM_YEARS + 1] =
{
    365, 730, 1096, 1461, 1826, 2191, 2557, 2922, 3287, 3652, 4018, 4383, 4748, 5113, 5479, 5844,
    6209, 6574, 6940, 7305, 7670, 8035, 8401, 8766, 9131, 9496, 9862, 10227, 10592, 10957, 11323,
    11688, 12053, 12418, 12784, 13149, 13514, 13879, 14245, 14610, 14975, 15340, 15706, 16071,
    16436, 16801, 17167, 17532, 17897, 18262, 18628, 18993, 19358, 19723, 20089, 20454, 20819,
    21184, 21550, 21915, 22280, 22645, 23011, 23376, 23741, 24106, 24472, 24837, 25202, 25567,
    25933, 26298, 26663, 27028, 27394, 27759, 28124, 28489, 28855, 29220, 29585, 29950, 30316,
    30681, 31046, 31411, 31777, 32142, 32507, 32872, 33238, 33603, 33968, 34333, 34699, 35064,
    35429, 35794, 36160, 36525, 36890, 37255, 37621, 37986, 38351, 38716, 39082, 39447, 39812,
    40177, 40543, 40908, 41273, 41638, 42004, 42369, 42734, 43099, 43465, 43830, 44195, 44560,
    44926, 45291, 45656, 46021, 46387, 46752, 47117, 47482, 47847, 48212, 48577, 48942, 49308,
    49673, 50038, 50403, 50769, 51134, 51499, 51864, 52230, 52595, 52960, 53325, 53691, 54056,
    54421, 54786, 55152, 55517, 55882, 56247, 56613, 56978, 57343, 57708, 58074, 58439, 58804,
    59169, 59535, 59900, 60265, 60630, 60996, 61361, 61726, 62091, 62457, 62822, 63187, 63552,
    63918, 64283, 64648, 65013, 65379, 65744, 66109, 66474, 66840, 67205, 67570, 67935, 68301,
    68666, 69031, 69396, 69762, 70127, 70492, 70857, 71223, 71588, 71953, 72318, 72684, 73049,
    73414, 73779, 74145, 74510, 74875, 75240, 75606, 75971, 76336, 76701, 77067, 77432, 77797,
    78162, 78528, 78893, 79258, 79623, 79989, 80354, 80719, 81084, 81450, 81815, 82180, 82545,
    82911, 83276, 83641, 84006
};

#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
/* --------------------------------------------------------------------------------------------- */
/* Sets magic number to protect time struct from external modification.                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFDTimeStructSetMagic(SSFDTimeStruct_t *ts)
{
    SSF_REQUIRE(ts != NULL);

    ts->magic = 0;
    ts->magic = SSFFCSum16((uint8_t *)ts, sizeof(SSFDTimeStruct_t), SSF_FCSUM_INITIAL);
}
/* --------------------------------------------------------------------------------------------- */
/* Clears magic number to indicate time struct not valid.                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFDTimeStructClearMagic(SSFDTimeStruct_t *ts)
{
    SSF_REQUIRE(ts != NULL);

    memset(ts, 0, sizeof(SSFDTimeStruct_t));
    ts->magic = 1;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if struct magic number valid, else false.                                        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFDTimeStructIsMagicValid(const SSFDTimeStruct_t *ts)
{
    SSFDTimeStruct_t tsc;

    SSF_REQUIRE(ts != NULL);

    /* Make a copy of ts and return if the magic is valid */
    memcpy(&tsc, ts, sizeof(tsc));
    tsc.magic = 0;
    tsc.magic = SSFFCSum16((uint8_t *)&tsc, sizeof(tsc), SSF_FCSUM_INITIAL);
    return (tsc.magic == ts->magic);
}
#endif /* SSF_DTIME_STRUCT_STRICT_CHECK */

/* --------------------------------------------------------------------------------------------- */
/* Performs the harder conversions from unix to struct time.                                     */
/* --------------------------------------------------------------------------------------------- */
void _SSFDTimeUnixToStruct(uint32_t unixDays, SSFDTimeStruct_t *ts)
{
    bool isLeap;
    uint16_t i;

    SSF_REQUIRE(ts != NULL);

    /* Perform search for the year/yday based on unixDays */
    i = (uint16_t)SSF_MIN(SSFDTIME_NUM_YEARS, unixDays / SSF_TS_DAYOFYEAR_LEAP_MAX);
    do
    {
        SSF_ASSERT(i <= SSFDTIME_NUM_YEARS);

        /* Is unixDays this year or earlier? */
        if (unixDays < _unixDaysToYear[i])
        {
            if ((i == 0) || (unixDays >= _unixDaysToYear[i - 1])) 
            {
                /* Found year and yday */
                ts->year = i;
                if (i != 0) { unixDays -= _unixDaysToYear[i - 1]; }
                ts->yday = (uint16_t)unixDays;
                break;
            }
            /* Need to search lower in array */
            i--;
        }
        /* No, need to search higher in array */
        else { SSF_ERROR(); }
    } while (true);

    /* Search to find month and month day, loop unrolled for speed */
    isLeap = SSFDTIME_IS_LEAP_YEAR(ts->year);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_JAN);
    /* February is leap month special case */
    if (unixDays < (uint32_t)(_daysInMonth[SSF_DTIME_MONTH_FEB] + (uint8_t)isLeap))
    {
        ts->month = SSF_DTIME_MONTH_FEB;
        ts->day = (uint8_t)unixDays;
        return;
    }
    unixDays -= (_daysInMonth[SSF_DTIME_MONTH_FEB] + (uint8_t)isLeap);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_MAR);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_APR);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_MAY);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_JUN);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_JUL);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_AUG);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_SEP);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_OCT);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_NOV);
    SSFDTIME_MONTH_DAY(SSF_DTIME_MONTH_DEC);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if struct time is inited successfully from basic time inputs, else false.        */
/* --------------------------------------------------------------------------------------------- */
bool SSFDTimeStructInit(SSFDTimeStruct_t *ts, uint16_t year, uint8_t month, uint8_t day,
                        uint8_t hour, uint8_t min, uint8_t sec, uint32_t fsec)
{
    uint32_t unixDays;

    SSF_REQUIRE(ts != NULL);

    SSF_DTIME_STRUCT_CHECK_YEAR(year);
    SSF_DTIME_STRUCT_CHECK_MONTH(month);
    SSF_DTIME_STRUCT_CHECK_DAY(year, month, day);
    SSF_DTIME_STRUCT_CHECK_HOUR(hour);
    SSF_DTIME_STRUCT_CHECK_MIN(min);
    SSF_DTIME_STRUCT_CHECK_SEC(sec);
    SSF_DTIME_STRUCT_CHECK_FSEC(fsec);

    ts->year = year;
    ts->month = month;
    ts->day = day;
    ts->hour = hour;
    ts->min = min;
    ts->sec = sec;
    ts->fsec = fsec;
    ts->yday = day;
    if (month > 0)
    {
        month--;
        if ((month >= 1) && (SSFDTIME_IS_LEAP_YEAR(year))) { ts->yday += 1; }
        ts->yday += _daysInMonthAcc[month];
    }

    /* Compute total days since epoch */
    unixDays = ts->yday;
    unixDays += ts->year * SSFDTIME_DAYS_IN_YEAR;
    unixDays += ((ts->year + 1) >> 2);
    if (ts->year > (SSFDTIME_NON_LEAP_YEAR - SSFDTIME_EPOCH_YEAR)) unixDays--;

    ts->wday = (unixDays + SSFDTIME_EPOCH_DAY) % SSFDTIME_DAYS_IN_WEEK;
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    _SSFDTimeStructSetMagic(ts);
#endif
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if conversion from unixSys time to struct time successful, else false.           */
/* --------------------------------------------------------------------------------------------- */
bool SSFDTimeUnixToStruct(SSFPortTick_t unixSys, SSFDTimeStruct_t *ts, size_t tsSize)
{
    uint32_t unixDays;

    SSF_REQUIRE(ts != NULL);
    SSF_REQUIRE(tsSize == sizeof(SSFDTimeStruct_t));

#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    _SSFDTimeStructSetMagic(ts);
#endif
    /* Time in supported range? */
    if (unixSys > SSFDTIME_UNIX_EPOCH_SYS_MAX) return false;

    /* Record fractional seconds then normalize unix to seconds */
    ts->fsec = unixSys % SSF_TICKS_PER_SEC;
    unixSys = unixSys / SSF_TICKS_PER_SEC;

    /* Fail if time above limit */
    if (unixSys > SSFDTIME_UNIX_EPOCH_SYS_MAX) return false;

    /* Perform the easy conversions */
    ts->sec = unixSys % SSFDTIME_SEC_IN_MIN;
    ts->min = (unixSys / SSFDTIME_SEC_IN_MIN) % SSFDTIME_MIN_IN_HOUR;
    ts->hour = (unixSys / SSFDTIME_SEC_IN_HOUR) % SSFDTIME_HRS_IN_DAY;
    unixDays = (uint32_t)(unixSys / SSFDTIME_SEC_IN_DAY);
    ts->wday = (unixDays + SSFDTIME_EPOCH_DAY) % SSFDTIME_DAYS_IN_WEEK;

    /* Perform the harder conversions */
    _SSFDTimeUnixToStruct(unixDays, ts);

#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    _SSFDTimeStructSetMagic(ts);
#endif

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Return true if conversion from struct time to unixSys time is successful, else false.         */
/* --------------------------------------------------------------------------------------------- */
bool SSFDTimeStructToUnix(const SSFDTimeStruct_t *ts, SSFPortTick_t *unixSys)
{
    SSF_REQUIRE(ts != NULL);
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    SSF_REQUIRE(_SSFDTimeStructIsMagicValid(ts));
#endif
    SSF_REQUIRE(unixSys != NULL);

    SSF_DTIME_STRUCT_CHECK_YEAR(ts->year);
    SSF_DTIME_STRUCT_CHECK_MONTH(ts->month);
    SSF_DTIME_STRUCT_CHECK_DAY(ts->year, ts->month, ts->day);
    SSF_DTIME_STRUCT_CHECK_HOUR(ts->hour);
    SSF_DTIME_STRUCT_CHECK_MIN(ts->min);
    SSF_DTIME_STRUCT_CHECK_SEC(ts->sec);
    SSF_DTIME_STRUCT_CHECK_FSEC(ts->fsec);
    SSF_DTIME_STRUCT_CHECK_WDAY(ts->wday);
    SSF_DTIME_STRUCT_CHECK_YDAY(ts->year, ts->yday);

    (*unixSys) = ts->year * SSFDTIME_SEC_IN_YEAR;

    /* Adjust for leap seconds */
    (*unixSys) += (((((SSFPortTick_t)ts->year) + 1) >> 2) * SSFDTIME_SEC_IN_DAY);
    if (ts->year > (SSFDTIME_NON_LEAP_YEAR - SSFDTIME_EPOCH_YEAR))
    { (*unixSys) -= SSFDTIME_SEC_IN_DAY; }

    (*unixSys) += ((SSFPortTick_t)ts->yday) * SSFDTIME_SEC_IN_DAY;
    (*unixSys) += ((SSFPortTick_t)ts->hour) * SSFDTIME_SEC_IN_HOUR;
    (*unixSys) += ((SSFPortTick_t)ts->min) * SSFDTIME_SEC_IN_MIN;
    (*unixSys) += ts->sec;
    (*unixSys) *= SSF_TICKS_PER_SEC;
    (*unixSys) += ts->fsec;

    /* Return if unixSys is in range */
    return ((*unixSys) <= SSFDTIME_UNIX_EPOCH_SYS_MAX);
}

/* --------------------------------------------------------------------------------------------- */
/* Return true if year is leap year, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFDTimeIsLeapYear(uint16_t year)
{
    SSF_ASSERT(year <= SSF_TS_YEAR_MAX);

    return(SSFDTIME_IS_LEAP_YEAR(year));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns days in month.                                                                        */
/* --------------------------------------------------------------------------------------------- */
uint8_t SSFDTimeDaysInMonth(uint16_t year, uint8_t month)
{
    SSF_ASSERT(year <= SSF_TS_YEAR_MAX);
    SSF_ASSERT(month <= SSF_TS_MONTH_MAX);

    if ((month == SSF_DTIME_MONTH_FEB) && SSFDTIME_IS_LEAP_YEAR(year))
    {
        return _daysInMonth[SSF_DTIME_MONTH_FEB];
    }
    return _daysInMonth[month] - 1;
}
