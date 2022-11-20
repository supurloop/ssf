/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfdtime.h                                                                                    */
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
#ifndef SSF_DTIME_H_INCLUDE
#define SSF_DTIME_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#if SSF_TICKS_PER_SEC == 1000ull
#define SSF_DTIME_SYS_PREC (3u)
#define SSF_TS_FSEC_MAX (999ull)
#elif SSF_TICKS_PER_SEC == 1000000ull
#define SSF_DTIME_SYS_PREC (6u)
#define SSF_TS_FSEC_MAX (999999ull)
#elif SSF_TICKS_PER_SEC == 1000000000ull
#define SSF_DTIME_SYS_PREC (9u)
#define SSF_TS_FSEC_MAX (999999999ull)
#endif

#define SSFDTIME_SEC_IN_MIN (60l)
#define SSFDTIME_MIN_IN_HOUR (60u)
#define SSFDTIME_MIN_IN_DAY (1440ul)
#define SSFDTIME_MONTHS_IN_YEAR (12u)

#define SSFDTIME_EPOCH_YEAR (1970ul)
#define SSFDTIME_EPOCH_DAY (SSF_DTIME_WDAY_THU)
#define SSFDTIME_UNIX_EPOCH_SEC_MIN (0ull) /* 1970-01-01T00:00:00Z */
#define SSFDTIME_UNIX_EPOCH_SEC_MAX (7258118399ull) /* 2199-12-31T23:59:59Z */
#define SSFDTIME_UNIX_EPOCH_SYS_MIN (0ull)
#define SSFDTIME_UNIX_EPOCH_SYS_MAX \
    ((SSFDTIME_UNIX_EPOCH_SEC_MAX * SSF_TICKS_PER_SEC) + SSF_TS_FSEC_MAX)

#define SSF_TS_SEC_MAX (59u)
#define SSF_TS_MIN_MAX (59u)
#define SSF_TS_HOUR_MAX (23u)
#define SSF_TS_DAY_MAX (30u)
#define SSF_TS_MONTH_MAX (11u)
#define SSF_TS_YEAR_MAX (229u)
#define SSF_TS_DAYOFWEEK_MAX (6u)
#define SSF_TS_DAYOFYEAR_MAX (364u)
#define SSF_TS_DAYOFYEAR_LEAP_MAX (365u)

typedef enum
{
    SSF_DTIME_WDAY_SUN,
    SSF_DTIME_WDAY_MON,
    SSF_DTIME_WDAY_TUE,
    SSF_DTIME_WDAY_WED,
    SSF_DTIME_WDAY_THU,
    SSF_DTIME_WDAY_FRI,
    SSF_DTIME_WDAY_SAT,
} SSFDTimeStructWday_t;
#define SSF_DTIME_WDAY_MAX SSF_DTIME_WDAY_SAT

typedef enum
{
    SSF_DTIME_MONTH_JAN,
    SSF_DTIME_MONTH_FEB,
    SSF_DTIME_MONTH_MAR,
    SSF_DTIME_MONTH_APR,
    SSF_DTIME_MONTH_MAY,
    SSF_DTIME_MONTH_JUN,
    SSF_DTIME_MONTH_JUL,
    SSF_DTIME_MONTH_AUG,
    SSF_DTIME_MONTH_SEP,
    SSF_DTIME_MONTH_OCT,
    SSF_DTIME_MONTH_NOV,
    SSF_DTIME_MONTH_DEC,
} SSFDTimeStructMonth_t;
#define SSF_DTIME_MONTH_MAX SSF_DTIME_MONTH_DEC

typedef struct
{
    uint32_t fsec;  /* 0 >= fsec  <= SSF_TS_FSEC_MAX */
    uint8_t  sec;   /* 0 >= sec   <= SSF_TS_SEC_MAX */
    uint8_t  min;   /* 0 >= min   <= SSF_TS_MIN_MAX */
    uint8_t  hour;  /* 0 >= hour  <= SSF_TS_HOUR_MAX */
    uint8_t  day;   /* 0 >= day   <= SSF_TS_DAY_MAX */
    uint8_t  month; /* 0 >= month <= SSF_TS_MONTH_MAX */
    uint16_t year;  /* 0 >= year  <= SSF_TS_YEAR_MAX */
    uint8_t  wday;  /* 0 >= wday  <= SSF_DTIME_WDAY_MAX */
    uint16_t yday;  /* 0 >= yday  <= SSF_TS_DAYOFYEAR_MAX || */
                    /* 0 >= yday  <= SSF_TS_DAYOFYEAR_LEAP_MAX for a leap year */
#if SSF_DTIME_STRUCT_STRICT_CHECK == 1
    uint16_t magic;
#endif
} SSFDTimeStruct_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFDTimeStructInit(SSFDTimeStruct_t *ts, uint16_t year, uint8_t month, uint8_t day,
                        uint8_t hour, uint8_t min, uint8_t sec, uint32_t fsec);
bool SSFDTimeUnixToStruct(SSFPortTick_t unixSys, SSFDTimeStruct_t *ts, size_t tsSize);
bool SSFDTimeStructToUnix(const SSFDTimeStruct_t *ts, SSFPortTick_t *unixSys);
bool SSFDTimeIsLeapYear(uint16_t year);
uint8_t SSFDTimeDaysInMonth(uint16_t year, uint8_t month);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_DTIME_UNIT_TEST == 1
void SSFDTimeUnitTest(void);
#endif /* SSF_CONFIG_DTIME_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_DTIME_H_INCLUDE */
