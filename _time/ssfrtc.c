/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfrtc.c                                                                                      */
/* Provides interface that tracks "now" as Unix system ticks from a RTC device.                  */
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
/* Design and Limitations of ssfrtc Interface                                                    */
/*                                                                                               */
/* The RTC device is only written to when time is updated from an external source, like NTP.     */
/* The RTC device only needs to be read on boot.                                                 */
/* All other reads of Unix sys "now" are derived from the system tick counter.                   */
/*                                                                                               */
/* --------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfdtime.h"
#include "ssfrtc.h"

/* --------------------------------------------------------------------------------------------- */
/* Module variables.                                                                             */
/* --------------------------------------------------------------------------------------------- */
static bool _ssfrtcIsInited;
static bool _ssfRTCIsNowInited;
static SSFPortTick_t _ssfRTCUnixBaseSys;
static SSFPortTick_t _ssfRTCTickBaseSys;

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
SSF_RTC_THREAD_SYNC_DECLARATION;
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */

#if SSF_RTC_ENABLE_SIM == 1
uint64_t _ssfRTCSimUnixSec;

/* --------------------------------------------------------------------------------------------- */
/* Returns true if write to RTC device successful, else false.                                   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRTCSimWrite(uint64_t unixSec)
{
    SSF_ASSERT(_ssfrtcIsInited);

    _ssfRTCSimUnixSec = unixSec;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if read from RTC device successful, else false.                                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRTCSimRead(uint64_t *unixSec)
{
    SSF_ASSERT(_ssfrtcIsInited);
    SSF_ASSERT(unixSec != NULL);

    /* A real RTC device would return a new time, not just a static value like the sim does! */
    (*unixSec) = _ssfRTCSimUnixSec;
    return true;
}
#endif /* SSF_RTC_ENABLE_SIM */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if init from RTC device successful, else false.                                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFRTCInit(void)
{
    uint64_t rtcUnixSec;

    SSF_ASSERT(_ssfrtcIsInited == false);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_RTC_THREAD_SYNC_INIT();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */   
    _ssfrtcIsInited = true;

    /* Is RTC read successful? */
    if (SSF_RTC_READ(&rtcUnixSec))
    {
        /* Yes, did RTC return a Unix time in seconds that is valid? */
        if (rtcUnixSec <= SSFDTIME_UNIX_EPOCH_SEC_MAX)
        {
            /* Yes, track the base */
            _ssfRTCUnixBaseSys =  rtcUnixSec * SSF_TICKS_PER_SEC;
            _ssfRTCTickBaseSys = SSFPortGetTick64();
            _ssfRTCIsNowInited = true;
            return true;
        }
    }

    /* Something went wrong, not inited anymore */
    _ssfRTCUnixBaseSys = 0;
    _ssfRTCTickBaseSys = 0;
    _ssfRTCIsNowInited = false;
   return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinits the RTC interface.                                                                    */
/* --------------------------------------------------------------------------------------------- */
void SSFRTCDeInit(void)
{
    SSF_ASSERT(_ssfrtcIsInited);

    _ssfRTCUnixBaseSys = 0;
    _ssfRTCTickBaseSys = 0;
    _ssfRTCIsNowInited = false;

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_RTC_THREAD_SYNC_DEINIT();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */   
    _ssfrtcIsInited = false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if write of new RTC time to device succeeds else false.                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFRTCSet(uint64_t unixSec)
{
    SSF_ASSERT(_ssfrtcIsInited);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_RTC_THREAD_SYNC_ACQUIRE();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */   

    /* Is Unix sec in valid range? */
    if (unixSec <= SSFDTIME_UNIX_EPOCH_SEC_MAX)
    {
        /* Yes, did RTC write succeed? */
        if (SSF_RTC_WRITE(unixSec))
        {
            /* Yes, track the base */
            _ssfRTCUnixBaseSys =  unixSec * SSF_TICKS_PER_SEC;
            _ssfRTCTickBaseSys = SSFPortGetTick64();
            _ssfRTCIsNowInited = true;
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
            SSF_RTC_THREAD_SYNC_RELEASE();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */           
            return true;
        }
    }

    /* Something went wrong, not inited anymore */
    _ssfRTCUnixBaseSys = 0;
    _ssfRTCIsNowInited = false;
#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_RTC_THREAD_SYNC_RELEASE();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */           
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and unixSys set to now, else false.                                              */
/* --------------------------------------------------------------------------------------------- */
bool SSFRTCGetUnixNow(SSFPortTick_t *unixSys)
{
    SSFPortTick_t retVal;

    SSF_ASSERT(_ssfrtcIsInited);

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_RTC_THREAD_SYNC_ACQUIRE();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */   

    retVal = _ssfRTCIsNowInited;
    if (unixSys != NULL)
    {
        *unixSys = (SSFPortGetTick64() - _ssfRTCTickBaseSys) + _ssfRTCUnixBaseSys;
    }

#if SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1
    SSF_RTC_THREAD_SYNC_RELEASE();
#endif /* SSF_CONFIG_ENABLE_THREAD_SUPPORT */           

    return retVal;
}
