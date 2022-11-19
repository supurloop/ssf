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
    SSFDTimeStruct_t ts;
    SSFPortTick_t unixSys, unixSysOut;
    int16_t zoneOffsetMin;
    char isoStr[SSFISO8601_MAX_SIZE] = "";
    char isoStr2[SSFISO8601_MAX_SIZE] = "";
    SSFPortTick_t unixSysMin = SSFDTIME_UNIX_EPOCH_SYS_MIN;
    SSFPortTick_t unixSysMax = SSFDTIME_UNIX_EPOCH_SYS_MAX;

#if SSF_ISO8601_EXHAUSTIVE_UNIT_TEST == 1
    for(unixSys = unixSysMin; unixSys < unixSysMax; unixSys+=SSF_TICKS_PER_SEC)
    {
        if ((unixSys % (1000000ull * SSF_TICKS_PER_SEC)) == 0)
        {
            printf("unixSys %f%%: %llu %s\r\n", (((unixSys * 1.0) - unixSysMin) / (unixSysMax - unixSysMin)) * 100.0, unixSys, isoStr2);
        }

        SSF_ASSERT(SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr2, sizeof(isoStr2)));
        unixSysOut = SSFDTIME_UNIX_EPOCH_SYS_MAX + 1;
        //printf("isoStr2: %s\r\n", isoStr2);
        SSF_ASSERT(SSFISO8601ISOToUnix(isoStr2, &unixSysOut, &zoneOffsetMin));
        SSF_ASSERT(unixSys == unixSysOut);
    }
#endif /* SSF_ISO8601_EXHAUSTIVE_UNIT_TEST */
}
