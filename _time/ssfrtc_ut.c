/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfrtc_ut.c                                                                                   */
/* Provides unit test for ssfrtc interface.                                                      */
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
#include "ssfport.h"
#include "ssfdtime.h"
#include "ssfrtc.h"

/* --------------------------------------------------------------------------------------------- */
/* Unit tests the ssfrtc interface.                                                              */
/* --------------------------------------------------------------------------------------------- */
void SSFRTCUnitTest(void)
{
    SSFPortTick_t rtcSys;
    SSFPortTick_t rtcExpected;

    /* Assertion tests */

    /* Test SSFRTCInit() SSFRTCDeInit() */
    SSF_ASSERT(SSFRTCInit());
    SSF_ASSERT_TEST(SSFRTCInit());
    SSFRTCDeInit();
    SSF_ASSERT_TEST(SSFRTCDeInit());
    SSF_ASSERT(SSFRTCInit());

    /* Test SSFRTCSet() */
    SSFRTCDeInit();
    SSF_ASSERT(SSFRTCInit());
    _ssfRTCSimUnixSec = SSFDTIME_UNIX_EPOCH_SEC_MAX + 1;
    SSF_ASSERT(SSFRTCSet(SSFDTIME_UNIX_EPOCH_SEC_MIN));
    SSF_ASSERT(_ssfRTCSimUnixSec == SSFDTIME_UNIX_EPOCH_SEC_MIN);
    _ssfRTCSimUnixSec = SSFDTIME_UNIX_EPOCH_SEC_MAX + 1;
    SSF_ASSERT(SSFRTCSet(SSFDTIME_UNIX_EPOCH_SEC_MAX));
    SSF_ASSERT(_ssfRTCSimUnixSec == SSFDTIME_UNIX_EPOCH_SEC_MAX);
    SSF_ASSERT(SSFRTCSet(SSFDTIME_UNIX_EPOCH_SEC_MAX + 1) == false);

    /* Test SSFRTCGetUnixNow() */
    SSFRTCDeInit();
    SSF_ASSERT_TEST(SSFRTCGetUnixNow(&rtcSys));
    _ssfRTCSimUnixSec = SSFDTIME_UNIX_EPOCH_SEC_MIN;
    SSF_ASSERT(SSFRTCInit());
    rtcExpected = SSFDTIME_UNIX_EPOCH_SEC_MIN * SSF_TICKS_PER_SEC;
    SSF_ASSERT(SSFRTCGetUnixNow(&rtcSys));
    SSF_ASSERT((rtcSys - rtcExpected) < SSF_TICKS_PER_SEC);
    SSF_ASSERT(SSFRTCSet(SSFDTIME_UNIX_EPOCH_SEC_MAX));
    rtcExpected = SSFDTIME_UNIX_EPOCH_SEC_MAX * SSF_TICKS_PER_SEC;
    SSF_ASSERT(SSFRTCGetUnixNow(&rtcSys));
    SSF_ASSERT((rtcSys - rtcExpected) < SSF_TICKS_PER_SEC);
}
