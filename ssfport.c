/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfport.c                                                                                     */
/* Provides port interface.                                                                      */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#include <stdio.h>
#include <stdlib.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Variables.                                                                                    */
/* --------------------------------------------------------------------------------------------- */
void *ssfUnused;

#if SSF_CONFIG_UNIT_TEST == 1
jmp_buf ssfUnitTestMark;
jmp_buf ssfUnitTestZeroMark;
int ssfUnitTestJmpRet;
#endif /* SSF_CONFIG_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Never returns (except for unit testing), reports assertion failure.                           */
/* --------------------------------------------------------------------------------------------- */
#ifdef _WIN32
__declspec(noreturn)
#endif /* _WIN32 */
void SSFPortAssert(const char *file, unsigned int line)
{
#if SSF_CONFIG_UNIT_TEST == 1
    if (memcmp(ssfUnitTestMark, ssfUnitTestZeroMark, sizeof(ssfUnitTestMark)) != 0)
    { longjmp(ssfUnitTestMark, -1); } else
#endif /* SSF_CONFIG_UNIT_TEST */
    { printf("SSF Assertion: %s:%u\r\n", file, line); }
    exit(1);
}

#ifndef _WIN32
SSFPortTick_t SSFPortGetTick64(void)
{
    struct timespec ticks;
    clock_gettime(CLOCK_MONOTONIC, &ticks);
    return (SSFPortTick_t) ((((SSFPortTick_t)ticks.tv_sec) * 1000) + (ticks.tv_nsec / 1000000));
}
#endif /* _WIN32 */

