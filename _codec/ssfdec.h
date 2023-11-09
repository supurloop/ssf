/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfdec.h                                                                                      */
/* Provides integer to decimal string conversion interface.                                      */
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
#ifndef SSF_DEC_H_INCLUDE
#define SSF_DEC_H_INCLUDE

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

#define SSF_DEC_MAX_STR_LEN (20u)

size_t SSFDecIntToStr(int64_t i, SSFCStrOut_t str, size_t strSize);
size_t SSFDecUIntToStr(uint64_t i, SSFCStrOut_t str, size_t strSize);
size_t SSFDecIntToStrPadded(int64_t i, SSFCStrOut_t str, size_t strSize, uint8_t minFieldWidth,
                            char padChar);
size_t SSFDecUIntToStrPadded(uint64_t i, SSFCStrOut_t str, size_t strSize, uint8_t minFieldWidth,
                             char padChar);

bool SSFDecStrToXInt(SSFCStrIn_t str, int64_t* sval, uint64_t* uval);
#define SSFDecStrToInt(str, val) SSFDecStrToXInt(str, val, NULL)
#define SSFDecStrToUInt(str, val) SSFDecStrToXInt(str, NULL, val)

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_DEC_UNIT_TEST == 1
void SSFDecUnitTest(void);
#endif /* SSF_CONFIG_DEC_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_DEC_H_INCLUDE */

