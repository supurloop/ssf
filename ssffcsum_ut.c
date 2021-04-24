/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssffcsum_ut.c                                                                                 */
/* Provides Fletcher checksum interface unit test.                                               */
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
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ssffcsum.h"
#include "ssfassert.h"
#include "ssfport.h"

#if SSF_CONFIG_FCSUM_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on Fletcher checksum external interface.                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFFCSumUnitTest(void)
{
    uint16_t fc;

    SSF_ASSERT_TEST(SSFFCSum16(NULL, 2, SSF_FCSUM_INITIAL));

    SSF_ASSERT(SSFFCSum16((uint8_t *)"\x01\x02", 2, SSF_FCSUM_INITIAL) == 0x0403);
    fc = SSFFCSum16((uint8_t *)"\x01", 1, SSF_FCSUM_INITIAL);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"\x02", 1, fc) == 0x0403);

    SSF_ASSERT(SSFFCSum16((uint8_t *)"abcde", 5, SSF_FCSUM_INITIAL) == 0xC8F0);
    fc = SSFFCSum16((uint8_t *)"a", 1, SSF_FCSUM_INITIAL);
    fc = SSFFCSum16((uint8_t *)"bcd", 3, fc);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"e", 1, fc) == 0xC8F0);

    SSF_ASSERT(SSFFCSum16((uint8_t *)"abcdef", 6, SSF_FCSUM_INITIAL) == 0x2057);
    fc = SSFFCSum16((uint8_t *)"a", 1, SSF_FCSUM_INITIAL);
    fc = SSFFCSum16((uint8_t *)"bcd", 3, fc);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"ef", 2, fc) == 0x2057);

    SSF_ASSERT(SSFFCSum16((uint8_t *)"abcdefgh", 8, SSF_FCSUM_INITIAL) == 0x0627);
    fc = SSFFCSum16((uint8_t *)"a", 1, SSF_FCSUM_INITIAL);
    fc = SSFFCSum16((uint8_t *)"bcd", 3, fc);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"efgh", 4, fc) == 0x0627);

    SSF_ASSERT(SSFFCSum16((uint8_t *)"\x01\xfe", 2, SSF_FCSUM_INITIAL) == 0x0100);
    SSF_ASSERT(SSFFCSum16((uint8_t *)"\xff", 1, SSF_FCSUM_INITIAL) == 0x0000);
}
#endif /* SSF_CONFIG_FCSUM_UNIT_TEST */
