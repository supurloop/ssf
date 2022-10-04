/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssffcsum.c                                                                                    */
/* Provides Fletcher checksum interface.                                                         */
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
#include "ssffcsum.h"
#include "ssfport.h"
#include "ssfassert.h"
#include "ssffcsum.h"

/* Mod 255 where 0 <= a <= 510 */
#define MOD255(a) ((((a) > 255) && ((a) != 510)) ? (uint8_t)(((a) >> 8) + ((a) & 0xff)) : \
                                                   ((a) < 255) ? (uint8_t)(a) : (uint8_t)0)

/* --------------------------------------------------------------------------------------------- */
/* Returns the 16-bit Fletcher checksum on inLen bytes of in starting with initial value.        */
/* --------------------------------------------------------------------------------------------- */
uint16_t SSFFCSum16(const uint8_t *in, size_t inLen, uint16_t initial)
{
    uint16_t s1 = initial & 0xff;
    uint16_t s2 = initial >> 8;

    SSF_ASSERT(in != NULL);

    while (inLen)
    {
        s1 = (s1 + *in);
        s1 = MOD255(s1);
        s2 = (s1 + s2);
        s2 = MOD255(s2);
        inLen--;
        in++;
    }
    return (s2 << 8) | s1;
}
