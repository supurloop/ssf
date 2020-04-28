/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhex.h                                                                                      */
/* Provides ASCII hex encoder/decoder interface.                                                 */
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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_HEX_H_INCLUDE
#define SSF_HEX_H_INCLUDE

#include <stdint.h>
#include <stdbool.h>

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
typedef enum SSFHexCase
{
    SSF_HEX_CASE_LOWER,
    SSF_HEX_CASE_UPPER,
    SSF_HEX_CASE_MAX,
} SSFHexCase_t;

#define SSFIsHex(h) (((h) >= 'a' && (h) <= 'f') || ((h) >= 'A' && (h) <= 'F') || \
                     ((h) >= '0' && (h) <= '9'))

/* --------------------------------------------------------------------------------------------- */
/* External Interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFHexBinToByte(uint8_t in, char *out, size_t outSize, SSFHexCase_t hcase);
bool SSFHexByteToBin(const char *hex, uint8_t *out);

bool SSFHexBytesToBin(const char *in, size_t inLenLim, uint8_t *out, size_t outSize, 
                      size_t *outLen, bool rev);
bool SSFHexBinToBytes(const uint8_t *in, size_t inLen, char *out, size_t outSize, size_t *outLen,
                      bool rev, SSFHexCase_t hcase);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_HEX_UNIT_TEST == 1
void SSFHexUnitTest(void);
#endif /* SSF_CONFIG_HEX_UNIT_TEST */

#endif /* SSF_HEX_H_INCLUDE */
