/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhex.c                                                                                      */
/* Provides hex encoder/decoder interface.                                                       */
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
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ssfhex.h"
#include "ssfport.h"
#include "ssfassert.h"

/* --------------------------------------------------------------------------------------------- */
/* Returns true if binary byte converted successfully to ASCII hex bytes, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFHexBinToByte(char *out, size_t outSize, uint8_t in)
{
    SSF_REQUIRE(out != NULL);

    return (snprintf(out, outSize, "%02X", (unsigned int) in) < 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if ASCII hex bytes converted successfully to binary byte, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFHexByteToBin(char hex0, char hex1, uint8_t *out)
{
    char tmp[3] = "  ";

    SSF_ASSERT(out != NULL);

    tmp[0] = hex0;
    if (!SSFIsHex(tmp[0])) return false;
    tmp[1] = hex1;
    if (!SSFIsHex(tmp[1])) return false;
    *out = (uint8_t)strtol(tmp, NULL, 16);
    return true;
}

bool SSFHexBytesToBin(const char *in, uint8_t *out, size_t outSize, size_t *outLen)
{
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(out != NULL);
    return true;
}

bool SSFHexBinToBytes(const uint8_t *in, size_t inLen, char *out, size_t outSize, size_t *outLen)
{
    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE(out != NULL);
    return true;
}

