/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsha2.h                                                                                     */
/* Provides SHA2 interface: SHA256, SHA224, SHA512, SHA384, SHA512/224, or SHA512/256            */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2021 Supurloop Software LLC                                                         */
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
#ifndef SSF_SHA2_H_INCLUDE
#define SSF_SHA2_H_INCLUDE

#include <stdio.h>
#include <stdint.h>
#include "ssfport.h"

#define SSF_SHA2_224_BYTE_SIZE (28u)
#define SSF_SHA2_256_BYTE_SIZE (32u)
#define SSF_SHA2_512_BYTE_SIZE (64u)
#define SSF_SHA2_384_BYTE_SIZE (48u)
#define SSF_SHA2_512_224_BYTE_SIZE (28u)
#define SSF_SHA2_512_256_BYTE_SIZE (32u)

/* --------------------------------------------------------------------------------------------- */
/* External Interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFSHA2_32(const uint8_t* in, uint32_t inLen, uint8_t* out, uint32_t outSize,
                uint16_t hashBitSize);
#define SSFSHA256(in, inLen, out, outSize) SSFSHA2_32(in, inLen, out, outSize, 256)
#define SSFSHA224(in, inLen, out, outSize) SSFSHA2_32(in, inLen, out, outSize, 224)

void SSFSHA2_64(const uint8_t* in, uint32_t inLen, uint8_t* out, uint32_t outSize,
    uint16_t hashBitSize, uint16_t truncationBitSize);

#define SSFSHA512(in, inLen, out, outSize) SSFSHA2_64(in, inLen, out, outSize, 512, 0)
#define SSFSHA512_256(in, inLen, out, outSize) SSFSHA2_64(in, inLen, out, outSize, 512, 256)
#define SSFSHA512_224(in, inLen, out, outSize) SSFSHA2_64(in, inLen, out, outSize, 512, 224)
#define SSFSHA384(in, inLen, out, outSize) SSFSHA2_64(in, inLen, out, outSize, 384, 0)

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_SHA2_UNIT_TEST == 1
void SSFSHA2UnitTest(void);
#endif /* SSF_CONFIG_SHA2_UNIT_TEST */

#endif /* SSF_SHA2_H_INCLUDE */
