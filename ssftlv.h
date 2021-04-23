/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftlv.h                                                                                      */
/* Provides encode/decoder interface for TAG/LENGTH/VALUE (aka TLV) data structures.             */
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
#ifndef SSFTLV_H_INCLUDE
#define SSFTLV_H_INCLUDE

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

#if SSF_TLV_ENABLE_FIXED_MODE == 1
typedef uint8_t SSFTLVVar_t;
#else
typedef uint32_t SSFTLVVar_t;
#endif

typedef struct SSFTLV
{
    uint8_t* buf;
    uint32_t bufSize;
    uint32_t bufLen;
} SSFTLV_t;

#define SSFTLVGet(tlv, tag, instance, val, valSize, valLen) \
       SSFTLVRead(tlv, tag, instance, val, valSize, NULL, valLen)
#define SSFTLVFind(tlv, tag, instance, valPtr, valLen) \
        SSFTLVRead(tlv, tag, instance, NULL, 0, valPtr, valLen)

void SSFTLVInit(SSFTLV_t* tlv, uint8_t* buf, uint32_t bufSize, uint32_t bufLen);
bool SSFTLVPut(SSFTLV_t* tlv, SSFTLVVar_t tag, const uint8_t* val, SSFTLVVar_t valLen);
bool SSFTLVRead(const SSFTLV_t* tlv, SSFTLVVar_t tag, uint16_t instance, uint8_t* val,
                uint32_t valSize, uint8_t** valPtr, SSFTLVVar_t* valLen);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_TLV_UNIT_TEST == 1
void SSFTLVUnitTest(void);
#endif /* SSF_CONFIG_TLV_UNIT_TEST */

#endif /* SSFTLV_H_INCLUDE */
