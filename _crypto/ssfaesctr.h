/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfaesctr.h                                                                                   */
/* Provides AES-CTR confidentiality-only stream cipher per NIST SP 800-38A Sec. 6.5.             */
/*                                                                                               */
/* https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf                 */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
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
#ifndef SSF_AESCTR_H_INCLUDE
#define SSF_AESCTR_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "ssfport.h"
#include "ssfaes.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AESCTR_KEY_MAX_SIZE (32u)               /* Holds AES-128 / 192 / 256 keys. */
#define SSF_AESCTR_BLOCK_SIZE   SSF_AES_BLOCK_SIZE  /* Always 16. */

typedef struct SSFAESCTRContext
{
    uint8_t  key[SSF_AESCTR_KEY_MAX_SIZE];
    size_t   keyLen;                                /* 16, 24, or 32. */
    uint8_t  counter[SSF_AESCTR_BLOCK_SIZE];        /* Current 128-bit counter value. */
    uint8_t  ks[SSF_AESCTR_BLOCK_SIZE];             /* Buffered keystream. */
    size_t   ksOff;                                 /* Index of next unused keystream byte. */
    uint32_t magic;
} SSFAESCTRContext_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFAESCTRBegin(SSFAESCTRContext_t *ctx, const uint8_t *key, size_t keyLen, const uint8_t *iv);
void SSFAESCTRCrypt(SSFAESCTRContext_t *ctx, const uint8_t *in, uint8_t *out, size_t len);
void SSFAESCTRDeInit(SSFAESCTRContext_t *ctx);
void SSFAESCTR(const uint8_t *key, size_t keyLen, const uint8_t *iv, const uint8_t *in,
               uint8_t *out, size_t len);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_AESCTR_UNIT_TEST == 1
void SSFAESCTRUnitTest(void);
#endif /* SSF_CONFIG_AESCTR_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_AESCTR_H_INCLUDE */

