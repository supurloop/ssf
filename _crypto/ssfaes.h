/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfaes.h                                                                                      */
/* Provides AES block interface.                                                                 */
/*                                                                                               */
/* https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf                                      */
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
#ifndef SSFAES_H_INCLUDE
#define SSFAES_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AES_BLOCK_SIZE (16u)

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFAESBlockEncrypt(const uint8_t *pt, size_t ptLen, uint8_t *ct, size_t ctSize,
                        const uint8_t *key, size_t keyLen, uint8_t nr, uint8_t nk);

#define SSFAES128BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen) \
    SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, 10, 4)
#define SSFAES192BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen) \
    SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, 12, 6)
#define SSFAES256BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen) \
    SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, 14, 8)

#define SSFAESXXXBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen) \
    SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, \
                       (6 + (((keyLen) & 0xff) >> 2)), (((keyLen) & 0xff) >> 2))

void SSFAESBlockDecrypt(const uint8_t *ct, size_t ctLen, uint8_t *pt, size_t ptSize,
                        const uint8_t *key, size_t keyLen, uint8_t nr, uint8_t nk);

#define SSFAES128BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen) \
    SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, 10, 4)
#define SSFAES192BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen) \
    SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, 12, 6)
#define SSFAES256BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen) \
    SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, 14, 8)

#define SSFAESXXXBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen) \
    SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, \
                       (6 + (((keyLen) & 0xff) >> 2)), (((keyLen) & 0xff) >> 2))
                       
#if SSF_CONFIG_AES_UNIT_TEST == 1
void SSFAESUnitTest(void);
#endif /* SSF_CONFIG_AES_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSFAES_H_INCLUDE */

