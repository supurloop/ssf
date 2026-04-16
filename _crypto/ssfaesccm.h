/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfaesccm.h                                                                                   */
/* Provides AES-CCM (Counter with CBC-MAC) authenticated encryption (RFC 3610, SP 800-38C).     */
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
#ifndef SSF_AESCCM_H_INCLUDE
#define SSF_AESCCM_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Limitations                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* Nonce length must be between 7 and 13 bytes (L = 15 - nonceLen, 2 <= L <= 8).                 */
/* Tag length must be 4, 6, 8, 10, 12, 14, or 16 bytes.                                         */
/* Key length must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.                        */
/* Maximum plaintext/ciphertext length is limited to 2^(8*L) - 1 bytes.                          */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_AESCCM_BLOCK_SIZE (16u)

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Encrypt and authenticate.                                                                     */
/* Produces ciphertext (same length as plaintext) and an authentication tag.                     */
void SSFAESCCMEncrypt(const uint8_t *pt, size_t ptLen,
                      const uint8_t *nonce, size_t nonceLen,
                      const uint8_t *aad, size_t aadLen,
                      const uint8_t *key, size_t keyLen,
                      uint8_t *tag, size_t tagSize,
                      uint8_t *ct, size_t ctSize);

/* Decrypt and verify.                                                                           */
/* Returns true if the tag is valid. On failure, plaintext is zeroed.                            */
bool SSFAESCCMDecrypt(const uint8_t *ct, size_t ctLen,
                      const uint8_t *nonce, size_t nonceLen,
                      const uint8_t *aad, size_t aadLen,
                      const uint8_t *key, size_t keyLen,
                      const uint8_t *tag, size_t tagLen,
                      uint8_t *pt, size_t ptSize);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_AESCCM_UNIT_TEST == 1
void SSFAESCCMUnitTest(void);
#endif /* SSF_CONFIG_AESCCM_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_AESCCM_H_INCLUDE */
