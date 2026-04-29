/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfchacha20poly1305.h                                                                         */
/* Provides ChaCha20-Poly1305 AEAD interface (RFC 7539).                                         */
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
#ifndef SSFCHACHA20POLY1305_H_INCLUDE
#define SSFCHACHA20POLY1305_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_CCP_KEY_SIZE   (32u)
#define SSF_CCP_NONCE_SIZE (12u)
#define SSF_CCP_TAG_SIZE   (16u)

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFChaCha20Poly1305Encrypt(const uint8_t *pt, size_t ptLen, const uint8_t *iv, size_t ivLen,
                                const uint8_t *auth, size_t authLen, const uint8_t *key,
                                size_t keyLen, uint8_t *tag, size_t tagSize, uint8_t *ct,
                                size_t ctSize);

bool SSFChaCha20Poly1305Decrypt(const uint8_t *ct, size_t ctLen, const uint8_t *iv, size_t ivLen,
                                const uint8_t *auth, size_t authLen, const uint8_t *key,
                                size_t keyLen, const uint8_t *tag, size_t tagLen, uint8_t *pt,
                                size_t ptSize);

#if SSF_CONFIG_CCP_UNIT_TEST == 1
void SSFChaCha20Poly1305UnitTest(void);
#endif /* SSF_CONFIG_CCP_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSFCHACHA20POLY1305_H_INCLUDE */

