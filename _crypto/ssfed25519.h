/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfed25519.h                                                                                  */
/* Provides Ed25519 digital signature interface (RFC 8032).                                      */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2024 Supurloop Software LLC                                                         */
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
#ifndef SSF_ED25519_H_INCLUDE
#define SSF_ED25519_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_ED25519_SEED_SIZE     (32u)
#define SSF_ED25519_PUB_KEY_SIZE  (32u)
#define SSF_ED25519_SIG_SIZE      (64u)

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFEd25519KeyGen(uint8_t seed[SSF_ED25519_SEED_SIZE], uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE]);
void SSFEd25519PubKeyFromSeed(const uint8_t seed[SSF_ED25519_SEED_SIZE],
                              uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE]);
bool SSFEd25519Sign(const uint8_t seed[SSF_ED25519_SEED_SIZE],
                    const uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE], const uint8_t *msg,
                    size_t msgLen, uint8_t sig[SSF_ED25519_SIG_SIZE]);
bool SSFEd25519Verify(const uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE], const uint8_t *msg,
                      size_t msgLen, const uint8_t sig[SSF_ED25519_SIG_SIZE]);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_ED25519_UNIT_TEST == 1
void SSFEd25519UnitTest(void);
#endif /* SSF_CONFIG_ED25519_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_ED25519_H_INCLUDE */

