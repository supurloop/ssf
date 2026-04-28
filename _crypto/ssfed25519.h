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

/* --------------------------------------------------------------------------------------------- */
/* Per US export restrictions for open source cryptographic software the Department of Commerce  */
/* has been notified of the inclusion of cryptographic software in the SSF. This is a copy of    */
/* the notice emailed on Nov 11, 2021:                                                           */
/* --------------------------------------------------------------------------------------------- */
/* Unrestricted Encryption Source Code Notification                                              */
/* To : crypt@bis.doc.gov; enc@nsa.gov                                                           */
/* Subject : Addition to SSF Source Code                                                         */
/* Department of Commerce                                                                        */
/* Bureau of Export Administration                                                               */
/* Office of Strategic Trade and Foreign Policy Controls                                         */
/* 14th Street and Pennsylvania Ave., N.W.                                                       */
/* Room 2705                                                                                     */
/* Washington, DC 20230                                                                          */
/* Re: Unrestricted Encryption Source Code Notification Commodity : Addition to SSF Source Code  */
/*                                                                                               */
/* Dear Sir / Madam,                                                                             */
/*                                                                                               */
/* Pursuant to paragraph(e)(1) of Part 740.13 of the U.S.Export Administration Regulations       */
/* ("EAR", 15 CFR Part 730 et seq.), we are providing this written notification of the Internet  */
/* location of the unrestricted, publicly available Source Code being added to the Small System  */
/* Framework (SSF) Source Code. SSF Source Code is a free embedded system application framework  */
/* developed by Supurloop Software LLC in the Public Interest. This notification serves as a     */
/* notification of an addition of new software to the SSF archive. This archive is updated from  */
/* time to time, but its location is constant. Therefore this notification serves as a one-time  */
/* notification for subsequent updates that may occur in the future to the software covered by   */
/* this notification. Such updates may add or enhance cryptographic functionality of the SSF.    */
/* The Internet location for the SSF Source Code is: https://github.com/supurloop/ssf            */
/*                                                                                               */
/* This site may be mirrored to a number of other sites located outside the United States.       */
/*                                                                                               */
/* The following software is being added to the SSF archive:                                     */
/*                                                                                               */
/* ssfed25519.c, ssfed25519.h - Ed25519 digital signature (RFC 8032).                            */
/*                                                                                               */
/* If you have any questions, please email me at xxx@xxx, or call me on (XXX) XXX-XXXX.          */
/*                                                                                               */
/* Sincerely,                                                                                    */
/* James Higgins                                                                                 */
/* President                                                                                     */
/* Supurloop Software LLC                                                                        */
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
/* Limitations                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* Ed25519 pure mode only (no pre-hashing / Ed25519ctx / Ed25519ph).                             */
/* Seed-based API: the 32-byte seed is the secret; the expanded key is derived internally.       */
/* Signing is deterministic per RFC 8032: the nonce is derived from SHA-512(prefix || message).  */
/* Self-contained: dedicated GF(2^255-19) field arithmetic; no ssfbn dependency.                 */
/* Requires SHA-512 from ssfsha2 module and the platform entropy source for SSFEd25519KeyGen.    */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_ED25519_SEED_SIZE     (32u)
#define SSF_ED25519_PUB_KEY_SIZE  (32u)
#define SSF_ED25519_SIG_SIZE      (64u)

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Generate an Ed25519 key pair.                                                                 */
/* seed receives 32 random bytes. pubKey receives the derived 32-byte public key.                */
/* Requires platform entropy (/dev/urandom on POSIX).                                            */
bool SSFEd25519KeyGen(uint8_t seed[SSF_ED25519_SEED_SIZE],
                      uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE]);

/* Derive public key from a 32-byte seed.                                                        */
void SSFEd25519PubKeyFromSeed(const uint8_t seed[SSF_ED25519_SEED_SIZE],
                               uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE]);

/* Sign a message. Ed25519 signs the raw message (hashing is internal per RFC 8032).             */
/* Returns true on success; returns false if the verify-after-sign check rejects the produced     */
/* signature. A false return indicates either a fault during the private operation or a pubKey    */
/* that does not correspond to seed. On false, sig is wiped to all zeros.                         */
bool SSFEd25519Sign(const uint8_t seed[SSF_ED25519_SEED_SIZE],
                    const uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE],
                    const uint8_t *msg, size_t msgLen,
                    uint8_t sig[SSF_ED25519_SIG_SIZE]);

/* Verify a signature. Returns true if valid, false otherwise.                                   */
bool SSFEd25519Verify(const uint8_t pubKey[SSF_ED25519_PUB_KEY_SIZE],
                      const uint8_t *msg, size_t msgLen,
                      const uint8_t sig[SSF_ED25519_SIG_SIZE]);

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
