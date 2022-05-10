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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
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
/* ssfaes.c, ssfaes.h - AES block encryption.                                                    */
/* ssfaesgcm.c, ssfaesgcm.h - AES-GCM authenticated encryption.                                  */
/*                                                                                               */
/* If you have any questions, please email me at xxx@xxx, or call me on (XXX) XXX-XXXX.          */
/*                                                                                               */
/* Sincerely,                                                                                    */
/* James Higgins                                                                                 */
/* President                                                                                     */
/* Supurloop Software LLC                                                                        */
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

