/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfrsa.h                                                                                      */
/* Provides RSA digital signature (PKCS#1 v1.5, PSS) and key generation interface.               */
/*                                                                                               */
/* RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2                               */
/* FIPS 186-4: Digital Signature Standard (DSS)                                                  */
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
/* ssfrsa.c, ssfrsa.h - RSA digital signature and key generation.                                */
/*                                                                                               */
/* If you have any questions, please email me at xxx@xxx, or call me on (XXX) XXX-XXXX.          */
/*                                                                                               */
/* Sincerely,                                                                                    */
/* James Higgins                                                                                 */
/* President                                                                                     */
/* Supurloop Software LLC                                                                        */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_RSA_H_INCLUDE
#define SSF_RSA_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfbn.h"

/* --------------------------------------------------------------------------------------------- */
/* Module enable / compile-time validation                                                       */
/*                                                                                                */
/* SSF_RSA_ANY_ENABLED is the master gate: the module compiles to nothing when no key size is    */
/* enabled (a pure-ECC build can leave ssfrsa.c in the project without dragging RSA in). The API */
/* declarations, sizing constants, and ssfrsa.c implementation are all conditional on it.        */
/* --------------------------------------------------------------------------------------------- */
#if (SSF_RSA_CONFIG_ENABLE_2048 == 1) || \
    (SSF_RSA_CONFIG_ENABLE_3072 == 1) || \
    (SSF_RSA_CONFIG_ENABLE_4096 == 1)
#define SSF_RSA_ANY_ENABLED (1u)
#else
#define SSF_RSA_ANY_ENABLED (0u)
#endif

#if SSF_RSA_ANY_ENABLED == 1

/* The BN module's working width must hold a 2N-limb product for any enabled RSA size. */
#if SSF_RSA_CONFIG_ENABLE_4096 == 1
#if SSF_BN_CONFIG_MAX_BITS < 8192
#error SSF_BN_CONFIG_MAX_BITS must be >= 8192 for RSA-4096 support (2 x 4096-bit modulus).
#endif
#elif SSF_RSA_CONFIG_ENABLE_3072 == 1
#if SSF_BN_CONFIG_MAX_BITS < 6144
#error SSF_BN_CONFIG_MAX_BITS must be >= 6144 for RSA-3072 support (2 x 3072-bit modulus).
#endif
#elif SSF_RSA_CONFIG_ENABLE_2048 == 1
#if SSF_BN_CONFIG_MAX_BITS < 4096
#error SSF_BN_CONFIG_MAX_BITS must be >= 4096 for RSA-2048 support (2 x 2048-bit modulus).
#endif
#endif

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* Maximum key size in bits, derived from the largest enabled key size. */
#if SSF_RSA_CONFIG_ENABLE_4096 == 1
#define SSF_RSA_MAX_KEY_BITS (4096u)
#elif SSF_RSA_CONFIG_ENABLE_3072 == 1
#define SSF_RSA_MAX_KEY_BITS (3072u)
#else
#define SSF_RSA_MAX_KEY_BITS (2048u)
#endif

/* Maximum key size in bytes. */
#define SSF_RSA_MAX_KEY_BYTES (SSF_RSA_MAX_KEY_BITS / 8u)

/* Maximum signature size in bytes (equal to key size). */
#define SSF_RSA_MAX_SIG_SIZE SSF_RSA_MAX_KEY_BYTES

/* Maximum DER-encoded public key size. */
#define SSF_RSA_MAX_PUB_KEY_DER_SIZE (SSF_RSA_MAX_KEY_BYTES + 40u)

/* Maximum DER-encoded private key size. */
#define SSF_RSA_MAX_PRIV_KEY_DER_SIZE (5u * SSF_RSA_MAX_KEY_BYTES + 200u)

/* Hash algorithm selection for RSA padding. */
typedef enum
{
    SSF_RSA_HASH_MIN = -1,
    SSF_RSA_HASH_SHA256,   /* SHA-256 (32-byte hash, for RSA-2048+) */
    SSF_RSA_HASH_SHA384,   /* SHA-384 (48-byte hash, for RSA-3072+) */
    SSF_RSA_HASH_SHA512,   /* SHA-512 (64-byte hash, for RSA-4096) */
    SSF_RSA_HASH_MAX,
} SSFRSAHash_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface: key generation                                                            */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
bool SSFRSAKeyGen(uint16_t bits,
                  uint8_t *privKeyDer, size_t privKeyDerSize, size_t *privKeyDerLen,
                  uint8_t *pubKeyDer, size_t pubKeyDerSize, size_t *pubKeyDerLen);
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN */

/* --------------------------------------------------------------------------------------------- */
/* External interface: key validation                                                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFRSAPubKeyIsValid(const uint8_t *pubKeyDer, size_t pubKeyDerLen);
bool SSFRSAPrivKeyIsValid(const uint8_t *privKeyDer, size_t privKeyDerLen);

/* --------------------------------------------------------------------------------------------- */
/* FIPS 186-4 §B.3 keygen post-condition checks (halfBits = nlen / 2).                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFRSAFipsPrimeDistanceOK(const SSFBN_t *p, const SSFBN_t *q, uint16_t halfBits);
bool SSFRSAFipsDLowerBoundOK(const SSFBN_t *d, uint16_t halfBits);
bool SSFRSAFipsECoprimeOK(const SSFBN_t *e, const SSFBN_t *pMinus1, const SSFBN_t *qMinus1);

/* --------------------------------------------------------------------------------------------- */
/* External interface: PKCS#1 v1.5 signature (RFC 8017 Section 8.2)                              */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
bool SSFRSASignPKCS1(const uint8_t *privKeyDer, size_t privKeyDerLen, SSFRSAHash_t hash,
                     const uint8_t *hashVal, size_t hashLen,
                     uint8_t *sig, size_t sigSize, size_t *sigLen);
bool SSFRSAVerifyPKCS1(const uint8_t *pubKeyDer, size_t pubKeyDerLen, SSFRSAHash_t hash,
                       const uint8_t *hashVal, size_t hashLen,
                       const uint8_t *sig, size_t sigLen);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */

/* --------------------------------------------------------------------------------------------- */
/* External interface: RSA-PSS signature (RFC 8017 Section 8.1)                                  */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
bool SSFRSASignPSS(const uint8_t *privKeyDer, size_t privKeyDerLen, SSFRSAHash_t hash,
                   const uint8_t *hashVal, size_t hashLen,
                   uint8_t *sig, size_t sigSize, size_t *sigLen);
bool SSFRSAVerifyPSS(const uint8_t *pubKeyDer, size_t pubKeyDerLen, SSFRSAHash_t hash,
                     const uint8_t *hashVal, size_t hashLen,
                     const uint8_t *sig, size_t sigLen);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */

#endif /* SSF_RSA_ANY_ENABLED == 1 — end of API gated on at-least-one-size-enabled */

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/*                                                                                               */
/* The declaration is NOT gated on SSF_RSA_ANY_ENABLED — main.c references SSFRSAUnitTest under  */
/* SSF_CONFIG_RSA_UNIT_TEST and would fail to link if the symbol disappeared. ssfrsa_ut.c gates  */
/* the body internally and prints a "skipped" message when no sizes are enabled.                  */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_RSA_UNIT_TEST == 1
void SSFRSAUnitTest(void);
#endif /* SSF_CONFIG_RSA_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_RSA_H_INCLUDE */

