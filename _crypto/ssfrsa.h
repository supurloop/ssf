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
/* Limitations                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* Supported key sizes: 2048, 3072, 4096 bits (limited by SSF_BN_CONFIG_MAX_BITS).               */
/* Public exponent is fixed at e = 65537 (F4).                                                   */
/* Key generation requires platform entropy (/dev/urandom on POSIX).                             */
/* Key generation is computationally expensive: seconds on modern CPUs, minutes on embedded.     */
/* Private key operations use CRT for ~4x speedup over direct modular exponentiation.            */
/* Keys are DER-encoded in PKCS#1 format (RSAPublicKey, RSAPrivateKey).                          */
/* PSS salt length equals the hash output length (per TLS 1.3 requirement).                      */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* Maximum key size in bytes. */
#define SSF_RSA_MAX_KEY_BYTES (SSF_BN_CONFIG_MAX_BITS / 8u)

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

/* Generate an RSA key pair.                                                                     */
/* bits must be 2048, 3072, or 4096.                                                             */
/* privKeyDer receives the PKCS#1 RSAPrivateKey DER encoding.                                    */
/* pubKeyDer receives the PKCS#1 RSAPublicKey DER encoding.                                      */
/* Returns false on failure.                                                                     */
bool SSFRSAKeyGen(uint16_t bits,
                  uint8_t *privKeyDer, size_t privKeyDerSize, size_t *privKeyDerLen,
                  uint8_t *pubKeyDer, size_t pubKeyDerSize, size_t *pubKeyDerLen);

#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN */

/* --------------------------------------------------------------------------------------------- */
/* External interface: key validation                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Validate a DER-encoded RSA public key. Returns true if the DER parses, the modulus has a      */
/* supported bit length (2048, 3072, or 4096), the public exponent is at least 65537 and odd,    */
/* and 1 < e < n. Does not verify that n is actually a product of two primes (which would        */
/* require factoring); a deliberately weak modulus with a small factor still passes here.        */
bool SSFRSAPubKeyIsValid(const uint8_t *pubKeyDer, size_t pubKeyDerLen);

/* Validate a DER-encoded PKCS#1 RSAPrivateKey. Returns true if the DER parses with version=0,   */
/* the public-side fields satisfy SSFRSAPubKeyIsValid, and the algebraic CRT consistency holds:  */
/*   n == p * q                                                                                  */
/*   dp == d mod (p - 1)                                                                         */
/*   dq == d mod (q - 1)                                                                         */
/*   qInv * q ≡ 1 (mod p)                                                                        */
/* These checks confirm the key is internally consistent — a tampered private key (corrupted     */
/* dp/dq/qInv, or an attempt to swap p and q labels) fails here. Does not verify that p and q    */
/* are actually prime or check FIPS 186-4 §B.3 keygen-side bounds.                                */
bool SSFRSAPrivKeyIsValid(const uint8_t *privKeyDer, size_t privKeyDerLen);

/* --------------------------------------------------------------------------------------------- */
/* FIPS 186-4 §B.3 keygen post-condition checks. Used internally by SSFRSAKeyGen and exposed for */
/* unit testing and (future) imported-key validation. halfBits = nlen / 2 (i.e., 1024 for RSA-   */
/* 2048, 1536 for RSA-3072, 2048 for RSA-4096).                                                  */
/* --------------------------------------------------------------------------------------------- */

/* §B.3.3 step 5.4: returns true if |p - q| > 2^(halfBits - 100). Defends against Fermat-style   */
/* factorization when the two primes happen to be unusually close.                                */
bool SSFRSAFipsPrimeDistanceOK(const SSFBN_t *p, const SSFBN_t *q, uint16_t halfBits);

/* §B.3.1: returns true if d > 2^halfBits. Defends against Wiener's continued-fraction attack    */
/* on small private exponents.                                                                    */
bool SSFRSAFipsDLowerBoundOK(const SSFBN_t *d, uint16_t halfBits);

/* Returns true if gcd(e, p-1) == 1 AND gcd(e, q-1) == 1. Both must hold for                     */
/* d = e^(-1) mod λ(n) to exist; the modular inverse fails otherwise.                            */
bool SSFRSAFipsECoprimeOK(const SSFBN_t *e, const SSFBN_t *pMinus1, const SSFBN_t *qMinus1);

/* --------------------------------------------------------------------------------------------- */
/* External interface: PKCS#1 v1.5 signature (RFC 8017 Section 8.2)                              */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1

/* Sign a message hash using RSASSA-PKCS1-v1_5. Deterministic (no randomness needed).            */
/* hashVal is the pre-computed message hash. hashLen must match the hash algorithm's output size. */
/* sig receives the signature (keyBytes long). sigLen receives the actual length written.         */
bool SSFRSASignPKCS1(const uint8_t *privKeyDer, size_t privKeyDerLen,
                     SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                     uint8_t *sig, size_t sigSize, size_t *sigLen);

/* Verify an RSASSA-PKCS1-v1_5 signature.                                                       */
bool SSFRSAVerifyPKCS1(const uint8_t *pubKeyDer, size_t pubKeyDerLen,
                       SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                       const uint8_t *sig, size_t sigLen);

#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */

/* --------------------------------------------------------------------------------------------- */
/* External interface: RSA-PSS signature (RFC 8017 Section 8.1)                                  */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1

/* Sign a message hash using RSASSA-PSS with random salt (salt length = hash length).            */
bool SSFRSASignPSS(const uint8_t *privKeyDer, size_t privKeyDerLen,
                   SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                   uint8_t *sig, size_t sigSize, size_t *sigLen);

/* Verify an RSASSA-PSS signature.                                                              */
bool SSFRSAVerifyPSS(const uint8_t *pubKeyDer, size_t pubKeyDerLen,
                     SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                     const uint8_t *sig, size_t sigLen);

#endif /* SSF_RSA_CONFIG_ENABLE_PSS */

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_RSA_UNIT_TEST == 1
void SSFRSAUnitTest(void);
#endif /* SSF_CONFIG_RSA_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_RSA_H_INCLUDE */
