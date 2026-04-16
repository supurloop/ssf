/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfecdsa.h                                                                                    */
/* Provides ECDSA digital signature and ECDH key agreement interface.                            */
/*                                                                                               */
/* FIPS 186-4: Digital Signature Standard (DSS)                                                  */
/* RFC 6979: Deterministic Usage of the DSA and ECDSA                                            */
/* NIST SP 800-56A Rev. 3: Pair-Wise Key-Establishment Using Discrete Logarithm Cryptography    */
/* SEC 1 v2: Elliptic Curve Cryptography                                                        */
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
/* ssfecdsa.c, ssfecdsa.h - ECDSA digital signature and ECDH key agreement.                      */
/*                                                                                               */
/* If you have any questions, please email me at xxx@xxx, or call me on (XXX) XXX-XXXX.          */
/*                                                                                               */
/* Sincerely,                                                                                    */
/* James Higgins                                                                                 */
/* President                                                                                     */
/* Supurloop Software LLC                                                                        */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_ECDSA_H_INCLUDE
#define SSF_ECDSA_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfec.h"

/* --------------------------------------------------------------------------------------------- */
/* Limitations                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* Signing uses deterministic nonce generation per RFC 6979. This eliminates the need for a      */
/* cryptographic random number source during signing and prevents nonce-reuse attacks.            */
/* The hash algorithm is selected automatically: SHA-256 for P-256, SHA-384 for P-384.           */
/* Signatures are DER-encoded per SEC 1 / X.690: SEQUENCE { INTEGER r, INTEGER s }.              */
/* Maximum DER signature size is 2 + 2 + 33 + 2 + 33 = 72 bytes for P-256, and                  */
/* 2 + 2 + 49 + 2 + 49 = 104 bytes for P-384 (extra byte when high bit set).                    */
/* Public keys are SEC 1 uncompressed format: 0x04 || X || Y.                                    */
/* Private keys are big-endian unsigned integers of the curve's coordinate byte length.          */
/* ECDH shared secret output is the raw x-coordinate of the shared point; use SSFHKDF to         */
/* derive keying material from it.                                                               */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */

/* Maximum private key size in bytes. */
#define SSF_ECDSA_MAX_PRIV_KEY_SIZE SSF_EC_MAX_COORD_BYTES

/* Maximum public key size in bytes (SEC 1 uncompressed). */
#define SSF_ECDSA_MAX_PUB_KEY_SIZE SSF_EC_MAX_ENCODED_SIZE

/* Maximum DER-encoded signature size in bytes. */
/* SEQUENCE(2) + INTEGER(2 + coordBytes + 1) + INTEGER(2 + coordBytes + 1) */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
#define SSF_ECDSA_MAX_SIG_SIZE (104u)
#elif SSF_EC_CONFIG_ENABLE_P256 == 1
#define SSF_ECDSA_MAX_SIG_SIZE (72u)
#endif

/* Maximum ECDH shared secret size in bytes (raw x-coordinate). */
#define SSF_ECDH_MAX_SECRET_SIZE SSF_EC_MAX_COORD_BYTES

/* --------------------------------------------------------------------------------------------- */
/* External interface: key generation                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Generate an ECDSA key pair.                                                                   */
/* privKey receives the private key as a big-endian integer (coordBytes long).                   */
/* pubKey receives the public key in SEC 1 uncompressed format (1 + 2*coordBytes).               */
/* pubKeyLen receives the actual public key length written.                                      */
/* Requires a seeded SSFPRNGContext_t for random number generation.                              */
/* Returns false on failure.                                                                     */
bool SSFECDSAKeyGen(SSFECCurve_t curve,
                    uint8_t *privKey, size_t privKeySize,
                    uint8_t *pubKey, size_t pubKeySize, size_t *pubKeyLen);

/* Compute the public key from a private key.                                                    */
/* privKey is the private key as a big-endian integer.                                           */
/* pubKey receives the public key in SEC 1 uncompressed format.                                  */
/* pubKeyLen receives the actual public key length written.                                      */
/* Returns false if the private key is invalid (not in [1, n-1]).                                */
bool SSFECDSAPubKeyFromPrivKey(SSFECCurve_t curve,
                               const uint8_t *privKey, size_t privKeyLen,
                               uint8_t *pubKey, size_t pubKeySize, size_t *pubKeyLen);

/* Validate a public key. Returns true if the key is a valid point on the curve.                 */
bool SSFECDSAPubKeyIsValid(SSFECCurve_t curve, const uint8_t *pubKey, size_t pubKeyLen);

/* --------------------------------------------------------------------------------------------- */
/* External interface: ECDSA signing                                                             */
/* --------------------------------------------------------------------------------------------- */

/* Sign a message hash using ECDSA with deterministic nonce (RFC 6979).                          */
/* hash is the message hash (SHA-256 for P-256, SHA-384 for P-384).                              */
/* hashLen must be the hash output size for the curve (32 for P-256, 48 for P-384).              */
/* privKey is the private key as a big-endian integer (coordBytes).                              */
/* sig receives the DER-encoded signature: SEQUENCE { INTEGER r, INTEGER s }.                    */
/* sigLen receives the actual signature length written.                                          */
/* Returns false on failure.                                                                     */
bool SSFECDSASign(SSFECCurve_t curve,
                  const uint8_t *privKey, size_t privKeyLen,
                  const uint8_t *hash, size_t hashLen,
                  uint8_t *sig, size_t sigSize, size_t *sigLen);

/* --------------------------------------------------------------------------------------------- */
/* External interface: ECDSA verification                                                        */
/* --------------------------------------------------------------------------------------------- */

/* Verify an ECDSA signature over a message hash.                                                */
/* hash is the message hash (SHA-256 for P-256, SHA-384 for P-384).                              */
/* hashLen must be the hash output size for the curve.                                           */
/* pubKey is the public key in SEC 1 uncompressed format.                                        */
/* sig is the DER-encoded signature.                                                             */
/* Returns true if the signature is valid.                                                       */
bool SSFECDSAVerify(SSFECCurve_t curve,
                    const uint8_t *pubKey, size_t pubKeyLen,
                    const uint8_t *hash, size_t hashLen,
                    const uint8_t *sig, size_t sigLen);

/* --------------------------------------------------------------------------------------------- */
/* External interface: ECDH key agreement                                                        */
/* --------------------------------------------------------------------------------------------- */

/* Compute an ECDH shared secret.                                                                */
/* privKey is the local private key as a big-endian integer.                                     */
/* peerPubKey is the peer's public key in SEC 1 uncompressed format.                             */
/* secret receives the shared secret (x-coordinate of the shared point, big-endian).             */
/* secretLen receives the actual secret length written (coordBytes for the curve).               */
/* The peer's public key is validated before use. Returns false on any failure.                   */
/* The raw shared secret should be processed through SSFHKDF for key derivation.                 */
bool SSFECDHComputeSecret(SSFECCurve_t curve,
                          const uint8_t *privKey, size_t privKeyLen,
                          const uint8_t *peerPubKey, size_t peerPubKeyLen,
                          uint8_t *secret, size_t secretSize, size_t *secretLen);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
void SSFECDSAUnitTest(void);
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_ECDSA_H_INCLUDE */
