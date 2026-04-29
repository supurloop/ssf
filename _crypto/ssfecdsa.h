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
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */

/* Maximum private key size in bytes. */
#define SSF_ECDSA_MAX_PRIV_KEY_SIZE SSF_EC_MAX_COORD_BYTES

/* Maximum public key size in bytes (SEC 1 uncompressed). */
#define SSF_ECDSA_MAX_PUB_KEY_SIZE SSF_EC_MAX_ENCODED_SIZE

/* Maximum DER-encoded signature size in bytes (SEQUENCE + 2 INTEGERs with optional sign byte). */
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
bool SSFECDSAKeyGen(SSFECCurve_t curve, uint8_t *privKey, size_t privKeySize, uint8_t *pubKey,
                    size_t pubKeySize, size_t *pubKeyLen);
bool SSFECDSAPubKeyFromPrivKey(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                               uint8_t *pubKey, size_t pubKeySize, size_t *pubKeyLen);
bool SSFECDSAPubKeyIsValid(SSFECCurve_t curve, const uint8_t *pubKey, size_t pubKeyLen);

/* --------------------------------------------------------------------------------------------- */
/* External interface: ECDSA signing                                                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSASign(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                  const uint8_t *hash, size_t hashLen, uint8_t *sig, size_t sigSize,
                  size_t *sigLen);

/* --------------------------------------------------------------------------------------------- */
/* External interface: ECDSA verification                                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSAVerify(SSFECCurve_t curve, const uint8_t *pubKey, size_t pubKeyLen,
                    const uint8_t *hash, size_t hashLen, const uint8_t *sig, size_t sigLen);

/* --------------------------------------------------------------------------------------------- */
/* External interface: ECDH key agreement                                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDHComputeSecret(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                          const uint8_t *peerPubKey, size_t peerPubKeyLen, uint8_t *secret,
                          size_t secretSize, size_t *secretLen);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
void SSFECDSAUnitTest(void);

/* Test wrapper around the internal projective verify check (synthetic R). */
bool _SSFECDSAVerifyCheckRForTest(SSFECCurve_t curve, const SSFECPoint_t *R, const SSFBN_t *r);

/* Test-only exit hooks fired AFTER zeroization, BEFORE return; NULL in production. */
extern void (*_SSFECDSASignTestExitHook)(void *ctx,
                                         const SSFBN_t *d, const SSFBN_t *k, const SSFBN_t *e,
                                         const SSFBN_t *kInv, const SSFBN_t *tmp,
                                         const SSFECPoint_t *R,
                                         const SSFBN_t *Rx, const SSFBN_t *Ry);
extern void *_SSFECDSASignTestExitHookCtx;

extern void (*_SSFECDSAECDHTestExitHook)(void *ctx,
                                         const SSFBN_t *d,
                                         const SSFECPoint_t *S,
                                         const SSFBN_t *Sx, const SSFBN_t *Sy);
extern void *_SSFECDSAECDHTestExitHookCtx;

extern void (*_SSFECDSAKeyGenTestExitHook)(void *ctx,
                                           const SSFBN_t *d,
                                           const uint8_t *entropy, size_t entropyLen);
extern void *_SSFECDSAKeyGenTestExitHookCtx;
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_ECDSA_H_INCLUDE */

