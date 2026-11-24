/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpkey.h                                                                                     */
/* Provides private key decoding: PKCS#8, SEC 1 and PKCS#1, in DER or PEM.                       */
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
#ifndef SSF_PKEY_H_INCLUDE
#define SSF_PKEY_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_PKEY_MAX_PRIV_SIZE (48u)  /* P-384 scalar; P-256 is 32, an Ed25519 seed 32          */
#define SSF_PKEY_MAX_PUB_SIZE  (97u)  /* P-384 uncompressed point; P-256 is 65, Ed25519 32      */

typedef enum
{
    SSF_PKEY_TYPE_MIN = -1,
    SSF_PKEY_TYPE_NONE,      /* 0: no key. A zeroed or wiped SSFPKey_t, as after a failed decode */
    SSF_PKEY_TYPE_RSA,       /* rsaDer: PKCS#1 RSAPrivateKey for SSFRSASign*()                    */
    SSF_PKEY_TYPE_P256,      /* priv: 32-byte scalar; pub: 65-byte uncompressed point             */
    SSF_PKEY_TYPE_P384,      /* priv: 48-byte scalar; pub: 97-byte uncompressed point             */
    SSF_PKEY_TYPE_ED25519,   /* priv: 32-byte seed; pub: 32-byte public key                       */
    SSF_PKEY_TYPE_MAX,
} SSFPKeyType_t;

/* A decoded private key in the form the SSF signing functions take. For RSA, rsaDer points into */
/* the DER the key was decoded from, so that buffer must outlive the key; priv / pub are unused. */
/* For EC and Ed25519 the key is copied out and pub is always set (taken from the file after a  */
/* match check, or derived). Wipe with SSFPKeyWipe() when done.                                  */
typedef struct
{
    SSFPKeyType_t type;
    const uint8_t *rsaDer;
    size_t rsaDerLen;
    uint8_t priv[SSF_PKEY_MAX_PRIV_SIZE];
    size_t privLen;
    uint8_t pub[SSF_PKEY_MAX_PUB_SIZE];
    size_t pubLen;
} SSFPKey_t;

/* --------------------------------------------------------------------------------------------- */
/* External Interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Decodes an unencrypted private key in DER: PKCS#8 PrivateKeyInfo / OneAsymmetricKey          */
/* (RFC 5208, RFC 5958: RSA, P-256, P-384, Ed25519), SEC 1 ECPrivateKey (RFC 5915) or PKCS#1    */
/* RSAPrivateKey (RFC 8017). The key is validated: EC scalar in [1, n-1], RSA key consistent,   */
/* and a public key in the file must match the private key. On failure *keyOut is wiped.         */
bool SSFPKeyDecodeDER(const uint8_t *der, size_t derLen, SSFPKey_t *keyOut);

/* Decodes the one private key block of a PEM buffer ("PRIVATE KEY", "EC PRIVATE KEY",          */
/* "RSA PRIVATE KEY") into derBuf, then as SSFPKeyDecodeDER(). Other blocks (e.g. "EC           */
/* PARAMETERS", "CERTIFICATE") are skipped. Fails on "ENCRYPTED PRIVATE KEY", on no key block or */
/* more than one, and on any malformed block. On failure *keyOut and all of derBuf are wiped.    */
/* On success derBuf holds the key's DER: the caller wipes it when done. derBuf must not overlap */
/* pem. After any failure keyOut->type is SSF_PKEY_TYPE_NONE.                                   */
bool SSFPKeyDecodePEM(const char *pem, size_t pemLen, uint8_t *derBuf, size_t derBufSize,
                      SSFPKey_t *keyOut);

/* Zeroes the whole key structure. */
void SSFPKeyWipe(SSFPKey_t *key);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_PKEY_UNIT_TEST == 1
void SSFPKeyUnitTest(void);
#endif /* SSF_CONFIG_PKEY_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_PKEY_H_INCLUDE */
