/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfx509_ut.c                                                                                  */
/* Provides unit tests for the ssfx509 X.509 certificate parser.                                 */
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
#include "ssfassert.h"
#include "ssfx509.h"
#include "ssfasn1.h"
#include "ssfecdsa.h"
#include "ssfecdsa_ut_sign.h"                 /* SSF signer, or OpenSSL with signing off */
#include "ssfrsa.h"
#include "ssfed25519.h"
#include "ssfsha2.h"
#include "ssftls.h"
#include "ssfpem.h"

#if SSF_CONFIG_X509_UNIT_TEST == 1
#include "ssfx509_ut_csr.h"

/* RSA schemes ssfx509 verifies in this build (as in ssfx509.c) */
#if (SSF_RSA_ANY_ENABLED == 1) && (SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1)
#define _UT_RSA_PKCS1_VERIFY (1u)
#else
#define _UT_RSA_PKCS1_VERIFY (0u)
#endif
#if (SSF_RSA_ANY_ENABLED == 1) && (SSF_RSA_CONFIG_ENABLE_PSS == 1)
#define _UT_RSA_PSS_VERIFY (1u)
#else
#define _UT_RSA_PSS_VERIFY (0u)
#endif

/* Tests that sign generate a 2048-bit key, so they also need that size and KeyGen */
#if (_UT_RSA_PKCS1_VERIFY == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1) && \
    (SSF_RSA_CONFIG_ENABLE_KEYGEN == 1)
#define _UT_RSA_PKCS1_SIGN (1u)
#else
#define _UT_RSA_PKCS1_SIGN (0u)
#endif
#if (_UT_RSA_PSS_VERIFY == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1) && \
    (SSF_RSA_CONFIG_ENABLE_KEYGEN == 1)
#define _UT_RSA_PSS_SIGN (1u)
#else
#define _UT_RSA_PSS_SIGN (0u)
#endif

/* OpenSSL self-signed P-256 cert, CN=test.ssf.local, SAN test.ssf.local/localhost, 2026-2027 */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
static const uint8_t _utTestCertDER[] = {
    0x30, 0x82, 0x02, 0x47, 0x30, 0x82, 0x01, 0xec, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x00, 0xa7, 0x0b, 0x5a, 0xc1, 0x0c, 0xa0, 0x36, 0xe5,
    0x64, 0xaa, 0xf4, 0x7e, 0x6f, 0xdc, 0x17, 0xab, 0x74, 0xd0, 0x84, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x5e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
    0x02, 0x43, 0x41, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07,
    0x0c, 0x04, 0x54, 0x65, 0x73, 0x74, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x03, 0x53, 0x53, 0x46, 0x31, 0x0c, 0x30, 0x0a,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x44, 0x65, 0x76, 0x31, 0x17,
    0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x74, 0x65, 0x73,
    0x74, 0x2e, 0x73, 0x73, 0x66, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x30,
    0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x34, 0x30, 0x35, 0x32, 0x30, 0x35,
    0x38, 0x33, 0x38, 0x5a, 0x17, 0x0d, 0x32, 0x37, 0x30, 0x34, 0x30, 0x35,
    0x32, 0x30, 0x35, 0x38, 0x33, 0x38, 0x5a, 0x30, 0x5e, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x43, 0x41, 0x31,
    0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x04, 0x54, 0x65,
    0x73, 0x74, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x03, 0x53, 0x53, 0x46, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x03, 0x44, 0x65, 0x76, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x0e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x73, 0x73,
    0x66, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x30, 0x59, 0x30, 0x13, 0x06,
    0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x38, 0x83,
    0x13, 0xf7, 0x3d, 0x5e, 0x9d, 0x05, 0x5b, 0x79, 0x2d, 0x9c, 0x7d, 0x65,
    0x4e, 0x92, 0xbd, 0x9a, 0xbc, 0xc7, 0x4f, 0xbd, 0x4e, 0xa0, 0x95, 0x70,
    0x41, 0x37, 0xc3, 0x4e, 0xe3, 0x90, 0x72, 0x51, 0x67, 0x1a, 0xd5, 0xee,
    0xe4, 0xf2, 0x58, 0x03, 0x7f, 0xf2, 0x2b, 0x2c, 0xd3, 0x1f, 0x4c, 0x07,
    0xf3, 0x15, 0xdc, 0x72, 0x13, 0x20, 0x42, 0x3f, 0xa5, 0x3d, 0x5d, 0xff,
    0xbe, 0xd8, 0xa3, 0x81, 0x87, 0x30, 0x81, 0x84, 0x30, 0x1d, 0x06, 0x03,
    0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x6a, 0x6e, 0xd3, 0x11, 0x6c,
    0xd2, 0x5d, 0xfb, 0xc0, 0x1a, 0xdf, 0x1c, 0xd0, 0x6d, 0x0e, 0xf1, 0x82,
    0x37, 0x5c, 0x2c, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0x6a, 0x6e, 0xd3, 0x11, 0x6c, 0xd2, 0x5d, 0xfb,
    0xc0, 0x1a, 0xdf, 0x1c, 0xd0, 0x6d, 0x0e, 0xf1, 0x82, 0x37, 0x5c, 0x2c,
    0x30, 0x24, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x1d, 0x30, 0x1b, 0x82,
    0x0e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x73, 0x73, 0x66, 0x2e, 0x6c, 0x6f,
    0x63, 0x61, 0x6c, 0x82, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
    0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30,
    0x46, 0x02, 0x21, 0x00, 0xc3, 0xe0, 0x96, 0x7b, 0x72, 0x41, 0x0c, 0xdd,
    0xa5, 0xd5, 0x6d, 0x1e, 0x9f, 0x7a, 0x5b, 0x44, 0xfb, 0x19, 0xd7, 0x77,
    0x09, 0xb9, 0xb2, 0x01, 0x6b, 0xc9, 0x07, 0xab, 0x17, 0x41, 0x46, 0xf5,
    0x02, 0x21, 0x00, 0x8f, 0xce, 0x3a, 0xdc, 0xe6, 0x1d, 0x98, 0x5b, 0xb6,
    0x91, 0x8a, 0x40, 0x27, 0x10, 0x1c, 0xb1, 0x66, 0x44, 0x62, 0x19, 0x58,
    0xa7, 0xa5, 0x33, 0x1b, 0x35, 0x8a, 0xb6, 0x68, 0x6a, 0xd2, 0x9b
};
#else
/* AUDIT X509-21: the same certificate re-issued by OpenSSL 3.5 on a P-384 key */
static const uint8_t _utTestCertDER[] = {
    0x30, 0x82, 0x02, 0x83, 0x30, 0x82, 0x02, 0x09, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x00, 0xa7, 0x0b, 0x5a, 0xc1, 0x0c, 0xa0, 0x36, 0xe5,
    0x64, 0xaa, 0xf4, 0x7e, 0x6f, 0xdc, 0x17, 0xab, 0x74, 0xd0, 0x84, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x5e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
    0x02, 0x43, 0x41, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07,
    0x0c, 0x04, 0x54, 0x65, 0x73, 0x74, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x03, 0x53, 0x53, 0x46, 0x31, 0x0c, 0x30, 0x0a,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x44, 0x65, 0x76, 0x31, 0x17,
    0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x74, 0x65, 0x73,
    0x74, 0x2e, 0x73, 0x73, 0x66, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x30,
    0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x34, 0x30, 0x35, 0x32, 0x30, 0x35,
    0x38, 0x33, 0x38, 0x5a, 0x17, 0x0d, 0x32, 0x37, 0x30, 0x34, 0x30, 0x35,
    0x32, 0x30, 0x35, 0x38, 0x33, 0x38, 0x5a, 0x30, 0x5e, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x43, 0x41, 0x31,
    0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x04, 0x54, 0x65,
    0x73, 0x74, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x03, 0x53, 0x53, 0x46, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x03, 0x44, 0x65, 0x76, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x0e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x73, 0x73,
    0x66, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x30, 0x76, 0x30, 0x10, 0x06,
    0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
    0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xed, 0xe4, 0x4b, 0xf2, 0xd0,
    0x42, 0x17, 0xad, 0xd5, 0x2a, 0xe5, 0x27, 0x5f, 0xeb, 0xe5, 0x25, 0x80,
    0xc8, 0x73, 0x8d, 0x70, 0xd6, 0xe1, 0xbf, 0x36, 0x7e, 0xfb, 0x8c, 0x98,
    0x29, 0xcf, 0x68, 0xdc, 0x4c, 0xc5, 0xf5, 0x69, 0x6a, 0xde, 0x11, 0x26,
    0x98, 0x21, 0x7a, 0x9d, 0x1e, 0xd7, 0x6b, 0x54, 0xa1, 0x20, 0x08, 0x88,
    0x62, 0xf6, 0xe9, 0x47, 0x4d, 0xf0, 0x25, 0x63, 0xef, 0x08, 0x94, 0x22,
    0xfa, 0x78, 0x70, 0x6e, 0x66, 0xae, 0x83, 0x74, 0x06, 0x2e, 0x17, 0xdb,
    0xf0, 0x28, 0x55, 0x78, 0xea, 0x5a, 0x3b, 0x29, 0x42, 0x8b, 0x4b, 0x07,
    0x24, 0xa4, 0x8b, 0x95, 0x03, 0xbc, 0x5d, 0xa3, 0x81, 0x87, 0x30, 0x81,
    0x84, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
    0xc1, 0x57, 0xdf, 0xbe, 0xca, 0xd5, 0xf0, 0x5a, 0x12, 0xe3, 0xc6, 0x1e,
    0x7a, 0xd2, 0xd4, 0xb3, 0x4e, 0x16, 0x13, 0x46, 0x30, 0x1f, 0x06, 0x03,
    0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xc1, 0x57, 0xdf,
    0xbe, 0xca, 0xd5, 0xf0, 0x5a, 0x12, 0xe3, 0xc6, 0x1e, 0x7a, 0xd2, 0xd4,
    0xb3, 0x4e, 0x16, 0x13, 0x46, 0x30, 0x24, 0x06, 0x03, 0x55, 0x1d, 0x11,
    0x04, 0x1d, 0x30, 0x1b, 0x82, 0x0e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x73,
    0x73, 0x66, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x82, 0x09, 0x6c, 0x6f,
    0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x0c, 0x06, 0x03, 0x55,
    0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07,
    0x80, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
    0x02, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x30, 0x3a, 0x61, 0xf6, 0xf4,
    0x50, 0x89, 0x29, 0xb9, 0x40, 0xbe, 0xd9, 0x1d, 0xdf, 0x9d, 0xa0, 0xff,
    0x60, 0x7d, 0xab, 0xce, 0x48, 0xf2, 0xa2, 0xca, 0x6a, 0x5e, 0x5c, 0x39,
    0xd2, 0x1f, 0x70, 0xdc, 0x5d, 0x89, 0xbb, 0x9f, 0x0e, 0xd3, 0xed, 0x61,
    0x4b, 0x72, 0x46, 0xed, 0xee, 0xe0, 0x33, 0x87, 0x02, 0x31, 0x00, 0xa7,
    0x8a, 0x17, 0xf5, 0xea, 0x9a, 0xab, 0x74, 0x56, 0x72, 0x62, 0x20, 0xba,
    0xcf, 0xa8, 0x36, 0x4a, 0x7e, 0x08, 0x3c, 0xd9, 0xb5, 0x6e, 0x06, 0xb5,
    0x81, 0x98, 0x4d, 0x8f, 0xed, 0xfb, 0x8d, 0x2f, 0x22, 0x6d, 0x9f, 0x22,
    0x5c, 0xa4, 0xf8, 0x27, 0x2b, 0xb9, 0xdc, 0x02, 0xd0, 0x4f, 0xdf
};
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

/* OID constants for certificate generation (must be file-scope for struct pointer references) */
static const uint8_t _utSigAlgOid[] = {
    0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u  /* ecdsa-with-SHA256 */
};
static const uint8_t _utPubKeyAlgOid[] = {
    0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u          /* ecPublicKey */
};
/* AUDIT X509-21: generated certificates use P-256 when it is enabled, else P-384 */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
#define _UT_CURVE SSF_EC_CURVE_P256
#define _UT_PRIV_LEN (32u)
#define _UT_PUB_LEN (65u)
static const uint8_t _utCurveOid[] = {
    0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u   /* P-256 */
};
#else
#define _UT_CURVE SSF_EC_CURVE_P384
#define _UT_PRIV_LEN (48u)
#define _UT_PUB_LEN (97u)
static const uint8_t _utCurveOid[] = {
    0x2Bu, 0x81u, 0x04u, 0x00u, 0x22u                        /* P-384 */
};
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a self-signed ECDSA cert is made; generates a key pair if privKey[0] == 0.    */
/* --------------------------------------------------------------------------------------------- */
static bool _GenTestCert(const char *cnStr, uint64_t notBefore, uint64_t notAfter,
                         bool isCA, bool addBC, bool addKU, uint16_t kuBits,
                         uint8_t *certDer, uint32_t certDerSize, uint32_t *certDerLen,
                         uint8_t *privKey, uint8_t *pubKey, size_t *pubKeyLen)
{
    SSFX509GenParams_t params;
    uint8_t serial[] = { 0x01u };
    uint8_t tbsDer[512];
    uint32_t tbsLen;
    uint8_t tbsHash[32];
    uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
    size_t sigLen;

    SSF_REQUIRE(cnStr != NULL);
    SSF_REQUIRE(certDer != NULL);
    SSF_REQUIRE(certDerLen != NULL);
    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(pubKeyLen != NULL);

    /* Key pair still to be generated? */
    if (privKey[0] == 0u)
    {
        /* Yes, generate it */
        if (!SSFECDSAKeyGen(_UT_CURVE, privKey, SSF_ECDSA_MAX_PRIV_KEY_SIZE,
                            pubKey, SSF_ECDSA_MAX_PUB_KEY_SIZE, pubKeyLen)) return false;
    }

    memset(&params, 0, sizeof(params));
    params.version = 2u;
    params.serial = serial;
    params.serialLen = sizeof(serial);
    params.sigAlgOidRaw = _utSigAlgOid;
    params.sigAlgOidRawLen = sizeof(_utSigAlgOid);
    params.issuer.cn = cnStr;
    params.subject.cn = cnStr;
    params.notBefore = notBefore;
    params.notAfter = notAfter;
    params.pubKeyAlgOidRaw = _utPubKeyAlgOid;
    params.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
    params.ecCurveOidRaw = _utCurveOid;
    params.ecCurveOidRawLen = sizeof(_utCurveOid);
    params.pubKey = pubKey;
    params.pubKeyLen = (uint32_t)*pubKeyLen;
    params.addBasicConstraints = addBC;
    params.isCA = isCA;
    params.pathLenConstraint = -1; /* absent by default */
    params.addKeyUsage = addKU;
    params.keyUsageBits = kuBits;

    (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &params, &tbsLen);
    if (tbsLen == 0u) return false;

    SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
    if (!_SSFECDSAUTSign(_UT_CURVE, privKey, _UT_PRIV_LEN, tbsHash, 32, sig, sizeof(sig),
                         &sigLen)) return false;

    (void)SSFX509EncodeCert(certDer, certDerSize, &params, sig, (uint32_t)sigLen, certDerLen);
    return (*certDerLen > 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a leaf cert signed by the CA key, issuer CN differing from subject, is made.  */
/* --------------------------------------------------------------------------------------------- */
static bool _GenSignedLeafCert(const char *leafCNStr, const char *issuerCNStr,
                               uint64_t notBefore, uint64_t notAfter,
                               uint8_t *certDer, uint32_t certDerSize, uint32_t *certDerLen,
                               const uint8_t *caPrivKey,
                               uint8_t *leafPubKey, size_t *leafPubKeyLen)
{
    SSFX509GenParams_t params;
    uint8_t serial[] = { 0x02u };
    uint8_t leafPrivKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
    uint8_t tbsDer[512];
    uint32_t tbsLen;
    uint8_t tbsHash[32];
    uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
    size_t sigLen;

    SSF_REQUIRE(leafCNStr != NULL);
    SSF_REQUIRE(issuerCNStr != NULL);
    SSF_REQUIRE(certDer != NULL);
    SSF_REQUIRE(certDerLen != NULL);
    SSF_REQUIRE(caPrivKey != NULL);
    SSF_REQUIRE(leafPubKey != NULL);
    SSF_REQUIRE(leafPubKeyLen != NULL);

    /* Generate fresh key pair for the leaf */
    memset(leafPrivKey, 0, sizeof(leafPrivKey));
    if (!SSFECDSAKeyGen(_UT_CURVE, leafPrivKey, sizeof(leafPrivKey),
                        leafPubKey, SSF_ECDSA_MAX_PUB_KEY_SIZE, leafPubKeyLen)) return false;

    memset(&params, 0, sizeof(params));
    params.version = 2u;
    params.serial = serial;
    params.serialLen = sizeof(serial);
    params.sigAlgOidRaw = _utSigAlgOid;
    params.sigAlgOidRawLen = sizeof(_utSigAlgOid);
    params.issuer.cn = issuerCNStr;
    params.subject.cn = leafCNStr;
    params.notBefore = notBefore;
    params.notAfter = notAfter;
    params.pubKeyAlgOidRaw = _utPubKeyAlgOid;
    params.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
    params.ecCurveOidRaw = _utCurveOid;
    params.ecCurveOidRawLen = sizeof(_utCurveOid);
    params.pubKey = leafPubKey;
    params.pubKeyLen = (uint32_t)*leafPubKeyLen;
    params.addBasicConstraints = false;
    params.isCA = false;
    params.pathLenConstraint = -1;
    params.addKeyUsage = false;
    params.keyUsageBits = 0u;

    /* Encode TBS, hash, sign with CA key */
    (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &params, &tbsLen);
    if (tbsLen == 0u) return false;

    SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
    if (!_SSFECDSAUTSign(_UT_CURVE, caPrivKey, _UT_PRIV_LEN, tbsHash, 32, sig, sizeof(sig),
                         &sigLen)) return false;

    (void)SSFX509EncodeCert(certDer, certDerSize, &params, sig, (uint32_t)sigLen, certDerLen);
    return (*certDerLen > 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Fills p with a minimal v3 ECDSA P-256 self-issued parameter set for generation tests.         */
/* --------------------------------------------------------------------------------------------- */
static void _utGenBaseParams(SSFX509GenParams_t *p, const uint8_t *serial, const uint8_t *pubKey,
                             uint32_t pubKeyLen)
{
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(serial != NULL);
    SSF_REQUIRE(pubKey != NULL);

    memset(p, 0, sizeof(*p));
    p->version = 2u;
    p->serial = serial;
    p->serialLen = 1u;
    p->sigAlgOidRaw = _utSigAlgOid;
    p->sigAlgOidRawLen = sizeof(_utSigAlgOid);
    p->issuer.cn = "ut";
    p->subject.cn = "ut";
    p->notBefore = 1700000000ull;
    p->notAfter = 2000000000ull;
    p->pubKeyAlgOidRaw = _utPubKeyAlgOid;
    p->pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
    p->ecCurveOidRaw = _utCurveOid;
    p->ecCurveOidRawLen = sizeof(_utCurveOid);
    p->pubKey = pubKey;
    p->pubKeyLen = pubKeyLen;
    p->pathLenConstraint = -1;
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts EncodeTBS and EncodeCert write exactly what they measure and the output re-parses.    */
/* --------------------------------------------------------------------------------------------- */
static void _utGenCheckConsistent(const SSFX509GenParams_t *p, const uint8_t *sig, uint32_t sigLen,
                                  uint8_t *out, uint32_t outSize, SSFX509Cert_t *parsed)
{
    uint32_t measured;
    uint32_t written;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(parsed != NULL);

    SSF_ASSERT(SSFX509EncodeTBS(NULL, 0, p, &measured) == true);
    SSF_ASSERT(SSFX509EncodeTBS(out, outSize, p, &written) == true);
    SSF_ASSERT(measured != 0u);
    SSF_ASSERT(written == measured);

    SSF_ASSERT(SSFX509EncodeCert(NULL, 0, p, sig, sigLen, &measured) == true);
    SSF_ASSERT(SSFX509EncodeCert(out, outSize, p, sig, sigLen, &written) == true);
    SSF_ASSERT(measured != 0u);
    SSF_ASSERT(written == measured);
    SSF_ASSERT(SSFX509Parse(out, written, parsed) == true);
    SSF_ASSERT(parsed->pubKeyLen == p->pubKeyLen);
    SSF_ASSERT(parsed->signatureLen == sigLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Generates a P-256 key, self-signs p with it, and returns the certificate DER length, else 0.  */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _utSelfSign(SSFX509GenParams_t *p, uint8_t *pubKey, size_t pubKeySize,
                            uint8_t *out, uint32_t outSize)
{
    static uint8_t tbs[SSF_X509_CONFIG_MAX_CERT_SIZE];
    uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
    size_t pubKeyLen;
    uint32_t tbsLen;
    uint32_t certLen;
    uint8_t hash[32];
    uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
    size_t sigLen;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(out != NULL);

    if (!SSFECDSAKeyGen(_UT_CURVE, privKey, sizeof(privKey), pubKey, pubKeySize,
                        &pubKeyLen)) return 0;
    p->pubKey = pubKey;
    p->pubKeyLen = (uint32_t)pubKeyLen;
    (void)SSFX509EncodeTBS(tbs, sizeof(tbs), p, &tbsLen);
    if (tbsLen == 0u) return 0;
    SSFSHA256(tbs, tbsLen, hash, sizeof(hash));
    if (!_SSFECDSAUTSign(_UT_CURVE, privKey, _UT_PRIV_LEN, hash, 32u, sig, sizeof(sig), &sigLen))
        return 0;
    if (!SSFX509EncodeCert(out, outSize, p, sig, (uint32_t)sigLen, &certLen)) return 0;
    return certLen;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns cert length of a v3 cert with numExts unknown exts, BC pathLen, INTEGER DN option.    */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _utBuildCertExts(uint32_t numExts, int32_t pathLen, bool oddDN, uint8_t *out,
                                 uint32_t outSize)
{
    static uint8_t exts[1024];
    static uint8_t extsSeq[1040];
    static uint8_t tbsContent[1280];
    static uint8_t tbs[1300];
    static uint8_t certContent[1400];
    uint8_t tmp[128];
    uint8_t tmp2[128];
    uint8_t tmp3[128];
    uint8_t pub[65];
    uint8_t sig[64];
    uint8_t serial[] = { 0x01u };
    uint8_t oid[] = { 0x55u, 0x1Du, 0x00u };
    uint32_t extsLen = 0;
    uint32_t pos = 0;
    uint32_t n;
    uint32_t w;
    uint32_t i;

    SSF_REQUIRE(numExts <= (SSF_X509_CONFIG_MAX_EXTENSIONS + 1u));
    SSF_REQUIRE(out != NULL);

    memset(pub, 0x04u, sizeof(pub));
    memset(sig, 0x33u, sizeof(sig));

    /* Unknown, non-critical extensions 2.5.29.64 onward, each with a NULL value */
    for (i = 0; i < numExts; i++)
    {
        oid[2] = (uint8_t)(0x40u + i);
        n = 0;
        if (!SSFASN1EncOIDRaw(tmp, sizeof(tmp), oid, sizeof(oid), &w)) return 0;
        n += w;
        if (!SSFASN1EncNull(tmp2, sizeof(tmp2), &w)) return 0;
        if (!SSFASN1EncOctetString(&tmp[n], sizeof(tmp) - n, tmp2, w, &w)) return 0;
        n += w;
        if (!SSFASN1EncWrap(&exts[extsLen], sizeof(exts) - extsLen, SSF_ASN1_TAG_SEQUENCE, tmp, n,
                            &w)) return 0;
        extsLen += w;
    }

    /* Critical BasicConstraints { cA TRUE, pathLenConstraint } requested? */
    if (pathLen >= 0)
    {
        static const uint8_t bcOid[] = { 0x55u, 0x1Du, 0x13u };

        /* Yes, append it */
        n = 0;
        if (!SSFASN1EncBool(tmp2, sizeof(tmp2), true, &w)) return 0;
        n += w;
        if (!SSFASN1EncIntU64(&tmp2[n], sizeof(tmp2) - n, (uint64_t)pathLen, &w)) return 0;
        n += w;
        if (!SSFASN1EncWrap(tmp3, sizeof(tmp3), SSF_ASN1_TAG_SEQUENCE, tmp2, n, &w)) return 0;
        n = w;
        if (!SSFASN1EncOctetString(tmp2, sizeof(tmp2), tmp3, n, &w)) return 0;
        n = w;
        pos = 0;
        if (!SSFASN1EncOIDRaw(tmp, sizeof(tmp), bcOid, sizeof(bcOid), &w)) return 0;
        pos += w;
        if (!SSFASN1EncBool(&tmp[pos], sizeof(tmp) - pos, true, &w)) return 0;
        pos += w;
        memcpy(&tmp[pos], tmp2, n);
        pos += n;
        if (!SSFASN1EncWrap(&exts[extsLen], sizeof(exts) - extsLen, SSF_ASN1_TAG_SEQUENCE, tmp,
                            pos, &w)) return 0;
        extsLen += w;
    }

    /* TBSCertificate content */
    pos = 0;
    if (!SSFASN1EncIntU64(tmp, sizeof(tmp), 2u, &w)) return 0;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_CONTEXT_EXPLICIT(0),
                        tmp, w, &w)) return 0;
    pos += w;
    if (!SSFASN1EncInt(&tbsContent[pos], sizeof(tbsContent) - pos, serial, sizeof(serial), &w))
        return 0;
    pos += w;
    if (!SSFASN1EncOIDRaw(tmp, sizeof(tmp), _utSigAlgOid, sizeof(_utSigAlgOid), &w)) return 0;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp, w,
                        &w)) return 0;
    pos += w;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp, 0u,
                        &w)) return 0;
    pos += w;
    n = 0;
    if (!SSFASN1EncUTCTime(tmp, sizeof(tmp), 1700000000ull, &w)) return 0;
    n += w;
    if (!SSFASN1EncUTCTime(&tmp[n], sizeof(tmp) - n, 2000000000ull, &w)) return 0;
    n += w;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp, n,
                        &w)) return 0;
    pos += w;
    /* Subject with a non-string attribute value requested? */
    if (oddDN)
    {
        static const uint8_t snOid[] = { 0x55u, 0x04u, 0x05u };
        static const uint8_t cnOid[] = { 0x55u, 0x04u, 0x03u };

        /* Yes, SET { SEQUENCE { serialNumber OID, INTEGER 7 } } then a commonName */
        n = 0;
        if (!SSFASN1EncOIDRaw(tmp2, sizeof(tmp2), snOid, sizeof(snOid), &w)) return 0;
        n += w;
        if (!SSFASN1EncIntU64(&tmp2[n], sizeof(tmp2) - n, 7u, &w)) return 0;
        n += w;
        if (!SSFASN1EncWrap(tmp3, sizeof(tmp3), SSF_ASN1_TAG_SEQUENCE, tmp2, n, &w)) return 0;
        if (!SSFASN1EncWrap(tmp, sizeof(tmp), SSF_ASN1_TAG_SET, tmp3, w, &w)) return 0;
        n = w;

        /* SET { SEQUENCE { commonName OID, UTF8String "x" } } */
        i = 0;
        if (!SSFASN1EncOIDRaw(tmp2, sizeof(tmp2), cnOid, sizeof(cnOid), &w)) return 0;
        i += w;
        if (!SSFASN1EncString(&tmp2[i], sizeof(tmp2) - i, SSF_ASN1_TAG_UTF8_STRING,
                              (const uint8_t *)"x", 1u, &w)) return 0;
        i += w;
        if (!SSFASN1EncWrap(tmp3, sizeof(tmp3), SSF_ASN1_TAG_SEQUENCE, tmp2, i, &w)) return 0;
        if (!SSFASN1EncWrap(&tmp[n], sizeof(tmp) - n, SSF_ASN1_TAG_SET, tmp3, w, &w)) return 0;
        n += w;
        if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp,
                            n, &w)) return 0;
    }
    else
    {
        /* No, empty subject */
        if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp,
                            0u, &w)) return 0;
    }
    pos += w;
    n = 0;
    if (!SSFASN1EncOIDRaw(tmp2, sizeof(tmp2), _utPubKeyAlgOid, sizeof(_utPubKeyAlgOid), &w))
        return 0;
    n += w;
    if (!SSFASN1EncOIDRaw(&tmp2[n], sizeof(tmp2) - n, _utCurveOid, sizeof(_utCurveOid), &w))
        return 0;
    n += w;
    if (!SSFASN1EncWrap(tmp, sizeof(tmp), SSF_ASN1_TAG_SEQUENCE, tmp2, n, &w)) return 0;
    n = w;
    if (!SSFASN1EncBitString(&tmp[n], sizeof(tmp) - n, pub, sizeof(pub), 0u, &w)) return 0;
    n += w;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp, n,
                        &w)) return 0;
    pos += w;
    /* Any extensions? */
    if (extsLen > 0u)
    {
        /* Yes, wrap them in [3] */
        if (!SSFASN1EncWrap(extsSeq, sizeof(extsSeq), SSF_ASN1_TAG_SEQUENCE, exts, extsLen, &w))
            return 0;
        if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos,
                            SSF_ASN1_CONTEXT_EXPLICIT(3), extsSeq, w, &w)) return 0;
        pos += w;
    }
    if (!SSFASN1EncWrap(tbs, sizeof(tbs), SSF_ASN1_TAG_SEQUENCE, tbsContent, pos, &w)) return 0;

    /* Certificate { tbs, signatureAlgorithm, signatureValue } */
    pos = w;
    memcpy(certContent, tbs, pos);
    if (!SSFASN1EncOIDRaw(tmp, sizeof(tmp), _utSigAlgOid, sizeof(_utSigAlgOid), &w)) return 0;
    if (!SSFASN1EncWrap(&certContent[pos], sizeof(certContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp,
                        w, &w)) return 0;
    pos += w;
    if (!SSFASN1EncBitString(&certContent[pos], sizeof(certContent) - pos, sig, sizeof(sig), 0u,
                             &w)) return 0;
    pos += w;
    if (!SSFASN1EncWrap(out, outSize, SSF_ASN1_TAG_SEQUENCE, certContent, pos, &w)) return 0;
    return w;
}

/* --------------------------------------------------------------------------------------------- */
/* Signs p with the given P-256 private key and returns the certificate DER length, else 0.      */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _utSignCert(const SSFX509GenParams_t *p, const uint8_t *privKey, uint8_t *out,
                            uint32_t outSize)
{
    static uint8_t tbs[SSF_X509_CONFIG_MAX_CERT_SIZE];
    uint32_t tbsLen;
    uint32_t certLen;
    uint8_t hash[32];
    uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
    size_t sigLen;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(out != NULL);

    (void)SSFX509EncodeTBS(tbs, sizeof(tbs), p, &tbsLen);
    if (tbsLen == 0u) return 0;
    SSFSHA256(tbs, tbsLen, hash, sizeof(hash));
    if (!_SSFECDSAUTSign(_UT_CURVE, privKey, _UT_PRIV_LEN, hash, 32u, sig, sizeof(sig), &sigLen))
        return 0;
    if (!SSFX509EncodeCert(out, outSize, p, sig, (uint32_t)sigLen, &certLen)) return 0;
    return certLen;
}

/* Last verify error; _UT_VERR checks it, then poisons it so a stale value cannot pass */
static SSFX509VerifyErr_t _utVErr;
#define _UT_VERR(_c, _i) do { \
    SSF_ASSERT(_utVErr.code == SSF_X509_VERIFY_##_c); \
    SSF_ASSERT(_utVErr.certIdx == (uint8_t)(_i)); \
    _utVErr.code = SSF_X509_VERIFY_MAX; \
    _utVErr.certIdx = 0xffu; } while (0)

/* Receives lengths from encoder calls whose failure is the point of the test */
static uint32_t _utScratchLen;

static uint32_t _utTraceCount;
/* Trace checks run when tracing is compiled in; with it out the callback must never fire */
#if SSF_TLS_CONFIG_ENABLE_TRACE == 1
#define _UT_TRACE_ASSERT(x) SSF_ASSERT(x)
#else
#define _UT_TRACE_ASSERT(x) SSF_ASSERT(_utTraceCount == 0u)
#endif
static uint32_t _utTraceErrors;
static int _utTraceLastLevel;
static int _utTraceLastCategory;
static void *_utTraceLastCtx;
static char _utTraceLastMsg[256];

/* --------------------------------------------------------------------------------------------- */
/* Verifier trace callback: counts calls and keeps the last level, category, message and ctx.    */
/* --------------------------------------------------------------------------------------------- */
static void _utTrace(int level, int category, const char *msgStr, void *ctxOpt)
{
    size_t n = 0;

    SSF_REQUIRE(msgStr != NULL);

    _utTraceCount++;
    /* Error level trace? */
    if (level == (int)SSF_TLS_TRACE_ERROR) _utTraceErrors++;
    _utTraceLastLevel = level;
    _utTraceLastCategory = category;
    _utTraceLastCtx = ctxOpt;

    /* Is there another message character that fits in the capture buffer? */
    while ((msgStr[n] != '\0') && (n < (sizeof(_utTraceLastMsg) - 1u)))
    {
        /* Yes */
        _utTraceLastMsg[n] = msgStr[n];
        n++;
    }
    _utTraceLastMsg[n] = '\0';
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if needleStr occurs in hayStr, else false.                                       */
/* --------------------------------------------------------------------------------------------- */
static bool _utContains(const char *hayStr, const char *needleStr)
{
    size_t i;
    size_t j;

    SSF_REQUIRE(hayStr != NULL);
    SSF_REQUIRE(needleStr != NULL);

    for (i = 0; hayStr[i] != '\0'; i++)
    {
        for (j = 0; (needleStr[j] != '\0') && (hayStr[i + j] != '\0') &&
                    (hayStr[i + j] == needleStr[j]); j++)
        {
        }
        /* Whole needle matched here? */
        if (needleStr[j] == '\0') return true;
    }
    return (needleStr[0] == '\0');
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true with *atOut set to the offset of the first pat in buf, else false if absent.     */
/* --------------------------------------------------------------------------------------------- */
static bool _utFind(const uint8_t *buf, uint32_t bufLen, const uint8_t *pat, uint32_t patLen,
                    uint32_t *atOut)
{
    uint32_t i;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(pat != NULL);
    SSF_REQUIRE(patLen > 0u);
    SSF_REQUIRE(atOut != NULL);

    for (i = 0; (i + patLen) <= bufLen; i++)
    {
        /* Pattern found at offset i? */
        if (memcmp(&buf[i], pat, patLen) == 0)
        {
            /* Yes */
            *atOut = i;
            return true;
        }
    }
    return false;
}

#define _UT_GT_NOT_BEFORE   (2524608000ull)   /* 2050-01-01T00:00:00Z */
#define _UT_GT_NOT_AFTER    (2600000000ull)   /* 2052-05-26T... */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a v3 cert with optional GeneralizedTime validity and unique IDs is built.     */
/* --------------------------------------------------------------------------------------------- */
static bool _utBuildCertVariant(bool generalizedTime, bool uniqueIds, uint8_t *out,
                                uint32_t outSize, uint32_t *lenOut)
{
    static uint8_t tbsContent[512];
    static uint8_t tbs[520];
    static uint8_t certContent[640];
    uint8_t tmp[128];
    uint8_t tmp2[128];
    uint8_t pub[65];
    uint8_t sig[64];
    uint8_t serial[] = { 0x01u };
    uint8_t uid[] = { 0x00u, 0xAAu };
    static const uint8_t extOid[] = { 0x55u, 0x1Du, 0x40u };
    uint32_t pos = 0;
    uint32_t n;
    uint32_t w;

    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(lenOut != NULL);

    *lenOut = 0;
    memset(pub, 0x04u, sizeof(pub));
    memset(sig, 0x33u, sizeof(sig));

    if (!SSFASN1EncIntU64(tmp, sizeof(tmp), 2u, &w)) return false;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_CONTEXT_EXPLICIT(0),
                        tmp, w, &w)) return false;
    pos += w;
    if (!SSFASN1EncInt(&tbsContent[pos], sizeof(tbsContent) - pos, serial, sizeof(serial), &w))
        return false;
    pos += w;
    if (!SSFASN1EncOIDRaw(tmp, sizeof(tmp), _utSigAlgOid, sizeof(_utSigAlgOid), &w)) return false;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp, w,
                        &w)) return false;
    pos += w;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp, 0u,
                        &w)) return false;
    pos += w;

    /* Validity */
    n = 0;
    /* GeneralizedTime validity requested? */
    if (generalizedTime)
    {
        /* Yes, 2050 and later dates */
        if (!SSFASN1EncGeneralizedTime(tmp, sizeof(tmp), _UT_GT_NOT_BEFORE, &w)) return false;
        n += w;
        if (!SSFASN1EncGeneralizedTime(&tmp[n], sizeof(tmp) - n, _UT_GT_NOT_AFTER, &w))
            return false;
        n += w;
    }
    else
    {
        /* No, UTCTime dates */
        if (!SSFASN1EncUTCTime(tmp, sizeof(tmp), 1700000000ull, &w)) return false;
        n += w;
        if (!SSFASN1EncUTCTime(&tmp[n], sizeof(tmp) - n, 2000000000ull, &w)) return false;
        n += w;
    }
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp, n,
                        &w)) return false;
    pos += w;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp, 0u,
                        &w)) return false;
    pos += w;

    /* SubjectPublicKeyInfo */
    n = 0;
    if (!SSFASN1EncOIDRaw(tmp2, sizeof(tmp2), _utPubKeyAlgOid, sizeof(_utPubKeyAlgOid), &w))
        return false;
    n += w;
    if (!SSFASN1EncOIDRaw(&tmp2[n], sizeof(tmp2) - n, _utCurveOid, sizeof(_utCurveOid), &w))
        return false;
    n += w;
    if (!SSFASN1EncWrap(tmp, sizeof(tmp), SSF_ASN1_TAG_SEQUENCE, tmp2, n, &w)) return false;
    n = w;
    if (!SSFASN1EncBitString(&tmp[n], sizeof(tmp) - n, pub, sizeof(pub), 0u, &w)) return false;
    n += w;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp, n,
                        &w)) return false;
    pos += w;

    /* issuerUniqueID [1] and subjectUniqueID [2] IMPLICIT BIT STRINGs requested? */
    if (uniqueIds)
    {
        /* Yes, append both */
        if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, 0x81u, uid, sizeof(uid),
                            &w)) return false;
        pos += w;
        uid[1] = 0xBBu;
        if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, 0x82u, uid, sizeof(uid),
                            &w)) return false;
        pos += w;
    }

    /* Extensions [3]: one unknown non-critical extension with a NULL value */
    n = 0;
    if (!SSFASN1EncOIDRaw(tmp2, sizeof(tmp2), extOid, sizeof(extOid), &w)) return false;
    n += w;
    if (!SSFASN1EncNull(tmp, sizeof(tmp), &w)) return false;
    if (!SSFASN1EncOctetString(&tmp2[n], sizeof(tmp2) - n, tmp, w, &w)) return false;
    n += w;
    if (!SSFASN1EncWrap(tmp, sizeof(tmp), SSF_ASN1_TAG_SEQUENCE, tmp2, n, &w)) return false;
    if (!SSFASN1EncWrap(tmp2, sizeof(tmp2), SSF_ASN1_TAG_SEQUENCE, tmp, w, &w)) return false;
    if (!SSFASN1EncWrap(&tbsContent[pos], sizeof(tbsContent) - pos, SSF_ASN1_CONTEXT_EXPLICIT(3),
                        tmp2, w, &w)) return false;
    pos += w;

    if (!SSFASN1EncWrap(tbs, sizeof(tbs), SSF_ASN1_TAG_SEQUENCE, tbsContent, pos, &w)) return false;
    pos = w;
    memcpy(certContent, tbs, pos);
    if (!SSFASN1EncOIDRaw(tmp, sizeof(tmp), _utSigAlgOid, sizeof(_utSigAlgOid), &w)) return false;
    if (!SSFASN1EncWrap(&certContent[pos], sizeof(certContent) - pos, SSF_ASN1_TAG_SEQUENCE, tmp,
                        w, &w)) return false;
    pos += w;
    if (!SSFASN1EncBitString(&certContent[pos], sizeof(certContent) - pos, sig, sizeof(sig), 0u,
                             &w)) return false;
    pos += w;
    if (!SSFASN1EncWrap(out, outSize, SSF_ASN1_TAG_SEQUENCE, certContent, pos, &w)) return false;
    *lenOut = w;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a self-signed P-256 CA named cnStr is built into out with *lenOut set.        */
/* --------------------------------------------------------------------------------------------- */
static bool _utMakeCA(const char *cnStr, const uint8_t *serial, uint8_t *priv, uint8_t *pub,
                      size_t *pubLen, uint8_t *out, uint32_t outSize, uint32_t *lenOut)
{
    SSFX509GenParams_t p;

    SSF_REQUIRE(cnStr != NULL);
    SSF_REQUIRE(serial != NULL);
    SSF_REQUIRE(priv != NULL);
    SSF_REQUIRE(pub != NULL);
    SSF_REQUIRE(pubLen != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(lenOut != NULL);

    *lenOut = 0;
    if (!SSFECDSAKeyGen(_UT_CURVE, priv, SSF_ECDSA_MAX_PRIV_KEY_SIZE, pub,
                        SSF_ECDSA_MAX_PUB_KEY_SIZE, pubLen)) return false;
    _utGenBaseParams(&p, serial, pub, (uint32_t)*pubLen);
    p.issuer.cn = cnStr;
    p.subject.cn = cnStr;
    p.addBasicConstraints = true;
    p.isCA = true;
    p.addKeyUsage = true;
    p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
    *lenOut = _utSignCert(&p, priv, out, outSize);
    return (*lenOut != 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns bytes written to out: in with 05 00 appended inside the element path names, else 0.   */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _utAppendJunk(const uint8_t *in, uint32_t inLen, const uint8_t *path,
                              uint32_t pathLen, uint8_t *out, uint32_t outSize)
{
    static uint8_t content[5][SSF_X509_CONFIG_MAX_CERT_SIZE + 16u];
    SSFASN1Cursor_t c;
    SSFASN1Cursor_t next;
    SSFASN1Cursor_t child;
    const uint8_t *val;
    uint32_t valLen;
    uint32_t len = 0;
    uint32_t idx = 0;
    uint32_t w;
    uint16_t tag;
    uint8_t *buf;

    SSF_REQUIRE(in != NULL);
    SSF_REQUIRE((path != NULL) || (pathLen == 0u));
    SSF_REQUIRE(pathLen < 5u);
    SSF_REQUIRE(out != NULL);

    buf = content[pathLen];
    c.buf = in;
    c.bufLen = inLen;
    if (!SSFASN1DecGetTLV(&c, &tag, &val, &valLen, &next)) return 0;
    /* Is this the element to append to? */
    if (pathLen == 0u)
    {
        /* Yes, copy its content and append 05 00 */
        memcpy(buf, val, valLen);
        len = valLen;
        buf[len++] = 0x05u;
        buf[len++] = 0x00u;
    }
    else
    {
        /* No, rebuild the children, descending into the one path names */
        child.buf = val;
        child.bufLen = valLen;
        while (!SSFASN1DecIsEmpty(&child))
        {
            const uint8_t *start = child.buf;
            const uint8_t *cv;
            uint32_t cvLen;
            uint16_t ct;
            uint32_t childLen;

            if (!SSFASN1DecGetTLV(&child, &ct, &cv, &cvLen, &child)) return 0;
            childLen = (uint32_t)(child.buf - start);
            /* Is this the child on the path? */
            if (idx == path[0])
            {
                /* Yes, descend into it */
                w = _utAppendJunk(start, childLen, &path[1], pathLen - 1u, &buf[len],
                                  (uint32_t)sizeof(content[0]) - len);
                if (w == 0u) return 0;
                len += w;
            }
            else
            {
                /* No, copy it unchanged */
                memcpy(&buf[len], start, childLen);
                len += childLen;
            }
            idx++;
        }
    }
    if (!SSFASN1EncWrap(out, outSize, tag, buf, len, &w)) return 0;
    return w;
}

/* ---- CSR (PKCS#10) generation ---- */
static const uint8_t _utCsrOidP256[] = { 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u };
static const uint8_t _utCsrOidP384[] = { 0x2Bu, 0x81u, 0x04u, 0x00u, 0x22u };
static const uint8_t _utCsrOidSHA384[] = { 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x03u };

/* Fills CSR parameters for an EC key on P-256 or P-384 with an empty subject. */
static void _UTCSRParams(SSFX509CSRParams_t *p, bool isP384, const uint8_t *pub)
{
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(pub != NULL);

    memset(p, 0, sizeof(*p));
    p->sigAlgOidRaw = (isP384 ? _utCsrOidSHA384 : _utSigAlgOid);
    p->sigAlgOidRawLen = (uint32_t)(isP384 ? sizeof(_utCsrOidSHA384) : sizeof(_utSigAlgOid));
    p->pubKeyAlgOidRaw = _utPubKeyAlgOid;
    p->pubKeyAlgOidRawLen = (uint32_t)sizeof(_utPubKeyAlgOid);
    p->ecCurveOidRaw = (isP384 ? _utCsrOidP384 : _utCsrOidP256);
    p->ecCurveOidRawLen = (uint32_t)(isP384 ? sizeof(_utCsrOidP384) : sizeof(_utCsrOidP256));
    p->pubKey = pub;
    p->pubKeyLen = (isP384 ? 97u : 65u);
}

/* Hashes data with the CSR's hash (SHA-256 for P-256, SHA-384 for P-384); returns its size. */
static size_t _UTCSRHash(bool isP384, const uint8_t *data, uint32_t dataLen, uint8_t *hash)
{
    SSF_REQUIRE(data != NULL);
    SSF_REQUIRE(hash != NULL);

    /* P-384 key? */
    if (isP384)
    {
        /* Yes, ecdsa-with-SHA384 */
        SSFSHA384(data, dataLen, hash, SSF_SHA2_384_BYTE_SIZE);
        return SSF_SHA2_384_BYTE_SIZE;
    }
    /* No, ecdsa-with-SHA256 */
    SSFSHA256(data, dataLen, hash, SSF_SHA2_256_BYTE_SIZE);
    return SSF_SHA2_256_BYTE_SIZE;
}

/* Builds a CSR the way a caller does: CSRInfo, hash, sign, wrap; returns its length. */
static uint32_t _UTCSRBuild(const SSFX509CSRParams_t *p, bool isP384, const uint8_t *priv,
                            uint8_t *out, uint32_t outSize)
{
    static uint8_t cri[1024];
    uint8_t hash[SSF_SHA2_384_BYTE_SIZE];
    uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
    size_t hashLen;
    size_t sigLen;
    uint32_t criLen;
    uint32_t measured;
    uint32_t len;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(priv != NULL);
    SSF_REQUIRE(out != NULL);

    SSF_ASSERT(SSFX509EncodeCSRInfo(NULL, 0, p, &measured));
    SSF_ASSERT(SSFX509EncodeCSRInfo(cri, sizeof(cri), p, &criLen));
    SSF_ASSERT(criLen == measured);
    hashLen = _UTCSRHash(isP384, cri, criLen, hash);
    SSF_ASSERT(_SSFECDSAUTSign((isP384 ? SSF_EC_CURVE_P384 : SSF_EC_CURVE_P256), priv,
                               (isP384 ? 48u : 32u), hash, hashLen, sig, sizeof(sig), &sigLen));
    SSF_ASSERT(SSFX509EncodeCSR(NULL, 0, p, sig, (uint32_t)sigLen, &measured));
    SSF_ASSERT(SSFX509EncodeCSR(out, outSize, p, sig, (uint32_t)sigLen, &len));
    SSF_ASSERT(len == measured);
    return len;
}

/* Walks a CSR, checks every field against p, and verifies its signature with the public key. */
static void _UTCSRVerify(const uint8_t *csr, uint32_t csrLen, const SSFX509CSRParams_t *p,
                         bool isP384)
{
    SSFASN1Cursor_t cur;
    SSFASN1Cursor_t outer;
    SSFASN1Cursor_t cri;
    SSFASN1Cursor_t spki;
    SSFASN1Cursor_t alg;
    SSFASN1Cursor_t next;
    const uint8_t *criStart;
    const uint8_t *v;
    uint32_t vLen;
    uint64_t version;
    uint16_t tag;
    uint8_t unused;
    uint8_t hash[SSF_SHA2_384_BYTE_SIZE];
    size_t hashLen;

    SSF_REQUIRE(csr != NULL);
    SSF_REQUIRE(p != NULL);

    cur.buf = csr;
    cur.bufLen = csrLen;
    SSF_ASSERT(SSFASN1DecOpenConstructed(&cur, SSF_ASN1_TAG_SEQUENCE, &outer, &next));
    SSF_ASSERT(SSFASN1DecIsEmpty(&next));
    criStart = outer.buf;
    SSF_ASSERT(SSFASN1DecOpenConstructed(&outer, SSF_ASN1_TAG_SEQUENCE, &cri, &outer));

    /* CertificationRequestInfo: version 0, subject, SPKI, empty attributes [0] */
    SSF_ASSERT((SSFASN1DecGetIntU64(&cri, &version, &cri)) && (version == 0u));
    SSF_ASSERT(SSFASN1DecSkip(&cri, &cri));
    SSF_ASSERT(SSFASN1DecOpenConstructed(&cri, SSF_ASN1_TAG_SEQUENCE, &spki, &cri));
    SSF_ASSERT(SSFASN1DecOpenConstructed(&spki, SSF_ASN1_TAG_SEQUENCE, &alg, &spki));
    SSF_ASSERT(SSFASN1DecGetOIDRaw(&alg, &v, &vLen, &alg));
    SSF_ASSERT((vLen == p->pubKeyAlgOidRawLen) && (memcmp(v, p->pubKeyAlgOidRaw, vLen) == 0));
    SSF_ASSERT(SSFASN1DecGetOIDRaw(&alg, &v, &vLen, &alg));
    SSF_ASSERT((vLen == p->ecCurveOidRawLen) && (memcmp(v, p->ecCurveOidRaw, vLen) == 0));
    SSF_ASSERT(SSFASN1DecIsEmpty(&alg));
    SSF_ASSERT((SSFASN1DecGetBitString(&spki, &v, &vLen, &unused, &spki)) && (unused == 0u));
    SSF_ASSERT((vLen == p->pubKeyLen) && (memcmp(v, p->pubKey, vLen) == 0));
    SSF_ASSERT(SSFASN1DecIsEmpty(&spki));
    SSF_ASSERT(SSFASN1DecGetTLV(&cri, &tag, &v, &vLen, &cri));
    SSF_ASSERT((tag == SSF_ASN1_CONTEXT_EXPLICIT(0)) && (vLen == 0u));
    SSF_ASSERT(SSFASN1DecIsEmpty(&cri));

    /* signatureAlgorithm without parameters, then the signature over the CRI's DER */
    hashLen = _UTCSRHash(isP384, criStart, (uint32_t)(outer.buf - criStart), hash);
    SSF_ASSERT(SSFASN1DecOpenConstructed(&outer, SSF_ASN1_TAG_SEQUENCE, &alg, &outer));
    SSF_ASSERT(SSFASN1DecGetOIDRaw(&alg, &v, &vLen, &alg));
    SSF_ASSERT((vLen == p->sigAlgOidRawLen) && (memcmp(v, p->sigAlgOidRaw, vLen) == 0));
    SSF_ASSERT(SSFASN1DecIsEmpty(&alg));
    SSF_ASSERT((SSFASN1DecGetBitString(&outer, &v, &vLen, &unused, &outer)) && (unused == 0u));
    SSF_ASSERT(SSFASN1DecIsEmpty(&outer));
    SSF_ASSERT(SSFECDSAVerify((isP384 ? SSF_EC_CURVE_P384 : SSF_EC_CURVE_P256), p->pubKey,
                              p->pubKeyLen, hash, hashLen, v, vLen));
}

/* Checks a CSR built from the fixture key against its OpenSSL fixture. */
static void _UTCSRFixture(const SSFX509CSRParams_t *p, bool isP384, const uint8_t *priv,
                          const uint8_t *fix, uint32_t fixLen, const char *fixPemStrOpt)
{
    static uint8_t out[1024];
    static uint8_t cri[1024];
    static char pem[2048];
    SSFASN1Cursor_t cur;
    SSFASN1Cursor_t outer;
    SSFASN1Cursor_t next;
    uint32_t criLen;
    uint32_t len;
    size_t pemLen;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(priv != NULL);
    SSF_REQUIRE(fix != NULL);

    /* The CSRInfo is the fixture's, byte for byte */
    cur.buf = fix;
    cur.bufLen = fixLen;
    SSF_ASSERT(SSFASN1DecOpenConstructed(&cur, SSF_ASN1_TAG_SEQUENCE, &outer, &next));
    SSF_ASSERT(SSFASN1DecSkip(&outer, &next));
    SSF_ASSERT(SSFX509EncodeCSRInfo(cri, sizeof(cri), p, &criLen));
    SSF_ASSERT(criLen == (uint32_t)(next.buf - outer.buf));
    SSF_ASSERT(memcmp(cri, outer.buf, criLen) == 0);

    /* The whole CSR verifies, and with SSF's RFC 6979 signer equals OpenSSL's nonce-type:1 */
    len = _UTCSRBuild(p, isP384, priv, out, sizeof(out));
    _UTCSRVerify(out, len, p, isP384);
    _UTCSRVerify(fix, fixLen, p, isP384);
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
    SSF_ASSERT((len == fixLen) && (memcmp(out, fix, fixLen) == 0));
    /* Is there a PEM form to match? */
    if (fixPemStrOpt != NULL)
    {
        /* Yes, ssfpem gives OpenSSL's text */
        SSF_ASSERT(SSFPEMEncode("CERTIFICATE REQUEST", out, len, pem, sizeof(pem), &pemLen));
        SSF_ASSERT((pemLen == strlen(fixPemStrOpt)) && (memcmp(pem, fixPemStrOpt, pemLen) == 0));
    }
#else
    (void)fixPemStrOpt;
    (void)pem;
    (void)pemLen;
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */
}

/* Checks that CSRInfo and CSR both refuse p in their measure and write passes. */
static void _UTCSRRefuse(const SSFX509CSRParams_t *p, const uint8_t *sig, uint32_t sigLen)
{
    static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE + 16u];
    uint32_t len;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(sig != NULL);

    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSRInfo(NULL, 0, p, &len) == false) && (len == 0u));
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSRInfo(out, sizeof(out), p, &len) == false) && (len == 0u));
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSR(NULL, 0, p, sig, sigLen, &len) == false) && (len == 0u));
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSR(out, sizeof(out), p, sig, sigLen, &len) == false) &&
               (len == 0u));
}

/* Checks that CSRInfo and CSR both accept p. */
static void _UTCSRAccept(const SSFX509CSRParams_t *p, const uint8_t *sig, uint32_t sigLen)
{
    static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
    uint32_t len;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(sig != NULL);

    SSF_ASSERT((SSFX509EncodeCSRInfo(NULL, 0, p, &len)) && (len > 0u));
    SSF_ASSERT((SSFX509EncodeCSRInfo(out, sizeof(out), p, &len)) && (len > 0u));
    SSF_ASSERT((SSFX509EncodeCSR(NULL, 0, p, sig, sigLen, &len)) && (len > 0u));
    SSF_ASSERT((SSFX509EncodeCSR(out, sizeof(out), p, sig, sigLen, &len)) && (len > 0u));
}

/* Asserts all four encoders, measure and write, refuse a Name value that is not UTF-8. */
static void _UTNameUTF8Refuse(SSFX509GenParams_t *g, SSFX509CSRParams_t *c, const uint8_t *sig,
                              uint32_t sigLen)
{
    static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
    uint32_t len;

    SSF_REQUIRE(g != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(sig != NULL);

    SSF_ASSERT(SSFX509EncodeTBS(NULL, 0, g, &len) == false);
    SSF_ASSERT(SSFX509EncodeTBS(out, sizeof(out), g, &len) == false);
    SSF_ASSERT(SSFX509EncodeCert(NULL, 0, g, sig, sigLen, &len) == false);
    SSF_ASSERT(SSFX509EncodeCert(out, sizeof(out), g, sig, sigLen, &len) == false);
    _UTCSRRefuse(c, sig, sigLen);
}

/* Checks that Name values must be well-formed UTF-8 in certificates and CSRs alike. */
static void _UTNameUTF8(void)
{
    static const char *good[] = {
        "plain", "caf\xC3\xA9", "\xE2\x82\xAC" "100", "\xED\x9F\xBF", "\xEE\x80\x80",
        "\xEF\xBF\xBF", "\xF0\x9F\x98\x80", "\xF4\x8F\xBF\xBF", "a\xDF\xBF" "b"
    };
    static const char *bad[] = {
        "\x80", "ab\xBF", "\xC0\xAF", "\xC1\x81", "\xE0\x80\xAF", "\xED\xA0\x80",
        "\xED\xBF\xBF", "\xF0\x8F\xBF\xBF", "\xF4\x90\x80\x80", "\xF5\x80\x80\x80", "\xFF",
        "ok\xC3", "ok\xE2\x82", "ok\xF0\x9F\x98", "\xC3(", "\xE2\x82(",
    };
    static SSFX509GenParams_t g;
    static SSFX509CSRParams_t c;
    static SSFX509Cert_t parsed;
    static uint8_t pub[65];
    static uint8_t sig[72];
    static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
    uint8_t serial[] = { 0x07u };
    uint32_t i;
    uint32_t f;

    memset(pub, 0x04, sizeof(pub));
    memset(sig, 0x30, sizeof(sig));

    /* ---- Well-formed 1..4-byte forms are written as given, in every field ---- */
    for (i = 0; i < (sizeof(good) / sizeof(good[0])); i++)
    {
        _utGenBaseParams(&g, serial, pub, sizeof(pub));
        g.subject.cn = good[i];
        g.subject.o = good[i];
        g.subject.ou = good[i];
        g.subject.st = good[i];
        g.subject.l = good[i];
        g.issuer = g.subject;
        _utGenCheckConsistent(&g, sig, sizeof(sig), out, sizeof(out), &parsed);
        SSF_ASSERT((parsed.subject.cnLen == strlen(good[i])) &&
                   (memcmp(parsed.subject.cn, good[i], parsed.subject.cnLen) == 0));
        SSF_ASSERT((parsed.issuer.lLen == strlen(good[i])) &&
                   (memcmp(parsed.issuer.l, good[i], parsed.issuer.lLen) == 0));
        _UTCSRParams(&c, false, pub);
        c.subject = g.subject;
        _UTCSRAccept(&c, sig, sizeof(sig));
    }

    /* ---- Ill-formed: every encoder refuses, whichever subject or issuer field holds it ---- */
    for (i = 0; i < (sizeof(bad) / sizeof(bad[0])); i++)
    {
        for (f = 0; f < 6u; f++)
        {
            _utGenBaseParams(&g, serial, pub, sizeof(pub));
            _UTCSRParams(&c, false, pub);
            if (f == 0u) c.subject.cn = bad[i];
            else if (f == 1u) c.subject.o = bad[i];
            else if (f == 2u) c.subject.ou = bad[i];
            else if (f == 3u) c.subject.st = bad[i];
            else if (f == 4u) c.subject.l = bad[i];
            else c.subject.cn = "ok";
            /* The certificate subject matches the CSR's; for f == 5 only the issuer is bad */
            g.subject = c.subject;
            if (f == 5u) g.issuer.cn = bad[i];
            if (f == 5u) c.subject.cn = bad[i];
            _UTNameUTF8Refuse(&g, &c, sig, sizeof(sig));
        }
    }
}

/* Checks the CSR buffer sizes, name bounds, size cap and contracts with a placeholder key. */
static void _UTCSRLimits(void)
{
    static SSFX509CSRParams_t p;
    static uint8_t pub[97];
    static uint8_t sig[72];
    static uint8_t big[SSF_X509_CONFIG_MAX_CERT_SIZE];
    static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
    static char name[130];
    static uint32_t len;
    static uint32_t need;
    static uint32_t sigLen;

    memset(pub, 0x04, sizeof(pub));
    memset(sig, 0x30, sizeof(sig));
    _UTCSRParams(&p, false, pub);
    p.subject.cn = "dev-1";

    /* ---- Measure, one byte short, exact fit ---- */
    SSF_ASSERT(SSFX509EncodeCSRInfo(NULL, 0, &p, &need));
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSRInfo(out, (need - 1u), &p, &len) == false) && (len == 0u));
    SSF_ASSERT((SSFX509EncodeCSRInfo(out, need, &p, &len)) && (len == need));
    SSF_ASSERT(SSFX509EncodeCSR(NULL, 0, &p, sig, sizeof(sig), &need));
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSR(out, (need - 1u), &p, sig, sizeof(sig), &len) == false) &&
               (len == 0u));
    SSF_ASSERT((SSFX509EncodeCSR(out, need, &p, sig, sizeof(sig), &len)) && (len == need));

    /* ---- Subject bounds (RFC 5280): at the bound accepted, one over refused ---- */
    memset(name, 'a', sizeof(name));
    name[64] = '\0';
    p.subject.cn = name;
    _UTCSRAccept(&p, sig, sizeof(sig));
    p.subject.cn = NULL;
    p.subject.o = name;
    _UTCSRAccept(&p, sig, sizeof(sig));
    p.subject.o = NULL;
    p.subject.ou = name;
    _UTCSRAccept(&p, sig, sizeof(sig));
    name[64] = 'a';
    name[65] = '\0';
    p.subject.ou = NULL;
    p.subject.cn = name;
    _UTCSRRefuse(&p, sig, sizeof(sig));
    p.subject.cn = NULL;
    p.subject.o = name;
    _UTCSRRefuse(&p, sig, sizeof(sig));
    p.subject.o = NULL;
    p.subject.ou = name;
    _UTCSRRefuse(&p, sig, sizeof(sig));
    p.subject.ou = NULL;
    memset(name, 'a', sizeof(name));
    name[128] = '\0';
    p.subject.st = name;
    _UTCSRAccept(&p, sig, sizeof(sig));
    p.subject.st = NULL;
    p.subject.l = name;
    _UTCSRAccept(&p, sig, sizeof(sig));
    name[128] = 'a';
    name[129] = '\0';
    p.subject.l = NULL;
    p.subject.st = name;
    _UTCSRRefuse(&p, sig, sizeof(sig));
    p.subject.st = NULL;
    p.subject.l = name;
    _UTCSRRefuse(&p, sig, sizeof(sig));
    p.subject.l = NULL;
    p.subject.c = "US";
    _UTCSRAccept(&p, sig, sizeof(sig));
    p.subject.c = "U";
    _UTCSRRefuse(&p, sig, sizeof(sig));
    p.subject.c = "USA";
    _UTCSRRefuse(&p, sig, sizeof(sig));
    p.subject.c = "U*";
    _UTCSRRefuse(&p, sig, sizeof(sig));
    p.subject.c = NULL;

    /* ---- Size cap: the largest signature that fits, and one byte more ---- */
    memset(big, 0x30, sizeof(big));
    sigLen = (uint32_t)sizeof(big);
    while ((sigLen > 0u) && (!SSFX509EncodeCSR(NULL, 0, &p, big, sigLen, &need))) sigLen--;
    SSF_ASSERT((sigLen > 0u) && (need == SSF_X509_CONFIG_MAX_CERT_SIZE));
    SSF_ASSERT((SSFX509EncodeCSR(out, sizeof(out), &p, big, sigLen, &len)) && (len == need));
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSR(NULL, 0, &p, big, (sigLen + 1u), &len) == false) && (len == 0u));
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSR(out, sizeof(out), &p, big, (sigLen + 1u), &len) == false) &&
               (len == 0u));

    /* ---- A signature length near 4 GB is refused, not wrapped to a small size ---- */
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSR(NULL, 0, &p, sig, 0xFFFFFFF0u, &len) == false) && (len == 0u));
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSR(NULL, 0, &p, sig, 0xFFFFFFFEu, &len) == false) && (len == 0u));
    {
        static SSFX509GenParams_t gp;
        static const uint8_t serial[] = { 0x01u };

        _utGenBaseParams(&gp, serial, pub, 65u);
        len = 1u;
        SSF_ASSERT((SSFX509EncodeCert(NULL, 0, &gp, sig, 0xFFFFFFF0u, &len) == false) &&
                   (len == 0u));
        SSF_ASSERT((SSFX509EncodeCert(NULL, 0, &gp, sig, sizeof(sig), &len)) && (len > 0u));
        gp.sigAlgParams = sig;
        gp.sigAlgParamsLen = 0xFFFFFFFEu;
        len = 1u;
        SSF_ASSERT((SSFX509EncodeCert(NULL, 0, &gp, sig, sizeof(sig), &len) == false) &&
                   (len == 0u));
        len = 1u;
        SSF_ASSERT((SSFX509EncodeTBS(NULL, 0, &gp, &len) == false) && (len == 0u));
    }
    p.pubKeyLen = 0xFFFFFFF0u;
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSRInfo(NULL, 0, &p, &len) == false) && (len == 0u));
    p.pubKeyLen = 65u;
    /* Content that fits 32 bits but whose outer header would not: CRI + AlgId + BIT STRING */
    SSF_ASSERT(SSFX509EncodeCSRInfo(NULL, 0, &p, &need));
    sigLen = 0xFFFFFFFCu - need - 12u - 7u;
    len = 1u;
    SSF_ASSERT((SSFX509EncodeCSR(NULL, 0, &p, sig, sigLen, &len) == false) && (len == 0u));

    /* ---- Contracts ---- */
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 0, NULL, &len));
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 0, &p, NULL));
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 1u, &p, &len));
    SSF_ASSERT_TEST(SSFX509EncodeCSR(NULL, 0, NULL, sig, sizeof(sig), &len));
    SSF_ASSERT_TEST(SSFX509EncodeCSR(NULL, 0, &p, sig, sizeof(sig), NULL));
    SSF_ASSERT_TEST(SSFX509EncodeCSR(NULL, 1u, &p, sig, sizeof(sig), &len));
    SSF_ASSERT_TEST(SSFX509EncodeCSR(NULL, 0, &p, NULL, sizeof(sig), &len));
    SSF_ASSERT_TEST(SSFX509EncodeCSR(NULL, 0, &p, sig, 0u, &len));
    SSF_ASSERT_TEST(SSFX509EncodeCSR(out, sizeof(out), &p, &out[8], sizeof(sig), &len));
    SSF_ASSERT_TEST(SSFX509EncodeCSR(&out[8], 64u, &p, out, 9u, &len));
    SSF_ASSERT(SSFX509EncodeCSR(&out[256], 1024u, &p, out, 256u, &len));
    SSF_ASSERT(SSFX509EncodeCSR(out, 256u, &p, &out[256], 9u, &len));
    memcpy(&out[512], pub, 65u);
    p.pubKey = &out[512];
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(out, 1024u, &p, &len));
    SSF_ASSERT_TEST(SSFX509EncodeCSR(out, 1024u, &p, sig, sizeof(sig), &len));
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(&out[576], 256u, &p, &len));
    SSF_ASSERT(SSFX509EncodeCSRInfo(out, 512u, &p, &len));
    SSF_ASSERT(SSFX509EncodeCSRInfo(&out[577], 256u, &p, &len));
    SSF_ASSERT(SSFX509EncodeCSR(&out[577], 512u, &p, sig, sizeof(sig), &len));
    p.pubKey = pub;
    p.sigAlgOidRaw = NULL;
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 0, &p, &len));
    SSF_ASSERT_TEST(SSFX509EncodeCSR(NULL, 0, &p, sig, sizeof(sig), &len));
    _UTCSRParams(&p, false, pub);
    p.sigAlgOidRawLen = 0u;
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 0, &p, &len));
    _UTCSRParams(&p, false, pub);
    p.pubKeyAlgOidRaw = NULL;
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 0, &p, &len));
    _UTCSRParams(&p, false, pub);
    p.pubKeyAlgOidRawLen = 0u;
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 0, &p, &len));
    _UTCSRParams(&p, false, pub);
    p.ecCurveOidRaw = NULL;
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 0, &p, &len));
    _UTCSRParams(&p, false, pub);
    p.ecCurveOidRawLen = 0u;
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 0, &p, &len));
    _UTCSRParams(&p, false, pub);
    p.pubKey = NULL;
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 0, &p, &len));
    _UTCSRParams(&p, false, pub);
    p.pubKeyLen = 0u;
    SSF_ASSERT_TEST(SSFX509EncodeCSRInfo(NULL, 0, &p, &len));
}

/* Runs the CSR generation tests. */
static void _UTCSR(void)
{
    static SSFX509CSRParams_t p;
    static uint8_t out[1024];
    uint8_t priv[48];
    uint8_t pub[97];
    size_t pubLen;
    uint32_t len;
    uint32_t i;

    /* ---- OpenSSL fixtures ---- */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    _UTCSRParams(&p, false, _utCsrP256Pub);
    p.subject.cn = "dev-1";
    _UTCSRFixture(&p, false, _utCsrP256Priv, _utCsrP256CN, sizeof(_utCsrP256CN),
                  _utCsrP256CNPem);
    p.subject.c = "US";
    p.subject.st = "CA";
    p.subject.l = "Test";
    p.subject.o = "SSF";
    p.subject.ou = "Dev";
    p.subject.cn = "dev-2";
    _UTCSRFixture(&p, false, _utCsrP256Priv, _utCsrP256All, sizeof(_utCsrP256All), NULL);
    _UTCSRParams(&p, false, _utCsrP256Pub);
    _UTCSRFixture(&p, false, _utCsrP256Priv, _utCsrP256Empty, sizeof(_utCsrP256Empty), NULL);
#endif /* SSF_EC_CONFIG_ENABLE_P256 */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    _UTCSRParams(&p, true, _utCsrP384Pub);
    p.subject.cn = "dev-384";
    _UTCSRFixture(&p, true, _utCsrP384Priv, _utCsrP384CN, sizeof(_utCsrP384CN), NULL);
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

    /* ---- Generated keys on each built curve ---- */
    for (i = 0; i < 6u; i++)
    {
        bool isP384 = ((i & 1u) != 0u);

        /* Is this curve compiled out? */
        if (((isP384) && (SSF_EC_CONFIG_ENABLE_P384 == 0)) ||
            ((!isP384) && (SSF_EC_CONFIG_ENABLE_P256 == 0)))
        {
            /* Yes, skip it */
            continue;
        }
        SSF_ASSERT(SSFECDSAKeyGen((isP384 ? SSF_EC_CURVE_P384 : SSF_EC_CURVE_P256), priv,
                                  sizeof(priv), pub, sizeof(pub), &pubLen));
        _UTCSRParams(&p, isP384, pub);
        p.subject.cn = "generated";
        p.subject.c = ((i < 2u) ? "US" : NULL);
        len = _UTCSRBuild(&p, isP384, priv, out, sizeof(out));
        _UTCSRVerify(out, len, &p, isP384);
    }
    memset(priv, 0, sizeof(priv));

    _UTCSRLimits();
    _UTNameUTF8();
}

/* --------------------------------------------------------------------------------------------- */
/* Runs the ssfx509 unit tests.                                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFX509UnitTest(void)
{
    static SSFX509Cert_t cert;

#if SSF_ECDSA_UT_CAN_SIGN == 0
    /* Signing compiled out and no OpenSSL: the generated-input tests below cannot be built */
    SSF_UT_PRINTF("%s skipped: needs SSF_ECDSA_CONFIG_ENABLE_SIGN or OpenSSL\n", __func__);
    return;
#endif

    /* ---- Parse the test certificate ---- */
    SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &cert) == true);

    /* ---- Version ---- */
    SSF_ASSERT(cert.version == 2u);

    /* ---- Serial number ---- */
    SSF_ASSERT(cert.serial != NULL);
    SSF_ASSERT(cert.serialLen > 0);

    /* ---- Signature algorithm: ECDSA with SHA-256 ---- */
    SSF_ASSERT(SSFX509IsSigECDSASHA256(&cert) == true);
    SSF_ASSERT(SSFX509IsKeyRSA(&cert) == false);

    /* ---- Subject DN ---- */
    SSF_ASSERT(cert.subject.cn != NULL);
    SSF_ASSERT(cert.subject.cnLen == 14u);
    SSF_ASSERT(memcmp(cert.subject.cn, "test.ssf.local", 14) == 0);
    SSF_ASSERT((cert.subject.c != NULL) && (cert.subject.cLen == 2u));
    SSF_ASSERT(memcmp(cert.subject.c, "US", 2) == 0);
    SSF_ASSERT((cert.subject.st != NULL) && (cert.subject.stLen == 2u));
    SSF_ASSERT(memcmp(cert.subject.st, "CA", 2) == 0);
    SSF_ASSERT((cert.subject.l != NULL) && (cert.subject.lLen == 4u));
    SSF_ASSERT(memcmp(cert.subject.l, "Test", 4) == 0);
    SSF_ASSERT((cert.subject.o != NULL) && (cert.subject.oLen == 3u));
    SSF_ASSERT(memcmp(cert.subject.o, "SSF", 3) == 0);
    SSF_ASSERT((cert.subject.ou != NULL) && (cert.subject.ouLen == 3u));
    SSF_ASSERT(memcmp(cert.subject.ou, "Dev", 3) == 0);

    /* ---- Issuer DN (self-signed, same as subject) ---- */
    SSF_ASSERT(cert.issuer.cnLen == cert.subject.cnLen);
    SSF_ASSERT(memcmp(cert.issuer.cn, cert.subject.cn, cert.subject.cnLen) == 0);

    /* ---- Validity dates; notBefore: Apr 5 20:58:38 2026 UTC ---- */
    SSF_ASSERT(cert.notBefore > 0);
    SSF_ASSERT(cert.notAfter > cert.notBefore);
    /* Check that the cert is currently valid (issued today) */
    SSF_ASSERT(SSFX509IsValid(&cert, cert.notBefore + 1u) == true);
    /* Check expired */
    SSF_ASSERT(SSFX509IsValid(&cert, cert.notAfter + 1u) == false);
    /* Check not-yet-valid */
    SSF_ASSERT(SSFX509IsValid(&cert, cert.notBefore - 1u) == false);

    /* ---- Public key: EC on the build's test curve ---- */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    SSF_ASSERT(SSFX509IsKeyP256(&cert) == true);
#else
    SSF_ASSERT(SSFX509IsKeyP384(&cert) == true);
#endif /* SSF_EC_CONFIG_ENABLE_P256 */
    SSF_ASSERT(cert.pubKey != NULL);
    /* Uncompressed point: 04 || X || Y */
    SSF_ASSERT(cert.pubKeyLen == _UT_PUB_LEN);
    SSF_ASSERT(cert.pubKey[0] == 0x04u);

    /* ---- Extensions ---- */
    /* SKID, AKID, SAN, BC, KU */
    SSF_ASSERT(cert.extsLen == 5u);

    /* Basic Constraints: CA:FALSE */
    SSF_ASSERT(cert.hasBasicConstraints == true);
    SSF_ASSERT(cert.isCA == false);
    SSF_ASSERT(cert.pathLenConstraint == -1);

    /* Key Usage: digitalSignature */
    SSF_ASSERT(cert.hasKeyUsage == true);
    SSF_ASSERT((cert.keyUsageBits & SSF_X509_KU_DIGITAL_SIGNATURE) != 0);
    SSF_ASSERT((cert.keyUsageBits & SSF_X509_KU_KEY_CERT_SIGN) == 0);

    /* Subject Alternative Name: DNS:test.ssf.local, DNS:localhost */
    SSF_ASSERT(cert.sanLen == 2u);
    SSF_ASSERT(cert.san[0].type == SSF_X509_SAN_DNS);
    SSF_ASSERT(cert.san[0].valLen == 14u);
    SSF_ASSERT(memcmp(cert.san[0].val, "test.ssf.local", 14) == 0);
    SSF_ASSERT(cert.san[1].type == SSF_X509_SAN_DNS);
    SSF_ASSERT(cert.san[1].valLen == 9u);
    SSF_ASSERT(memcmp(cert.san[1].val, "localhost", 9) == 0);

    /* Subject Key Identifier */
    SSF_ASSERT(cert.skid != NULL);
    SSF_ASSERT(cert.skidLen == 20u);

    /* Authority Key Identifier */
    SSF_ASSERT(cert.akid != NULL);
    SSF_ASSERT(cert.akidLen == 20u);
    /* Self-signed: AKID == SKID */
    SSF_ASSERT(memcmp(cert.akid, cert.skid, 20) == 0);

    /* ---- TBS raw and signature ---- */
    SSF_ASSERT(cert.tbsRaw != NULL);
    SSF_ASSERT(cert.tbsRawLen > 0);
    SSF_ASSERT(cert.signature != NULL);
    SSF_ASSERT(cert.signatureLen > 0);

    /* ---- Truncated certificate fails ---- */
    SSF_ASSERT(SSFX509Parse(_utTestCertDER, 10, &cert) == false);

    /* ==== Certificate Generation Round-Trip ==== */
    {
        /* OID constants for ECDSA P-256 */
        static const uint8_t ecdsaSHA256[] = {
            0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u
        };
        static const uint8_t ecPubKey[] = {
            0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u
        };
        static const uint8_t p256[] = {
            0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u
        };
        /* Fake public key (65 bytes, uncompressed P-256) */
        static const uint8_t fakePubKey[65] = {
            0x04u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
            0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
            0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
            0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu,
            0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
            0x28u, 0x29u, 0x2Au, 0x2Bu, 0x2Cu, 0x2Du, 0x2Eu, 0x2Fu,
            0x30u, 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u, 0x37u,
            0x38u, 0x39u, 0x3Au, 0x3Bu, 0x3Cu, 0x3Du, 0x3Eu, 0x3Fu,
            0x40u
        };
        static const uint8_t serial[] = { 0x01u, 0x02u, 0x03u };
        static const uint8_t fakeSig[64] = { 0xAAu }; /* Dummy signature */

        static SSFX509GenParams_t genParams;
        static uint8_t derBuf[1024];
        uint32_t derLen;
        static SSFX509Cert_t parsed;

        memset(&genParams, 0, sizeof(genParams));
        genParams.pathLenConstraint = -1;
        genParams.version = 2;
        genParams.serial = serial;
        genParams.serialLen = sizeof(serial);
        genParams.sigAlgOidRaw = ecdsaSHA256;
        genParams.sigAlgOidRawLen = sizeof(ecdsaSHA256);
        genParams.issuer.cn = "Test CA";
        genParams.issuer.c = "US";
        genParams.issuer.o = "SSF";
        genParams.subject.cn = "test.device";
        genParams.subject.c = "US";
        genParams.subject.o = "SSF";
        genParams.notBefore = 1718452800ull;  /* 2024-06-15 12:00:00 */
        genParams.notAfter = 1750000000ull;   /* ~2025-06-15 */
        genParams.pubKeyAlgOidRaw = ecPubKey;
        genParams.pubKeyAlgOidRawLen = sizeof(ecPubKey);
        genParams.ecCurveOidRaw = p256;
        genParams.ecCurveOidRawLen = sizeof(p256);
        genParams.pubKey = fakePubKey;
        genParams.pubKeyLen = sizeof(fakePubKey);
        genParams.addBasicConstraints = true;
        genParams.isCA = false;
        genParams.addKeyUsage = true;
        genParams.keyUsageBits = SSF_X509_KU_DIGITAL_SIGNATURE;

        /* ---- Two-pass: measure then encode ---- */
        {
            uint32_t needed = 0u;
            (void)SSFX509EncodeCert(NULL, 0, &genParams, fakeSig, sizeof(fakeSig), &needed);
            SSF_ASSERT(needed > 0);
            SSF_ASSERT(needed <= sizeof(derBuf));
        }

        /* ---- Encode the full certificate ---- */
        (void)SSFX509EncodeCert(derBuf, sizeof(derBuf), &genParams, fakeSig, sizeof(fakeSig),
         &derLen);
        SSF_ASSERT(derLen > 0);

        /* ---- Parse it back and verify ---- */
        SSF_ASSERT(SSFX509Parse(derBuf, derLen, &parsed) == true);

        SSF_ASSERT(parsed.version == 2u);
        SSF_ASSERT(parsed.serialLen == 3u);
        SSF_ASSERT(memcmp(parsed.serial, serial, 3) == 0);

        /* Subject */
        SSF_ASSERT(parsed.subject.cn != NULL);
        SSF_ASSERT(parsed.subject.cnLen == 11u);
        SSF_ASSERT(memcmp(parsed.subject.cn, "test.device", 11) == 0);
        SSF_ASSERT((parsed.subject.c != NULL) && (parsed.subject.cLen == 2u));
        SSF_ASSERT(memcmp(parsed.subject.c, "US", 2) == 0);

        /* Issuer */
        SSF_ASSERT(parsed.issuer.cn != NULL);
        SSF_ASSERT(parsed.issuer.cnLen == 7u);
        SSF_ASSERT(memcmp(parsed.issuer.cn, "Test CA", 7) == 0);

        /* Validity */
        SSF_ASSERT(parsed.notBefore == 1718452800ull);
        SSF_ASSERT(parsed.notAfter == 1750000000ull);

        /* Public key */
        SSF_ASSERT(SSFX509IsKeyP256(&parsed) == true);
        SSF_ASSERT(parsed.pubKeyLen == 65u);
        SSF_ASSERT(memcmp(parsed.pubKey, fakePubKey, 65) == 0);

        /* Algorithm */
        SSF_ASSERT(SSFX509IsSigECDSASHA256(&parsed) == true);

        /* Extensions */
        SSF_ASSERT(parsed.hasBasicConstraints == true);
        SSF_ASSERT(parsed.isCA == false);
        SSF_ASSERT(parsed.hasKeyUsage == true);
        SSF_ASSERT((parsed.keyUsageBits & SSF_X509_KU_DIGITAL_SIGNATURE) != 0);

        /* Signature */
        SSF_ASSERT(parsed.signature != NULL);
        SSF_ASSERT(parsed.signatureLen == sizeof(fakeSig));

        /* TBS raw exists for signature verification */
        SSF_ASSERT(parsed.tbsRaw != NULL);
        SSF_ASSERT(parsed.tbsRawLen > 0);
    }

    /* ---- 1. Signature Verification (SSFX509VerifyCertSignature) ---- */
    {
        /* 1a. Self-signed cert: verify signature against itself */
        {
            static uint8_t caDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t caDerLen;
            static uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t pubKeyLen;
            static SSFX509Cert_t caCert;

            memset(privKey, 0, sizeof(privKey));
            SSF_ASSERT(_GenTestCert("selfsign.test", 1700000000ull, 2000000000ull,
                       true, true, true,
                       SSF_X509_KU_KEY_CERT_SIGN | SSF_X509_KU_CRL_SIGN,
                       caDer, sizeof(caDer), &caDerLen,
                       privKey, pubKey, &pubKeyLen) == true);

            SSF_ASSERT(SSFX509Parse(caDer, caDerLen, &caCert) == true);
            SSF_ASSERT(SSFX509VerifyCertSignature(&caCert, &caCert) == true);
        }

        /* 1b. Two certs with different keys: cross-verification fails */
        {
            static uint8_t cert1Der[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t cert1DerLen;
            static uint8_t priv1[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            static uint8_t pub1[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t pub1Len;
            static uint8_t cert2Der[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t cert2DerLen;
            static uint8_t priv2[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            static uint8_t pub2[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t pub2Len;
            static SSFX509Cert_t c1;
            static SSFX509Cert_t c2;

            memset(priv1, 0, sizeof(priv1));
            memset(priv2, 0, sizeof(priv2));
            SSF_ASSERT(_GenTestCert("cert1.test", 1700000000ull, 2000000000ull,
                       false, false, false, 0,
                       cert1Der, sizeof(cert1Der), &cert1DerLen,
                       priv1, pub1, &pub1Len) == true);
            SSF_ASSERT(_GenTestCert("cert2.test", 1700000000ull, 2000000000ull,
                       false, false, false, 0,
                       cert2Der, sizeof(cert2Der), &cert2DerLen,
                       priv2, pub2, &pub2Len) == true);

            SSF_ASSERT(SSFX509Parse(cert1Der, cert1DerLen, &c1) == true);
            SSF_ASSERT(SSFX509Parse(cert2Der, cert2DerLen, &c2) == true);
            /* cert1 signed by key1, verified with key2 should fail */
            SSF_ASSERT(SSFX509VerifyCertSignature(&c1, &c2) == false);
            SSF_ASSERT(SSFX509VerifyCertSignature(&c2, &c1) == false);
        }

        /* 1c. Verify existing test cert signature against itself */
        {
            static SSFX509Cert_t selfCert;
            SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &selfCert) == true);
            SSF_ASSERT(SSFX509VerifyCertSignature(&selfCert, &selfCert) == true);
        }
    }

    /* ---- 2. Chain Verification (SSFX509VerifyChain) ---- */
    {
        /* A time inside both generated certs and _utTestCertDER (valid Apr 5 2026 to Apr 5 2027) */
        uint64_t nowTime = 1780000000ull;

        /* 2a. Self-signed trust anchor using _utTestCertDER (has SANs) */
        {
            const uint8_t *chain[1];
            uint32_t chainLens[1];
            const uint8_t *trust[1];
            uint32_t trustLens[1];

            chain[0] = _utTestCertDER; chainLens[0] = sizeof(_utTestCertDER);
            trust[0] = _utTestCertDER; trustLens[0] = sizeof(_utTestCertDER);
            /* "test.ssf.local" is a SAN in the test cert */
            SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                       trust, trustLens, 1, "test.ssf.local", nowTime, &_utVErr) == true);
            _UT_VERR(OK, 0u);
            /* "localhost" is also a SAN */
            SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                       trust, trustLens, 1, "localhost", nowTime, &_utVErr) == true);
            _UT_VERR(OK, 0u);
        }

        /* 2b. Hostname mismatch: valid self-signed chain but wrong hostname */
        {
            const uint8_t *chain[1];
            uint32_t chainLens[1];
            const uint8_t *trust[1];
            uint32_t trustLens[1];

            chain[0] = _utTestCertDER; chainLens[0] = sizeof(_utTestCertDER);
            trust[0] = _utTestCertDER; trustLens[0] = sizeof(_utTestCertDER);
            /* "wrong.test" is NOT a SAN */
            SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                       trust, trustLens, 1, "wrong.test", nowTime, &_utVErr) == false);
            _UT_VERR(ERR_HOSTNAME, 0u);
        }

        /* 2d. Expired cert: notAfter in the past relative to nowTime */
        {
            static uint8_t caDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t caDerLen;
            static uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t pubKeyLen;
            const uint8_t *chain[1];
            uint32_t chainLens[1];
            const uint8_t *trust[1];
            uint32_t trustLens[1];

            memset(privKey, 0, sizeof(privKey));
            SSF_ASSERT(_GenTestCert("expired.test", 1700000000ull, 1770000000ull,
                       true, true, true,
                       SSF_X509_KU_KEY_CERT_SIGN | SSF_X509_KU_CRL_SIGN,
                       caDer, sizeof(caDer), &caDerLen,
                       privKey, pubKey, &pubKeyLen) == true);

            chain[0] = caDer; chainLens[0] = caDerLen;
            trust[0] = caDer; trustLens[0] = caDerLen;
            /* nowTime=1780000000 > notAfter=1770000000 */
            SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                       trust, trustLens, 1, "expired.test", nowTime, &_utVErr) == false);
            _UT_VERR(ERR_EXPIRED, 0u);
        }

        /* 2e. Not-yet-valid cert: notBefore in the future */
        {
            static uint8_t caDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t caDerLen;
            static uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t pubKeyLen;
            const uint8_t *chain[1];
            uint32_t chainLens[1];
            const uint8_t *trust[1];
            uint32_t trustLens[1];

            memset(privKey, 0, sizeof(privKey));
            SSF_ASSERT(_GenTestCert("future.test", 1800000000ull, 2000000000ull,
                       true, true, true,
                       SSF_X509_KU_KEY_CERT_SIGN | SSF_X509_KU_CRL_SIGN,
                       caDer, sizeof(caDer), &caDerLen,
                       privKey, pubKey, &pubKeyLen) == true);

            chain[0] = caDer; chainLens[0] = caDerLen;
            trust[0] = caDer; trustLens[0] = caDerLen;
            /* nowTime=1780000000 < notBefore=1800000000 */
            SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                       trust, trustLens, 1, "future.test", nowTime, &_utVErr) == false);
            _UT_VERR(ERR_NOT_YET_VALID, 0u);
        }

        /* 2f. Empty trust store: trustCount=0 is a precondition violation, see the SSF_REQUIRE */
        {
            static uint8_t caDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t caDerLen;
            static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t caPubLen;
            static uint8_t otherDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t otherDerLen;
            static uint8_t otherPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            static uint8_t otherPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t otherPubLen;
            const uint8_t *chain[1];
            uint32_t chainLens[1];
            const uint8_t *trust[1];
            uint32_t trustLens[1];

            memset(caPriv, 0, sizeof(caPriv));
            memset(otherPriv, 0, sizeof(otherPriv));
            SSF_ASSERT(_GenTestCert("real.test", 1700000000ull, 2000000000ull,
                       true, true, true,
                       SSF_X509_KU_KEY_CERT_SIGN | SSF_X509_KU_CRL_SIGN,
                       caDer, sizeof(caDer), &caDerLen,
                       caPriv, caPub, &caPubLen) == true);
            SSF_ASSERT(_GenTestCert("other.test", 1700000000ull, 2000000000ull,
                       true, true, true,
                       SSF_X509_KU_KEY_CERT_SIGN | SSF_X509_KU_CRL_SIGN,
                       otherDer, sizeof(otherDer), &otherDerLen,
                       otherPriv, otherPub, &otherPubLen) == true);

            chain[0] = caDer;    chainLens[0] = caDerLen;
            trust[0] = otherDer; trustLens[0] = otherDerLen;
            /* Chain cert issued by "real.test", trust only has "other.test" */
            SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                       trust, trustLens, 1, "real.test", nowTime, &_utVErr) == false);
            _UT_VERR(ERR_UNKNOWN_CA, 0u);
        }

        /* 2g. Non-CA intermediate: chain with non-CA cert as issuer */
        {
            static uint8_t midDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t midDerLen;
            static uint8_t midPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            static uint8_t midPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t midPubLen;
            static uint8_t leafDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t leafDerLen;
            static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t leafPubLen;
            const uint8_t *chain[2];
            uint32_t chainLens[2];
            const uint8_t *trust[1];
            uint32_t trustLens[1];

            /* Intermediate with isCA=false (no BC or BC with CA:false) */
            memset(midPriv, 0, sizeof(midPriv));
            SSF_ASSERT(_GenTestCert("mid.test", 1700000000ull, 2000000000ull,
                       false, true, false, 0,  /* addBC=true, isCA=false */
                       midDer, sizeof(midDer), &midDerLen,
                       midPriv, midPub, &midPubLen) == true);

            SSF_ASSERT(_GenSignedLeafCert("leaf2.test", "mid.test",
                       1700000000ull, 2000000000ull,
                       leafDer, sizeof(leafDer), &leafDerLen,
                       midPriv, leafPub, &leafPubLen) == true);

            chain[0] = leafDer; chainLens[0] = leafDerLen;
            chain[1] = midDer;  chainLens[1] = midDerLen;
            trust[0] = midDer;  trustLens[0] = midDerLen;
            /* Anchor mid.test's own BC is unchecked, so only the host name check fails (no SAN) */
            SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 2,
                       trust, trustLens, 1, "leaf2.test", nowTime, &_utVErr) == false);
            _UT_VERR(ERR_HOSTNAME, 0u);

            /* On the path below a real root, mid.test is NOT a CA: verification fails */
            {
                static uint8_t rootDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
                static uint8_t mid2Der[SSF_X509_CONFIG_MAX_CERT_SIZE];
                static uint8_t rootPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
                static uint8_t rootPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
                static const uint8_t ser[] = { 0x31u };
                static SSFX509GenParams_t mp;
                size_t rootPubLen;
                uint32_t rootDerLen;
                uint32_t mid2Len;

                SSF_ASSERT(_utMakeCA("root.test", ser, rootPriv, rootPub, &rootPubLen, rootDer,
                                     sizeof(rootDer), &rootDerLen) == true);
                _utGenBaseParams(&mp, ser, midPub, (uint32_t)midPubLen);
                mp.issuer.cn = "root.test";
                mp.subject.cn = "mid.test";
                mp.addBasicConstraints = true;
                mp.isCA = false;
                mid2Len = _utSignCert(&mp, rootPriv, mid2Der, sizeof(mid2Der));
                SSF_ASSERT(mid2Len != 0u);
                chain[1] = mid2Der; chainLens[1] = mid2Len;
                trust[0] = rootDer; trustLens[0] = rootDerLen;
                SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 2,
                           trust, trustLens, 1, "leaf2.test", nowTime, &_utVErr) == false);
                _UT_VERR(ERR_NOT_CA, 1u);
            }
        }
    }

    /* ---- 3. Validity Checking (SSFX509IsValid) ---- */
    {
        static SSFX509Cert_t vc;
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &vc) == true);

        /* 3a. Time inside validity window */
        SSF_ASSERT(SSFX509IsValid(&vc, vc.notBefore + 1000u) == true);

        /* 3b. Time before notBefore */
        SSF_ASSERT(SSFX509IsValid(&vc, vc.notBefore - 1u) == false);

        /* 3c. Time after notAfter */
        SSF_ASSERT(SSFX509IsValid(&vc, vc.notAfter + 1u) == false);

        /* 3d. Time exactly at notBefore (inclusive) */
        SSF_ASSERT(SSFX509IsValid(&vc, vc.notBefore) == true);

        /* 3e. Time exactly at notAfter (inclusive per RFC 5280 Section 4.1.2.5) */
        SSF_ASSERT(SSFX509IsValid(&vc, vc.notAfter) == true);
    }

    /* ---- 4. OID Helper Functions ---- */
    {
        static SSFX509Cert_t oc;
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &oc) == true);

        /* 4a. Positive: ECDSA cert on the build's test curve */
        SSF_ASSERT(SSFX509IsSigECDSASHA256(&oc) == true);
#if SSF_EC_CONFIG_ENABLE_P256 == 1
        SSF_ASSERT(SSFX509IsKeyP256(&oc) == true);
#else
        SSF_ASSERT(SSFX509IsKeyP384(&oc) == true);
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

        /* 4b. Negative: not RSA, not the other curve */
        SSF_ASSERT(SSFX509IsKeyRSA(&oc) == false);
#if SSF_EC_CONFIG_ENABLE_P256 == 1
        SSF_ASSERT(SSFX509IsKeyP384(&oc) == false);
#else
        SSF_ASSERT(SSFX509IsKeyP256(&oc) == false);
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

        /* 4c. Negative: RSA-related OID helpers */
        SSF_ASSERT(SSFX509IsSigRSAPKCS1SHA256(&oc) == false);
        SSF_ASSERT(SSFX509IsSigRSAPKCS1SHA384(&oc) == false);
        SSF_ASSERT(SSFX509IsSigRSAPSSSHA256(&oc) == false);
        SSF_ASSERT(SSFX509IsSigRSAPSSSHA384(&oc) == false);

        /* 4d. Negative: not ECDSA-SHA384 */
        SSF_ASSERT(SSFX509IsSigECDSASHA384(&oc) == false);
    }

    /* ---- 5. Extension Parsing ---- */
    {
        static SSFX509Cert_t ec;
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &ec) == true);

        /* 5a. BasicConstraints */
        SSF_ASSERT(ec.hasBasicConstraints == true);
        SSF_ASSERT(ec.isCA == false);
        SSF_ASSERT(ec.pathLenConstraint == -1);

        /* 5b. KeyUsage */
        SSF_ASSERT(ec.hasKeyUsage == true);
        SSF_ASSERT((ec.keyUsageBits & SSF_X509_KU_DIGITAL_SIGNATURE) != 0u);

        /* 5c. SAN */
        SSF_ASSERT(ec.sanLen == 2u);
        SSF_ASSERT(ec.san[0].type == SSF_X509_SAN_DNS);
        SSF_ASSERT(ec.san[0].valLen == 14u);
        SSF_ASSERT(memcmp(ec.san[0].val, "test.ssf.local", 14) == 0);
        SSF_ASSERT(ec.san[1].type == SSF_X509_SAN_DNS);
        SSF_ASSERT(ec.san[1].valLen == 9u);
        SSF_ASSERT(memcmp(ec.san[1].val, "localhost", 9) == 0);

        /* 5d. SKID */
        SSF_ASSERT(ec.skid != NULL);
        SSF_ASSERT(ec.skidLen == 20u);

        /* 5e. AKID */
        SSF_ASSERT(ec.akid != NULL);
        SSF_ASSERT(ec.akidLen == 20u);

        /* 5f. Total extensions count */
        SSF_ASSERT(ec.extsLen == 5u);
    }

    /* ---- 6. Certificate Generation Edge Cases ---- */
    {
        /* 6a. V1 cert (version=0, no extensions) */
        {
            static const uint8_t fakePubKeyV1[65] = {
                0x04u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
                0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
                0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
                0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu,
                0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
                0x28u, 0x29u, 0x2Au, 0x2Bu, 0x2Cu, 0x2Du, 0x2Eu, 0x2Fu,
                0x30u, 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u, 0x37u,
                0x38u, 0x39u, 0x3Au, 0x3Bu, 0x3Cu, 0x3Du, 0x3Eu, 0x3Fu,
                0x40u
            };
            static const uint8_t serialV1[] = { 0x05u };
            static const uint8_t fakeSigV1[64] = { 0xBBu };
            static SSFX509GenParams_t p;
            static uint8_t buf[1024];
            uint32_t len;
            static SSFX509Cert_t v1c;

            memset(&p, 0, sizeof(p));
            p.pathLenConstraint = -1;
            p.version = 0u; /* v1 */
            p.serial = serialV1;
            p.serialLen = sizeof(serialV1);
            p.sigAlgOidRaw = _utSigAlgOid;
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            p.issuer.cn = "v1issuer";
            p.subject.cn = "v1subject";
            p.notBefore = 1700000000ull;
            p.notAfter = 2000000000ull;
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            p.ecCurveOidRaw = _utCurveOid;
            p.ecCurveOidRawLen = sizeof(_utCurveOid);
            p.pubKey = fakePubKeyV1;
            p.pubKeyLen = sizeof(fakePubKeyV1);
            p.addBasicConstraints = false;
            p.addKeyUsage = false;

            (void)SSFX509EncodeCert(buf, sizeof(buf), &p, fakeSigV1, sizeof(fakeSigV1), &len);
            SSF_ASSERT(len > 0u);
            SSF_ASSERT(SSFX509Parse(buf, len, &v1c) == true);
            SSF_ASSERT(v1c.version == 0u);
            SSF_ASSERT(v1c.extsLen == 0u);
        }

        /* 6b. Generate cert with all DN fields */
        {
            static const uint8_t fakePubKeyDN[65] = {
                0x04u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
                0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
                0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu,
                0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
                0x28u, 0x29u, 0x2Au, 0x2Bu, 0x2Cu, 0x2Du, 0x2Eu, 0x2Fu,
                0x30u, 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u, 0x37u,
                0x38u, 0x39u, 0x3Au, 0x3Bu, 0x3Cu, 0x3Du, 0x3Eu, 0x3Fu,
                0x40u
            };
            static const uint8_t serialDN[] = { 0x0Au };
            static const uint8_t fakeSigDN[64] = { 0xCCu };
            static SSFX509GenParams_t p;
            static uint8_t buf[1024];
            uint32_t len;
            static SSFX509Cert_t dnc;

            memset(&p, 0, sizeof(p));
            p.pathLenConstraint = -1;
            p.version = 2u;
            p.serial = serialDN;
            p.serialLen = sizeof(serialDN);
            p.sigAlgOidRaw = _utSigAlgOid;
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            p.issuer.cn = "IssuerCN";
            p.issuer.c = "US";
            p.issuer.st = "CA";
            p.issuer.l = "City";
            p.issuer.o = "Org";
            p.issuer.ou = "Unit";
            p.subject.cn = "SubjectCN";
            p.subject.c = "GB";
            p.subject.st = "London";
            p.subject.l = "Town";
            p.subject.o = "Corp";
            p.subject.ou = "Dept";
            p.notBefore = 1700000000ull;
            p.notAfter = 2000000000ull;
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            p.ecCurveOidRaw = _utCurveOid;
            p.ecCurveOidRawLen = sizeof(_utCurveOid);
            p.pubKey = fakePubKeyDN;
            p.pubKeyLen = sizeof(fakePubKeyDN);
            p.addBasicConstraints = false;
            p.addKeyUsage = false;

            (void)SSFX509EncodeCert(buf, sizeof(buf), &p, fakeSigDN, sizeof(fakeSigDN), &len);
            SSF_ASSERT(len > 0u);
            SSF_ASSERT(SSFX509Parse(buf, len, &dnc) == true);

            /* Verify all subject DN fields */
            SSF_ASSERT((dnc.subject.cn != NULL) && (dnc.subject.cnLen == 9u));
            SSF_ASSERT(memcmp(dnc.subject.cn, "SubjectCN", 9) == 0);
            SSF_ASSERT((dnc.subject.c != NULL) && (dnc.subject.cLen == 2u));
            SSF_ASSERT(memcmp(dnc.subject.c, "GB", 2) == 0);
            SSF_ASSERT((dnc.subject.st != NULL) && (dnc.subject.stLen == 6u));
            SSF_ASSERT(memcmp(dnc.subject.st, "London", 6) == 0);
            SSF_ASSERT((dnc.subject.l != NULL) && (dnc.subject.lLen == 4u));
            SSF_ASSERT(memcmp(dnc.subject.l, "Town", 4) == 0);
            SSF_ASSERT((dnc.subject.o != NULL) && (dnc.subject.oLen == 4u));
            SSF_ASSERT(memcmp(dnc.subject.o, "Corp", 4) == 0);
            SSF_ASSERT((dnc.subject.ou != NULL) && (dnc.subject.ouLen == 4u));
            SSF_ASSERT(memcmp(dnc.subject.ou, "Dept", 4) == 0);

            /* Verify all issuer DN fields */
            SSF_ASSERT((dnc.issuer.cn != NULL) && (dnc.issuer.cnLen == 8u));
            SSF_ASSERT(memcmp(dnc.issuer.cn, "IssuerCN", 8) == 0);
            SSF_ASSERT((dnc.issuer.c != NULL) && (dnc.issuer.cLen == 2u));
            SSF_ASSERT(memcmp(dnc.issuer.c, "US", 2) == 0);
            SSF_ASSERT((dnc.issuer.st != NULL) && (dnc.issuer.stLen == 2u));
            SSF_ASSERT(memcmp(dnc.issuer.st, "CA", 2) == 0);
            SSF_ASSERT((dnc.issuer.l != NULL) && (dnc.issuer.lLen == 4u));
            SSF_ASSERT(memcmp(dnc.issuer.l, "City", 4) == 0);
            SSF_ASSERT((dnc.issuer.o != NULL) && (dnc.issuer.oLen == 3u));
            SSF_ASSERT(memcmp(dnc.issuer.o, "Org", 3) == 0);
            SSF_ASSERT((dnc.issuer.ou != NULL) && (dnc.issuer.ouLen == 4u));
            SSF_ASSERT(memcmp(dnc.issuer.ou, "Unit", 4) == 0);
        }

        /* 6c. Generate CA cert with keyCertSign and crlSign */
        {
            static uint8_t caDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t caDerLen;
            static uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t pubKeyLen;
            static SSFX509Cert_t caCert;

            memset(privKey, 0, sizeof(privKey));
            SSF_ASSERT(_GenTestCert("ca.gen.test", 1700000000ull, 2000000000ull,
                       true, true, true,
                       SSF_X509_KU_KEY_CERT_SIGN | SSF_X509_KU_CRL_SIGN,
                       caDer, sizeof(caDer), &caDerLen,
                       privKey, pubKey, &pubKeyLen) == true);

            SSF_ASSERT(SSFX509Parse(caDer, caDerLen, &caCert) == true);
            SSF_ASSERT(caCert.hasBasicConstraints == true);
            SSF_ASSERT(caCert.isCA == true);
            SSF_ASSERT(caCert.hasKeyUsage == true);
            SSF_ASSERT((caCert.keyUsageBits & SSF_X509_KU_KEY_CERT_SIGN) != 0u);
            SSF_ASSERT((caCert.keyUsageBits & SSF_X509_KU_CRL_SIGN) != 0u);
        }

        /* 6d. Buffer too small for EncodeTBS */
        {
            static const uint8_t fakePubKeySmall[65] = { 0x04u };
            static const uint8_t serialSmall[] = { 0x01u };
            static SSFX509GenParams_t p;

            memset(&p, 0, sizeof(p));
            p.pathLenConstraint = -1;
            p.version = 2u;
            p.serial = serialSmall;
            p.serialLen = sizeof(serialSmall);
            p.sigAlgOidRaw = _utSigAlgOid;
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            p.issuer.cn = "test";
            p.subject.cn = "test";
            p.notBefore = 1700000000ull;
            p.notAfter = 2000000000ull;
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            p.ecCurveOidRaw = _utCurveOid;
            p.ecCurveOidRawLen = sizeof(_utCurveOid);
            p.pubKey = fakePubKeySmall;
            p.pubKeyLen = sizeof(fakePubKeySmall);
            p.addBasicConstraints = false;
            p.addKeyUsage = false;

            {
                uint8_t tinyBuf[4];
                SSF_ASSERT(SSFX509EncodeTBS(tinyBuf, sizeof(tinyBuf), &p, &_utScratchLen) == false);
            }
        }

        /* 6e. Buffer too small for EncodeCert */
        {
            static const uint8_t fakePubKeySmall2[65] = { 0x04u };
            static const uint8_t serialSmall2[] = { 0x01u };
            static const uint8_t fakeSigSmall[64] = { 0xDDu };
            static SSFX509GenParams_t p;

            memset(&p, 0, sizeof(p));
            p.pathLenConstraint = -1;
            p.version = 2u;
            p.serial = serialSmall2;
            p.serialLen = sizeof(serialSmall2);
            p.sigAlgOidRaw = _utSigAlgOid;
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            p.issuer.cn = "test";
            p.subject.cn = "test";
            p.notBefore = 1700000000ull;
            p.notAfter = 2000000000ull;
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            p.ecCurveOidRaw = _utCurveOid;
            p.ecCurveOidRawLen = sizeof(_utCurveOid);
            p.pubKey = fakePubKeySmall2;
            p.pubKeyLen = sizeof(fakePubKeySmall2);
            p.addBasicConstraints = false;
            p.addKeyUsage = false;

            {
                uint8_t tinyBuf[4];
                SSF_ASSERT(SSFX509EncodeCert(tinyBuf, sizeof(tinyBuf), &p,
                           fakeSigSmall, sizeof(fakeSigSmall), &_utScratchLen) == false);
            }
        }

        /* 6f. Two-pass: measure then encode */
        {
            static const uint8_t fakePubKey2P[65] = { 0x04u, 0xFFu };
            static const uint8_t serial2P[] = { 0x07u };
            static const uint8_t fakeSig2P[64] = { 0xEEu };
            static SSFX509GenParams_t p;
            uint32_t needed;
            static uint8_t buf[1024];
            uint32_t len;

            memset(&p, 0, sizeof(p));
            p.pathLenConstraint = -1;
            p.version = 2u;
            p.serial = serial2P;
            p.serialLen = sizeof(serial2P);
            p.sigAlgOidRaw = _utSigAlgOid;
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            p.issuer.cn = "twopass";
            p.subject.cn = "twopass";
            p.notBefore = 1700000000ull;
            p.notAfter = 2000000000ull;
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            p.ecCurveOidRaw = _utCurveOid;
            p.ecCurveOidRawLen = sizeof(_utCurveOid);
            p.pubKey = fakePubKey2P;
            p.pubKeyLen = sizeof(fakePubKey2P);
            p.addBasicConstraints = true;
            p.isCA = true;
            p.addKeyUsage = true;
            p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;

            /* Measure with NULL buf */
            (void)SSFX509EncodeTBS(NULL, 0, &p, &needed);
            SSF_ASSERT(needed > 0u);

            /* Encode and verify length matches */
            {
                static uint8_t tbsBuf[512];
                uint32_t tbsLen;
                (void)SSFX509EncodeTBS(tbsBuf, sizeof(tbsBuf), &p, &tbsLen);
                SSF_ASSERT(tbsLen == needed);
            }

            /* Same for EncodeCert */
            (void)SSFX509EncodeCert(NULL, 0, &p, fakeSig2P, sizeof(fakeSig2P), &needed);
            SSF_ASSERT(needed > 0u);
            (void)SSFX509EncodeCert(buf, sizeof(buf), &p, fakeSig2P, sizeof(fakeSig2P), &len);
            SSF_ASSERT(len == needed);
        }
    }

    /* ---- 7. Parse Error Handling ---- */
    {
        static SSFX509Cert_t pc;

        /* 7a. Zero-length DER */
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, 0, &pc) == false);

        /* 7b. Truncated DER (first few bytes only) */
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, 3, &pc) == false);
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, 10, &pc) == false);
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, 50, &pc) == false);

        /* 7c. Garbage bytes */
        {
            uint8_t garbage[32] = { 0xFFu, 0xFEu, 0xFDu, 0xFCu, 0x00u, 0x01u, 0x02u, 0x03u,
                                    0xABu, 0xCDu, 0xEFu, 0x12u, 0x34u, 0x56u, 0x78u, 0x9Au,
                                    0xBCu, 0xDEu, 0xF0u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u,
                                    0x66u, 0x77u, 0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu };
            SSF_ASSERT(SSFX509Parse(garbage, sizeof(garbage), &pc) == false);
        }

        /* 7d. Single byte */
        {
            uint8_t single = 0x30u;
            SSF_ASSERT(SSFX509Parse(&single, 1, &pc) == false);
        }
    }

    /* ---- 8. Hostname Matching (via VerifyChain) ---- */
    {
        /* Self-signed _utTestCertDER (SANs test.ssf.local, localhost) as chain and trust */
        const uint8_t *chain[1];
        uint32_t chainLens[1];
        const uint8_t *trust[1];
        uint32_t trustLens[1];
        uint64_t validTime = 1780000000ull; /* safely within _utTestCertDER validity */

        chain[0] = _utTestCertDER; chainLens[0] = sizeof(_utTestCertDER);
        trust[0] = _utTestCertDER; trustLens[0] = sizeof(_utTestCertDER);

        /* 8a. Exact match: "test.ssf.local" */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                   trust, trustLens, 1, "test.ssf.local", validTime, &_utVErr) == true);
        _UT_VERR(OK, 0u);

        /* 8b. Exact match: "localhost" */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                   trust, trustLens, 1, "localhost", validTime, &_utVErr) == true);
        _UT_VERR(OK, 0u);

        /* 8c. Hostname mismatch: "other.local" */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                   trust, trustLens, 1, "other.local", validTime, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);

        /* COV-10: a hostname longer than any DNS name (> 253) cannot match, even by prefix */
        {
            static char longHost[300];

            memset(longHost, 'a', sizeof(longHost) - 1u);
            memcpy(longHost, "test.ssf.local", 14u);
            longHost[sizeof(longHost) - 1u] = '\0';
            SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                       trust, trustLens, 1, longHost, validTime, &_utVErr) == false);
            _UT_VERR(ERR_HOSTNAME, 0u);
        }

        /* 8d. Case-insensitive: "TEST.SSF.LOCAL" */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                   trust, trustLens, 1, "TEST.SSF.LOCAL", validTime, &_utVErr) == true);
        _UT_VERR(OK, 0u);

        /* 8e. Case-insensitive: "LOCALHOST" */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                   trust, trustLens, 1, "LOCALHOST", validTime, &_utVErr) == true);
        _UT_VERR(OK, 0u);

        /* 8f. Partial match should fail: "test.ssf" */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                   trust, trustLens, 1, "test.ssf", validTime, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);

        /* 8g. Substring should fail: "ssf.local" */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                   trust, trustLens, 1, "ssf.local", validTime, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);

        /* 8h. Extra dot should fail: "test.ssf.local." */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1,
                   trust, trustLens, 1, "test.ssf.local.", validTime, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);
    }

    /* ---- 8E. Extended Key Usage (EKU) Validation (RFC 5280 Section 4.2.1.12) ---- */

    /* ---- EKU parsing: cert without EKU -> hasExtKeyUsage is false ---- */
    {
        static SSFX509Cert_t certNoEku;
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &certNoEku) == true);
        SSF_ASSERT(certNoEku.hasExtKeyUsage == false);
        SSF_ASSERT(certNoEku.ekuServerAuth == false);
        SSF_ASSERT(certNoEku.ekuClientAuth == false);
    }

    /* ---- EKU: generate cert with clientAuth only -> VerifyChain rejects ---- */
    {
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t caPubLen;
        static uint8_t caCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t caCertLen;

        static uint8_t leafCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t leafCertLen;

        const uint8_t *chain[1];
        uint32_t chainLens[1];
        const uint8_t *trust[1];
        uint32_t trustLens[1];

        /* Generate self-signed CA (no EKU) */
        memset(caPriv, 0, sizeof(caPriv));
        SSF_ASSERT(_GenTestCert("eku-ca", 1700000000ull, 2000000000ull,
                   true, true, false, 0,
                   caCert, sizeof(caCert), &caCertLen,
                   caPriv, caPub, &caPubLen) == true);

        /* Generate leaf cert WITH EKU = clientAuth only (no serverAuth) */
        {
            static SSFX509GenParams_t lp;
            uint8_t serial[] = { 0x05u };
            static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t leafPubLen;
            static uint8_t tbsDer[512];
            uint32_t tbsLen;
            uint8_t tbsHash[32];
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
            size_t sigLen;

            SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv),
                       leafPub, sizeof(leafPub), &leafPubLen) == true);

            memset(&lp, 0, sizeof(lp));
            lp.pathLenConstraint = -1;
            lp.version = 2u;
            lp.serial = serial;
            lp.serialLen = 1u;
            lp.sigAlgOidRaw = _utSigAlgOid;
            lp.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            lp.issuer.cn = "eku-ca";
            lp.subject.cn = "eku-leaf";
            lp.notBefore = 1700000000ull;
            lp.notAfter = 2000000000ull;
            lp.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            lp.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            lp.ecCurveOidRaw = _utCurveOid;
            lp.ecCurveOidRawLen = sizeof(_utCurveOid);
            lp.pubKey = leafPub;
            lp.pubKeyLen = (uint32_t)leafPubLen;
            lp.addExtKeyUsage = true;
            lp.ekuClientAuth = true;   /* Only clientAuth - no serverAuth */
            lp.ekuServerAuth = false;

            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &lp, &tbsLen);
            SSF_ASSERT(tbsLen > 0u);
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, caPriv, _UT_PRIV_LEN, tbsHash, 32, sig,
                                       sizeof(sig), &sigLen) == true);
            (void)SSFX509EncodeCert(leafCert, sizeof(leafCert), &lp,
                                             sig, (uint32_t)sigLen, &leafCertLen);
            SSF_ASSERT(leafCertLen > 0u);

            /* Verify EKU was parsed correctly */
            {
                static SSFX509Cert_t parsed;
                SSF_ASSERT(SSFX509Parse(leafCert, leafCertLen, &parsed) == true);
                SSF_ASSERT(parsed.hasExtKeyUsage == true);
                SSF_ASSERT(parsed.ekuClientAuth == true);
                SSF_ASSERT(parsed.ekuServerAuth == false);
            }
        }

        /* VerifyChain with clientAuth-only leaf -> must be rejected */
        chain[0] = leafCert;   chainLens[0] = leafCertLen;
        trust[0] = caCert;     trustLens[0] = caCertLen;

        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1u,
                   trust, trustLens, 1u,
                   "eku-leaf", 1800000000ull, &_utVErr) == false); _UT_VERR(ERR_EKU, 0u);
    }

    /* ---- EKU: a cert without EKU is not restricted (_utTestCertDER, covered in section 8) ---- */

    /* ---- 8A. Signature Algorithm Consistency (RFC 5280 Section 4.1.2.3) ---- */

    /* ---- Existing test cert: TBS and outer sigAlg OIDs match ---- */
    {
        static SSFX509Cert_t parsed;
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &parsed) == true);

        /* Both OIDs should be present */
        SSF_ASSERT(parsed.sigAlgOidRaw != NULL);
        SSF_ASSERT(parsed.sigAlgOidRawLen > 0u);
        SSF_ASSERT(parsed.outerSigAlgOidRaw != NULL);
        SSF_ASSERT(parsed.outerSigAlgOidRawLen > 0u);

        /* They should match */
        SSF_ASSERT(parsed.sigAlgOidRawLen == parsed.outerSigAlgOidRawLen);
        SSF_ASSERT(memcmp(parsed.sigAlgOidRaw, parsed.outerSigAlgOidRaw,
                   parsed.sigAlgOidRawLen) == 0);
    }

    /* ---- Generated cert: TBS and outer sigAlg OIDs match ---- */
    {
        static uint8_t priv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubLen;
        static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t certLen;
        static SSFX509Cert_t parsed;

        memset(priv, 0, sizeof(priv));
        SSF_ASSERT(_GenTestCert("sigalg-test", 1700000000ull, 2000000000ull,
                   false, false, false, 0,
                   certDer, sizeof(certDer), &certLen,
                   priv, pub, &pubLen) == true);

        SSF_ASSERT(SSFX509Parse(certDer, certLen, &parsed) == true);
        SSF_ASSERT(parsed.sigAlgOidRaw != NULL);
        SSF_ASSERT(parsed.outerSigAlgOidRaw != NULL);
        SSF_ASSERT(parsed.sigAlgOidRawLen == parsed.outerSigAlgOidRawLen);
        SSF_ASSERT(memcmp(parsed.sigAlgOidRaw, parsed.outerSigAlgOidRaw,
                   parsed.sigAlgOidRawLen) == 0);
    }

    /* ---- Self-signed test cert with consistent sigAlg passes (covered by section 8) ---- */

    /* ---- 8V. v1/v2 Certificate Rejection (RFC 5280 Section 6.1.1(c)) ---- */

    /* ---- v1 cert in chain -> rejected ---- */
    {
        /* Generate a self-signed v1 cert with a real key pair and signature */
        static uint8_t v1Priv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t v1Pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t v1PubLen;
        static uint8_t v1Cert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t v1CertLen;

        const uint8_t *chain[1];
        uint32_t chainLens[1];
        const uint8_t *trust[1];
        uint32_t trustLens[1];

        {
            static SSFX509GenParams_t p;
            uint8_t serial[] = { 0x09u };
            static uint8_t tbsDer[512];
            uint32_t tbsLen;
            uint8_t tbsHash[32];
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
            size_t sigLen;

            SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, v1Priv, sizeof(v1Priv),
                       v1Pub, sizeof(v1Pub), &v1PubLen) == true);

            memset(&p, 0, sizeof(p));
            p.pathLenConstraint = -1;
            p.version = 0u; /* v1 - no extensions */
            p.serial = serial;
            p.serialLen = 1u;
            p.sigAlgOidRaw = _utSigAlgOid;
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            p.issuer.cn = "v1-test";
            p.subject.cn = "v1-test";
            p.notBefore = 1700000000ull;
            p.notAfter = 2000000000ull;
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            p.ecCurveOidRaw = _utCurveOid;
            p.ecCurveOidRawLen = sizeof(_utCurveOid);
            p.pubKey = v1Pub;
            p.pubKeyLen = (uint32_t)v1PubLen;

            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen);
            SSF_ASSERT(tbsLen > 0u);
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, v1Priv, _UT_PRIV_LEN, tbsHash, 32, sig,
                                       sizeof(sig), &sigLen) == true);
            (void)SSFX509EncodeCert(v1Cert, sizeof(v1Cert), &p,
                                           sig, (uint32_t)sigLen, &v1CertLen);
            SSF_ASSERT(v1CertLen > 0u);

            /* Confirm it's v1 */
            {
                static SSFX509Cert_t parsed;
                SSF_ASSERT(SSFX509Parse(v1Cert, v1CertLen, &parsed) == true);
                SSF_ASSERT(parsed.version == 0u);
            }
        }

        /* VerifyChain must reject v1 cert per RFC 5280 */
        chain[0] = v1Cert;   chainLens[0] = v1CertLen;
        trust[0] = v1Cert;   trustLens[0] = v1CertLen;

        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1u,
                   trust, trustLens, 1u,
                   "v1-test", 1800000000ull, &_utVErr) == false); _UT_VERR(ERR_VERSION, 0u);
    }

    /* ---- v3 cert (existing test cert) still accepted, covered by section 8 ---- */

    /* ---- 8S. SKID/AKID Cross-Check (RFC 5280 Section 4.2.1.1) ---- */

    /* ---- Matching SKID/AKID -> consistent ---- */
    {
        static const uint8_t keyId[] = { 0x01u, 0x02u, 0x03u, 0x04u };
        static SSFX509Cert_t certStub;
        static SSFX509Cert_t issuerStub;

        memset(&certStub, 0, sizeof(certStub));
        memset(&issuerStub, 0, sizeof(issuerStub));
        certStub.akid = keyId;
        certStub.akidLen = sizeof(keyId);
        issuerStub.skid = keyId;
        issuerStub.skidLen = sizeof(keyId);

        SSF_ASSERT(SSFX509CheckSKIDAKID(&certStub, &issuerStub) == true);
    }

    /* ---- Mismatched SKID/AKID -> inconsistent ---- */
    {
        static const uint8_t akidVal[] = { 0x01u, 0x02u, 0x03u, 0x04u };
        static const uint8_t skidVal[] = { 0xAAu, 0xBBu, 0xCCu, 0xDDu };
        static SSFX509Cert_t certStub;
        static SSFX509Cert_t issuerStub;

        memset(&certStub, 0, sizeof(certStub));
        memset(&issuerStub, 0, sizeof(issuerStub));
        certStub.akid = akidVal;
        certStub.akidLen = sizeof(akidVal);
        issuerStub.skid = skidVal;
        issuerStub.skidLen = sizeof(skidVal);

        SSF_ASSERT(SSFX509CheckSKIDAKID(&certStub, &issuerStub) == false);
    }

    /* ---- Different lengths -> inconsistent ---- */
    {
        static const uint8_t akidVal[] = { 0x01u, 0x02u, 0x03u };
        static const uint8_t skidVal[] = { 0x01u, 0x02u, 0x03u, 0x04u };
        static SSFX509Cert_t certStub;
        static SSFX509Cert_t issuerStub;

        memset(&certStub, 0, sizeof(certStub));
        memset(&issuerStub, 0, sizeof(issuerStub));
        certStub.akid = akidVal;
        certStub.akidLen = sizeof(akidVal);
        issuerStub.skid = skidVal;
        issuerStub.skidLen = sizeof(skidVal);

        SSF_ASSERT(SSFX509CheckSKIDAKID(&certStub, &issuerStub) == false);
    }

    /* ---- Cert has no AKID -> consistent (AKID optional) ---- */
    {
        static const uint8_t skidVal[] = { 0x01u, 0x02u, 0x03u, 0x04u };
        static SSFX509Cert_t certStub;
        static SSFX509Cert_t issuerStub;

        memset(&certStub, 0, sizeof(certStub));
        memset(&issuerStub, 0, sizeof(issuerStub));
        /* certStub.akid is NULL (from memset) */
        issuerStub.skid = skidVal;
        issuerStub.skidLen = sizeof(skidVal);

        SSF_ASSERT(SSFX509CheckSKIDAKID(&certStub, &issuerStub) == true);
    }

    /* ---- Issuer has no SKID -> consistent (SKID optional) ---- */
    {
        static const uint8_t akidVal[] = { 0x01u, 0x02u, 0x03u, 0x04u };
        static SSFX509Cert_t certStub;
        static SSFX509Cert_t issuerStub;

        memset(&certStub, 0, sizeof(certStub));
        memset(&issuerStub, 0, sizeof(issuerStub));
        certStub.akid = akidVal;
        certStub.akidLen = sizeof(akidVal);
        /* issuerStub.skid is NULL (from memset) */

        SSF_ASSERT(SSFX509CheckSKIDAKID(&certStub, &issuerStub) == true);
    }

    /* ---- Neither has SKID/AKID -> consistent ---- */
    {
        static SSFX509Cert_t certStub;
        static SSFX509Cert_t issuerStub;

        memset(&certStub, 0, sizeof(certStub));
        memset(&issuerStub, 0, sizeof(issuerStub));

        SSF_ASSERT(SSFX509CheckSKIDAKID(&certStub, &issuerStub) == true);
    }

    /* ---- Existing test cert: self-signed AKID matches SKID ---- */
    {
        static SSFX509Cert_t parsed;
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &parsed) == true);
        SSF_ASSERT(parsed.akid != NULL);
        SSF_ASSERT(parsed.skid != NULL);
        /* Self-signed: AKID should match SKID */
        SSF_ASSERT(SSFX509CheckSKIDAKID(&parsed, &parsed) == true);
    }

    /* ---- 8I. IP Address SAN Matching (RFC 5280 Section 4.2.1.6) ---- */

    /* ---- IPv4 matching: exact match ---- */
    {
        static const uint8_t ip4[] = { 192u, 168u, 1u, 100u };
        SSF_ASSERT(SSFX509MatchIPAddress("192.168.1.100", ip4, 4u) == true);
    }

    /* ---- IPv4 matching: mismatch ---- */
    {
        static const uint8_t ip4[] = { 192u, 168u, 1u, 100u };
        SSF_ASSERT(SSFX509MatchIPAddress("192.168.1.101", ip4, 4u) == false);
    }

    /* ---- IPv4 matching: 0.0.0.0 ---- */
    {
        static const uint8_t ip4[] = { 0u, 0u, 0u, 0u };
        SSF_ASSERT(SSFX509MatchIPAddress("0.0.0.0", ip4, 4u) == true);
    }

    /* ---- IPv4 matching: 255.255.255.255 ---- */
    {
        static const uint8_t ip4[] = { 255u, 255u, 255u, 255u };
        SSF_ASSERT(SSFX509MatchIPAddress("255.255.255.255", ip4, 4u) == true);
    }

    /* ---- IPv4 matching: 10.0.0.1 ---- */
    {
        static const uint8_t ip4[] = { 10u, 0u, 0u, 1u };
        SSF_ASSERT(SSFX509MatchIPAddress("10.0.0.1", ip4, 4u) == true);
    }

    /* ---- IPv4 matching: hostname is not an IP -> no match ---- */
    {
        static const uint8_t ip4[] = { 10u, 0u, 0u, 1u };
        SSF_ASSERT(SSFX509MatchIPAddress("example.com", ip4, 4u) == false);
    }

    /* ---- IPv4 matching: invalid IP format -> no match ---- */
    {
        static const uint8_t ip4[] = { 10u, 0u, 0u, 1u };
        SSF_ASSERT(SSFX509MatchIPAddress("10.0.0.", ip4, 4u) == false);
        SSF_ASSERT(SSFX509MatchIPAddress("10.0.0.256", ip4, 4u) == false);
        SSF_ASSERT(SSFX509MatchIPAddress("10.0.0", ip4, 4u) == false);
        SSF_ASSERT(SSFX509MatchIPAddress("", ip4, 4u) == false);
    }

    /* ---- IPv4 matching: wrong SAN length (not 4) -> no match ---- */
    {
        static const uint8_t ip6[16] = { 0 };
        SSF_ASSERT(SSFX509MatchIPAddress("10.0.0.1", ip6, 16u) == false);
    }

    /* ---- IPv4 matching: trailing text after valid IP -> no match ---- */
    {
        static const uint8_t ip4[] = { 10u, 0u, 0u, 1u };
        SSF_ASSERT(SSFX509MatchIPAddress("10.0.0.1extra", ip4, 4u) == false);
        SSF_ASSERT(SSFX509MatchIPAddress("10.0.0.1.5", ip4, 4u) == false);
    }

    /* ---- An IP hostname must not match the DNS-only SANs of _utTestCertDER ---- */
    {
        const uint8_t *chain[1] = { _utTestCertDER };
        uint32_t chainLens[1] = { sizeof(_utTestCertDER) };
        const uint8_t *trust[1] = { _utTestCertDER };
        uint32_t trustLens[1] = { sizeof(_utTestCertDER) };

        /* IP hostname against DNS-only SANs fails host matching (time inside validity) */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1u,
                   trust, trustLens, 1u,
                   "192.168.1.1", 1780000000ull, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);
    }

    /* ---- 8K. Key Usage keyCertSign Validation (RFC 5280 Section 6.1.4(h)) ---- */

    /* ---- Intermediate CA with Key Usage but NO keyCertSign -> rejected ---- */
    {
        static uint8_t rootPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t rootPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t rootPubLen;
        static uint8_t rootCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t rootCertLen;

        static uint8_t intPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t intPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t intPubLen;
        static uint8_t intCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t intCertLen;

        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t leafPubLen;
        static uint8_t leafCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t leafCertLen;

        const uint8_t *chain[2];
        uint32_t chainLens[2];
        const uint8_t *trust[1];
        uint32_t trustLens[1];

        /* Generate root CA (with keyCertSign - proper CA) */
        memset(rootPriv, 0, sizeof(rootPriv));
        SSF_ASSERT(_GenTestCert("ku-root", 1700000000ull, 2000000000ull,
                   true, true, true,
                   SSF_X509_KU_KEY_CERT_SIGN | SSF_X509_KU_CRL_SIGN,
                   rootCert, sizeof(rootCert), &rootCertLen,
                   rootPriv, rootPub, &rootPubLen) == true);

        /* Generate intermediate CA with KU=digitalSignature ONLY (NO keyCertSign) */
        {
            static SSFX509GenParams_t ip;
            uint8_t serial[] = { 0x08u };
            static uint8_t tbsDer[512];
            uint32_t tbsLen;
            uint8_t tbsHash[32];
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
            size_t sigLen;

            SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, intPriv, sizeof(intPriv),
                       intPub, sizeof(intPub), &intPubLen) == true);

            memset(&ip, 0, sizeof(ip));
            ip.pathLenConstraint = -1;
            ip.version = 2u;
            ip.serial = serial;
            ip.serialLen = 1u;
            ip.sigAlgOidRaw = _utSigAlgOid;
            ip.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            ip.issuer.cn = "ku-root";
            ip.subject.cn = "ku-int-bad";
            ip.notBefore = 1700000000ull;
            ip.notAfter = 2000000000ull;
            ip.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            ip.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            ip.ecCurveOidRaw = _utCurveOid;
            ip.ecCurveOidRawLen = sizeof(_utCurveOid);
            ip.pubKey = intPub;
            ip.pubKeyLen = (uint32_t)intPubLen;
            ip.addBasicConstraints = true;
            ip.isCA = true;
            ip.addKeyUsage = true;
            ip.keyUsageBits = SSF_X509_KU_DIGITAL_SIGNATURE; /* NO keyCertSign */

            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &ip, &tbsLen);
            SSF_ASSERT(tbsLen > 0u);
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, rootPriv, _UT_PRIV_LEN, tbsHash, 32, sig,
                                       sizeof(sig), &sigLen) == true);
            (void)SSFX509EncodeCert(intCert, sizeof(intCert), &ip,
                                            sig, (uint32_t)sigLen, &intCertLen);
            SSF_ASSERT(intCertLen > 0u);

            /* Verify intermediate has KU but no keyCertSign */
            {
                static SSFX509Cert_t parsed;
                SSF_ASSERT(SSFX509Parse(intCert, intCertLen, &parsed) == true);
                SSF_ASSERT(parsed.hasKeyUsage == true);
                SSF_ASSERT((parsed.keyUsageBits & SSF_X509_KU_KEY_CERT_SIGN) == 0);
            }
        }

        /* Generate leaf cert signed by intermediate */
        SSF_ASSERT(_GenSignedLeafCert("ku-leaf", "ku-int-bad",
                   1700000000ull, 2000000000ull,
                   leafCert, sizeof(leafCert), &leafCertLen,
                   intPriv, leafPub, &leafPubLen) == true);

        /* Chain: [leaf, intermediate], trust: [root] */
        chain[0] = leafCert;   chainLens[0] = leafCertLen;
        chain[1] = intCert;    chainLens[1] = intCertLen;
        trust[0] = rootCert;   trustLens[0] = rootCertLen;

        /* RFC 5280 6.1.4(h): intermediate whose Key Usage lacks keyCertSign is rejected */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 2u,
                   trust, trustLens, 1u,
                   "ku-leaf", 1800000000ull, &_utVErr) == false); _UT_VERR(ERR_CA_KEY_USAGE, 1u);
    }

    /* ---- 8X. Unknown Critical Extension Rejection (RFC 5280 Section 4.2) ---- */

    /* ---- Self-signed cert with unknown critical extension -> rejected ---- */
    {
        /* Fake OID: 2.5.29.127 - not a recognized extension */
        static const uint8_t unknownOid[] = { 0x55u, 0x1Du, 0x7Fu };
        static const uint8_t fakeValue[] = { 0x01u };

        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t caPubLen;
        static uint8_t caCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t caCertLen;

        const uint8_t *chain[1];
        uint32_t chainLens[1];
        const uint8_t *trust[1];
        uint32_t trustLens[1];

        /* Generate self-signed cert with unknown CRITICAL extension */
        {
            static SSFX509GenParams_t p;
            uint8_t serial[] = { 0x07u };
            static uint8_t tbsDer[512];
            uint32_t tbsLen;
            uint8_t tbsHash[32];
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
            size_t sigLen;

            memset(caPriv, 0, sizeof(caPriv));
            SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPriv, sizeof(caPriv),
                       caPub, sizeof(caPub), &caPubLen) == true);

            memset(&p, 0, sizeof(p));
            p.pathLenConstraint = -1;
            p.version = 2u;
            p.serial = serial;
            p.serialLen = 1u;
            p.sigAlgOidRaw = _utSigAlgOid;
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            p.issuer.cn = "crit-ext-test";
            p.subject.cn = "crit-ext-test";
            p.notBefore = 1700000000ull;
            p.notAfter = 2000000000ull;
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            p.ecCurveOidRaw = _utCurveOid;
            p.ecCurveOidRawLen = sizeof(_utCurveOid);
            p.pubKey = caPub;
            p.pubKeyLen = (uint32_t)caPubLen;
            p.addRawExt = true;
            p.rawExtOid = unknownOid;
            p.rawExtOidLen = sizeof(unknownOid);
            p.rawExtValue = fakeValue;
            p.rawExtValueLen = sizeof(fakeValue);
            p.rawExtCritical = true;  /* CRITICAL unknown extension */

            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen);
            SSF_ASSERT(tbsLen > 0u);
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, caPriv, _UT_PRIV_LEN, tbsHash, 32, sig,
                                       sizeof(sig), &sigLen) == true);
            (void)SSFX509EncodeCert(caCert, sizeof(caCert), &p,
                                           sig, (uint32_t)sigLen, &caCertLen);
            SSF_ASSERT(caCertLen > 0u);

            /* Verify the extension was parsed as critical */
            {
                static SSFX509Cert_t parsed;
                bool foundCritical = false;
                uint8_t e;
                SSF_ASSERT(SSFX509Parse(caCert, caCertLen, &parsed) == true);
                for (e = 0; e < parsed.extsLen; e++)
                {
                    /* Is this the critical unknown extension? */
                    if ((parsed.exts[e].critical) &&
                        (parsed.exts[e].oidRawLen == sizeof(unknownOid)) &&
                        (memcmp(parsed.exts[e].oidRaw, unknownOid, sizeof(unknownOid)) == 0))
                    {
                        /* Yes */
                        foundCritical = true;
                    }
                }
                SSF_ASSERT(foundCritical == true);
            }
        }

        /* VerifyChain must reject cert with unknown critical extension */
        chain[0] = caCert;   chainLens[0] = caCertLen;
        trust[0] = caCert;   trustLens[0] = caCertLen;

        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 1u,
                   trust, trustLens, 1u,
                   "crit-ext-test", 1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_CRITICAL_EXT, 0u);
    }

    /* ---- Recognized extensions only (_utTestCertDER) still pass, covered by section 8 ---- */

    /* ---- 8W. Wildcard Hostname Matching is covered by the wildcard SAN tests below ---- */

    /* ---- 8P. Path Length Constraint Enforcement (RFC 5280 Section 6.1.4(k)) ---- */

    /* ---- pathLenConstraint=0 with subordinate CA -> chain MUST be rejected ---- */
    {
        /* Leaf <- intermediate CA <- root (pathLen 0): the intermediate violates the root */

        static uint8_t rootPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t rootPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t rootPubLen;
        static uint8_t rootCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t rootCertLen;

        static uint8_t intPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t intPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t intPubLen;
        static uint8_t intCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t intCertLen;

        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t leafPubLen;
        static uint8_t leafCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t leafCertLen;

        const uint8_t *chain[2];
        uint32_t chainLens[2];
        const uint8_t *trust[1];
        uint32_t trustLens[1];

        /* Generate root CA with pathLenConstraint=0 */
        memset(rootPriv, 0, sizeof(rootPriv));
        {
            static SSFX509GenParams_t rp;
            uint8_t serial[] = { 0x01u };
            static uint8_t tbsDer[512];
            uint32_t tbsLen;
            uint8_t tbsHash[32];
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
            size_t sigLen;

            SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, rootPriv, sizeof(rootPriv),
                       rootPub, sizeof(rootPub), &rootPubLen) == true);

            memset(&rp, 0, sizeof(rp));
            rp.pathLenConstraint = 0; /* NO subordinate CAs */
            rp.version = 2u;
            rp.serial = serial;
            rp.serialLen = 1u;
            rp.sigAlgOidRaw = _utSigAlgOid;
            rp.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            rp.issuer.cn = "root-plc0";
            rp.subject.cn = "root-plc0";
            rp.notBefore = 1700000000ull;
            rp.notAfter = 2000000000ull;
            rp.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            rp.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            rp.ecCurveOidRaw = _utCurveOid;
            rp.ecCurveOidRawLen = sizeof(_utCurveOid);
            rp.pubKey = rootPub;
            rp.pubKeyLen = (uint32_t)rootPubLen;
            rp.addBasicConstraints = true;
            rp.isCA = true;

            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &rp, &tbsLen);
            SSF_ASSERT(tbsLen > 0u);
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, rootPriv, _UT_PRIV_LEN, tbsHash, 32, sig,
                                       sizeof(sig), &sigLen) == true);
            (void)SSFX509EncodeCert(rootCert, sizeof(rootCert), &rp,
                                             sig, (uint32_t)sigLen, &rootCertLen);
            SSF_ASSERT(rootCertLen > 0u);
        }

        /* Generate intermediate CA signed by root */
        {
            static SSFX509GenParams_t ip;
            uint8_t serial[] = { 0x02u };
            static uint8_t tbsDer[512];
            uint32_t tbsLen;
            uint8_t tbsHash[32];
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
            size_t sigLen;

            SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, intPriv, sizeof(intPriv),
                       intPub, sizeof(intPub), &intPubLen) == true);

            memset(&ip, 0, sizeof(ip));
            ip.pathLenConstraint = -1;
            ip.version = 2u;
            ip.serial = serial;
            ip.serialLen = 1u;
            ip.sigAlgOidRaw = _utSigAlgOid;
            ip.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            ip.issuer.cn = "root-plc0";
            ip.subject.cn = "int-ca";
            ip.notBefore = 1700000000ull;
            ip.notAfter = 2000000000ull;
            ip.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            ip.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            ip.ecCurveOidRaw = _utCurveOid;
            ip.ecCurveOidRawLen = sizeof(_utCurveOid);
            ip.pubKey = intPub;
            ip.pubKeyLen = (uint32_t)intPubLen;
            ip.addBasicConstraints = true;
            ip.isCA = true;

            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &ip, &tbsLen);
            SSF_ASSERT(tbsLen > 0u);
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, rootPriv, _UT_PRIV_LEN, tbsHash, 32, sig,
                                       sizeof(sig), &sigLen) == true);
            (void)SSFX509EncodeCert(intCert, sizeof(intCert), &ip,
                                            sig, (uint32_t)sigLen, &intCertLen);
            SSF_ASSERT(intCertLen > 0u);
        }

        /* Generate leaf cert signed by intermediate */
        SSF_ASSERT(_GenSignedLeafCert("leaf-plc", "int-ca", 1700000000ull, 2000000000ull,
                   leafCert, sizeof(leafCert), &leafCertLen,
                   intPriv, leafPub, &leafPubLen) == true);

        /* Assemble chain: [leaf, intermediate], trust: [root] */
        chain[0] = leafCert;   chainLens[0] = leafCertLen;
        chain[1] = intCert;    chainLens[1] = intCertLen;
        trust[0] = rootCert;   trustLens[0] = rootCertLen;

        /* Root pathLenConstraint 0 forbids the subordinate intermediate CA: rejected */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLens, 2u,
                   trust, trustLens, 1u,
                   "leaf-plc", 1800000000ull, &_utVErr) == false); _UT_VERR(ERR_PATH_LEN, 2u);
    }

    /* ---- pathLenConstraint=1 with one subordinate CA -> chain accepted ---- */
    {
        static uint8_t rootPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t rootPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t rootPubLen;
        static uint8_t rootCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t rootCertLen;

        static uint8_t intPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t intPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t intPubLen;
        static uint8_t intCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t intCertLen;

        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t leafPubLen;
        static uint8_t leafCert[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t leafCertLen;

        const uint8_t *chain[2];
        uint32_t chainLens[2];
        const uint8_t *trust[1];
        uint32_t trustLens[1];

        /* Generate root CA with pathLenConstraint=1 (one subordinate CA allowed) */
        {
            static SSFX509GenParams_t rp;
            uint8_t serial[] = { 0x01u };
            static uint8_t tbsDer[512];
            uint32_t tbsLen;
            uint8_t tbsHash[32];
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
            size_t sigLen;

            SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, rootPriv, sizeof(rootPriv),
                       rootPub, sizeof(rootPub), &rootPubLen) == true);

            memset(&rp, 0, sizeof(rp));
            rp.pathLenConstraint = 1; /* One subordinate CA allowed */
            rp.version = 2u;
            rp.serial = serial;
            rp.serialLen = 1u;
            rp.sigAlgOidRaw = _utSigAlgOid;
            rp.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            rp.issuer.cn = "root-plc1";
            rp.subject.cn = "root-plc1";
            rp.notBefore = 1700000000ull;
            rp.notAfter = 2000000000ull;
            rp.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            rp.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            rp.ecCurveOidRaw = _utCurveOid;
            rp.ecCurveOidRawLen = sizeof(_utCurveOid);
            rp.pubKey = rootPub;
            rp.pubKeyLen = (uint32_t)rootPubLen;
            rp.addBasicConstraints = true;
            rp.isCA = true;

            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &rp, &tbsLen);
            SSF_ASSERT(tbsLen > 0u);
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, rootPriv, _UT_PRIV_LEN, tbsHash, 32, sig,
                                       sizeof(sig), &sigLen) == true);
            (void)SSFX509EncodeCert(rootCert, sizeof(rootCert), &rp,
                                             sig, (uint32_t)sigLen, &rootCertLen);
            SSF_ASSERT(rootCertLen > 0u);
        }

        /* Generate intermediate CA signed by root */
        {
            static SSFX509GenParams_t ip;
            uint8_t serial[] = { 0x02u };
            static uint8_t tbsDer[512];
            uint32_t tbsLen;
            uint8_t tbsHash[32];
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
            size_t sigLen;

            SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, intPriv, sizeof(intPriv),
                       intPub, sizeof(intPub), &intPubLen) == true);

            memset(&ip, 0, sizeof(ip));
            ip.pathLenConstraint = -1;
            ip.version = 2u;
            ip.serial = serial;
            ip.serialLen = 1u;
            ip.sigAlgOidRaw = _utSigAlgOid;
            ip.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            ip.issuer.cn = "root-plc1";
            ip.subject.cn = "int-ca-plc1";
            ip.notBefore = 1700000000ull;
            ip.notAfter = 2000000000ull;
            ip.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            ip.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            ip.ecCurveOidRaw = _utCurveOid;
            ip.ecCurveOidRawLen = sizeof(_utCurveOid);
            ip.pubKey = intPub;
            ip.pubKeyLen = (uint32_t)intPubLen;
            ip.addBasicConstraints = true;
            ip.isCA = true;

            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &ip, &tbsLen);
            SSF_ASSERT(tbsLen > 0u);
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, rootPriv, _UT_PRIV_LEN, tbsHash, 32, sig,
                                       sizeof(sig), &sigLen) == true);
            (void)SSFX509EncodeCert(intCert, sizeof(intCert), &ip,
                                            sig, (uint32_t)sigLen, &intCertLen);
            SSF_ASSERT(intCertLen > 0u);
        }

        /* Generate leaf cert signed by intermediate */
        SSF_ASSERT(_GenSignedLeafCert("leaf-plc1", "int-ca-plc1", 1700000000ull, 2000000000ull,
                   leafCert, sizeof(leafCert), &leafCertLen,
                   intPriv, leafPub, &leafPubLen) == true);

        chain[0] = leafCert;   chainLens[0] = leafCertLen;
        chain[1] = intCert;    chainLens[1] = intCertLen;
        trust[0] = rootCert;   trustLens[0] = rootCertLen;

        /* pathLenConstraint=1 allows 1 subordinate CA; code signing needs no SAN hostname */
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLens, 2u, trust, trustLens, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL,
                                             1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);
    }

#if _UT_RSA_PSS_SIGN == 1
    /* ---- 9. RSA-PSS hash comes from the PSS parameters (cert structs built directly) ---- */
    {
        /* RSA-PSS OID: 1.2.840.113549.1.1.10 */
        static const uint8_t rsaPssOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Au
        };

        static const uint8_t rsaKeyOidStub[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
        };
        /* RSASSA-PSS-params { [0] sha256, [1] mgf1-sha256, [2] 32 }: SSF signs with salt == hLen */
        static const uint8_t pssParamsSHA256Salt32[] = {
            0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u,
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            /* [1] maskGenAlgorithm MGF1-SHA-256 */
            0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
            0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
            0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            0xA2u, 0x03u, 0x02u, 0x01u, 0x20u
        };

        static uint8_t rsaPriv[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t rsaPub[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t rsaPrivLen;
        size_t rsaPubLen;

        /* Arbitrary TBS content - just needs to be consistent between hash and sig */
        static const uint8_t fakeTbs[] = "This is fake TBS content for RSA-PSS testing.";
        uint8_t hash256[SSF_SHA2_256_BYTE_SIZE];
        uint8_t hash384[SSF_SHA2_384_BYTE_SIZE];
        static uint8_t sig256[SSF_RSA_MAX_SIG_SIZE];
        static uint8_t sig384[SSF_RSA_MAX_SIG_SIZE];
        size_t sig256Len;
        size_t sig384Len;
        static SSFX509Cert_t certStub;
        static SSFX509Cert_t issuerStub;

        /* Generate 2048-bit RSA key pair */
        SSF_ASSERT(SSFRSAKeyGen(2048, rsaPriv, sizeof(rsaPriv), &rsaPrivLen,
                   rsaPub, sizeof(rsaPub), &rsaPubLen) == true);

        /* Sign fakeTbs with RSA-PSS-SHA256 */
        SSFSHA256(fakeTbs, sizeof(fakeTbs), hash256, sizeof(hash256));
        SSF_ASSERT(SSFRSASignPSS(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA256,
                   hash256, SSF_SHA2_256_BYTE_SIZE,
                   sig256, sizeof(sig256), &sig256Len) == true);

        /* Sign fakeTbs with RSA-PSS-SHA384 */
        SSFSHA384(fakeTbs, sizeof(fakeTbs), hash384, sizeof(hash384));
        SSF_ASSERT(SSFRSASignPSS(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA384,
                   hash384, SSF_SHA2_384_BYTE_SIZE,
                   sig384, sizeof(sig384), &sig384Len) == true);

        /* Build issuer stub with RSA public key, labelled rsaEncryption (AUDIT X509-11) */
        memset(&issuerStub, 0, sizeof(issuerStub));
        issuerStub.pubKey = rsaPub;
        issuerStub.pubKeyLen = (uint32_t)rsaPubLen;
        issuerStub.pubKeyAlgOidRaw = rsaKeyOidStub;
        issuerStub.pubKeyAlgOidRawLen = sizeof(rsaKeyOidStub);

        /* ---- RSA-PSS-SHA256: verify succeeds (correct hash) ---- */
        memset(&certStub, 0, sizeof(certStub));
        certStub.sigAlgOidRaw = rsaPssOid;
        certStub.sigAlgOidRawLen = sizeof(rsaPssOid);
        certStub.tbsRaw = fakeTbs;
        certStub.tbsRawLen = sizeof(fakeTbs);
        certStub.signature = sig256;
        certStub.signatureLen = (uint32_t)sig256Len;
        certStub.sigAlgParams = pssParamsSHA256Salt32;
        certStub.sigAlgParamsLen = sizeof(pssParamsSHA256Salt32);

        SSF_ASSERT(SSFX509IsSigRSAPSSSHA256(&certStub) == true);
        SSF_ASSERT(SSFX509IsSigRSAPSSSHA384(&certStub) == false);
        SSF_ASSERT(SSFX509VerifyCertSignature(&certStub, &issuerStub) == true);

        /* ---- RSA-PSS-SHA384: verify succeeds when PSS parameters name SHA-384 ---- */
        {
            /* RSASSA-PSS-params: SEQUENCE { [0] EXPLICIT SEQUENCE { OID sha384, NULL } } */
            static const uint8_t pssParamsSHA384[] = {
                0x30u, 0x34u,                   /* SEQUENCE len=52 */
                0xA0u, 0x0Fu,                   /* [0] EXPLICIT len=15 */
                0x30u, 0x0Du,                   /* SEQUENCE len=13 (AlgorithmIdentifier) */
                0x06u, 0x09u,                   /* OID len=9 */
                0x60u, 0x86u, 0x48u, 0x01u,     /* id-sha384: 2.16.840.1.101.3.4.2.2 */
                0x65u, 0x03u, 0x04u, 0x02u, 0x02u,
                0x05u, 0x00u,                   /* NULL */
                /* [1] maskGenAlgorithm MGF1-SHA-384 */
                0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
                0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
                0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x02u, 0x05u, 0x00u,
                0xA2u, 0x03u, 0x02u, 0x01u, 0x30u /* [2] saltLength 48 */
            };

            certStub.signature = sig384;
            certStub.signatureLen = (uint32_t)sig384Len;
            certStub.sigAlgParams = pssParamsSHA384;
            certStub.sigAlgParamsLen = sizeof(pssParamsSHA384);

            /* The helpers check the hash named by the PSS parameters, not just the OID */
            SSF_ASSERT(SSFX509IsSigRSAPSSSHA256(&certStub) == false);
            SSF_ASSERT(SSFX509IsSigRSAPSSSHA384(&certStub) == true);
            SSF_ASSERT(SSFX509VerifyCertSignature(&certStub, &issuerStub) == true);
        }

        /* ---- RSA-PSS without params (RFC 4055 SHA-1 defaults) fails closed ---- */
        {
            certStub.signature = sig256;
            certStub.signatureLen = (uint32_t)sig256Len;
            certStub.sigAlgParams = NULL;
            certStub.sigAlgParamsLen = 0;
            SSF_ASSERT(SSFX509IsSigRSAPSSSHA256(&certStub) == false);
            SSF_ASSERT(SSFX509IsSigRSAPSSSHA384(&certStub) == false);
            SSF_ASSERT(SSFX509VerifyCertSignature(&certStub, &issuerStub) == false);
        }

        /* ---- RSA-PSS-SHA384 without parameters: fails (defaults to SHA-256) ---- */
        {
            certStub.signature = sig384;
            certStub.signatureLen = (uint32_t)sig384Len;
            certStub.sigAlgParams = NULL;
            certStub.sigAlgParamsLen = 0;
            SSF_ASSERT(SSFX509VerifyCertSignature(&certStub, &issuerStub) == false);
        }

        /* ---- COV-3d: RSA-PSS-SHA512 (params name SHA-512, salt 64) verifies, tamper fails ---- */
        {
            static const uint8_t pssParamsSHA512[] = {
                0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u,
                0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x03u, 0x05u, 0x00u,
                /* [1] maskGenAlgorithm MGF1-SHA-512 */
                0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
                0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
                0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x03u, 0x05u, 0x00u,
                0xA2u, 0x03u, 0x02u, 0x01u, 0x40u /* [2] saltLength 64 */
            };
            uint8_t hash512[SSF_SHA2_512_BYTE_SIZE];
            static uint8_t sig512[SSF_RSA_MAX_SIG_SIZE];
            size_t sig512Len;

            SSFSHA512(fakeTbs, sizeof(fakeTbs), hash512, sizeof(hash512));
            SSF_ASSERT(SSFRSASignPSS(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA512, hash512,
                                     SSF_SHA2_512_BYTE_SIZE, sig512, sizeof(sig512),
                                     &sig512Len) == true);
            SSF_ASSERT(SSFX509VerifySignature(&issuerStub, rsaPssOid, sizeof(rsaPssOid),
                                              pssParamsSHA512, sizeof(pssParamsSHA512), NULL, 0u,
                                              fakeTbs, sizeof(fakeTbs), sig512,
                                              (uint32_t)sig512Len) == true);
            sig512[sig512Len / 2u] ^= 0x01u;
            SSF_ASSERT(SSFX509VerifySignature(&issuerStub, rsaPssOid, sizeof(rsaPssOid),
                                              pssParamsSHA512, sizeof(pssParamsSHA512), NULL, 0u,
                                              fakeTbs, sizeof(fakeTbs), sig512,
                                              (uint32_t)sig512Len) == false);
            sig512[sig512Len / 2u] ^= 0x01u;

            /* ---- COV-3c: an RSA key below the size policy is refused before PSS verify ---- */
            {
                static const uint8_t pubTiny[] = {
                    0x30u, 0x07u, 0x02u, 0x02u, 0x00u, 0xC5u, 0x02u, 0x01u, 0x03u
                };
                static SSFX509Cert_t tinyStub;

                tinyStub = issuerStub;
                tinyStub.pubKey = pubTiny;
                tinyStub.pubKeyLen = sizeof(pubTiny);
                SSF_ASSERT(SSFX509VerifySignature(&tinyStub, rsaPssOid, sizeof(rsaPssOid),
                                                  pssParamsSHA512, sizeof(pssParamsSHA512), NULL,
                                                  0u, fakeTbs, sizeof(fakeTbs), sig512,
                                                  (uint32_t)sig512Len) == false);
            }
        }

        /* ---- COV-3a/b: EC key on an unknown curve; PKCS#1 v1.5 handed an EC key ---- */
        {
            static const uint8_t ecdsaSha256Oid[] = {
                0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u
            };
            static const uint8_t ecPubKeyOid[] = {
                0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u
            };
            static const uint8_t secp256k1Oid[] = { 0x2Bu, 0x81u, 0x04u, 0x00u, 0x0Au };
            static const uint8_t sha256RsaOid[] = {
                0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Bu
            };
            static uint8_t ecPoint[65];
            static uint8_t ecSig[72];
            static SSFX509Cert_t ecStub;

            memset(ecPoint, 0x11, sizeof(ecPoint));
            ecPoint[0] = 0x04u;
            memset(ecSig, 0x22, sizeof(ecSig));
            memset(&ecStub, 0, sizeof(ecStub));
            ecStub.pubKey = ecPoint;
            ecStub.pubKeyLen = sizeof(ecPoint);
            ecStub.pubKeyAlgOidRaw = ecPubKeyOid;
            ecStub.pubKeyAlgOidRawLen = sizeof(ecPubKeyOid);
            ecStub.ecCurveOidRaw = secp256k1Oid;
            ecStub.ecCurveOidRawLen = sizeof(secp256k1Oid);
            SSF_ASSERT(SSFX509VerifySignature(&ecStub, ecdsaSha256Oid, sizeof(ecdsaSha256Oid),
                                              NULL, 0u, NULL, 0u, fakeTbs, sizeof(fakeTbs), ecSig,
                                              sizeof(ecSig)) == false);
            SSF_ASSERT(SSFX509VerifySignature(&ecStub, sha256RsaOid, sizeof(sha256RsaOid),
                                              NULL, 0u, NULL, 0u, fakeTbs, sizeof(fakeTbs), sig256,
                                              (uint32_t)sig256Len) == false);
        }
    }

    /* ---- 10. RSA-PSS Full Encode/Parse/Verify Round-Trip ---- */

    /* ---- RSA-PSS-SHA256: full cert encode -> parse -> verify ---- */
    {
        /* RSA-PSS OID: 1.2.840.113549.1.1.10 */
        static const uint8_t rsaPssOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Au
        };
        /* RSA public key OID: 1.2.840.113549.1.1.1 */
        static const uint8_t rsaPubKeyOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
        };

        static uint8_t rsaPriv[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t rsaPub[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t rsaPrivLen;
        size_t rsaPubLen;
        static SSFX509GenParams_t rp;
        uint8_t serial[] = { 0x20u };
        /* RSASSA-PSS-params { [0] sha256, [1] mgf1-sha256, [2] 32 } matching SSFRSASignPSS */
        static const uint8_t pssParamsSalt32[] = {
            0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u,
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            /* [1] maskGenAlgorithm MGF1-SHA-256 */
            0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
            0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
            0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            0xA2u, 0x03u, 0x02u, 0x01u, 0x20u
        };
        static uint8_t tbsDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t tbsLen;
        uint8_t tbsHash[SSF_SHA2_256_BYTE_SIZE];
        static uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
        size_t sigLen;
        static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t certDerLen;
        static SSFX509Cert_t parsed;

        /* Generate 2048-bit RSA key pair */
        SSF_ASSERT(SSFRSAKeyGen(2048, rsaPriv, sizeof(rsaPriv), &rsaPrivLen,
                   rsaPub, sizeof(rsaPub), &rsaPubLen) == true);

        /* Build self-signed RSA-PSS cert */
        memset(&rp, 0, sizeof(rp));
        rp.pathLenConstraint = -1;
        rp.version = 2u;
        rp.serial = serial;
        rp.serialLen = 1u;
        rp.sigAlgOidRaw = rsaPssOid;
        rp.sigAlgOidRawLen = sizeof(rsaPssOid);
        rp.sigAlgParams = pssParamsSalt32;
        rp.sigAlgParamsLen = sizeof(pssParamsSalt32);
        rp.issuer.cn = "rsa-pss-full";
        rp.subject.cn = "rsa-pss-full";
        rp.notBefore = 1700000000ull;
        rp.notAfter = 2000000000ull;
        rp.pubKeyAlgOidRaw = rsaPubKeyOid;
        rp.pubKeyAlgOidRawLen = sizeof(rsaPubKeyOid);
        rp.pubKey = rsaPub;
        rp.pubKeyLen = (uint32_t)rsaPubLen;

        /* Encode TBS - this requires spkiBuf large enough for RSA pubkey */
        (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &rp, &tbsLen);
        SSF_ASSERT(tbsLen > 0u);

        /* Hash and sign with RSA-PSS-SHA256 */
        SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
        SSF_ASSERT(SSFRSASignPSS(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA256,
                   tbsHash, SSF_SHA2_256_BYTE_SIZE,
                   sig, sizeof(sig), &sigLen) == true);

        (void)SSFX509EncodeCert(certDer, sizeof(certDer), &rp,
                                        sig, (uint32_t)sigLen, &certDerLen);
        SSF_ASSERT(certDerLen > 0u);

        /* Parse and verify self-signed signature */
        SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == true);
        SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == true);
    }

    /* ---- RSA-PSS-SHA384: full cert encode -> parse -> verify, with PSS parameters encoded ---- */
    {
        static const uint8_t rsaPssOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Au
        };
        static const uint8_t rsaPubKeyOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
        };
        /* PSS parameters for SHA-384 */
        static const uint8_t pssParamsSHA384[] = {
            0x30u, 0x34u,
            0xA0u, 0x0Fu,
            0x30u, 0x0Du,
            0x06u, 0x09u,
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x02u,
            0x05u, 0x00u,
            /* [1] maskGenAlgorithm MGF1-SHA-384 */
            0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
            0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
            0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x02u, 0x05u, 0x00u,
            0xA2u, 0x03u, 0x02u, 0x01u, 0x30u /* [2] saltLength 48 */
        };

        static uint8_t rsaPriv[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t rsaPub[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t rsaPrivLen;
        size_t rsaPubLen;
        static SSFX509GenParams_t rp;
        uint8_t serial[] = { 0x21u };
        static uint8_t tbsDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t tbsLen;
        uint8_t tbsHash[SSF_SHA2_384_BYTE_SIZE];
        static uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
        size_t sigLen;
        static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t certDerLen;
        static SSFX509Cert_t parsed;

        SSF_ASSERT(SSFRSAKeyGen(2048, rsaPriv, sizeof(rsaPriv), &rsaPrivLen,
                   rsaPub, sizeof(rsaPub), &rsaPubLen) == true);

        memset(&rp, 0, sizeof(rp));
        rp.pathLenConstraint = -1;
        rp.version = 2u;
        rp.serial = serial;
        rp.serialLen = 1u;
        rp.sigAlgOidRaw = rsaPssOid;
        rp.sigAlgOidRawLen = sizeof(rsaPssOid);
        rp.sigAlgParams = pssParamsSHA384;
        rp.sigAlgParamsLen = sizeof(pssParamsSHA384);
        rp.issuer.cn = "rsa-pss384";
        rp.subject.cn = "rsa-pss384";
        rp.notBefore = 1700000000ull;
        rp.notAfter = 2000000000ull;
        rp.pubKeyAlgOidRaw = rsaPubKeyOid;
        rp.pubKeyAlgOidRawLen = sizeof(rsaPubKeyOid);
        rp.pubKey = rsaPub;
        rp.pubKeyLen = (uint32_t)rsaPubLen;

        /* Encode TBS */
        (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &rp, &tbsLen);
        SSF_ASSERT(tbsLen > 0u);

        /* Hash with SHA-384 and sign with RSA-PSS-SHA384 */
        SSFSHA384(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
        SSF_ASSERT(SSFRSASignPSS(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA384,
                   tbsHash, SSF_SHA2_384_BYTE_SIZE,
                   sig, sizeof(sig), &sigLen) == true);

        (void)SSFX509EncodeCert(certDer, sizeof(certDer), &rp,
                                        sig, (uint32_t)sigLen, &certDerLen);
        SSF_ASSERT(certDerLen > 0u);

        /* Parse and verify: the verifier must read PSS params to use SHA-384 */
        SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == true);
        SSF_ASSERT(parsed.sigAlgParams != NULL);
        SSF_ASSERT(parsed.sigAlgParamsLen > 0u);
        SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == true);
    }
#endif /* _UT_RSA_PSS_SIGN == 1 */

    /* ---- 11. SHA-512 Signature Algorithm Support ---- */

#if _UT_RSA_PKCS1_SIGN == 1
    /* ---- RSA PKCS#1 v1.5 SHA-512: full encode -> parse -> verify ---- */
    {
        /* sha512WithRSAEncryption: 1.2.840.113549.1.1.13 */
        static const uint8_t rsaPkcs1Sha512Oid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Du
        };
        static const uint8_t rsaPubKeyOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
        };

        static uint8_t rsaPriv[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t rsaPub[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t rsaPrivLen;
        size_t rsaPubLen;
        static SSFX509GenParams_t rp;
        uint8_t serial[] = { 0x30u };
        static uint8_t tbsDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t tbsLen;
        uint8_t tbsHash[SSF_SHA2_512_BYTE_SIZE];
        static uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
        size_t sigLen;
        static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t certDerLen;
        static SSFX509Cert_t parsed;

        SSF_ASSERT(SSFRSAKeyGen(2048, rsaPriv, sizeof(rsaPriv), &rsaPrivLen,
                   rsaPub, sizeof(rsaPub), &rsaPubLen) == true);

        memset(&rp, 0, sizeof(rp));
        rp.pathLenConstraint = -1;
        rp.version = 2u;
        rp.serial = serial;
        rp.serialLen = 1u;
        rp.sigAlgOidRaw = rsaPkcs1Sha512Oid;
        rp.sigAlgOidRawLen = sizeof(rsaPkcs1Sha512Oid);
        rp.issuer.cn = "rsa-sha512";
        rp.subject.cn = "rsa-sha512";
        rp.notBefore = 1700000000ull;
        rp.notAfter = 2000000000ull;
        rp.pubKeyAlgOidRaw = rsaPubKeyOid;
        rp.pubKeyAlgOidRawLen = sizeof(rsaPubKeyOid);
        rp.pubKey = rsaPub;
        rp.pubKeyLen = (uint32_t)rsaPubLen;

        (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &rp, &tbsLen);
        SSF_ASSERT(tbsLen > 0u);

        SSFSHA512(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
        SSF_ASSERT(SSFRSASignPKCS1(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA512,
                   tbsHash, SSF_SHA2_512_BYTE_SIZE,
                   sig, sizeof(sig), &sigLen) == true);

        (void)SSFX509EncodeCert(certDer, sizeof(certDer), &rp,
                                        sig, (uint32_t)sigLen, &certDerLen);
        SSF_ASSERT(certDerLen > 0u);

        SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == true);
        SSF_ASSERT(SSFX509IsSigRSAPKCS1SHA512(&parsed) == true);
        SSF_ASSERT(SSFX509IsSigRSAPKCS1SHA256(&parsed) == false);
        SSF_ASSERT(SSFX509IsSigRSAPKCS1SHA384(&parsed) == false);
        SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == true);

        /* COV-3d: plain rsaEncryption with a SHA-512 digest algorithm (CMS, RFC 3370 3.2) */
        {
            static const uint8_t sha512Oid[] = {
                0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x03u
            };
            static const uint8_t sha384Oid[] = {
                0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x02u
            };

            SSF_ASSERT(SSFX509VerifySignature(&parsed, rsaPubKeyOid, sizeof(rsaPubKeyOid), NULL,
                                              0u, sha512Oid, sizeof(sha512Oid), tbsDer, tbsLen,
                                              sig, (uint32_t)sigLen) == true);
            SSF_ASSERT(SSFX509VerifySignature(&parsed, rsaPubKeyOid, sizeof(rsaPubKeyOid), NULL,
                                              0u, sha384Oid, sizeof(sha384Oid), tbsDer, tbsLen,
                                              sig, (uint32_t)sigLen) == false);
        }
    }
#endif /* _UT_RSA_PKCS1_SIGN == 1 */

#if _UT_RSA_PSS_SIGN == 1
    /* ---- RSA-PSS SHA-512: full encode -> parse -> verify ---- */
    {
        static const uint8_t rsaPssOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Au
        };
        static const uint8_t rsaPubKeyOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
        };
        /* PSS parameters for SHA-512 */
        static const uint8_t pssParamsSHA512[] = {
            0x30u, 0x34u,
            0xA0u, 0x0Fu,
            0x30u, 0x0Du,
            0x06u, 0x09u,
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x03u, /* SHA-512 OID */
            0x05u, 0x00u,
            /* [1] maskGenAlgorithm MGF1-SHA-512 */
            0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
            0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
            0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x03u, 0x05u, 0x00u,
            0xA2u, 0x03u, 0x02u, 0x01u, 0x40u /* [2] saltLength 64 */
        };

        static uint8_t rsaPriv[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t rsaPub[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t rsaPrivLen;
        size_t rsaPubLen;
        static SSFX509GenParams_t rp;
        uint8_t serial[] = { 0x31u };
        static uint8_t tbsDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t tbsLen;
        uint8_t tbsHash[SSF_SHA2_512_BYTE_SIZE];
        static uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
        size_t sigLen;
        static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t certDerLen;
        static SSFX509Cert_t parsed;

        SSF_ASSERT(SSFRSAKeyGen(2048, rsaPriv, sizeof(rsaPriv), &rsaPrivLen,
                   rsaPub, sizeof(rsaPub), &rsaPubLen) == true);

        memset(&rp, 0, sizeof(rp));
        rp.pathLenConstraint = -1;
        rp.version = 2u;
        rp.serial = serial;
        rp.serialLen = 1u;
        rp.sigAlgOidRaw = rsaPssOid;
        rp.sigAlgOidRawLen = sizeof(rsaPssOid);
        rp.sigAlgParams = pssParamsSHA512;
        rp.sigAlgParamsLen = sizeof(pssParamsSHA512);
        rp.issuer.cn = "rsa-pss512";
        rp.subject.cn = "rsa-pss512";
        rp.notBefore = 1700000000ull;
        rp.notAfter = 2000000000ull;
        rp.pubKeyAlgOidRaw = rsaPubKeyOid;
        rp.pubKeyAlgOidRawLen = sizeof(rsaPubKeyOid);
        rp.pubKey = rsaPub;
        rp.pubKeyLen = (uint32_t)rsaPubLen;

        (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &rp, &tbsLen);
        SSF_ASSERT(tbsLen > 0u);

        SSFSHA512(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
        SSF_ASSERT(SSFRSASignPSS(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA512,
                   tbsHash, SSF_SHA2_512_BYTE_SIZE,
                   sig, sizeof(sig), &sigLen) == true);

        (void)SSFX509EncodeCert(certDer, sizeof(certDer), &rp,
                                        sig, (uint32_t)sigLen, &certDerLen);
        SSF_ASSERT(certDerLen > 0u);

        SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == true);
        SSF_ASSERT(parsed.sigAlgParams != NULL);
        SSF_ASSERT(parsed.sigAlgParamsLen > 0u);
        SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == true);
    }
#endif /* _UT_RSA_PSS_SIGN == 1 */

    /* ==== SAN / SKID / AKID Extension Encoding Round-Trip Tests ==== */

    /* ---- Test: SAN with DNS names round-trip ---- */
    {
        static const char *sanDNS[] = { "test.local", "localhost", NULL };
        static const uint8_t fakePubKeySAN[65] = { 0x04u, 0x01u };
        static const uint8_t serialSAN[] = { 0x20u };
        static const uint8_t fakeSigSAN[64] = { 0xBBu };
        static SSFX509GenParams_t p;
        static uint8_t derBuf[1024];
        uint32_t derLen;
        static SSFX509Cert_t parsed;

        memset(&p, 0, sizeof(p));
        p.pathLenConstraint = -1;
        p.version = 2u;
        p.serial = serialSAN;
        p.serialLen = sizeof(serialSAN);
        p.sigAlgOidRaw = _utSigAlgOid;
        p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
        p.issuer.cn = "san-test";
        p.subject.cn = "san-test";
        p.notBefore = 1700000000ull;
        p.notAfter = 2000000000ull;
        p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
        p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
        p.ecCurveOidRaw = _utCurveOid;
        p.ecCurveOidRawLen = sizeof(_utCurveOid);
        p.pubKey = fakePubKeySAN;
        p.pubKeyLen = sizeof(fakePubKeySAN);
        p.sanDNSNames = sanDNS;

        (void)SSFX509EncodeCert(derBuf, sizeof(derBuf), &p, fakeSigSAN, sizeof(fakeSigSAN),
         &derLen);
        SSF_ASSERT(derLen > 0u);
        SSF_ASSERT(SSFX509Parse(derBuf, derLen, &parsed) == true);
        SSF_ASSERT(parsed.sanLen == 2u);
        SSF_ASSERT(parsed.san[0].type == SSF_X509_SAN_DNS);
        SSF_ASSERT(parsed.san[0].valLen == 10u);
        SSF_ASSERT(memcmp(parsed.san[0].val, "test.local", 10) == 0);
        SSF_ASSERT(parsed.san[1].type == SSF_X509_SAN_DNS);
        SSF_ASSERT(parsed.san[1].valLen == 9u);
        SSF_ASSERT(memcmp(parsed.san[1].val, "localhost", 9) == 0);
    }

    /* ---- Test: SAN with IP address round-trip ---- */
    {
        static const uint8_t ip1[] = { 10u, 0u, 0u, 1u };
        static const uint8_t *sanIPs[] = { ip1, NULL };
        static const uint8_t fakePubKeyIP[65] = { 0x04u, 0x02u };
        static const uint8_t serialIP[] = { 0x21u };
        static const uint8_t fakeSigIP[64] = { 0xCCu };
        static SSFX509GenParams_t p;
        static uint8_t derBuf[1024];
        uint32_t derLen;
        static SSFX509Cert_t parsed;

        memset(&p, 0, sizeof(p));
        p.pathLenConstraint = -1;
        p.version = 2u;
        p.serial = serialIP;
        p.serialLen = sizeof(serialIP);
        p.sigAlgOidRaw = _utSigAlgOid;
        p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
        p.issuer.cn = "ip-test";
        p.subject.cn = "ip-test";
        p.notBefore = 1700000000ull;
        p.notAfter = 2000000000ull;
        p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
        p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
        p.ecCurveOidRaw = _utCurveOid;
        p.ecCurveOidRawLen = sizeof(_utCurveOid);
        p.pubKey = fakePubKeyIP;
        p.pubKeyLen = sizeof(fakePubKeyIP);
        p.sanIPAddrs = sanIPs;

        (void)SSFX509EncodeCert(derBuf, sizeof(derBuf), &p, fakeSigIP, sizeof(fakeSigIP), &derLen);
        SSF_ASSERT(derLen > 0u);
        SSF_ASSERT(SSFX509Parse(derBuf, derLen, &parsed) == true);
        SSF_ASSERT(parsed.sanLen == 1u);
        SSF_ASSERT(parsed.san[0].type == SSF_X509_SAN_IP);
        SSF_ASSERT(parsed.san[0].valLen == 4u);
        SSF_ASSERT(memcmp(parsed.san[0].val, ip1, 4) == 0);
    }

    /* ---- Test: SKID encoding round-trip ---- */
    {
        static const uint8_t skidVal[] = { 0x01u, 0x02u, 0x03u, 0x04u };
        static const uint8_t fakePubKeySKID[65] = { 0x04u, 0x03u };
        static const uint8_t serialSKID[] = { 0x22u };
        static const uint8_t fakeSigSKID[64] = { 0xDDu };
        static SSFX509GenParams_t p;
        static uint8_t derBuf[1024];
        uint32_t derLen;
        static SSFX509Cert_t parsed;

        memset(&p, 0, sizeof(p));
        p.pathLenConstraint = -1;
        p.version = 2u;
        p.serial = serialSKID;
        p.serialLen = sizeof(serialSKID);
        p.sigAlgOidRaw = _utSigAlgOid;
        p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
        p.issuer.cn = "skid-test";
        p.subject.cn = "skid-test";
        p.notBefore = 1700000000ull;
        p.notAfter = 2000000000ull;
        p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
        p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
        p.ecCurveOidRaw = _utCurveOid;
        p.ecCurveOidRawLen = sizeof(_utCurveOid);
        p.pubKey = fakePubKeySKID;
        p.pubKeyLen = sizeof(fakePubKeySKID);
        p.skid = skidVal;
        p.skidLen = sizeof(skidVal);

        (void)SSFX509EncodeCert(derBuf, sizeof(derBuf), &p, fakeSigSKID, sizeof(fakeSigSKID),
         &derLen);
        SSF_ASSERT(derLen > 0u);
        SSF_ASSERT(SSFX509Parse(derBuf, derLen, &parsed) == true);
        SSF_ASSERT(parsed.skid != NULL);
        SSF_ASSERT(parsed.skidLen == 4u);
        SSF_ASSERT(memcmp(parsed.skid, skidVal, 4) == 0);
    }

    /* ---- Test: AKID encoding round-trip ---- */
    {
        static const uint8_t akidVal[] = { 0xAAu, 0xBBu, 0xCCu, 0xDDu };
        static const uint8_t fakePubKeyAKID[65] = { 0x04u, 0x04u };
        static const uint8_t serialAKID[] = { 0x23u };
        static const uint8_t fakeSigAKID[64] = { 0xEEu };
        static SSFX509GenParams_t p;
        static uint8_t derBuf[1024];
        uint32_t derLen;
        static SSFX509Cert_t parsed;

        memset(&p, 0, sizeof(p));
        p.pathLenConstraint = -1;
        p.version = 2u;
        p.serial = serialAKID;
        p.serialLen = sizeof(serialAKID);
        p.sigAlgOidRaw = _utSigAlgOid;
        p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
        p.issuer.cn = "akid-test";
        p.subject.cn = "akid-test";
        p.notBefore = 1700000000ull;
        p.notAfter = 2000000000ull;
        p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
        p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
        p.ecCurveOidRaw = _utCurveOid;
        p.ecCurveOidRawLen = sizeof(_utCurveOid);
        p.pubKey = fakePubKeyAKID;
        p.pubKeyLen = sizeof(fakePubKeyAKID);
        p.akid = akidVal;
        p.akidLen = sizeof(akidVal);

        (void)SSFX509EncodeCert(derBuf, sizeof(derBuf), &p, fakeSigAKID, sizeof(fakeSigAKID),
         &derLen);
        SSF_ASSERT(derLen > 0u);
        SSF_ASSERT(SSFX509Parse(derBuf, derLen, &parsed) == true);
        SSF_ASSERT(parsed.akid != NULL);
        SSF_ASSERT(parsed.akidLen == 4u);
        SSF_ASSERT(memcmp(parsed.akid, akidVal, 4) == 0);
    }

    /* ---- Test: Full cert with SAN in VerifyChain (hostname matching) ---- */
    {
        static const char *sanDNSChain[] = { "test.local", NULL };
        static uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t serial[] = { 0x30u };
        static SSFX509GenParams_t p;
        static uint8_t tbsDer[512];
        uint32_t tbsLen;
        uint8_t tbsHash[32];
        static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;
        static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t certDerLen;

        memset(privKey, 0, sizeof(privKey));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, privKey, sizeof(privKey),
                                   pubKey, sizeof(pubKey), &pubKeyLen) == true);

        memset(&p, 0, sizeof(p));
        p.pathLenConstraint = -1;
        p.version = 2u;
        p.serial = serial;
        p.serialLen = sizeof(serial);
        p.sigAlgOidRaw = _utSigAlgOid;
        p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
        p.issuer.cn = "test.local";
        p.subject.cn = "test.local";
        p.notBefore = 1700000000ull;
        p.notAfter = 2000000000ull;
        p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
        p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
        p.ecCurveOidRaw = _utCurveOid;
        p.ecCurveOidRawLen = sizeof(_utCurveOid);
        p.pubKey = pubKey;
        p.pubKeyLen = (uint32_t)pubKeyLen;
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN | SSF_X509_KU_DIGITAL_SIGNATURE;
        p.sanDNSNames = sanDNSChain;

        (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen);
        SSF_ASSERT(tbsLen > 0u);
        SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
        SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, privKey, _UT_PRIV_LEN, tbsHash, 32, sig, sizeof(sig),
                                   &sigLen) == true);
        (void)SSFX509EncodeCert(certDer, sizeof(certDer), &p, sig, (uint32_t)sigLen, &certDerLen);
        SSF_ASSERT(certDerLen > 0u);

        {
            const uint8_t *chainDer[1];
            uint32_t chainDerLen_arr[1];
            const uint8_t *trustDer[1];
            uint32_t trustDerLen_arr[1];

            chainDer[0] = certDer;
            chainDerLen_arr[0] = certDerLen;
            trustDer[0] = certDer;
            trustDerLen_arr[0] = certDerLen;

            /* Hostname "test.local" should match SAN */
            SSF_ASSERT(SSFX509VerifyChain(chainDer, chainDerLen_arr, 1u,
                                           trustDer, trustDerLen_arr, 1u,
                                           "test.local", 1800000000ull, &_utVErr) == true);
            _UT_VERR(OK, 0u);

            /* Wrong hostname should fail */
            SSF_ASSERT(SSFX509VerifyChain(chainDer, chainDerLen_arr, 1u,
                                           trustDer, trustDerLen_arr, 1u,
                                           "wrong.local", 1800000000ull, &_utVErr) == false);
            _UT_VERR(ERR_HOSTNAME, 0u);
        }
    }

    /* ---- Test: SKID/AKID cross-check with generated CA + leaf ---- */
    {
        static const uint8_t keyIdVal[] = {
            0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u
        };
        static const char *caSanDNS[] = { "ca.skid.test", NULL };
        static const char *leafSanDNS[] = { "leaf.skid.test", NULL };
        static uint8_t caPrivKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t caPubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t caPubKeyLen;
        static uint8_t leafPrivKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t leafPubKeyLen;
        uint8_t caSerial[] = { 0x40u };
        uint8_t leafSerial[] = { 0x41u };
        static SSFX509GenParams_t cp;
        static SSFX509GenParams_t lp;
        static uint8_t tbsDer[512];
        uint32_t tbsLen;
        uint8_t tbsHash[32];
        static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;
        static uint8_t caCertDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t caCertDerLen;
        static uint8_t leafCertDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t leafCertDerLen;

        /* Generate CA key pair */
        memset(caPrivKey, 0, sizeof(caPrivKey));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPrivKey, sizeof(caPrivKey),
                                   caPubKey, sizeof(caPubKey), &caPubKeyLen) == true);

        /* Generate CA cert with SKID */
        memset(&cp, 0, sizeof(cp));
        cp.pathLenConstraint = -1;
        cp.version = 2u;
        cp.serial = caSerial;
        cp.serialLen = sizeof(caSerial);
        cp.sigAlgOidRaw = _utSigAlgOid;
        cp.sigAlgOidRawLen = sizeof(_utSigAlgOid);
        cp.issuer.cn = "ca.skid.test";
        cp.subject.cn = "ca.skid.test";
        cp.notBefore = 1700000000ull;
        cp.notAfter = 2000000000ull;
        cp.pubKeyAlgOidRaw = _utPubKeyAlgOid;
        cp.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
        cp.ecCurveOidRaw = _utCurveOid;
        cp.ecCurveOidRawLen = sizeof(_utCurveOid);
        cp.pubKey = caPubKey;
        cp.pubKeyLen = (uint32_t)caPubKeyLen;
        cp.addBasicConstraints = true;
        cp.isCA = true;
        cp.addKeyUsage = true;
        cp.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        cp.sanDNSNames = caSanDNS;
        cp.skid = keyIdVal;
        cp.skidLen = sizeof(keyIdVal);

        (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &cp, &tbsLen);
        SSF_ASSERT(tbsLen > 0u);
        SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
        SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, caPrivKey, _UT_PRIV_LEN, tbsHash, 32, sig,
                                   sizeof(sig), &sigLen) == true);
        (void)SSFX509EncodeCert(caCertDer, sizeof(caCertDer), &cp, sig, (uint32_t)sigLen,
         &caCertDerLen);
        SSF_ASSERT(caCertDerLen > 0u);

        /* Verify CA has SKID */
        {
            static SSFX509Cert_t caParsed;
            SSF_ASSERT(SSFX509Parse(caCertDer, caCertDerLen, &caParsed) == true);
            SSF_ASSERT(caParsed.skid != NULL);
            SSF_ASSERT(caParsed.skidLen == sizeof(keyIdVal));
            SSF_ASSERT(memcmp(caParsed.skid, keyIdVal, sizeof(keyIdVal)) == 0);
        }

        /* Generate leaf key pair */
        memset(leafPrivKey, 0, sizeof(leafPrivKey));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPrivKey, sizeof(leafPrivKey),
                                   leafPubKey, sizeof(leafPubKey), &leafPubKeyLen) == true);

        /* Generate leaf cert with AKID matching CA's SKID */
        memset(&lp, 0, sizeof(lp));
        lp.pathLenConstraint = -1;
        lp.version = 2u;
        lp.serial = leafSerial;
        lp.serialLen = sizeof(leafSerial);
        lp.sigAlgOidRaw = _utSigAlgOid;
        lp.sigAlgOidRawLen = sizeof(_utSigAlgOid);
        lp.issuer.cn = "ca.skid.test";
        lp.subject.cn = "leaf.skid.test";
        lp.notBefore = 1700000000ull;
        lp.notAfter = 2000000000ull;
        lp.pubKeyAlgOidRaw = _utPubKeyAlgOid;
        lp.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
        lp.ecCurveOidRaw = _utCurveOid;
        lp.ecCurveOidRawLen = sizeof(_utCurveOid);
        lp.pubKey = leafPubKey;
        lp.pubKeyLen = (uint32_t)leafPubKeyLen;
        lp.sanDNSNames = leafSanDNS;
        lp.akid = keyIdVal;
        lp.akidLen = sizeof(keyIdVal);

        (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &lp, &tbsLen);
        SSF_ASSERT(tbsLen > 0u);
        SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
        SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, caPrivKey, _UT_PRIV_LEN, tbsHash, 32, sig,
                                   sizeof(sig), &sigLen) == true);
        (void)SSFX509EncodeCert(leafCertDer, sizeof(leafCertDer), &lp,
                                           sig, (uint32_t)sigLen, &leafCertDerLen);
        SSF_ASSERT(leafCertDerLen > 0u);

        /* Verify leaf has AKID */
        {
            static SSFX509Cert_t leafParsed;
            SSF_ASSERT(SSFX509Parse(leafCertDer, leafCertDerLen, &leafParsed) == true);
            SSF_ASSERT(leafParsed.akid != NULL);
            SSF_ASSERT(leafParsed.akidLen == sizeof(keyIdVal));
            SSF_ASSERT(memcmp(leafParsed.akid, keyIdVal, sizeof(keyIdVal)) == 0);
        }

        /* Verify chain: leaf signed by CA, SKID/AKID match */
        {
            const uint8_t *chainDer[1];
            uint32_t chainDerLen_arr[1];
            const uint8_t *trustDer[1];
            uint32_t trustDerLen_arr[1];
            static SSFX509Cert_t leafParsed2;
            static SSFX509Cert_t caParsed2;

            chainDer[0] = leafCertDer;
            chainDerLen_arr[0] = leafCertDerLen;
            trustDer[0] = caCertDer;
            trustDerLen_arr[0] = caCertDerLen;

            SSF_ASSERT(SSFX509VerifyChain(chainDer, chainDerLen_arr, 1u,
                                           trustDer, trustDerLen_arr, 1u,
                                           "leaf.skid.test", 1800000000ull, &_utVErr) == true);
            _UT_VERR(OK, 0u);

            /* Verify SKID/AKID cross-check passes */
            SSF_ASSERT(SSFX509Parse(leafCertDer, leafCertDerLen, &leafParsed2) == true);
            SSF_ASSERT(SSFX509Parse(caCertDer, caCertDerLen, &caParsed2) == true);
            SSF_ASSERT(SSFX509CheckSKIDAKID(&leafParsed2, &caParsed2) == true);
        }
    }

    /* ---- Ed25519 self-signed certificate round-trip (RFC 8410) ---- */
    {
        /* id-Ed25519 OID 1.3.101.112 - same for sigAlg and pubKeyAlg */
        static const uint8_t edOid[] = { 0x2Bu, 0x65u, 0x70u };
        static const uint8_t edSerial[] = { 0x11u };
        static const char *edSanDNS[] = { "ed25519.ssf.local", NULL };
        uint8_t edSeed[SSF_ED25519_SEED_SIZE];
        uint8_t edPubKey[SSF_ED25519_PUB_KEY_SIZE];
        static uint8_t edTbs[512];
        uint32_t edTbsLen;
        uint8_t edSig[SSF_ED25519_SIG_SIZE];
        static uint8_t edCertDer[1024];
        uint32_t edCertDerLen;
        static SSFX509GenParams_t ep;
        static SSFX509Cert_t edParsed;

        /* Generate Ed25519 key pair (seed + derived pubKey) */
        SSF_ASSERT(SSFEd25519KeyGen(edSeed, edPubKey) == true);

        /* Build TBS with Ed25519 OIDs. RFC 8410: algorithm has no parameters. */
        memset(&ep, 0, sizeof(ep));
        ep.pathLenConstraint = -1;
        ep.version = 2u;
        ep.serial = edSerial;
        ep.serialLen = sizeof(edSerial);
        ep.sigAlgOidRaw = edOid;
        ep.sigAlgOidRawLen = sizeof(edOid);
        ep.issuer.cn = "ed25519.ssf.local";
        ep.subject.cn = "ed25519.ssf.local";
        ep.notBefore = 1700000000ull;
        ep.notAfter = 2000000000ull;
        ep.pubKeyAlgOidRaw = edOid;
        ep.pubKeyAlgOidRawLen = sizeof(edOid);
        ep.ecCurveOidRaw = NULL;  /* Ed25519: no curve OID in SPKI algorithm */
        ep.ecCurveOidRawLen = 0u;
        ep.pubKey = edPubKey;
        ep.pubKeyLen = SSF_ED25519_PUB_KEY_SIZE;
        ep.sanDNSNames = edSanDNS;

        (void)SSFX509EncodeTBS(edTbs, sizeof(edTbs), &ep, &edTbsLen);
        SSF_ASSERT(edTbsLen > 0u);

        /* Ed25519 signs the raw TBS (no pre-hash). */
        SSFEd25519Sign(edSeed, edPubKey, edTbs, edTbsLen, edSig);

        (void)SSFX509EncodeCert(edCertDer, sizeof(edCertDer), &ep,
                                          edSig, SSF_ED25519_SIG_SIZE, &edCertDerLen);
        SSF_ASSERT(edCertDerLen > 0u);

        /* Parse back and verify algorithm identification */
        SSF_ASSERT(SSFX509Parse(edCertDer, edCertDerLen, &edParsed) == true);
        SSF_ASSERT(SSFX509IsSigEd25519(&edParsed) == true);
        SSF_ASSERT(SSFX509IsSigECDSASHA256(&edParsed) == false);
        SSF_ASSERT(SSFX509IsKeyRSA(&edParsed) == false);
        SSF_ASSERT(edParsed.pubKeyLen == SSF_ED25519_PUB_KEY_SIZE);
        SSF_ASSERT(edParsed.signatureLen == SSF_ED25519_SIG_SIZE);
        SSF_ASSERT(edParsed.ecCurveOidRaw == NULL);

        /* IsKey* tests the subject key, IsSig* the issuer's algorithm; self-signed: both Ed25519 */
        SSF_ASSERT(SSFX509IsKeyEd25519(&edParsed) == true);
        SSF_ASSERT(SSFX509IsSigEd25519(&edParsed) == true);
        SSF_ASSERT(SSFX509IsKeyP256(&edParsed) == false);
        SSF_ASSERT(SSFX509IsSigECDSASHA256(&edParsed) == false);
        SSF_ASSERT_TEST(SSFX509IsKeyEd25519(NULL));

        /* Ed25519 key issued by an ECDSA CA: key Ed25519, signature not (placeholder sig) */
        {
            static uint8_t mixedDer[1024];
            static SSFX509Cert_t mixed;
            uint32_t mixedLen = 0;

            ep.sigAlgOidRaw = _utSigAlgOid;
            ep.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            (void)SSFX509EncodeCert(mixedDer, sizeof(mixedDer), &ep, edSig, SSF_ED25519_SIG_SIZE,
                                    &mixedLen);
            ep.sigAlgOidRaw = edOid;
            ep.sigAlgOidRawLen = sizeof(edOid);
            SSF_ASSERT(mixedLen > 0u);
            SSF_ASSERT(SSFX509Parse(mixedDer, mixedLen, &mixed) == true);
            SSF_ASSERT(SSFX509IsKeyEd25519(&mixed) == true);
            SSF_ASSERT(SSFX509IsSigEd25519(&mixed) == false);
            SSF_ASSERT(SSFX509IsSigECDSASHA256(&mixed) == true);
        }

        /* Verify signature using our Ed25519 module directly against the parsed TBS */
        SSF_ASSERT(SSFEd25519Verify(edParsed.pubKey, edParsed.tbsRaw, edParsed.tbsRawLen,
                                     edParsed.signature) == true);

        /* Verify signature via X.509 dispatch (self-signed: cert is its own issuer) */
        SSF_ASSERT(SSFX509VerifyCertSignature(&edParsed, &edParsed) == true);

        /* Full chain verification: self-signed leaf with itself as trust anchor */
        {
            const uint8_t *chainDer[1];
            uint32_t chainDerLen_arr[1];
            const uint8_t *trustDer[1];
            uint32_t trustDerLen_arr[1];

            chainDer[0] = edCertDer;
            chainDerLen_arr[0] = edCertDerLen;
            trustDer[0] = edCertDer;
            trustDerLen_arr[0] = edCertDerLen;

            SSF_ASSERT(SSFX509VerifyChain(chainDer, chainDerLen_arr, 1u,
                                           trustDer, trustDerLen_arr, 1u,
                                           "ed25519.ssf.local", 1800000000ull, &_utVErr) == true);
            _UT_VERR(OK, 0u);
        }

        /* Tamper with signature - verification must fail */
        {
            static uint8_t corruptCert[1024];
            static SSFX509Cert_t corruptParsed;
            memcpy(corruptCert, edCertDer, edCertDerLen);
            /* Flip one bit in the signature (near end of cert DER) */
            corruptCert[edCertDerLen - 1u] ^= 0x01u;
            SSF_ASSERT(SSFX509Parse(corruptCert, edCertDerLen, &corruptParsed) == true);
            SSF_ASSERT(SSFX509VerifyCertSignature(&corruptParsed, &corruptParsed) == false);
        }
    }

    /* ---- Large certificate (> 2048 bytes, max SAN entries of long DNS names) round-trip ---- */
    {
        static SSFX509GenParams_t p;
        static uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        static uint8_t tbsDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t tbsLen;
        uint8_t tbsHash[32];
        static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;
        static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t certDerLen;
        uint8_t serial[] = { 0x42u };
        static SSFX509Cert_t parsed;
        uint32_t i;

        /* MAX_SAN_ENTRIES DNS names of 240 chars push the DER well beyond 2048 bytes */
        static char sanBuf[SSF_X509_CONFIG_MAX_SAN_ENTRIES][241];
        static const char *sanPtrs[SSF_X509_CONFIG_MAX_SAN_ENTRIES + 1];

        memset(privKey, 0, sizeof(privKey));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, privKey, sizeof(privKey),
                                   pubKey, sizeof(pubKey), &pubKeyLen) == true);

        for (i = 0; i < SSF_X509_CONFIG_MAX_SAN_ENTRIES; i++)
        {
            uint32_t j;
            /* Generate a 240-char DNS label list: "hostN-<padding>.example.ssf.local" */
            int n = snprintf(sanBuf[i], sizeof(sanBuf[i]), "host%u-", (unsigned)i);
            for (j = (uint32_t)n; j < 222u; j++) sanBuf[i][j] = (char)('a' + (j % 26u));
            memcpy(&sanBuf[i][222], ".example.ssf.local", 18);
            sanBuf[i][240] = '\0';
            sanPtrs[i] = sanBuf[i];
        }
        sanPtrs[SSF_X509_CONFIG_MAX_SAN_ENTRIES] = NULL;

        memset(&p, 0, sizeof(p));
        p.pathLenConstraint = -1;
        p.version = 2u;
        p.serial = serial;
        p.serialLen = sizeof(serial);
        p.sigAlgOidRaw = _utSigAlgOid;
        p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
        p.issuer.cn = "large.ssf.local";
        p.subject.cn = "large.ssf.local";
        p.notBefore = 1700000000ull;
        p.notAfter = 2000000000ull;
        p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
        p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
        p.ecCurveOidRaw = _utCurveOid;
        p.ecCurveOidRawLen = sizeof(_utCurveOid);
        p.pubKey = pubKey;
        p.pubKeyLen = (uint32_t)pubKeyLen;
        p.sanDNSNames = sanPtrs;

        (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen);
        SSF_ASSERT(tbsLen > 0u);
        SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
        SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, privKey, _UT_PRIV_LEN, tbsHash, 32, sig, sizeof(sig),
                                   &sigLen) == true);
        (void)SSFX509EncodeCert(certDer, sizeof(certDer), &p, sig, (uint32_t)sigLen, &certDerLen);
        SSF_ASSERT(certDerLen > 0u);

        /* The DER must exceed 2048 bytes for this test to exercise the larger limit */
        SSF_ASSERT(certDerLen > 2048u);
        SSF_ASSERT(certDerLen <= SSF_X509_CONFIG_MAX_CERT_SIZE);

        /* Parse the oversized cert and verify all SAN entries round-tripped intact. */
        SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == true);
        SSF_ASSERT(parsed.sanLen == SSF_X509_CONFIG_MAX_SAN_ENTRIES);
        for (i = 0; i < SSF_X509_CONFIG_MAX_SAN_ENTRIES; i++)
        {
            SSF_ASSERT(parsed.san[i].type == SSF_X509_SAN_DNS);
            SSF_ASSERT(parsed.san[i].valLen == 240u);
            SSF_ASSERT(memcmp(parsed.san[i].val, sanBuf[i], 240u) == 0);
        }

        /* Self-signed signature verifies over the TBS region the parser recovers */
        SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == true);

        /* Full chain: self-signed leaf as its own anchor, hostname matches one of the SANs */
        {
            const uint8_t *chainDer[1];
            uint32_t chainDerLen_arr[1];
            const uint8_t *trustDer[1];
            uint32_t trustDerLen_arr[1];

            chainDer[0] = certDer;
            chainDerLen_arr[0] = certDerLen;
            trustDer[0] = certDer;
            trustDerLen_arr[0] = certDerLen;

            SSF_ASSERT(SSFX509VerifyChain(chainDer, chainDerLen_arr, 1u,
                                           trustDer, trustDerLen_arr, 1u,
                                           sanBuf[0], 1800000000ull, &_utVErr) == true);
            _UT_VERR(OK, 0u);
        }
    }

    /* ---- Name Constraints (RFC 5280 4.2.1.10): matching leafs pass, others rejected ---- */
    {
        /* Helper ECDSA key material, reused across sub-tests */
        static uint8_t caPrivKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t caPubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t caPubKeyLen;
        static uint8_t leafPrivKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t leafPubKeyLen;

        memset(caPrivKey, 0, sizeof(caPrivKey));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPrivKey, sizeof(caPrivKey),
                                   caPubKey, sizeof(caPubKey), &caPubKeyLen) == true);
        memset(leafPrivKey, 0, sizeof(leafPrivKey));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPrivKey, sizeof(leafPrivKey),
                                   leafPubKey, sizeof(leafPubKey), &leafPubKeyLen) == true);

        /* CA permits dNSName example.com and iPAddress 10.0.0.0/8, excludes banned.example.com */
        static uint8_t caDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint32_t caDerLen;
        {
            static SSFX509GenParams_t cp;
            uint8_t caSerial[] = { 0x10u };
            static const char *caPermDNS[] = { "example.com", NULL };
            static const uint8_t caPermIP1[] = { 10u, 0u, 0u, 0u, 0xFFu, 0u, 0u, 0u };
            static const uint8_t *caPermIPs[] = { caPermIP1, NULL };
            static const char *caExclDNS[] = { "banned.example.com", NULL };
            static uint8_t caTbs[512];
            uint32_t caTbsLen;
            uint8_t caTbsHash[32];
            static uint8_t caSig[SSF_ECDSA_MAX_SIG_SIZE];
            size_t caSigLen;

            memset(&cp, 0, sizeof(cp));
            cp.pathLenConstraint = 0; /* CA can only sign end-entity certs */
            cp.version = 2u;
            cp.serial = caSerial;
            cp.serialLen = sizeof(caSerial);
            cp.sigAlgOidRaw = _utSigAlgOid;
            cp.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            cp.issuer.cn = "nc.test.ca";
            cp.subject.cn = "nc.test.ca";
            cp.notBefore = 1700000000ull;
            cp.notAfter = 2000000000ull;
            cp.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            cp.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            cp.ecCurveOidRaw = _utCurveOid;
            cp.ecCurveOidRawLen = sizeof(_utCurveOid);
            cp.pubKey = caPubKey;
            cp.pubKeyLen = (uint32_t)caPubKeyLen;
            cp.addBasicConstraints = true;
            cp.isCA = true;
            cp.addKeyUsage = true;
            cp.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
            cp.addNameConstraints = true;
            cp.ncPermittedDNS = caPermDNS;
            cp.ncPermittedIPs = caPermIPs;
            cp.ncExcludedDNS = caExclDNS;

            (void)SSFX509EncodeTBS(caTbs, sizeof(caTbs), &cp, &caTbsLen);
            SSF_ASSERT(caTbsLen > 0u);
            SSFSHA256(caTbs, caTbsLen, caTbsHash, sizeof(caTbsHash));
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, caPrivKey, _UT_PRIV_LEN, caTbsHash, 32, caSig,
                                       sizeof(caSig), &caSigLen) == true);
            (void)SSFX509EncodeCert(caDer, sizeof(caDer), &cp, caSig, (uint32_t)caSigLen,
             &caDerLen);
            SSF_ASSERT(caDerLen > 0u);
        }

        /* Verify CA parses with name constraints extracted correctly. */
        {
            static SSFX509Cert_t caParsed;
            SSF_ASSERT(SSFX509Parse(caDer, caDerLen, &caParsed) == true);
            SSF_ASSERT(caParsed.hasNameConstraints == true);
            SSF_ASSERT(caParsed.permittedLen == 2u);
            SSF_ASSERT(caParsed.excludedLen == 1u);
            SSF_ASSERT(caParsed.permittedSubtrees[0].type == SSF_X509_SAN_DNS);
            SSF_ASSERT(caParsed.permittedSubtrees[0].valLen == 11u);
            SSF_ASSERT(memcmp(caParsed.permittedSubtrees[0].val, "example.com", 11) == 0);
            SSF_ASSERT(caParsed.permittedSubtrees[1].type == SSF_X509_SAN_IP);
            SSF_ASSERT(caParsed.permittedSubtrees[1].valLen == 8u);
            SSF_ASSERT(caParsed.excludedSubtrees[0].type == SSF_X509_SAN_DNS);
            SSF_ASSERT(caParsed.excludedSubtrees[0].valLen == 18u);
            SSF_ASSERT(memcmp(caParsed.excludedSubtrees[0].val, "banned.example.com", 18) == 0);
        }

        /* Helper to build a leaf cert signed by the CA with a given SAN set. */
        #define _NC_BUILD_LEAF(_leafCN, _sanDNS, _sanIPs, _leafDer, _leafDerLen) do { \
            static SSFX509GenParams_t lp; \
            uint8_t leafSerial[] = { 0x20u }; \
            static uint8_t leafTbs[512]; \
            uint32_t leafTbsLen; \
            uint8_t leafTbsHash[32]; \
            static uint8_t leafSig[SSF_ECDSA_MAX_SIG_SIZE]; \
            size_t leafSigLen; \
            memset(&lp, 0, sizeof(lp)); \
            lp.pathLenConstraint = -1; \
            lp.version = 2u; \
            lp.serial = leafSerial; \
            lp.serialLen = sizeof(leafSerial); \
            lp.sigAlgOidRaw = _utSigAlgOid; \
            lp.sigAlgOidRawLen = sizeof(_utSigAlgOid); \
            lp.issuer.cn = "nc.test.ca"; \
            lp.subject.cn = (_leafCN); \
            lp.notBefore = 1700000000ull; \
            lp.notAfter = 2000000000ull; \
            lp.pubKeyAlgOidRaw = _utPubKeyAlgOid; \
            lp.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid); \
            lp.ecCurveOidRaw = _utCurveOid; \
            lp.ecCurveOidRawLen = sizeof(_utCurveOid); \
            lp.pubKey = leafPubKey; \
            lp.pubKeyLen = (uint32_t)leafPubKeyLen; \
            lp.sanDNSNames = (_sanDNS); \
            lp.sanIPAddrs = (_sanIPs); \
            (void)SSFX509EncodeTBS(leafTbs, sizeof(leafTbs), &lp, &leafTbsLen); \
            SSF_ASSERT(leafTbsLen > 0u); \
            SSFSHA256(leafTbs, leafTbsLen, leafTbsHash, sizeof(leafTbsHash)); \
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, caPrivKey, _UT_PRIV_LEN, \
                                        leafTbsHash, 32, leafSig, sizeof(leafSig), \
                                        &leafSigLen) == true); \
            (void)SSFX509EncodeCert((_leafDer), SSF_X509_CONFIG_MAX_CERT_SIZE, &lp, \
                                               leafSig, (uint32_t)leafSigLen, &(_leafDerLen)); \
            SSF_ASSERT((_leafDerLen) > 0u); \
        } while (0)

        /* Case 1: leaf SAN "foo.example.com" - inside permittedSubtrees -> accept. */
        {
            static const char *san[] = { "foo.example.com", NULL };
            static uint8_t leafDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t leafDerLen;
            const uint8_t *chain[1]; uint32_t chainL[1];
            const uint8_t *trust[1]; uint32_t trustL[1];
            _NC_BUILD_LEAF("foo.example.com", san, NULL, leafDer, leafDerLen);
            chain[0] = leafDer; chainL[0] = leafDerLen;
            trust[0] = caDer; trustL[0] = caDerLen;
            SSF_ASSERT(SSFX509VerifyChain(chain, chainL, 1u, trust, trustL, 1u,
                                           "foo.example.com", 1800000000ull, &_utVErr) == true);
            _UT_VERR(OK, 0u);
        }

        /* Case 2: leaf SAN "evil.com" - outside permittedSubtrees -> reject. */
        {
            static const char *san[] = { "evil.com", NULL };
            static uint8_t leafDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t leafDerLen;
            const uint8_t *chain[1]; uint32_t chainL[1];
            const uint8_t *trust[1]; uint32_t trustL[1];
            _NC_BUILD_LEAF("evil.com", san, NULL, leafDer, leafDerLen);
            chain[0] = leafDer; chainL[0] = leafDerLen;
            trust[0] = caDer; trustL[0] = caDerLen;
            SSF_ASSERT(SSFX509VerifyChain(chain, chainL, 1u, trust, trustL, 1u,
                                           "evil.com", 1800000000ull, &_utVErr) == false);
            _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
        }

        /* Case 3: leaf SAN "banned.example.com" - explicitly excluded -> reject. */
        {
            static const char *san[] = { "banned.example.com", NULL };
            static uint8_t leafDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t leafDerLen;
            const uint8_t *chain[1]; uint32_t chainL[1];
            const uint8_t *trust[1]; uint32_t trustL[1];
            _NC_BUILD_LEAF("banned.example.com", san, NULL, leafDer, leafDerLen);
            chain[0] = leafDer; chainL[0] = leafDerLen;
            trust[0] = caDer; trustL[0] = caDerLen;
            SSF_ASSERT(SSFX509VerifyChain(chain, chainL, 1u, trust, trustL, 1u,
                                           "banned.example.com", 1800000000ull, &_utVErr) == false);
            _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
        }

        /* Case 4: leaf with sub-label of an excluded name -> also excluded. */
        {
            static const char *san[] = { "sub.banned.example.com", NULL };
            static uint8_t leafDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t leafDerLen;
            const uint8_t *chain[1]; uint32_t chainL[1];
            const uint8_t *trust[1]; uint32_t trustL[1];
            _NC_BUILD_LEAF("sub.banned.example.com", san, NULL, leafDer, leafDerLen);
            chain[0] = leafDer; chainL[0] = leafDerLen;
            trust[0] = caDer; trustL[0] = caDerLen;
            SSF_ASSERT(SSFX509VerifyChain(chain, chainL, 1u, trust, trustL, 1u,
                                           "sub.banned.example.com", 1800000000ull,
                                               &_utVErr) == false);
            _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
        }

        /* Case 5: exact match of permitted name (not a sub-label) -> accept. */
        {
            static const char *san[] = { "example.com", NULL };
            static uint8_t leafDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t leafDerLen;
            const uint8_t *chain[1]; uint32_t chainL[1];
            const uint8_t *trust[1]; uint32_t trustL[1];
            _NC_BUILD_LEAF("example.com", san, NULL, leafDer, leafDerLen);
            chain[0] = leafDer; chainL[0] = leafDerLen;
            trust[0] = caDer; trustL[0] = caDerLen;
            SSF_ASSERT(SSFX509VerifyChain(chain, chainL, 1u, trust, trustL, 1u,
                                           "example.com", 1800000000ull, &_utVErr) == true);
            _UT_VERR(OK, 0u);
        }

        /* Case 6: non-boundary suffix - "notexample.com" must NOT match "example.com". */
        {
            static const char *san[] = { "notexample.com", NULL };
            static uint8_t leafDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t leafDerLen;
            const uint8_t *chain[1]; uint32_t chainL[1];
            const uint8_t *trust[1]; uint32_t trustL[1];
            _NC_BUILD_LEAF("notexample.com", san, NULL, leafDer, leafDerLen);
            chain[0] = leafDer; chainL[0] = leafDerLen;
            trust[0] = caDer; trustL[0] = caDerLen;
            SSF_ASSERT(SSFX509VerifyChain(chain, chainL, 1u, trust, trustL, 1u,
                                           "notexample.com", 1800000000ull, &_utVErr) == false);
            _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
        }

        /* Case 7: iPAddress SAN inside permitted 10.0.0.0/8 -> accept. */
        {
            static const uint8_t ipBytes[] = { 10u, 5u, 6u, 7u };
            static const uint8_t *ips[] = { ipBytes, NULL };
            /* The leaf uses an iPAddress SAN and the IP string as hostname */
            static uint8_t leafDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t leafDerLen;
            const uint8_t *chain[1]; uint32_t chainL[1];
            const uint8_t *trust[1]; uint32_t trustL[1];
            _NC_BUILD_LEAF("10.5.6.7", NULL, ips, leafDer, leafDerLen);
            chain[0] = leafDer; chainL[0] = leafDerLen;
            trust[0] = caDer; trustL[0] = caDerLen;
            SSF_ASSERT(SSFX509VerifyChain(chain, chainL, 1u, trust, trustL, 1u,
                                           "10.5.6.7", 1800000000ull, &_utVErr) == true);
            _UT_VERR(OK, 0u);
        }

        /* Case 8: iPAddress SAN outside permitted 10.0.0.0/8 -> reject. */
        {
            static const uint8_t ipBytes[] = { 192u, 168u, 1u, 1u };
            static const uint8_t *ips[] = { ipBytes, NULL };
            static uint8_t leafDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t leafDerLen;
            const uint8_t *chain[1]; uint32_t chainL[1];
            const uint8_t *trust[1]; uint32_t trustL[1];
            _NC_BUILD_LEAF("192.168.1.1", NULL, ips, leafDer, leafDerLen);
            chain[0] = leafDer; chainL[0] = leafDerLen;
            trust[0] = caDer; trustL[0] = caDerLen;
            SSF_ASSERT(SSFX509VerifyChain(chain, chainL, 1u, trust, trustL, 1u,
                                           "192.168.1.1", 1800000000ull, &_utVErr) == false);
            _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
        }

        /* Case 9: mixed SANs, DNS permitted but IP not -> reject (every SAN must pass) */
        {
            static const char *san[] = { "foo.example.com", NULL };
            static const uint8_t badIp[] = { 192u, 168u, 1u, 1u };
            static const uint8_t *ips[] = { badIp, NULL };
            static uint8_t leafDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t leafDerLen;
            const uint8_t *chain[1]; uint32_t chainL[1];
            const uint8_t *trust[1]; uint32_t trustL[1];
            _NC_BUILD_LEAF("foo.example.com", san, ips, leafDer, leafDerLen);
            chain[0] = leafDer; chainL[0] = leafDerLen;
            trust[0] = caDer; trustL[0] = caDerLen;
            SSF_ASSERT(SSFX509VerifyChain(chain, chainL, 1u, trust, trustL, 1u,
                                           "foo.example.com", 1800000000ull, &_utVErr) == false);
            _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
        }

        #undef _NC_BUILD_LEAF
    }

    /* ---- Duplicate Extension Detection (RFC 5280 4.2): BC plus raw BC must not parse ---- */
    {
        /* id-ce-basicConstraints: 2.5.29.19 */
        static const uint8_t _bcOid[] = { 0x55u, 0x1Du, 0x13u };
        /* id-ce-keyUsage: 2.5.29.15 */
        static const uint8_t _kuOid[] = { 0x55u, 0x1Du, 0x0Fu };
        /* id-ce-subjectAltName: 2.5.29.17 */
        static const uint8_t _sanOid[] = { 0x55u, 0x1Du, 0x11u };

        /* Minimal empty BasicConstraints value: OCTET STRING content is an empty SEQUENCE. */
        static const uint8_t _bcEmptyVal[] = { 0x30u, 0x00u };
        /* Minimal Key Usage value: BIT STRING with unused=0 and one zero byte. */
        static const uint8_t _kuVal[] = { 0x03u, 0x02u, 0x00u, 0x00u };
        /* Minimal SAN value: SEQUENCE containing one [2] IMPLICIT IA5String "x". */
        static const uint8_t _sanVal[] = { 0x30u, 0x03u, 0x82u, 0x01u, 0x78u };

        static uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t serial[] = { 0x77u };

        memset(privKey, 0, sizeof(privKey));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, privKey, sizeof(privKey),
                                   pubKey, sizeof(pubKey), &pubKeyLen) == true);

        /* Helper macro: primary ext plus raw duplicate must fail SSFX509Parse (BC, KU, SAN) */
        #define _DUP_EXT_EXPECT_REJECT(_configure) do { \
            static SSFX509GenParams_t p; \
            static uint8_t tbsDer[512]; \
            uint32_t tbsLen; \
            uint8_t tbsHash[32]; \
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE]; \
            size_t sigLen; \
            static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE]; \
            uint32_t certDerLen; \
            static SSFX509Cert_t parsed; \
            memset(&p, 0, sizeof(p)); \
            p.pathLenConstraint = -1; \
            p.version = 2u; \
            p.serial = serial; \
            p.serialLen = sizeof(serial); \
            p.sigAlgOidRaw = _utSigAlgOid; \
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid); \
            p.issuer.cn = "dup.test"; \
            p.subject.cn = "dup.test"; \
            p.notBefore = 1700000000ull; \
            p.notAfter = 2000000000ull; \
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid; \
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid); \
            p.ecCurveOidRaw = _utCurveOid; \
            p.ecCurveOidRawLen = sizeof(_utCurveOid); \
            p.pubKey = pubKey; \
            p.pubKeyLen = (uint32_t)pubKeyLen; \
            _configure(&p); \
            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen); \
            SSF_ASSERT(tbsLen > 0u); \
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash)); \
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, privKey, _UT_PRIV_LEN, tbsHash, 32, \
                                        sig, sizeof(sig), &sigLen) == true); \
            (void)SSFX509EncodeCert(certDer, sizeof(certDer), &p, sig, \
                                            (uint32_t)sigLen, &certDerLen); \
            SSF_ASSERT(certDerLen > 0u); \
            SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == false); \
        } while (0)

        /* Duplicate BasicConstraints: addBasicConstraints=true + rawExt at BC OID. */
        #define _CFG_DUP_BC(pp) do { \
            (pp)->addBasicConstraints = true; \
            (pp)->isCA = false; \
            (pp)->addRawExt = true; \
            (pp)->rawExtOid = _bcOid; \
            (pp)->rawExtOidLen = sizeof(_bcOid); \
            (pp)->rawExtValue = _bcEmptyVal; \
            (pp)->rawExtValueLen = sizeof(_bcEmptyVal); \
            (pp)->rawExtCritical = true; \
        } while (0)
        _DUP_EXT_EXPECT_REJECT(_CFG_DUP_BC);
        #undef _CFG_DUP_BC

        /* Duplicate KeyUsage: addKeyUsage=true + rawExt at KU OID. */
        #define _CFG_DUP_KU(pp) do { \
            (pp)->addKeyUsage = true; \
            (pp)->keyUsageBits = SSF_X509_KU_DIGITAL_SIGNATURE; \
            (pp)->addRawExt = true; \
            (pp)->rawExtOid = _kuOid; \
            (pp)->rawExtOidLen = sizeof(_kuOid); \
            (pp)->rawExtValue = _kuVal; \
            (pp)->rawExtValueLen = sizeof(_kuVal); \
            (pp)->rawExtCritical = true; \
        } while (0)
        _DUP_EXT_EXPECT_REJECT(_CFG_DUP_KU);
        #undef _CFG_DUP_KU

        /* Duplicate SubjectAltName: sanDNSNames populated + rawExt at SAN OID. */
        #define _CFG_DUP_SAN(pp) do { \
            static const char *sanList[] = { "dup.test", NULL }; \
            (pp)->sanDNSNames = sanList; \
            (pp)->addRawExt = true; \
            (pp)->rawExtOid = _sanOid; \
            (pp)->rawExtOidLen = sizeof(_sanOid); \
            (pp)->rawExtValue = _sanVal; \
            (pp)->rawExtValueLen = sizeof(_sanVal); \
            (pp)->rawExtCritical = false; \
        } while (0)
        _DUP_EXT_EXPECT_REJECT(_CFG_DUP_SAN);
        #undef _CFG_DUP_SAN

        /* Positive control: the same raw extension alone (no primary BC) parses */
        {
            static SSFX509GenParams_t p;
            static uint8_t tbsDer[512];
            uint32_t tbsLen;
            uint8_t tbsHash[32];
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
            size_t sigLen;
            static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t certDerLen;
            static SSFX509Cert_t parsed;

            memset(&p, 0, sizeof(p));
            p.pathLenConstraint = -1;
            p.version = 2u;
            p.serial = serial;
            p.serialLen = sizeof(serial);
            p.sigAlgOidRaw = _utSigAlgOid;
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            p.issuer.cn = "dup.test";
            p.subject.cn = "dup.test";
            p.notBefore = 1700000000ull;
            p.notAfter = 2000000000ull;
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            p.ecCurveOidRaw = _utCurveOid;
            p.ecCurveOidRawLen = sizeof(_utCurveOid);
            p.pubKey = pubKey;
            p.pubKeyLen = (uint32_t)pubKeyLen;
            /* Only the rawExt carrying BC - no duplicate. */
            p.addRawExt = true;
            p.rawExtOid = _bcOid;
            p.rawExtOidLen = sizeof(_bcOid);
            p.rawExtValue = _bcEmptyVal;
            p.rawExtValueLen = sizeof(_bcEmptyVal);
            p.rawExtCritical = true;

            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen);
            SSF_ASSERT(tbsLen > 0u);
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, privKey, _UT_PRIV_LEN, tbsHash, 32, sig,
                                       sizeof(sig), &sigLen) == true);
            (void)SSFX509EncodeCert(certDer, sizeof(certDer), &p, sig, (uint32_t)sigLen,
             &certDerLen);
            SSF_ASSERT(certDerLen > 0u);

            /* Single-extension cert must parse. */
            SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == true);
            SSF_ASSERT(parsed.extsLen == 1u);
        }

        #undef _DUP_EXT_EXPECT_REJECT
    }

    /* ---- Serial Number Validation (RFC 5280 4.1.2.2): non-negative, <= 20 octets ---- */
    {
        static uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;

        memset(privKey, 0, sizeof(privKey));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, privKey, sizeof(privKey),
                                   pubKey, sizeof(pubKey), &pubKeyLen) == true);

        /* Helper macro: build a cert with the given serial, expect the given parse result */
        #define _SERIAL_CASE(_serial, _serialLen, _expect) do { \
            static SSFX509GenParams_t p; \
            static uint8_t tbsDer[512]; \
            uint32_t tbsLen; \
            uint8_t tbsHash[32]; \
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE]; \
            size_t sigLen; \
            static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE]; \
            uint32_t certDerLen; \
            static SSFX509Cert_t parsed; \
            memset(&p, 0, sizeof(p)); \
            p.pathLenConstraint = -1; \
            p.version = 2u; \
            p.serial = (_serial); \
            p.serialLen = (_serialLen); \
            p.sigAlgOidRaw = _utSigAlgOid; \
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid); \
            p.issuer.cn = "serial.test"; \
            p.subject.cn = "serial.test"; \
            p.notBefore = 1700000000ull; \
            p.notAfter = 2000000000ull; \
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid; \
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid); \
            p.ecCurveOidRaw = _utCurveOid; \
            p.ecCurveOidRawLen = sizeof(_utCurveOid); \
            p.pubKey = pubKey; \
            p.pubKeyLen = (uint32_t)pubKeyLen; \
            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen); \
            SSF_ASSERT(tbsLen > 0u); \
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash)); \
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, privKey, _UT_PRIV_LEN, tbsHash, 32, \
                                        sig, sizeof(sig), &sigLen) == true); \
            (void)SSFX509EncodeCert(certDer, sizeof(certDer), &p, sig, \
                                            (uint32_t)sigLen, &certDerLen); \
            SSF_ASSERT(certDerLen > 0u); \
            SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == (_expect)); \
        } while (0)

        /* Case 1: typical 1-byte positive serial -> accept (baseline). */
        {
            static const uint8_t s[] = { 0x2Au };
            _SERIAL_CASE(s, sizeof(s), true);
        }

        /* Case 2: maximum conforming length of 20 octets, first byte < 0x80 -> accept */
        {
            static const uint8_t s[20] = {
                0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u,
                0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, 0x10u,
                0x11u, 0x12u, 0x13u, 0x14u
            };
            _SERIAL_CASE(s, sizeof(s), true);
        }

        /* Case 3: zero serial; CAs must not emit it but verifiers should accept it -> accept */
        {
            static const uint8_t s[] = { 0x00u };
            _SERIAL_CASE(s, sizeof(s), true);
        }

        /* Case 4: 21-octet serial -> reject */
        {
            static const uint8_t s[21] = {
                0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u,
                0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, 0x10u,
                0x11u, 0x12u, 0x13u, 0x14u, 0x15u
            };
            _SERIAL_CASE(s, sizeof(s), false);
        }

        /* Case 5: high-bit serial is unsigned; the generator adds 0x00 (AUDIT ASN1-6) */
        {
            static const uint8_t s[] = { 0x80u };
            _SERIAL_CASE(s, sizeof(s), true);
        }

        /* Case 6: multi-byte high-bit serial: likewise written as a positive INTEGER. */
        {
            static const uint8_t s[] = { 0xFFu, 0x01u, 0x02u };
            _SERIAL_CASE(s, sizeof(s), true);
        }

        /* Case 7: 20 bytes {0x00, 0x80, 0x01, ...}: the leading 0x00 keeps it positive -> accept */
        {
            static const uint8_t s[20] = {
                0x00u, 0x80u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u,
                0x07u, 0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu,
                0x0Fu, 0x10u, 0x11u, 0x12u
            };
            _SERIAL_CASE(s, sizeof(s), true);
        }

        #undef _SERIAL_CASE

        /* Case 8: negative serial on the wire (patched, AUDIT ASN1-6) -> reject */
        {
            static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            static uint8_t fakeSig[64];
            static const uint8_t ser1[] = { 0x02u, 0x01u, 0x01u };
            static const uint8_t ser3[] = { 0x02u, 0x03u, 0x01u, 0x01u, 0x02u };
            uint8_t s1[] = { 0x01u };
            uint8_t s3[] = { 0x01u, 0x01u, 0x02u };
            static SSFX509GenParams_t p;
            static SSFX509Cert_t parsed;
            uint32_t certDerLen;
            uint32_t at;

            memset(fakeSig, 0x55u, sizeof(fakeSig));
            _utGenBaseParams(&p, s1, pubKey, (uint32_t)pubKeyLen);
            SSF_ASSERT(SSFX509EncodeCert(certDer, sizeof(certDer), &p, fakeSig, sizeof(fakeSig),
                                         &certDerLen) == true);
            SSF_ASSERT(_utFind(certDer, certDerLen, ser1, sizeof(ser1), &at) == true);
            certDer[at + 2u] = 0x80u;
            SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == false);
            _utGenBaseParams(&p, s3, pubKey, (uint32_t)pubKeyLen);
            p.serialLen = sizeof(s3);
            SSF_ASSERT(SSFX509EncodeCert(certDer, sizeof(certDer), &p, fakeSig, sizeof(fakeSig),
                                         &certDerLen) == true);
            SSF_ASSERT(_utFind(certDer, certDerLen, ser3, sizeof(ser3), &at) == true);
            certDer[at + 2u] = 0xFFu;
            SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == false);
        }
    }

    /* ---- Wildcard SANs (RFC 6125 6.4.3, CA/B BR 3.2.2.6), including *.com rejection ---- */
    {
        static uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t serial[] = { 0x33u };

        memset(privKey, 0, sizeof(privKey));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, privKey, sizeof(privKey),
                                   pubKey, sizeof(pubKey), &pubKeyLen) == true);

        /* Helper: self-signed cert with wildcard SAN, VerifyChain(hostname) as expected */
        #define _WC_CASE(_sanDNSName, _hostname, _expect, _code, _idx) do { \
            static SSFX509GenParams_t p; \
            static uint8_t tbsDer[512]; \
            uint32_t tbsLen; \
            uint8_t tbsHash[32]; \
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE]; \
            size_t sigLen; \
            static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE]; \
            uint32_t certDerLen; \
            const char *sanList[] = { (_sanDNSName), NULL }; \
            const uint8_t *chain[1]; uint32_t chainL[1]; \
            const uint8_t *trust[1]; uint32_t trustL[1]; \
            memset(&p, 0, sizeof(p)); \
            p.pathLenConstraint = -1; \
            p.version = 2u; \
            p.serial = serial; \
            p.serialLen = sizeof(serial); \
            p.sigAlgOidRaw = _utSigAlgOid; \
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid); \
            p.issuer.cn = "wildcard.test"; \
            p.subject.cn = "wildcard.test"; \
            p.notBefore = 1700000000ull; \
            p.notAfter = 2000000000ull; \
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid; \
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid); \
            p.ecCurveOidRaw = _utCurveOid; \
            p.ecCurveOidRawLen = sizeof(_utCurveOid); \
            p.pubKey = pubKey; \
            p.pubKeyLen = (uint32_t)pubKeyLen; \
            p.sanDNSNames = sanList; \
            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen); \
            SSF_ASSERT(tbsLen > 0u); \
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash)); \
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, privKey, _UT_PRIV_LEN, tbsHash, 32, \
                                        sig, sizeof(sig), &sigLen) == true); \
            (void)SSFX509EncodeCert(certDer, sizeof(certDer), &p, sig, \
                                            (uint32_t)sigLen, &certDerLen); \
            SSF_ASSERT(certDerLen > 0u); \
            chain[0] = certDer; chainL[0] = certDerLen; \
            trust[0] = certDer; trustL[0] = certDerLen; \
            SSF_ASSERT(SSFX509VerifyChain(chain, chainL, 1u, trust, trustL, 1u, \
                                           (_hostname), 1800000000ull, &_utVErr) == (_expect)); \
            _UT_VERR(_code, _idx); \
        } while (0)

        /* Positive: standard third-level wildcard. */
        _WC_CASE("*.example.com", "foo.example.com", true, OK, 0u);

        /* Positive: case-insensitive match. */
        _WC_CASE("*.example.com", "FOO.ExAmPlE.com", true, OK, 0u);

        /* Negative: wildcard does not match the apex (RFC 6125 label-count rule 2). */
        _WC_CASE("*.example.com", "example.com", false, ERR_HOSTNAME, 0u);

        /* Negative: wildcard matches exactly one label, not two. */
        _WC_CASE("*.example.com", "a.b.example.com", false, ERR_HOSTNAME, 0u);

        /* Negative: different domain entirely. */
        _WC_CASE("*.example.com", "example.org", false, ERR_HOSTNAME, 0u);

        /* Negative: suffix overlap without label boundary. */
        _WC_CASE("*.example.com", "fooexample.com", false, ERR_HOSTNAME, 0u);

        /* Negative: label-count floor - *.com must NOT match foo.com (BR Sec. 3.2.2.6). */
        _WC_CASE("*.com", "foo.com", false, ERR_HOSTNAME, 0u);

        /* Negative: label-count floor - *.net must NOT match anything.net. */
        _WC_CASE("*.net", "example.net", false, ERR_HOSTNAME, 0u);

        /* Negative: label-count floor - *.org must NOT match bar.org. */
        _WC_CASE("*.org", "bar.org", false, ERR_HOSTNAME, 0u);

        /* Positive: 4th-level wildcard - base "sub.example.com" has a dot, allowed. */
        _WC_CASE("*.sub.example.com", "foo.sub.example.com", true, OK, 0u);

        /* Negative: partial-label wildcard; the leftmost label must be exactly "*" */
        _WC_CASE("foo*.example.com", "foobar.example.com", false, ERR_HOSTNAME, 0u);

        /* Negative: wildcard not in leftmost position - "foo.*.example.com" is invalid. */
        _WC_CASE("foo.*.example.com", "foo.bar.example.com", false, ERR_HOSTNAME, 0u);

        /* Known limitation: "*.co.uk" matches "foo.co.uk" (no Public Suffix List) */

        #undef _WC_CASE
    }

    /* ---- AKID/SKID with RFC 7093 SHA-2 keyIdentifier sizes round-trip at boundary lengths ---- */
    {
        static uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t serial[] = { 0x44u };
        uint32_t idx;
        /* KeyIdentifier payloads filled with a deterministic pattern for per-byte comparison */
        static uint8_t kidBuf[64];

        for (idx = 0; idx < sizeof(kidBuf); idx++)
        {
            kidBuf[idx] = (uint8_t)((idx * 7u) ^ 0xA5u);
        }

        memset(privKey, 0, sizeof(privKey));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, privKey, sizeof(privKey),
                                   pubKey, sizeof(pubKey), &pubKeyLen) == true);

        /* Round-trip AKID/SKID of the given length (20/32/48/64: SHA-1/256/384/512 identifiers) */
        #define _KID_ROUND_TRIP(_kidLen) do { \
            static SSFX509GenParams_t p; \
            static uint8_t tbsDer[512]; \
            uint32_t tbsLen; \
            uint8_t tbsHash[32]; \
            static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE]; \
            size_t sigLen; \
            static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE]; \
            uint32_t certDerLen; \
            static SSFX509Cert_t parsed; \
            memset(&p, 0, sizeof(p)); \
            p.pathLenConstraint = -1; \
            p.version = 2u; \
            p.serial = serial; \
            p.serialLen = sizeof(serial); \
            p.sigAlgOidRaw = _utSigAlgOid; \
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid); \
            p.issuer.cn = "kid.test"; \
            p.subject.cn = "kid.test"; \
            p.notBefore = 1700000000ull; \
            p.notAfter = 2000000000ull; \
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid; \
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid); \
            p.ecCurveOidRaw = _utCurveOid; \
            p.ecCurveOidRawLen = sizeof(_utCurveOid); \
            p.pubKey = pubKey; \
            p.pubKeyLen = (uint32_t)pubKeyLen; \
            p.skid = kidBuf; \
            p.skidLen = (_kidLen); \
            p.akid = kidBuf; \
            p.akidLen = (_kidLen); \
            (void)SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen); \
            SSF_ASSERT(tbsLen > 0u); \
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash)); \
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, privKey, _UT_PRIV_LEN, tbsHash, 32, \
                                        sig, sizeof(sig), &sigLen) == true); \
            (void)SSFX509EncodeCert(certDer, sizeof(certDer), &p, sig, \
                                            (uint32_t)sigLen, &certDerLen); \
            SSF_ASSERT(certDerLen > 0u); \
            SSF_ASSERT(SSFX509Parse(certDer, certDerLen, &parsed) == true); \
            SSF_ASSERT(parsed.skidLen == (_kidLen)); \
            SSF_ASSERT(memcmp(parsed.skid, kidBuf, (_kidLen)) == 0); \
            SSF_ASSERT(parsed.akidLen == (_kidLen)); \
            SSF_ASSERT(memcmp(parsed.akid, kidBuf, (_kidLen)) == 0); \
        } while (0)

        /* 20 bytes - SHA-1 baseline (RFC 5280 Sec. 4.2.1.2 default). Regression guard. */
        _KID_ROUND_TRIP(20u);

        /* 30 bytes - just under the old 32-byte buffer ceiling. Used to work. */
        _KID_ROUND_TRIP(30u);

        /* 32 bytes: SHA-256 keyIdentifier (RFC 7093) */
        _KID_ROUND_TRIP(32u);

        /* 48 bytes - SHA-384 keyIdentifier. Old AKID: 16-byte stack overflow. */
        _KID_ROUND_TRIP(48u);

        /* 64 bytes: SHA-512 keyIdentifier, the maximum supported */
        _KID_ROUND_TRIP(64u);

        /* Over-limit: 65-byte AKID/SKID. Encoder must refuse (return 0) rather than overflow. */
        {
            static SSFX509GenParams_t p;
            static uint8_t tbsDer[512];
            memset(&p, 0, sizeof(p));
            p.pathLenConstraint = -1;
            p.version = 2u;
            p.serial = serial;
            p.serialLen = sizeof(serial);
            p.sigAlgOidRaw = _utSigAlgOid;
            p.sigAlgOidRawLen = sizeof(_utSigAlgOid);
            p.issuer.cn = "kid.test";
            p.subject.cn = "kid.test";
            p.notBefore = 1700000000ull;
            p.notAfter = 2000000000ull;
            p.pubKeyAlgOidRaw = _utPubKeyAlgOid;
            p.pubKeyAlgOidRawLen = sizeof(_utPubKeyAlgOid);
            p.ecCurveOidRaw = _utCurveOid;
            p.ecCurveOidRawLen = sizeof(_utCurveOid);
            p.pubKey = pubKey;
            p.pubKeyLen = (uint32_t)pubKeyLen;
            p.akid = kidBuf;
            p.akidLen = 65u;  /* > _UT_KID_MAX */
            SSF_ASSERT(SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &_utScratchLen) == false);

            /* Same for SKID alone. */
            p.akid = NULL;
            p.akidLen = 0u;
            p.skid = kidBuf;
            p.skidLen = 65u;
            SSF_ASSERT(SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &_utScratchLen) == false);
        }

        #undef _KID_ROUND_TRIP
    }

    /* ---- Real-world Entrust.net 2048 root with a TeletexString OU (RFC 5280 4.1.2.4) ---- */
    {
        static const uint8_t entrust2048Der[] = {
            0x30, 0x82, 0x04, 0x2a, 0x30, 0x82, 0x03, 0x12, 0xa0, 0x03, 0x02, 0x01,
            0x02, 0x02, 0x04, 0x38, 0x63, 0xde, 0xf8, 0x30, 0x0d, 0x06, 0x09, 0x2a,
            0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x81,
            0xb4, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0b,
            0x45, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74, 0x31,
            0x40, 0x30, 0x3e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x14, 0x37, 0x77, 0x77,
            0x77, 0x2e, 0x65, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65,
            0x74, 0x2f, 0x43, 0x50, 0x53, 0x5f, 0x32, 0x30, 0x34, 0x38, 0x20, 0x69,
            0x6e, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x20, 0x62, 0x79, 0x20, 0x72, 0x65,
            0x66, 0x2e, 0x20, 0x28, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x73, 0x20, 0x6c,
            0x69, 0x61, 0x62, 0x2e, 0x29, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55,
            0x04, 0x0b, 0x13, 0x1c, 0x28, 0x63, 0x29, 0x20, 0x31, 0x39, 0x39, 0x39,
            0x20, 0x45, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74,
            0x20, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x31, 0x33, 0x30, 0x31,
            0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x2a, 0x45, 0x6e, 0x74, 0x72, 0x75,
            0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69,
            0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74,
            0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x28, 0x32, 0x30, 0x34, 0x38,
            0x29, 0x30, 0x1e, 0x17, 0x0d, 0x39, 0x39, 0x31, 0x32, 0x32, 0x34, 0x31,
            0x37, 0x35, 0x30, 0x35, 0x31, 0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x37,
            0x32, 0x34, 0x31, 0x34, 0x31, 0x35, 0x31, 0x32, 0x5a, 0x30, 0x81, 0xb4,
            0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0b, 0x45,
            0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74, 0x31, 0x40,
            0x30, 0x3e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x14, 0x37, 0x77, 0x77, 0x77,
            0x2e, 0x65, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74,
            0x2f, 0x43, 0x50, 0x53, 0x5f, 0x32, 0x30, 0x34, 0x38, 0x20, 0x69, 0x6e,
            0x63, 0x6f, 0x72, 0x70, 0x2e, 0x20, 0x62, 0x79, 0x20, 0x72, 0x65, 0x66,
            0x2e, 0x20, 0x28, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x73, 0x20, 0x6c, 0x69,
            0x61, 0x62, 0x2e, 0x29, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04,
            0x0b, 0x13, 0x1c, 0x28, 0x63, 0x29, 0x20, 0x31, 0x39, 0x39, 0x39, 0x20,
            0x45, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74, 0x20,
            0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x31, 0x33, 0x30, 0x31, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x13, 0x2a, 0x45, 0x6e, 0x74, 0x72, 0x75, 0x73,
            0x74, 0x2e, 0x6e, 0x65, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66,
            0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68,
            0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x28, 0x32, 0x30, 0x34, 0x38, 0x29,
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xad, 0x4d, 0x4b,
            0xa9, 0x12, 0x86, 0xb2, 0xea, 0xa3, 0x20, 0x07, 0x15, 0x16, 0x64, 0x2a,
            0x2b, 0x4b, 0xd1, 0xbf, 0x0b, 0x4a, 0x4d, 0x8e, 0xed, 0x80, 0x76, 0xa5,
            0x67, 0xb7, 0x78, 0x40, 0xc0, 0x73, 0x42, 0xc8, 0x68, 0xc0, 0xdb, 0x53,
            0x2b, 0xdd, 0x5e, 0xb8, 0x76, 0x98, 0x35, 0x93, 0x8b, 0x1a, 0x9d, 0x7c,
            0x13, 0x3a, 0x0e, 0x1f, 0x5b, 0xb7, 0x1e, 0xcf, 0xe5, 0x24, 0x14, 0x1e,
            0xb1, 0x81, 0xa9, 0x8d, 0x7d, 0xb8, 0xcc, 0x6b, 0x4b, 0x03, 0xf1, 0x02,
            0x0c, 0xdc, 0xab, 0xa5, 0x40, 0x24, 0x00, 0x7f, 0x74, 0x94, 0xa1, 0x9d,
            0x08, 0x29, 0xb3, 0x88, 0x0b, 0xf5, 0x87, 0x77, 0x9d, 0x55, 0xcd, 0xe4,
            0xc3, 0x7e, 0xd7, 0x6a, 0x64, 0xab, 0x85, 0x14, 0x86, 0x95, 0x5b, 0x97,
            0x32, 0x50, 0x6f, 0x3d, 0xc8, 0xba, 0x66, 0x0c, 0xe3, 0xfc, 0xbd, 0xb8,
            0x49, 0xc1, 0x76, 0x89, 0x49, 0x19, 0xfd, 0xc0, 0xa8, 0xbd, 0x89, 0xa3,
            0x67, 0x2f, 0xc6, 0x9f, 0xbc, 0x71, 0x19, 0x60, 0xb8, 0x2d, 0xe9, 0x2c,
            0xc9, 0x90, 0x76, 0x66, 0x7b, 0x94, 0xe2, 0xaf, 0x78, 0xd6, 0x65, 0x53,
            0x5d, 0x3c, 0xd6, 0x9c, 0xb2, 0xcf, 0x29, 0x03, 0xf9, 0x2f, 0xa4, 0x50,
            0xb2, 0xd4, 0x48, 0xce, 0x05, 0x32, 0x55, 0x8a, 0xfd, 0xb2, 0x64, 0x4c,
            0x0e, 0xe4, 0x98, 0x07, 0x75, 0xdb, 0x7f, 0xdf, 0xb9, 0x08, 0x55, 0x60,
            0x85, 0x30, 0x29, 0xf9, 0x7b, 0x48, 0xa4, 0x69, 0x86, 0xe3, 0x35, 0x3f,
            0x1e, 0x86, 0x5d, 0x7a, 0x7a, 0x15, 0xbd, 0xef, 0x00, 0x8e, 0x15, 0x22,
            0x54, 0x17, 0x00, 0x90, 0x26, 0x93, 0xbc, 0x0e, 0x49, 0x68, 0x91, 0xbf,
            0xf8, 0x47, 0xd3, 0x9d, 0x95, 0x42, 0xc1, 0x0e, 0x4d, 0xdf, 0x6f, 0x26,
            0xcf, 0xc3, 0x18, 0x21, 0x62, 0x66, 0x43, 0x70, 0xd6, 0xd5, 0xc0, 0x07,
            0xe1, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0e,
            0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
            0x01, 0x06, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
            0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55,
            0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x55, 0xe4, 0x81, 0xd1, 0x11, 0x80,
            0xbe, 0xd8, 0x89, 0xb9, 0x08, 0xa3, 0x31, 0xf9, 0xa1, 0x24, 0x09, 0x16,
            0xb9, 0x70, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x3b, 0x9b,
            0x8f, 0x56, 0x9b, 0x30, 0xe7, 0x53, 0x99, 0x7c, 0x7a, 0x79, 0xa7, 0x4d,
            0x97, 0xd7, 0x19, 0x95, 0x90, 0xfb, 0x06, 0x1f, 0xca, 0x33, 0x7c, 0x46,
            0x63, 0x8f, 0x96, 0x66, 0x24, 0xfa, 0x40, 0x1b, 0x21, 0x27, 0xca, 0xe6,
            0x72, 0x73, 0xf2, 0x4f, 0xfe, 0x31, 0x99, 0xfd, 0xc8, 0x0c, 0x4c, 0x68,
            0x53, 0xc6, 0x80, 0x82, 0x13, 0x98, 0xfa, 0xb6, 0xad, 0xda, 0x5d, 0x3d,
            0xf1, 0xce, 0x6e, 0xf6, 0x15, 0x11, 0x94, 0x82, 0x0c, 0xee, 0x3f, 0x95,
            0xaf, 0x11, 0xab, 0x0f, 0xd7, 0x2f, 0xde, 0x1f, 0x03, 0x8f, 0x57, 0x2c,
            0x1e, 0xc9, 0xbb, 0x9a, 0x1a, 0x44, 0x95, 0xeb, 0x18, 0x4f, 0xa6, 0x1f,
            0xcd, 0x7d, 0x57, 0x10, 0x2f, 0x9b, 0x04, 0x09, 0x5a, 0x84, 0xb5, 0x6e,
            0xd8, 0x1d, 0x3a, 0xe1, 0xd6, 0x9e, 0xd1, 0x6c, 0x79, 0x5e, 0x79, 0x1c,
            0x14, 0xc5, 0xe3, 0xd0, 0x4c, 0x93, 0x3b, 0x65, 0x3c, 0xed, 0xdf, 0x3d,
            0xbe, 0xa6, 0xe5, 0x95, 0x1a, 0xc3, 0xb5, 0x19, 0xc3, 0xbd, 0x5e, 0x5b,
            0xbb, 0xff, 0x23, 0xef, 0x68, 0x19, 0xcb, 0x12, 0x93, 0x27, 0x5c, 0x03,
            0x2d, 0x6f, 0x30, 0xd0, 0x1e, 0xb6, 0x1a, 0xac, 0xde, 0x5a, 0xf7, 0xd1,
            0xaa, 0xa8, 0x27, 0xa6, 0xfe, 0x79, 0x81, 0xc4, 0x79, 0x99, 0x33, 0x57,
            0xba, 0x12, 0xb0, 0xa9, 0xe0, 0x42, 0x6c, 0x93, 0xca, 0x56, 0xde, 0xfe,
            0x6d, 0x84, 0x0b, 0x08, 0x8b, 0x7e, 0x8d, 0xea, 0xd7, 0x98, 0x21, 0xc6,
            0xf3, 0xe7, 0x3c, 0x79, 0x2f, 0x5e, 0x9c, 0xd1, 0x4c, 0x15, 0x8d, 0xe1,
            0xec, 0x22, 0x37, 0xcc, 0x9a, 0x43, 0x0b, 0x97, 0xdc, 0x80, 0x90, 0x8d,
            0xb3, 0x67, 0x9b, 0x6f, 0x48, 0x08, 0x15, 0x56, 0xcf, 0xbf, 0xf1, 0x2b,
            0x7c, 0x5e, 0x9a, 0x76, 0xe9, 0x59, 0x90, 0xc5, 0x7c, 0x83, 0x35, 0x11,
            0x65, 0x51
        };
        static SSFX509Cert_t rootCert;

        SSF_ASSERT(SSFX509Parse(entrust2048Der, sizeof(entrust2048Der), &rootCert) == true);
        SSF_ASSERT(rootCert.subject.cn != NULL);
        SSF_ASSERT(rootCert.subject.cnLen == 42u);
        SSF_ASSERT(memcmp(rootCert.subject.cn,
                           "Entrust.net Certification Authority (2048)", 42) == 0);
        /* The TeletexString OU is retrieved too (the parser keeps the last of the two OUs) */
        SSF_ASSERT(rootCert.subject.ou != NULL);
    }

    /* ---- ecdsa-with-SHA256 over a P-384 key (RFC 5758 3.2): SSL.com Root CA ECC ---- */
    {
        static const uint8_t sslcomRootEccDer[] = {
            0x30, 0x82, 0x02, 0x8d, 0x30, 0x82, 0x02, 0x14, 0xa0, 0x03, 0x02, 0x01,
            0x02, 0x02, 0x08, 0x75, 0xe6, 0xdf, 0xcb, 0xc1, 0x68, 0x5b, 0xa8, 0x30,
            0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
            0x7c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
            0x55, 0x53, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
            0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
            0x55, 0x04, 0x07, 0x0c, 0x07, 0x48, 0x6f, 0x75, 0x73, 0x74, 0x6f, 0x6e,
            0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0f, 0x53,
            0x53, 0x4c, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61, 0x74, 0x69,
            0x6f, 0x6e, 0x31, 0x31, 0x30, 0x2f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
            0x28, 0x53, 0x53, 0x4c, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x52, 0x6f, 0x6f,
            0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
            0x69, 0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74,
            0x79, 0x20, 0x45, 0x43, 0x43, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30,
            0x32, 0x31, 0x32, 0x31, 0x38, 0x31, 0x34, 0x30, 0x33, 0x5a, 0x17, 0x0d,
            0x34, 0x31, 0x30, 0x32, 0x31, 0x32, 0x31, 0x38, 0x31, 0x34, 0x30, 0x33,
            0x5a, 0x30, 0x7c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
            0x13, 0x02, 0x55, 0x53, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04,
            0x08, 0x0c, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x10, 0x30, 0x0e,
            0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x07, 0x48, 0x6f, 0x75, 0x73, 0x74,
            0x6f, 0x6e, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
            0x0f, 0x53, 0x53, 0x4c, 0x20, 0x43, 0x6f, 0x72, 0x70, 0x6f, 0x72, 0x61,
            0x74, 0x69, 0x6f, 0x6e, 0x31, 0x31, 0x30, 0x2f, 0x06, 0x03, 0x55, 0x04,
            0x03, 0x0c, 0x28, 0x53, 0x53, 0x4c, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x52,
            0x6f, 0x6f, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
            0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72,
            0x69, 0x74, 0x79, 0x20, 0x45, 0x43, 0x43, 0x30, 0x76, 0x30, 0x10, 0x06,
            0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
            0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x45, 0x6e, 0xa9, 0x50, 0xc4,
            0xa6, 0x23, 0x36, 0x9e, 0x5f, 0x28, 0x8d, 0x17, 0xcb, 0x96, 0x22, 0x64,
            0x3f, 0xdc, 0x7a, 0x8e, 0x1d, 0xcc, 0x08, 0xb3, 0xa2, 0x71, 0x24, 0xba,
            0x8e, 0x49, 0xb9, 0x04, 0x1b, 0x47, 0x96, 0x58, 0xab, 0x2d, 0x95, 0xc8,
            0xed, 0x9e, 0x08, 0x35, 0xc8, 0x27, 0xeb, 0x89, 0x8c, 0x53, 0x58, 0xeb,
            0x62, 0x8a, 0xfe, 0xf0, 0x5b, 0x0f, 0x6b, 0x31, 0x52, 0x63, 0x41, 0x3b,
            0x89, 0xcd, 0xec, 0xec, 0xb6, 0x8d, 0x19, 0xd3, 0x34, 0x07, 0xdc, 0xbb,
            0xc6, 0x06, 0x7f, 0xc2, 0x45, 0x95, 0xec, 0xcb, 0x7f, 0xa8, 0x23, 0xe0,
            0x09, 0xe9, 0x81, 0xfa, 0xf3, 0x47, 0xd3, 0xa3, 0x63, 0x30, 0x61, 0x30,
            0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x82, 0xd1,
            0x85, 0x73, 0x30, 0xe7, 0x35, 0x04, 0xd3, 0x8e, 0x02, 0x92, 0xfb, 0xe5,
            0xa4, 0xd1, 0xc4, 0x21, 0xe8, 0xcd, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
            0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
            0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
            0x82, 0xd1, 0x85, 0x73, 0x30, 0xe7, 0x35, 0x04, 0xd3, 0x8e, 0x02, 0x92,
            0xfb, 0xe5, 0xa4, 0xd1, 0xc4, 0x21, 0xe8, 0xcd, 0x30, 0x0e, 0x06, 0x03,
            0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86,
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
            0x03, 0x67, 0x00, 0x30, 0x64, 0x02, 0x30, 0x6f, 0xe7, 0xeb, 0x59, 0x11,
            0xa4, 0x60, 0xcf, 0x61, 0xb0, 0x96, 0x7b, 0xed, 0x05, 0xf9, 0x2f, 0x13,
            0x91, 0xdc, 0xed, 0xe5, 0xfc, 0x50, 0x6b, 0x11, 0x46, 0x46, 0xb3, 0x1c,
            0x21, 0x00, 0x62, 0xbb, 0xbe, 0xc3, 0xe7, 0xe8, 0xcd, 0x07, 0x99, 0xf9,
            0x0d, 0x0b, 0x5d, 0x72, 0x3e, 0xc4, 0xaa, 0x02, 0x30, 0x1f, 0xbc, 0xba,
            0x0b, 0xe2, 0x30, 0x24, 0xfb, 0x7c, 0x6d, 0x80, 0x55, 0x0a, 0x99, 0x3e,
            0x80, 0x0d, 0x33, 0xe5, 0x66, 0xa3, 0xb3, 0xa3, 0xbb, 0xa5, 0xd5, 0x8b,
            0x8f, 0x09, 0x2c, 0xa6, 0x5d, 0x7e, 0xe2, 0xf0, 0x07, 0x08, 0x68, 0x6d,
            0xd2, 0x7c, 0x69, 0x6e, 0x5f, 0xdf, 0xe5, 0x6a, 0x65
        };
        static SSFX509Cert_t rootCert;

        SSF_ASSERT(SSFX509Parse(sslcomRootEccDer, sizeof(sslcomRootEccDer), &rootCert) == true);
        /* Confirm the cross-curve pairing: ecdsa-with-SHA256 sigAlg, P-384 key */
        SSF_ASSERT(SSFX509IsSigECDSASHA256(&rootCert) == true);
        SSF_ASSERT(SSFX509IsKeyP384(&rootCert) == true);

        /* Self-signed root: the curve comes from cert.ecCurveOidRaw (P-384), not the sigAlg OID */
#if SSF_EC_CONFIG_ENABLE_P384 == 1
        SSF_ASSERT(SSFX509VerifyCertSignature(&rootCert, &rootCert) == true);
#else
        /* AUDIT CFG-1: with P-384 compiled out the curve is unsupported; verify is false */
        SSF_ASSERT(SSFX509VerifyCertSignature(&rootCert, &rootCert) == false);
#endif
    }

    /* ---- Generation: measured size equals written size and the output re-parses ---- */
    {
        static const uint8_t rsaOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
        };
        static const uint8_t rsaSha256Oid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Bu
        };
        static const uint8_t rawOid[] = { 0x55u, 0x1Du, 0x20u };
        static const uint8_t rawVal[] = { 0x30u, 0x00u };
        static const uint8_t ncIp[] = { 10u, 0u, 0u, 0u, 255u, 0u, 0u, 0u };
        static const uint8_t *ncIps[] = { ncIp, NULL };
        static const char *ncDns[] = { "example.com", NULL };
        static uint8_t bigKey[560];
        static uint8_t kid[64];
        static uint8_t fakeSig[2000];
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE + 2048u];
        static char cn64[65];
        static char cn65[66];
        static char st128[129];
        static char sanBuf[SSF_X509_CONFIG_MAX_SAN_ENTRIES][251];
        static char san254[255];
        static const char *sanPtrs[SSF_X509_CONFIG_MAX_SAN_ENTRIES + 1u];
        static const char *sanOne[2];
        uint8_t serial[] = { 0x07u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        uint32_t i;
        uint32_t n;

        memset(bigKey, 0x5Au, sizeof(bigKey));
        memset(kid, 0xA5u, sizeof(kid));
        memset(fakeSig, 0x11u, sizeof(fakeSig));
        memset(cn64, 'c', 64u);
        cn64[64] = '\0';
        memset(cn65, 'c', 65u);
        cn65[65] = '\0';
        memset(st128, 's', 128u);
        st128[128] = '\0';
        memset(san254, 'x', 254u);
        san254[254] = '\0';
        sanOne[0] = san254;
        sanOne[1] = NULL;
        for (i = 0; i < SSF_X509_CONFIG_MAX_SAN_ENTRIES; i++)
        {
            memset(sanBuf[i], (int)('a' + (char)i), 250u);
            sanBuf[i][250] = '\0';
            sanPtrs[i] = sanBuf[i];
        }
        sanPtrs[SSF_X509_CONFIG_MAX_SAN_ENTRIES] = NULL;

        /* Baseline P-256 */
        _utGenBaseParams(&p, serial, bigKey, 65u);
        _utGenCheckConsistent(&p, fakeSig, 64u, out, sizeof(out), &parsed);

        /* COV-10: all extensions/DN set; every short buffer is refused with nothing past size */
        {
            static const uint8_t sanIp[] = { 192u, 168u, 1u, 1u };
            static const uint8_t *sanIps[] = { sanIp, NULL };
            static const char *sanDns[] = { "a.example.com", "b.example.com", NULL };
            static const char *ncExDns[] = { "bad.example.com", NULL };
            static const uint8_t ncExIp[] = { 10u, 1u, 0u, 0u, 255u, 255u, 0u, 0u };
            static const uint8_t *ncExIps[] = { ncExIp, NULL };
            static const uint8_t nullParams[] = { 0x05u, 0x00u };
            uint32_t full;
            uint32_t sz;
            uint32_t w;
            uint32_t g;
            uint8_t pass;

            for (pass = 0u; pass < 2u; pass++)
            {
                _utGenBaseParams(&p, serial, bigKey, (pass == 0u) ? 65u : 270u);
                p.issuer.o = "Org"; p.issuer.ou = "Unit"; p.issuer.c = "US";
                p.issuer.st = "State"; p.issuer.l = "City";
                p.subject = p.issuer;
                p.subject.cn = "leaf";
                p.isCA = true;
                p.pathLenConstraint = 2;
                p.addBasicConstraints = true;
                p.addKeyUsage = true;
                p.keyUsageBits = 0x0186u;
                p.addExtKeyUsage = true;
                p.ekuServerAuth = true;
                p.ekuClientAuth = true;
                p.ekuCodeSigning = true;
                p.sanDNSNames = sanDns;
                p.sanIPAddrs = sanIps;
                p.skid = kid; p.skidLen = 20u;
                p.akid = kid; p.akidLen = 20u;
                p.addRawExt = true;
                p.rawExtOid = rawOid; p.rawExtOidLen = sizeof(rawOid);
                p.rawExtValue = rawVal; p.rawExtValueLen = sizeof(rawVal);
                p.rawExtCritical = true;
                p.addNameConstraints = true;
                p.ncPermittedDNS = ncDns; p.ncPermittedIPs = ncIps;
                p.ncExcludedDNS = ncExDns; p.ncExcludedIPs = ncExIps;
                /* RSA-shaped pass? */
                if (pass == 1u)
                {
                    /* Yes, no curve OID, sha256WithRSA with explicit NULL parameters */
                    p.pubKeyAlgOidRaw = rsaOid; p.pubKeyAlgOidRawLen = sizeof(rsaOid);
                    p.ecCurveOidRaw = NULL; p.ecCurveOidRawLen = 0u;
                    p.sigAlgOidRaw = rsaSha256Oid; p.sigAlgOidRawLen = sizeof(rsaSha256Oid);
                    p.sigAlgParams = nullParams; p.sigAlgParamsLen = sizeof(nullParams);
                }
                _utGenCheckConsistent(&p, fakeSig, 64u, out, sizeof(out), &parsed);

                SSF_ASSERT(SSFX509EncodeTBS(NULL, 0u, &p, &full) == true);
                for (sz = 0u; sz < full; sz++)
                {
                    memset(out, 0xA5, full + 16u);
                    SSF_ASSERT(SSFX509EncodeTBS(out, sz, &p, &w) == false);
                    for (g = sz; g < (full + 16u); g++) SSF_ASSERT(out[g] == 0xA5u);
                }
                SSF_ASSERT(SSFX509EncodeCert(NULL, 0u, &p, fakeSig, 64u, &full) == true);
                for (sz = 0u; sz < full; sz++)
                {
                    memset(out, 0xA5, full + 16u);
                    SSF_ASSERT(SSFX509EncodeCert(out, sz, &p, fakeSig, 64u, &w) == false);
                    for (g = sz; g < (full + 16u); g++) SSF_ASSERT(out[g] == 0xA5u);
                }
            }

            /* A validity time past what X.509 time can carry is unencodable, both passes */
            _utGenBaseParams(&p, serial, bigKey, 65u);
            p.notAfter = UINT64_MAX;
            SSF_ASSERT(SSFX509EncodeTBS(NULL, 0u, &p, &w) == false);
            SSF_ASSERT(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, 64u, &w) == false);
            _utGenBaseParams(&p, serial, bigKey, 65u);
            p.notBefore = UINT64_MAX;
            SSF_ASSERT(SSFX509EncodeTBS(out, sizeof(out), &p, &w) == false);

            /* DN attributes past RFC 5280 bounds (C 2, ST/L 128, O/OU 64), NC dNSName > 253 */
            {
                static char over129[130];
                static char over254[255];
                static const char *ncLong[2];
                uint8_t f;

                memset(over129, 'z', 129u); over129[129] = '\0';
                memset(over254, 'z', 254u); over254[254] = '\0';
                for (f = 0u; f < 5u; f++)
                {
                    _utGenBaseParams(&p, serial, bigKey, 65u);
                    if (f == 0u) p.subject.c = "USA";
                    else if (f == 1u) p.subject.st = over129;
                    else if (f == 2u) p.subject.l = over129;
                    else if (f == 3u) p.subject.o = cn65;
                    else p.subject.ou = cn65;
                    SSF_ASSERT(SSFX509EncodeTBS(NULL, 0u, &p, &w) == false);
                    p.subject.c = "US";
                    p.subject.st = st128;
                    p.subject.l = st128;
                    p.subject.o = cn64;
                    p.subject.ou = cn64;
                    SSF_ASSERT(SSFX509EncodeTBS(NULL, 0u, &p, &w) == true);
                }
                _utGenBaseParams(&p, serial, bigKey, 65u);
                p.isCA = true;
                p.addBasicConstraints = true;
                p.addNameConstraints = true;
                ncLong[0] = over254; ncLong[1] = NULL;
                p.ncPermittedDNS = ncLong;
                SSF_ASSERT(SSFX509EncodeTBS(NULL, 0u, &p, &w) == false);
            }
        }

        /* RSA-4096 sized SubjectPublicKeyInfo and signature */
        _utGenBaseParams(&p, serial, bigKey, sizeof(bigKey));
        p.pubKeyAlgOidRaw = rsaOid;
        p.pubKeyAlgOidRawLen = sizeof(rsaOid);
        p.ecCurveOidRaw = NULL;
        p.ecCurveOidRawLen = 0u;
        p.sigAlgOidRaw = rsaSha256Oid;
        p.sigAlgOidRawLen = sizeof(rsaSha256Oid);
        _utGenCheckConsistent(&p, fakeSig, 512u, out, sizeof(out), &parsed);
        SSF_ASSERT(SSFX509IsKeyRSA(&parsed) == true);

        /* Every DN attribute at its RFC 5280 Appendix A upper bound */
        _utGenBaseParams(&p, serial, bigKey, 65u);
        p.subject.cn = cn64;
        p.subject.o = cn64;
        p.subject.ou = cn64;
        p.subject.c = "US";
        p.subject.st = st128;
        p.subject.l = st128;
        p.issuer = p.subject;
        _utGenCheckConsistent(&p, fakeSig, 64u, out, sizeof(out), &parsed);
        SSF_ASSERT((parsed.subject.cnLen == 64u) && (parsed.subject.stLen == 128u));
        SSF_ASSERT((parsed.issuer.lLen == 128u) && (parsed.issuer.cLen == 2u));

        /* Every extension at once, maximum SAN count, 64-byte key identifiers */
        _utGenBaseParams(&p, serial, bigKey, 65u);
        p.addBasicConstraints = true;
        p.isCA = true;
        p.pathLenConstraint = 3;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN | SSF_X509_KU_CRL_SIGN;
        p.addExtKeyUsage = true;
        p.ekuServerAuth = true;
        p.ekuClientAuth = true;
        p.sanDNSNames = sanPtrs;
        p.skid = kid;
        p.skidLen = sizeof(kid);
        p.akid = kid;
        p.akidLen = sizeof(kid);
        p.addRawExt = true;
        p.rawExtOid = rawOid;
        p.rawExtOidLen = sizeof(rawOid);
        p.rawExtValue = rawVal;
        p.rawExtValueLen = sizeof(rawVal);
        p.addNameConstraints = true;
        p.ncPermittedDNS = ncDns;
        p.ncPermittedIPs = ncIps;
        p.ncExcludedDNS = ncDns;
        _utGenCheckConsistent(&p, fakeSig, 64u, out, sizeof(out), &parsed);
        SSF_ASSERT(parsed.sanLen == SSF_X509_CONFIG_MAX_SAN_ENTRIES);
        SSF_ASSERT((parsed.skidLen == 64u) && (parsed.akidLen == 64u));
        SSF_ASSERT((parsed.permittedLen == 2u) && (parsed.excludedLen == 1u));
        SSF_ASSERT((parsed.pathLenConstraint == 3) && (parsed.isCA == true));
        SSF_ASSERT((parsed.ekuServerAuth == true) && (parsed.ekuClientAuth == true));

        /* DN attribute over its upper bound: both passes report failure */
        _utGenBaseParams(&p, serial, bigKey, 65u);
        p.subject.cn = cn65;
        SSF_ASSERT(SSFX509EncodeTBS(NULL, 0, &p, &_utScratchLen) == false);
        SSF_ASSERT(SSFX509EncodeTBS(out, sizeof(out), &p, &_utScratchLen) == false);

        /* dNSName over 253 octets: both passes report failure */
        _utGenBaseParams(&p, serial, bigKey, 65u);
        p.sanDNSNames = sanOne;
        SSF_ASSERT(SSFX509EncodeTBS(NULL, 0, &p, &_utScratchLen) == false);
        SSF_ASSERT(SSFX509EncodeTBS(out, sizeof(out), &p, &_utScratchLen) == false);

        /* Certificate larger than SSF_X509_CONFIG_MAX_CERT_SIZE: both passes report failure */
        _utGenBaseParams(&p, serial, bigKey, 65u);
        p.sanDNSNames = sanPtrs;
        (void)SSFX509EncodeTBS(NULL, 0, &p, &n);
        SSF_ASSERT((n != 0u) && ((n + sizeof(fakeSig)) > SSF_X509_CONFIG_MAX_CERT_SIZE));
        SSF_ASSERT(SSFX509EncodeCert(NULL, 0, &p, fakeSig, sizeof(fakeSig),
                   &_utScratchLen) == false);
        SSF_ASSERT(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig),
                   &_utScratchLen) == false);

        /* Output buffer one byte short: failure and nothing written past the buffer */
        _utGenBaseParams(&p, serial, bigKey, 65u);
        (void)SSFX509EncodeCert(NULL, 0, &p, fakeSig, 64u, &n);
        memset(out, 0xEEu, sizeof(out));
        SSF_ASSERT(SSFX509EncodeCert(out, n - 1u, &p, fakeSig, 64u, &_utScratchLen) == false);
        SSF_ASSERT((out[n - 1u] == 0xEEu) && (out[n] == 0xEEu));
    }
    /* ---- Fail-closed edges: version, empty names, wildcard label, extension cap, pathLen ---- */
    {
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t fakeSig[64];
        static const char *sanWild[] = { "*.example.com", NULL };
        static const uint8_t verV3[] = { 0xA0u, 0x03u, 0x02u, 0x01u, 0x02u };
        static const uint8_t sanOidE[] = { 0x55u, 0x1Du, 0x11u };
        /* SAN { [2] "", [2] "ok" }, built raw since the generator refuses an empty dNSName */
        static const uint8_t sanEmptyRaw[] = {
            0x30u, 0x06u, 0x82u, 0x00u, 0x82u, 0x02u, 'o', 'k'
        };
        static const char *sanNul[] = { "ab", NULL };
        uint8_t serial[] = { 0x09u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        const uint8_t *chain[1];
        uint32_t chainLen[1];
        uint32_t n;
        uint32_t i;

        memset(fakeSig, 0x22u, sizeof(fakeSig));
        memset(pubKey, 0x04u, sizeof(pubKey));

        /* A version above v3 does not parse; encode v3, patch version to 3 (X509-14) */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(_utFind(out, n, verV3, sizeof(verV3), &i) == true);
        out[i + 4u] = 0x03u;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);

        /* An empty hostname is a contract violation, not a runtime mismatch */
        chain[0] = _utTestCertDER;
        chainLen[0] = sizeof(_utTestCertDER);
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "",
                                           1800000000ull, &_utVErr));

        /* Empty and NUL-containing dNSName entries are dropped at parse */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.addRawExt = true;
        p.rawExtOid = sanOidE;
        p.rawExtOidLen = sizeof(sanOidE);
        p.rawExtValue = sanEmptyRaw;
        p.rawExtValueLen = sizeof(sanEmptyRaw);
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.sanLen == 1u) && (parsed.san[0].valLen == 2u));
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.sanDNSNames = sanNul;
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        for (i = 0; (i + 3u) < n; i++)
        {
            /* Is this the dNSName "ab" to patch into "a" followed by a NUL byte? */
            if ((out[i] == 0x82u) && (out[i + 1u] == 0x02u) && (out[i + 2u] == (uint8_t)'a') &&
                (out[i + 3u] == (uint8_t)'b'))
            {
                /* Yes */
                out[i + 3u] = 0u;
                break;
            }
        }
        SSF_ASSERT((i + 3u) < n);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.sanLen == 0u);

        /* A wildcard must match at least one character in the leftmost label */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.sanDNSNames = sanWild;
        n = _utSelfSign(&p, pubKey, sizeof(pubKey), out, sizeof(out));
        SSF_ASSERT(n != 0u);
        chain[0] = out;
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "www.example.com",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, ".example.com",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);

        /* More extensions than SSF_X509_CONFIG_MAX_EXTENSIONS fails to parse, the cap parses */
        n = _utBuildCertExts(SSF_X509_CONFIG_MAX_EXTENSIONS, -1, false, out, sizeof(out));
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.extsLen == SSF_X509_CONFIG_MAX_EXTENSIONS);
        n = _utBuildCertExts(SSF_X509_CONFIG_MAX_EXTENSIONS + 1u, -1, false, out, sizeof(out));
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);

        /* pathLenConstraint above 127 clamps to 127 instead of wrapping to absent */
        n = _utBuildCertExts(0u, 128, false, out, sizeof(out));
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.hasBasicConstraints == true) && (parsed.pathLenConstraint == 127));
        n = _utBuildCertExts(0u, 5, false, out, sizeof(out));
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.pathLenConstraint == 5);
    }

    /* ---- Conformance: inclusive notAfter, chain names, sigAlg params ---- */
    {
        static uint8_t caOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static const char *sanX[] = { "x", NULL };
        static const uint8_t nullParams[] = { 0x05u, 0x00u };
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t caPubLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x0Au };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        const uint8_t *chain[2];
        uint32_t chainLen[2];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t caLen;
        uint32_t leafLen;
        uint32_t oidLen = sizeof(_utSigAlgOid);
        uint32_t last;
        uint32_t i;

        /* RFC 5280 Section 4.1.2.5: the validity period includes the notAfter second */
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &parsed) == true);
        SSF_ASSERT(SSFX509IsValid(&parsed, parsed.notAfter) == true);
        SSF_ASSERT(SSFX509IsValid(&parsed, parsed.notAfter + 1u) == false);
        SSF_ASSERT(SSFX509IsValid(&parsed, parsed.notBefore) == true);
        SSF_ASSERT(SSFX509IsValid(&parsed, parsed.notBefore - 1u) == false);

        /* CA and leaf key pairs */
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPriv, sizeof(caPriv), caPub, sizeof(caPub),
                                  &caPubLen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);
        _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "ca";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
        SSF_ASSERT(caLen != 0u);
        trust[0] = caOut;
        trustLen[0] = caLen;
        chain[1] = caOut;
        chainLen[1] = caLen;

        /* RFC 5280 Section 6.1.3 (a)(4): a leaf signed by the CA key but naming another issuer */
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "other";
        p.subject.cn = "leaf";
        p.sanDNSNames = sanX;
        leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chain[0] = leafOut;
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "x",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_UNKNOWN_CA, 0u);       /* No sent cert or anchor issued it */

        /* Same leaf with the correct issuer name verifies */
        p.issuer.cn = "ca";
        leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "x",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);

        /* RFC 5280 4.1.1.2: outer params equal TBS copy (ECDSA NULL rejected, X509-11) */
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.sanDNSNames = sanX;
        p.sigAlgParams = nullParams;
        p.sigAlgParamsLen = sizeof(nullParams);
        leafLen = _utSelfSign(&p, leafPub, sizeof(leafPub), leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chain[0] = leafOut;
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "x",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_UNKNOWN_CA, 0u);
        last = 0;
        for (i = 0; (i + oidLen + 3u) < leafLen; i++)
        {
            /* Is this an AlgorithmIdentifier { sigAlg OID, NULL } (the last one is the outer)? */
            if ((leafOut[i] == 0x06u) && (leafOut[i + 1u] == (uint8_t)oidLen) &&
                (memcmp(&leafOut[i + 2u], _utSigAlgOid, oidLen) == 0) &&
                (leafOut[i + 2u + oidLen] == 0x05u) && (leafOut[i + 3u + oidLen] == 0x00u))
            {
                /* Yes */
                last = i + 2u + oidLen;
            }
        }
        SSF_ASSERT(last != 0u);
        leafOut[last] = 0x04u;
        SSF_ASSERT(SSFX509Parse(leafOut, leafLen, &parsed) == true);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "x",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_SIG_ALG_MISMATCH, 0u);
    }

    /* ---- Key Usage low octet, anyExtendedKeyUsage, leading-dot constraint, non-string DN ---- */
    {
        static uint8_t caOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t fakeSig[64];
        static const char *sanA[] = { "a.example.com", NULL };
        static const char *sanApex[] = { "example.com", NULL };
        static const char *ncDot[] = { ".example.com", NULL };
        static const uint8_t ekuOid[] = { 0x55u, 0x1Du, 0x25u };
        static const uint8_t anyEkuValue[] = { 0x30u, 0x06u, 0x06u, 0x04u,
                                                0x55u, 0x1Du, 0x25u, 0x00u };
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t caPubLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x0Bu };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        const uint8_t *chain[2];
        uint32_t chainLen[2];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t caLen;
        uint32_t leafLen;
        uint32_t n;

        memset(fakeSig, 0x44u, sizeof(fakeSig));
        memset(leafPub, 0x04u, sizeof(leafPub));

        /* Every Key Usage bit round-trips through generation, including decipherOnly (bit 8) */
        _utGenBaseParams(&p, serial, leafPub, 65u);
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_DIGITAL_SIGNATURE | 0x0080u;
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.hasKeyUsage == true);
        SSF_ASSERT(parsed.keyUsageBits == (SSF_X509_KU_DIGITAL_SIGNATURE | 0x0080u));
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.keyUsageBits == SSF_X509_KU_KEY_CERT_SIGN);

        /* anyExtendedKeyUsage satisfies the serverAuth requirement (RFC 5280 Section 4.2.1.12) */
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "any";
        p.subject.cn = "any";
        p.sanDNSNames = sanApex;
        p.addRawExt = true;
        p.rawExtOid = ekuOid;
        p.rawExtOidLen = sizeof(ekuOid);
        p.rawExtValue = anyEkuValue;
        p.rawExtValueLen = sizeof(anyEkuValue);
        leafLen = _utSignCert(&p, leafPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        SSF_ASSERT(SSFX509Parse(leafOut, leafLen, &parsed) == true);
        SSF_ASSERT((parsed.hasExtKeyUsage == true) && (parsed.ekuAnyPurpose == true));
        SSF_ASSERT(parsed.ekuServerAuth == false);
        chain[0] = leafOut;
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "example.com",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);

        /* A leading-dot dNSName constraint permits proper subdomains only */
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPriv, sizeof(caPriv), caPub, sizeof(caPub),
                                  &caPubLen) == true);
        _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "ca";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addNameConstraints = true;
        p.ncPermittedDNS = ncDot;
        caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
        SSF_ASSERT(caLen != 0u);
        trust[0] = caOut;
        trustLen[0] = caLen;
        chain[1] = caOut;
        chainLen[1] = caLen;
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "leaf";
        p.sanDNSNames = sanA;
        leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chain[0] = leafOut;
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "a.example.com",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);
        p.sanDNSNames = sanApex;
        leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "example.com",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);

        /* A DN attribute with a non-string value is skipped and the rest of the name parses */
        n = _utBuildCertExts(0u, -1, true, out, sizeof(out));
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.subject.cnLen == 1u) && (parsed.subject.cn[0] == (uint8_t)'x'));
    }

    /* ---- RSA-PSS saltLength 20: OpenSSL self-signed cert with DEFAULT saltLength omitted ---- */
    {
        static const uint8_t pss20Der[] = {
            0x30, 0x82, 0x03, 0x92, 0x30, 0x82, 0x02, 0x4b, 0xa0, 0x03, 0x02, 0x01,
            0x02, 0x02, 0x14, 0x36, 0xf3, 0x63, 0xf8, 0xfb, 0xde, 0xdf, 0x41, 0x14,
            0x6d, 0x20, 0x50, 0x42, 0x5d, 0xea, 0xf6, 0x41, 0x06, 0x2e, 0xc8, 0x30,
            0x3c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
            0x30, 0x2f, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06,
            0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d,
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03,
            0x0c, 0x0a, 0x70, 0x73, 0x73, 0x32, 0x30, 0x2e, 0x74, 0x65, 0x73, 0x74,
            0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x31, 0x38, 0x30, 0x31,
            0x33, 0x30, 0x33, 0x37, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x31,
            0x30, 0x32, 0x35, 0x30, 0x31, 0x33, 0x30, 0x33, 0x37, 0x5a, 0x30, 0x15,
            0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x70,
            0x73, 0x73, 0x32, 0x30, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x82, 0x01,
            0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
            0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01,
            0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcd, 0x6a, 0xff, 0x4d, 0x7c, 0xba,
            0xe3, 0x6e, 0xb0, 0xf1, 0xb0, 0x40, 0xc2, 0xfa, 0xcb, 0xc8, 0x5a, 0xdb,
            0xe0, 0xa3, 0x35, 0xea, 0x27, 0xa9, 0xc9, 0x1d, 0x57, 0xed, 0x6c, 0x6d,
            0x0a, 0xfa, 0xff, 0x7d, 0xe3, 0x72, 0x72, 0xeb, 0x85, 0xa5, 0x21, 0xa0,
            0xea, 0xc1, 0x13, 0x33, 0x84, 0x23, 0xda, 0xd0, 0x9e, 0xb2, 0x1b, 0x46,
            0x13, 0xd8, 0x84, 0x26, 0xab, 0x0d, 0x5b, 0xa4, 0x4b, 0x4f, 0x8d, 0xc9,
            0x02, 0x51, 0x6c, 0x0b, 0xf9, 0xad, 0x46, 0x97, 0x22, 0x1e, 0x61, 0x14,
            0x03, 0x3a, 0x3d, 0xb9, 0x54, 0x61, 0xe4, 0x8f, 0xff, 0x47, 0x1d, 0x84,
            0x5d, 0x90, 0xe1, 0x45, 0xa9, 0x58, 0xea, 0xcf, 0xbe, 0x2c, 0x67, 0x91,
            0x33, 0x10, 0x56, 0xa0, 0xd3, 0x89, 0x0d, 0x69, 0x95, 0xff, 0xe3, 0x40,
            0x61, 0x6d, 0xf5, 0xd8, 0x59, 0xcb, 0x6f, 0xd6, 0xbe, 0xd6, 0x41, 0x35,
            0xf1, 0x0e, 0x52, 0x97, 0xc4, 0x4d, 0x8f, 0xa0, 0x0c, 0xcd, 0xdf, 0xd8,
            0x09, 0x08, 0x32, 0xdb, 0xfc, 0xfd, 0xfa, 0x52, 0x49, 0x70, 0xf0, 0xc3,
            0xdc, 0xe5, 0xf0, 0x98, 0x95, 0x4f, 0x66, 0x64, 0xa8, 0x10, 0xcc, 0xb4,
            0xf1, 0xae, 0x13, 0x31, 0x8e, 0x13, 0xd6, 0x15, 0xe3, 0x33, 0x18, 0xc4,
            0xb5, 0x85, 0x1d, 0x51, 0x00, 0xe0, 0x5a, 0xc8, 0xfb, 0x5c, 0xf9, 0xfb,
            0x6f, 0x60, 0x19, 0xa0, 0x23, 0xc7, 0x68, 0xbf, 0x7b, 0xe9, 0x7a, 0xdf,
            0xb1, 0x6d, 0x27, 0x29, 0xa0, 0xfa, 0x4b, 0x91, 0x1f, 0x55, 0x90, 0xb8,
            0x03, 0x1d, 0x3a, 0x62, 0xaa, 0x3d, 0xac, 0x60, 0x38, 0x6d, 0xa0, 0x61,
            0x03, 0xc2, 0x4d, 0x17, 0x5e, 0x34, 0x45, 0xaa, 0xc1, 0x49, 0x21, 0x50,
            0x53, 0x81, 0x8d, 0xf1, 0x94, 0x58, 0xcf, 0x2c, 0xb6, 0x64, 0x34, 0xd8,
            0x1d, 0x79, 0x27, 0x2a, 0x90, 0x6d, 0xfd, 0xf6, 0x08, 0x97, 0x02, 0x03,
            0x01, 0x00, 0x01, 0xa3, 0x7a, 0x30, 0x78, 0x30, 0x1d, 0x06, 0x03, 0x55,
            0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x29, 0x74, 0xaa, 0xb8, 0x60, 0xe2,
            0x72, 0xd0, 0x98, 0xde, 0xf9, 0x8e, 0x1f, 0x65, 0x6c, 0x58, 0x7c, 0xd2,
            0xa9, 0x7d, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,
            0x16, 0x80, 0x14, 0x29, 0x74, 0xaa, 0xb8, 0x60, 0xe2, 0x72, 0xd0, 0x98,
            0xde, 0xf9, 0x8e, 0x1f, 0x65, 0x6c, 0x58, 0x7c, 0xd2, 0xa9, 0x7d, 0x30,
            0x15, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0e, 0x30, 0x0c, 0x82, 0x0a,
            0x70, 0x73, 0x73, 0x32, 0x30, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x0f,
            0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
            0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
            0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x84, 0x30, 0x3c, 0x06, 0x09, 0x2a,
            0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x2f, 0xa0, 0x0f,
            0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48,
            0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
            0x01, 0x00, 0x76, 0xc6, 0x58, 0x94, 0xfa, 0x41, 0x41, 0x25, 0xf3, 0xe3,
            0x72, 0x19, 0xd1, 0x12, 0x7c, 0xc3, 0x4f, 0x8a, 0xfe, 0x02, 0x49, 0xf6,
            0x0a, 0xce, 0xb7, 0x89, 0x2e, 0x58, 0xf0, 0xcc, 0x15, 0xdc, 0xd5, 0xda,
            0x40, 0x0e, 0x94, 0x1e, 0x17, 0xfd, 0x73, 0x50, 0x6d, 0x2e, 0xd8, 0x70,
            0x6e, 0x2e, 0x51, 0xa4, 0x6d, 0xa9, 0xb2, 0x2b, 0x97, 0x21, 0xa4, 0x65,
            0x5f, 0xa4, 0x1e, 0x31, 0x3d, 0xaf, 0x53, 0x68, 0xbe, 0x6d, 0xe6, 0x4f,
            0x98, 0xb5, 0x48, 0x86, 0xfc, 0xfd, 0x08, 0xe5, 0x9d, 0x5d, 0x08, 0x9f,
            0x42, 0x4b, 0x26, 0xaa, 0x38, 0x5e, 0x48, 0x84, 0xdb, 0x36, 0xfd, 0x11,
            0x82, 0x3d, 0x47, 0xd8, 0x70, 0x20, 0x9b, 0x92, 0xf5, 0xfe, 0x77, 0x28,
            0x80, 0x13, 0x27, 0x31, 0x90, 0x0a, 0xa6, 0xbb, 0xa0, 0xc5, 0x11, 0x04,
            0x1c, 0xc8, 0xa4, 0x61, 0x7b, 0xde, 0xf2, 0x00, 0x6b, 0x53, 0x70, 0x6b,
            0xd7, 0x80, 0xb5, 0x16, 0xf4, 0xa5, 0x5d, 0x83, 0xdb, 0x95, 0xeb, 0xb6,
            0x47, 0x5f, 0xde, 0x85, 0x8b, 0xfb, 0x47, 0x42, 0x3e, 0xfc, 0x2f, 0xeb,
            0x9c, 0x8b, 0x7e, 0x9b, 0x18, 0x7c, 0x66, 0x7a, 0xc2, 0xcf, 0x3b, 0x37,
            0x92, 0x5a, 0x32, 0xe0, 0x62, 0x31, 0x50, 0x9e, 0xbb, 0x62, 0xb0, 0xe2,
            0xa4, 0x49, 0x11, 0xf8, 0xb9, 0x0c, 0x86, 0x18, 0x0b, 0xa2, 0x89, 0x9b,
            0x3b, 0x67, 0x3a, 0x31, 0xf4, 0x1b, 0x0f, 0xa9, 0x85, 0xc0, 0x76, 0xe2,
            0x85, 0xa0, 0x6a, 0xe7, 0xa6, 0xda, 0x99, 0x67, 0xdf, 0xec, 0x59, 0x77,
            0x85, 0xda, 0x3f, 0x20, 0xe3, 0xef, 0x9b, 0xcb, 0xb1, 0x73, 0xa4, 0x6b,
            0x11, 0xff, 0x7c, 0xb3, 0xd5, 0xb7, 0x9e, 0x53, 0x32, 0xbf, 0x68, 0x13,
            0x7c, 0xf8, 0x0d, 0xc1, 0xa7, 0xef, 0xd7, 0x71, 0xc0, 0xa4, 0xf4, 0xc1,
            0x73, 0x72, 0xdd, 0x1a, 0x0b, 0xe5
        };
        static SSFX509Cert_t pss;
        const uint8_t *chain[1];
        uint32_t chainLen[1];

        SSF_ASSERT(SSFX509Parse(pss20Der, sizeof(pss20Der), &pss) == true);
        SSF_ASSERT(SSFX509IsSigRSAPSSSHA256(&pss) == true);
        /* With RSA-PSS compiled out the signature fails closed */
        SSF_ASSERT(SSFX509VerifyCertSignature(&pss, &pss) == (_UT_RSA_PSS_VERIFY == 1u));
        chain[0] = pss20Der;
        chainLen[0] = sizeof(pss20Der);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "pss20.test",
                                      1800000000ull, &_utVErr) == (_UT_RSA_PSS_VERIFY == 1u));
        if (_UT_RSA_PSS_VERIFY == 1u) { _UT_VERR(OK, 0u); } else { _UT_VERR(ERR_UNKNOWN_CA, 0u); }
    }

    /* ---- Bounded string lengths: 253-octet dNSName accepted, longer hostnames never match ---- */
    {
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t fakeSig[64];
        static char san253[254];
        static char host300[301];
        static const char *sanMax[2];
        static const char *sanX[] = { "x", NULL };
        uint8_t serial[] = { 0x0Cu };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        const uint8_t *chain[1];
        uint32_t chainLen[1];
        uint32_t n;

        memset(fakeSig, 0x55u, sizeof(fakeSig));
        memset(pubKey, 0x04u, sizeof(pubKey));
        memset(san253, 'd', 253u);
        san253[253] = '\0';
        sanMax[0] = san253;
        sanMax[1] = NULL;
        memset(host300, 'h', 300u);
        host300[300] = '\0';

        /* Exactly the RFC 1035 bound encodes and parses back with the same length */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.sanDNSNames = sanMax;
        SSF_ASSERT(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n) == true);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.sanLen == 1u) && (parsed.san[0].valLen == 253u));

        /* A hostname longer than any valid dNSName is rejected before any SAN comparison */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.sanDNSNames = sanX;
        n = _utSelfSign(&p, pubKey, sizeof(pubKey), out, sizeof(out));
        SSF_ASSERT(n != 0u);
        chain[0] = out;
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, host300,
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "x",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);
    }

    /* ---- Anchor constraints come from the anchor that signed, not the first one by name ---- */
    {
        static uint8_t caA[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caB[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t pubA[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t pubB[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static const char *sanEvil[] = { "evil.com", NULL };
        static const char *sanGood[] = { "good.com", NULL };
        static const char *ncExcl[] = { "evil.com", NULL };
        static uint8_t privA[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t privB[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t pubALen;
        size_t pubBLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x0Du };
        static SSFX509GenParams_t p;
        const uint8_t *chain[1];
        uint32_t chainLen[1];
        const uint8_t *trust[2];
        uint32_t trustLen[2];
        uint32_t aLen;
        uint32_t bLen;
        uint32_t leafLen;

        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, privA, sizeof(privA), pubA, sizeof(pubA),
                                  &pubALen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, privB, sizeof(privB), pubB, sizeof(pubB),
                                  &pubBLen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);

        /* Anchor A: subject "ca", unconstrained, never signs the leaf */
        _utGenBaseParams(&p, serial, pubA, (uint32_t)pubALen);
        p.issuer.cn = "ca";
        p.subject.cn = "ca";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        aLen = _utSignCert(&p, privA, caA, sizeof(caA));
        SSF_ASSERT(aLen != 0u);

        /* Anchor B: same subject "ca", excludes evil.com, signs the leaf */
        _utGenBaseParams(&p, serial, pubB, (uint32_t)pubBLen);
        p.issuer.cn = "ca";
        p.subject.cn = "ca";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addNameConstraints = true;
        p.ncExcludedDNS = ncExcl;
        bLen = _utSignCert(&p, privB, caB, sizeof(caB));
        SSF_ASSERT(bLen != 0u);

        /* Leaf for evil.com signed by B */
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "leaf";
        p.sanDNSNames = sanEvil;
        leafLen = _utSignCert(&p, privB, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chain[0] = leafOut;
        chainLen[0] = leafLen;

        /* B alone rejects it */
        trust[0] = caB;
        trustLen[0] = bLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 1u, "evil.com",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);

        /* A listed before B: B still signs, so B's exclusion still applies */
        trust[0] = caA;
        trustLen[0] = aLen;
        trust[1] = caB;
        trustLen[1] = bLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 2u, "evil.com",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);

        /* B listed before A: same answer */
        trust[0] = caB;
        trustLen[0] = bLen;
        trust[1] = caA;
        trustLen[1] = aLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 2u, "evil.com",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);

        /* A leaf for a name B permits is accepted with either ordering */
        p.sanDNSNames = sanGood;
        leafLen = _utSignCert(&p, privB, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 2u, "good.com",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);
        trust[0] = caA;
        trustLen[0] = aLen;
        trust[1] = caB;
        trustLen[1] = bLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 2u, "good.com",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);

        /* Mirror image: only the non-signing twin excludes the name, so the leaf is accepted */
        leafLen = _utSignCert(&p, privA, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chainLen[0] = leafLen;
        p.sanDNSNames = sanEvil;
        leafLen = _utSignCert(&p, privA, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chainLen[0] = leafLen;
        trust[0] = caB;
        trustLen[0] = bLen;
        trust[1] = caA;
        trustLen[1] = aLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 2u, "evil.com",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);
    }

    /* ---- AUDIT X509-3: Name Constraints that cannot be held in full fail the parse ---- */
    {
        static uint8_t caOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t fakeSig[64];
        static const uint8_t ncOid[] = { 0x55u, 0x1Du, 0x1Eu };
        static const char *excl9[] = { "a1.com", "a2.com", "a3.com", "a4.com", "a5.com",
                                       "a6.com", "a7.com", "a8.com", "evil.com", NULL };
        static const char *excl8[] = { "a1.com", "a2.com", "a3.com", "a4.com", "a5.com",
                                       "a6.com", "a7.com", "evil.com", NULL };
        static const char *perm9[] = { "p1.com", "p2.com", "p3.com", "p4.com", "p5.com",
                                       "p6.com", "p7.com", "p8.com", "p9.com", NULL };
        static const char *sanEvil[] = { "evil.com", NULL };
        static const char *sanGood[] = { "good.com", NULL };
        /* SEQUENCE { [1] { SEQUENCE { [2] "evil.com" } } }: well formed, the control */
        static const uint8_t ncGood[] = {
            0x30u, 0x0Eu, 0xA1u, 0x0Cu, 0x30u, 0x0Au, 0x82u, 0x08u,
            'e', 'v', 'i', 'l', '.', 'c', 'o', 'm'
        };
        /* Body is a SET, not a SEQUENCE */
        static const uint8_t ncSet[] = { 0x31u, 0x00u };
        /* Empty SEQUENCE: neither subtree list present */
        static const uint8_t ncEmpty[] = { 0x30u, 0x00u };
        /* Subtree list with the unknown tag [2] */
        static const uint8_t ncBadTag[] = {
            0x30u, 0x0Eu, 0xA2u, 0x0Cu, 0x30u, 0x0Au, 0x82u, 0x08u,
            'e', 'v', 'i', 'l', '.', 'c', 'o', 'm'
        };
        /* Excluded list followed by a stray NULL inside the SEQUENCE */
        static const uint8_t ncInnerTrail[] = {
            0x30u, 0x10u, 0xA1u, 0x0Cu, 0x30u, 0x0Au, 0x82u, 0x08u,
            'e', 'v', 'i', 'l', '.', 'c', 'o', 'm', 0x05u, 0x00u
        };
        /* Well-formed SEQUENCE followed by a stray NULL inside the extension value */
        static const uint8_t ncOuterTrail[] = {
            0x30u, 0x0Eu, 0xA1u, 0x0Cu, 0x30u, 0x0Au, 0x82u, 0x08u,
            'e', 'v', 'i', 'l', '.', 'c', 'o', 'm', 0x05u, 0x00u
        };
        /* excludedSubtrees [1] before permittedSubtrees [0] */
        static const uint8_t ncOutOfOrder[] = {
            0x30u, 0x1Cu,
            0xA1u, 0x0Cu, 0x30u, 0x0Au, 0x82u, 0x08u, 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm',
            0xA0u, 0x0Cu, 0x30u, 0x0Au, 0x82u, 0x08u, 'g', 'o', 'o', 'd', '.', 'c', 'o', 'm'
        };
        /* Empty excluded list (GeneralSubtrees is SIZE (1..MAX)) */
        static const uint8_t ncEmptyList[] = { 0x30u, 0x02u, 0xA1u, 0x00u };
        /* GeneralSubtree that is a SET, not a SEQUENCE */
        static const uint8_t ncSubtreeSet[] = {
            0x30u, 0x0Eu, 0xA1u, 0x0Cu, 0x31u, 0x0Au, 0x82u, 0x08u,
            'e', 'v', 'i', 'l', '.', 'c', 'o', 'm'
        };
        /* GeneralName whose length overruns its GeneralSubtree */
        static const uint8_t ncNameOverrun[] = {
            0x30u, 0x0Au, 0xA1u, 0x08u, 0x30u, 0x06u, 0x82u, 0x08u, 'e', 'v', 'i', 'l'
        };
        static const struct { const uint8_t *body; uint32_t len; } bad[] = {
            { ncSet, sizeof(ncSet) }, { ncEmpty, sizeof(ncEmpty) },
            { ncBadTag, sizeof(ncBadTag) }, { ncInnerTrail, sizeof(ncInnerTrail) },
            { ncOuterTrail, sizeof(ncOuterTrail) }, { ncOutOfOrder, sizeof(ncOutOfOrder) },
            { ncEmptyList, sizeof(ncEmptyList) }, { ncSubtreeSet, sizeof(ncSubtreeSet) },
            { ncNameOverrun, sizeof(ncNameOverrun) }
        };
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t caPubLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x1Du };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        const uint8_t *chain[1];
        uint32_t chainLen[1];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t caLen;
        uint32_t leafLen;
        uint32_t n;
        uint32_t i;

        memset(fakeSig, 0x55u, sizeof(fakeSig));
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPriv, sizeof(caPriv), caPub,
                                  sizeof(caPub), &caPubLen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);

        /* More excluded, or more permitted, subtrees than fit: dropping any would loosen */
        _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
        p.addNameConstraints = true;
        p.ncExcludedDNS = excl9;
        SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                     &n) == true);
        SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);
        p.ncExcludedDNS = NULL;
        p.ncPermittedDNS = perm9;
        SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                     &n) == true);
        SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);

        /* Malformed bodies: the control parses, every broken variant fails */
        _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
        p.addRawExt = true;
        p.rawExtOid = ncOid;
        p.rawExtOidLen = sizeof(ncOid);
        p.rawExtCritical = true;
        p.rawExtValue = ncGood;
        p.rawExtValueLen = sizeof(ncGood);
        SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                     &n) == true);
        SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
        SSF_ASSERT((parsed.hasNameConstraints == true) && (parsed.excludedLen == 1u));
        for (i = 0; i < (uint32_t)(sizeof(bad) / sizeof(bad[0])); i++)
        {
            p.rawExtValue = bad[i].body;
            p.rawExtValueLen = bad[i].len;
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);
        }

        /* Exactly the cap: every exclusion is kept, including the last one */
        _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "ca";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addNameConstraints = true;
        p.ncExcludedDNS = excl8;
        caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
        SSF_ASSERT(caLen != 0u);
        SSF_ASSERT(SSFX509Parse(caOut, caLen, &parsed) == true);
        SSF_ASSERT(parsed.excludedLen == SSF_X509_CONFIG_MAX_NAME_CONSTRAINTS);
        trust[0] = caOut;
        trustLen[0] = caLen;
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "leaf";
        p.sanDNSNames = sanEvil;
        leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chain[0] = leafOut;
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 1u, "evil.com",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
        p.sanDNSNames = sanGood;
        leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 1u, "good.com",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);

        /* AUDIT ASN1-1: a pathLenConstraint that is not a valid unsigned INTEGER fails */
        {
            static const uint8_t bcOid[] = { 0x55u, 0x1Du, 0x13u };
            /* SEQUENCE { cA TRUE, pathLenConstraint -1 } */
            static const uint8_t bcNegPathLen[] = {
                0x30u, 0x06u, 0x01u, 0x01u, 0xFFu, 0x02u, 0x01u, 0xFFu
            };
            /* SEQUENCE { cA TRUE, pathLenConstraint 0 }: the control */
            static const uint8_t bcPathLen0[] = {
                0x30u, 0x06u, 0x01u, 0x01u, 0xFFu, 0x02u, 0x01u, 0x00u
            };

            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            p.addRawExt = true;
            p.rawExtOid = bcOid;
            p.rawExtOidLen = sizeof(bcOid);
            p.rawExtCritical = true;
            p.rawExtValue = bcPathLen0;
            p.rawExtValueLen = sizeof(bcPathLen0);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT((parsed.isCA == true) && (parsed.pathLenConstraint == 0));
            p.rawExtValue = bcNegPathLen;
            p.rawExtValueLen = sizeof(bcNegPathLen);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);
        }

        /* AUDIT X509-8: basicConstraints with an undecodable pathLen or trailing data fails */
        {
            static const uint8_t bcOid8[] = { 0x55u, 0x1Du, 0x13u };
            /* { cA TRUE, OCTET STRING 00 } and { cA TRUE, 9-byte INTEGER } (audit cases) */
            static const uint8_t bcOctetPl[] = {
                0x30u, 0x06u, 0x01u, 0x01u, 0xFFu, 0x04u, 0x01u, 0x00u
            };
            static const uint8_t bcBigPl[] = {
                0x30u, 0x0Eu, 0x01u, 0x01u, 0xFFu, 0x02u, 0x09u,
                0x01u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
            };
            /* { cA TRUE, pathLen 0, NULL } and { cA TRUE, pathLen 0 } followed by 05 00 */
            static const uint8_t bcInnerTrail[] = {
                0x30u, 0x08u, 0x01u, 0x01u, 0xFFu, 0x02u, 0x01u, 0x00u, 0x05u, 0x00u
            };
            static const uint8_t bcOuterTrail[] = {
                0x30u, 0x06u, 0x01u, 0x01u, 0xFFu, 0x02u, 0x01u, 0x00u, 0x05u, 0x00u
            };
            /* Controls: { cA TRUE, pathLen 0 }, { cA TRUE }, {} */
            static const uint8_t bcPl0[] = {
                0x30u, 0x06u, 0x01u, 0x01u, 0xFFu, 0x02u, 0x01u, 0x00u
            };
            static const uint8_t bcCAOnly[] = { 0x30u, 0x03u, 0x01u, 0x01u, 0xFFu };
            static const uint8_t bcEmpty[] = { 0x30u, 0x00u };
            static const struct { const uint8_t *v; uint32_t len; } badBc[] = {
                { bcOctetPl, sizeof(bcOctetPl) }, { bcBigPl, sizeof(bcBigPl) },
                { bcInnerTrail, sizeof(bcInnerTrail) }, { bcOuterTrail, sizeof(bcOuterTrail) }
            };
            uint32_t k;

            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            p.addRawExt = true;
            p.rawExtOid = bcOid8;
            p.rawExtOidLen = sizeof(bcOid8);
            p.rawExtCritical = true;
            for (k = 0; k < (uint32_t)(sizeof(badBc) / sizeof(badBc[0])); k++)
            {
                p.rawExtValue = badBc[k].v;
                p.rawExtValueLen = badBc[k].len;
                SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                             &n) == true);
                SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);
            }
            p.rawExtValue = bcPl0;
            p.rawExtValueLen = sizeof(bcPl0);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT((parsed.isCA == true) && (parsed.pathLenConstraint == 0));
            p.rawExtValue = bcCAOnly;
            p.rawExtValueLen = sizeof(bcCAOnly);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT((parsed.isCA == true) && (parsed.pathLenConstraint == -1));
            p.rawExtValue = bcEmpty;
            p.rawExtValueLen = sizeof(bcEmpty);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT((parsed.isCA == false) && (parsed.pathLenConstraint == -1));
        }

        /* AUDIT X509-14: generator parameters RFC 5280 forbids are caller errors (DBC) */
        {
            static const uint8_t kid[] = { 0x01u, 0x02u };
            static const char *sanNone[] = { NULL };
            static const char *sanEmptyName[] = { "", NULL };
            static const char *sanOk14[] = { "ok.com", NULL };

            #define _X14(_setup) do { \
                _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen); \
                _setup; \
                SSF_ASSERT_TEST(SSFX509EncodeTBS(caOut, sizeof(caOut), &p, &n)); \
                SSF_ASSERT_TEST(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, \
                                                  sizeof(fakeSig), &n)); \
            } while (0)

            _X14(p.skid = kid; p.skidLen = 0u);
            _X14(p.akid = kid; p.akidLen = 0u);
            _X14(p.skidLen = sizeof(kid));
            _X14(p.addNameConstraints = true);
            _X14(p.addExtKeyUsage = true);
            _X14(p.sanDNSNames = sanNone);
            _X14(p.sanDNSNames = sanEmptyName);
            _X14(p.addBasicConstraints = true; p.isCA = false; p.pathLenConstraint = 0);
            _X14(p.pathLenConstraint = 0);
            _X14(p.version = 1u);
            _X14(p.version = 3u);
            #undef _X14

            /* Valid counterparts still encode */
            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            p.skid = kid;
            p.skidLen = sizeof(kid);
            p.addExtKeyUsage = true;
            p.ekuCodeSigning = true;
            p.sanDNSNames = sanOk14;
            p.addBasicConstraints = true;
            p.isCA = true;
            p.pathLenConstraint = 0;
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            p.version = 0u;
            p.skid = NULL;
            p.skidLen = 0u;
            p.addExtKeyUsage = false;
            p.sanDNSNames = NULL;
            p.addBasicConstraints = false;
            p.pathLenConstraint = -1;
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
        }

        /* ---- AUDIT X509-9/10/11/12 and MATCH-1 (Low batch 2) ---- */
        {
            static uint8_t junkOut[SSF_X509_CONFIG_MAX_CERT_SIZE + 32u];
            static const uint8_t sanOid9[] = { 0x55u, 0x1Du, 0x11u };
            static const uint8_t rsaOid11[] = {
                0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
            };
            static const uint8_t nullParams[] = { 0x05u, 0x00u };
            /* SAN { [2] "evil.com" } (control), { INTEGER "evil.com" }, { constructed [2] } */
            static const uint8_t sanDnsOk[] = {
                0x30u, 0x0Au, 0x82u, 0x08u, 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm'
            };
            static const uint8_t sanInt[] = {
                0x30u, 0x0Au, 0x02u, 0x08u, 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm'
            };
            static const uint8_t sanCons[] = {
                0x30u, 0x0Cu, 0xA2u, 0x0Au, 0x04u, 0x08u, 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm'
            };
            /* SAN { [2] "evil.com" } followed by a stray NULL inside the extension value */
            static const uint8_t sanTrail[] = {
                0x30u, 0x0Au, 0x82u, 0x08u, 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm', 0x05u, 0x00u
            };
            static const uint8_t pathCert[] = { 0u };
            static const uint8_t pathTbs[] = { 0u };
            static const uint8_t pathExts[] = { 0u, 7u };
            static const uint8_t pathExt0[] = { 0u, 7u, 0u, 0u };
            static const uint8_t ver2[] = { 0xA0u, 0x03u, 0x02u, 0x01u, 0x02u };
            static const char *sanGood10[] = { "good.com", NULL };
            uint32_t w;
            uint32_t at;

            /* X509-9: a SAN entry must be a primitive context-specific dNSName to count as one */
            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            p.addRawExt = true;
            p.rawExtOid = sanOid9;
            p.rawExtOidLen = sizeof(sanOid9);
            p.rawExtValue = sanDnsOk;
            p.rawExtValueLen = sizeof(sanDnsOk);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT((parsed.sanLen == 1u) && (parsed.san[0].type == SSF_X509_SAN_DNS));
            p.rawExtValue = sanInt;
            p.rawExtValueLen = sizeof(sanInt);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);
            p.rawExtValue = sanCons;
            p.rawExtValueLen = sizeof(sanCons);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);

            /* X509-12: trailing data at each level fails the parse */
            p.rawExtValue = sanTrail;
            p.rawExtValueLen = sizeof(sanTrail);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);
            p.rawExtValue = sanDnsOk;
            p.rawExtValueLen = sizeof(sanDnsOk);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            w = _utAppendJunk(caOut, n, pathCert, 0u, junkOut, sizeof(junkOut));
            SSF_ASSERT((w != 0u) && (SSFX509Parse(junkOut, w, &parsed) == false));
            w = _utAppendJunk(caOut, n, pathTbs, 1u, junkOut, sizeof(junkOut));
            SSF_ASSERT((w != 0u) && (SSFX509Parse(junkOut, w, &parsed) == false));
            w = _utAppendJunk(caOut, n, pathExts, 2u, junkOut, sizeof(junkOut));
            SSF_ASSERT((w != 0u) && (SSFX509Parse(junkOut, w, &parsed) == false));
            w = _utAppendJunk(caOut, n, pathExt0, 4u, junkOut, sizeof(junkOut));
            SSF_ASSERT((w != 0u) && (SSFX509Parse(junkOut, w, &parsed) == false));
            memcpy(junkOut, caOut, n);
            junkOut[n] = 0x05u;
            junkOut[n + 1u] = 0x00u;
            SSF_ASSERT(SSFX509Parse(junkOut, n + 2u, &parsed) == false);
            SSF_ASSERT(SSFX509Parse(junkOut, n, &parsed) == true);
            /* A v1 certificate (version patched to 0) must not carry extensions */
            SSF_ASSERT(_utFind(caOut, n, ver2, sizeof(ver2), &at) == true);
            caOut[at + 4u] = 0x00u;
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);

            /* X509-11: EC key labelled rsaEncryption is not an EC point; ECDSA params absent */
            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
            SSF_ASSERT((caLen != 0u) && (SSFX509Parse(caOut, caLen, &parsed) == true));
            SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == true);
            p.pubKeyAlgOidRaw = rsaOid11;
            p.pubKeyAlgOidRawLen = sizeof(rsaOid11);
            caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
            SSF_ASSERT((caLen != 0u) && (SSFX509Parse(caOut, caLen, &parsed) == true));
            SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == false);
            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            p.sigAlgParams = nullParams;
            p.sigAlgParamsLen = sizeof(nullParams);
            caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
            SSF_ASSERT((caLen != 0u) && (SSFX509Parse(caOut, caLen, &parsed) == true));
            SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == false);

            /* X509-10: root sent last in the chain; its pathLen 0 allows the leaf it issued */
            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            p.issuer.cn = "root10";
            p.subject.cn = "root10";
            p.addBasicConstraints = true;
            p.isCA = true;
            p.pathLenConstraint = 0;
            p.addKeyUsage = true;
            p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
            caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
            SSF_ASSERT(caLen != 0u);
            _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
            p.issuer.cn = "root10";
            p.subject.cn = "leaf10";
            p.sanDNSNames = sanGood10;
            leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
            SSF_ASSERT(leafLen != 0u);
            {
                const uint8_t *chain10[2];
                uint32_t chainLen10[2];

                chain10[0] = leafOut;
                chainLen10[0] = leafLen;
                chain10[1] = caOut;
                chainLen10[1] = caLen;
                trust[0] = caOut;
                trustLen[0] = caLen;
                SSF_ASSERT(SSFX509VerifyChain(chain10, chainLen10, 1u, trust, trustLen, 1u,
                                              "good.com", 1800000000ull, &_utVErr) == true);
                _UT_VERR(OK, 0u);
                SSF_ASSERT(SSFX509VerifyChain(chain10, chainLen10, 2u, trust, trustLen, 1u,
                                              "good.com", 1800000000ull, &_utVErr) == true);
                _UT_VERR(OK, 0u);
            }
        }

        /* AUDIT X509-6: a present field that does not decode fails the parse, never defaults */
        {
            static const uint8_t unkOid[] = { 0x2Au, 0x03u, 0x04u };
            static const uint8_t bcOid[] = { 0x55u, 0x1Du, 0x13u };
            static const uint8_t akidOid[] = { 0x55u, 0x1Du, 0x23u };
            static const uint8_t unkValue[] = { 0xAAu, 0xBBu };
            /* critical TRUE + OCTET STRING { AA BB }; a bad 2-byte BOOLEAN + { AA } */
            static const uint8_t critGood[] = { 0x01u, 0x01u, 0xFFu, 0x04u, 0x02u, 0xAAu, 0xBBu };
            static const uint8_t critBad[] = { 0x01u, 0x02u, 0xFFu, 0xFFu, 0x04u, 0x01u, 0xAAu };
            /* BasicConstraints SEQUENCE { BOOLEAN with 2 content bytes } */
            static const uint8_t bcBadCA[] = { 0x30u, 0x04u, 0x01u, 0x02u, 0xFFu, 0xFFu };
            /* AKID SEQUENCE { [0] keyIdentifier whose length overruns the SEQUENCE } */
            static const uint8_t akidOverrun[] = { 0x30u, 0x04u, 0x80u, 0x05u, 0xAAu, 0xBBu };
            /* AKID SEQUENCE { [0] AA BB }: the control */
            static const uint8_t akidGood[] = { 0x30u, 0x04u, 0x80u, 0x02u, 0xAAu, 0xBBu };
            uint8_t curvePat[2u + sizeof(_utCurveOid)];
            uint32_t at;

            /* Critical flag that does not decode: must not read as non-critical */
            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            p.addRawExt = true;
            p.rawExtOid = unkOid;
            p.rawExtOidLen = sizeof(unkOid);
            p.rawExtValue = unkValue;
            p.rawExtValueLen = sizeof(unkValue);
            p.rawExtCritical = true;
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT((parsed.extsLen == 1u) && (parsed.exts[0].critical == true));
            SSF_ASSERT(_utFind(caOut, n, critGood, sizeof(critGood), &at) == true);
            memcpy(&caOut[at], critBad, sizeof(critBad));
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);

            /* AUDIT ASN1-4: a critical flag of 0x01 is not DER TRUE and fails the parse */
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(_utFind(caOut, n, critGood, sizeof(critGood), &at) == true);
            caOut[at + 2u] = 0x01u;
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);

            /* cA flag that does not decode */
            p.rawExtOid = bcOid;
            p.rawExtOidLen = sizeof(bcOid);
            p.rawExtValue = bcBadCA;
            p.rawExtValueLen = sizeof(bcBadCA);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);

            /* AUDIT ASN1-4: a cA flag of 0x01 fails the parse */
            {
                static const uint8_t bcCA01[] = { 0x30u, 0x03u, 0x01u, 0x01u, 0x01u };

                p.rawExtValue = bcCA01;
                p.rawExtValueLen = sizeof(bcCA01);
                SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig,
                                             sizeof(fakeSig), &n) == true);
                SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);
            }

            /* AKID keyIdentifier that does not decode; a good one is read */
            p.rawExtOid = akidOid;
            p.rawExtOidLen = sizeof(akidOid);
            p.rawExtCritical = false;
            p.rawExtValue = akidGood;
            p.rawExtValueLen = sizeof(akidGood);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT((parsed.akidLen == 2u) && (parsed.akid[0] == 0xAAu));
            p.rawExtValue = akidOverrun;
            p.rawExtValueLen = sizeof(akidOverrun);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);

            /* EC curve OID whose length overruns the AlgorithmIdentifier */
            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT(parsed.ecCurveOidRaw != NULL);
            curvePat[0] = 0x06u;
            curvePat[1] = (uint8_t)sizeof(_utCurveOid);
            memcpy(&curvePat[2], _utCurveOid, sizeof(_utCurveOid));
            SSF_ASSERT(_utFind(caOut, n, curvePat, sizeof(curvePat), &at) == true);
            caOut[at + 1u]++;
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);
        }

        /* AUDIT ASN1-5: BIT STRING padding adds no key usages; keys and sigs are whole octets */
        {
            static const uint8_t kuOid[] = { 0x55u, 0x1Du, 0x0Fu };
            /* digitalSignature only, but the seven padding bits are set */
            static const uint8_t kuPadSet[] = { 0x03u, 0x02u, 0x07u, 0xFFu };
            /* digitalSignature only, DER: the control */
            static const uint8_t kuDigSig[] = { 0x03u, 0x02u, 0x07u, 0x80u };
            uint32_t at;

            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            p.addRawExt = true;
            p.rawExtOid = kuOid;
            p.rawExtOidLen = sizeof(kuOid);
            p.rawExtCritical = true;
            p.rawExtValue = kuDigSig;
            p.rawExtValueLen = sizeof(kuDigSig);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT(parsed.keyUsageBits == SSF_X509_KU_DIGITAL_SIGNATURE);
            /* Padding bits set: not DER, so keyUsage keeps its fail-closed default of no usages */
            p.rawExtValue = kuPadSet;
            p.rawExtValueLen = sizeof(kuPadSet);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT((parsed.hasKeyUsage == true) && (parsed.keyUsageBits == 0u));

            /* Public key BIT STRING with one unused bit (padding bit itself zero) */
            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT(_utFind(caOut, n, caPub, (uint32_t)caPubLen, &at) == true);
            SSF_ASSERT((at >= 3u) && (caOut[at - 3u] == 0x03u) && (caOut[at - 1u] == 0x00u));
            caOut[at - 1u] = 0x01u;
            caOut[at + (uint32_t)caPubLen - 1u] &= 0xFEu;
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);

            /* Signature BIT STRING (the last element) with one unused bit */
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT((caOut[n - sizeof(fakeSig) - 3u] == 0x03u) &&
                       (caOut[n - sizeof(fakeSig) - 1u] == 0x00u));
            caOut[n - sizeof(fakeSig) - 1u] = 0x01u;
            caOut[n - 1u] &= 0xFEu;
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);
        }

        /* AUDIT ASN1-6: a high-bit serial is written unsigned, parses back with a 0x00 byte */
        {
            uint8_t hiSerial[] = { 0x80u, 0x01u };

            _utGenBaseParams(&p, hiSerial, caPub, (uint32_t)caPubLen);
            p.serialLen = sizeof(hiSerial);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT((parsed.serialLen == 3u) && (parsed.serial[0] == 0x00u));
            SSF_ASSERT((parsed.serial[1] == 0x80u) && (parsed.serial[2] == 0x01u));
        }

        /* AUDIT ASN1-3: a serial with an unneeded leading 0x00 is not DER and fails to parse */
        {
            static const uint8_t serial0105[] = { 0x02u, 0x02u, 0x01u, 0x05u };
            uint8_t padSerial[] = { 0x01u, 0x05u };
            uint8_t okSerial[] = { 0x00u, 0x85u };
            uint32_t at;

            _utGenBaseParams(&p, okSerial, caPub, (uint32_t)caPubLen);
            p.serialLen = sizeof(okSerial);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT((parsed.serialLen == 2u) && (parsed.serial[1] == 0x85u));
            /* Encode serial 01 05, then patch it on the wire to the non-minimal 00 05 */
            _utGenBaseParams(&p, padSerial, caPub, (uint32_t)caPubLen);
            p.serialLen = sizeof(padSerial);
            SSF_ASSERT(SSFX509EncodeCert(caOut, sizeof(caOut), &p, fakeSig, sizeof(fakeSig),
                                         &n) == true);
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == true);
            SSF_ASSERT(_utFind(caOut, n, serial0105, sizeof(serial0105), &at) == true);
            caOut[at + 2u] = 0x00u;
            SSF_ASSERT(SSFX509Parse(caOut, n, &parsed) == false);
        }
    }

    /* ---- AUDIT X509-4: a constraint on a form SSF does not enforce rejects any instance ---- */
    {
        static uint8_t caOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t tbsDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t certContent[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static const uint8_t ncOid[] = { 0x55u, 0x1Du, 0x1Eu };
        static const uint8_t sanOid[] = { 0x55u, 0x1Du, 0x11u };
        /* permitted [0] { GeneralSubtree { [4] Name { O=Good } } } */
        static const uint8_t ncDirGood[] = {
            0x30u, 0x17u, 0xA0u, 0x15u, 0x30u, 0x13u, 0xA4u, 0x11u,
            0x30u, 0x0Fu, 0x31u, 0x0Du, 0x30u, 0x0Bu, 0x06u, 0x03u, 0x55u, 0x04u, 0x0Au,
            0x0Cu, 0x04u, 'G', 'o', 'o', 'd'
        };
        /* permitted [0] { GeneralSubtree { [1] rfc822Name "good.com" } } */
        static const uint8_t ncEmailGood[] = {
            0x30u, 0x0Eu, 0xA0u, 0x0Cu, 0x30u, 0x0Au, 0x81u, 0x08u,
            'g', 'o', 'o', 'd', '.', 'c', 'o', 'm'
        };
        /* permitted [0] { GeneralSubtree { [6] URI "good.com" } } */
        static const uint8_t ncUriGood[] = {
            0x30u, 0x0Eu, 0xA0u, 0x0Cu, 0x30u, 0x0Au, 0x86u, 0x08u,
            'g', 'o', 'o', 'd', '.', 'c', 'o', 'm'
        };
        /* SAN { [1] "x@evil.com" } and SAN { [6] "https://x" } */
        static const uint8_t sanEmail[] = {
            0x30u, 0x0Cu, 0x81u, 0x0Au, 'x', '@', 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm'
        };
        static const uint8_t sanUri[] = {
            0x30u, 0x0Bu, 0x86u, 0x09u, 'h', 't', 't', 'p', 's', ':', '/', '/', 'x'
        };
        /* RDN CN="cccccccccccccc" and an equal-length RDN emailAddress="x@ev.com" */
        static const uint8_t rdnCN[] = {
            0x31u, 0x17u, 0x30u, 0x15u, 0x06u, 0x03u, 0x55u, 0x04u, 0x03u, 0x0Cu, 0x0Eu,
            'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c'
        };
        static const uint8_t rdnEmail[] = {
            0x31u, 0x17u, 0x30u, 0x15u, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u,
            0x0Du, 0x01u, 0x09u, 0x01u, 0x16u, 0x08u, 'x', '@', 'e', 'v', '.', 'c', 'o', 'm'
        };
        static const uint8_t ecdsaSha256Oid[] = {
            0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u
        };
        static const char *sanGood[] = { "good.com", NULL };
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t tbsHash[SSF_SHA2_256_BYTE_SIZE];
        static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        uint8_t algId[16];
        size_t caPubLen;
        size_t leafPubLen;
        size_t sigLen;
        uint8_t serial[] = { 0x4Du };
        static SSFX509GenParams_t p;
        const uint8_t *chain[1];
        uint32_t chainLen[1];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t caLen;
        uint32_t leafLen;
        uint32_t tbsLen;
        uint32_t algIdLen;
        uint32_t n;
        uint32_t w;
        uint32_t at;

        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPriv, sizeof(caPriv), caPub,
                                  sizeof(caPub), &caPubLen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);

        /* Anchor "ca" carrying one raw critical Name Constraints body */
        #define _X5094_ANCHOR(_nc) do { \
            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen); \
            p.issuer.cn = "ca"; p.subject.cn = "ca"; \
            p.addBasicConstraints = true; p.isCA = true; \
            p.addKeyUsage = true; p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN; \
            p.addRawExt = true; p.rawExtOid = ncOid; p.rawExtOidLen = sizeof(ncOid); \
            p.rawExtValue = (_nc); p.rawExtValueLen = sizeof(_nc); p.rawExtCritical = true; \
            caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut)); \
            SSF_ASSERT(caLen != 0u); \
            trust[0] = caOut; trustLen[0] = caLen; \
        } while (0)
        /* Code-signing leaf issued by "ca"; the caller sets subject and SANs afterwards */
        #define _X5094_LEAF_BASE() do { \
            _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen); \
            p.issuer.cn = "ca"; p.subject.cn = NULL; \
            p.addKeyUsage = true; p.keyUsageBits = SSF_X509_KU_DIGITAL_SIGNATURE; \
            p.addExtKeyUsage = true; p.ekuCodeSigning = true; \
        } while (0)
        #define _X5094_VERIFY(_expect, _code, _idx) do { \
            leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut)); \
            SSF_ASSERT(leafLen != 0u); \
            chain[0] = leafOut; chainLen[0] = leafLen; \
            SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 1u, trust, trustLen, 1u, \
                                                 SSF_X509_PURPOSE_CODE_SIGNING, NULL, \
                                                 1800000000ull, &_utVErr) == (_expect)); \
            _UT_VERR(_code, _idx); \
        } while (0)

        /* directoryName constraint: a leaf with a subject is rejected; with none, accepted */
        _X5094_ANCHOR(ncDirGood);
        _X5094_LEAF_BASE();
        p.subject.o = "Evil";
        p.subject.cn = "evil";
        _X5094_VERIFY(false, ERR_NAME_CONSTRAINTS, 0u);
        _X5094_LEAF_BASE();
        p.subject.o = "Good";
        _X5094_VERIFY(false, ERR_NAME_CONSTRAINTS, 0u);
        _X5094_LEAF_BASE();
        p.sanDNSNames = sanGood;
        _X5094_VERIFY(true, OK, 0u);

        /* rfc822Name constraint: an email SAN rejects; DNS-only and no subject is accepted */
        _X5094_ANCHOR(ncEmailGood);
        _X5094_LEAF_BASE();
        p.addRawExt = true; p.rawExtOid = sanOid; p.rawExtOidLen = sizeof(sanOid);
        p.rawExtValue = sanEmail; p.rawExtValueLen = sizeof(sanEmail);
        _X5094_VERIFY(false, ERR_NAME_CONSTRAINTS, 0u);
        _X5094_LEAF_BASE();
        p.sanDNSNames = sanGood;
        _X5094_VERIFY(true, OK, 0u);

        /* rfc822Name constraint, emailAddress RDN swapped in for an equal-length CN: rejected */
        _X5094_LEAF_BASE();
        p.subject.cn = "cccccccccccccc";
        SSF_ASSERT(SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen) == true);
        SSF_ASSERT(_utFind(tbsDer, tbsLen, rdnCN, sizeof(rdnCN), &at) == true);
        memcpy(&tbsDer[at], rdnEmail, sizeof(rdnEmail));
        SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
        SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, caPriv, _UT_PRIV_LEN, tbsHash, sizeof(tbsHash), sig,
                                   sizeof(sig), &sigLen) == true);
        SSF_ASSERT(SSFASN1EncOIDRaw(tbsHash, sizeof(tbsHash), ecdsaSha256Oid,
                                    sizeof(ecdsaSha256Oid), &w) == true);
        SSF_ASSERT(SSFASN1EncWrap(algId, sizeof(algId), SSF_ASN1_TAG_SEQUENCE, tbsHash, w,
                                  &algIdLen) == true);
        memcpy(certContent, tbsDer, tbsLen);
        n = tbsLen;
        memcpy(&certContent[n], algId, algIdLen);
        n += algIdLen;
        SSF_ASSERT(SSFASN1EncBitString(&certContent[n], sizeof(certContent) - n, sig,
                                       (uint32_t)sigLen, 0u, &w) == true);
        n += w;
        SSF_ASSERT(SSFASN1EncWrap(leafOut, sizeof(leafOut), SSF_ASN1_TAG_SEQUENCE, certContent,
                                  n, &leafLen) == true);
        chain[0] = leafOut;
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 1u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL,
                                             1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
        /* Control: the unpatched CN leaf carries no email instance, so it is accepted */
        _X5094_VERIFY(true, OK, 0u);

        /* URI constraint: a URI SAN rejects; DNS-only is accepted */
        _X5094_ANCHOR(ncUriGood);
        _X5094_LEAF_BASE();
        p.addRawExt = true; p.rawExtOid = sanOid; p.rawExtOidLen = sizeof(sanOid);
        p.rawExtValue = sanUri; p.rawExtValueLen = sizeof(sanUri);
        _X5094_VERIFY(false, ERR_NAME_CONSTRAINTS, 0u);
        _X5094_LEAF_BASE();
        p.sanDNSNames = sanGood;
        _X5094_VERIFY(true, OK, 0u);
        #undef _X5094_ANCHOR
        #undef _X5094_LEAF_BASE
        #undef _X5094_VERIFY
    }

    /* ---- AUDIT X509-5: an IP-literal hostname matches only iPAddress SANs ---- */
    {
        static uint8_t caOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static const uint8_t ip10Net[] = { 10u, 0u, 0u, 0u, 255u, 0u, 0u, 0u };
        static const uint8_t *ncIPs[] = { ip10Net, NULL };
        static const uint8_t ip10123[] = { 10u, 1u, 2u, 3u };
        static const uint8_t *sanIP10123[] = { ip10123, NULL };
        static const char *sanDns8888[] = { "8.8.8.8", NULL };
        static const char *sanWild001[] = { "*.0.0.1", NULL };
        static const char *sanDns10001[] = { "10.0.0.1", NULL };
        static const char *sanDnsV6[] = { "::1", NULL };
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t caPubLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x5Du };
        static SSFX509GenParams_t p;
        const uint8_t *chain[1];
        uint32_t chainLen[1];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t caLen;
        uint32_t leafLen;

        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPriv, sizeof(caPriv), caPub,
                                  sizeof(caPub), &caPubLen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);

        /* Anchor "ca" constrained to 10.0.0.0/8, with no DNS subtrees */
        _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "ca";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addNameConstraints = true;
        p.ncPermittedIPs = ncIPs;
        caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
        SSF_ASSERT(caLen != 0u);
        trust[0] = caOut;
        trustLen[0] = caLen;

        #define _X5095_CASE(_dns, _ips, _host, _expect, _code, _idx) do { \
            _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen); \
            p.issuer.cn = "ca"; \
            p.subject.cn = "leaf"; \
            p.sanDNSNames = (_dns); \
            p.sanIPAddrs = (_ips); \
            leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut)); \
            SSF_ASSERT(leafLen != 0u); \
            chain[0] = leafOut; \
            chainLen[0] = leafLen; \
            SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 1u, (_host), \
                                          1800000000ull, &_utVErr) == (_expect)); \
            _UT_VERR(_code, _idx); \
        } while (0)

        /* dNSName "8.8.8.8" escapes the IP constraint and must not match host 8.8.8.8 */
        _X5095_CASE(sanDns8888, NULL, "8.8.8.8", false, ERR_HOSTNAME, 0u);
        /* A proper iPAddress SAN inside the permitted range still matches */
        _X5095_CASE(NULL, sanIP10123, "10.1.2.3", true, OK, 0u);
        /* Wildcard and exact dNSNames that look like IPv4 never match an IP literal */
        _X5095_CASE(sanWild001, NULL, "10.0.0.1", false, ERR_HOSTNAME, 0u);
        _X5095_CASE(sanDns10001, NULL, "10.0.0.1", false, ERR_HOSTNAME, 0u);
        /* A hostname with ':' is an (unsupported) IPv6 literal, never a DNS name */
        _X5095_CASE(sanDnsV6, NULL, "::1", false, ERR_HOSTNAME, 0u);
        #undef _X5095_CASE
    }

    /* ---- COV-5: an IP exclusion that cannot be evaluated against a SAN rejects the SAN ---- */
    {
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t caOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static const uint8_t exclIP[] = { 192u, 168u, 0u, 0u, 255u, 255u, 0u, 0u };
        static const uint8_t *exclIPs[] = { exclIP, NULL };
        static const uint8_t ip10001[] = { 10u, 0u, 0u, 1u };
        static const uint8_t *sanIP10001[] = { ip10001, NULL };
        static const uint8_t sanOid[] = { 0x55u, 0x1Du, 0x11u };
        static const uint8_t ncOid[] = { 0x55u, 0x1Du, 0x1Eu };
        /* SubjectAltName { iPAddress [7] of 5 bytes } (neither IPv4 nor IPv6) */
        static const uint8_t san5[] = { 0x30u, 0x07u, 0x87u, 0x05u, 10u, 0u, 0u, 1u, 1u };
        /* NameConstraints { excludedSubtrees [1] { { iPAddress [7] of 7 bytes } } } */
        static const uint8_t ncExcl7[] = {
            0x30u, 0x0Du, 0xA1u, 0x0Bu, 0x30u, 0x09u, 0x87u, 0x07u,
            10u, 0u, 0u, 0u, 255u, 0u, 0u
        };
        size_t caPubLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x5Eu };
        static SSFX509GenParams_t p;
        const uint8_t *chain[1];
        uint32_t chainLen[1];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t caLen;
        uint32_t leafLen;
        uint8_t ca;

        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPriv, sizeof(caPriv), caPub,
                                  sizeof(caPub), &caPubLen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);

        /* ca 0: excludes 192.168.0.0/16 (8-byte subtree); ca 1: a 7-byte excluded subtree */
        for (ca = 0u; ca < 2u; ca++)
        {
            _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
            p.issuer.cn = "ca";
            p.subject.cn = "ca";
            p.addBasicConstraints = true;
            p.isCA = true;
            p.addKeyUsage = true;
            p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
            /* 8-byte excluded subtree CA? */
            if (ca == 0u)
            {
                /* Yes, exclude 192.168.0.0/16 */
                p.addNameConstraints = true;
                p.ncExcludedIPs = exclIPs;
            }
            else
            {
                /* No, raw Name Constraints with a 7-byte excluded subtree */
                p.addRawExt = true;
                p.rawExtOid = ncOid; p.rawExtOidLen = sizeof(ncOid);
                p.rawExtValue = ncExcl7; p.rawExtValueLen = sizeof(ncExcl7);
                p.rawExtCritical = true;
            }
            caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
            SSF_ASSERT(caLen != 0u);
            trust[0] = caOut;
            trustLen[0] = caLen;

            /* A well-formed IPv4 SAN outside 192.168/16: passes ca 0, refused by ca 1 */
            _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
            p.issuer.cn = "ca";
            p.subject.cn = "leaf";
            p.sanIPAddrs = sanIP10001;
            leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
            SSF_ASSERT(leafLen != 0u);
            chain[0] = leafOut;
            chainLen[0] = leafLen;
            /* 8-byte excluded subtree CA? */
            if (ca == 0u)
            {
                /* Yes, 10.0.0.1 is outside 192.168/16 */
                SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 1u, "10.0.0.1",
                                              1800000000ull, &_utVErr) == true);
                _UT_VERR(OK, 0u);
            }
            else
            {
                /* No, the 7-byte subtree is refused */
                SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 1u, "10.0.0.1",
                                              1800000000ull, &_utVErr) == false);
                _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
            }

            /* 8-byte excluded subtree CA? */
            if (ca == 0u)
            {
                /* Yes, a 5-byte iPAddress SAN cannot be ruled out by it, so it is refused */
                _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
                p.issuer.cn = "ca";
                p.subject.cn = "leaf";
                p.addRawExt = true;
                p.rawExtOid = sanOid; p.rawExtOidLen = sizeof(sanOid);
                p.rawExtValue = san5; p.rawExtValueLen = sizeof(san5);
                leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
                SSF_ASSERT(leafLen != 0u);
                chainLen[0] = leafLen;
                SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, trust, trustLen, 1u, "10.0.0.1",
                                              1800000000ull, &_utVErr) == false);
                _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
            }
        }
    }

    /* ---- A SAN GeneralName overrunning its SEQUENCE fails to parse instead of looping ---- */
    {
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t fakeSig[64];
        static const char *sanAB[] = { "ab", "cd", NULL };
        uint8_t serial[] = { 0x0Eu };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        uint32_t n;
        uint32_t i;

        memset(fakeSig, 0x66u, sizeof(fakeSig));
        memset(pubKey, 0x04u, sizeof(pubKey));
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.sanDNSNames = sanAB;
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.sanLen == 2u);

        for (i = 0; (i + 3u) < n; i++)
        {
            /* Is this the first dNSName "ab", to patch to declare 127 content bytes? */
            if ((out[i] == 0x82u) && (out[i + 1u] == 0x02u) && (out[i + 2u] == (uint8_t)'a') &&
                (out[i + 3u] == (uint8_t)'b'))
            {
                /* Yes */
                out[i + 1u] = 0x7Fu;
                break;
            }
        }
        SSF_ASSERT((i + 3u) < n);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);

        /* A length that overruns by exactly one byte is caught as well */
        out[i + 1u] = 0x07u;   /* "ab" + the 4-byte "cd" element leaves 6 bytes, not 7 */
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);

        /* Restoring the length makes it parse again */
        out[i + 1u] = 0x02u;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.sanLen == 2u);
    }

    /* ---- Preconditions: every public function asserts on NULL and out-of-range arguments ---- */
    {
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t fakeSig[64];
        static const uint8_t ip[4] = { 1u, 2u, 3u, 4u };
        const uint8_t *chain[SSF_X509_CONFIG_MAX_CHAIN_DEPTH + 1u];
        uint32_t chainLen[SSF_X509_CONFIG_MAX_CHAIN_DEPTH + 1u];
        const uint8_t *nullEntry[1];
        uint32_t nullEntryLen[1];
        uint8_t serial[] = { 0x10u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t c;
        uint32_t n;
        uint32_t i;
        uint64_t now;

        memset(pubKey, 0x04u, sizeof(pubKey));
        memset(fakeSig, 0x77u, sizeof(fakeSig));
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &c) == true);
        now = c.notBefore + 1u;
        for (i = 0; i <= SSF_X509_CONFIG_MAX_CHAIN_DEPTH; i++)
        {
            chain[i] = _utTestCertDER;
            chainLen[i] = sizeof(_utTestCertDER);
        }
        nullEntry[0] = NULL;
        nullEntryLen[0] = sizeof(_utTestCertDER);

        /* Parse and inspection */
        SSF_ASSERT_TEST(SSFX509Parse(NULL, sizeof(_utTestCertDER), &c));
        SSF_ASSERT_TEST(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), NULL));
        SSF_ASSERT_TEST(SSFX509IsValid(NULL, now));
        SSF_ASSERT_TEST(SSFX509IsSigECDSASHA256(NULL));
        SSF_ASSERT_TEST(SSFX509IsSigECDSASHA384(NULL));
        SSF_ASSERT_TEST(SSFX509IsKeyRSA(NULL));
        SSF_ASSERT_TEST(SSFX509IsKeyP256(NULL));
        SSF_ASSERT_TEST(SSFX509IsKeyP384(NULL));
        SSF_ASSERT_TEST(SSFX509IsSigRSAPSSSHA256(NULL));
        SSF_ASSERT_TEST(SSFX509IsSigRSAPSSSHA384(NULL));
        SSF_ASSERT_TEST(SSFX509IsSigRSAPKCS1SHA256(NULL));
        SSF_ASSERT_TEST(SSFX509IsSigRSAPKCS1SHA384(NULL));
        SSF_ASSERT_TEST(SSFX509IsSigRSAPKCS1SHA512(NULL));
        SSF_ASSERT_TEST(SSFX509IsSigEd25519(NULL));

        /* Verification helpers */
        SSF_ASSERT_TEST(SSFX509VerifyCertSignature(NULL, &c));
        SSF_ASSERT_TEST(SSFX509VerifyCertSignature(&c, NULL));
        SSF_ASSERT_TEST(SSFX509CheckSKIDAKID(NULL, &c));
        SSF_ASSERT_TEST(SSFX509CheckSKIDAKID(&c, NULL));
        SSF_ASSERT_TEST(SSFX509MatchIPAddress(NULL, ip, 4u));
        SSF_ASSERT_TEST(SSFX509MatchIPAddress("1.2.3.4", NULL, 4u));

        /* Generation: a NULL buffer is only legal with a size of 0 */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        SSF_ASSERT_TEST(SSFX509EncodeTBS(NULL, 1u, &p, &n));
        SSF_ASSERT_TEST(SSFX509EncodeTBS(out, sizeof(out), NULL, &n));
        SSF_ASSERT_TEST(SSFX509EncodeTBS(out, sizeof(out), &p, NULL));
        SSF_ASSERT_TEST(SSFX509EncodeCert(NULL, 1u, &p, fakeSig, sizeof(fakeSig), &n));
        SSF_ASSERT_TEST(SSFX509EncodeCert(out, sizeof(out), NULL, fakeSig, sizeof(fakeSig), &n));
        SSF_ASSERT_TEST(SSFX509EncodeCert(out, sizeof(out), &p, NULL, sizeof(fakeSig), &n));
        SSF_ASSERT_TEST(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), NULL));

        /* Chain verification */
        SSF_ASSERT_TEST(SSFX509VerifyChain(NULL, chainLen, 1u, chain, chainLen, 1u, "x", now,
                                           &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "x", now,
                                           NULL));
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, NULL, 1u, chain, chainLen, 1u, "x", now,
                                           &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, chainLen, 0u, chain, chainLen, 1u, "x", now,
                                           &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, chainLen, SSF_X509_CONFIG_MAX_CHAIN_DEPTH + 1u,
                                           chain, chainLen, 1u, "x", now, &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, chainLen, 1u, NULL, chainLen, 1u, "x", now,
                                           &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, chainLen, 1u, chain, NULL, 1u, "x", now,
                                           &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 0u, "x", now,
                                           &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, NULL, now,
                                           &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChain(nullEntry, nullEntryLen, 1u, chain, chainLen, 1u, "x",
                                           now, &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, chainLen, 1u, nullEntry, nullEntryLen, 1u,
                                           "test.ssf.local", now, &_utVErr));
    }

    /* ---- Malformed ext bodies, DN, SPKI, ext header: fail closed or fail the parse ---- */
    {
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t bcRootOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t bcRootPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t bcRootPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t bcRootPubLen;
        uint32_t bcRootLen;
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t fakeSig[64];
        static const uint8_t bcOid[] = { 0x55u, 0x1Du, 0x13u };
        static const uint8_t kuOid[] = { 0x55u, 0x1Du, 0x0Fu };
        static const uint8_t ekuOid[] = { 0x55u, 0x1Du, 0x25u };
        static const uint8_t sanOid[] = { 0x55u, 0x1Du, 0x11u };
        static const uint8_t skidOid[] = { 0x55u, 0x1Du, 0x0Eu };
        static const uint8_t akidOid[] = { 0x55u, 0x1Du, 0x23u };
        static const uint8_t ncOid[] = { 0x55u, 0x1Du, 0x1Eu };
        static const uint8_t notSeq[] = { 0x04u, 0x01u, 0xFFu };          /* OCTET STRING */
        static const uint8_t seqOverrun[] = { 0x30u, 0x03u, 0x01u, 0x01u }; /* claims 3, has 2 */
        static const uint8_t kuNotBits[] = { 0x04u, 0x02u, 0x01u, 0x80u };
        static const uint8_t ekuTruncOid[] = { 0x30u, 0x03u, 0x06u, 0x01u };
        static const uint8_t sanNotSeq[] = { 0x04u, 0x03u, 0x82u, 0x01u, 0x61u };
        static const uint8_t skidNotOctets[] = { 0x30u, 0x02u, 0x05u, 0x00u };
        static const uint8_t akidNotSeq[] = { 0x04u, 0x02u, 0xAAu, 0xBBu };
        static const uint8_t ncEmptyOctets[] = { 0x04u, 0x00u };
        static const uint8_t dnPattern[] = { 0x31u, 0x0Bu, 0x30u, 0x09u, 0x06u, 0x03u, 0x55u,
                                             0x04u, 0x03u, 0x0Cu, 0x02u, 0x75u, 0x74u };
        static const uint8_t spkiPattern[] = { 0x03u, 0x42u, 0x00u, 0x04u };
        static const uint8_t bcExtPattern[] = { 0x30u, 0x0Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x13u,
                                                0x01u, 0x01u, 0xFFu };
        static const char *sanX[] = { "x", NULL };
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t caPubLen;
        uint8_t serial[] = { 0x11u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        static SSFX509Cert_t issuer;
        const uint8_t *chain[2];
        uint32_t chainLen[2];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t n;
        uint32_t caLen;
        uint32_t at;

        memset(fakeSig, 0x88u, sizeof(fakeSig));
        memset(pubKey, 0x04u, sizeof(pubKey));

        /* Helper: encode p with one raw extension carrying the given body and parse it */
        #define _RAW_EXT_PARSE(_oid, _body, _crit) do { \
            _utGenBaseParams(&p, serial, pubKey, 65u); \
            p.addRawExt = true; \
            p.rawExtOid = (_oid); p.rawExtOidLen = sizeof(_oid); \
            p.rawExtValue = (_body); p.rawExtValueLen = sizeof(_body); \
            p.rawExtCritical = (_crit); \
            (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n); \
            SSF_ASSERT(n != 0u); \
            SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true); \
            SSF_ASSERT(parsed.extsLen == 1u); \
        } while (0)

        /* BC body not a SEQUENCE or overrunning: flag recorded, cA FALSE, pathLen absent */
        _RAW_EXT_PARSE(bcOid, notSeq, true);
        SSF_ASSERT((parsed.hasBasicConstraints == true) && (parsed.isCA == false));
        SSF_ASSERT(parsed.pathLenConstraint == -1);
        _RAW_EXT_PARSE(bcOid, seqOverrun, true);
        SSF_ASSERT((parsed.hasBasicConstraints == true) && (parsed.isCA == false));

        /* Key Usage body that is not a BIT STRING: present with no bits, so never keyCertSign */
        _RAW_EXT_PARSE(kuOid, kuNotBits, true);
        SSF_ASSERT((parsed.hasKeyUsage == true) && (parsed.keyUsageBits == 0u));

        /* EKU with a truncated OID: present with no purposes, so a leaf is rejected */
        _RAW_EXT_PARSE(ekuOid, ekuTruncOid, false);
        SSF_ASSERT((parsed.hasExtKeyUsage == true) && (parsed.ekuServerAuth == false));
        SSF_ASSERT((parsed.ekuClientAuth == false) && (parsed.ekuAnyPurpose == false));

        /* SAN body that is not a SEQUENCE: no names, so no hostname can match */
        _RAW_EXT_PARSE(sanOid, sanNotSeq, false);
        SSF_ASSERT(parsed.sanLen == 0u);

        /* SKID that is not an OCTET STRING and AKID that is not a SEQUENCE: both read as absent */
        _RAW_EXT_PARSE(skidOid, skidNotOctets, false);
        SSF_ASSERT((parsed.skid == NULL) && (parsed.skidLen == 0u));
        _RAW_EXT_PARSE(akidOid, akidNotSeq, false);
        SSF_ASSERT((parsed.akid == NULL) && (parsed.akidLen == 0u));
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &issuer) == true);
        SSF_ASSERT(SSFX509CheckSKIDAKID(&parsed, &issuer) == true);

        #undef _RAW_EXT_PARSE

        /* Name Constraints body not a SEQUENCE fails the parse (AUDIT X509-3) */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.addRawExt = true;
        p.rawExtOid = ncOid;
        p.rawExtOidLen = sizeof(ncOid);
        p.rawExtValue = ncEmptyOctets;
        p.rawExtValueLen = sizeof(ncEmptyOctets);
        p.rawExtCritical = true;
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);

        /* A CA with a malformed Basic Constraints body below a root cannot issue */
        SSF_ASSERT(_utMakeCA("root", serial, bcRootPriv, bcRootPub, &bcRootPubLen, bcRootOut,
                             sizeof(bcRootOut), &bcRootLen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPriv, sizeof(caPriv), caPub, sizeof(caPub),
                                  &caPubLen) == true);
        _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
        p.issuer.cn = "root";
        p.subject.cn = "ca";
        p.addRawExt = true;
        p.rawExtOid = bcOid;
        p.rawExtOidLen = sizeof(bcOid);
        p.rawExtValue = notSeq;
        p.rawExtValueLen = sizeof(notSeq);
        p.rawExtCritical = true;
        caLen = _utSignCert(&p, bcRootPriv, caOut, sizeof(caOut));
        SSF_ASSERT(caLen != 0u);
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.issuer.cn = "ca";
        p.subject.cn = "leaf";
        p.sanDNSNames = sanX;
        n = _utSignCert(&p, caPriv, out, sizeof(out));
        SSF_ASSERT(n != 0u);
        chain[0] = out;
        chainLen[0] = n;
        chain[1] = caOut;
        chainLen[1] = caLen;
        trust[0] = bcRootOut;
        trustLen[0] = bcRootLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "x",
                                      1800000000ull, &_utVErr) == false); _UT_VERR(ERR_NOT_CA, 1u);

        /* DN: a SET whose length overruns, or that is not a SET, fails the parse */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(_utFind(out, n, dnPattern, sizeof(dnPattern), &at) == true);
        out[at + 1u] = 0x0Cu;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);
        out[at + 1u] = 0x0Bu;
        out[at] = 0x30u;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);
        out[at] = 0x31u;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);

        /* SPKI: a public key BIT STRING whose length overruns fails the parse */
        SSF_ASSERT(_utFind(out, n, spkiPattern, sizeof(spkiPattern), &at) == true);
        out[at + 1u] = 0x43u;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);
        out[at + 1u] = 0x42u;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);

        /* Extension header: an Extension SEQUENCE whose length overruns fails the parse */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.addBasicConstraints = true;
        p.isCA = true;
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(_utFind(out, n, bcExtPattern, sizeof(bcExtPattern), &at) == true);
        out[at + 1u] = 0x10u;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);
        out[at + 1u] = 0x0Fu;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.isCA == true);
    }

    /* ---- Name Constraints imposed by an intermediate, not the anchor (RFC 5280 6.1.4 (g)) ---- */
    {
        static uint8_t rootOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t intOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t rootPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t intPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static const char *permitted[] = { "example.com", NULL };
        static const char *rootExcluded[] = { "a.example.com", NULL };
        static const char *sanIn[] = { "a.example.com", NULL };
        static const char *sanOut[] = { "evil.com", NULL };
        static const char *sanIntName[] = { "int.example.com", NULL };
        static const char *rootExcludesInt[] = { "int.example.com", NULL };
        static uint8_t rootPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t intPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t rootPubLen;
        size_t intPubLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x12u };
        static SSFX509GenParams_t p;
        const uint8_t *chain[2];
        uint32_t chainLen[2];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t rootLen;
        uint32_t intLen;
        uint32_t leafLen;

        /* Unconstrained root anchor */
        SSF_ASSERT(_utMakeCA("root", serial, rootPriv, rootPub, &rootPubLen, rootOut,
                             sizeof(rootOut), &rootLen) == true);
        trust[0] = rootOut;
        trustLen[0] = rootLen;

        /* Intermediate signed by root, permitting only example.com */
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, intPriv, sizeof(intPriv), intPub,
                                  sizeof(intPub), &intPubLen) == true);
        _utGenBaseParams(&p, serial, intPub, (uint32_t)intPubLen);
        p.issuer.cn = "root";
        p.subject.cn = "int";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addNameConstraints = true;
        p.ncPermittedDNS = permitted;
        intLen = _utSignCert(&p, rootPriv, intOut, sizeof(intOut));
        SSF_ASSERT(intLen != 0u);
        chain[1] = intOut;
        chainLen[1] = intLen;

        /* Leaf inside the intermediate's subtree is accepted */
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "int";
        p.subject.cn = "leaf";
        p.sanDNSNames = sanIn;
        leafLen = _utSignCert(&p, intPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chain[0] = leafOut;
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "a.example.com",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);

        /* Leaf outside it is rejected even though the anchor imposes nothing */
        p.sanDNSNames = sanOut;
        leafLen = _utSignCert(&p, intPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "evil.com",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);

        /* The anchor's exclusion reaches the leaf through the intermediate */
        SSF_ASSERT(_utMakeCA("root", serial, rootPriv, rootPub, &rootPubLen, rootOut,
                             sizeof(rootOut), &rootLen) == true);
        _utGenBaseParams(&p, serial, rootPub, (uint32_t)rootPubLen);
        p.issuer.cn = "root";
        p.subject.cn = "root";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addNameConstraints = true;
        p.ncExcludedDNS = rootExcluded;
        rootLen = _utSignCert(&p, rootPriv, rootOut, sizeof(rootOut));
        SSF_ASSERT(rootLen != 0u);
        trustLen[0] = rootLen;
        _utGenBaseParams(&p, serial, intPub, (uint32_t)intPubLen);
        p.issuer.cn = "root";
        p.subject.cn = "int";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        intLen = _utSignCert(&p, rootPriv, intOut, sizeof(intOut));
        SSF_ASSERT(intLen != 0u);
        chainLen[1] = intLen;
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "int";
        p.subject.cn = "leaf";
        p.sanDNSNames = sanIn;
        leafLen = _utSignCert(&p, intPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "a.example.com",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);

        /* The anchor's exclusion also applies to the intermediate's own SAN */
        _utGenBaseParams(&p, serial, rootPub, (uint32_t)rootPubLen);
        p.issuer.cn = "root";
        p.subject.cn = "root";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addNameConstraints = true;
        p.ncExcludedDNS = rootExcludesInt;
        rootLen = _utSignCert(&p, rootPriv, rootOut, sizeof(rootOut));
        SSF_ASSERT(rootLen != 0u);
        trustLen[0] = rootLen;
        _utGenBaseParams(&p, serial, intPub, (uint32_t)intPubLen);
        p.issuer.cn = "root";
        p.subject.cn = "int";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.sanDNSNames = sanIntName;
        intLen = _utSignCert(&p, rootPriv, intOut, sizeof(intOut));
        SSF_ASSERT(intLen != 0u);
        chainLen[1] = intLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "a.example.com",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 1u);
    }

    /* ---- Trace callback: failures report an ERROR with the reason, NULL disables tracing ---- */
    {
        const uint8_t *chain[1];
        uint32_t chainLen[1];
        static SSFX509Cert_t c;
        uint32_t before;
        int marker = 0;

        chain[0] = _utTestCertDER;
        chainLen[0] = sizeof(_utTestCertDER);
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &c) == true);

        _utTraceCount = 0;
        _utTraceErrors = 0;
        _utTraceLastMsg[0] = '\0';
        SSFX509SetTraceCtx(_utTrace, &marker);

        /* A hostname mismatch reports one ERROR in the CERT category naming the hostname */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "nope.test",
                                      c.notBefore + 1u, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);
        _UT_TRACE_ASSERT(_utTraceErrors == 1u);
        _UT_TRACE_ASSERT(_utTraceLastLevel == (int)SSF_TLS_TRACE_ERROR);
        _UT_TRACE_ASSERT(_utTraceLastCategory == (int)SSF_TLS_TRACE_CERT);
        _UT_TRACE_ASSERT(_utTraceLastCtx == (void *)&marker);
        _UT_TRACE_ASSERT(_utContains(_utTraceLastMsg, "nope.test") == true);

        /* An expired chain reports the validity failure */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "test.ssf.local",
                                      c.notAfter + 1u, &_utVErr) == false);
        _UT_VERR(ERR_EXPIRED, 0u);
        _UT_TRACE_ASSERT(_utTraceErrors == 2u);
        _UT_TRACE_ASSERT(_utContains(_utTraceLastMsg, "not valid") == true);

        /* A successful verification emits DEBUG traces and no ERROR */
        before = _utTraceCount;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "test.ssf.local",
                                      c.notBefore + 1u, &_utVErr) == true); _UT_VERR(OK, 0u);
        _UT_TRACE_ASSERT(_utTraceCount > before);
        _UT_TRACE_ASSERT(_utTraceErrors == 2u);
        _UT_TRACE_ASSERT(_utTraceLastLevel == (int)SSF_TLS_TRACE_DEBUG);

        /* NULL disables tracing: a failure is still a failure but produces no callback */
        SSFX509SetTraceCtx(NULL, NULL);
        before = _utTraceCount;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "nope.test",
                                      c.notBefore + 1u, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);
        _UT_TRACE_ASSERT(_utTraceCount == before);
    }

    /* ---- Validity edges: intermediate, anchor, inverted window, post-2049, UTCTime limit ---- */
    {
        static uint8_t rootOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t intOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t rootPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t intPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t fakeSig[64];
        static const char *sanX[] = { "x", NULL };
        static uint8_t rootPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t intPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t rootPubLen;
        size_t intPubLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x13u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        const uint8_t *chain[2];
        uint32_t chainLen[2];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t rootLen;
        uint32_t intLen;
        uint32_t leafLen;
        uint32_t n;
        const uint64_t now = 1800000000ull;

        memset(fakeSig, 0x99u, sizeof(fakeSig));
        SSF_ASSERT(_utMakeCA("root", serial, rootPriv, rootPub, &rootPubLen, rootOut,
                             sizeof(rootOut), &rootLen) == true);
        trust[0] = rootOut;
        trustLen[0] = rootLen;
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, intPriv, sizeof(intPriv), intPub,
                                  sizeof(intPub), &intPubLen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);

        /* Leaf valid at now, signed by the intermediate */
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "int";
        p.subject.cn = "leaf";
        p.sanDNSNames = sanX;
        leafLen = _utSignCert(&p, intPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        chain[0] = leafOut;
        chainLen[0] = leafLen;

        /* Intermediate that expired before now */
        _utGenBaseParams(&p, serial, intPub, (uint32_t)intPubLen);
        p.issuer.cn = "root";
        p.subject.cn = "int";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.notAfter = now - 1u;
        intLen = _utSignCert(&p, rootPriv, intOut, sizeof(intOut));
        SSF_ASSERT(intLen != 0u);
        chain[1] = intOut;
        chainLen[1] = intLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "x", now,
                                      &_utVErr) == false);
        _UT_VERR(ERR_EXPIRED, 1u);

        /* Intermediate not yet valid at now */
        p.notAfter = 2000000000ull;
        p.notBefore = now + 1u;
        intLen = _utSignCert(&p, rootPriv, intOut, sizeof(intOut));
        SSF_ASSERT(intLen != 0u);
        chainLen[1] = intLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "x", now,
                                      &_utVErr) == false);
        _UT_VERR(ERR_NOT_YET_VALID, 1u);

        /* The same intermediate inside its window verifies */
        p.notBefore = 1700000000ull;
        intLen = _utSignCert(&p, rootPriv, intOut, sizeof(intOut));
        SSF_ASSERT(intLen != 0u);
        chainLen[1] = intLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "x", now,
                                      &_utVErr) == true);
        _UT_VERR(OK, 0u);

        /* An expired trust anchor is skipped, so nothing anchors the chain */
        _utGenBaseParams(&p, serial, rootPub, (uint32_t)rootPubLen);
        p.issuer.cn = "root";
        p.subject.cn = "root";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.notAfter = now - 1u;
        rootLen = _utSignCert(&p, rootPriv, rootOut, sizeof(rootOut));
        SSF_ASSERT(rootLen != 0u);
        trustLen[0] = rootLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "x", now,
                                      &_utVErr) == false);
        _UT_VERR(ERR_UNKNOWN_CA, 1u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "x", now - 2u,
                                      &_utVErr)
                   == true); _UT_VERR(OK, 0u);

        /* notBefore after notAfter parses but is valid at no time */
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.notBefore = 2000000000ull;
        p.notAfter = 1700000000ull;
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.notBefore == 2000000000ull) && (parsed.notAfter == 1700000000ull));
        SSF_ASSERT(SSFX509IsValid(&parsed, 1700000000ull) == false);
        SSF_ASSERT(SSFX509IsValid(&parsed, now) == false);
        SSF_ASSERT(SSFX509IsValid(&parsed, 2000000000ull) == false);

        /* GeneralizedTime validity in 2050-2052 parses and is honored */
        SSF_ASSERT(_utBuildCertVariant(true, false, out, sizeof(out), &n) == true);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.notBefore == _UT_GT_NOT_BEFORE);
        SSF_ASSERT(parsed.notAfter == _UT_GT_NOT_AFTER);
        SSF_ASSERT(SSFX509IsValid(&parsed, _UT_GT_NOT_BEFORE) == true);
        SSF_ASSERT(SSFX509IsValid(&parsed, _UT_GT_NOT_AFTER) == true);
        SSF_ASSERT(SSFX509IsValid(&parsed, _UT_GT_NOT_BEFORE - 1u) == false);
        SSF_ASSERT(SSFX509IsValid(&parsed, _UT_GT_NOT_AFTER + 1u) == false);

        /* Generation emits UTCTime only, so a validity date past 2049 cannot be encoded */
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.notAfter = _UT_GT_NOT_BEFORE;
        SSF_ASSERT(SSFX509EncodeTBS(NULL, 0u, &p, &n) == false);
        SSF_ASSERT(n == 0u);
        SSF_ASSERT(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n) == false);
        SSF_ASSERT(n == 0u);
        p.notAfter = 2524607999ull;   /* 2049-12-31T23:59:59Z, the last UTCTime second */
        SSF_ASSERT(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n) == true);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.notAfter == 2524607999ull);
    }

    /* ---- Non-IPv4 iPAddress SANs never match; IPv6 subtrees enforced by address family ---- */
    {
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static const uint8_t sanOid[] = { 0x55u, 0x1Du, 0x11u };
        static const uint8_t ncOid[] = { 0x55u, 0x1Du, 0x1Eu };
        static const uint8_t sanV6[] = {
            0x30u, 0x12u, 0x87u, 0x10u,
            0x20u, 0x01u, 0x0Du, 0xB8u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
        };
        /* SubjectAltName { [2] "dual.test", [7] 2001:db8::1 } */
        static const uint8_t sanDnsV6[] = {
            0x30u, 0x1Du, 0x82u, 0x09u, 'd', 'u', 'a', 'l', '.', 't', 'e', 's', 't',
            0x87u, 0x10u,
            0x20u, 0x01u, 0x0Du, 0xB8u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
        };
        static const uint8_t sanZeroThenV4[] = {
            0x30u, 0x08u, 0x87u, 0x00u, 0x87u, 0x04u, 0x0Au, 0x00u, 0x00u, 0x01u
        };
        static const uint8_t ncPermitV6[] = {
            0x30u, 0x16u, 0xA0u, 0x14u, 0x30u, 0x12u, 0x87u, 0x10u,
            0x20u, 0x01u, 0x0Du, 0xB8u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        static const uint8_t ncExcludeV6[] = {
            0x30u, 0x16u, 0xA1u, 0x14u, 0x30u, 0x12u, 0x87u, 0x10u,
            0x20u, 0x01u, 0x0Du, 0xB8u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        static const uint8_t ip10[4] = { 10u, 0u, 0u, 1u };
        static const uint8_t *sanIPs[] = { ip10, NULL };
        static const char *sanDNS[] = { "x", NULL };
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t caPubLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x14u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        const uint8_t *chain[2];
        uint32_t chainLen[2];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t n;
        uint32_t caLen;

        /* A 16-byte iPAddress SAN is retained with its length but matches no hostname */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.addRawExt = true;
        p.rawExtOid = sanOid;
        p.rawExtOidLen = sizeof(sanOid);
        p.rawExtValue = sanV6;
        p.rawExtValueLen = sizeof(sanV6);
        n = _utSelfSign(&p, pubKey, sizeof(pubKey), out, sizeof(out));
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.sanLen == 1u) && (parsed.san[0].type == SSF_X509_SAN_IP));
        SSF_ASSERT(parsed.san[0].valLen == 16u);
        SSF_ASSERT(SSFX509MatchIPAddress("32.1.13.184", parsed.san[0].val, 16u) == false);
        chain[0] = out;
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "32.1.13.184",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "2001:db8::1",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);

        /* A cert also listing an IPv6 address parses and verifies by DNS; IPv6 never matches */
        p.rawExtValue = sanDnsV6;
        p.rawExtValueLen = sizeof(sanDnsV6);
        n = _utSelfSign(&p, pubKey, sizeof(pubKey), out, sizeof(out));
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.sanLen == 2u) && (parsed.san[1].valLen == 16u));
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "dual.test",
                                      1800000000ull, &_utVErr) == true);
        _UT_VERR(OK, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "2001:db8::1",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);

        /* A zero-length iPAddress is harmless and a following IPv4 entry still matches */
        p.rawExtValue = sanZeroThenV4;
        p.rawExtValueLen = sizeof(sanZeroThenV4);
        n = _utSelfSign(&p, pubKey, sizeof(pubKey), out, sizeof(out));
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.sanLen == 2u) && (parsed.san[0].valLen == 0u));
        SSF_ASSERT(parsed.san[1].valLen == 4u);
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "10.0.0.1",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "0.0.0.0",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);

        /* An IPv6-only permitted subtree rejects IPv4 iPAddress SANs, dNSName SANs stay free */
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPriv, sizeof(caPriv), caPub, sizeof(caPub),
                                  &caPubLen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);
        _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "ca";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addRawExt = true;
        p.rawExtOid = ncOid;
        p.rawExtOidLen = sizeof(ncOid);
        p.rawExtValue = ncPermitV6;
        p.rawExtValueLen = sizeof(ncPermitV6);
        p.rawExtCritical = true;
        caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
        SSF_ASSERT(caLen != 0u);
        SSF_ASSERT(SSFX509Parse(caOut, caLen, &parsed) == true);
        SSF_ASSERT((parsed.hasNameConstraints == true) && (parsed.permittedLen == 1u));
        SSF_ASSERT((parsed.permittedSubtrees[0].type == SSF_X509_SAN_IP) &&
                   (parsed.permittedSubtrees[0].valLen == 16u));
        trust[0] = caOut;
        trustLen[0] = caLen;
        chain[1] = caOut;
        chainLen[1] = caLen;
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "leaf";
        p.sanIPAddrs = sanIPs;
        n = _utSignCert(&p, caPriv, out, sizeof(out));
        SSF_ASSERT(n != 0u);
        chain[0] = out;
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "10.0.0.1",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
        p.sanIPAddrs = NULL;
        p.sanDNSNames = sanDNS;
        n = _utSignCert(&p, caPriv, out, sizeof(out));
        SSF_ASSERT(n != 0u);
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "x",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);

        /* An excluded IPv6 subtree never matches an IPv4 SAN, so it is accepted */
        _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "ca";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addRawExt = true;
        p.rawExtOid = ncOid;
        p.rawExtOidLen = sizeof(ncOid);
        p.rawExtValue = ncExcludeV6;
        p.rawExtValueLen = sizeof(ncExcludeV6);
        p.rawExtCritical = true;
        caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
        SSF_ASSERT(caLen != 0u);
        trustLen[0] = caLen;
        chainLen[1] = caLen;
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "leaf";
        p.sanIPAddrs = sanIPs;
        n = _utSignCert(&p, caPriv, out, sizeof(out));
        SSF_ASSERT(n != 0u);
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "10.0.0.1",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);
    }

    /* ---- Chain depth: the configured maximum verifies, one more is a precondition ---- */
    {
        static uint8_t der[SSF_X509_CONFIG_MAX_CHAIN_DEPTH][SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t rootOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t priv[SSF_X509_CONFIG_MAX_CHAIN_DEPTH][SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t pub[SSF_X509_CONFIG_MAX_CHAIN_DEPTH][SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static size_t pubLen[SSF_X509_CONFIG_MAX_CHAIN_DEPTH];
        static char cn[SSF_X509_CONFIG_MAX_CHAIN_DEPTH][4];
        static uint8_t rootPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static const char *sanDeep[] = { "deep.test", NULL };
        static uint8_t rootPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t rootPubLen;
        uint8_t serial[] = { 0x15u };
        static SSFX509GenParams_t p;
        const uint8_t *chain[SSF_X509_CONFIG_MAX_CHAIN_DEPTH + 1u];
        uint32_t chainLen[SSF_X509_CONFIG_MAX_CHAIN_DEPTH + 1u];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t rootLen;
        uint32_t k;

#if SSF_X509_CONFIG_MAX_CHAIN_DEPTH > 10
#error "This test names chain certificates with one digit"
#endif
        SSF_ASSERT(_utMakeCA("root", serial, rootPriv, rootPub, &rootPubLen, rootOut,
                             sizeof(rootOut), &rootLen) == true);
        trust[0] = rootOut;
        trustLen[0] = rootLen;

        /* cert[k] is issued by cert[k + 1]; the last one is issued by the root */
        for (k = 0; k < SSF_X509_CONFIG_MAX_CHAIN_DEPTH; k++)
        {
            cn[k][0] = 'c';
            cn[k][1] = 'a';
            cn[k][2] = (char)('0' + k);
            cn[k][3] = '\0';
            SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, priv[k], SSF_ECDSA_MAX_PRIV_KEY_SIZE,
                                      pub[k], SSF_ECDSA_MAX_PUB_KEY_SIZE, &pubLen[k]) == true);
        }
        for (k = SSF_X509_CONFIG_MAX_CHAIN_DEPTH; k > 0u; k--)
        {
            uint32_t idx = k - 1u;
            uint32_t len;

            _utGenBaseParams(&p, serial, pub[idx], (uint32_t)pubLen[idx]);
            p.issuer.cn = (k == SSF_X509_CONFIG_MAX_CHAIN_DEPTH) ? "root" : cn[k];
            p.subject.cn = cn[idx];
            /* CA on the chain? */
            if (idx > 0u)
            {
                /* Yes, cA and keyCertSign */
                p.addBasicConstraints = true;
                p.isCA = true;
                p.addKeyUsage = true;
                p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
            }
            else
            {
                /* No, the leaf with its SAN */
                p.sanDNSNames = sanDeep;
            }
            len = _utSignCert(&p, (k == SSF_X509_CONFIG_MAX_CHAIN_DEPTH) ? rootPriv : priv[k],
                              der[idx], SSF_X509_CONFIG_MAX_CERT_SIZE);
            SSF_ASSERT(len != 0u);
            chain[idx] = der[idx];
            chainLen[idx] = len;
        }
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, SSF_X509_CONFIG_MAX_CHAIN_DEPTH, trust,
                                      trustLen, 1u, "deep.test", 1800000000ull, &_utVErr) == true);
        _UT_VERR(OK, 0u);

        /* One certificate more than the configured depth is a contract violation */
        chain[SSF_X509_CONFIG_MAX_CHAIN_DEPTH] = rootOut;
        chainLen[SSF_X509_CONFIG_MAX_CHAIN_DEPTH] = rootLen;
        SSF_ASSERT_TEST(SSFX509VerifyChain(chain, chainLen, SSF_X509_CONFIG_MAX_CHAIN_DEPTH + 1u,
                                           trust, trustLen, 1u, "deep.test", 1800000000ull,
                                               &_utVErr));

        /* Dropping the top intermediate breaks the link to the root */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, SSF_X509_CONFIG_MAX_CHAIN_DEPTH - 1u, trust,
                                      trustLen, 1u, "deep.test", 1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_UNKNOWN_CA, SSF_X509_CONFIG_MAX_CHAIN_DEPTH - 2u);
    }

    /* ---- Path building (RFC 8446 4.4.2): extras, any order after leaf, ends at anchor ---- */
    {
        enum { R_ROOT, R_OLD, R_OTHER, R_INT1, R_INT2, R_INT2W, R_LEAF, R_CROSS, R_CROSSX, R_JUNK,
               R_LA, R_LB, R_LEAFL, R_INT2S, R_INT2WS, R_LEAFK, R_INT2N, R_INT2KU, R_INT1P0,
               R_INT1NC, R_INT2J, R_LEAFE, R_LEAFKU, R_BAD, R_INT1NC2, R_INT2SAN, R_N };
        static uint8_t der[R_N][SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint32_t len[R_N];
        static uint8_t priv[R_N][SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t pub[R_N][SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static size_t pubLen[R_N];
        static const char *san[] = { "path.test", NULL };
        static const char *ncExcl[] = { "path.test", NULL };
        static const char *ncExcl2[] = { "bad.test", NULL };
        static const char *sanBad[] = { "bad.test", NULL };
        static const uint8_t junkOid[] = { 0x2Bu, 0x06u, 0x01u, 0x04u, 0x01u, 0x83u, 0xB2u, 0x03u };
        static const uint8_t junkVal[] = { 0x05u, 0x00u };
        static const uint8_t idA[] = { 0xAAu };
        static const uint8_t idB[] = { 0xBBu };
        static SSFX509GenParams_t p;
        uint8_t serial[] = { 0x16u };
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t k;

        /* Self-signed CAs: root is the only trust anchor */
        SSF_ASSERT(_utMakeCA("root", serial, priv[R_ROOT], pub[R_ROOT], &pubLen[R_ROOT],
                             der[R_ROOT], sizeof(der[R_ROOT]), &len[R_ROOT]));
        SSF_ASSERT(_utMakeCA("old", serial, priv[R_OLD], pub[R_OLD], &pubLen[R_OLD],
                             der[R_OLD], sizeof(der[R_OLD]), &len[R_OLD]));
        SSF_ASSERT(_utMakeCA("other", serial, priv[R_OTHER], pub[R_OTHER], &pubLen[R_OTHER],
                             der[R_OTHER], sizeof(der[R_OTHER]), &len[R_OTHER]));
        trust[0] = der[R_ROOT];
        trustLen[0] = len[R_ROOT];
        for (k = R_INT1; k < R_N; k++)
        {
            SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, priv[k], SSF_ECDSA_MAX_PRIV_KEY_SIZE, pub[k],
                                      SSF_ECDSA_MAX_PUB_KEY_SIZE, &pubLen[k]));
        }

        /* Issues cert k (subject subj, CA unless it carries a SAN) with key keyIdx's key */
        #define _UT_PATH_CERT(k, subj, iss, signer, keyIdx, isLeaf) do { \
            _utGenBaseParams(&p, serial, pub[keyIdx], (uint32_t)pubLen[keyIdx]); \
            p.subject.cn = (subj); p.issuer.cn = (iss); \
            if (isLeaf) { p.sanDNSNames = san; } \
            else { p.addBasicConstraints = true; p.isCA = true; p.addKeyUsage = true; \
                   p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN; } \
            _utPathTweak(&p, (k)); \
            len[k] = _utSignCert(&p, priv[signer], der[k], sizeof(der[k])); \
            SSF_ASSERT(len[k] != 0u); } while (0)
        #define _utPathTweak(pp, k) do { \
            if ((k) == R_CROSSX) (pp)->notAfter = 1750000000ull; \
            if ((k) == R_JUNK) { (pp)->addRawExt = true; (pp)->rawExtOid = junkOid; \
                (pp)->rawExtOidLen = sizeof(junkOid); (pp)->rawExtValue = junkVal; \
                (pp)->rawExtValueLen = sizeof(junkVal); (pp)->rawExtCritical = true; } \
            if ((k) == R_INT2S) { (pp)->skid = idA; (pp)->skidLen = 1u; } \
            if ((k) == R_INT2WS) { (pp)->skid = idB; (pp)->skidLen = 1u; } \
            if ((k) == R_LEAFK) { (pp)->akid = idA; (pp)->akidLen = 1u; } \
            if ((k) == R_INT2N) (pp)->isCA = false; \
            if ((k) == R_INT2KU) (pp)->keyUsageBits = SSF_X509_KU_DIGITAL_SIGNATURE; \
            if ((k) == R_INT1P0) (pp)->pathLenConstraint = 0; \
            if ((k) == R_INT1NC) { (pp)->addNameConstraints = true; \
                (pp)->ncExcludedDNS = ncExcl; } \
            if ((k) == R_INT2J) { (pp)->addRawExt = true; (pp)->rawExtOid = junkOid; \
                (pp)->rawExtOidLen = sizeof(junkOid); (pp)->rawExtValue = junkVal; \
                (pp)->rawExtValueLen = sizeof(junkVal); (pp)->rawExtCritical = true; } \
            if ((k) == R_LEAFE) { (pp)->addExtKeyUsage = true; (pp)->ekuClientAuth = true; } \
            if ((k) == R_LEAFKU) { (pp)->addKeyUsage = true; \
                (pp)->keyUsageBits = SSF_X509_KU_KEY_AGREEMENT; } \
            if ((k) == R_INT1NC2) { (pp)->addNameConstraints = true; \
                (pp)->ncExcludedDNS = ncExcl2; } \
            if ((k) == R_INT2SAN) (pp)->sanDNSNames = sanBad; } while (0)

        _UT_PATH_CERT(R_INT1, "int1", "root", R_ROOT, R_INT1, false);
        _UT_PATH_CERT(R_INT2, "int2", "int1", R_INT1, R_INT2, false);
        _UT_PATH_CERT(R_INT2W, "int2", "int1", R_INT1, R_INT2W, false);  /* Same name, other key */
        _UT_PATH_CERT(R_LEAF, "leaf", "int2", R_INT2, R_LEAF, true);
        _UT_PATH_CERT(R_CROSS, "root", "old", R_OLD, R_ROOT, false);     /* Root key, cross-sign */
        _UT_PATH_CERT(R_CROSSX, "root", "old", R_OLD, R_ROOT, false);    /* ... and expired */
        _UT_PATH_CERT(R_JUNK, "junk", "other", R_OTHER, R_JUNK, false);  /* Unknown critical ext */
        _UT_PATH_CERT(R_LA, "la", "lb", R_LB, R_LA, false);              /* la and lb issue each */
        _UT_PATH_CERT(R_LB, "lb", "la", R_LA, R_LB, false);              /* other: a loop */
        _UT_PATH_CERT(R_LEAFL, "leaf", "la", R_LA, R_LEAFL, true);
        _UT_PATH_CERT(R_INT2S, "int2", "int1", R_INT1, R_INT2, false);   /* SKID AA */
        _UT_PATH_CERT(R_INT2WS, "int2", "int1", R_INT1, R_INT2W, false); /* SKID BB, other key */
        _UT_PATH_CERT(R_LEAFK, "leaf", "int2", R_INT2, R_LEAFK, true);   /* AKID AA */
        _UT_PATH_CERT(R_INT2N, "int2", "int1", R_INT1, R_INT2, false);   /* cA FALSE */
        _UT_PATH_CERT(R_INT2KU, "int2", "int1", R_INT1, R_INT2, false);  /* No keyCertSign */
        _UT_PATH_CERT(R_INT1P0, "int1", "root", R_ROOT, R_INT1, false);  /* pathLen 0 */
        _UT_PATH_CERT(R_INT1NC, "int1", "root", R_ROOT, R_INT1, false);  /* Excludes path.test */
        _UT_PATH_CERT(R_INT2J, "int2", "int1", R_INT1, R_INT2, false);   /* Unknown critical ext */
        _UT_PATH_CERT(R_LEAFE, "leaf", "int2", R_INT2, R_LEAFE, true);   /* EKU clientAuth only */
        _UT_PATH_CERT(R_LEAFKU, "leaf", "int2", R_INT2, R_LEAFKU, true); /* KU keyAgreement */
        _UT_PATH_CERT(R_INT1NC2, "int1", "root", R_ROOT, R_INT1, false); /* Excludes bad.test */
        _UT_PATH_CERT(R_INT2SAN, "int2", "int1", R_INT1, R_INT2, false); /* SAN bad.test */
        memcpy(der[R_BAD], der[R_INT2], len[R_INT2]);                    /* Truncated: no parse */
        len[R_BAD] = len[R_INT2] - 1u;
        #undef _UT_PATH_CERT
        #undef _utPathTweak

        /* Verifies the chain of the listed certificates and checks the reported result */
        #define _UT_PATH(_ok, _c, _i, ...) do { \
            static const uint8_t _ids[] = { __VA_ARGS__ }; \
            const uint8_t *_ch[sizeof(_ids)]; uint32_t _cl[sizeof(_ids)]; uint32_t _j; \
            for (_j = 0; _j < sizeof(_ids); _j++) \
            { _ch[_j] = der[_ids[_j]]; _cl[_j] = len[_ids[_j]]; } \
            SSF_ASSERT(SSFX509VerifyChain(_ch, _cl, (uint8_t)sizeof(_ids), trust, trustLen, 1u, \
                                          "path.test", 1800000000ull, &_utVErr) == (_ok)); \
            _UT_VERR(_c, _i); } while (0)

        _UT_PATH(true, OK, 0u, R_LEAF, R_INT2, R_INT1);                     /* In order */
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT2, R_INT1, R_ROOT);             /* Root sent */
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT2, R_INT1, R_CROSS);            /* "Long chain" */
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT2, R_INT1, R_CROSSX);           /* ... expired extra */
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT2, R_INT1, R_OTHER);            /* Unrelated extra */
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT2, R_INT1, R_JUNK);             /* Unused crit. ext */
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT1, R_INT2);                     /* Out of order */
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT1, R_OTHER, R_INT2);
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT2, R_INT2, R_INT1);             /* Duplicate */
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT2W, R_INT2, R_INT1);            /* Same-name decoy */
        _UT_PATH(true, OK, 0u, R_LEAFK, R_INT2WS, R_INT2S, R_INT1);         /* Key ids pick int2 */
        _UT_PATH(false, ERR_UNKNOWN_CA, 1u, R_LEAF, R_INT2);                /* int1 missing */
        _UT_PATH(false, ERR_UNKNOWN_CA, 2u, R_LEAFL, R_LA, R_LB);           /* A loop ends */
        _UT_PATH(false, ERR_SIGNATURE, 0u, R_LEAF, R_INT2W, R_INT1);        /* Only the decoy */
        _UT_PATH(false, ERR_KEY_ID_MISMATCH, 0u, R_LEAFK, R_INT2WS, R_INT1); /* Key id rules out */
        _UT_PATH(true, OK, 0u, R_LEAF, R_BAD, R_INT2, R_INT1);              /* Unparsable extra */

        /* Post-build checks name the chain index, not the path position, of an out-of-order cert */
        _UT_PATH(false, ERR_NOT_CA, 3u, R_LEAF, R_OTHER, R_INT1, R_INT2N);
        _UT_PATH(false, ERR_CA_KEY_USAGE, 3u, R_LEAF, R_OTHER, R_INT1, R_INT2KU);
        _UT_PATH(false, ERR_PATH_LEN, 1u, R_LEAF, R_INT1P0, R_OTHER, R_INT2);
        _UT_PATH(false, ERR_NAME_CONSTRAINTS, 0u, R_LEAF, R_INT1NC, R_OTHER, R_INT2);
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT1NC2, R_OTHER, R_INT2);         /* NC control */
        _UT_PATH(true, OK, 0u, R_LEAF, R_INT1, R_OTHER, R_INT2SAN);         /* SAN control */
        _UT_PATH(false, ERR_NAME_CONSTRAINTS, 3u, R_LEAF, R_INT1NC2, R_OTHER, R_INT2SAN);
        _UT_PATH(false, ERR_CRITICAL_EXT, 3u, R_LEAF, R_OTHER, R_INT1, R_INT2J);
        _UT_PATH(false, ERR_EKU, 0u, R_LEAFE, R_OTHER, R_INT1, R_INT2);
        _UT_PATH(true, OK, 0u, R_LEAFKU, R_OTHER, R_INT1, R_INT2);          /* KU: server auth */

        /* The same chains for code signing: the leaf's Key Usage now counts, and no hostname */
        #define _UT_PATH_CS(_ok, _c, _i, ...) do { \
            static const uint8_t _ids[] = { __VA_ARGS__ }; \
            const uint8_t *_ch[sizeof(_ids)]; uint32_t _cl[sizeof(_ids)]; uint32_t _j; \
            for (_j = 0; _j < sizeof(_ids); _j++) \
            { _ch[_j] = der[_ids[_j]]; _cl[_j] = len[_ids[_j]]; } \
            SSF_ASSERT(SSFX509VerifyChainPurpose(_ch, _cl, (uint8_t)sizeof(_ids), trust, \
                                                 trustLen, 1u, SSF_X509_PURPOSE_CODE_SIGNING, \
                                                 NULL, 1800000000ull, &_utVErr) == (_ok)); \
            _UT_VERR(_c, _i); } while (0)
        _UT_PATH_CS(true, OK, 0u, R_LEAF, R_OTHER, R_INT1, R_INT2);
        _UT_PATH_CS(false, ERR_LEAF_KEY_USAGE, 0u, R_LEAFKU, R_OTHER, R_INT1, R_INT2);
        _UT_PATH_CS(false, ERR_EKU, 0u, R_LEAFE, R_OTHER, R_INT1, R_INT2);
        _UT_PATH_CS(false, ERR_NAME_CONSTRAINTS, 0u, R_LEAF, R_INT1NC, R_OTHER, R_INT2);
        #undef _UT_PATH_CS
        #undef _UT_PATH
    }

    /* ---- SAN cap: more than SSF_X509_CONFIG_MAX_SAN_ENTRIES SANs fails to parse (X509-16) ---- */
    {
        static uint8_t caOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static char names[SSF_X509_CONFIG_MAX_SAN_ENTRIES][12];
        static const char *sans[SSF_X509_CONFIG_MAX_SAN_ENTRIES + 2u];
        static const char *excl[] = { "evil.com", NULL };
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t caPubLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x16u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        const uint8_t *chain[2];
        uint32_t chainLen[2];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        uint32_t caLen;
        uint32_t leafLen;
        uint32_t k;

#if SSF_X509_CONFIG_MAX_SAN_ENTRIES > 10
#error "This test names SAN entries with one digit"
#endif
        for (k = 0; k < SSF_X509_CONFIG_MAX_SAN_ENTRIES; k++)
        {
            names[k][0] = 'n';
            names[k][1] = (char)('0' + k);
            names[k][2] = '.';
            names[k][3] = 'o';
            names[k][4] = 'k';
            names[k][5] = '.';
            names[k][6] = 'c';
            names[k][7] = 'o';
            names[k][8] = 'm';
            names[k][9] = '\0';
            sans[k] = names[k];
        }
        sans[SSF_X509_CONFIG_MAX_SAN_ENTRIES] = "evil.com";
        sans[SSF_X509_CONFIG_MAX_SAN_ENTRIES + 1u] = NULL;

        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, caPriv, sizeof(caPriv), caPub, sizeof(caPub),
                                  &caPubLen) == true);
        _utGenBaseParams(&p, serial, caPub, (uint32_t)caPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "ca";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addNameConstraints = true;
        p.ncExcludedDNS = excl;
        caLen = _utSignCert(&p, caPriv, caOut, sizeof(caOut));
        SSF_ASSERT(caLen != 0u);
        trust[0] = caOut;
        trustLen[0] = caLen;
        chain[1] = caOut;
        chainLen[1] = caLen;

        /* The (MAX + 1)th SAN is excluded: the leaf no longer parses, so the chain fails */
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "leaf";
        p.sanDNSNames = sans;
        leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        SSF_ASSERT(SSFX509Parse(leafOut, leafLen, &parsed) == false);
        chain[0] = leafOut;
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, names[0],
                                      1800000000ull, &_utVErr) == false); _UT_VERR(ERR_PARSE, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "evil.com",
                                      1800000000ull, &_utVErr) == false); _UT_VERR(ERR_PARSE, 0u);

        /* Excluded name first within capacity: leaf parses, anchor constraint rejects any host */
        sans[0] = "evil.com";
        sans[SSF_X509_CONFIG_MAX_SAN_ENTRIES] = NULL;            /* Exactly MAX_SAN_ENTRIES */
        leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut));
        SSF_ASSERT(leafLen != 0u);
        SSF_ASSERT(SSFX509Parse(leafOut, leafLen, &parsed) == true);
        SSF_ASSERT(parsed.sanLen == SSF_X509_CONFIG_MAX_SAN_ENTRIES);
        chainLen[0] = leafLen;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, names[1],
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);
    }

    /* ---- Parser branches: AKID, unique IDs, critical FALSE, BC, KU, unused bits, sigAlg ---- */
    {
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t fakeSig[64];
        static const uint8_t akidOid[] = { 0x55u, 0x1Du, 0x23u };
        static const uint8_t bcOid[] = { 0x55u, 0x1Du, 0x13u };
        static const uint8_t unknownOid[] = { 0x55u, 0x1Du, 0x40u };
        static const uint8_t akidIssuerOnly[] = {
            0x30u, 0x06u, 0xA1u, 0x04u, 0x82u, 0x02u, 0x63u, 0x61u
        };
        static const uint8_t akidKeyAndIssuer[] = {
            0x30u, 0x0Au, 0x80u, 0x02u, 0xAAu, 0xBBu, 0xA1u, 0x04u, 0x82u, 0x02u, 0x63u, 0x61u
        };
        static const uint8_t bcPathLenNoCA[] = { 0x30u, 0x03u, 0x02u, 0x01u, 0x00u };
        static const uint8_t nullValue[] = { 0x05u, 0x00u };
        static const uint8_t critTruePattern[] = { 0x06u, 0x03u, 0x55u, 0x1Du, 0x40u, 0x01u,
                                                   0x01u, 0xFFu };
        static const uint8_t spkiPattern[] = { 0x03u, 0x42u, 0x00u, 0x04u };
        static const uint8_t sigPattern[] = { 0x03u, 0x41u, 0x00u, 0x66u, 0x66u };
        static const uint8_t sha1WithRSA[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x05u
        };
        static const char *sanX[] = { "x", NULL };
        uint8_t serial[] = { 0x17u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        static SSFX509Cert_t issuer;
        const uint8_t *chain[1];
        uint32_t chainLen[1];
        uint32_t n;
        uint32_t at;

        memset(fakeSig, 0x66u, sizeof(fakeSig));
        memset(pubKey, 0x04u, sizeof(pubKey));
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &issuer) == true);

        /* AKID in authorityCertIssuer form only: read as absent, so the SKID check passes */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.addRawExt = true;
        p.rawExtOid = akidOid;
        p.rawExtOidLen = sizeof(akidOid);
        p.rawExtValue = akidIssuerOnly;
        p.rawExtValueLen = sizeof(akidIssuerOnly);
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.akid == NULL) && (parsed.akidLen == 0u));
        SSF_ASSERT(SSFX509CheckSKIDAKID(&parsed, &issuer) == true);

        /* AKID with keyIdentifier followed by authorityCertIssuer: the identifier is read */
        p.rawExtValue = akidKeyAndIssuer;
        p.rawExtValueLen = sizeof(akidKeyAndIssuer);
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.akidLen == 2u) && (parsed.akid[0] == 0xAAu));
        SSF_ASSERT(parsed.akid[1] == 0xBBu);
        SSF_ASSERT(SSFX509CheckSKIDAKID(&parsed, &issuer) == false);

        /* issuerUniqueID and subjectUniqueID are skipped and the extensions after them parse */
        SSF_ASSERT(_utBuildCertVariant(false, true, out, sizeof(out), &n) == true);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.version == 2u) && (parsed.extsLen == 1u));
        SSF_ASSERT(parsed.exts[0].oidRawLen == 3u);
        SSF_ASSERT(parsed.exts[0].oidRaw[2] == 0x40u);
        SSF_ASSERT(_utBuildCertVariant(false, false, out, sizeof(out), &n) == true);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(parsed.extsLen == 1u);

        /* AUDIT X509-1: a unique ID whose length overruns the TBS fails, not loops forever */
        {
            static const uint8_t issuerUid[] = { 0x81u, 0x02u, 0x00u, 0xAAu };
            static const uint8_t subjectUid[] = { 0x82u, 0x02u, 0x00u, 0xBBu };

            SSF_ASSERT(_utBuildCertVariant(false, true, out, sizeof(out), &n) == true);
            SSF_ASSERT(_utFind(out, n, issuerUid, sizeof(issuerUid), &at) == true);
            out[at + 1u] = 0x7Fu;
            SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);

            SSF_ASSERT(_utBuildCertVariant(false, true, out, sizeof(out), &n) == true);
            SSF_ASSERT(_utFind(out, n, subjectUid, sizeof(subjectUid), &at) == true);
            out[at + 1u] = 0x7Fu;
            SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);
        }

        /* An explicitly encoded critical FALSE reads as non-critical */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.addRawExt = true;
        p.rawExtOid = unknownOid;
        p.rawExtOidLen = sizeof(unknownOid);
        p.rawExtValue = nullValue;
        p.rawExtValueLen = sizeof(nullValue);
        p.rawExtCritical = true;
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.extsLen == 1u) && (parsed.exts[0].critical == true));
        SSF_ASSERT(_utFind(out, n, critTruePattern, sizeof(critTruePattern), &at) == true);
        out[at + sizeof(critTruePattern) - 1u] = 0x00u;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.extsLen == 1u) && (parsed.exts[0].critical == false));

        /* Basic Constraints with pathLenConstraint but no cA: not a CA, pathLen still read */
        p.rawExtOid = bcOid;
        p.rawExtOidLen = sizeof(bcOid);
        p.rawExtValue = bcPathLenNoCA;
        p.rawExtValueLen = sizeof(bcPathLenNoCA);
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.hasBasicConstraints == true) && (parsed.isCA == false));
        SSF_ASSERT(parsed.pathLenConstraint == 0);

        /* An empty Key Usage bit string is present with no bits */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.addKeyUsage = true;
        p.keyUsageBits = 0u;
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.hasKeyUsage == true) && (parsed.keyUsageBits == 0u));

        /* Nonzero unused bits on the public key or signature fail the parse (AUDIT ASN1-5) */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.pubKeyUnusedBits == 0u) && (parsed.signatureUnusedBits == 0u));
        SSF_ASSERT(_utFind(out, n, spkiPattern, sizeof(spkiPattern), &at) == true);
        out[at + 2u] = 0x03u;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);
        out[at + 2u] = 0x00u;
        SSF_ASSERT(_utFind(out, n, sigPattern, sizeof(sigPattern), &at) == true);
        out[at + 2u] = 0x02u;
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == false);

        /* An unsupported signature algorithm parses but never verifies */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.sigAlgOidRaw = sha1WithRSA;
        p.sigAlgOidRawLen = sizeof(sha1WithRSA);
        p.sanDNSNames = sanX;
        n = _utSelfSign(&p, pubKey, sizeof(pubKey), out, sizeof(out));
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((SSFX509IsSigECDSASHA256(&parsed) == false) &&
                   (SSFX509IsSigECDSASHA384(&parsed) == false));
        SSF_ASSERT((SSFX509IsSigRSAPKCS1SHA256(&parsed) == false) &&
                   (SSFX509IsSigRSAPKCS1SHA384(&parsed) == false));
        SSF_ASSERT((SSFX509IsSigRSAPKCS1SHA512(&parsed) == false) &&
                   (SSFX509IsSigRSAPSSSHA256(&parsed) == false));
        SSF_ASSERT(SSFX509IsSigEd25519(&parsed) == false);
        SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == false);
        chain[0] = out;
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "x",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_UNKNOWN_CA, 0u);
    }

    /* ---- Key and algorithm mismatches, and RSA-PSS parameter edges ---- */
    {
        static const uint8_t ed25519Oid[] = { 0x2Bu, 0x65u, 0x70u };
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t fakeSig[64];
        static uint8_t fakeKey32[32];
        uint8_t serial[] = { 0x18u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        uint32_t n;
#if _UT_RSA_PSS_SIGN == 1
        static const uint8_t rsaPssOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Au
        };
        static const uint8_t rsaPubKeyOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
        };
        /* RSASSA-PSS-params { [0] sha256, [1] mgf1-sha256, [2] saltLength 32 } */
        static const uint8_t pssSalt32[] = {
            0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u,
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            /* [1] maskGenAlgorithm MGF1-SHA-256 */
            0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
            0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
            0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            0xA2u, 0x03u, 0x02u, 0x01u, 0x20u
        };
        /* saltLength -1: not a valid unsigned INTEGER (AUDIT ASN1-1) */
        static const uint8_t pssSaltNeg[] = {
            0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u,
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            /* [1] maskGenAlgorithm MGF1-SHA-256 */
            0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
            0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
            0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            0xA2u, 0x03u, 0x02u, 0x01u, 0xFFu
        };
        /* saltLength 33, one more than SHA-256 produces */
        static const uint8_t pssSalt33[] = {
            0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u,
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            /* [1] maskGenAlgorithm MGF1-SHA-256 */
            0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
            0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
            0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            0xA2u, 0x03u, 0x02u, 0x01u, 0x21u
        };
        /* hashAlgorithm OID 2.16.840.1.101.3.4.2.9, which this module does not know */
        static const uint8_t pssUnknownHash[] = {
            0x30u, 0x16u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u,
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x09u, 0x05u, 0x00u,
            0xA2u, 0x03u, 0x02u, 0x01u, 0x20u
        };
        /* [1] maskGenAlgorithm present as SEQUENCE { NULL }: not MGF1, rejected */
        static const uint8_t pssOddMgf[] = {
            0x30u, 0x1Cu, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u,
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            0xA1u, 0x04u, 0x30u, 0x02u, 0x05u, 0x00u,
            0xA2u, 0x03u, 0x02u, 0x01u, 0x20u
        };
        static uint8_t rsaPriv[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t rsaPub[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        static uint8_t tbsDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        uint8_t tbsHash[SSF_SHA2_256_BYTE_SIZE];
        static uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
        size_t rsaPrivLen;
        size_t rsaPubLen;
        size_t sigLen;
        static SSFX509Cert_t rsaCert;
        static SSFX509Cert_t ecCert;
        uint32_t tbsLen;
        uint32_t certLen;
        int marker = 0;
#endif /* _UT_RSA_PSS_SIGN == 1 */

        memset(fakeSig, 0x55u, sizeof(fakeSig));
        memset(fakeKey32, 0x5Au, sizeof(fakeKey32));
        memset(pubKey, 0x04u, sizeof(pubKey));
#if _UT_RSA_PSS_SIGN == 1
        SSF_ASSERT(SSFRSAKeyGen(2048, rsaPriv, sizeof(rsaPriv), &rsaPrivLen, rsaPub,
                                sizeof(rsaPub), &rsaPubLen) == true);

        /* Helper: self-sign an RSA-PSS SHA-256 cert carrying the given parameters */
        #define _PSS_CERT(_params) do { \
            _utGenBaseParams(&p, serial, rsaPub, (uint32_t)rsaPubLen); \
            p.ecCurveOidRaw = NULL; p.ecCurveOidRawLen = 0u; \
            p.pubKeyAlgOidRaw = rsaPubKeyOid; p.pubKeyAlgOidRawLen = sizeof(rsaPubKeyOid); \
            p.sigAlgOidRaw = rsaPssOid; p.sigAlgOidRawLen = sizeof(rsaPssOid); \
            p.sigAlgParams = (_params); p.sigAlgParamsLen = sizeof(_params); \
            SSF_ASSERT(SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen) == true); \
            SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash)); \
            SSF_ASSERT(SSFRSASignPSS(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA256, tbsHash, \
                                     sizeof(tbsHash), sig, sizeof(sig), &sigLen) == true); \
            SSF_ASSERT(SSFX509EncodeCert(certDer, sizeof(certDer), &p, sig, (uint32_t)sigLen, \
                                         &certLen) == true); \
            SSF_ASSERT(SSFX509Parse(certDer, certLen, &rsaCert) == true); \
        } while (0)

        /* Baseline: a correct PSS cert verifies against itself */
        _PSS_CERT(pssSalt32);
        SSF_ASSERT(SSFX509IsKeyRSA(&rsaCert) == true);
        SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == true);

        /* AUDIT X509-2: an issuer whose RSA key BIT STRING is empty fails, never traps */
        {
            static const uint8_t rsaPkcs1Sha256Oid[] = {
                0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Bu
            };
            static uint8_t emptyKeyDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
            uint32_t emptyKeyDerLen;
            static SSFX509Cert_t emptyKeyCert;
            const uint8_t *chainDer[2];
            uint32_t chainDerLen[2];
            const uint8_t *trustDer[1];
            uint32_t trustDerLen[1];

            _utGenBaseParams(&p, serial, rsaPub, 0u);
            p.ecCurveOidRaw = NULL;
            p.ecCurveOidRawLen = 0u;
            p.pubKeyAlgOidRaw = rsaPubKeyOid;
            p.pubKeyAlgOidRawLen = sizeof(rsaPubKeyOid);
            p.sigAlgOidRaw = rsaPssOid;
            p.sigAlgOidRawLen = sizeof(rsaPssOid);
            p.sigAlgParams = pssSalt32;
            p.sigAlgParamsLen = sizeof(pssSalt32);
            p.addBasicConstraints = true;
            p.isCA = true;
            SSF_ASSERT(SSFX509EncodeCert(emptyKeyDer, sizeof(emptyKeyDer), &p, sig,
                                         (uint32_t)sigLen, &emptyKeyDerLen) == true);
            SSF_ASSERT(SSFX509Parse(emptyKeyDer, emptyKeyDerLen, &emptyKeyCert) == true);
            SSF_ASSERT(emptyKeyCert.pubKeyLen == 0u);

            /* RSA-PSS and RSA PKCS#1 v1.5 with the empty key */
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &emptyKeyCert) == false);
            SSF_ASSERT(SSFX509VerifySignature(&emptyKeyCert, rsaPkcs1Sha256Oid,
                                              sizeof(rsaPkcs1Sha256Oid), NULL, 0u, NULL, 0u,
                                              rsaCert.tbsRaw, rsaCert.tbsRawLen,
                                              rsaCert.signature, rsaCert.signatureLen) == false);

            /* A hostile chain: real RSA-PSS leaf, forged issuer with the empty key */
            chainDer[0] = certDer;
            chainDerLen[0] = certLen;
            chainDer[1] = emptyKeyDer;
            chainDerLen[1] = emptyKeyDerLen;
            trustDer[0] = _utTestCertDER;
            trustDerLen[0] = sizeof(_utTestCertDER);
            SSF_ASSERT(SSFX509VerifyChainPurpose(chainDer, chainDerLen, 2u, trustDer,
                                                 trustDerLen, 1u, SSF_X509_PURPOSE_CODE_SIGNING,
                                                 NULL, 1800000000ull, &_utVErr) == false);
            _UT_VERR(ERR_SIGNATURE, 0u);
        }

        /* An ECDSA-signed cert cannot be verified with an RSA issuer: no curve to use */
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &ecCert) == true);
        SSF_ASSERT(SSFX509VerifyCertSignature(&ecCert, &ecCert) == true);
        SSF_ASSERT(SSFX509VerifyCertSignature(&ecCert, &rsaCert) == false);

        /* An RSA-PSS cert cannot be verified with an EC issuer: the point is not an RSA key */
        SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &ecCert) == false);

        /* saltLength above the hash length is refused before any RSA arithmetic */
        _utTraceErrors = 0;
        _utTraceLastMsg[0] = '\0';
        SSFX509SetTraceCtx(_utTrace, &marker);
        _PSS_CERT(pssSalt33);
        SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
        _UT_TRACE_ASSERT(_utTraceErrors == 1u);
        _UT_TRACE_ASSERT(_utContains(_utTraceLastMsg, "saltLength") == true);
        SSFX509SetTraceCtx(NULL, NULL);

        /* An unrecognized hashAlgorithm OID fails verification, never SHA-256 (AUDIT X509-7) */
        _PSS_CERT(pssUnknownHash);
        SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);

        /* A maskGenAlgorithm that is not MGF1 over the same hash fails (AUDIT X509-7) */
        _PSS_CERT(pssOddMgf);
        SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);

        /* AUDIT X509-7: strict RSASSA-PSS-params; SSF signs SHA-256, MGF1-SHA-256, salt 32 */
        {
            /* every field explicit, hash with NULL params */
            static const uint8_t pssGood[] = {
                0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA1u,
                0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u,
                0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA2u,
                0x03u, 0x02u, 0x01u, 0x20u
            };
            /* hash AlgorithmIdentifier without NULL */
            static const uint8_t pssGoodNoNull[] = {
                0x30u, 0x32u, 0xA0u, 0x0Du, 0x30u, 0x0Bu, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0xA1u, 0x1Cu, 0x30u,
                0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u,
                0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u, 0x48u, 0x01u,
                0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA2u, 0x03u, 0x02u,
                0x01u, 0x20u
            };
            /* trailerField 1 present */
            static const uint8_t pssGoodTrailer[] = {
                0x30u, 0x39u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA1u,
                0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u,
                0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA2u,
                0x03u, 0x02u, 0x01u, 0x20u, 0xA3u, 0x03u, 0x02u, 0x01u, 0x01u
            };
            /* NULL, not a SEQUENCE */
            static const uint8_t pssNull[] = {
                0x05u, 0x00u
            };
            /* [0] absent: SHA-1 default */
            static const uint8_t pssNoHash[] = {
                0x30u, 0x23u, 0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u,
                0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u,
                0x09u, 0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u,
                0x05u, 0x00u, 0xA2u, 0x03u, 0x02u, 0x01u, 0x20u
            };
            /* [0] SHA-1 */
            static const uint8_t pssSha1[] = {
                0x30u, 0x30u, 0xA0u, 0x0Bu, 0x30u, 0x09u, 0x06u, 0x05u, 0x2Bu, 0x0Eu,
                0x03u, 0x02u, 0x1Au, 0x05u, 0x00u, 0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u,
                0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u,
                0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u,
                0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA2u, 0x03u, 0x02u, 0x01u, 0x20u
            };
            /* [0] unknown hash OID */
            static const uint8_t pssUnkHash[] = {
                0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x09u, 0x05u, 0x00u, 0xA1u,
                0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u,
                0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA2u,
                0x03u, 0x02u, 0x01u, 0x20u
            };
            /* [1] absent: MGF1-SHA-1 default */
            static const uint8_t pssNoMgf[] = {
                0x30u, 0x16u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA2u,
                0x03u, 0x02u, 0x01u, 0x20u
            };
            /* [1] MGF1-SHA-384 with [0] SHA-256 */
            static const uint8_t pssMgf384[] = {
                0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA1u,
                0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u,
                0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x02u, 0x05u, 0x00u, 0xA2u,
                0x03u, 0x02u, 0x01u, 0x20u
            };
            /* [1] unknown mask generation function */
            static const uint8_t pssMgfUnk[] = {
                0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA1u,
                0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u,
                0x0Du, 0x01u, 0x01u, 0x09u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA2u,
                0x03u, 0x02u, 0x01u, 0x20u
            };
            /* trailerField 2 */
            static const uint8_t pssTrailer2[] = {
                0x30u, 0x39u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA1u,
                0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u,
                0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA2u,
                0x03u, 0x02u, 0x01u, 0x20u, 0xA3u, 0x03u, 0x02u, 0x01u, 0x02u
            };
            /* trailing NULL inside the SEQUENCE */
            static const uint8_t pssInnerJunk[] = {
                0x30u, 0x36u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA1u,
                0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u,
                0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA2u,
                0x03u, 0x02u, 0x01u, 0x20u, 0x05u, 0x00u
            };
            /* [2] before [0] and [1] */
            static const uint8_t pssOrder[] = {
                0x30u, 0x34u, 0xA2u, 0x03u, 0x02u, 0x01u, 0x20u, 0xA0u, 0x0Fu, 0x30u,
                0x0Du, 0x06u, 0x09u, 0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u,
                0x02u, 0x01u, 0x05u, 0x00u, 0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u,
                0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u,
                0x0Du, 0x06u, 0x09u, 0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u,
                0x02u, 0x01u, 0x05u, 0x00u
            };
            /* trailing NULL after the SEQUENCE */
            static const uint8_t pssOuterJunk[] = {
                0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA1u,
                0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u,
                0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
                0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0xA2u,
                0x03u, 0x02u, 0x01u, 0x20u, 0x05u, 0x00u
            };
            _PSS_CERT(pssGood);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == true);
            _PSS_CERT(pssGoodNoNull);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == true);
            _PSS_CERT(pssGoodTrailer);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == true);
            _PSS_CERT(pssNull);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
            _PSS_CERT(pssNoHash);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
            _PSS_CERT(pssSha1);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
            _PSS_CERT(pssUnkHash);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
            _PSS_CERT(pssNoMgf);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
            _PSS_CERT(pssMgf384);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
            _PSS_CERT(pssMgfUnk);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
            _PSS_CERT(pssTrailer2);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
            _PSS_CERT(pssInnerJunk);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
            _PSS_CERT(pssOrder);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
            _PSS_CERT(pssOuterJunk);
            SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
        }

        /* AUDIT ASN1-1: a negative saltLength fails verification, never defaults to 20 */
        _PSS_CERT(pssSaltNeg);
        SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);

        /* Absent parameters select SHA-1 per RFC 4055, which is unsupported: fails closed */
        _utGenBaseParams(&p, serial, rsaPub, (uint32_t)rsaPubLen);
        p.ecCurveOidRaw = NULL;
        p.ecCurveOidRawLen = 0u;
        p.pubKeyAlgOidRaw = rsaPubKeyOid;
        p.pubKeyAlgOidRawLen = sizeof(rsaPubKeyOid);
        p.sigAlgOidRaw = rsaPssOid;
        p.sigAlgOidRawLen = sizeof(rsaPssOid);
        SSF_ASSERT(SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen) == true);
        SSFSHA256(tbsDer, tbsLen, tbsHash, sizeof(tbsHash));
        SSF_ASSERT(SSFRSASignPSS(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA256, tbsHash,
                                 sizeof(tbsHash), sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(SSFX509EncodeCert(certDer, sizeof(certDer), &p, sig, (uint32_t)sigLen,
                                     &certLen) == true);
        SSF_ASSERT(SSFX509Parse(certDer, certLen, &rsaCert) == true);
        SSF_ASSERT((rsaCert.sigAlgParams == NULL) && (rsaCert.sigAlgParamsLen == 0u));
        SSF_ASSERT(SSFX509VerifyCertSignature(&rsaCert, &rsaCert) == false);
        #undef _PSS_CERT
#endif /* _UT_RSA_PSS_SIGN == 1 */

        /* Ed25519 with a 65-byte issuer key or a 63-byte signature is rejected on size alone */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.sigAlgOidRaw = ed25519Oid;
        p.sigAlgOidRawLen = sizeof(ed25519Oid);
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT(SSFX509IsSigEd25519(&parsed) == true);
        SSF_ASSERT(SSFX509IsKeyEd25519(&parsed) == false);       /* Signed Ed25519, EC key */
        SSF_ASSERT(parsed.pubKeyLen == 65u);
        SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == false);
        _utGenBaseParams(&p, serial, fakeKey32, 32u);
        p.ecCurveOidRaw = NULL;
        p.ecCurveOidRawLen = 0u;
        p.pubKeyAlgOidRaw = ed25519Oid;
        p.pubKeyAlgOidRawLen = sizeof(ed25519Oid);
        p.sigAlgOidRaw = ed25519Oid;
        p.sigAlgOidRawLen = sizeof(ed25519Oid);
        (void)SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, 63u, &n);
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.pubKeyLen == 32u) && (parsed.signatureLen == 63u));
        SSF_ASSERT(SSFX509VerifyCertSignature(&parsed, &parsed) == false);
    }

#if (_UT_RSA_PKCS1_VERIFY == 0) || (_UT_RSA_PSS_VERIFY == 0)
    /* ---- RSA scheme compiled out: its signatures fail closed as an unsupported algorithm ---- */
    {
        static const uint8_t rsaEncryptionOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
        };
        static const uint8_t data[] = "signed data";
        static uint8_t fakeKey[256];
        static uint8_t fakeSig[256];
        static SSFX509Cert_t key;
        int marker = 0;

        memset(fakeKey, 0x5Au, sizeof(fakeKey));
        memset(fakeSig, 0x55u, sizeof(fakeSig));
        memset(&key, 0, sizeof(key));
        key.pubKey = fakeKey;
        key.pubKeyLen = sizeof(fakeKey);
        key.pubKeyAlgOidRaw = rsaEncryptionOid;
        key.pubKeyAlgOidRawLen = sizeof(rsaEncryptionOid);
        SSFX509SetTraceCtx(_utTrace, &marker);
#if _UT_RSA_PKCS1_VERIFY == 0
        {
            static const uint8_t rsaSha256Oid[] = {
                0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Bu
            };

            _utTraceErrors = 0;
            _utTraceLastMsg[0] = '\0';
            SSF_ASSERT(SSFX509VerifySignature(&key, rsaSha256Oid, sizeof(rsaSha256Oid), NULL, 0u,
                                              NULL, 0u, data, sizeof(data), fakeSig,
                                              sizeof(fakeSig)) == false);
            _UT_TRACE_ASSERT(_utTraceErrors == 1u);
            _UT_TRACE_ASSERT(_utContains(_utTraceLastMsg, "unsupported sigAlg") == true);
        }
#endif /* _UT_RSA_PKCS1_VERIFY == 0 */
#if _UT_RSA_PSS_VERIFY == 0
        {
            static const uint8_t rsaPssOid[] = {
                0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Au
            };
            /* RSASSA-PSS-params { [0] sha256, [1] mgf1-sha256, [2] saltLength 32 } */
            static const uint8_t pssSalt32[] = {
                0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u,
                0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
                0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
                0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
                0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
                0xA2u, 0x03u, 0x02u, 0x01u, 0x20u
            };

            _utTraceErrors = 0;
            _utTraceLastMsg[0] = '\0';
            SSF_ASSERT(SSFX509VerifySignature(&key, rsaPssOid, sizeof(rsaPssOid), pssSalt32,
                                              sizeof(pssSalt32), NULL, 0u, data, sizeof(data),
                                              fakeSig, sizeof(fakeSig)) == false);
            _UT_TRACE_ASSERT(_utTraceErrors == 1u);
            _UT_TRACE_ASSERT(_utContains(_utTraceLastMsg, "unsupported sigAlg") == true);
        }
#endif /* _UT_RSA_PSS_VERIFY == 0 */
        SSFX509SetTraceCtx(NULL, NULL);
    }
#endif /* (_UT_RSA_PKCS1_VERIFY == 0) || (_UT_RSA_PSS_VERIFY == 0) */

    /* ---- Hostname edges: trailing dot, upper-case SAN, leading-zero IPv4, type mixing ---- */
    {
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static const char *sanMixed[] = { "FOO.Example.COM", "*.EXAMPLE.net", NULL };
        static const char *sanDNSOnly[] = { "foo.example.com", NULL };
        static const uint8_t ip10[4] = { 10u, 0u, 0u, 1u };
        static const uint8_t *sanIPs[] = { ip10, NULL };
        uint8_t serial[] = { 0x19u };
        static SSFX509GenParams_t p;
        const uint8_t *chain[1];
        uint32_t chainLen[1];
        uint32_t n;
        const uint64_t now = 1800000000ull;

        /* Upper-case SAN values match lower-case hostnames, exact and wildcard alike */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.sanDNSNames = sanMixed;
        p.sanIPAddrs = sanIPs;
        n = _utSelfSign(&p, pubKey, sizeof(pubKey), out, sizeof(out));
        SSF_ASSERT(n != 0u);
        chain[0] = out;
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "foo.example.com",
                                      now, &_utVErr) == true); _UT_VERR(OK, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "bar.example.net",
                                      now, &_utVErr) == true); _UT_VERR(OK, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "BAR.example.NET",
                                      now, &_utVErr) == true); _UT_VERR(OK, 0u);

        /* A trailing dot is not stripped, so the absolute form does not match */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "foo.example.com.",
                                      now, &_utVErr) == false); _UT_VERR(ERR_HOSTNAME, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "bar.example.net.",
                                      now, &_utVErr) == false); _UT_VERR(ERR_HOSTNAME, 0u);

        /* Leading-zero IPv4 literals match nothing (AUDIT X509-17); only the canonical form does */
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "10.0.0.1",
                                      now, &_utVErr) == true); _UT_VERR(OK, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "010.0.0.1",
                                      now, &_utVErr) == false); _UT_VERR(ERR_HOSTNAME, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "10.0.0.01",
                                      now, &_utVErr) == false); _UT_VERR(ERR_HOSTNAME, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "10.0.0.10",
                                      now, &_utVErr) == false); _UT_VERR(ERR_HOSTNAME, 0u);

        /* An IPv4 literal never matches a dNSName, and a name never matches an iPAddress */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.sanDNSNames = sanDNSOnly;
        n = _utSelfSign(&p, pubKey, sizeof(pubKey), out, sizeof(out));
        SSF_ASSERT(n != 0u);
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "10.0.0.1",
                                      now, &_utVErr) == false); _UT_VERR(ERR_HOSTNAME, 0u);
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.sanIPAddrs = sanIPs;
        n = _utSelfSign(&p, pubKey, sizeof(pubKey), out, sizeof(out));
        SSF_ASSERT(n != 0u);
        chainLen[0] = n;
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "foo.example.com",
                                      now, &_utVErr) == false); _UT_VERR(ERR_HOSTNAME, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 1u, chain, chainLen, 1u, "10.0.0.1",
                                      now, &_utVErr) == true); _UT_VERR(OK, 0u);
    }

    /* ---- Generation edges: v2 silently carries no extensions, countryName must be 2 chars ---- */
    {
        static uint8_t out[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t fakeSig[64];
        uint8_t serial[] = { 0x1Au };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        uint32_t n;

        memset(fakeSig, 0xAAu, sizeof(fakeSig));
        memset(pubKey, 0x04u, sizeof(pubKey));

        /* v2 is not generated (AUDIT X509-14) but parses: encode v3 without exts and patch to 1 */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.version = 1u;
        SSF_ASSERT_TEST(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n));
        _utGenBaseParams(&p, serial, pubKey, 65u);
        SSF_ASSERT(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n) == true);
        {
            static const uint8_t verV3b[] = { 0xA0u, 0x03u, 0x02u, 0x01u, 0x02u };
            uint32_t at;

            SSF_ASSERT(_utFind(out, n, verV3b, sizeof(verV3b), &at) == true);
            out[at + 4u] = 0x01u;
        }
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.version == 1u) && (parsed.extsLen == 0u));
        SSF_ASSERT((parsed.hasBasicConstraints == false) && (parsed.hasKeyUsage == false));

        /* Version 1 omits the version field entirely */
        p.version = 0u;
        SSF_ASSERT(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n) == true);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.version == 0u) && (parsed.extsLen == 0u));

        /* countryName must be exactly two characters (RFC 5280 Appendix A) */
        _utGenBaseParams(&p, serial, pubKey, 65u);
        p.subject.c = "USA";
        SSF_ASSERT(SSFX509EncodeTBS(NULL, 0u, &p, &n) == false);
        SSF_ASSERT(n == 0u);
        SSF_ASSERT(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n) == false);
        SSF_ASSERT(n == 0u);
        p.subject.c = "U";
        SSF_ASSERT(SSFX509EncodeTBS(NULL, 0u, &p, &n) == false);
        p.subject.c = "";
        SSF_ASSERT(SSFX509EncodeTBS(NULL, 0u, &p, &n) == false);
        p.subject.c = "US";
        p.issuer.c = "GB";
        SSF_ASSERT(SSFX509EncodeCert(out, sizeof(out), &p, fakeSig, sizeof(fakeSig), &n) == true);
        SSF_ASSERT(SSFX509Parse(out, n, &parsed) == true);
        SSF_ASSERT((parsed.subject.cLen == 2u) && (memcmp(parsed.subject.c, "US", 2u) == 0));
        SSF_ASSERT((parsed.issuer.cLen == 2u) && (memcmp(parsed.issuer.c, "GB", 2u) == 0));
    }

    /* ---- SSFX509VerifySignature: a signature over arbitrary data, checked with a cert key ---- */
    {
        static const uint8_t sha256Oid[] = {
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u
        };
        static const uint8_t sha384Oid[] = {
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x02u
        };
        static const uint8_t sha512Oid[] = {
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x03u
        };
        static const uint8_t ed25519Oid[] = { 0x2Bu, 0x65u, 0x70u };
        static uint8_t tbsDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t certDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t ecPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t data[64];
        static uint8_t ecPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t edSeed[SSF_ED25519_SEED_SIZE];
        uint8_t edPub[SSF_ED25519_PUB_KEY_SIZE];
        uint8_t edSig[SSF_ED25519_SIG_SIZE];
        uint8_t hash[SSF_SHA2_512_BYTE_SIZE];
#if (_UT_RSA_PKCS1_SIGN == 1) && (_UT_RSA_PSS_SIGN == 1)
        static uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
#else
        static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
#endif /* (_UT_RSA_PKCS1_SIGN == 1) && (_UT_RSA_PSS_SIGN == 1) */
        size_t sigLen;
        size_t ecPubLen;
        uint8_t serial[] = { 0x1Bu };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t c;
        uint32_t tbsLen;
        uint32_t n;
#if (_UT_RSA_PKCS1_SIGN == 1) && (_UT_RSA_PSS_SIGN == 1)
        static const uint8_t rsaEncryptionOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
        };
        static const uint8_t rsaSha256Oid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Bu
        };
        static const uint8_t rsaSha384Oid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Cu
        };
        static const uint8_t rsaPssOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Au
        };
        static const uint8_t pssSalt32[] = {
            0x30u, 0x34u, 0xA0u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x09u,
            0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            /* [1] maskGenAlgorithm MGF1-SHA-256 */
            0xA1u, 0x1Cu, 0x30u, 0x1Au, 0x06u, 0x09u, 0x2Au, 0x86u, 0x48u, 0x86u,
            0xF7u, 0x0Du, 0x01u, 0x01u, 0x08u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u,
            0x86u, 0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u, 0x00u,
            0xA2u, 0x03u, 0x02u, 0x01u, 0x20u
        };
        static uint8_t rsaPriv[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t rsaPub[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t rsaPrivLen;
        size_t rsaPubLen;
#endif /* (_UT_RSA_PKCS1_SIGN == 1) && (_UT_RSA_PSS_SIGN == 1) */

        memset(data, 0x5Au, sizeof(data));

        /* ECDSA P-256: a digest algorithm may confirm the implied SHA-256 but not contradict it */
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, ecPriv, sizeof(ecPriv), ecPub, sizeof(ecPub),
                                  &ecPubLen) == true);
        _utGenBaseParams(&p, serial, ecPub, (uint32_t)ecPubLen);
        n = _utSignCert(&p, ecPriv, certDer, sizeof(certDer));
        SSF_ASSERT(n != 0u);
        SSF_ASSERT(SSFX509Parse(certDer, n, &c) == true);
        SSFSHA256(data, sizeof(data), hash, SSF_SHA2_256_BYTE_SIZE);
        SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, ecPriv, _UT_PRIV_LEN, hash, SSF_SHA2_256_BYTE_SIZE,
                                   sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, _utSigAlgOid, sizeof(_utSigAlgOid), NULL, 0u, NULL,
                                          0u, data, sizeof(data), sig, (uint32_t)sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, _utSigAlgOid, sizeof(_utSigAlgOid), NULL, 0u,
                                          sha256Oid, sizeof(sha256Oid), data, sizeof(data), sig,
                                          (uint32_t)sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, _utSigAlgOid, sizeof(_utSigAlgOid), NULL, 0u,
                                          sha384Oid, sizeof(sha384Oid), data, sizeof(data), sig,
                                          (uint32_t)sigLen) == false);
        data[7] ^= 0x01u;
        SSF_ASSERT(SSFX509VerifySignature(&c, _utSigAlgOid, sizeof(_utSigAlgOid), NULL, 0u, NULL,
                                          0u, data, sizeof(data), sig, (uint32_t)sigLen) == false);
        data[7] ^= 0x01u;
        sig[5] ^= 0x01u;
        SSF_ASSERT(SSFX509VerifySignature(&c, _utSigAlgOid, sizeof(_utSigAlgOid), NULL, 0u, NULL,
                                          0u, data, sizeof(data), sig, (uint32_t)sigLen) == false);
        sig[5] ^= 0x01u;
        SSF_ASSERT(SSFX509VerifySignature(&c, _utSigAlgOid, sizeof(_utSigAlgOid), NULL, 0u, NULL,
                                          0u, data, sizeof(data) - 1u, sig,
                                          (uint32_t)sigLen) == false);

        /* The certificate's own signature verifies through the same entry point */
        SSF_ASSERT(SSFX509VerifySignature(&c, c.sigAlgOidRaw, c.sigAlgOidRawLen, c.sigAlgParams,
                                          c.sigAlgParamsLen, NULL, 0u, c.tbsRaw, c.tbsRawLen,
                                          c.signature, c.signatureLen) == true);
        SSF_ASSERT(SSFX509VerifyCertSignature(&c, &c) == true);

        /* An unknown signature algorithm never verifies */
        SSF_ASSERT(SSFX509VerifySignature(&c, sha256Oid, sizeof(sha256Oid), NULL, 0u, NULL, 0u,
                                          data, sizeof(data), sig, (uint32_t)sigLen) == false);

        /* ecdsa-with-SHA384 on P-256 (AUDIT ECDSA-3): SHA-384 sig verifies, SHA-256 sig does not */
        {
            static const uint8_t ecdsaSha384Oid[] = {
                0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x03u
            };
            static uint8_t sig384[SSF_ECDSA_MAX_SIG_SIZE];
            size_t sig384Len;

            SSF_ASSERT(SSFX509VerifySignature(&c, ecdsaSha384Oid, sizeof(ecdsaSha384Oid), NULL, 0u,
                                              NULL, 0u, data, sizeof(data), sig,
                                              (uint32_t)sigLen) == false);
            SSFSHA384(data, sizeof(data), hash, SSF_SHA2_384_BYTE_SIZE);
            SSF_ASSERT(_SSFECDSAUTSign(_UT_CURVE, ecPriv, _UT_PRIV_LEN, hash,
                                       SSF_SHA2_384_BYTE_SIZE, sig384, sizeof(sig384),
                                       &sig384Len) == true);
            SSF_ASSERT(SSFX509VerifySignature(&c, ecdsaSha384Oid, sizeof(ecdsaSha384Oid), NULL, 0u,
                                              NULL, 0u, data, sizeof(data), sig384,
                                              (uint32_t)sig384Len) == true);
        }

#if (_UT_RSA_PKCS1_SIGN == 1) && (_UT_RSA_PSS_SIGN == 1)
        /* RSA: plain rsaEncryption needs the digest algorithm; elsewhere it must agree */
        SSF_ASSERT(SSFRSAKeyGen(2048, rsaPriv, sizeof(rsaPriv), &rsaPrivLen, rsaPub,
                                sizeof(rsaPub), &rsaPubLen) == true);
        _utGenBaseParams(&p, serial, rsaPub, (uint32_t)rsaPubLen);
        p.ecCurveOidRaw = NULL;
        p.ecCurveOidRawLen = 0u;
        p.pubKeyAlgOidRaw = rsaEncryptionOid;
        p.pubKeyAlgOidRawLen = sizeof(rsaEncryptionOid);
        p.sigAlgOidRaw = rsaSha256Oid;
        p.sigAlgOidRawLen = sizeof(rsaSha256Oid);
        SSF_ASSERT(SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen) == true);
        SSFSHA256(tbsDer, tbsLen, hash, SSF_SHA2_256_BYTE_SIZE);
        SSF_ASSERT(SSFRSASignPKCS1(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA256, hash,
                                   SSF_SHA2_256_BYTE_SIZE, sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(SSFX509EncodeCert(certDer, sizeof(certDer), &p, sig, (uint32_t)sigLen,
                                     &n) == true);
        SSF_ASSERT(SSFX509Parse(certDer, n, &c) == true);
        SSF_ASSERT(SSFX509VerifyCertSignature(&c, &c) == true);
        SSFSHA256(data, sizeof(data), hash, SSF_SHA2_256_BYTE_SIZE);
        SSF_ASSERT(SSFRSASignPKCS1(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA256, hash,
                                   SSF_SHA2_256_BYTE_SIZE, sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaEncryptionOid, sizeof(rsaEncryptionOid), NULL, 0u,
                                          sha256Oid, sizeof(sha256Oid), data, sizeof(data), sig,
                                          (uint32_t)sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaEncryptionOid, sizeof(rsaEncryptionOid), NULL, 0u,
                                          sha384Oid, sizeof(sha384Oid), data, sizeof(data), sig,
                                          (uint32_t)sigLen) == false);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaEncryptionOid, sizeof(rsaEncryptionOid), NULL, 0u,
                                          NULL, 0u, data, sizeof(data), sig,
                                          (uint32_t)sigLen) == false);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaSha256Oid, sizeof(rsaSha256Oid), NULL, 0u, NULL,
                                          0u, data, sizeof(data), sig, (uint32_t)sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaSha256Oid, sizeof(rsaSha256Oid), NULL, 0u,
                                          sha256Oid, sizeof(sha256Oid), data, sizeof(data), sig,
                                          (uint32_t)sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaSha256Oid, sizeof(rsaSha256Oid), NULL, 0u,
                                          sha384Oid, sizeof(sha384Oid), data, sizeof(data), sig,
                                          (uint32_t)sigLen) == false);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaSha384Oid, sizeof(rsaSha384Oid), NULL, 0u, NULL,
                                          0u, data, sizeof(data), sig, (uint32_t)sigLen) == false);

        /* The same key with SHA-384 */
        SSFSHA384(data, sizeof(data), hash, SSF_SHA2_384_BYTE_SIZE);
        SSF_ASSERT(SSFRSASignPKCS1(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA384, hash,
                                   SSF_SHA2_384_BYTE_SIZE, sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaEncryptionOid, sizeof(rsaEncryptionOid), NULL, 0u,
                                          sha384Oid, sizeof(sha384Oid), data, sizeof(data), sig,
                                          (uint32_t)sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaSha384Oid, sizeof(rsaSha384Oid), NULL, 0u, NULL,
                                          0u, data, sizeof(data), sig, (uint32_t)sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaEncryptionOid, sizeof(rsaEncryptionOid), NULL, 0u,
                                          sha256Oid, sizeof(sha256Oid), data, sizeof(data), sig,
                                          (uint32_t)sigLen) == false);

        /* RSA-PSS: the parameters select the hash and a digest algorithm must agree with them */
        SSFSHA256(data, sizeof(data), hash, SSF_SHA2_256_BYTE_SIZE);
        SSF_ASSERT(SSFRSASignPSS(rsaPriv, rsaPrivLen, SSF_RSA_HASH_SHA256, hash,
                                 SSF_SHA2_256_BYTE_SIZE, sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaPssOid, sizeof(rsaPssOid), pssSalt32,
                                          sizeof(pssSalt32), NULL, 0u, data, sizeof(data), sig,
                                          (uint32_t)sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaPssOid, sizeof(rsaPssOid), pssSalt32,
                                          sizeof(pssSalt32), sha256Oid, sizeof(sha256Oid), data,
                                          sizeof(data), sig, (uint32_t)sigLen) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, rsaPssOid, sizeof(rsaPssOid), pssSalt32,
                                          sizeof(pssSalt32), sha512Oid, sizeof(sha512Oid), data,
                                          sizeof(data), sig, (uint32_t)sigLen) == false);

        /* AUDIT X509-11: RSA PKCS#1 v1.5 needs rsaEncryption; RSA-PSS also takes id-RSASSA-PSS */
        {
            static SSFX509Cert_t k;

            k = c;
            k.pubKeyAlgOidRaw = ed25519Oid;
            k.pubKeyAlgOidRawLen = sizeof(ed25519Oid);
            SSF_ASSERT(SSFX509VerifySignature(&k, rsaPssOid, sizeof(rsaPssOid), pssSalt32,
                                              sizeof(pssSalt32), NULL, 0u, data, sizeof(data),
                                              sig, (uint32_t)sigLen) == false);
            k.pubKeyAlgOidRaw = rsaPssOid;
            k.pubKeyAlgOidRawLen = sizeof(rsaPssOid);
            SSF_ASSERT(SSFX509VerifySignature(&k, rsaPssOid, sizeof(rsaPssOid), pssSalt32,
                                              sizeof(pssSalt32), NULL, 0u, data, sizeof(data),
                                              sig, (uint32_t)sigLen) == true);
        }
#endif /* (_UT_RSA_PKCS1_SIGN == 1) && (_UT_RSA_PSS_SIGN == 1) */

        /* Ed25519 signs the data itself; RFC 8419 pairs it only with SHA-512 */
        SSF_ASSERT(SSFEd25519KeyGen(edSeed, edPub) == true);
        _utGenBaseParams(&p, serial, edPub, SSF_ED25519_PUB_KEY_SIZE);
        p.ecCurveOidRaw = NULL;
        p.ecCurveOidRawLen = 0u;
        p.pubKeyAlgOidRaw = ed25519Oid;
        p.pubKeyAlgOidRawLen = sizeof(ed25519Oid);
        p.sigAlgOidRaw = ed25519Oid;
        p.sigAlgOidRawLen = sizeof(ed25519Oid);
        SSF_ASSERT(SSFX509EncodeTBS(tbsDer, sizeof(tbsDer), &p, &tbsLen) == true);
        SSF_ASSERT(SSFEd25519Sign(edSeed, edPub, tbsDer, tbsLen, edSig) == true);
        SSF_ASSERT(SSFX509EncodeCert(certDer, sizeof(certDer), &p, edSig, sizeof(edSig),
                                     &n) == true);
        SSF_ASSERT(SSFX509Parse(certDer, n, &c) == true);
        SSF_ASSERT(SSFX509VerifyCertSignature(&c, &c) == true);
        SSF_ASSERT(SSFEd25519Sign(edSeed, edPub, data, sizeof(data), edSig) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, ed25519Oid, sizeof(ed25519Oid), NULL, 0u, NULL, 0u,
                                          data, sizeof(data), edSig, sizeof(edSig)) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, ed25519Oid, sizeof(ed25519Oid), NULL, 0u, sha512Oid,
                                          sizeof(sha512Oid), data, sizeof(data), edSig,
                                          sizeof(edSig)) == true);
        SSF_ASSERT(SSFX509VerifySignature(&c, ed25519Oid, sizeof(ed25519Oid), NULL, 0u, sha256Oid,
                                          sizeof(sha256Oid), data, sizeof(data), edSig,
                                          sizeof(edSig)) == false);
        /* AUDIT X509-11: Ed25519 needs an id-Ed25519 key and absent algorithm parameters */
        {
            static const uint8_t edNull[] = { 0x05u, 0x00u };
            static const uint8_t ecPubOid[] = {
                0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u
            };
            static SSFX509Cert_t k;

            k = c;
            SSF_ASSERT(SSFX509VerifySignature(&c, ed25519Oid, sizeof(ed25519Oid), edNull,
                                              sizeof(edNull), NULL, 0u, data, sizeof(data),
                                              edSig, sizeof(edSig)) == false);
            k.pubKeyAlgOidRaw = ecPubOid;
            k.pubKeyAlgOidRawLen = sizeof(ecPubOid);
            SSF_ASSERT(SSFX509VerifySignature(&k, ed25519Oid, sizeof(ed25519Oid), NULL, 0u, NULL,
                                              0u, data, sizeof(data), edSig,
                                              sizeof(edSig)) == false);
        }
        data[0] ^= 0x80u;
        SSF_ASSERT(SSFX509VerifySignature(&c, ed25519Oid, sizeof(ed25519Oid), NULL, 0u, NULL, 0u,
                                          data, sizeof(data), edSig, sizeof(edSig)) == false);
        data[0] ^= 0x80u;
        SSF_ASSERT(SSFX509VerifySignature(&c, ed25519Oid, sizeof(ed25519Oid), NULL, 0u, NULL, 0u,
                                          data, sizeof(data), edSig, sizeof(edSig) - 1u) == false);

        /* Preconditions */
        SSF_ASSERT_TEST(SSFX509VerifySignature(NULL, ed25519Oid, sizeof(ed25519Oid), NULL, 0u, NULL,
                                               0u, data, sizeof(data), edSig, sizeof(edSig)));
        SSF_ASSERT_TEST(SSFX509VerifySignature(&c, NULL, sizeof(ed25519Oid), NULL, 0u, NULL, 0u,
                                               data, sizeof(data), edSig, sizeof(edSig)));
        SSF_ASSERT_TEST(SSFX509VerifySignature(&c, ed25519Oid, sizeof(ed25519Oid), NULL, 1u, NULL,
                                               0u, data, sizeof(data), edSig, sizeof(edSig)));
        SSF_ASSERT_TEST(SSFX509VerifySignature(&c, ed25519Oid, sizeof(ed25519Oid), NULL, 0u, NULL,
                                               1u, data, sizeof(data), edSig, sizeof(edSig)));
        SSF_ASSERT_TEST(SSFX509VerifySignature(&c, ed25519Oid, sizeof(ed25519Oid), NULL, 0u, NULL,
                                               0u, NULL, sizeof(data), edSig, sizeof(edSig)));
        SSF_ASSERT_TEST(SSFX509VerifySignature(&c, ed25519Oid, sizeof(ed25519Oid), NULL, 0u, NULL,
                                               0u, data, sizeof(data), NULL, sizeof(edSig)));
    }

    /* ---- Code-signing chain purpose: no hostname, EKU codeSigning, KU digitalSignature ---- */
    {
        static uint8_t caOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t leafOut[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t caPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        static const uint8_t ekuOid[] = { 0x55u, 0x1Du, 0x25u };
        static const uint8_t anyEkuValue[] = { 0x30u, 0x06u, 0x06u, 0x04u,
                                                0x55u, 0x1Du, 0x25u, 0x00u };
        static uint8_t caPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t caPubLen;
        size_t leafPubLen;
        uint8_t serial[] = { 0x1Cu };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t parsed;
        const uint8_t *chain[2];
        uint32_t chainLen[2];
        const uint8_t *trust[1];
        uint32_t trustLen[1];
        const uint8_t *self[1];
        uint32_t selfLen[1];
        uint32_t caLen;
        uint32_t leafLen;
        const uint64_t now = 1800000000ull;

        SSF_ASSERT(_utMakeCA("ca", serial, caPriv, caPub, &caPubLen, caOut, sizeof(caOut),
                             &caLen) == true);
        trust[0] = caOut;
        trustLen[0] = caLen;
        chain[1] = caOut;
        chainLen[1] = caLen;
        SSF_ASSERT(SSFECDSAKeyGen(_UT_CURVE, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);

        /* Helper: sign the leaf described by p and point the chain at it */
        #define _LEAF() do { \
            leafLen = _utSignCert(&p, caPriv, leafOut, sizeof(leafOut)); \
            SSF_ASSERT(leafLen != 0u); \
            chain[0] = leafOut; \
            chainLen[0] = leafLen; \
        } while (0)

        /* Signer with no SAN or EKU, KU digitalSignature: code signing passes, TLS server fails */
        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "signer";
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_DIGITAL_SIGNATURE;
        _LEAF();
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL, now,
                                                 &_utVErr) == true);
        _UT_VERR(OK, 0u);
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, "ignored",
                                             now, &_utVErr) == true); _UT_VERR(OK, 0u);
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_SERVER_AUTH, "signer", now,
                                                 &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);
        SSF_ASSERT(SSFX509VerifyChain(chain, chainLen, 2u, trust, trustLen, 1u, "signer",
                                      now, &_utVErr) == false); _UT_VERR(ERR_HOSTNAME, 0u);

        /* Everything else about the chain is still enforced: expiry and an unknown issuer name */
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL,
                                             2000000001ull, &_utVErr) == false);
        _UT_VERR(ERR_EXPIRED, 0u);
        p.issuer.cn = "other";
        _LEAF();
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL, now,
                                                 &_utVErr) == false);
        _UT_VERR(ERR_UNKNOWN_CA, 0u);       /* No sent cert or anchor issued it */
        p.issuer.cn = "ca";

        /* EKU codeSigning is parsed, generated, and honored */
        p.addExtKeyUsage = true;
        p.ekuCodeSigning = true;
        _LEAF();
        SSF_ASSERT(SSFX509Parse(leafOut, leafLen, &parsed) == true);
        SSF_ASSERT((parsed.hasExtKeyUsage == true) && (parsed.ekuCodeSigning == true));
        SSF_ASSERT((parsed.ekuServerAuth == false) && (parsed.ekuClientAuth == false));
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL, now,
                                                 &_utVErr) == true);
        _UT_VERR(OK, 0u);

        /* An EKU without codeSigning rejects the signer; anyExtendedKeyUsage satisfies it */
        p.ekuCodeSigning = false;
        p.ekuClientAuth = true;
        _LEAF();
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL, now,
                                                 &_utVErr) == false);
        _UT_VERR(ERR_EKU, 0u);
        p.ekuClientAuth = false;
        p.ekuServerAuth = true;
        _LEAF();
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL, now,
                                                 &_utVErr) == false);
        _UT_VERR(ERR_EKU, 0u);
        p.addExtKeyUsage = false;
        p.ekuServerAuth = false;
        p.addRawExt = true;
        p.rawExtOid = ekuOid;
        p.rawExtOidLen = sizeof(ekuOid);
        p.rawExtValue = anyEkuValue;
        p.rawExtValueLen = sizeof(anyEkuValue);
        _LEAF();
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL, now,
                                                 &_utVErr) == true);
        _UT_VERR(OK, 0u);
        p.addRawExt = false;

        /* Key Usage, when present, must include digitalSignature or nonRepudiation */
        p.keyUsageBits = SSF_X509_KU_KEY_ENCIPHERMENT;
        _LEAF();
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL, now,
                                                 &_utVErr) == false);
        _UT_VERR(ERR_LEAF_KEY_USAGE, 0u);
        p.keyUsageBits = SSF_X509_KU_NON_REPUDIATION;
        _LEAF();
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL, now,
                                                 &_utVErr) == true);
        _UT_VERR(OK, 0u);
        p.addKeyUsage = false;
        _LEAF();
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain, chainLen, 2u, trust, trustLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL, now,
                                                 &_utVErr) == true);
        _UT_VERR(OK, 0u);
        #undef _LEAF

        /* The server-auth purpose is exactly the legacy entry point */
        self[0] = _utTestCertDER;
        selfLen[0] = sizeof(_utTestCertDER);
        SSF_ASSERT(SSFX509Parse(_utTestCertDER, sizeof(_utTestCertDER), &parsed) == true);
        SSF_ASSERT(SSFX509VerifyChainPurpose(self, selfLen, 1u, self, selfLen, 1u,
                                             SSF_X509_PURPOSE_SERVER_AUTH, "test.ssf.local",
                                             parsed.notBefore + 1u, &_utVErr) == true);
        _UT_VERR(OK, 0u);
        SSF_ASSERT(SSFX509VerifyChainPurpose(self, selfLen, 1u, self, selfLen, 1u,
                                             SSF_X509_PURPOSE_SERVER_AUTH, "nope.test",
                                             parsed.notBefore + 1u, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);
        SSF_ASSERT(SSFX509VerifyChainPurpose(self, selfLen, 1u, self, selfLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL,
                                             parsed.notBefore + 1u, &_utVErr) == true);
        _UT_VERR(OK, 0u);

        /* Preconditions: server auth needs a hostname, the purpose must be in range */
        SSF_ASSERT_TEST(SSFX509VerifyChainPurpose(self, selfLen, 1u, self, selfLen, 1u,
                                                  SSF_X509_PURPOSE_SERVER_AUTH, NULL,
                                                  parsed.notBefore + 1u, &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChainPurpose(self, selfLen, 1u, self, selfLen, 1u,
                                                  SSF_X509_PURPOSE_SERVER_AUTH, "",
                                                  parsed.notBefore + 1u, &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChainPurpose(self, selfLen, 1u, self, selfLen, 1u,
                                                  SSF_X509_PURPOSE_MIN, NULL,
                                                  parsed.notBefore + 1u, &_utVErr));
        SSF_ASSERT_TEST(SSFX509VerifyChainPurpose(self, selfLen, 1u, self, selfLen, 1u,
                                                  SSF_X509_PURPOSE_MAX, NULL,
                                                  parsed.notBefore + 1u, &_utVErr));
    }

    /* ---- AUDIT RSA-10: RSA-1024, e = 1 and even e keys are refused, 2048-bit e = 3 passes ---- */
#if (SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1)
    {
        static const uint8_t rsaEncOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x01u
        };
        static const uint8_t sha256RsaOid[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Bu
        };
        static const uint8_t digestInfoSha256[] = {
            0x30u, 0x31u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u, 0x48u, 0x01u, 0x65u, 0x03u,
            0x04u, 0x02u, 0x01u, 0x05u, 0x00u, 0x04u, 0x20u
        };
        static const uint8_t msg[] = "SSF AUDIT RSA-10 test message";
        static const uint8_t pub1024[140] = {
            0x30u, 0x81u, 0x89u, 0x02u, 0x81u, 0x81u, 0x00u, 0xBEu, 0x6Du, 0x73u, 0xC0u, 0x37u,
            0x97u, 0x4Fu, 0x40u, 0x2Bu, 0xC0u, 0x3Du, 0xEDu, 0xF9u, 0xA9u, 0x2Eu, 0x80u, 0x5Au,
            0xE8u, 0xD2u, 0xA3u, 0x95u, 0x5Eu, 0x90u, 0xABu, 0x00u, 0x5Du, 0xCDu, 0xA4u, 0xD9u,
            0xBCu, 0x9Fu, 0x4Cu, 0xE2u, 0xF8u, 0xE2u, 0xA9u, 0x7Bu, 0xFFu, 0xAFu, 0xE3u, 0xAEu,
            0x75u, 0x94u, 0x9Bu, 0x56u, 0xAAu, 0x84u, 0xF6u, 0x4Cu, 0xE2u, 0xF5u, 0x22u, 0xE0u,
            0xADu, 0xA0u, 0x3Au, 0x7Du, 0xDBu, 0x50u, 0x92u, 0xB8u, 0xFCu, 0x24u, 0x79u, 0xF8u,
            0xA3u, 0x01u, 0x48u, 0xC8u, 0x98u, 0x98u, 0xBDu, 0x01u, 0x5Au, 0xABu, 0x45u, 0x38u,
            0x93u, 0x7Bu, 0xC4u, 0x61u, 0xD8u, 0xA5u, 0x9Bu, 0xF5u, 0xD3u, 0x54u, 0xB3u, 0xC8u,
            0x9Cu, 0xFFu, 0xB1u, 0x24u, 0x7Fu, 0xD7u, 0x03u, 0xB7u, 0x2Eu, 0x4Cu, 0xDCu, 0x98u,
            0xB9u, 0xDFu, 0x24u, 0x76u, 0x51u, 0x70u, 0x86u, 0xBCu, 0x45u, 0xCDu, 0xF2u, 0x07u,
            0xA3u, 0x81u, 0x67u, 0xACu, 0xB1u, 0x8Eu, 0x90u, 0xADu, 0x96u, 0x9Eu, 0x2Cu, 0x9Au,
            0xE2u, 0x00u, 0x5Fu, 0x02u, 0x03u, 0x01u, 0x00u, 0x01u
        };
        static const uint8_t sig1024[128] = {
            0x9Au, 0x57u, 0xC0u, 0xB2u, 0xDBu, 0x04u, 0x56u, 0x42u, 0x4Au, 0xBCu, 0x22u, 0x4Bu,
            0x39u, 0x56u, 0x02u, 0xD2u, 0xB4u, 0x90u, 0x83u, 0x03u, 0xC9u, 0x60u, 0x6Bu, 0xA5u,
            0x16u, 0xB3u, 0xFFu, 0xC7u, 0xF9u, 0x05u, 0xA2u, 0xD9u, 0x3Du, 0xAEu, 0xD2u, 0x62u,
            0x3Cu, 0x48u, 0x86u, 0x12u, 0x18u, 0x46u, 0x70u, 0xBCu, 0xFCu, 0x02u, 0x84u, 0x69u,
            0x87u, 0x0Du, 0x4Du, 0x20u, 0x37u, 0x9Eu, 0xEAu, 0x1Eu, 0x90u, 0x2Cu, 0x7Cu, 0x77u,
            0x4Au, 0x20u, 0xE0u, 0x95u, 0xF7u, 0x05u, 0x57u, 0x45u, 0x5Eu, 0xA3u, 0x04u, 0x8Bu,
            0x48u, 0xAAu, 0x3Fu, 0x2Cu, 0xAAu, 0x7Cu, 0x93u, 0x7Bu, 0x57u, 0x57u, 0x39u, 0xACu,
            0x6Du, 0x7Cu, 0x2Eu, 0x6Bu, 0xBAu, 0x3Eu, 0x06u, 0x1Bu, 0x79u, 0xDFu, 0x0Bu, 0xC1u,
            0xABu, 0x54u, 0xE4u, 0x3Au, 0x30u, 0xA7u, 0xE4u, 0xE8u, 0xAFu, 0x11u, 0x93u, 0x7Au,
            0xCDu, 0x58u, 0x04u, 0x1Cu, 0xCDu, 0x73u, 0x28u, 0x78u, 0x40u, 0x09u, 0xB4u, 0x32u,
            0xAAu, 0x31u, 0x69u, 0x2Cu, 0xD0u, 0x7Bu, 0x3Fu, 0x3Eu
        };
        static const uint8_t pub2048e3[268] = {
            0x30u, 0x82u, 0x01u, 0x08u, 0x02u, 0x82u, 0x01u, 0x01u, 0x00u, 0xDFu, 0x88u, 0x86u,
            0x90u, 0xEAu, 0x66u, 0x4Cu, 0x71u, 0xE9u, 0xCAu, 0x95u, 0xD7u, 0x5Fu, 0xC9u, 0x9Fu,
            0x16u, 0xE0u, 0xCFu, 0x60u, 0x3Cu, 0xD3u, 0xD3u, 0xB7u, 0xEDu, 0xA0u, 0x0Fu, 0x9Bu,
            0x4Du, 0x7Eu, 0x70u, 0x31u, 0x47u, 0x2Cu, 0x81u, 0x2Eu, 0x1Au, 0x14u, 0x66u, 0x62u,
            0x3Fu, 0xB4u, 0x4Fu, 0x91u, 0xD3u, 0xB9u, 0x7Fu, 0x06u, 0xD5u, 0x55u, 0x91u, 0xC3u,
            0xD4u, 0x13u, 0x97u, 0x63u, 0xB9u, 0x0Bu, 0x3Bu, 0xCFu, 0x30u, 0xD5u, 0xFDu, 0x55u,
            0x1Bu, 0x22u, 0x96u, 0x9Au, 0x78u, 0xD9u, 0x86u, 0x75u, 0xE0u, 0x36u, 0x79u, 0xE9u,
            0xD9u, 0xCDu, 0x52u, 0xE4u, 0xDCu, 0x67u, 0xE8u, 0x3Bu, 0xA5u, 0xC0u, 0xFDu, 0x85u,
            0x77u, 0xABu, 0x0Cu, 0x36u, 0x17u, 0xD9u, 0xCEu, 0xCAu, 0x48u, 0x79u, 0x58u, 0xB1u,
            0x15u, 0xD2u, 0x4Du, 0xAFu, 0x29u, 0x48u, 0x08u, 0x6Bu, 0x12u, 0x25u, 0x9Cu, 0x14u,
            0x55u, 0xA1u, 0x47u, 0xACu, 0x22u, 0xD1u, 0x30u, 0x73u, 0x75u, 0x6Au, 0xDEu, 0xFCu,
            0x8Du, 0xE3u, 0x5Fu, 0xA4u, 0x94u, 0x79u, 0xB7u, 0x2Eu, 0x93u, 0x43u, 0x0Bu, 0x5Eu,
            0x80u, 0x47u, 0x0Cu, 0xE1u, 0x9Au, 0x60u, 0xA1u, 0xA7u, 0x4Fu, 0xCAu, 0x85u, 0x7Bu,
            0x97u, 0x04u, 0xBCu, 0x9Fu, 0x6Cu, 0x17u, 0x82u, 0x38u, 0x7Bu, 0x0Cu, 0xBAu, 0xDCu,
            0x0Bu, 0xE5u, 0x53u, 0x9Fu, 0x4Au, 0x88u, 0xD9u, 0x66u, 0x97u, 0x08u, 0x6Bu, 0x72u,
            0xD4u, 0x1Au, 0x8Fu, 0x46u, 0xABu, 0x3Cu, 0xA4u, 0x45u, 0xD9u, 0xF4u, 0x90u, 0x83u,
            0x16u, 0xD6u, 0x6Au, 0x44u, 0x9Fu, 0x69u, 0xF2u, 0x7Cu, 0x24u, 0xCAu, 0x6Cu, 0x1Cu,
            0xE8u, 0xEEu, 0x7Cu, 0x5Du, 0x7Fu, 0x6Eu, 0x36u, 0x70u, 0x22u, 0x9Bu, 0x39u, 0x3Bu,
            0xA0u, 0x0Bu, 0x1Cu, 0xA5u, 0xF8u, 0x87u, 0x8Cu, 0x91u, 0xD5u, 0x5Eu, 0xD1u, 0xB2u,
            0x53u, 0x1Fu, 0x7Fu, 0xE3u, 0xF6u, 0x60u, 0x51u, 0x95u, 0x6Bu, 0xE5u, 0x62u, 0x70u,
            0x13u, 0xD2u, 0xB1u, 0xC7u, 0x2Eu, 0x86u, 0x37u, 0x5Cu, 0xDCu, 0x0Bu, 0xC2u, 0xBAu,
            0x2Bu, 0x87u, 0x2Au, 0xBCu, 0x3Fu, 0xAFu, 0x14u, 0xF8u, 0xC9u, 0x4Fu, 0x13u, 0x7Bu,
            0xF1u, 0x02u, 0x01u, 0x03u
        };
        static const uint8_t sig2048e3[256] = {
            0x3Cu, 0xBFu, 0x2Du, 0x3Du, 0x06u, 0xEBu, 0xECu, 0x78u, 0x1Bu, 0xECu, 0x24u, 0x01u,
            0xA5u, 0x63u, 0x14u, 0x9Fu, 0x9Cu, 0x7Bu, 0x3Eu, 0x3Eu, 0xD5u, 0xBCu, 0x5Au, 0x50u,
            0xE5u, 0xDFu, 0x9Bu, 0xD7u, 0x97u, 0x2Au, 0x2Fu, 0x4Fu, 0xC5u, 0x56u, 0x0Bu, 0x44u,
            0x1Du, 0x1Fu, 0x8Eu, 0xD0u, 0xF0u, 0x71u, 0xD8u, 0x45u, 0x30u, 0x0Bu, 0xDCu, 0xE7u,
            0x16u, 0x8Du, 0x18u, 0xA5u, 0xEFu, 0xF8u, 0xA4u, 0xF7u, 0x74u, 0x0Du, 0x96u, 0xA9u,
            0x79u, 0x72u, 0x2Fu, 0x6Eu, 0xB9u, 0xF3u, 0x09u, 0x2Fu, 0xA4u, 0x86u, 0x46u, 0xD5u,
            0xB1u, 0x50u, 0xCFu, 0x22u, 0x07u, 0xA6u, 0xE5u, 0x7Bu, 0x2Au, 0xF6u, 0xCCu, 0xB0u,
            0xBBu, 0xF6u, 0x92u, 0x5Fu, 0x08u, 0x65u, 0x34u, 0x95u, 0x8Au, 0x7Bu, 0x8Au, 0xB7u,
            0x73u, 0xCCu, 0xD0u, 0x76u, 0x0Fu, 0x98u, 0x43u, 0x03u, 0xCCu, 0x39u, 0xCAu, 0x4Bu,
            0x74u, 0x9Fu, 0x37u, 0x7Du, 0x0Fu, 0x55u, 0xFBu, 0xE5u, 0xB7u, 0xDCu, 0xF8u, 0xDBu,
            0xE3u, 0x4Eu, 0x36u, 0x3Fu, 0xBDu, 0xFEu, 0x16u, 0xFCu, 0xBCu, 0xF1u, 0xB2u, 0xD6u,
            0xB9u, 0x76u, 0xB2u, 0x68u, 0xB3u, 0x62u, 0xEFu, 0xBFu, 0xE4u, 0x68u, 0x89u, 0xA5u,
            0x39u, 0x58u, 0x94u, 0xB4u, 0xCBu, 0x51u, 0xBCu, 0x2Cu, 0x7Bu, 0x0Eu, 0xA2u, 0x5Au,
            0x91u, 0xB3u, 0x6Du, 0x4Fu, 0x67u, 0x48u, 0x41u, 0xD5u, 0x1Eu, 0xEEu, 0x95u, 0x3Eu,
            0x75u, 0x41u, 0xDBu, 0xF4u, 0xF0u, 0x71u, 0xC9u, 0xC0u, 0xA1u, 0xEBu, 0x48u, 0xAFu,
            0xC5u, 0x30u, 0xEDu, 0x04u, 0x95u, 0x0Fu, 0xF8u, 0x51u, 0xB0u, 0x4Du, 0x18u, 0xECu,
            0xCBu, 0x08u, 0xE3u, 0xD7u, 0x95u, 0xB5u, 0x0Du, 0xB4u, 0x3Fu, 0xCBu, 0x7Au, 0xADu,
            0x62u, 0x72u, 0xFEu, 0x95u, 0xEEu, 0x96u, 0xB3u, 0x3Fu, 0xFCu, 0x80u, 0x6Cu, 0xD5u,
            0x03u, 0x2Fu, 0x05u, 0xC1u, 0x79u, 0xB3u, 0xC5u, 0x6Bu, 0x29u, 0x92u, 0x79u, 0xE4u,
            0x44u, 0x9Cu, 0xB0u, 0x93u, 0x4Bu, 0x20u, 0x35u, 0xCAu, 0xD4u, 0x31u, 0xFCu, 0x9Au,
            0x36u, 0xE1u, 0xD4u, 0x56u, 0xAAu, 0x1Eu, 0x52u, 0xFDu, 0x06u, 0x30u, 0xBBu, 0xA5u,
            0xC0u, 0x4Au, 0x13u, 0x95u
        };
        static uint8_t pubE1[4u + 4u + 257u + 3u];
        static uint8_t sigE1[256];
        static SSFX509Cert_t kc;
        uint8_t hash[32];
        uint32_t i;

        memset(&kc, 0, sizeof(kc));
        kc.pubKeyAlgOidRaw = rsaEncOid;
        kc.pubKeyAlgOidRawLen = sizeof(rsaEncOid);

        /* RSA-2048 with e = 3: odd and >= 3, at the minimum size, so it must still verify. */
        kc.pubKey = pub2048e3;
        kc.pubKeyLen = sizeof(pub2048e3);
        SSF_ASSERT(SSFX509VerifySignature(&kc, sha256RsaOid, sizeof(sha256RsaOid), NULL, 0u, NULL,
                                          0u, msg, (uint32_t)(sizeof(msg) - 1u), sig2048e3,
                                          sizeof(sig2048e3)) == true);

#if SSF_X509_CONFIG_RSA_MIN_BITS > 1024u
        /* RSA-1024 with a valid signature: below the minimum size, must be refused. */
        kc.pubKey = pub1024;
        kc.pubKeyLen = sizeof(pub1024);
        SSF_ASSERT(SSFX509VerifySignature(&kc, sha256RsaOid, sizeof(sha256RsaOid), NULL, 0u, NULL,
                                          0u, msg, (uint32_t)(sizeof(msg) - 1u), sig1024,
                                          sizeof(sig1024)) == false);
#endif /* SSF_X509_CONFIG_RSA_MIN_BITS > 1024u */

        /* 2048-bit odd n = C5 FF .. FF 01 with e = 1: the PKCS#1 EM itself "verifies". */
        i = 0u;
        pubE1[i++] = 0x30u; pubE1[i++] = 0x82u; pubE1[i++] = 0x01u; pubE1[i++] = 0x08u;
        pubE1[i++] = 0x02u; pubE1[i++] = 0x82u; pubE1[i++] = 0x01u; pubE1[i++] = 0x01u;
        pubE1[i++] = 0x00u;
        pubE1[i++] = 0xC5u;
        while (i < (4u + 4u + 1u + 255u)) pubE1[i++] = 0xFFu;
        pubE1[i++] = 0x01u;
        pubE1[i++] = 0x02u; pubE1[i++] = 0x01u; pubE1[i++] = 0x01u;
        SSF_ASSERT(i == sizeof(pubE1));
        SSFSHA256(msg, (uint32_t)(sizeof(msg) - 1u), hash, sizeof(hash));
        sigE1[0] = 0x00u;
        sigE1[1] = 0x01u;
        memset(&sigE1[2], 0xFF, sizeof(sigE1) - 3u - sizeof(digestInfoSha256) - sizeof(hash));
        i = (uint32_t)(sizeof(sigE1) - sizeof(digestInfoSha256) - sizeof(hash));
        sigE1[i - 1u] = 0x00u;
        memcpy(&sigE1[i], digestInfoSha256, sizeof(digestInfoSha256));
        memcpy(&sigE1[i + sizeof(digestInfoSha256)], hash, sizeof(hash));
        kc.pubKey = pubE1;
        kc.pubKeyLen = sizeof(pubE1);
        SSF_ASSERT(SSFX509VerifySignature(&kc, sha256RsaOid, sizeof(sha256RsaOid), NULL, 0u, NULL,
                                          0u, msg, (uint32_t)(sizeof(msg) - 1u), sigE1,
                                          sizeof(sigE1)) == false);

        /* n = 0 or e = 0 (each the single INTEGER byte 0x00) is not a usable key: refused. */
        {
            static const uint8_t pubN0[] = {
                0x30u, 0x06u, 0x02u, 0x01u, 0x00u, 0x02u, 0x01u, 0x03u
            };
            static uint8_t pubE0[sizeof(pub2048e3)];

            kc.pubKey = pubN0;
            kc.pubKeyLen = sizeof(pubN0);
            SSF_ASSERT(SSFX509VerifySignature(&kc, sha256RsaOid, sizeof(sha256RsaOid), NULL, 0u,
                                              NULL, 0u, msg, (uint32_t)(sizeof(msg) - 1u),
                                              sig2048e3, sizeof(sig2048e3)) == false);
            memcpy(pubE0, pub2048e3, sizeof(pubE0));
            SSF_ASSERT(pubE0[sizeof(pubE0) - 1u] == 0x03u);
            pubE0[sizeof(pubE0) - 1u] = 0x00u;
            kc.pubKey = pubE0;
            kc.pubKeyLen = sizeof(pubE0);
            SSF_ASSERT(SSFX509VerifySignature(&kc, sha256RsaOid, sizeof(sha256RsaOid), NULL, 0u,
                                              NULL, 0u, msg, (uint32_t)(sizeof(msg) - 1u),
                                              sig2048e3, sizeof(sig2048e3)) == false);
        }
    }
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 && SSF_RSA_CONFIG_ENABLE_2048 */

    /* ---- AUDIT ASN1-14: a notAfter of 99991231235959Z parses, verifies and saturates ---- */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    {
        static const uint8_t cert9999[380] = {
            0x30u, 0x82u, 0x01u, 0x78u, 0x30u, 0x82u, 0x01u, 0x1Fu, 0xA0u, 0x03u, 0x02u, 0x01u,
            0x02u, 0x02u, 0x14u, 0x7Au, 0x85u, 0x50u, 0x2Du, 0xE1u, 0x8Cu, 0x2Eu, 0x07u, 0x83u,
            0xC0u, 0x9Bu, 0xFDu, 0x8Fu, 0xA6u, 0x06u, 0x42u, 0xE1u, 0x8Du, 0xF5u, 0xBBu, 0x30u,
            0x0Au, 0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x30u,
            0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u, 0x03u, 0x0Cu, 0x06u,
            0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x20u, 0x17u, 0x0Du, 0x32u, 0x36u,
            0x30u, 0x31u, 0x30u, 0x31u, 0x30u, 0x30u, 0x30u, 0x30u, 0x30u, 0x30u, 0x5Au, 0x18u,
            0x0Fu, 0x39u, 0x39u, 0x39u, 0x39u, 0x31u, 0x32u, 0x33u, 0x31u, 0x32u, 0x33u, 0x35u,
            0x39u, 0x35u, 0x39u, 0x5Au, 0x30u, 0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u,
            0x55u, 0x04u, 0x03u, 0x0Cu, 0x06u, 0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u,
            0x59u, 0x30u, 0x13u, 0x06u, 0x07u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u,
            0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u, 0x03u, 0x42u,
            0x00u, 0x04u, 0xB9u, 0xC8u, 0x9Fu, 0xBAu, 0x6Eu, 0x6Cu, 0xF2u, 0xB5u, 0x03u, 0xEEu,
            0x5Eu, 0xC8u, 0xC2u, 0x74u, 0x31u, 0x07u, 0x9Du, 0xD4u, 0xE9u, 0x5Eu, 0x4Bu, 0x52u,
            0xA3u, 0x0Eu, 0xB9u, 0x2Du, 0x4Eu, 0x8Au, 0x97u, 0x72u, 0x64u, 0x3Fu, 0x4Bu, 0x6Eu,
            0xD5u, 0x8Au, 0x31u, 0x12u, 0xD0u, 0xA6u, 0x58u, 0xB1u, 0xEEu, 0x2Du, 0x42u, 0xB4u,
            0x4Cu, 0x2Eu, 0xC6u, 0x4Fu, 0x90u, 0xF0u, 0x12u, 0x3Fu, 0xA0u, 0xE6u, 0xB8u, 0xB5u,
            0x4Eu, 0x8Au, 0xE6u, 0xA3u, 0xC4u, 0x7Au, 0xA3u, 0x53u, 0x30u, 0x51u, 0x30u, 0x1Du,
            0x06u, 0x03u, 0x55u, 0x1Du, 0x0Eu, 0x04u, 0x16u, 0x04u, 0x14u, 0xBDu, 0x9Bu, 0x3Du,
            0xBDu, 0x83u, 0xF1u, 0xC9u, 0xE4u, 0xC3u, 0xE1u, 0x66u, 0xD8u, 0xBCu, 0x9Du, 0x4Au,
            0xB6u, 0xB6u, 0xF6u, 0x77u, 0x7Fu, 0x30u, 0x1Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x23u,
            0x04u, 0x18u, 0x30u, 0x16u, 0x80u, 0x14u, 0xBDu, 0x9Bu, 0x3Du, 0xBDu, 0x83u, 0xF1u,
            0xC9u, 0xE4u, 0xC3u, 0xE1u, 0x66u, 0xD8u, 0xBCu, 0x9Du, 0x4Au, 0xB6u, 0xB6u, 0xF6u,
            0x77u, 0x7Fu, 0x30u, 0x0Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x13u, 0x01u, 0x01u, 0xFFu,
            0x04u, 0x05u, 0x30u, 0x03u, 0x01u, 0x01u, 0xFFu, 0x30u, 0x0Au, 0x06u, 0x08u, 0x2Au,
            0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x03u, 0x47u, 0x00u, 0x30u, 0x44u,
            0x02u, 0x20u, 0x0Eu, 0x33u, 0xB9u, 0x8Bu, 0x4Du, 0xA9u, 0x28u, 0xA1u, 0xF4u, 0x25u,
            0x7Bu, 0x2Au, 0xA0u, 0x1Au, 0x3Fu, 0x0Du, 0x4Eu, 0x8Cu, 0x61u, 0x27u, 0x91u, 0x6Au,
            0x93u, 0xB4u, 0x22u, 0xA4u, 0x04u, 0xC9u, 0x38u, 0x23u, 0x7Cu, 0xC2u, 0x02u, 0x20u,
            0x28u, 0x55u, 0xC7u, 0xF9u, 0x23u, 0xEDu, 0x5Cu, 0x5Du, 0xF6u, 0x2Bu, 0xDDu, 0xD2u,
            0xC6u, 0xD3u, 0x78u, 0x11u, 0x77u, 0x2Bu, 0xEEu, 0x62u, 0x5Du, 0xC7u, 0x73u, 0x8Cu,
            0xD7u, 0x19u, 0xFCu, 0xB5u, 0x19u, 0x59u, 0x76u, 0x56u
        };
        const uint8_t *chain9999[1];
        uint32_t chain9999Len[1];
        static SSFX509Cert_t c9999;

        SSF_ASSERT(SSFX509Parse(cert9999, sizeof(cert9999), &c9999) == true);
        SSF_ASSERT(c9999.notAfter == SSF_ASN1_TIME_FAR_FUTURE);
        SSF_ASSERT(SSFX509IsValid(&c9999, 1795000000ull) == true);
        chain9999[0] = cert9999;
        chain9999Len[0] = sizeof(cert9999);
        SSF_ASSERT(SSFX509VerifyChainPurpose(chain9999, chain9999Len, 1u, chain9999, chain9999Len,
                                             1u, SSF_X509_PURPOSE_CODE_SIGNING, NULL,
                                             1795000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);

        /* COV-2: an outer sigAlg OID that differs from the signed TBS copy is refused (4.1.2.3) */
        {
            static const uint8_t ecdsaSha256Oid[] = {
                0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u
            };
            static uint8_t certOuter[sizeof(cert9999)];
            static SSFX509Cert_t cOuter;
            uint32_t i;
            uint32_t last = 0u;

            memcpy(certOuter, cert9999, sizeof(certOuter));
            for (i = 0; (i + sizeof(ecdsaSha256Oid)) <= sizeof(certOuter); i++)
            {
                /* Is this the ecdsa-with-SHA256 OID (the last one is the outer copy)? */
                if (memcmp(&certOuter[i], ecdsaSha256Oid, sizeof(ecdsaSha256Oid)) == 0)
                {
                    /* Yes */
                    last = i + (uint32_t)sizeof(ecdsaSha256Oid) - 1u;
                }
            }
            SSF_ASSERT(last != 0u);
            certOuter[last] = 0x03u; /* ecdsa-with-SHA384, unsigned outer copy only */
            SSF_ASSERT(SSFX509Parse(certOuter, sizeof(certOuter), &cOuter) == true);
            SSF_ASSERT(cOuter.sigAlgOidRawLen == cOuter.outerSigAlgOidRawLen);
            chain9999[0] = certOuter;
            SSF_ASSERT(SSFX509VerifyChainPurpose(chain9999, chain9999Len, 1u, chain9999,
                                                 chain9999Len, 1u, SSF_X509_PURPOSE_CODE_SIGNING,
                                                 NULL, 1795000000ull, &_utVErr) == false);
            _UT_VERR(ERR_SIG_ALG_MISMATCH, 0u);
        }
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

    /* ---- AUDIT X509-16/17/18: identity and Name Constraints checks that could fail open ---- */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    {
        static uint8_t der[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t tbs[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static char sanNames[SSF_X509_CONFIG_MAX_SAN_ENTRIES + 1u][16];
        static const char *sanPtrs[SSF_X509_CONFIG_MAX_SAN_ENTRIES + 2u];
        static const uint8_t ncOid[] = { 0x55u, 0x1Du, 0x1Eu };
        /* NameConstraints { excludedSubtrees [1] { GeneralSubtree { [7] 2001:db8::/32 } } } */
        static const uint8_t ncIPv6Excl[] = {
            0x30u, 0x26u, 0xA1u, 0x24u, 0x30u, 0x22u, 0x87u, 0x20u,
            0x20u, 0x01u, 0x0Du, 0xB8u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        static uint8_t caDer[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static const uint8_t sanOid[] = { 0x55u, 0x1Du, 0x11u };
        /* SubjectAltName { [7] 2001:db8::1 } */
        static const uint8_t sanV6InRange[] = {
            0x30u, 0x12u, 0x87u, 0x10u,
            0x20u, 0x01u, 0x0Du, 0xB8u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
        };
        static const uint8_t ip10[4] = { 10u, 0u, 0u, 1u };
        static const char *sanLeading[] = { "010.0.0.1", NULL };
        static const uint8_t *ipSans[] = { ip10, NULL };
        static uint8_t leafPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t leafPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t leafPubLen;
        uint32_t caLen;
        const uint8_t *ch2[2];
        uint32_t ch2Len[2];
        const uint8_t *tr[1];
        uint32_t trLen[1];
        static uint8_t priv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        static uint8_t pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        uint8_t hash[SSF_SHA2_256_BYTE_SIZE];
        static uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        uint8_t serial[] = { 0x5Au };
        size_t pubLen;
        size_t sigLen;
        uint32_t tbsLen;
        uint32_t derLen;
        uint32_t i;
        static SSFX509GenParams_t p;
        static SSFX509Cert_t c;
        const uint8_t *ch[1];
        uint32_t chLen[1];

        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256, priv, sizeof(priv), pub, sizeof(pub),
                                  &pubLen) == true);

        /* X509-16: MAX_SAN_ENTRIES SANs parse; one more must not. */
        for (i = 0; i < (SSF_X509_CONFIG_MAX_SAN_ENTRIES + 1u); i++)
        {
            (void)snprintf(sanNames[i], sizeof(sanNames[i]), "h%u.example.com", (unsigned)i);
            sanPtrs[i] = sanNames[i];
        }
        _utGenBaseParams(&p, serial, pub, (uint32_t)pubLen);
        sanPtrs[SSF_X509_CONFIG_MAX_SAN_ENTRIES] = NULL;
        p.sanDNSNames = sanPtrs;
        SSF_ASSERT(SSFX509EncodeCert(der, sizeof(der), &p, sig, 64u, &derLen) == true);
        SSF_ASSERT(SSFX509Parse(der, derLen, &c) == true);
        SSF_ASSERT(c.sanLen == SSF_X509_CONFIG_MAX_SAN_ENTRIES);
        sanPtrs[SSF_X509_CONFIG_MAX_SAN_ENTRIES] = sanNames[SSF_X509_CONFIG_MAX_SAN_ENTRIES];
        sanPtrs[SSF_X509_CONFIG_MAX_SAN_ENTRIES + 1u] = NULL;
        SSF_ASSERT(SSFX509EncodeCert(der, sizeof(der), &p, sig, 64u, &derLen) == true);
        SSF_ASSERT(SSFX509Parse(der, derLen, &c) == false);

        /* X509-17: leading-zero octets are not IPv4 literals. */
        SSF_ASSERT(SSFX509MatchIPAddress("010.0.0.1", ip10, 4u) == false);
        SSF_ASSERT(SSFX509MatchIPAddress("10.0.0.01", ip10, 4u) == false);
        SSF_ASSERT(SSFX509MatchIPAddress("10.0.0.1", ip10, 4u) == true);

        /* X509-17: a self-signed leaf with dNSName "010.0.0.1" and iPAddress 10.0.0.1. */
        _utGenBaseParams(&p, serial, pub, (uint32_t)pubLen);
        p.sanDNSNames = sanLeading;
        p.sanIPAddrs = ipSans;
        SSF_ASSERT(SSFX509EncodeTBS(tbs, sizeof(tbs), &p, &tbsLen) == true);
        SSFSHA256(tbs, tbsLen, hash, sizeof(hash));
        SSF_ASSERT(_SSFECDSAUTSign(SSF_EC_CURVE_P256, priv, 32u, hash, sizeof(hash), sig,
                                   sizeof(sig), &sigLen) == true);
        SSF_ASSERT(SSFX509EncodeCert(der, sizeof(der), &p, sig, (uint32_t)sigLen, &derLen) == true);
        ch[0] = der;
        chLen[0] = derLen;
        SSF_ASSERT(SSFX509VerifyChain(ch, chLen, 1u, ch, chLen, 1u, "10.0.0.1",
                                      1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);
        SSF_ASSERT(SSFX509VerifyChain(ch, chLen, 1u, ch, chLen, 1u, "010.0.0.1",
                                      1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_HOSTNAME, 0u);

        /* X509-18: a CA excluding 2001:db8::/32 rejects an IPv6 SAN leaf, not an IPv4 one. */
        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256, leafPriv, sizeof(leafPriv), leafPub,
                                  sizeof(leafPub), &leafPubLen) == true);
        _utGenBaseParams(&p, serial, pub, (uint32_t)pubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "ca";
        p.addBasicConstraints = true;
        p.isCA = true;
        p.addKeyUsage = true;
        p.keyUsageBits = SSF_X509_KU_KEY_CERT_SIGN;
        p.addRawExt = true;
        p.rawExtOid = ncOid;
        p.rawExtOidLen = sizeof(ncOid);
        p.rawExtValue = ncIPv6Excl;
        p.rawExtValueLen = sizeof(ncIPv6Excl);
        p.rawExtCritical = true;
        caLen = _utSignCert(&p, priv, caDer, sizeof(caDer));
        SSF_ASSERT(caLen != 0u);
        SSF_ASSERT(SSFX509Parse(caDer, caLen, &c) == true);
        SSF_ASSERT((c.excludedLen == 1u) && (c.excludedSubtrees[0].valLen == 32u));
        ch2[1] = caDer;
        ch2Len[1] = caLen;
        tr[0] = caDer;
        trLen[0] = caLen;

        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "leaf";
        p.addRawExt = true;
        p.rawExtOid = sanOid;
        p.rawExtOidLen = sizeof(sanOid);
        p.rawExtValue = sanV6InRange;
        p.rawExtValueLen = sizeof(sanV6InRange);
        derLen = _utSignCert(&p, priv, der, sizeof(der));
        SSF_ASSERT(derLen != 0u);
        ch2[0] = der;
        ch2Len[0] = derLen;
        SSF_ASSERT(SSFX509VerifyChainPurpose(ch2, ch2Len, 2u, tr, trLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL,
                                             1800000000ull, &_utVErr) == false);
        _UT_VERR(ERR_NAME_CONSTRAINTS, 0u);

        _utGenBaseParams(&p, serial, leafPub, (uint32_t)leafPubLen);
        p.issuer.cn = "ca";
        p.subject.cn = "leaf";
        p.sanIPAddrs = ipSans;
        derLen = _utSignCert(&p, priv, der, sizeof(der));
        SSF_ASSERT(derLen != 0u);
        ch2Len[0] = derLen;
        SSF_ASSERT(SSFX509VerifyChainPurpose(ch2, ch2Len, 2u, tr, trLen, 1u,
                                             SSF_X509_PURPOSE_CODE_SIGNING, NULL,
                                             1800000000ull, &_utVErr) == true); _UT_VERR(OK, 0u);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

    /* ---- AUDIT X509-19: non-DER content inside the signed certificate is rejected ---- */
    {
        static const uint8_t certBase[378] = {
            0x30u, 0x82u, 0x01u, 0x76u, 0x30u, 0x82u, 0x01u, 0x1Du, 0xA0u, 0x03u, 0x02u, 0x01u,
            0x02u, 0x02u, 0x14u, 0x20u, 0x7Au, 0xEDu, 0x60u, 0x77u, 0x4Fu, 0x25u, 0x92u, 0x6Du,
            0xE5u, 0xEEu, 0xF6u, 0x1Bu, 0x22u, 0xE1u, 0x09u, 0xA0u, 0xA2u, 0xA9u, 0x0Du, 0x30u,
            0x0Au, 0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x30u,
            0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u, 0x03u, 0x0Cu, 0x06u,
            0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x1Eu, 0x17u, 0x0Du, 0x32u, 0x36u,
            0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u, 0x39u, 0x5Au, 0x17u,
            0x0Du, 0x32u, 0x37u, 0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u,
            0x39u, 0x5Au, 0x30u, 0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u,
            0x03u, 0x0Cu, 0x06u, 0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x59u, 0x30u,
            0x13u, 0x06u, 0x07u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u, 0x06u, 0x08u,
            0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u, 0x03u, 0x42u, 0x00u, 0x04u,
            0x11u, 0x14u, 0x5Au, 0xBBu, 0x02u, 0x71u, 0x4Eu, 0x2Fu, 0x7Du, 0xC8u, 0x8Cu, 0xFDu,
            0xDCu, 0x8Cu, 0x52u, 0xF3u, 0x0Bu, 0xC5u, 0x85u, 0x93u, 0x5Du, 0xC8u, 0x21u, 0x0Cu,
            0x36u, 0x50u, 0x83u, 0x8Fu, 0x91u, 0x1Du, 0x2Au, 0xD7u, 0x2Au, 0xAEu, 0xD9u, 0x79u,
            0xFFu, 0x27u, 0x9Bu, 0xA8u, 0x0Bu, 0x02u, 0xBEu, 0xCAu, 0xC3u, 0xF1u, 0x9Bu, 0x29u,
            0x82u, 0x13u, 0x68u, 0x39u, 0xDBu, 0xFEu, 0xE3u, 0x46u, 0x13u, 0x54u, 0xD8u, 0x18u,
            0xCBu, 0xFEu, 0x26u, 0xD0u, 0xA3u, 0x53u, 0x30u, 0x51u, 0x30u, 0x1Du, 0x06u, 0x03u,
            0x55u, 0x1Du, 0x0Eu, 0x04u, 0x16u, 0x04u, 0x14u, 0x65u, 0x00u, 0xBEu, 0x4Cu, 0x87u,
            0xFBu, 0x5Eu, 0x7Eu, 0x43u, 0x64u, 0x41u, 0x1Au, 0x88u, 0xD4u, 0x4Eu, 0x48u, 0x50u,
            0x23u, 0x09u, 0x9Au, 0x30u, 0x1Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x23u, 0x04u, 0x18u,
            0x30u, 0x16u, 0x80u, 0x14u, 0x65u, 0x00u, 0xBEu, 0x4Cu, 0x87u, 0xFBu, 0x5Eu, 0x7Eu,
            0x43u, 0x64u, 0x41u, 0x1Au, 0x88u, 0xD4u, 0x4Eu, 0x48u, 0x50u, 0x23u, 0x09u, 0x9Au,
            0x30u, 0x0Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x13u, 0x01u, 0x01u, 0xFFu, 0x04u, 0x05u,
            0x30u, 0x03u, 0x01u, 0x01u, 0xFFu, 0x30u, 0x0Au, 0x06u, 0x08u, 0x2Au, 0x86u, 0x48u,
            0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x03u, 0x47u, 0x00u, 0x30u, 0x44u, 0x02u, 0x20u,
            0x00u, 0xE7u, 0x1Cu, 0xF8u, 0xF8u, 0xC8u, 0x65u, 0x7Eu, 0xEAu, 0xD5u, 0x2Eu, 0x99u,
            0x96u, 0x1Du, 0x22u, 0x8Cu, 0x90u, 0xF2u, 0x8Bu, 0x6Fu, 0x24u, 0xAEu, 0x1Eu, 0xA6u,
            0x59u, 0x09u, 0x37u, 0x2Cu, 0x28u, 0xF4u, 0xAAu, 0xECu, 0x02u, 0x20u, 0x7Fu, 0x0Du,
            0xADu, 0x5Fu, 0x07u, 0x78u, 0x3Cu, 0xC1u, 0x6Cu, 0xE1u, 0x4Cu, 0xF0u, 0x57u, 0xFFu,
            0x7Eu, 0x75u, 0xBEu, 0xCBu, 0x4Cu, 0xDFu, 0xE7u, 0x2Cu, 0xFCu, 0x38u, 0x73u, 0x4Bu,
            0x25u, 0xF1u, 0x66u, 0x3Au, 0xBCu, 0x8Eu
        };
        static const uint8_t certValidityTrail[380] = {
            0x30u, 0x82u, 0x01u, 0x78u, 0x30u, 0x82u, 0x01u, 0x1Fu, 0xA0u, 0x03u, 0x02u, 0x01u,
            0x02u, 0x02u, 0x14u, 0x20u, 0x7Au, 0xEDu, 0x60u, 0x77u, 0x4Fu, 0x25u, 0x92u, 0x6Du,
            0xE5u, 0xEEu, 0xF6u, 0x1Bu, 0x22u, 0xE1u, 0x09u, 0xA0u, 0xA2u, 0xA9u, 0x0Du, 0x30u,
            0x0Au, 0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x30u,
            0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u, 0x03u, 0x0Cu, 0x06u,
            0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x20u, 0x17u, 0x0Du, 0x32u, 0x36u,
            0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u, 0x39u, 0x5Au, 0x17u,
            0x0Du, 0x32u, 0x37u, 0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u,
            0x39u, 0x5Au, 0x05u, 0x00u, 0x30u, 0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u,
            0x55u, 0x04u, 0x03u, 0x0Cu, 0x06u, 0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u,
            0x59u, 0x30u, 0x13u, 0x06u, 0x07u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u,
            0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u, 0x03u, 0x42u,
            0x00u, 0x04u, 0x11u, 0x14u, 0x5Au, 0xBBu, 0x02u, 0x71u, 0x4Eu, 0x2Fu, 0x7Du, 0xC8u,
            0x8Cu, 0xFDu, 0xDCu, 0x8Cu, 0x52u, 0xF3u, 0x0Bu, 0xC5u, 0x85u, 0x93u, 0x5Du, 0xC8u,
            0x21u, 0x0Cu, 0x36u, 0x50u, 0x83u, 0x8Fu, 0x91u, 0x1Du, 0x2Au, 0xD7u, 0x2Au, 0xAEu,
            0xD9u, 0x79u, 0xFFu, 0x27u, 0x9Bu, 0xA8u, 0x0Bu, 0x02u, 0xBEu, 0xCAu, 0xC3u, 0xF1u,
            0x9Bu, 0x29u, 0x82u, 0x13u, 0x68u, 0x39u, 0xDBu, 0xFEu, 0xE3u, 0x46u, 0x13u, 0x54u,
            0xD8u, 0x18u, 0xCBu, 0xFEu, 0x26u, 0xD0u, 0xA3u, 0x53u, 0x30u, 0x51u, 0x30u, 0x1Du,
            0x06u, 0x03u, 0x55u, 0x1Du, 0x0Eu, 0x04u, 0x16u, 0x04u, 0x14u, 0x65u, 0x00u, 0xBEu,
            0x4Cu, 0x87u, 0xFBu, 0x5Eu, 0x7Eu, 0x43u, 0x64u, 0x41u, 0x1Au, 0x88u, 0xD4u, 0x4Eu,
            0x48u, 0x50u, 0x23u, 0x09u, 0x9Au, 0x30u, 0x1Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x23u,
            0x04u, 0x18u, 0x30u, 0x16u, 0x80u, 0x14u, 0x65u, 0x00u, 0xBEu, 0x4Cu, 0x87u, 0xFBu,
            0x5Eu, 0x7Eu, 0x43u, 0x64u, 0x41u, 0x1Au, 0x88u, 0xD4u, 0x4Eu, 0x48u, 0x50u, 0x23u,
            0x09u, 0x9Au, 0x30u, 0x0Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x13u, 0x01u, 0x01u, 0xFFu,
            0x04u, 0x05u, 0x30u, 0x03u, 0x01u, 0x01u, 0xFFu, 0x30u, 0x0Au, 0x06u, 0x08u, 0x2Au,
            0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x03u, 0x47u, 0x00u, 0x30u, 0x44u,
            0x02u, 0x20u, 0x00u, 0xE7u, 0x1Cu, 0xF8u, 0xF8u, 0xC8u, 0x65u, 0x7Eu, 0xEAu, 0xD5u,
            0x2Eu, 0x99u, 0x96u, 0x1Du, 0x22u, 0x8Cu, 0x90u, 0xF2u, 0x8Bu, 0x6Fu, 0x24u, 0xAEu,
            0x1Eu, 0xA6u, 0x59u, 0x09u, 0x37u, 0x2Cu, 0x28u, 0xF4u, 0xAAu, 0xECu, 0x02u, 0x20u,
            0x7Fu, 0x0Du, 0xADu, 0x5Fu, 0x07u, 0x78u, 0x3Cu, 0xC1u, 0x6Cu, 0xE1u, 0x4Cu, 0xF0u,
            0x57u, 0xFFu, 0x7Eu, 0x75u, 0xBEu, 0xCBu, 0x4Cu, 0xDFu, 0xE7u, 0x2Cu, 0xFCu, 0x38u,
            0x73u, 0x4Bu, 0x25u, 0xF1u, 0x66u, 0x3Au, 0xBCu, 0x8Eu
        };
        static const uint8_t certSpkiTrail[380] = {
            0x30u, 0x82u, 0x01u, 0x78u, 0x30u, 0x82u, 0x01u, 0x1Fu, 0xA0u, 0x03u, 0x02u, 0x01u,
            0x02u, 0x02u, 0x14u, 0x20u, 0x7Au, 0xEDu, 0x60u, 0x77u, 0x4Fu, 0x25u, 0x92u, 0x6Du,
            0xE5u, 0xEEu, 0xF6u, 0x1Bu, 0x22u, 0xE1u, 0x09u, 0xA0u, 0xA2u, 0xA9u, 0x0Du, 0x30u,
            0x0Au, 0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x30u,
            0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u, 0x03u, 0x0Cu, 0x06u,
            0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x1Eu, 0x17u, 0x0Du, 0x32u, 0x36u,
            0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u, 0x39u, 0x5Au, 0x17u,
            0x0Du, 0x32u, 0x37u, 0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u,
            0x39u, 0x5Au, 0x30u, 0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u,
            0x03u, 0x0Cu, 0x06u, 0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x5Bu, 0x30u,
            0x13u, 0x06u, 0x07u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u, 0x06u, 0x08u,
            0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u, 0x03u, 0x42u, 0x00u, 0x04u,
            0x11u, 0x14u, 0x5Au, 0xBBu, 0x02u, 0x71u, 0x4Eu, 0x2Fu, 0x7Du, 0xC8u, 0x8Cu, 0xFDu,
            0xDCu, 0x8Cu, 0x52u, 0xF3u, 0x0Bu, 0xC5u, 0x85u, 0x93u, 0x5Du, 0xC8u, 0x21u, 0x0Cu,
            0x36u, 0x50u, 0x83u, 0x8Fu, 0x91u, 0x1Du, 0x2Au, 0xD7u, 0x2Au, 0xAEu, 0xD9u, 0x79u,
            0xFFu, 0x27u, 0x9Bu, 0xA8u, 0x0Bu, 0x02u, 0xBEu, 0xCAu, 0xC3u, 0xF1u, 0x9Bu, 0x29u,
            0x82u, 0x13u, 0x68u, 0x39u, 0xDBu, 0xFEu, 0xE3u, 0x46u, 0x13u, 0x54u, 0xD8u, 0x18u,
            0xCBu, 0xFEu, 0x26u, 0xD0u, 0x05u, 0x00u, 0xA3u, 0x53u, 0x30u, 0x51u, 0x30u, 0x1Du,
            0x06u, 0x03u, 0x55u, 0x1Du, 0x0Eu, 0x04u, 0x16u, 0x04u, 0x14u, 0x65u, 0x00u, 0xBEu,
            0x4Cu, 0x87u, 0xFBu, 0x5Eu, 0x7Eu, 0x43u, 0x64u, 0x41u, 0x1Au, 0x88u, 0xD4u, 0x4Eu,
            0x48u, 0x50u, 0x23u, 0x09u, 0x9Au, 0x30u, 0x1Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x23u,
            0x04u, 0x18u, 0x30u, 0x16u, 0x80u, 0x14u, 0x65u, 0x00u, 0xBEu, 0x4Cu, 0x87u, 0xFBu,
            0x5Eu, 0x7Eu, 0x43u, 0x64u, 0x41u, 0x1Au, 0x88u, 0xD4u, 0x4Eu, 0x48u, 0x50u, 0x23u,
            0x09u, 0x9Au, 0x30u, 0x0Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x13u, 0x01u, 0x01u, 0xFFu,
            0x04u, 0x05u, 0x30u, 0x03u, 0x01u, 0x01u, 0xFFu, 0x30u, 0x0Au, 0x06u, 0x08u, 0x2Au,
            0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x03u, 0x47u, 0x00u, 0x30u, 0x44u,
            0x02u, 0x20u, 0x00u, 0xE7u, 0x1Cu, 0xF8u, 0xF8u, 0xC8u, 0x65u, 0x7Eu, 0xEAu, 0xD5u,
            0x2Eu, 0x99u, 0x96u, 0x1Du, 0x22u, 0x8Cu, 0x90u, 0xF2u, 0x8Bu, 0x6Fu, 0x24u, 0xAEu,
            0x1Eu, 0xA6u, 0x59u, 0x09u, 0x37u, 0x2Cu, 0x28u, 0xF4u, 0xAAu, 0xECu, 0x02u, 0x20u,
            0x7Fu, 0x0Du, 0xADu, 0x5Fu, 0x07u, 0x78u, 0x3Cu, 0xC1u, 0x6Cu, 0xE1u, 0x4Cu, 0xF0u,
            0x57u, 0xFFu, 0x7Eu, 0x75u, 0xBEu, 0xCBu, 0x4Cu, 0xDFu, 0xE7u, 0x2Cu, 0xFCu, 0x38u,
            0x73u, 0x4Bu, 0x25u, 0xF1u, 0x66u, 0x3Au, 0xBCu, 0x8Eu
        };
        static const uint8_t certSpkiAlgTrail[380] = {
            0x30u, 0x82u, 0x01u, 0x78u, 0x30u, 0x82u, 0x01u, 0x1Fu, 0xA0u, 0x03u, 0x02u, 0x01u,
            0x02u, 0x02u, 0x14u, 0x20u, 0x7Au, 0xEDu, 0x60u, 0x77u, 0x4Fu, 0x25u, 0x92u, 0x6Du,
            0xE5u, 0xEEu, 0xF6u, 0x1Bu, 0x22u, 0xE1u, 0x09u, 0xA0u, 0xA2u, 0xA9u, 0x0Du, 0x30u,
            0x0Au, 0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x30u,
            0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u, 0x03u, 0x0Cu, 0x06u,
            0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x1Eu, 0x17u, 0x0Du, 0x32u, 0x36u,
            0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u, 0x39u, 0x5Au, 0x17u,
            0x0Du, 0x32u, 0x37u, 0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u,
            0x39u, 0x5Au, 0x30u, 0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u,
            0x03u, 0x0Cu, 0x06u, 0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x5Bu, 0x30u,
            0x15u, 0x06u, 0x07u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u, 0x06u, 0x08u,
            0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u, 0x05u, 0x00u, 0x03u, 0x42u,
            0x00u, 0x04u, 0x11u, 0x14u, 0x5Au, 0xBBu, 0x02u, 0x71u, 0x4Eu, 0x2Fu, 0x7Du, 0xC8u,
            0x8Cu, 0xFDu, 0xDCu, 0x8Cu, 0x52u, 0xF3u, 0x0Bu, 0xC5u, 0x85u, 0x93u, 0x5Du, 0xC8u,
            0x21u, 0x0Cu, 0x36u, 0x50u, 0x83u, 0x8Fu, 0x91u, 0x1Du, 0x2Au, 0xD7u, 0x2Au, 0xAEu,
            0xD9u, 0x79u, 0xFFu, 0x27u, 0x9Bu, 0xA8u, 0x0Bu, 0x02u, 0xBEu, 0xCAu, 0xC3u, 0xF1u,
            0x9Bu, 0x29u, 0x82u, 0x13u, 0x68u, 0x39u, 0xDBu, 0xFEu, 0xE3u, 0x46u, 0x13u, 0x54u,
            0xD8u, 0x18u, 0xCBu, 0xFEu, 0x26u, 0xD0u, 0xA3u, 0x53u, 0x30u, 0x51u, 0x30u, 0x1Du,
            0x06u, 0x03u, 0x55u, 0x1Du, 0x0Eu, 0x04u, 0x16u, 0x04u, 0x14u, 0x65u, 0x00u, 0xBEu,
            0x4Cu, 0x87u, 0xFBu, 0x5Eu, 0x7Eu, 0x43u, 0x64u, 0x41u, 0x1Au, 0x88u, 0xD4u, 0x4Eu,
            0x48u, 0x50u, 0x23u, 0x09u, 0x9Au, 0x30u, 0x1Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x23u,
            0x04u, 0x18u, 0x30u, 0x16u, 0x80u, 0x14u, 0x65u, 0x00u, 0xBEu, 0x4Cu, 0x87u, 0xFBu,
            0x5Eu, 0x7Eu, 0x43u, 0x64u, 0x41u, 0x1Au, 0x88u, 0xD4u, 0x4Eu, 0x48u, 0x50u, 0x23u,
            0x09u, 0x9Au, 0x30u, 0x0Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x13u, 0x01u, 0x01u, 0xFFu,
            0x04u, 0x05u, 0x30u, 0x03u, 0x01u, 0x01u, 0xFFu, 0x30u, 0x0Au, 0x06u, 0x08u, 0x2Au,
            0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x03u, 0x47u, 0x00u, 0x30u, 0x44u,
            0x02u, 0x20u, 0x00u, 0xE7u, 0x1Cu, 0xF8u, 0xF8u, 0xC8u, 0x65u, 0x7Eu, 0xEAu, 0xD5u,
            0x2Eu, 0x99u, 0x96u, 0x1Du, 0x22u, 0x8Cu, 0x90u, 0xF2u, 0x8Bu, 0x6Fu, 0x24u, 0xAEu,
            0x1Eu, 0xA6u, 0x59u, 0x09u, 0x37u, 0x2Cu, 0x28u, 0xF4u, 0xAAu, 0xECu, 0x02u, 0x20u,
            0x7Fu, 0x0Du, 0xADu, 0x5Fu, 0x07u, 0x78u, 0x3Cu, 0xC1u, 0x6Cu, 0xE1u, 0x4Cu, 0xF0u,
            0x57u, 0xFFu, 0x7Eu, 0x75u, 0xBEu, 0xCBu, 0x4Cu, 0xDFu, 0xE7u, 0x2Cu, 0xFCu, 0x38u,
            0x73u, 0x4Bu, 0x25u, 0xF1u, 0x66u, 0x3Au, 0xBCu, 0x8Eu
        };
        static const uint8_t certAttrTrail[380] = {
            0x30u, 0x82u, 0x01u, 0x78u, 0x30u, 0x82u, 0x01u, 0x1Fu, 0xA0u, 0x03u, 0x02u, 0x01u,
            0x02u, 0x02u, 0x14u, 0x20u, 0x7Au, 0xEDu, 0x60u, 0x77u, 0x4Fu, 0x25u, 0x92u, 0x6Du,
            0xE5u, 0xEEu, 0xF6u, 0x1Bu, 0x22u, 0xE1u, 0x09u, 0xA0u, 0xA2u, 0xA9u, 0x0Du, 0x30u,
            0x0Au, 0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x30u,
            0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u, 0x03u, 0x0Cu, 0x06u,
            0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x1Eu, 0x17u, 0x0Du, 0x32u, 0x36u,
            0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u, 0x39u, 0x5Au, 0x17u,
            0x0Du, 0x32u, 0x37u, 0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u,
            0x39u, 0x5Au, 0x30u, 0x13u, 0x31u, 0x11u, 0x30u, 0x0Fu, 0x06u, 0x03u, 0x55u, 0x04u,
            0x03u, 0x0Cu, 0x06u, 0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x05u, 0x00u, 0x30u,
            0x59u, 0x30u, 0x13u, 0x06u, 0x07u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u,
            0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u, 0x03u, 0x42u,
            0x00u, 0x04u, 0x11u, 0x14u, 0x5Au, 0xBBu, 0x02u, 0x71u, 0x4Eu, 0x2Fu, 0x7Du, 0xC8u,
            0x8Cu, 0xFDu, 0xDCu, 0x8Cu, 0x52u, 0xF3u, 0x0Bu, 0xC5u, 0x85u, 0x93u, 0x5Du, 0xC8u,
            0x21u, 0x0Cu, 0x36u, 0x50u, 0x83u, 0x8Fu, 0x91u, 0x1Du, 0x2Au, 0xD7u, 0x2Au, 0xAEu,
            0xD9u, 0x79u, 0xFFu, 0x27u, 0x9Bu, 0xA8u, 0x0Bu, 0x02u, 0xBEu, 0xCAu, 0xC3u, 0xF1u,
            0x9Bu, 0x29u, 0x82u, 0x13u, 0x68u, 0x39u, 0xDBu, 0xFEu, 0xE3u, 0x46u, 0x13u, 0x54u,
            0xD8u, 0x18u, 0xCBu, 0xFEu, 0x26u, 0xD0u, 0xA3u, 0x53u, 0x30u, 0x51u, 0x30u, 0x1Du,
            0x06u, 0x03u, 0x55u, 0x1Du, 0x0Eu, 0x04u, 0x16u, 0x04u, 0x14u, 0x65u, 0x00u, 0xBEu,
            0x4Cu, 0x87u, 0xFBu, 0x5Eu, 0x7Eu, 0x43u, 0x64u, 0x41u, 0x1Au, 0x88u, 0xD4u, 0x4Eu,
            0x48u, 0x50u, 0x23u, 0x09u, 0x9Au, 0x30u, 0x1Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x23u,
            0x04u, 0x18u, 0x30u, 0x16u, 0x80u, 0x14u, 0x65u, 0x00u, 0xBEu, 0x4Cu, 0x87u, 0xFBu,
            0x5Eu, 0x7Eu, 0x43u, 0x64u, 0x41u, 0x1Au, 0x88u, 0xD4u, 0x4Eu, 0x48u, 0x50u, 0x23u,
            0x09u, 0x9Au, 0x30u, 0x0Fu, 0x06u, 0x03u, 0x55u, 0x1Du, 0x13u, 0x01u, 0x01u, 0xFFu,
            0x04u, 0x05u, 0x30u, 0x03u, 0x01u, 0x01u, 0xFFu, 0x30u, 0x0Au, 0x06u, 0x08u, 0x2Au,
            0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x03u, 0x47u, 0x00u, 0x30u, 0x44u,
            0x02u, 0x20u, 0x00u, 0xE7u, 0x1Cu, 0xF8u, 0xF8u, 0xC8u, 0x65u, 0x7Eu, 0xEAu, 0xD5u,
            0x2Eu, 0x99u, 0x96u, 0x1Du, 0x22u, 0x8Cu, 0x90u, 0xF2u, 0x8Bu, 0x6Fu, 0x24u, 0xAEu,
            0x1Eu, 0xA6u, 0x59u, 0x09u, 0x37u, 0x2Cu, 0x28u, 0xF4u, 0xAAu, 0xECu, 0x02u, 0x20u,
            0x7Fu, 0x0Du, 0xADu, 0x5Fu, 0x07u, 0x78u, 0x3Cu, 0xC1u, 0x6Cu, 0xE1u, 0x4Cu, 0xF0u,
            0x57u, 0xFFu, 0x7Eu, 0x75u, 0xBEu, 0xCBu, 0x4Cu, 0xDFu, 0xE7u, 0x2Cu, 0xFCu, 0x38u,
            0x73u, 0x4Bu, 0x25u, 0xF1u, 0x66u, 0x3Au, 0xBCu, 0x8Eu
        };
        static const uint8_t certExplicitV1[292] = {
            0x30u, 0x82u, 0x01u, 0x20u, 0x30u, 0x81u, 0xC8u, 0xA0u, 0x03u, 0x02u, 0x01u, 0x00u,
            0x02u, 0x14u, 0x20u, 0x7Au, 0xEDu, 0x60u, 0x77u, 0x4Fu, 0x25u, 0x92u, 0x6Du, 0xE5u,
            0xEEu, 0xF6u, 0x1Bu, 0x22u, 0xE1u, 0x09u, 0xA0u, 0xA2u, 0xA9u, 0x0Du, 0x30u, 0x0Au,
            0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x04u, 0x03u, 0x02u, 0x30u, 0x11u,
            0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u, 0x03u, 0x0Cu, 0x06u, 0x64u,
            0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x1Eu, 0x17u, 0x0Du, 0x32u, 0x36u, 0x31u,
            0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u, 0x39u, 0x5Au, 0x17u, 0x0Du,
            0x32u, 0x37u, 0x31u, 0x31u, 0x31u, 0x39u, 0x31u, 0x33u, 0x34u, 0x38u, 0x35u, 0x39u,
            0x5Au, 0x30u, 0x11u, 0x31u, 0x0Fu, 0x30u, 0x0Du, 0x06u, 0x03u, 0x55u, 0x04u, 0x03u,
            0x0Cu, 0x06u, 0x64u, 0x65u, 0x76u, 0x69u, 0x63u, 0x65u, 0x30u, 0x59u, 0x30u, 0x13u,
            0x06u, 0x07u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du, 0x02u, 0x01u, 0x06u, 0x08u, 0x2Au,
            0x86u, 0x48u, 0xCEu, 0x3Du, 0x03u, 0x01u, 0x07u, 0x03u, 0x42u, 0x00u, 0x04u, 0x11u,
            0x14u, 0x5Au, 0xBBu, 0x02u, 0x71u, 0x4Eu, 0x2Fu, 0x7Du, 0xC8u, 0x8Cu, 0xFDu, 0xDCu,
            0x8Cu, 0x52u, 0xF3u, 0x0Bu, 0xC5u, 0x85u, 0x93u, 0x5Du, 0xC8u, 0x21u, 0x0Cu, 0x36u,
            0x50u, 0x83u, 0x8Fu, 0x91u, 0x1Du, 0x2Au, 0xD7u, 0x2Au, 0xAEu, 0xD9u, 0x79u, 0xFFu,
            0x27u, 0x9Bu, 0xA8u, 0x0Bu, 0x02u, 0xBEu, 0xCAu, 0xC3u, 0xF1u, 0x9Bu, 0x29u, 0x82u,
            0x13u, 0x68u, 0x39u, 0xDBu, 0xFEu, 0xE3u, 0x46u, 0x13u, 0x54u, 0xD8u, 0x18u, 0xCBu,
            0xFEu, 0x26u, 0xD0u, 0x30u, 0x0Au, 0x06u, 0x08u, 0x2Au, 0x86u, 0x48u, 0xCEu, 0x3Du,
            0x04u, 0x03u, 0x02u, 0x03u, 0x47u, 0x00u, 0x30u, 0x44u, 0x02u, 0x20u, 0x00u, 0xE7u,
            0x1Cu, 0xF8u, 0xF8u, 0xC8u, 0x65u, 0x7Eu, 0xEAu, 0xD5u, 0x2Eu, 0x99u, 0x96u, 0x1Du,
            0x22u, 0x8Cu, 0x90u, 0xF2u, 0x8Bu, 0x6Fu, 0x24u, 0xAEu, 0x1Eu, 0xA6u, 0x59u, 0x09u,
            0x37u, 0x2Cu, 0x28u, 0xF4u, 0xAAu, 0xECu, 0x02u, 0x20u, 0x7Fu, 0x0Du, 0xADu, 0x5Fu,
            0x07u, 0x78u, 0x3Cu, 0xC1u, 0x6Cu, 0xE1u, 0x4Cu, 0xF0u, 0x57u, 0xFFu, 0x7Eu, 0x75u,
            0xBEu, 0xCBu, 0x4Cu, 0xDFu, 0xE7u, 0x2Cu, 0xFCu, 0x38u, 0x73u, 0x4Bu, 0x25u, 0xF1u,
            0x66u, 0x3Au, 0xBCu, 0x8Eu
        };
        static uint8_t gen[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t fakeSig[64];
        static uint8_t key[65];
        static const uint8_t akidOid[] = { 0x55u, 0x1Du, 0x23u };
        static const uint8_t ekuOid[] = { 0x55u, 0x1Du, 0x25u };
        static const uint8_t ncOid[] = { 0x55u, 0x1Du, 0x1Eu };
        /* AKID { [0] AABB, [1] { [2] "ca" }, [2] 05 }: every field, in order */
        static const uint8_t akidAll[] = {
            0x30u, 0x0Du, 0x80u, 0x02u, 0xAAu, 0xBBu, 0xA1u, 0x04u, 0x82u, 0x02u, 0x63u, 0x61u,
            0x82u, 0x01u, 0x05u
        };
        /* AKID { [0] AABB, NULL } */
        static const uint8_t akidTrail[] = {
            0x30u, 0x06u, 0x80u, 0x02u, 0xAAu, 0xBBu, 0x05u, 0x00u
        };
        /* AKID { [1] { [2] "ca" }, [0] AABB }: out of order */
        static const uint8_t akidOrder[] = {
            0x30u, 0x0Au, 0xA1u, 0x04u, 0x82u, 0x02u, 0x63u, 0x61u, 0x80u, 0x02u, 0xAAu, 0xBBu
        };
        /* EKU { NULL, codeSigning } */
        static const uint8_t ekuNull[] = {
            0x30u, 0x0Cu, 0x05u, 0x00u, 0x06u, 0x08u, 0x2Bu, 0x06u, 0x01u, 0x05u, 0x05u, 0x07u,
            0x03u, 0x03u
        };
        /* NameConstraints { permitted [0] { { [2] "a.com", maximum [1] 1 } } } */
        static const uint8_t ncMax[] = {
            0x30u, 0x0Eu, 0xA0u, 0x0Cu, 0x30u, 0x0Au, 0x82u, 0x05u, 'a', '.', 'c', 'o', 'm',
            0x81u, 0x01u, 0x01u
        };
        /* NameConstraints { permitted [0] { { [2] "a.com", minimum [0] 0 } } } */
        static const uint8_t ncMin[] = {
            0x30u, 0x0Eu, 0xA0u, 0x0Cu, 0x30u, 0x0Au, 0x82u, 0x05u, 'a', '.', 'c', 'o', 'm',
            0x80u, 0x01u, 0x00u
        };
        static const struct
        {
            const uint8_t *oid;
            uint32_t oidLen;
            const uint8_t *val;
            uint32_t valLen;
            bool ok;
        } rawCases[] = {
            { akidOid, sizeof(akidOid), akidAll, sizeof(akidAll), true },
            { akidOid, sizeof(akidOid), akidTrail, sizeof(akidTrail), false },
            { akidOid, sizeof(akidOid), akidOrder, sizeof(akidOrder), false },
            { ekuOid, sizeof(ekuOid), ekuNull, sizeof(ekuNull), false },
            { ncOid, sizeof(ncOid), ncMax, sizeof(ncMax), false },
            { ncOid, sizeof(ncOid), ncMin, sizeof(ncMin), false }
        };
        uint8_t serial[] = { 0x19u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t c;
        uint32_t genLen;
        uint32_t i;

        SSF_ASSERT(SSFX509Parse(certBase, sizeof(certBase), &c) == true);
        SSF_ASSERT(SSFX509Parse(certValidityTrail, sizeof(certValidityTrail), &c) == false);
        SSF_ASSERT(SSFX509Parse(certSpkiTrail, sizeof(certSpkiTrail), &c) == false);
        SSF_ASSERT(SSFX509Parse(certSpkiAlgTrail, sizeof(certSpkiAlgTrail), &c) == false);
        SSF_ASSERT(SSFX509Parse(certAttrTrail, sizeof(certAttrTrail), &c) == false);
        SSF_ASSERT(SSFX509Parse(certExplicitV1, sizeof(certExplicitV1), &c) == false);

        memset(fakeSig, 0x66, sizeof(fakeSig));
        memset(key, 0x04, sizeof(key));
        for (i = 0; i < (uint32_t)(sizeof(rawCases) / sizeof(rawCases[0])); i++)
        {
            _utGenBaseParams(&p, serial, key, sizeof(key));
            p.addBasicConstraints = true;
            p.isCA = true;
            p.addRawExt = true;
            p.rawExtOid = rawCases[i].oid;
            p.rawExtOidLen = rawCases[i].oidLen;
            p.rawExtValue = rawCases[i].val;
            p.rawExtValueLen = rawCases[i].valLen;
            p.rawExtCritical = (rawCases[i].oid == ncOid);
            SSF_ASSERT(SSFX509EncodeCert(gen, sizeof(gen), &p, fakeSig, sizeof(fakeSig),
                                         &genLen) == true);
            SSF_ASSERT(SSFX509Parse(gen, genLen, &c) == rawCases[i].ok);
        }
    }

    /* ---- AUDIT X509-20: generated countryName is a PrintableString (RFC 5280 App. A) ---- */
    {
        static uint8_t gen[SSF_X509_CONFIG_MAX_CERT_SIZE];
        static uint8_t fakeSig[64];
        static uint8_t key[65];
        /* AttributeTypeAndValue { id-at-countryName, PrintableString "US" } */
        static const uint8_t cPrintable[] = {
            0x06u, 0x03u, 0x55u, 0x04u, 0x06u, 0x13u, 0x02u, 'U', 'S'
        };
        /* AttributeTypeAndValue { id-at-countryName, UTF8String "US" } */
        static const uint8_t cUTF8[] = {
            0x06u, 0x03u, 0x55u, 0x04u, 0x06u, 0x0Cu, 0x02u, 'U', 'S'
        };
        uint8_t serial[] = { 0x20u };
        static SSFX509GenParams_t p;
        static SSFX509Cert_t c;
        uint32_t genLen;
        uint32_t i;
        uint32_t printableHits;
        uint32_t utf8Hits;

        memset(fakeSig, 0x66, sizeof(fakeSig));
        memset(key, 0x04, sizeof(key));
        _utGenBaseParams(&p, serial, key, sizeof(key));
        p.issuer.c = "US";
        p.subject.c = "US";
        p.subject.o = "Org";
        SSF_ASSERT(SSFX509EncodeCert(gen, sizeof(gen), &p, fakeSig, sizeof(fakeSig),
                                     &genLen) == true);
        printableHits = 0;
        utf8Hits = 0;
        for (i = 0; (i + sizeof(cPrintable)) <= genLen; i++)
        {
            if (memcmp(&gen[i], cPrintable, sizeof(cPrintable)) == 0) printableHits++;
            if (memcmp(&gen[i], cUTF8, sizeof(cUTF8)) == 0) utf8Hits++;
        }
        SSF_ASSERT(printableHits == 2u);
        SSF_ASSERT(utf8Hits == 0u);
        SSF_ASSERT(SSFX509Parse(gen, genLen, &c) == true);
        SSF_ASSERT((c.subject.cLen == 2u) && (memcmp(c.subject.c, "US", 2u) == 0));
        SSF_ASSERT((c.issuer.cLen == 2u) && (memcmp(c.issuer.c, "US", 2u) == 0));
        SSF_ASSERT((c.subject.oLen == 3u) && (memcmp(c.subject.o, "Org", 3u) == 0));

        /* A country character outside the PrintableString set is refused */
        p.subject.c = "U*";
        SSF_ASSERT(SSFX509EncodeCert(gen, sizeof(gen), &p, fakeSig, sizeof(fakeSig),
                                     &genLen) == false);
        p.subject.c = "U@";
        SSF_ASSERT(SSFX509EncodeCert(gen, sizeof(gen), &p, fakeSig, sizeof(fakeSig),
                                     &genLen) == false);
        p.subject.c = "\xC3\x9C";
        SSF_ASSERT(SSFX509EncodeCert(gen, sizeof(gen), &p, fakeSig, sizeof(fakeSig),
                                     &genLen) == false);

        /* Every PrintableString punctuation character is accepted */
        p.subject.c = "a'";
        SSF_ASSERT(SSFX509EncodeCert(gen, sizeof(gen), &p, fakeSig, sizeof(fakeSig),
                                     &genLen) == true);
        p.subject.c = "9?";
        SSF_ASSERT(SSFX509EncodeCert(gen, sizeof(gen), &p, fakeSig, sizeof(fakeSig),
                                     &genLen) == true);
    }

    /* ---- CSR (PKCS#10) generation ---- */
    _UTCSR();
}
#endif /* SSF_CONFIG_X509_UNIT_TEST */
