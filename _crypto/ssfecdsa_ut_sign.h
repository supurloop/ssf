/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfecdsa_ut_sign.h                                                                            */
/* Test-only ECDSA signer for unit tests that build certificates and messages to verify.         */
/*                                                                                               */
/* With SSF_ECDSA_CONFIG_ENABLE_SIGN 1 it is SSFECDSASign. With signing compiled out it signs    */
/* with OpenSSL (SSF_CONFIG_HAVE_OPENSSL 1), so verification tests keep their generated inputs.  */
/* With neither, SSF_ECDSA_UT_CAN_SIGN is 0 and the caller skips the tests that need a signer.   */
/* Include it only from unit test sources; never from production code.                           */
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
#ifndef SSF_ECDSA_UT_SIGN_H_INCLUDE
#define SSF_ECDSA_UT_SIGN_H_INCLUDE

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ssfport.h"
#include "ssfecdsa.h"

#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
#define SSF_ECDSA_UT_CAN_SIGN (1u)
#define _SSFECDSAUTSign SSFECDSASign

#elif SSF_CONFIG_HAVE_OPENSSL == 1
#define SSF_ECDSA_UT_CAN_SIGN (1u)
#ifndef OPENSSL_API_COMPAT
#define OPENSSL_API_COMPAT 10101 /* Legacy EC_KEY/ECDSA API without deprecation warnings */
#endif
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

/* Returns true with the DER ECDSA-Sig-Value of hash under privKey in sig, else false. */
static bool _SSFECDSAUTSign(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                            const uint8_t *hash, size_t hashLen, uint8_t *sig, size_t sigSize,
                            size_t *sigLen)
{
    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));
    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(privKeyLen > 0u);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(hashLen > 0u);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(sigLen != NULL);

    int nid = (curve == SSF_EC_CURVE_P256) ? NID_X9_62_prime256v1 : NID_secp384r1;
    EC_KEY *key = EC_KEY_new_by_curve_name(nid);
    BIGNUM *d = BN_bin2bn(privKey, (int)privKeyLen, NULL);
    ECDSA_SIG *s = NULL;
    unsigned char *p = sig;
    int n;
    bool ok = false;

    /* Is the key built and the signature made? */
    if ((key != NULL) && (d != NULL) && (EC_KEY_set_private_key(key, d) == 1))
    {
        /* Yes, sign the hash */
        s = ECDSA_do_sign(hash, (int)hashLen, key);
    }
    /* Does its DER encoding fit sig? */
    if ((s != NULL) && ((n = i2d_ECDSA_SIG(s, NULL)) > 0) && ((size_t)n <= sigSize))
    {
        /* Yes, write it */
        *sigLen = (size_t)i2d_ECDSA_SIG(s, &p);
        ok = true;
    }
    ECDSA_SIG_free(s);
    BN_clear_free(d);
    EC_KEY_free(key);
    return ok;
}

#else
#define SSF_ECDSA_UT_CAN_SIGN (0u)

/* No signer in this build: always false (callers skip the tests that need one). */
static bool _SSFECDSAUTSign(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                            const uint8_t *hash, size_t hashLen, uint8_t *sig, size_t sigSize,
                            size_t *sigLen)
{
    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));
    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(privKeyLen > 0u);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(hashLen > 0u);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(sigLen != NULL);

    (void)curve; (void)privKey; (void)privKeyLen; (void)hash; (void)hashLen;
    (void)sig; (void)sigSize; (void)sigLen;
    return false;
}
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN, SSF_CONFIG_HAVE_OPENSSL */

#endif /* SSF_ECDSA_UT_SIGN_H_INCLUDE */
