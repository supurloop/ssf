/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftls.h                                                                                      */
/* Provides TLS 1.3 core: key schedule, record layer, and handshake message codec (RFC 8446).    */
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
#ifndef SSF_TLS_H_INCLUDE
#define SSF_TLS_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfhmac.h"
#include "ssfsha2.h"

/* --------------------------------------------------------------------------------------------- */
/* Runtime trace callback system                                                                 */
/* --------------------------------------------------------------------------------------------- */

/* Trace severity levels */
typedef enum
{
    SSF_TLS_TRACE_ERROR,    /* Protocol errors, verification failures */
    SSF_TLS_TRACE_WARN,     /* Non-fatal issues */
    SSF_TLS_TRACE_INFO,     /* Handshake milestones */
    SSF_TLS_TRACE_DEBUG,    /* Record I/O, extension parsing */
} SSFTLSTraceLevel_t;

/* Trace categories */
typedef enum
{
    SSF_TLS_TRACE_HANDSHAKE,  /* Handshake state machine */
    SSF_TLS_TRACE_RECORD,     /* Record layer I/O */
    SSF_TLS_TRACE_CRYPTO,     /* Key derivation, signatures */
    SSF_TLS_TRACE_CERT,       /* Certificate chain verification */
    SSF_TLS_TRACE_ALERT,      /* TLS alerts */
} SSFTLSTraceCategory_t;

/* Per-connection trace callback. msg is a formatted string. userCtx is from SSFTLSCSetTrace. */
typedef void (*SSFTLSTraceFn_t)(SSFTLSTraceLevel_t level, SSFTLSTraceCategory_t category,
                                const char *msg, void *userCtx);

/* Trace context -- stored in each session, passed to internal functions. */
typedef struct SSFTLSTraceCtx
{
    SSFTLSTraceFn_t fn;
    void *userCtx;
} SSFTLSTraceCtx_t;

/* Internal trace macro: formats and invokes the callback if set. Zero overhead when fn is NULL. */
#define _SSF_TLS_TRACE(tctx, level, cat, ...) do { \
    if ((tctx) != NULL && (tctx)->fn != NULL) { \
        char _tlsTraceBuf[256]; \
        snprintf(_tlsTraceBuf, sizeof(_tlsTraceBuf), __VA_ARGS__); \
        (tctx)->fn(level, cat, _tlsTraceBuf, (tctx)->userCtx); \
    } } while (0)

/* Convenience macros -- use T as the SSFTLSTraceCtx_t pointer */
#define SSF_TLS_TRACE_HS_INFO(T, ...)    _SSF_TLS_TRACE(T, SSF_TLS_TRACE_INFO, SSF_TLS_TRACE_HANDSHAKE, __VA_ARGS__)
#define SSF_TLS_TRACE_HS_ERROR(T, ...)   _SSF_TLS_TRACE(T, SSF_TLS_TRACE_ERROR, SSF_TLS_TRACE_HANDSHAKE, __VA_ARGS__)
#define SSF_TLS_TRACE_HS_DEBUG(T, ...)   _SSF_TLS_TRACE(T, SSF_TLS_TRACE_DEBUG, SSF_TLS_TRACE_HANDSHAKE, __VA_ARGS__)
#define SSF_TLS_TRACE_REC_DEBUG(T, ...)  _SSF_TLS_TRACE(T, SSF_TLS_TRACE_DEBUG, SSF_TLS_TRACE_RECORD, __VA_ARGS__)
#define SSF_TLS_TRACE_REC_ERROR(T, ...)  _SSF_TLS_TRACE(T, SSF_TLS_TRACE_ERROR, SSF_TLS_TRACE_RECORD, __VA_ARGS__)
#define SSF_TLS_TRACE_CRYPTO_INFO(T, ...) _SSF_TLS_TRACE(T, SSF_TLS_TRACE_INFO, SSF_TLS_TRACE_CRYPTO, __VA_ARGS__)
#define SSF_TLS_TRACE_CRYPTO_ERROR(T, ...) _SSF_TLS_TRACE(T, SSF_TLS_TRACE_ERROR, SSF_TLS_TRACE_CRYPTO, __VA_ARGS__)
#define SSF_TLS_TRACE_CRYPTO_DEBUG(T, ...) _SSF_TLS_TRACE(T, SSF_TLS_TRACE_DEBUG, SSF_TLS_TRACE_CRYPTO, __VA_ARGS__)
#define SSF_TLS_TRACE_CERT_INFO(T, ...)  _SSF_TLS_TRACE(T, SSF_TLS_TRACE_INFO, SSF_TLS_TRACE_CERT, __VA_ARGS__)
#define SSF_TLS_TRACE_CERT_ERROR(T, ...) _SSF_TLS_TRACE(T, SSF_TLS_TRACE_ERROR, SSF_TLS_TRACE_CERT, __VA_ARGS__)
#define SSF_TLS_TRACE_CERT_DEBUG(T, ...) _SSF_TLS_TRACE(T, SSF_TLS_TRACE_DEBUG, SSF_TLS_TRACE_CERT, __VA_ARGS__)
#define SSF_TLS_TRACE_ALERT(T, ...)      _SSF_TLS_TRACE(T, SSF_TLS_TRACE_WARN, SSF_TLS_TRACE_ALERT, __VA_ARGS__)

/* Legacy compatibility macro -- uses session->trace as the context */
#define SSF_TLS_TRACE(...)  /* removed -- use category-specific macros instead */

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */

/* Protocol constants */
#define SSF_TLS_VERSION_12         (0x0303u) /* Legacy record version */
#define SSF_TLS_VERSION_13         (0x0304u) /* TLS 1.3 */
#define SSF_TLS_RECORD_HEADER_SIZE (5u)
#define SSF_TLS_AEAD_TAG_SIZE      (16u)
#define SSF_TLS_MAX_HASH_SIZE      (48u)     /* SHA-384 */
#define SSF_TLS_MAX_KEY_SIZE       (32u)     /* AES-256 */
#define SSF_TLS_IV_SIZE            (12u)

/* Content types */
#define SSF_TLS_CT_CHANGE_CIPHER   ((uint8_t)20u)
#define SSF_TLS_CT_ALERT           ((uint8_t)21u)
#define SSF_TLS_CT_HANDSHAKE       ((uint8_t)22u)
#define SSF_TLS_CT_APPLICATION     ((uint8_t)23u)

/* Handshake types */
#define SSF_TLS_HS_CLIENT_HELLO         ((uint8_t)1u)
#define SSF_TLS_HS_SERVER_HELLO         ((uint8_t)2u)
#define SSF_TLS_HS_NEW_SESSION_TICKET   ((uint8_t)4u)
#define SSF_TLS_HS_CERTIFICATE_REQUEST  ((uint8_t)13u)
#define SSF_TLS_HS_KEY_UPDATE           ((uint8_t)24u)
#define SSF_TLS_HS_ENCRYPTED_EXTENSIONS ((uint8_t)8u)
#define SSF_TLS_HS_CERTIFICATE          ((uint8_t)11u)
#define SSF_TLS_HS_CERTIFICATE_VERIFY   ((uint8_t)15u)
#define SSF_TLS_HS_FINISHED             ((uint8_t)20u)

/* Cipher suites */
#define SSF_TLS_CS_AES_128_GCM_SHA256   (0x1301u)
#define SSF_TLS_CS_AES_256_GCM_SHA384   (0x1302u)
#define SSF_TLS_CS_AES_128_CCM_SHA256   (0x1304u)
#define SSF_TLS_CS_AES_128_CCM_8_SHA256 (0x1305u)
#define SSF_TLS_CS_CHACHA20_POLY1305_SHA256 (0x1303u)

/* Named groups for key exchange */
#define SSF_TLS_GROUP_SECP256R1  (0x0017u)
#define SSF_TLS_GROUP_SECP384R1  (0x0018u)
#define SSF_TLS_GROUP_X25519     (0x001Du)

/* Signature schemes (RFC 8446 Section 4.2.3) */
#define SSF_TLS_SIG_ECDSA_SECP256R1_SHA256 (0x0403u)
#define SSF_TLS_SIG_ECDSA_SECP384R1_SHA384 (0x0503u)
#define SSF_TLS_SIG_RSA_PSS_RSAE_SHA256    (0x0804u)
#define SSF_TLS_SIG_RSA_PSS_RSAE_SHA384    (0x0805u)
#define SSF_TLS_SIG_RSA_PKCS1_SHA256       (0x0401u)
#define SSF_TLS_SIG_RSA_PKCS1_SHA384       (0x0501u)
#define SSF_TLS_SIG_ED25519                (0x0807u)

/* Maximum size of the CertificateVerify "signed content" bytes that are handed to the           */
/* signature primitive. RFC 8446 Section 4.4.3 defines this as 64 filler bytes + 33 context      */
/* bytes + 1 separator + transcript hash (up to 48 bytes for SHA-384). Ed25519 signs this raw    */
/* buffer (no pre-hash), so crypto work structs need a buffer at least this size.                 */
#define SSF_TLS_CV_SIGN_CONTENT_MAX_SIZE   (98u + 48u)

/* Extension types */
#define SSF_TLS_EXT_SERVER_NAME        (0u)
#define SSF_TLS_EXT_SUPPORTED_GROUPS   (10u)
#define SSF_TLS_EXT_SIGNATURE_ALGS     (13u)
#define SSF_TLS_EXT_SUPPORTED_VERSIONS (43u)
#define SSF_TLS_EXT_ALPN               (16u)
#define SSF_TLS_EXT_PSK_KEY_EXCHANGE   (45u)
#define SSF_TLS_EXT_PRE_SHARED_KEY     (41u)
#define SSF_TLS_EXT_KEY_SHARE          (51u)

/* Alert descriptions */
#define SSF_TLS_ALERT_CLOSE_NOTIFY        ((uint8_t)0u)
#define SSF_TLS_ALERT_UNEXPECTED_MSG      ((uint8_t)10u)
#define SSF_TLS_ALERT_BAD_RECORD_MAC      ((uint8_t)20u)
#define SSF_TLS_ALERT_HANDSHAKE_FAILURE   ((uint8_t)40u)
#define SSF_TLS_ALERT_BAD_CERTIFICATE     ((uint8_t)42u)
#define SSF_TLS_ALERT_CERTIFICATE_UNKNOWN ((uint8_t)46u)
#define SSF_TLS_ALERT_DECODE_ERROR        ((uint8_t)50u)
#define SSF_TLS_ALERT_DECRYPT_ERROR       ((uint8_t)51u)
#define SSF_TLS_ALERT_INTERNAL_ERROR      ((uint8_t)80u)

/* --------------------------------------------------------------------------------------------- */
/* TLS transport I/O result (supports non-blocking operation)                                     */
/* --------------------------------------------------------------------------------------------- */
typedef enum
{
    SSF_TLS_IO_SUCCESS,      /* All requested bytes transferred */
    SSF_TLS_IO_WANT_READ,    /* Socket not ready for reading -- call again later */
    SSF_TLS_IO_WANT_WRITE,   /* Socket not ready for writing -- call again later */
    SSF_TLS_IO_ERROR,        /* Fatal error -- connection lost */
} SSFTLSIOResult_t;

/* --------------------------------------------------------------------------------------------- */
/* Typedefs                                                                                      */
/* --------------------------------------------------------------------------------------------- */

/* Transcript hash context (running hash of handshake messages). */
typedef struct SSFTLSTranscript
{
    union
    {
        SSFSHA2_32Context_t sha256;
        SSFSHA2_64Context_t sha384;
    } ctx;
    uint16_t hashLen;    /* 32 or 48 */
    SSFHMACHash_t hmac;  /* SSF_HMAC_HASH_SHA256 or SSF_HMAC_HASH_SHA384 */
} SSFTLSTranscript_t;

/* Per-direction record encryption/decryption state. */
typedef struct SSFTLSRecordState
{
    uint8_t key[SSF_TLS_MAX_KEY_SIZE];
    uint8_t iv[SSF_TLS_IV_SIZE];
    uint64_t seqNum;
    uint16_t keyLen;     /* 16 for AES-128, 32 for AES-256 */
    uint16_t cipherSuite;
} SSFTLSRecordState_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface: key schedule                                                              */
/* --------------------------------------------------------------------------------------------- */

/* HKDF-Expand-Label (RFC 8446 Section 7.1). */
void SSFTLSHkdfExpandLabel(SSFHMACHash_t hash,
                           const uint8_t *secret, size_t secretLen,
                           const char *label,
                           const uint8_t *context, size_t ctxLen,
                           uint8_t *out, size_t outLen);

/* Derive-Secret = HKDF-Expand-Label(secret, label, Transcript-Hash, hashLen). */
void SSFTLSDeriveSecret(SSFHMACHash_t hash,
                        const uint8_t *secret, size_t secretLen,
                        const char *label,
                        const uint8_t *transcriptHash, size_t transcriptHashLen,
                        uint8_t *out, size_t outLen);

/* Derive traffic key and IV from a traffic secret. */
void SSFTLSDeriveTrafficKeys(SSFHMACHash_t hash,
                             const uint8_t *trafficSecret, size_t secretLen,
                             uint8_t *key, size_t keyLen,
                             uint8_t *iv, size_t ivLen);

/* Compute the Finished verify_data: HMAC(finished_key, transcript_hash). */
void SSFTLSComputeFinished(SSFHMACHash_t hash,
                           const uint8_t *baseKey, size_t baseKeyLen,
                           const uint8_t *transcriptHash, size_t transcriptHashLen,
                           uint8_t *verifyData, size_t verifyDataLen);

/* --------------------------------------------------------------------------------------------- */
/* External interface: transcript hash                                                           */
/* --------------------------------------------------------------------------------------------- */

void SSFTLSTranscriptInit(SSFTLSTranscript_t *t, SSFHMACHash_t hash);
void SSFTLSTranscriptUpdate(SSFTLSTranscript_t *t, const uint8_t *data, size_t len);
void SSFTLSTranscriptHash(const SSFTLSTranscript_t *t, uint8_t *out, size_t outSize);

/* --------------------------------------------------------------------------------------------- */
/* External interface: record layer                                                              */
/* --------------------------------------------------------------------------------------------- */

/* Initialize record state with derived traffic keys. */
void SSFTLSRecordStateInit(SSFTLSRecordState_t *state, uint16_t cipherSuite,
                           const uint8_t *key, size_t keyLen,
                           const uint8_t *iv, size_t ivLen);

/* Encrypt plaintext into a TLS record (header + ciphertext + tag).                              */
/* record must have room for SSF_TLS_RECORD_HEADER_SIZE + ptLen + 1 + SSF_TLS_AEAD_TAG_SIZE.     */
bool SSFTLSRecordEncrypt(SSFTLSRecordState_t *state, uint8_t contentType,
                         const uint8_t *pt, size_t ptLen,
                         uint8_t *record, size_t recordSize, size_t *recordLen);

/* Decrypt a TLS record. Validates AEAD tag and extracts inner content type.                     */
bool SSFTLSRecordDecrypt(SSFTLSRecordState_t *state,
                         const uint8_t *record, size_t recordLen,
                         uint8_t *pt, size_t ptSize, size_t *ptLen,
                         uint8_t *contentType);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_TLS_UNIT_TEST == 1
void SSFTLSUnitTest(void);
#endif /* SSF_CONFIG_TLS_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_TLS_H_INCLUDE */
