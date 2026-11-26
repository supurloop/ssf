/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftlsc.h                                                                                     */
/* Provides TLS 1.3 client handshake and encrypted transport interface (RFC 8446).               */
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
#ifndef SSF_TLSC_H_INCLUDE
#define SSF_TLSC_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssftls.h"
#include "ssfnet.h"
#include "ssfx509.h"
#include "ssfpkey.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* Trust store: array of DER-encoded CA certificates */
typedef struct SSFTLSCTrustStore
{
    const uint8_t **caDer;
    const uint32_t *caDerLen;
    uint8_t count;
} SSFTLSCTrustStore_t;

/* SSFTLSCTrustFromPEM() results */
typedef enum
{
    SSF_TLSC_TRUST_OK,
    SSF_TLSC_TRUST_ERR_PEM,     /* A malformed PEM block (BEGIN / END lines, Base64) */
    SSF_TLSC_TRUST_ERR_LABEL,   /* A block that is not a CERTIFICATE */
    SSF_TLSC_TRUST_ERR_CERT,    /* A CERTIFICATE that is not exactly one X.509 certificate */
    SSF_TLSC_TRUST_ERR_COUNT,   /* More certificates than maxCount (255 when measuring) */
    SSF_TLSC_TRUST_ERR_SIZE,    /* The certificates do not fit poolSize bytes */
    SSF_TLSC_TRUST_ERR_EMPTY,   /* No certificate in the input */
} SSFTLSCTrustResult_t;

/* TLS client handshake states, advanced by pollOpen() */
typedef enum
{
    SSF_TLSC_HS_IDLE,
    SSF_TLSC_HS_SEND_CH,
    SSF_TLSC_HS_RECV_SH,
    SSF_TLSC_HS_DERIVE_HS_KEYS,      /* Crypto step: ECDH + handshake key schedule */
    SSF_TLSC_HS_RECV_EE_CERT,
    SSF_TLSC_HS_VERIFY_CHAIN,        /* Crypto step: certificate chain verification */
    SSF_TLSC_HS_RECV_CV,
    SSF_TLSC_HS_VERIFY_SIG,          /* Crypto step: CertificateVerify signature */
    SSF_TLSC_HS_RECV_FIN_SEND_FIN,   /* Without client authentication, also sends the Finished */
    SSF_TLSC_HS_SEND_CLIENT_CERT,    /* Client authentication: the Certificate, record by record */
    SSF_TLSC_HS_SIGN_CV,             /* Crypto step: the client CertificateVerify signature */
    SSF_TLSC_HS_SEND_CV_FIN,         /* Client authentication: CertificateVerify + Finished */
    SSF_TLSC_HS_COMPLETE,
    SSF_TLSC_HS_ERROR,
} SSFTLSCHandshakeState_t;

/* Forward declaration for self-reference in crypto work struct */
struct SSFTLSCSession;

/* Inputs and results of the crypto steps, carried between pollOpen() calls */
typedef struct SSFTLSCCryptoWork
{
    struct SSFTLSCSession *session;

    /* Phase 3: key exchange results */
    uint8_t serverPubKey[133];
    uint8_t serverPubKeyLen;
    uint16_t serverGroup;
    bool keyExchangeOk;

    /* Phase 5b: cert chain verification */
    const uint8_t *chainDerPtrs[SSF_X509_CONFIG_MAX_CHAIN_DEPTH];
    uint32_t chainDerLens[SSF_X509_CONFIG_MAX_CHAIN_DEPTH];
    uint8_t chainLen;                /* Certificates kept (at most the x509 chain depth) */
    uint8_t chainSeen;               /* Certificates the server sent (saturates at 255) */
    const char *hostname;
    uint64_t nowUnixSec;
    bool nowValid;                   /* nowUnixSec came from a set RTC */
    bool chainVerifyOk;
    SSFX509VerifyErr_t chainVerifyErr;    /* Why chain verification failed */

    /* Phase 6b: CertificateVerify signature verification */
    uint16_t sigScheme;
    /* Sign content hash, or for Ed25519 (0x0807) the raw sign content (RFC 8032 hashes it) */
    uint8_t contentHash[SSF_TLS_CV_SIGN_CONTENT_MAX_SIZE];
    size_t contentHashLen;
    const uint8_t *sigData;
    uint32_t sigDataLen;
    const uint8_t *leafPubKey;
    uint32_t leafPubKeyLen;
    bool sigVerifyOk;
} SSFTLSCCryptoWork_t;

/* Public key type of the server's end-entity certificate, for matching CertificateVerify */
typedef enum
{
    SSF_TLSC_LEAF_KEY_UNKNOWN,
    SSF_TLSC_LEAF_KEY_P256,          /* id-ecPublicKey, secp256r1 */
    SSF_TLSC_LEAF_KEY_P384,          /* id-ecPublicKey, secp384r1 */
    SSF_TLSC_LEAF_KEY_RSA,           /* rsaEncryption */
    SSF_TLSC_LEAF_KEY_ED25519
} SSFTLSCLeafKey_t;

/* Partial I/O tracking for resumable record send/receive */
typedef struct SSFTLSCIOCtx
{
    uint8_t hdr[SSF_TLS_RECORD_HEADER_SIZE]; /* The record header being received / judged */
    size_t hdrPos;                   /* Header bytes received into hdr */
    uint16_t fragLen;
    size_t fragPos;
    uint8_t *fragDst;                /* Where the fragment is being received (in hsBuf) */
    bool hdrComplete;
    uint8_t sendRecordBuf[SSF_TLS_RECORD_HEADER_SIZE + SSF_TLSC_CONFIG_MAX_SEND_RECORD + 1u +
                          SSF_TLS_AEAD_TAG_SIZE];
    size_t sendTotal;
    size_t sendPos;
    bool sendPending;
} SSFTLSCIOCtx_t;

#define SSF_TLSC_MAX_HOST_SIZE (256u)   /* Host name passed to open(), including the NUL */
/* hsBuf's data room for a whole TLSInnerPlaintext; hsBuf holds the AEAD tag beyond it */
#define SSF_TLSC_HSBUF_SIZE (SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u)
#define SSF_TLSC_CH_SIZE (768u)         /* Handshake scratch: ClientHello, server key, flight */
/* The largest ClientHello1 without ALPN (a 255-byte host name in server_name) */
#define SSF_TLSC_CH1_MAX_NO_ALPN (543u)
/* The ClientHello goes out as one plaintext record, so a record must hold the largest one */
#if SSF_TLSC_CONFIG_MAX_SEND_RECORD < SSF_TLSC_CH_SIZE
#error SSF_TLSC_CONFIG_MAX_SEND_RECORD must be at least SSF_TLSC_CH_SIZE (768) to send the ClientHello.
#endif

/* TLS client session */
typedef struct SSFTLSCSession
{
    SSFNetTransport_t transport;     /* Must be first; this is what a client is handed */
    SSFNetTransport_t *inner;        /* Byte stream the records travel over */
    bool peerClosed;                 /* Inner transport reported CLOSED */
    bool innerOpen;                  /* inner->open() succeeded and close() is still owed */
    bool ioFailed;                   /* Inner transport failed: no alert can be delivered */
    bool peerAlerted;                /* Peer sent a fatal alert: none is sent back (RFC 8446 6) */
    bool peerCloseNotify;            /* Peer sent close_notify: answered with close_notify */
    bool closeNotifySent;            /* shutdown() encrypted close_notify: no more data sent */
    bool clientHelloSent;            /* The peer has seen this handshake begin */
    uint8_t pendingAlert;            /* Fatal alert for the first failure; 0 = none recorded */

    /* Negotiated */
    uint16_t cipherSuite;
    SSFHMACHash_t hash;
    uint16_t hashLen;
    uint16_t keyLen;
    bool connected;

    /* Key material */
    uint8_t clientHsTrafficSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t serverHsTrafficSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t clientAppTrafficSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t serverAppTrafficSecret[SSF_TLS_MAX_HASH_SIZE];

    /* Record encryption state (send/recv) */
    SSFTLSRecordState_t sendState;
    SSFTLSRecordState_t recvState;
    bool sendStateInited;            /* sendState holds keys and must be de-initialized */
    bool recvStateInited;
    bool sendEncrypted;
    bool recvEncrypted;

    /* Runtime trace callback (NULL = disabled, zero overhead) */
    SSFTLSTraceCtx_t trace;

    /* Transcript hash */
    SSFTLSTranscript_t transcript;

    /* Trust store */
    SSFTLSCTrustStore_t trust;
    bool allowUnauthenticated;       /* Opt-in: connect with no trust anchors (test use only) */

    /* Client certificate (SSFTLSCSetClientCert), caller memory kept across connections */
    const uint8_t *const *clientChainDer;
    const uint32_t *clientChainLens;
    const SSFPKey_t *clientKey;
    uint8_t clientChainCount;        /* 0 = none */

    /* ALPN (SSFTLSCSetALPN), caller memory kept across connections */
    const char *const *alpnProtos;
    uint8_t alpnCount;               /* 0 = not offered */
    uint8_t alpnChosen;              /* 1 + index of the server's choice, 0 = none */

    /* Ephemeral ClientHello keys: X25519 at [0], P-384 at [32]; after an HRR its key at [0] */
    uint8_t ephemeralPrivKey[32u + 48u];

    /* Handshake secret */
    uint8_t savedHandshakeSecret[SSF_TLS_MAX_HASH_SIZE];

    /* HelloRetryRequest bookkeeping for validating the second ServerHello (RFC 8446 4.1.4) */
    SSFTLSCLeafKey_t leafKeyType;    /* Key type of the server's end-entity certificate */
    bool hrrDone;
    uint16_t hrrGroup;               /* Group the HRR selected; the only share in ClientHello2 */
    uint16_t hrrSuite;               /* Cipher suite the HRR selected; ServerHello must match */

    /* record_size_limit (RFC 8449): largest TLSInnerPlaintext the server accepts, 0 = none */
    uint16_t peerRecordLimit;

    /* CertificateRequest received; clientScheme 0 = answer with an empty Certificate */
    bool certRequested;
    uint16_t clientScheme;
    uint32_t certSendOff;            /* Bytes of the client flight message sent so far */

    /* Post-handshake handshake message (RFC 8446 4.6) being parsed record by record */
    uint8_t phHdr[4];
    uint8_t phHdrLen;
    uint8_t phType;
    uint32_t phRemain;
    bool keyUpdateOwed;              /* Server asked for a KeyUpdate: sent before the next data */
    uint32_t sendRecordsOnKey;       /* Records sent under the current client application key */

    /* Handshake scratch: one buffer owned by one phase at a time, length in hsScratchLen */
    union
    {
        uint8_t clientHello[SSF_TLSC_CH_SIZE];   /* SEND_CH until the ServerHello is processed */
        uint8_t leafPubKey[SSF_TLSC_CH_SIZE];    /* RECV_EE_CERT until VERIFY_SIG */
        uint8_t clientFlight[SSF_TLSC_CH_SIZE];  /* SIGN_CV until SEND_CV_FIN has sent it */
    } hsScratch;
    size_t hsScratchLen;

    /* The one receive buffer: records decrypted in place, handshake messages reassembled */
    uint8_t hsBuf[SSF_TLSC_HSBUF_SIZE + SSF_TLS_AEAD_TAG_SIZE];
    size_t hsBufLen;                 /* Total bytes in hsBuf */
    size_t hsBufPos;                 /* Current parse position */

    /* Partial I/O context for resumable record send/receive */
    SSFTLSCIOCtx_t ioCtx;

    /* Async handshake state */
    SSFTLSCHandshakeState_t hsState;
    SSFTLSCCryptoWork_t cryptoWork;
    char host[SSF_TLSC_MAX_HOST_SIZE];
    const char *hsHostname;          /* = host */
    uint16_t hsPort;
    uint8_t helperStep;              /* Per-state helper sub-step, reset to 0 on each transition */
    uint32_t magic;
} SSFTLSCSession_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Initializes a session over inner; pass &session->transport to the client */
void SSFTLSCInit(SSFTLSCSession_t *session, SSFNetTransport_t *inner,
                 const SSFTLSCTrustStore_t *trustStoreOpt);

/* Builds a trust store from a PEM certificate or bundle, or measures it with poolOpt NULL */
SSFTLSCTrustResult_t SSFTLSCTrustFromPEM(const char *pem, size_t pemLen, uint8_t *poolOpt,
                                         size_t poolSize, const uint8_t **dersOpt,
                                         uint32_t *lensOpt, uint8_t maxCount,
                                         SSFTLSCTrustStore_t *storeOpt, size_t *poolUsedOut,
                                         uint8_t *countOut);

/* Closes any connection, wipes the session and releases it */
void SSFTLSCDeInit(SSFTLSCSession_t *session);

#if SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED == 1
/* Opts in to connecting with no trust anchors; for tests and development only */
void SSFTLSCSetUnauthenticated(SSFTLSCSession_t *session, bool allow);
#else
/* Compiled out (SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED is 0): any call is a compile error */
#define SSFTLSCSetUnauthenticated(session, allow) do { \
    typedef char SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED_is_0_unauthenticated_mode_compiled_out[-1]; \
    } while (0)
#endif

/* Sets, or clears with all NULL / 0, the client certificate chain and key for mutual TLS */
bool SSFTLSCSetClientCert(SSFTLSCSession_t *session, const uint8_t *const *chainDerOpt,
                          const uint32_t *chainLensOpt, uint8_t chainCount,
                          const SSFPKey_t *keyOpt);

/* Sets, or clears with NULL, 0, the protocols offered with ALPN, in preference order */
bool SSFTLSCSetALPN(SSFTLSCSession_t *session, const char *const *protosOpt, uint8_t count);

/* Returns the protocol the server chose once the handshake is complete, else NULL */
const char *SSFTLSCGetALPN(const SSFTLSCSession_t *session);

/* Sets an optional per-connection trace callback; NULL traceFnOpt disables tracing */
void SSFTLSCSetTrace(SSFTLSCSession_t *session, SSFTLSTraceFn_t traceFnOpt, void *traceCtxOpt);

/* Returns the current handshake state */
SSFTLSCHandshakeState_t SSFTLSCGetHandshakeState(const SSFTLSCSession_t *session);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_TLSC_UNIT_TEST == 1
void SSFTLSCUnitTest(void);
bool _SSFTLSCParseCertificateForTest(const uint8_t *body, size_t bodyLen,
                                     const uint8_t **ders, uint32_t *lens, uint8_t *countOut);
bool _SSFTLSCParseCertificateSeenForTest(const uint8_t *body, size_t bodyLen,
                                         const uint8_t **ders, uint32_t *lens, uint8_t *countOut,
                                         uint8_t *seenOut);
extern void (*_SSFTLSCScrubTestHook)(void *ctx, const char *whatStr, const void *buf,
                                     size_t bufLen);
extern void *_SSFTLSCScrubTestHookCtx;
bool _SSFTLSCIsIPLiteralForTest(const char *hostStr);
bool _SSFTLSCSchemeMatchesKeyForTest(uint16_t scheme, SSFTLSCLeafKey_t key);
bool _SSFTLSCSaveLeafKeyForTest(SSFTLSCSession_t *session, const uint8_t *der, uint32_t derLen);
uint8_t _SSFTLSCChainAlertForTest(SSFX509VerifyCode_t code);
bool _SSFTLSCParseEncryptedExtensionsForTest(const uint8_t *body, size_t bodyLen,
                                             uint8_t *alertOut);
void _SSFTLSCInjectClientHelloForTest(const uint8_t *chOpt, size_t chLen,
                                      const uint8_t *x25519PrivOpt);
void _SSFTLSCInjectClientHello2ForTest(const uint8_t *ch2Opt, size_t ch2Len,
                                       const uint8_t *ecPrivOpt);
bool _SSFTLSCParseServerHelloExForTest(SSFTLSCSession_t *session, const uint8_t *body,
                                       size_t bodyLen, bool isHrr, uint16_t hrrGroup,
                                       uint16_t hrrSuite, uint8_t *alertOut, uint16_t *groupOut,
                                       uint8_t *pubOut, size_t *pubLenOut,
                                       const uint8_t **cookieOut, uint16_t *cookieLenOut);
bool _SSFTLSCParseServerHelloForTest(SSFTLSCSession_t *session, const uint8_t *body,
                                     size_t bodyLen, bool isHrr, uint8_t *alertOut);
SSFTLSIOResult_t _SSFTLSCSendHandshakeForTest(SSFTLSCSession_t *session, const uint8_t *msg,
                                              size_t msgLen);
bool _SSFTLSCParseEncryptedExtensionsAlpnForTest(SSFTLSCSession_t *session, const uint8_t *body,
                                                 size_t bodyLen, uint8_t *alertOut);
bool _SSFTLSCParseEncryptedExtensionsRslForTest(const uint8_t *body, size_t bodyLen,
                                                uint8_t *alertOut, uint16_t *recordLimitOut);
bool _SSFTLSCParseCertificateVerifyForTest(const uint8_t *body, size_t bodyLen,
                                           uint16_t *schemeOut, uint16_t *sigLenOut);
bool _SSFTLSCParseCertificateRequestForTest(const uint8_t *body, size_t bodyLen,
                                            uint8_t *alertOut);
bool _SSFTLSCChooseClientSchemeForTest(const uint8_t *body, size_t bodyLen, SSFPKeyType_t keyType,
                                       uint16_t *schemeOut, uint8_t *alertOut);
bool _SSFTLSCPostHandshakeFeedForTest(SSFTLSCSession_t *session, const uint8_t *rec,
                                      size_t recLen, uint8_t *alertOut, uint8_t *keyUpdateOut);
void _SSFTLSCNextTrafficSecretForTest(const SSFTLSCSession_t *session, uint8_t *secret);
bool _SSFTLSCRecordTypeAllowedForTest(const SSFTLSCSession_t *session, uint8_t contentType);
bool _SSFTLSCChooseClientSchemeChainForTest(SSFTLSCSession_t *session, const uint8_t *body,
                                            size_t bodyLen, bool nowValid, uint64_t nowUnixSec,
                                            uint16_t *schemeOut, uint8_t *alertOut);
size_t _SSFTLSCClientCertMsgLenForTest(const SSFTLSCSession_t *session);
void _SSFTLSCClientCertMsgCopyForTest(const SSFTLSCSession_t *session, size_t off, uint8_t *dst,
                                      size_t dstSize);
bool _SSFTLSCSignClientCVForTest(SSFTLSCSession_t *session, uint16_t scheme,
                                 const uint8_t *transcriptHash, size_t hashLen, uint8_t *msgOut,
                                 size_t msgSize, size_t *msgLenOut);
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_TLSC_H_INCLUDE */
