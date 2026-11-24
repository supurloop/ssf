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

/* --------------------------------------------------------------------------------------------- */
/* Design                                                                                        */
/* --------------------------------------------------------------------------------------------- */
/* - TLS 1.3 client (RFC 8446) over any byte-stream SSFNetTransport_t, normally ssfnetsock.      */
/*   The session is itself an SSFNetTransport_t: pass &session->transport to a client such as    */
/*   ssfmqttc. open() opens the inner transport; pollOpen() drives the inner open and then the   */
/*   handshake; send()/recv() carry application data; shutdown() writes out a partly written     */
/*   record and close_notify; close() ends both and never waits, so bytes send() accepted can be */
/*   lost without a shutdown() first.                                                            */
/* - No I/O blocks and no threads are used. Public-key work runs inline in pollOpen(), in three  */
/*   steps: key exchange (X25519 or P-256 ECDH), certificate chain verification, and the         */
/*   CertificateVerify signature. A call runs at most one step, then returns WANT_READ; the call */
/*   that completes the triggering message (ServerHello, Certificate, CertificateVerify) also    */
/*   runs its step. Each step occupies the caller for the whole computation: there is no finer  */
/*   split. Chain verification is the longest: it checks every signature in the chain plus the   */
/*   trust anchor's in one call, so its time grows with the chain length and is set by the      */
/*   slowest algorithms involved (P-384 and RSA-3072/4096 well above P-256, Ed25519 and         */
/*   RSA-2048). Size a single-threaded application's latency budget for that call.             */
/* - RSA keys are 2048 to 4096 bits (ssfrsa.md): a server or CA key larger than 4096 bits fails */
/*   the handshake. The largest size enabled in ssfrsa_opt.h sets the RSA verify stack (about   */
/*   10.9 KB at 4096, 5.7 KB at 2048 on Cortex-M4 -Os), whatever key size the server uses.      */
/* - Stack: pollOpen() needs about 18.9 KB below its caller's frame (Cortex-M4, gcc -Os, static */
/*   call graph, SSF_X509_CONFIG_MAX_CHAIN_DEPTH 6). The peak is chain verification: the 6.6 KB */
/*   of parsed certificates in SSFX509VerifyChainPurpose over an RSA signature check. Largest   */
/*   enabled RSA size 3072: 16.3 KB; 2048: 14.9 KB (an ECDSA check is then the deepest). Not    */
/*   included: the inner transport's functions, the trace callback, libc and the port layer.    */
/*   Key exchange and the other steps need less. Each chain entry adds about 1.1 KB.            */
/* - Client mode, full handshake only (no PSK resumption or 0-RTT). One connection per session.  */
/* - No client certificate. A server CertificateRequest is checked and answered with an empty   */
/*   Certificate before the client Finished (RFC 8446 4.4.2): a server that only asks carries  */
/*   on. One that requires a certificate sends certificate_required after the client Finished, */
/*   so pollOpen() has already reported success; the first recv() then fails and the trace     */
/*   says the server requires a client certificate.                                            */
/* - IPv4 only (ssfnet.h): open() refuses an IPv6 literal host whatever the inner transport.     */
/* - Chain limit: SSF_X509_CONFIG_MAX_CHAIN_DEPTH, the verifier's own. Certificates a server     */
/*   sends past it are dropped; if verification then fails, the trace says the chain was cut.   */
/* - The handshake has no timer of its own; the caller bounds it (ssfmqttc's connectTimeout).    */
/* - Certificate validity needs the time. SSFRTCInit() must have been called before a          */
/*   handshake with trust anchors; using ssfrtc uninitialized is a programming error and         */
/*   asserts (ssfrtc.md). A time that is not valid, or before                                    */
/*   SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC (the simulated RTC reads 1970 until SSFRTCSet()),     */
/*   fails the handshake with internal_error rather than checking certificates against it.      */
/* - Known gaps are tracked in ssftlsc_punchlist.md; this module is not yet production ready.    */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* Trust store: array of DER-encoded CA certificates.                                            */
typedef struct SSFTLSCTrustStore
{
    const uint8_t **caDer;
    const uint32_t *caDerLen;
    uint8_t count;
} SSFTLSCTrustStore_t;

/* TLS client handshake states, advanced by pollOpen() */
typedef enum
{
    SSF_TLSC_HS_IDLE,
    SSF_TLSC_HS_SEND_CH,
    SSF_TLSC_HS_RECV_SH,
    SSF_TLSC_HS_DERIVE_HS_KEYS,      /* Crypto step: ECDH + handshake key schedule              */
    SSF_TLSC_HS_RECV_EE_CERT,
    SSF_TLSC_HS_VERIFY_CHAIN,        /* Crypto step: certificate chain verification             */
    SSF_TLSC_HS_RECV_CV,
    SSF_TLSC_HS_VERIFY_SIG,          /* Crypto step: CertificateVerify signature                */
    SSF_TLSC_HS_RECV_FIN_SEND_FIN,
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
    uint8_t chainLen;                /* Certificates kept (at most the x509 chain depth)        */
    uint8_t chainSeen;               /* Certificates the server sent (saturates at 255)         */
    const char *hostname;
    uint64_t nowUnixSec;
    bool nowValid;                   /* nowUnixSec came from a set RTC                          */
    bool chainVerifyOk;
    SSFX509VerifyErr_t chainVerifyErr;    /* Why chain verification failed */

    /* Phase 6b: CertificateVerify signature verification */
    uint16_t sigScheme;
    /* For SHA-256/SHA-384 schemes this holds the pre-computed hash of the sign content.         */
    /* For Ed25519 (0x0807) this holds the raw sign content bytes (up to 146) which the Ed25519  */
    /* primitive hashes internally per RFC 8032.                                                  */
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
    SSF_TLSC_LEAF_KEY_P256,          /* id-ecPublicKey, secp256r1                               */
    SSF_TLSC_LEAF_KEY_P384,          /* id-ecPublicKey, secp384r1                               */
    SSF_TLSC_LEAF_KEY_RSA,           /* rsaEncryption                                           */
    SSF_TLSC_LEAF_KEY_ED25519
} SSFTLSCLeafKey_t;

/* Partial I/O tracking for resumable record send/receive */
typedef struct SSFTLSCIOCtx
{
    size_t hdrPos;                   /* Header bytes received into recvBuf[0..4]                */
    uint16_t fragLen;
    size_t fragPos;
    bool hdrComplete;
    uint8_t sendRecordBuf[SSF_TLS_RECORD_HEADER_SIZE + SSF_TLSC_CONFIG_MAX_SEND_RECORD + 1u +
                          SSF_TLS_AEAD_TAG_SIZE];
    size_t sendTotal;
    size_t sendPos;
    bool sendPending;
} SSFTLSCIOCtx_t;

#define SSF_TLSC_MAX_HOST_SIZE (256u)   /* Host name passed to open(), including the NUL       */

/* TLS client session. */
typedef struct SSFTLSCSession
{
    SSFNetTransport_t transport;     /* Must be first; this is what a client is handed          */
    SSFNetTransport_t *inner;        /* Byte stream the records travel over                     */
    bool peerClosed;                 /* Inner transport reported CLOSED                         */
    bool innerOpen;                  /* inner->open() succeeded and close() is still owed       */
    bool ioFailed;                   /* Inner transport failed: no alert can be delivered      */
    bool peerAlerted;                /* Peer sent a fatal alert: none is sent back (RFC 8446 6) */
    bool peerCloseNotify;            /* Peer sent close_notify: answered with close_notify     */
    bool closeNotifySent;            /* shutdown() encrypted close_notify: no more data sent   */
    bool clientHelloSent;            /* The peer has seen this handshake begin                 */
    uint8_t pendingAlert;            /* Fatal alert for the first failure; 0 = none recorded   */

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
    bool sendStateInited;            /* sendState holds keys and must be de-initialized        */
    bool recvStateInited;
    bool sendEncrypted;
    bool recvEncrypted;

    /* Runtime trace callback (NULL = disabled, zero overhead) */
    SSFTLSTraceCtx_t trace;

    /* Transcript hash */
    SSFTLSTranscript_t transcript;

    /* Trust store */
    SSFTLSCTrustStore_t trust;
    bool allowUnauthenticated;       /* Opt-in: connect with no trust anchors (test use only)  */

    /* Ephemeral key (stored separately from recvBuf to avoid corruption) */
    uint8_t ephemeralPrivKey[48];

    /* Handshake secret (stored separately from recvBuf to avoid corruption) */
    uint8_t savedHandshakeSecret[SSF_TLS_MAX_HASH_SIZE];

    /* HelloRetryRequest bookkeeping for validating the second ServerHello (RFC 8446 4.1.4)     */
    SSFTLSCLeafKey_t leafKeyType;    /* Key type of the server's end-entity certificate         */
    bool hrrDone;
    uint16_t hrrGroup;               /* Group the HRR selected; the only share in ClientHello2  */
    uint16_t hrrSuite;               /* Cipher suite the HRR selected; ServerHello must match   */

    /* record_size_limit (RFC 8449) from EncryptedExtensions: the largest TLSInnerPlaintext the  */
    /* server accepts, 64..2^14+1; 0 when not negotiated.                                        */
    uint16_t peerRecordLimit;

    /* The server sent a CertificateRequest: the client answers with an empty Certificate       */
    /* (RFC 8446 4.4.2) before its Finished.                                                   */
    bool certRequested;

    /* Saved ClientHello for transcript re-init when server selects SHA-384 suite */
    uint8_t clientHelloMsg[768];
    size_t clientHelloLen;

    /* Handshake message reassembly buffer (servers may bundle multiple HS msgs in one record). */
    /* After the handshake it holds the decrypted application record being returned by recv(). */
    /* Holds a record's whole TLSInnerPlaintext: content, content type, any zero padding.      */
    uint8_t hsBuf[SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u];
    size_t hsBufLen;   /* total bytes in hsBuf */
    size_t hsBufPos;   /* current parse position */

    /* Record buffer: header at [0..4], fragment after it, so records decrypt in place */
    uint8_t recvBuf[SSF_TLSC_CONFIG_MAX_RECV_RECORD + SSF_TLS_AEAD_TAG_SIZE +
                    SSF_TLS_RECORD_HEADER_SIZE + 1u];

    /* Partial I/O context for resumable record send/receive */
    SSFTLSCIOCtx_t ioCtx;

    /* Async handshake state */
    SSFTLSCHandshakeState_t hsState;
    SSFTLSCCryptoWork_t cryptoWork;
    char host[SSF_TLSC_MAX_HOST_SIZE];
    const char *hsHostname;          /* = host                                                  */
    uint16_t hsPort;
    /* Per-step helper sub-state marker. Semantics are scoped per helper; each _TlscHandle*     */
    /* helper owns its own numbering and resets to 0 on entry to a fresh state. The driver also  */
    /* clears this to 0 on state transitions and ERROR returns.                                   */
    uint8_t helperStep;
    uint32_t magic;
} SSFTLSCSession_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Initializes a session over inner, which must outlive it. trustStoreOpt is copied by value;    */
/* the arrays it points to must stay valid. Pass &session->transport to the client. A session   */
/* with no trust anchors fails closed: open() returns false, unless SSFTLSCSetUnauthenticated() */
/* has opted in (only possible when SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED is 1).                */
void SSFTLSCInit(SSFTLSCSession_t *session, SSFNetTransport_t *inner,
                 const SSFTLSCTrustStore_t *trustStoreOpt);

/* Closes any connection, wipes the session and releases it.                                    */
void SSFTLSCDeInit(SSFTLSCSession_t *session);

#if SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED == 1
/* Opts in (allow true) to connecting with no trust anchors. The server certificate chain and    */
/* host name are then NOT verified, so any party able to intercept the connection can            */
/* impersonate the server. For tests and development only. Has no effect when trust anchors are */
/* configured: they are always used. Call while the session is not open.                       */
void SSFTLSCSetUnauthenticated(SSFTLSCSession_t *session, bool allow);
#else
/* Compiled out (SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED is 0): any call is a compile error.      */
#define SSFTLSCSetUnauthenticated(session, allow) do { \
    typedef char SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED_is_0_unauthenticated_mode_compiled_out[-1]; \
    } while (0)
#endif

/* Sets an optional per-connection trace callback. NULL traceFn disables tracing.               */
void SSFTLSCSetTrace(SSFTLSCSession_t *session, SSFTLSTraceFn_t traceFn, void *traceCtx);

/* Returns the current handshake state.                                                          */
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
extern void (*_SSFTLSCScrubTestHook)(void *ctx, const char *what, const void *buf, size_t len);
extern void *_SSFTLSCScrubTestHookCtx;
bool _SSFTLSCIsIPLiteralForTest(const char *host);
bool _SSFTLSCSchemeMatchesKeyForTest(uint16_t scheme, SSFTLSCLeafKey_t key);
bool _SSFTLSCSaveLeafKeyForTest(SSFTLSCSession_t *session, const uint8_t *der, uint32_t derLen);
uint8_t _SSFTLSCChainAlertForTest(SSFX509VerifyCode_t code);
bool _SSFTLSCParseEncryptedExtensionsForTest(const uint8_t *body, size_t bodyLen,
                                             uint8_t *alertOut);
bool _SSFTLSCParseEncryptedExtensionsRslForTest(const uint8_t *body, size_t bodyLen,
                                                uint8_t *alertOut, uint16_t *recordLimitOut);
bool _SSFTLSCParseCertificateVerifyForTest(const uint8_t *body, size_t bodyLen,
                                           uint16_t *schemeOut, uint16_t *sigLenOut);
bool _SSFTLSCParseCertificateRequestForTest(const uint8_t *body, size_t bodyLen,
                                            uint8_t *alertOut);
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_TLSC_H_INCLUDE */
