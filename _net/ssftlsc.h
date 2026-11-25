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
/* - Stack: pollOpen() needs about 14.4 KB below its caller's frame (Cortex-M4, gcc -Os, static */
/*   call graph, SSF_X509_CONFIG_MAX_CHAIN_DEPTH 6). The peak is chain verification: the 2.1 KB */
/*   SSFX509VerifyChainPurpose frame (two parsed certificates) over an RSA signature check.     */
/*   Largest enabled RSA size 3072: 11.9 KB; 2048: 10.4 KB (an ECDSA check is then the          */
/*   deepest). Not included: the inner transport's functions, the trace callback, libc and the  */
/*   port layer. Key exchange and the other steps need less. Each chain entry adds 2 bytes.     */
/*   With an RSA client key the client CertificateVerify signature sets the peak instead: about */
/*   28.3 KB at the default RSA-4096 cap (RSA-PSS signing); P-256 / P-384 / Ed25519 signing     */
/*   stays below 10.4 KB.                                                                       */
/* - Client mode, full handshake only (no PSK resumption or 0-RTT). One connection per session.  */
/* - After the handshake, recv() parses handshake records: NewSessionTicket is checked only for  */
/*   its minimum length and skipped, its contents unparsed (no resumption, so no ticket is used); */
/*   KeyUpdate (RFC 8446 4.6.3) moves receiving to the server's next key, and when the server   */
/*   asks, the client's own KeyUpdate goes out at the start of the next send(), before any data. */
/*   The client also updates its key every SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS records (default */
/*   2^24, under the AES-GCM limit of 5.5). Anything else is unexpected_message.               */
/* - Client certificate (mutual TLS) is optional: SSFTLSCSetClientCert() with a chain and its   */
/*   ssfpkey key. When a server sends a CertificateRequest, the client signs with the first    */
/*   scheme in the server's signature_algorithms its key can make (P-256 / P-384 ECDSA,        */
/*   Ed25519, RSA-PSS rsae SHA-256 / SHA-384) and sends Certificate, CertificateVerify and     */
/*   Finished; the Certificate is streamed from the caller's memory record by record, so any   */
/*   chain fits any record size. The signature is a fourth inline crypto step (SIGN_CV). With  */
/*   no certificate set, or no scheme the server accepts, the client answers with an empty    */
/*   Certificate (RFC 8446 4.4.2): a server that only asks carries on. One that requires a     */
/*   certificate sends certificate_required (or rejects the chain) after the client Finished, */
/*   so pollOpen() has already reported success; the first recv() fails, and for              */
/*   certificate_required the trace says the server requires a client certificate.            */
/* - Trust anchors are DER certificates in caller memory (SSFTLSCTrustStore_t). From PEM, a     */
/*   single certificate or a CA bundle, SSFTLSCTrustFromPEM() builds the store; it fails closed */
/*   on anything that is not a certificate.                                                     */
/* - The server's certificate must be X.509 v3 with a subjectAltName for the host name (or IP  */
/*   address) connected to; the Common Name is never used (RFC 9525). Public CAs always issue   */
/*   such certificates. A self-made broker certificate often lacks them (older `openssl x509   */
/*   -req` without an extension file gives v1): issue it with e.g.                             */
/*   -addext "subjectAltName=DNS:broker.example" (req) or an -extfile line (x509). The trace   */
/*   says which rule a refused certificate broke.                                               */
/* - ALPN (RFC 7301) is optional: SSFTLSCSetALPN() with the protocols to offer, SSFTLSCGetALPN() */
/*   for the server's choice after the handshake.                                              */
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

/* SSFTLSCTrustFromPEM() results. */
typedef enum
{
    SSF_TLSC_TRUST_OK,
    SSF_TLSC_TRUST_ERR_PEM,     /* A malformed PEM block (BEGIN / END lines, Base64)            */
    SSF_TLSC_TRUST_ERR_LABEL,   /* A block that is not a CERTIFICATE                            */
    SSF_TLSC_TRUST_ERR_CERT,    /* A CERTIFICATE that is not exactly one X.509 certificate      */
    SSF_TLSC_TRUST_ERR_COUNT,   /* More certificates than maxCount (255 when measuring)         */
    SSF_TLSC_TRUST_ERR_SIZE,    /* The certificates do not fit poolSize bytes                   */
    SSF_TLSC_TRUST_ERR_EMPTY,   /* No certificate in the input                                  */
} SSFTLSCTrustResult_t;

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
    SSF_TLSC_HS_RECV_FIN_SEND_FIN,   /* Without client authentication, also sends the Finished  */
    SSF_TLSC_HS_SEND_CLIENT_CERT,    /* Client authentication: the Certificate, record by record */
    SSF_TLSC_HS_SIGN_CV,             /* Crypto step: the client CertificateVerify signature      */
    SSF_TLSC_HS_SEND_CV_FIN,         /* Client authentication: CertificateVerify + Finished      */
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
    uint8_t hdr[SSF_TLS_RECORD_HEADER_SIZE]; /* The record header being received / judged     */
    size_t hdrPos;                   /* Header bytes received into hdr                          */
    uint16_t fragLen;
    size_t fragPos;
    uint8_t *fragDst;                /* Where the fragment is being received (in hsBuf)         */
    bool hdrComplete;
    uint8_t sendRecordBuf[SSF_TLS_RECORD_HEADER_SIZE + SSF_TLSC_CONFIG_MAX_SEND_RECORD + 1u +
                          SSF_TLS_AEAD_TAG_SIZE];
    size_t sendTotal;
    size_t sendPos;
    bool sendPending;
} SSFTLSCIOCtx_t;

#define SSF_TLSC_MAX_HOST_SIZE (256u)   /* Host name passed to open(), including the NUL       */
/* hsBuf's data room: a record's whole TLSInnerPlaintext (content, content type, padding).    */
/* hsBuf holds SSF_TLS_AEAD_TAG_SIZE bytes more: a protected record's tag lands there.        */
#define SSF_TLSC_HSBUF_SIZE (SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u)
#define SSF_TLSC_CH_SIZE (768u)         /* Handshake scratch: ClientHello, server key, flight */
/* The largest ClientHello1 without ALPN: a 255-byte host name in server_name. ALPN adds 6     */
/* bytes plus the list, so SSF_TLS_CONFIG_MAX_ALPN_LEN may be at most CH_SIZE - 6 - this. The   */
/* session's handshake scratch (hsScratch) is this size too.                                   */
#define SSF_TLSC_CH1_MAX_NO_ALPN (543u)
/* The ClientHello goes out as one plaintext record, so a record must hold the largest one     */
#if SSF_TLSC_CONFIG_MAX_SEND_RECORD < SSF_TLSC_CH_SIZE
#error SSF_TLSC_CONFIG_MAX_SEND_RECORD must be at least SSF_TLSC_CH_SIZE (768) to send the ClientHello.
#endif

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

    /* Client certificate (SSFTLSCSetClientCert): pointers into the caller's memory, kept       */
    /* across connections. clientChainCount 0 = none.                                           */
    const uint8_t *const *clientChainDer;
    const uint32_t *clientChainLens;
    const SSFPKey_t *clientKey;
    uint8_t clientChainCount;

    /* ALPN (SSFTLSCSetALPN): the caller's protocol names, kept across connections; alpnCount 0 */
    /* = not offered. alpnChosen is 1 + the index of the server's choice, 0 for none.          */
    const char *const *alpnProtos;
    uint8_t alpnCount;
    uint8_t alpnChosen;

    /* Ephemeral key */
    uint8_t ephemeralPrivKey[48];

    /* Handshake secret */
    uint8_t savedHandshakeSecret[SSF_TLS_MAX_HASH_SIZE];

    /* HelloRetryRequest bookkeeping for validating the second ServerHello (RFC 8446 4.1.4)     */
    SSFTLSCLeafKey_t leafKeyType;    /* Key type of the server's end-entity certificate         */
    bool hrrDone;
    uint16_t hrrGroup;               /* Group the HRR selected; the only share in ClientHello2  */
    uint16_t hrrSuite;               /* Cipher suite the HRR selected; ServerHello must match   */

    /* record_size_limit (RFC 8449) from EncryptedExtensions: the largest TLSInnerPlaintext the  */
    /* server accepts, 64..2^14+1; 0 when not negotiated.                                        */
    uint16_t peerRecordLimit;

    /* The server sent a CertificateRequest. clientScheme is the signature scheme chosen for the */
    /* client CertificateVerify, or 0: no certificate configured or none the server accepts, so */
    /* the client answers with an empty Certificate (RFC 8446 4.4.2) before its Finished.      */
    bool certRequested;
    uint16_t clientScheme;
    uint32_t certSendOff;            /* Bytes of the client flight message sent so far          */

    /* Post-handshake handshake messages (RFC 8446 4.6), parsed as they arrive, record by record: */
    /* the header so far, the message type and the body bytes still to come.                   */
    uint8_t phHdr[4];
    uint8_t phHdrLen;
    uint8_t phType;
    uint32_t phRemain;
    bool keyUpdateOwed;              /* Server asked for a KeyUpdate: sent before the next data */
    uint32_t sendRecordsOnKey;       /* Records sent under the current client application key  */

    /* Handshake scratch: one buffer, owned by one phase at a time (no two overlap), its length  */
    /* in hsScratchLen. The members name the phases; all are the whole buffer.                  */
    /*   clientHello   ClientHello1, then ClientHello2: SEND_CH until the ServerHello is        */
    /*                 processed (the SHA-384 transcript restart, ClientHello2 after an HRR)    */
    /*   leafPubKey    the server certificate's public key: its Certificate (RECV_EE_CERT)      */
    /*                 until the CertificateVerify check (VERIFY_SIG)                            */
    /*   clientFlight  the client CertificateVerify and Finished: SIGN_CV until SEND_CV_FIN     */
    /*                 has sent them; then wiped                                                 */
    union
    {
        uint8_t clientHello[SSF_TLSC_CH_SIZE];
        uint8_t leafPubKey[SSF_TLSC_CH_SIZE];
        uint8_t clientFlight[SSF_TLSC_CH_SIZE];
    } hsScratch;
    size_t hsScratchLen;

    /* The one receive buffer. Each record's fragment is read straight to its end and decrypted */
    /* there in place, so it also reassembles handshake messages (servers may bundle several   */
    /* in a record, or split one across records); after the handshake it holds the application */
    /* record being returned by recv(). SSF_TLSC_HSBUF_SIZE bytes of plaintext, plus the tag.   */
    uint8_t hsBuf[SSF_TLSC_HSBUF_SIZE + SSF_TLS_AEAD_TAG_SIZE];
    size_t hsBufLen;   /* total bytes in hsBuf */
    size_t hsBufPos;   /* current parse position */

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

/* Builds a trust store from PEM text: one certificate or a bundle of them (RFC 7468), with     */
/* text allowed between blocks if it holds no "-----BEGIN" / "-----END" marker. Each            */
/* certificate is decoded as DER into poolOpt (one after another; it must not overlap pem,      */
/* which asserts), ders[i] / lens[i] are set for each (both arrays hold maxCount entries), and  */
/* *storeOpt is { ders, lens, count }, ready for SSFTLSCInit(); pool and arrays must stay valid */
/* while the session uses it.                                                                    */
/* It fails closed: every block must be a CERTIFICATE that parses as exactly one X.509          */
/* certificate, so a stray key, a malformed block (a damaged BEGIN line included: its END     */
/* line is then a stray marker), one more certificate than maxCount, or a pool too small,     */
/* rejects the whole input. *poolUsedOut gets the pool bytes used and *countOut */
/* the certificates loaded. On an error the store is { NULL, NULL, 0 }, *poolUsedOut is 0 and   */
/* *countOut is the 0-based index of the certificate block at fault.                            */
/* Measuring: with poolOpt NULL (ders, lens and storeOpt are then ignored and may be NULL) the */
/* pool size and count needed are reported; this checks the PEM and labels but cannot parse    */
/* the certificates. Anchors are not checked for the CA flag or validity here; the chain       */
/* verifier does that on every handshake. On a host, read the file into a buffer first, e.g.   */
/* fread() of a CA bundle.                                                                       */
SSFTLSCTrustResult_t SSFTLSCTrustFromPEM(const char *pem, size_t pemLen, uint8_t *poolOpt,
                                         size_t poolSize, const uint8_t **ders, uint32_t *lens,
                                         uint8_t maxCount, SSFTLSCTrustStore_t *storeOpt,
                                         size_t *poolUsedOut, uint8_t *countOut);

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

/* Sets the client certificate presented when a server asks for one (mutual TLS): chainDer[0]  */
/* is the end-entity certificate, then any intermediates, each chainLens[i] bytes of DER; key  */
/* is its private key (ssfpkey). Nothing is copied: the arrays, certificates and key must stay */
/* valid while the session can connect. Returns false, leaving no certificate set, if the chain */
/* is malformed, the leaf does not parse, or its public key is not key's. Pass NULL, NULL, 0,   */
/* NULL to clear. Call while the session is not open.                                          */
/* key must come from SSFPKeyDecodeDER() / SSFPKeyDecodePEM(), which validate it and fill every */
/* field consistently. Only the type and public key are compared here; a hand-built SSFPKey_t   */
/* whose other fields disagree (e.g. a scalar length that is not the curve's) is a programming  */
/* error and asserts when the CertificateVerify is signed.                                      */
/* When a server asks for a certificate, the chain is sent only if every certificate in it is   */
/* signed with a scheme the server lists (signature_algorithms_cert, else signature_algorithms; */
/* RFC 8446 4.4.2.3), a self-signed last certificate excepted; otherwise an empty Certificate. */
/* A leaf the server is likely to refuse (expired, Key Usage without digitalSignature, EKU     */
/* without clientAuth) is traced as a warning and still sent: the server decides.              */
bool SSFTLSCSetClientCert(SSFTLSCSession_t *session, const uint8_t *const *chainDer,
                          const uint32_t *chainLens, uint8_t chainCount, const SSFPKey_t *key);

/* Sets the protocols offered with ALPN (RFC 7301), in preference order: e.g. "x-amzn-mqtt-ca"  */
/* for AWS IoT MQTT on port 443. Nothing is copied: the array and strings must stay valid and   */
/* unchanged while the session can connect. Each name is a NUL-terminated string of 1..255     */
/* bytes; the names, each plus one length byte, must total at most SSF_TLS_CONFIG_MAX_ALPN_LEN  */
/* (default 32, at most 219). Returns false, leaving none set, otherwise. Pass NULL, 0 to      */
/* clear. Call while the session is not open.                                                   */
/* The server's answer must be exactly one of the offered names (else illegal_parameter). A     */
/* server may also answer with none: the handshake still succeeds, and SSFTLSCGetALPN() says   */
/* so; whether to carry on is the caller's decision. A server that requires ALPN and supports  */
/* none of the names ends the handshake with no_application_protocol.                          */
bool SSFTLSCSetALPN(SSFTLSCSession_t *session, const char *const *protos, uint8_t count);

/* Returns the protocol the server chose (the caller's own string from SSFTLSCSetALPN()), or    */
/* NULL if it chose none or the handshake is not complete: the choice arrives before the server */
/* is authenticated, so it is reported only once pollOpen() has succeeded. Cleared when the    */
/* connection closes and when SSFTLSCSetALPN() is called.                                       */
const char *SSFTLSCGetALPN(const SSFTLSCSession_t *session);

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
                                              size_t total);
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
bool _SSFTLSCPostHandshakeFeedForTest(SSFTLSCSession_t *session, const uint8_t *rec, size_t len,
                                      uint8_t *alertOut, uint8_t *keyUpdateOut);
void _SSFTLSCNextTrafficSecretForTest(const SSFTLSCSession_t *session, uint8_t *secret);
bool _SSFTLSCRecordTypeAllowedForTest(const SSFTLSCSession_t *session, uint8_t contentType);
bool _SSFTLSCChooseClientSchemeChainForTest(SSFTLSCSession_t *session, const uint8_t *body,
                                            size_t bodyLen, bool nowValid, uint64_t nowUnixSec,
                                            uint16_t *schemeOut, uint8_t *alertOut);
size_t _SSFTLSCClientCertMsgLenForTest(const SSFTLSCSession_t *session);
void _SSFTLSCClientCertMsgCopyForTest(const SSFTLSCSession_t *session, size_t off, uint8_t *dst,
                                      size_t n);
bool _SSFTLSCSignClientCVForTest(SSFTLSCSession_t *session, uint16_t scheme,
                                 const uint8_t *transcriptHash, size_t hashLen, uint8_t *msgOut,
                                 size_t msgSize, size_t *msgLenOut);
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_TLSC_H_INCLUDE */
