/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssftlsc configuration                                               */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_TLSC_OPT_H_INCLUDE
#define SSF_TLSC_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* 1 compiles in SSFTLSCSetUnauthenticated(), which lets a session with no trust anchors connect */
/* WITHOUT authenticating the server. 0 (production) compiles the mode out entirely: a call to  */
/* SSFTLSCSetUnauthenticated() fails to compile, and a session with no trust anchors can never  */
/* connect. Defaults to 1 only when the ssftlsc unit test is built. Override with -D.          */
#ifndef SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED
#if SSF_CONFIG_TLSC_UNIT_TEST == 1
#define SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED (1u)
#else
#define SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED (0u)
#endif
#endif

/* Largest record plaintext received, in bytes. RFC 8446 5.1 lets a peer send up to 2^14 (16384) */
/* unless a smaller limit is negotiated, so keep 16384 unless every server is known to send less. */
/* Largest record plaintext received, in bytes; advertised to the server as record_size_limit  */
/* (RFC 8449). Sizes the session's receive buffer (this + 17 bytes). 64..16384. It must hold: */
/* - the server's largest handshake message whole, however it splits it into records: usually */
/*   its Certificate, i.e. its certificate chain (a few hundred bytes for one EC certificate,  */
/*   2-5 KB with a public CA; test.mosquitto.org's Let's Encrypt chain is 4,106 bytes);        */
/* - its plaintext ServerHello / HelloRetryRequest (90-200 bytes; record_size_limit does not   */
/*   apply to them);                                                                           */
/* - every record it sends, unless it honors record_size_limit (GnuTLS does; OpenSSL s_server  */
/*   was seen sending larger records).                                                         */
/* Too small, the handshake fails with internal_error and a trace ("fragment too large",       */
/* "do not fit"). Keep the default unless the server and its certificate chain are known.     */
#ifndef SSF_TLSC_CONFIG_MAX_RECV_RECORD
#define SSF_TLSC_CONFIG_MAX_RECV_RECORD (16384u)
#endif

/* Largest record plaintext sent, in bytes. A sender may always use smaller records. Sizes the  */
/* session's send buffer. 768..16384: the ClientHello (up to 768 bytes) is one record.         */
#ifndef SSF_TLSC_CONFIG_MAX_SEND_RECORD
#define SSF_TLSC_CONFIG_MAX_SEND_RECORD (8192u)
#endif

#if (SSF_TLSC_CONFIG_MAX_RECV_RECORD < 64u) || (SSF_TLSC_CONFIG_MAX_RECV_RECORD > 16384u)
#error SSF_TLSC_CONFIG_MAX_RECV_RECORD must be 64..16384.
#endif
#if (SSF_TLSC_CONFIG_MAX_SEND_RECORD < 768u) || (SSF_TLSC_CONFIG_MAX_SEND_RECORD > 16384u)
#error SSF_TLSC_CONFIG_MAX_SEND_RECORD must be 768..16384.
#endif

/* Records the client sends under one application traffic key before it updates the key with a */
/* KeyUpdate (RFC 8446 4.6.3, 5.5). AES-GCM must not exceed 2^24.5 full-size records per key;   */
/* the default 2^24 stays below that for every suite (ChaCha20-Poly1305's limit is far higher, */
/* so updating early there costs one small record). 1..2^24.                                   */
#ifndef SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS
#define SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS (16777216ul)
#endif
#if (SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS < 1u) || (SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS > 16777216ul)
#error SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS must be 1..2^24.
#endif

/* Earliest Unix time (seconds) trusted for checking certificate validity. An RTC reading before */
/* this, such as a device that booted at 0 (1970), or a failed read, means no trusted time: the */
/* handshake fails with its own error instead of checking certificates against a wrong clock.  */
/* Default 2025-01-01T00:00:00Z.                                                                */
#ifndef SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC
#define SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC (1735689600ull)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_TLSC_OPT_H_INCLUDE */
