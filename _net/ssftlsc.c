/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftlsc.c                                                                                     */
/* Provides TLS 1.3 client handshake and encrypted transport implementation (RFC 8446).          */
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
#include <stddef.h>
#include <stdio.h>
#include "ssfassert.h"
#include "ssftlsc.h"
#include "ssfstr.h"
#include "ssfhkdf.h"
#include "ssfx25519.h"
#include "ssfecdsa.h"
#include "ssfrsa.h"
#include "ssfed25519.h"
#include "ssfx509.h"
#include "ssfasn1.h"
#include "ssfsha2.h"
#include "ssfprng.h"
#include "ssfrtc.h"
#include "ssfcrypt.h"
#include "ssfnet.h"
#include "ssfpem.h"

/* Max SNI hostname length (RFC 1035 DNS FQDN is 255 characters) */
#define SSF_TLSC_MAX_HOSTNAME_LEN (255u)

/* Largest protected fragment a peer may send: 2^14 + 1 TLSInnerPlaintext plus the AEAD tag */
#define SSF_TLSC_RFC_MAX_CIPHERTEXT (16384u + 1u + SSF_TLS_AEAD_TAG_SIZE)

/* record_size_limit extension (RFC 8449 4): a TLSInnerPlaintext limit of 64..2^14+1 */
#define SSF_TLSC_EXT_RECORD_SIZE_LIMIT (28u)
#define SSF_TLSC_RSL_MIN (64u)
/* signature_algorithms_cert (RFC 8446 4.2.3): schemes for signatures in certificates */
#define SSF_TLSC_EXT_SIG_ALGS_CERT (50u)
/* A warning: reported, the handshake goes on */
#define _SSF_TLSC_CERT_WARN(T, ...) \
    _SSF_TLS_TRACE(T, SSF_TLS_TRACE_WARN, SSF_TLS_TRACE_CERT, __VA_ARGS__)
/* An empty Certificate message: type, uint24 length 4, empty request context, empty list */
#define SSF_TLSC_EMPTY_CERT_LEN (8u)
#define SSF_TLSC_RSL_MAX (16384u + 1u)

/* The certificate chain limit is SSF_X509_CONFIG_MAX_CHAIN_DEPTH */
#ifdef SSF_TLS_CONFIG_MAX_CHAIN_DEPTH
#error SSF_TLS_CONFIG_MAX_CHAIN_DEPTH is not supported; ssftlsc uses SSF_X509_CONFIG_MAX_CHAIN_DEPTH.
#endif

/* The handshake scratch must hold the largest ClientHello, server key and client flight */
#if SSF_RSA_MAX_PUB_KEY_DER_SIZE > SSF_TLSC_CH_SIZE
#error SSF_TLSC_CH_SIZE is too small for the largest supported server RSA key.
#endif
#if (8u + SSF_RSA_MAX_SIG_SIZE + 4u + SSF_TLS_MAX_HASH_SIZE) > SSF_TLSC_CH_SIZE
#error SSF_TLSC_CH_SIZE is too small for an RSA CertificateVerify and Finished (mutual TLS).
#endif
#if (SSF_TLSC_CH1_MAX_NO_ALPN + 6u + SSF_TLS_CONFIG_MAX_ALPN_LEN) > SSF_TLSC_CH_SIZE
#error SSF_TLS_CONFIG_MAX_ALPN_LEN must be at most 219 for the ClientHello to fit.
#endif

/* Advertise, accept and use only the curves and RSA paddings compiled into this build */
#define _SSF_TLSC_P256 (SSF_EC_CONFIG_ENABLE_P256 == 1)
#define _SSF_TLSC_P384 (SSF_EC_CONFIG_ENABLE_P384 == 1)
#define _SSF_TLSC_ECDSA_SIGN (SSF_ECDSA_CONFIG_ENABLE_SIGN == 1)
#define _SSF_TLSC_PSS ((SSF_RSA_ANY_ENABLED == 1) && (SSF_RSA_CONFIG_ENABLE_PSS == 1))
#define _SSF_TLSC_PKCS1 ((SSF_RSA_ANY_ENABLED == 1) && (SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1))

/* Secret scrubbing; unit-test builds report each wipe to _SSFTLSCScrubTestHook */
#if SSF_CONFIG_TLSC_UNIT_TEST == 1
void (*_SSFTLSCScrubTestHook)(void *ctx, const char *whatStr, const void *buf,
                             size_t bufLen) = NULL;
void *_SSFTLSCScrubTestHookCtx = NULL;
#define _SSF_TLSC_SCRUB_REPORT(what, buf, len) do { if (_SSFTLSCScrubTestHook != NULL) { \
    _SSFTLSCScrubTestHook(_SSFTLSCScrubTestHookCtx, (what), (buf), (len)); } } while (0)
#else
#define _SSF_TLSC_SCRUB_REPORT(what, buf, len) do { } while (0)
#endif
#define _SSF_TLSC_SCRUB_N(what, buf, len) do { SSFCryptSecureZero((buf), (len)); \
    _SSF_TLSC_SCRUB_REPORT((what), (buf), (len)); } while (0)
#define _SSF_TLSC_SCRUB(buf) _SSF_TLSC_SCRUB_N(#buf, (buf), sizeof(buf))

/* Records the fatal alert for the first failure; _SSFTLSCFail sends it (RFC 8446 6). */
#define _SSF_TLSC_ALERT(s, desc) do { if ((s)->pendingAlert == 0u) (s)->pendingAlert = (desc); \
    } while (0)

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
/* Test hook state for _SSFTLSCInjectClientHelloForTest() */
static const uint8_t *_utInjectCH;
static size_t _utInjectCHLen;
static const uint8_t *_utInjectX25519;
static const uint8_t *_utInjectCH2;
static size_t _utInjectCH2Len;
static const uint8_t *_utInjectEC;

/* Test hook: flips a bit of the received server Finished verify_data */
bool _ssfTLSCUTCorruptServerFinished;
#endif

/* --------------------------------------------------------------------------------------------- */
/* Internal: binary encoding helpers (big-endian)                                                */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFTLSCPut16(uint8_t *buf, uint16_t v)
{ buf[0] = (uint8_t)(v >> 8); buf[1] = (uint8_t)v; return 2; }
static size_t _SSFTLSCPut24(uint8_t *buf, uint32_t v)
{ buf[0] = (uint8_t)(v >> 16); buf[1] = (uint8_t)(v >> 8); buf[2] = (uint8_t)v; return 3; }

static uint16_t _SSFTLSCGet16(const uint8_t *buf)
{ return (uint16_t)((((uint16_t)buf[0]) << 8) | ((uint16_t)buf[1])); }
static uint32_t _SSFTLSCGet24(const uint8_t *buf)
{ return (((uint32_t)buf[0]) << 16) | (((uint32_t)buf[1]) << 8) | ((uint32_t)buf[2]); }

/* --------------------------------------------------------------------------------------------- */
/* Internal: platform entropy                                                                    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCGetEntropy(uint8_t *buf, size_t len)
{
    SSF_REQUIRE(buf != NULL);

    if (len > 0xffffu) return false;
    return SSFPortGetEntropy(buf, (uint16_t)len);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: one send() on the inner transport; SUCCESS only once all of len has moved           */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCInnerSendOnce(SSFTLSCSession_t *s, const uint8_t *data, size_t len,
                                              size_t *sentOut)
{
    size_t sent = 0;
    SSFNetIOResult_t r;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE((data != NULL) || (len == 0u));
    SSF_REQUIRE(sentOut != NULL);

    *sentOut = 0;
    if (len == 0) return SSF_TLS_IO_SUCCESS;
    r = s->inner->send(s->inner, data, len, &sent);
    /* Did the inner transport accept bytes? */
    if (r == SSF_NET_IO_SUCCESS)
    {
        /* Yes, report how many */
        *sentOut = sent;
        return (sent == len) ? SSF_TLS_IO_SUCCESS : SSF_TLS_IO_WANT_WRITE;
    }
    if ((r == SSF_NET_IO_WANT_WRITE) || (r == SSF_NET_IO_WANT_READ)) return SSF_TLS_IO_WANT_WRITE;
    if (r == SSF_NET_IO_CLOSED) s->peerClosed = true;
    s->ioFailed = true;
    return SSF_TLS_IO_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: one recv() on the inner transport; SUCCESS only once all of len has arrived         */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCInnerRecvOnce(SSFTLSCSession_t *s, uint8_t *data, size_t len,
                                              size_t *recvdOut)
{
    size_t got = 0;
    SSFNetIOResult_t r;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE((data != NULL) || (len == 0u));
    SSF_REQUIRE(recvdOut != NULL);

    *recvdOut = 0;
    if (len == 0) return SSF_TLS_IO_SUCCESS;
    r = s->inner->recv(s->inner, data, len, &got);
    /* Did the inner transport deliver bytes? */
    if (r == SSF_NET_IO_SUCCESS)
    {
        /* Yes, report how many */
        *recvdOut = got;
        return (got == len) ? SSF_TLS_IO_SUCCESS : SSF_TLS_IO_WANT_READ;
    }
    if ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)) return SSF_TLS_IO_WANT_READ;
    if (r == SSF_NET_IO_CLOSED) s->peerClosed = true;
    s->ioFailed = true;
    return SSF_TLS_IO_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: continues writing the pending record; WANT_WRITE while some of it remains           */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCSendPending(SSFTLSCSession_t *s)
{
    SSFTLSCIOCtx_t *io;

    SSF_REQUIRE(s != NULL);
    io = &s->ioCtx;

    while (io->sendPending && (io->sendPos < io->sendTotal))
    {
        size_t sent = 0;
        SSFTLSIOResult_t r = _SSFTLSCInnerSendOnce(s, &io->sendRecordBuf[io->sendPos],
                                                   io->sendTotal - io->sendPos, &sent);
        io->sendPos += sent;
        if (r == SSF_TLS_IO_ERROR) { io->sendPending = false; return SSF_TLS_IO_ERROR; }
        if (io->sendPos < io->sendTotal) return SSF_TLS_IO_WANT_WRITE;
    }
    io->sendPending = false;
    return SSF_TLS_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: installs traffic keys in a record state, de-initializing any keys it already holds. */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCRecordStateSet(SSFTLSCSession_t *s, SSFTLSRecordState_t *state, bool *inited,
                                   const uint8_t *key, const uint8_t *iv)
{
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(state != NULL);
    SSF_REQUIRE(inited != NULL);
    SSF_REQUIRE(key != NULL);
    SSF_REQUIRE(iv != NULL);

    if (*inited) SSFTLSRecordStateDeInit(state);
    SSFTLSRecordStateInit(state, s->cipherSuite, key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    *inited = true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: sends a plaintext record, resuming a partly written one                             */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCSendPlainRecordOnce(SSFTLSCSession_t *s, uint8_t ct,
                                                    const uint8_t *data, size_t len)
{
    SSFTLSCIOCtx_t *io;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE((data != NULL) || (len == 0u));
    io = &s->ioCtx;

    /* Is this the first call for this record? */
    if (!io->sendPending)
    {
        /* Yes, frame the header and data in the send buffer */
        if (((size_t)5u + len) > sizeof(io->sendRecordBuf)) return SSF_TLS_IO_ERROR;
        io->sendRecordBuf[0] = ct;
        io->sendRecordBuf[1] = 0x03u; io->sendRecordBuf[2] = 0x03u;
        io->sendRecordBuf[3] = (uint8_t)((len >> 8) & 0xFFu);
        io->sendRecordBuf[4] = (uint8_t)(len & 0xFFu);
        if (len > 0) memcpy(&io->sendRecordBuf[5], data, len);
        io->sendTotal = 5u + len;
        io->sendPos = 0;
        io->sendPending = true;
    }

    return _SSFTLSCSendPending(s);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: sends an encrypted record, resuming a partly written one                            */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCSendEncRecordOnce(SSFTLSCSession_t *s, uint8_t ct,
                                                  const uint8_t *data, size_t len)
{
    SSFTLSCIOCtx_t *io;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE((data != NULL) || (len == 0u));
    io = &s->ioCtx;

    /* Is this the first call for this record? */
    if (!io->sendPending)
    {
        /* Yes, encrypt it once into the send buffer */
        size_t recordLen;

        if (!SSFTLSRecordEncrypt(&s->sendState, ct, data, len,
                                 io->sendRecordBuf, sizeof(io->sendRecordBuf), &recordLen))
            return SSF_TLS_IO_ERROR;
        io->sendTotal = recordLen;
        io->sendPos = 0;
        io->sendPending = true;
    }

    return _SSFTLSCSendPending(s);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: receives one record to pt, decrypting a protected one in place; resumable           */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCRecvRecordOnce(SSFTLSCSession_t *s, uint8_t *pt, size_t ptSize,
                                               size_t *ptLen, uint8_t *contentType)
{
    SSFTLSCIOCtx_t *io;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(pt != NULL);
    SSF_REQUIRE(ptLen != NULL);
    SSF_REQUIRE(contentType != NULL);
    io = &s->ioCtx;

    /* Read the 5-byte header, resumable */
    while (!io->hdrComplete)
    {
        size_t recvd = 0;
        SSFTLSIOResult_t r = _SSFTLSCInnerRecvOnce(s, &io->hdr[io->hdrPos],
                                                   ((size_t)SSF_TLS_RECORD_HEADER_SIZE) -
                                                   io->hdrPos, &recvd);
        io->hdrPos += recvd;
        /* Did the header read fail? */
        if (r == SSF_TLS_IO_ERROR)
        {
            /* Yes, reset the receive state */
            SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: header read failed");
            io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0; io->fragLen = 0;
            return SSF_TLS_IO_ERROR;
        }
        /* Is the header complete? */
        if (io->hdrPos >= SSF_TLS_RECORD_HEADER_SIZE)
        {
            /* Yes, judge it before reading the fragment */
            io->hdrComplete = true;
            io->fragLen = _SSFTLSCGet16(&io->hdr[3]);
            io->fragPos = 0;
            SSF_TLS_TRACE_REC_DEBUG(&s->trace,
                                    "RecvRecord: ct=%u ver=0x%04x fragLen=%u",
                                    io->hdr[0], _SSFTLSCGet16(&io->hdr[1]), io->fragLen);
            /* Is the content type unknown (RFC 8446 5)? */
            if ((io->hdr[0] < SSF_TLS_CT_CHANGE_CIPHER) ||
                (io->hdr[0] > SSF_TLS_CT_APPLICATION))
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: unknown record type %u",
                                        io->hdr[0]);
                io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0; io->fragLen = 0;
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR;
            }
            /* Is the content type wrong for this point of the connection (RFC 8446 5, 5.2)? */
            if ((io->hdr[0] == SSF_TLS_CT_CHANGE_CIPHER) ?
                (s->connected || (io->fragLen != 1u)) :
                (s->recvEncrypted != (io->hdr[0] == SSF_TLS_CT_APPLICATION)))
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: record type %u unexpected here",
                                        io->hdr[0]);
                io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0; io->fragLen = 0;
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR;
            }
            /* Is the fragment larger than this build's receive record? */
            if (io->fragLen > (SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u + SSF_TLS_AEAD_TAG_SIZE))
            {
                /* Yes, record_overflow if over the RFC or advertised limit, else internal_error */
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: fragment too large (%u)",
                                        io->fragLen);
                _SSF_TLSC_ALERT(s, ((io->fragLen > SSF_TLSC_RFC_MAX_CIPHERTEXT) ||
                                    ((io->hdr[0] != SSF_TLS_CT_APPLICATION) ?
                                     (io->fragLen > 16384u) : (s->peerRecordLimit != 0u))) ?
                                   SSF_TLS_ALERT_RECORD_OVERFLOW : SSF_TLS_ALERT_INTERNAL_ERROR);
                io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0; io->fragLen = 0;
                return SSF_TLS_IO_ERROR;
            }
            /* Does the fragment fit the room offered at pt? */
            {
                uint8_t alert = 0;

                /* Is the record protected? */
                if (s->recvEncrypted)
                {
                    /* Yes, its plaintext must fit; the tag goes in the room behind */
                    if (((size_t)io->fragLen > SSF_TLS_AEAD_TAG_SIZE) &&
                        (((size_t)io->fragLen - SSF_TLS_AEAD_TAG_SIZE) > ptSize))
                    { alert = SSF_TLS_ALERT_INTERNAL_ERROR; }
                }
                else if (io->fragLen > 16384u)
                {
                    /* No, and a plaintext record over 2^14 is the peer's error */
                    SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: plaintext record of %u "
                                            "bytes", io->fragLen);
                    alert = SSF_TLS_ALERT_RECORD_OVERFLOW;
                }
                else if ((size_t)io->fragLen > ptSize) { alert = SSF_TLS_ALERT_INTERNAL_ERROR; }
                else { /* Fits */ }
                /* Is the record over this build's limit? */
                if (alert == SSF_TLS_ALERT_INTERNAL_ERROR)
                {
                    SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: %u bytes do not fit (%zu "
                                            "free)", io->fragLen, ptSize);
                }
                if (alert != 0u)
                {
                    io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0; io->fragLen = 0;
                    _SSF_TLSC_ALERT(s, alert); return SSF_TLS_IO_ERROR;
                }
            }
            io->fragDst = pt;
            break;
        }
        /* No, resume the partial header next call */
        return SSF_TLS_IO_WANT_READ;
    }

    /* Read the fragment straight to pt, resumable; pt must not move mid-fragment */
    SSF_ASSERT(pt == io->fragDst);
    while (io->fragPos < io->fragLen)
    {
        size_t recvd = 0;
        SSFTLSIOResult_t r = _SSFTLSCInnerRecvOnce(s, &pt[io->fragPos], io->fragLen - io->fragPos,
                                                   &recvd);
        io->fragPos += recvd;
        /* Did the fragment read fail? */
        if (r == SSF_TLS_IO_ERROR)
        {
            SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: fragment read failed");
            io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0; io->fragLen = 0;
            return SSF_TLS_IO_ERROR;
        }
        if (io->fragPos >= io->fragLen) break;
        return SSF_TLS_IO_WANT_READ;
    }

    /* Record complete; the header stays in ioCtx.hdr as the AEAD additional data */
    {
        uint8_t hdr_ct = io->hdr[0];
        uint16_t fragLen = io->fragLen;

        io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0;

        /* Is it a plaintext change_cipher_spec (RFC 8446 5)? */
        if (hdr_ct == SSF_TLS_CT_CHANGE_CIPHER)
        {
            /* Yes, only the single byte 0x01 is allowed; the caller drops it */
            if (pt[0] != 0x01u)
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: unexpected change_cipher_spec");
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR;
            }
            *contentType = SSF_TLS_CT_CHANGE_CIPHER;
            *ptLen = 0;
            return SSF_TLS_IO_SUCCESS;
        }

        /* Is the record protected? */
        if (s->recvEncrypted)
        {
            /* Yes, decrypt it in place */
            bool ok;
            ok = SSFTLSRecordDecrypt(&s->recvState, io->hdr, pt, (size_t)fragLen, pt, ptSize,
                                     ptLen, contentType);
            /* Did decryption fail? */
            if (!ok)
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecordDecrypt failed (fragLen=%u seq=%llu)",
                                        fragLen, (unsigned long long)s->recvState.seqNum);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_BAD_RECORD_MAC); return SSF_TLS_IO_ERROR;
            }
            /* Is the inner type change_cipher_spec or unknown (RFC 8446 5)? */
            if ((*contentType != SSF_TLS_CT_HANDSHAKE) && (*contentType != SSF_TLS_CT_ALERT) &&
                (*contentType != SSF_TLS_CT_APPLICATION))
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: unexpected inner type %u",
                                        *contentType);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR;
            }
        }
        else
        {
            /* No, the plaintext is already at pt */
            *contentType = hdr_ct;
            *ptLen = fragLen;
        }

        /* Is it an empty handshake record (RFC 8446 5.1)? */
        if ((*contentType == SSF_TLS_CT_HANDSHAKE) && (*ptLen == 0u))
        {
            SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: empty handshake record");
            _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_DECODE_ERROR); return SSF_TLS_IO_ERROR;
        }
        /* Is it an alert, which must hold exactly one two-byte alert (RFC 8446 6)? */
        if (*contentType == SSF_TLS_CT_ALERT)
        {
            /* Yes, record which alert ended the connection */
            if (*ptLen != 2u)
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: alert length %zu", *ptLen);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_DECODE_ERROR); return SSF_TLS_IO_ERROR;
            }
            SSF_TLS_TRACE_ALERT(&s->trace, "RecvRecord: ALERT level=%u desc=%u", pt[0], pt[1]);
            /* Did the server require a client certificate? */
            if (pt[1] == SSF_TLS_ALERT_CERTIFICATE_REQUIRED)
            {
                /* Yes, say so */
                SSF_TLS_TRACE_HS_ERROR(&s->trace, "Server requires a client certificate "
                                       "(certificate_required); none is configured");
            }
            /* Did the server require an ALPN protocol not offered? */
            if (pt[1] == SSF_TLS_ALERT_NO_APPLICATION_PROTOCOL)
            {
                /* Yes, say so */
                SSF_TLS_TRACE_HS_ERROR(&s->trace, "Server requires an ALPN protocol the client "
                                       "did not offer (no_application_protocol)");
            }
            /* Is it close_notify (RFC 8446 6.1, 6.2)? */
            if (pt[1] == SSF_TLS_ALERT_CLOSE_NOTIFY)
            {
                /* Yes, it is answered with close_notify */
                s->peerCloseNotify = true;
                s->peerClosed = true;
            }
            else
            {
                /* No, any other alert ends the connection without a reply */
                s->peerAlerted = true;
            }
        }
        return SSF_TLS_IO_SUCCESS;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: receives one handshake message, reassembled in place in hsBuf; resumable            */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCRecvHandshakeOnce(SSFTLSCSession_t *s, const uint8_t **msgOut,
                                                  size_t *bodyLen, uint8_t *hsType,
                                                  bool addToTranscript)
{
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(msgOut != NULL);
    SSF_REQUIRE(bodyLen != NULL);
    SSF_REQUIRE(hsType != NULL);

    for (;;)
    {
        size_t avail = s->hsBufLen - s->hsBufPos;
        uint8_t ct = 0;
        size_t ptLen = 0;
        SSFTLSIOResult_t r;

        /* Is a message header buffered? */
        if (avail >= 4u)
        {
            /* Yes, a protected record's inner content type leaves one byte less for a message */
            size_t msgLen = (size_t)_SSFTLSCGet24(&s->hsBuf[s->hsBufPos + 1u]);
            size_t msgMax = SSF_TLSC_HSBUF_SIZE - (s->recvEncrypted ? 1u : 0u);

            /* Is the message larger than this build's buffer? */
            if ((4u + msgLen) > msgMax)
            {
                SSF_TLS_TRACE_HS_ERROR(&s->trace, "Handshake message of %lu bytes exceeds the "
                                       "%lu-byte buffer", (unsigned long)(4u + msgLen),
                                       (unsigned long)msgMax);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_INTERNAL_ERROR);
                return SSF_TLS_IO_ERROR;
            }
            /* Is the whole message buffered? */
            if (avail >= (4u + msgLen))
            {
                /* Yes, return it in place */
                *hsType = s->hsBuf[s->hsBufPos];
                *msgOut = &s->hsBuf[s->hsBufPos];
                *bodyLen = msgLen;
                if (addToTranscript) SSFTLSTranscriptUpdate(&s->transcript, *msgOut, 4u + msgLen);
                s->hsBufPos += 4u + msgLen;
                return SSF_TLS_IO_SUCCESS;
            }
        }

        /* No, move the unread bytes to the front, then append the next record's plaintext */
        if (s->hsBufPos > 0u)
        {
            if (avail > 0u) memmove(s->hsBuf, &s->hsBuf[s->hsBufPos], avail);
            s->hsBufPos = 0;
            s->hsBufLen = avail;
        }
        r = _SSFTLSCRecvRecordOnce(s, &s->hsBuf[s->hsBufLen], SSF_TLSC_HSBUF_SIZE - s->hsBufLen,
                                   &ptLen, &ct);
        if (r != SSF_TLS_IO_SUCCESS) return r;

        /* Is it a compatibility CCS, never allowed inside a fragmented message (RFC 8446 5.1)? */
        if (ct == SSF_TLS_CT_CHANGE_CIPHER)
        {
            if (avail == 0u) continue;
            SSF_TLS_TRACE_HS_ERROR(&s->trace, "Record interleaved in a fragmented handshake "
                                   "message");
            _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG);
            return SSF_TLS_IO_ERROR;
        }
        /* Is it other than a handshake record? */
        if (ct != SSF_TLS_CT_HANDSHAKE)
        {
            /* Yes, an alert ends the handshake; anything else is unexpected */
            if (ct != SSF_TLS_CT_ALERT) _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG);
            return SSF_TLS_IO_ERROR;
        }
        s->hsBufLen += ptLen;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: true if the last message ended its record, as one ending a key epoch must          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCHandshakeAtRecordEnd(SSFTLSCSession_t *s, const char *whatStr)
{
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(whatStr != NULL);

    if (s->hsBufPos == s->hsBufLen) return true;
    SSF_TLS_TRACE_HS_ERROR(&s->trace, "%s does not end its record (spans a key change)", whatStr);
    _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns true if hostStr is a literal IP address (no SNI may name it).               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCIsIPLiteral(const char *hostStr)
{
    size_t len = 0;
    size_t i;
    uint32_t parts = 0;
    uint32_t digits = 0;
    uint32_t value = 0;
    bool hasColon = false;
    SSF_REQUIRE(hostStr != NULL);

    if (!SSFStrLen(hostStr, SSF_TLSC_MAX_HOST_SIZE, &len) || (len == 0u)) return false;

    /* IPv6: hex digits, ':' and '.' (embedded IPv4) with at least one ':', then "%zone" */
    for (i = 0; (i < len) && (hostStr[i] != '%'); i++)
    {
        char c = hostStr[i];

        if (c == ':') { hasColon = true; continue; }
        if (!(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) ||
              ((c >= 'A') && (c <= 'F')) || (c == '.')))
        { hasColon = false; break; }
    }
    if (hasColon) return true;

    /* IPv4: exactly four dot-separated decimal parts of 1-3 digits, each at most 255 */
    for (i = 0; i <= len; i++)
    {
        char c = (i < len) ? hostStr[i] : '.';

        /* Is it a digit? */
        if ((c >= '0') && (c <= '9'))
        {
            /* Yes, accumulate the part's value */
            if (++digits > 3u) return false;
            value = (value * 10u) + (uint32_t)(c - '0');
        }
        else if ((c == '.') && (digits > 0u) && (value <= 255u))
        {
            /* No, a dot ends a valid part */
            parts++;
            digits = 0;
            value = 0;
        }
        else
        {
            /* No, anything else is not an IPv4 literal */
            return false;
        }
    }
    return (parts == 4u);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns true if a CertificateVerify scheme can be made with the leaf's key type.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCSchemeMatchesKey(uint16_t scheme, SSFTLSCLeafKey_t key)
{
    /* The ECDSA schemes also fix the curve; a scheme compiled out matches no key */
    switch (scheme)
    {
#if _SSF_TLSC_P256
    case SSF_TLS_SIG_ECDSA_SECP256R1_SHA256: return (key == SSF_TLSC_LEAF_KEY_P256);
#endif
#if _SSF_TLSC_P384
    case SSF_TLS_SIG_ECDSA_SECP384R1_SHA384: return (key == SSF_TLSC_LEAF_KEY_P384);
#endif
#if _SSF_TLSC_PSS
    case SSF_TLS_SIG_RSA_PSS_RSAE_SHA256:
    case SSF_TLS_SIG_RSA_PSS_RSAE_SHA384:    return (key == SSF_TLSC_LEAF_KEY_RSA);
#endif
    case SSF_TLS_SIG_ED25519:                return (key == SSF_TLSC_LEAF_KEY_ED25519);
    default:                                 return false;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns true if the client can sign a CertificateVerify with scheme and key type.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCSchemeCanSign(uint16_t scheme, SSFTLSCLeafKey_t key)
{
    /* Is it an ECDSA scheme in a build without ECDSA signing? */
    if (((scheme == SSF_TLS_SIG_ECDSA_SECP256R1_SHA256) ||
         (scheme == SSF_TLS_SIG_ECDSA_SECP384R1_SHA384)) && (!_SSF_TLSC_ECDSA_SIGN))
    {
        /* Yes, the client can verify it but not produce it */
        return false;
    }
    /* No */
    return _SSFTLSCSchemeMatchesKey(scheme, key);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns the key type of a parsed certificate (its subject public key).              */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSCLeafKey_t _SSFTLSCLeafKeyType(const SSFX509Cert_t *cert)
{
    SSF_REQUIRE(cert != NULL);

    if (SSFX509IsKeyRSA(cert)) return SSF_TLSC_LEAF_KEY_RSA;
    if (SSFX509IsKeyP256(cert)) return SSF_TLSC_LEAF_KEY_P256;
    if (SSFX509IsKeyP384(cert)) return SSF_TLSC_LEAF_KEY_P384;
    if (SSFX509IsKeyEd25519(cert)) return SSF_TLSC_LEAF_KEY_ED25519;
    return SSF_TLSC_LEAF_KEY_UNKNOWN;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: maps a private key type to the leaf key type its certificate carries.               */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSCLeafKey_t _SSFTLSCPKeyLeafType(SSFPKeyType_t type)
{
    switch (type)
    {
    case SSF_PKEY_TYPE_RSA:     return SSF_TLSC_LEAF_KEY_RSA;
    case SSF_PKEY_TYPE_P256:    return SSF_TLSC_LEAF_KEY_P256;
    case SSF_PKEY_TYPE_P384:    return SSF_TLSC_LEAF_KEY_P384;
    case SSF_PKEY_TYPE_ED25519: return SSF_TLSC_LEAF_KEY_ED25519;
    default:                    return SSF_TLSC_LEAF_KEY_UNKNOWN;
    }
}

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
bool _SSFTLSCIsIPLiteralForTest(const char *hostStr) { return _SSFTLSCIsIPLiteral(hostStr); }
static bool _SSFTLSCSaveLeafKey(SSFTLSCSession_t *session, const uint8_t *der, uint32_t derLen);
static uint8_t _SSFTLSCChainAlert(SSFX509VerifyCode_t code);

uint8_t _SSFTLSCChainAlertForTest(SSFX509VerifyCode_t code) { return _SSFTLSCChainAlert(code); }
bool _SSFTLSCSaveLeafKeyForTest(SSFTLSCSession_t *session, const uint8_t *der, uint32_t derLen)
{
    return _SSFTLSCSaveLeafKey(session, der, derLen);
}

bool _SSFTLSCSchemeMatchesKeyForTest(uint16_t scheme, SSFTLSCLeafKey_t key)
{
    return _SSFTLSCSchemeMatchesKey(scheme, key);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Internal: bounded writer for building handshake messages; any write past cap clears ok.       */
/* --------------------------------------------------------------------------------------------- */
typedef struct
{
    uint8_t *buf;
    size_t cap;
    size_t pos;
    bool ok;
} SSFTLSCWriter_t;

/* --------------------------------------------------------------------------------------------- */
/* Internal: appends bytes to a bounded writer                                                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCWBytes(SSFTLSCWriter_t *w, const void *data, size_t len)
{
    if ((w->ok == false) || (len > (w->cap - w->pos))) { w->ok = false; return; }
    if (len > 0u) memcpy(&w->buf[w->pos], data, len);
    w->pos += len;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: appends a byte to a bounded writer                                                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCW8(SSFTLSCWriter_t *w, uint8_t v) { _SSFTLSCWBytes(w, &v, 1); }

/* --------------------------------------------------------------------------------------------- */
/* Internal: appends a big-endian uint16 to a bounded writer                                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCW16(SSFTLSCWriter_t *w, uint16_t v)
{
    uint8_t b[2];

    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
    _SSFTLSCWBytes(w, b, sizeof(b));
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns the length of ALPN name, 1..255, or 0 if NULL, empty or longer (RFC 7301)   */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFTLSCAlpnLen(const char *name)
{
    size_t len;

    if ((name == NULL) || !SSFStrLen(name, 256u, &len)) return 0;
    return len;
}

/* One key share for _SSFTLSCBuildClientHello() */
typedef struct
{
    uint16_t group;
    const uint8_t *pub;
    uint16_t len;
} SSFTLSCKeyShare_t;

/* --------------------------------------------------------------------------------------------- */
/* Internal: builds ClientHello1 or ClientHello2 into s->hsScratch.clientHello                   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCBuildClientHello(SSFTLSCSession_t *s, const uint8_t random[32],
                                     const uint8_t *sid, uint8_t sidLen,
                                     const SSFTLSCKeyShare_t *shares, uint8_t shareCount,
                                     const uint8_t *cookieExtOpt, uint16_t cookieExtLen)
{
    SSFTLSCWriter_t w;
    size_t extLenPos;
    size_t ksLen = 0;
    size_t hostLen = 0;
    uint8_t i;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(random != NULL);
    SSF_REQUIRE((sid != NULL) || (sidLen == 0u));
    SSF_REQUIRE(sidLen <= 32u);
    SSF_REQUIRE((shares != NULL) || (shareCount == 0u));
    SSF_REQUIRE((cookieExtOpt != NULL) || (cookieExtLen == 0u));
    for (i = 0; i < shareCount; i++) ksLen += 4u + shares[i].len;
    (void)SSFStrLen(s->host, sizeof(s->host), &hostLen);     /* Validated by open() */

    w.buf = s->hsScratch.clientHello;
    w.cap = sizeof(s->hsScratch.clientHello);
    w.pos = 0;
    w.ok = true;

    _SSFTLSCW8(&w, SSF_TLS_HS_CLIENT_HELLO);
    _SSFTLSCW8(&w, 0); _SSFTLSCW16(&w, 0);                          /* Length, patched below */
    _SSFTLSCW16(&w, SSF_TLS_VERSION_12);                            /* legacy_version */
    _SSFTLSCWBytes(&w, random, 32);
    _SSFTLSCW8(&w, sidLen);
    _SSFTLSCWBytes(&w, sid, sidLen);
    /* cipher_suites in preference order (see _net/README.md) */
    _SSFTLSCW16(&w, 8);
    _SSFTLSCW16(&w, SSF_TLS_CS_CHACHA20_POLY1305_SHA256);
    _SSFTLSCW16(&w, SSF_TLS_CS_AES_128_GCM_SHA256);
    _SSFTLSCW16(&w, SSF_TLS_CS_AES_256_GCM_SHA384);
    _SSFTLSCW16(&w, SSF_TLS_CS_AES_128_CCM_SHA256);
    _SSFTLSCW8(&w, 1); _SSFTLSCW8(&w, 0);                           /* legacy_compression_methods */
    extLenPos = w.pos;
    _SSFTLSCW16(&w, 0);                                             /* Extensions length, patched */

    _SSFTLSCW16(&w, SSF_TLS_EXT_SUPPORTED_VERSIONS);                /* TLS 1.3 only */
    _SSFTLSCW16(&w, 3); _SSFTLSCW8(&w, 2); _SSFTLSCW16(&w, SSF_TLS_VERSION_13);

    /* Only groups and schemes this build can compute are offered (counts fixed at build time) */
#define _SSF_TLSC_NGROUPS (1u + (_SSF_TLSC_P256 ? 1u : 0u) + (_SSF_TLSC_P384 ? 1u : 0u))
#define _SSF_TLSC_NSIGALGS ((_SSF_TLSC_P256 ? 1u : 0u) + (_SSF_TLSC_P384 ? 1u : 0u) + \
                            (_SSF_TLSC_PSS ? 2u : 0u) + (_SSF_TLSC_PKCS1 ? 2u : 0u) + 1u)
    _SSFTLSCW16(&w, SSF_TLS_EXT_SUPPORTED_GROUPS);
    _SSFTLSCW16(&w, (uint16_t)(2u + (2u * _SSF_TLSC_NGROUPS)));
    _SSFTLSCW16(&w, (uint16_t)(2u * _SSF_TLSC_NGROUPS));
    _SSFTLSCW16(&w, SSF_TLS_GROUP_X25519);
#if _SSF_TLSC_P256
    _SSFTLSCW16(&w, SSF_TLS_GROUP_SECP256R1);
#endif
#if _SSF_TLSC_P384
    _SSFTLSCW16(&w, SSF_TLS_GROUP_SECP384R1);
#endif

    _SSFTLSCW16(&w, SSF_TLS_EXT_SIGNATURE_ALGS);
    _SSFTLSCW16(&w, (uint16_t)(2u + (2u * _SSF_TLSC_NSIGALGS)));
    _SSFTLSCW16(&w, (uint16_t)(2u * _SSF_TLSC_NSIGALGS));
#if _SSF_TLSC_P256
    _SSFTLSCW16(&w, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256);
#endif
#if _SSF_TLSC_P384
    _SSFTLSCW16(&w, SSF_TLS_SIG_ECDSA_SECP384R1_SHA384);
#endif
#if _SSF_TLSC_PSS
    _SSFTLSCW16(&w, SSF_TLS_SIG_RSA_PSS_RSAE_SHA256);
    _SSFTLSCW16(&w, SSF_TLS_SIG_RSA_PSS_RSAE_SHA384);
#endif
#if _SSF_TLSC_PKCS1
    /* rsa_pkcs1_*: certificate signatures only, never accepted in CertificateVerify */
    _SSFTLSCW16(&w, SSF_TLS_SIG_RSA_PKCS1_SHA256);
    _SSFTLSCW16(&w, SSF_TLS_SIG_RSA_PKCS1_SHA384);
#endif
    _SSFTLSCW16(&w, SSF_TLS_SIG_ED25519);
#undef _SSF_TLSC_NGROUPS
#undef _SSF_TLSC_NSIGALGS

    _SSFTLSCW16(&w, SSF_TLS_EXT_KEY_SHARE);
    _SSFTLSCW16(&w, (uint16_t)(2u + ksLen)); _SSFTLSCW16(&w, (uint16_t)ksLen);
    for (i = 0; i < shareCount; i++)
    {
        _SSFTLSCW16(&w, shares[i].group);
        _SSFTLSCW16(&w, shares[i].len);
        _SSFTLSCWBytes(&w, shares[i].pub, shares[i].len);
    }

    /* psk_dhe_ke, for servers that insist on it */
    _SSFTLSCW16(&w, SSF_TLS_EXT_PSK_KEY_EXCHANGE);
    _SSFTLSCW16(&w, 2); _SSFTLSCW8(&w, 1); _SSFTLSCW8(&w, 1);

    /* record_size_limit (RFC 8449 4): the receive buffer's TLSInnerPlaintext size, always sent */
    _SSFTLSCW16(&w, SSF_TLSC_EXT_RECORD_SIZE_LIMIT);
    _SSFTLSCW16(&w, 2); _SSFTLSCW16(&w, (uint16_t)(SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u));

    /* Is there a HelloRetryRequest cookie to echo unchanged (RFC 8446 4.2.2)? */
    if (cookieExtOpt != NULL)
    {
        _SSFTLSCW16(&w, 44u);
        _SSFTLSCW16(&w, cookieExtLen);
        _SSFTLSCWBytes(&w, cookieExtOpt, cookieExtLen);
    }

    /* Is the host a name, as server_name may not carry an IP literal (RFC 6066 3)? */
    if ((hostLen > 0u) && !_SSFTLSCIsIPLiteral(s->host))
    {
        _SSFTLSCW16(&w, SSF_TLS_EXT_SERVER_NAME);
        _SSFTLSCW16(&w, (uint16_t)(5u + hostLen)); _SSFTLSCW16(&w, (uint16_t)(3u + hostLen));
        _SSFTLSCW8(&w, 0);
        _SSFTLSCW16(&w, (uint16_t)hostLen);
        _SSFTLSCWBytes(&w, s->host, hostLen);
    }

    /* Is ALPN set (RFC 7301 3.1), its list already bounded by SSFTLSCSetALPN()? */
    if (s->alpnCount != 0u)
    {
        size_t listLen = 0;

        for (i = 0; i < s->alpnCount; i++) listLen += 1u + _SSFTLSCAlpnLen(s->alpnProtos[i]);
        _SSFTLSCW16(&w, SSF_TLS_EXT_ALPN);
        _SSFTLSCW16(&w, (uint16_t)(2u + listLen)); _SSFTLSCW16(&w, (uint16_t)listLen);
        for (i = 0; i < s->alpnCount; i++)
        {
            size_t n = _SSFTLSCAlpnLen(s->alpnProtos[i]);

            _SSFTLSCW8(&w, (uint8_t)n);
            _SSFTLSCWBytes(&w, s->alpnProtos[i], n);
        }
    }

    if ((w.ok == false) || (((w.pos - extLenPos) - 2u) > 0xffffu)) return false;
    _SSFTLSCPut16(&w.buf[extLenPos], (uint16_t)((w.pos - extLenPos) - 2u));
    _SSFTLSCPut24(&w.buf[1], (uint32_t)(w.pos - 4u));
    s->hsScratchLen = w.pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns the exact key_exchange length for a group's key share, else 0.              */
/* --------------------------------------------------------------------------------------------- */
static uint16_t _SSFTLSCKeyShareLen(uint16_t group)
{
    if (group == SSF_TLS_GROUP_X25519) return 32u;
    if (group == SSF_TLS_GROUP_SECP256R1) return 65u;    /* Uncompressed SEC 1 point */
    if (group == SSF_TLS_GROUP_SECP384R1) return 97u;
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns true if the latest ClientHello carried a key share for group.               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCKeyShareOffered(const SSFTLSCSession_t *s, uint16_t group)
{
    SSF_REQUIRE(s != NULL);

    if (s->hrrDone) return (group == s->hrrGroup);
    if (group == SSF_TLS_GROUP_X25519) return true;
#if _SSF_TLSC_P384
    if (group == SSF_TLS_GROUP_SECP384R1) return true;
#endif
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns true if group is in the ClientHello supported_groups list.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCGroupSupported(uint16_t group)
{
    if (group == SSF_TLS_GROUP_X25519) return true;
#if _SSF_TLSC_P256
    if (group == SSF_TLS_GROUP_SECP256R1) return true;
#endif
#if _SSF_TLSC_P384
    if (group == SSF_TLS_GROUP_SECP384R1) return true;
#endif
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: false only if a ServerHello body's framing shows it did not negotiate TLS 1.3       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCShHasVersions(const uint8_t *body, size_t bodyLen)
{
    size_t pos = 2u + 32u;
    size_t extEnd;

    SSF_REQUIRE(body != NULL);
    SSF_REQUIRE(bodyLen >= 35u);

    pos += ((1u + ((size_t)body[pos])) + 2u) + 1u;    /* session id, cipher suite, compression */
    if (pos == bodyLen) return false;                 /* No extension block */
    if ((pos + 2u) > bodyLen) return true;
    extEnd = (pos + 2u) + ((size_t)_SSFTLSCGet16(&body[pos]));
    if (extEnd != bodyLen) return true;
    for (pos += 2u; pos < extEnd; pos += (4u + ((size_t)_SSFTLSCGet16(&body[pos + 2u]))))
    {
        if ((extEnd - pos) < 4u) return true;
        if (_SSFTLSCGet16(&body[pos]) == SSF_TLS_EXT_SUPPORTED_VERSIONS) return true;
    }
    return (pos != extEnd);                           /* Overrun: malformed */
}

#define _SSF_TLSC_SH_REJECT(s, what, alert) do { \
    SSF_TLS_TRACE_HS_ERROR(&(s)->trace, "ServerHello rejected: %s%s", (what), \
                           isHrr ? " (HelloRetryRequest)" : ""); \
    _SSF_TLSC_ALERT((s), (alert)); \
    return false; } while (0)

/* --------------------------------------------------------------------------------------------- */
/* Internal: validates and parses a ServerHello or HelloRetryRequest body (RFC 8446 4.1.3-4.2)   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCParseServerHello(SSFTLSCSession_t *s, const uint8_t *body, size_t bodyLen,
                                     bool isHrr, uint8_t *serverPubKey, size_t *serverPubKeyLen,
                                     uint16_t *serverGroup, const uint8_t **cookieOut,
                                     uint16_t *cookieLenOut)
{
    size_t pos = 0;
    size_t extEnd;
    uint16_t cs;
    uint8_t sidLen;
    const uint8_t *chSid;
    uint8_t chSidLen;
    bool hasVersions = false;
    bool hasKeyShare = false;
    bool hasCookie = false;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(body != NULL);
    SSF_REQUIRE(serverGroup != NULL);

    if (serverPubKeyLen != NULL) *serverPubKeyLen = 0;
    if (cookieOut != NULL) *cookieOut = NULL;
    if (cookieLenOut != NULL) *cookieLenOut = 0;
    *serverGroup = 0;

    /* legacy_version (ignored when supported_versions is present, 4.2.1) + random */
    if (bodyLen < (2u + 32u + 1u))
    { _SSF_TLSC_SH_REJECT(s, "too short", SSF_TLS_ALERT_DECODE_ERROR); }
    pos = 2u + 32u;

    /* Did a server that does not know supported_versions answer with TLS 1.2 or earlier? */
    if (!_SSFTLSCShHasVersions(body, bodyLen))
    {
        _SSF_TLSC_SH_REJECT(s, "the server negotiated TLS 1.2 or earlier; TLS 1.3 is required",
                            SSF_TLS_ALERT_PROTOCOL_VERSION);
    }

    /* legacy_session_id_echo MUST equal the ClientHello legacy_session_id (4.1.3) */
    sidLen = body[pos++];
    chSidLen = s->hsScratch.clientHello[38];
    chSid = &s->hsScratch.clientHello[39];
    if ((sidLen > 32u) || ((pos + sidLen) > bodyLen))
    { _SSF_TLSC_SH_REJECT(s, "session id length", SSF_TLS_ALERT_DECODE_ERROR); }
    if ((sidLen != chSidLen) || (memcmp(&body[pos], chSid, sidLen) != 0))
    { _SSF_TLSC_SH_REJECT(s, "session id echo mismatch", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
    pos += sidLen;

    /* cipher_suite: one we can run; after an HRR, the one the HRR chose (4.1.4) */
    if ((((pos + 2u) + 1u) + 2u) > bodyLen)
    { _SSF_TLSC_SH_REJECT(s, "truncated", SSF_TLS_ALERT_DECODE_ERROR); }
    cs = _SSFTLSCGet16(&body[pos]); pos += 2;
    switch (cs)
    {
    case SSF_TLS_CS_AES_128_GCM_SHA256:
        s->hash = SSF_HMAC_HASH_SHA256; s->hashLen = 32; s->keyLen = 16; break;
    case SSF_TLS_CS_AES_256_GCM_SHA384:
        s->hash = SSF_HMAC_HASH_SHA384; s->hashLen = 48; s->keyLen = 32; break;
    case SSF_TLS_CS_CHACHA20_POLY1305_SHA256:
        s->hash = SSF_HMAC_HASH_SHA256; s->hashLen = 32; s->keyLen = 32; break;
    case SSF_TLS_CS_AES_128_CCM_SHA256:
        s->hash = SSF_HMAC_HASH_SHA256; s->hashLen = 32; s->keyLen = 16; break;
    default:
        _SSF_TLSC_SH_REJECT(s, "cipher suite", SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    }
    if (s->hrrDone && (cs != s->hrrSuite))
    { _SSF_TLSC_SH_REJECT(s, "cipher suite changed after HRR", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
    s->cipherSuite = cs;

    /* legacy_compression_method MUST be 0 (4.1.3) */
    if (body[pos++] != 0u)
    { _SSF_TLSC_SH_REJECT(s, "compression method", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }

    /* extensions: the list must fill the rest of the body exactly */
    extEnd = (pos + 2u) + _SSFTLSCGet16(&body[pos]);
    pos += 2;
    if (extEnd != bodyLen) _SSF_TLSC_SH_REJECT(s, "extensions length", SSF_TLS_ALERT_DECODE_ERROR);

    while (pos < extEnd)
    {
        uint16_t eType;
        uint16_t eLen;

        if ((pos + 4u) > extEnd)
        { _SSF_TLSC_SH_REJECT(s, "extension header", SSF_TLS_ALERT_DECODE_ERROR); }
        eType = _SSFTLSCGet16(&body[pos]);
        eLen = _SSFTLSCGet16(&body[pos + 2u]);
        pos += 4;
        if ((pos + eLen) > extEnd)
        { _SSF_TLSC_SH_REJECT(s, "extension length", SSF_TLS_ALERT_DECODE_ERROR); }

        /* Is it supported_versions? */
        if (eType == SSF_TLS_EXT_SUPPORTED_VERSIONS)
        {
            /* Yes, the selected version must be exactly TLS 1.3 (4.2.1) */
            if (hasVersions)
            { _SSF_TLSC_SH_REJECT(s, "duplicate supported_versions",
                                  SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
            hasVersions = true;
            if ((eLen != 2u) || (_SSFTLSCGet16(&body[pos]) != SSF_TLS_VERSION_13))
            { _SSF_TLSC_SH_REJECT(s, "supported_versions is not TLS 1.3",
                                  SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
        }
        else if (eType == SSF_TLS_EXT_KEY_SHARE)
        {
            /* No, key_share */
            uint16_t group;

            if (hasKeyShare)
            { _SSF_TLSC_SH_REJECT(s, "duplicate key_share", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
            hasKeyShare = true;
            if (eLen < 2u) _SSF_TLSC_SH_REJECT(s, "key_share length", SSF_TLS_ALERT_DECODE_ERROR);
            group = _SSFTLSCGet16(&body[pos]);
            /* Is it a HelloRetryRequest? */
            if (isHrr)
            {
                /* Yes, selected_group only, supported and without a share already sent (4.2.8) */
                if (eLen != 2u)
                { _SSF_TLSC_SH_REJECT(s, "key_share length", SSF_TLS_ALERT_DECODE_ERROR); }
                if (!_SSFTLSCGroupSupported(group))
                { _SSF_TLSC_SH_REJECT(s, "group not offered", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
                if (_SSFTLSCKeyShareOffered(s, group))
                { _SSF_TLSC_SH_REJECT(s, "group already has a key share",
                                      SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
            }
            else
            {
                /* No, one share for a group the ClientHello sent a share for (4.2.8) */
                uint16_t kLen;

                if (eLen < 4u)
                { _SSF_TLSC_SH_REJECT(s, "key_share length", SSF_TLS_ALERT_DECODE_ERROR); }
                kLen = _SSFTLSCGet16(&body[pos + 2u]);
                if (eLen != (4u + kLen))
                { _SSF_TLSC_SH_REJECT(s, "key_share length", SSF_TLS_ALERT_DECODE_ERROR); }
                if (!_SSFTLSCKeyShareOffered(s, group))
                { _SSF_TLSC_SH_REJECT(s, "group not offered", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
                if (kLen != _SSFTLSCKeyShareLen(group))
                { _SSF_TLSC_SH_REJECT(s, "key share size", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
                if (serverPubKey != NULL) memcpy(serverPubKey, &body[pos + 4u], kLen);
                if (serverPubKeyLen != NULL) *serverPubKeyLen = kLen;
            }
            *serverGroup = group;
        }
        else if (isHrr && (eType == 44u))
        {
            /* No, an HRR cookie (4.2.2) */
            if (hasCookie)
            { _SSF_TLSC_SH_REJECT(s, "duplicate cookie", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
            hasCookie = true;
            if ((eLen < 3u) || (_SSFTLSCGet16(&body[pos]) != (uint16_t)(eLen - 2u)))
            { _SSF_TLSC_SH_REJECT(s, "cookie length", SSF_TLS_ALERT_DECODE_ERROR); }
            if (cookieOut != NULL) *cookieOut = &body[pos];   /* Whole extension_data */
            if (cookieLenOut != NULL) *cookieLenOut = eLen;
        }
        else if ((eType == SSF_TLS_EXT_SERVER_NAME) || (eType == SSF_TLS_EXT_SUPPORTED_GROUPS) ||
                 (eType == SSF_TLS_EXT_SIGNATURE_ALGS) || (eType == SSF_TLS_EXT_ALPN) ||
                 (eType == SSF_TLS_EXT_PSK_KEY_EXCHANGE) ||
                 (eType == SSF_TLSC_EXT_RECORD_SIZE_LIMIT) || (eType == 44u))
        {
            /* No, recognized but not allowed in this message (4.2) */
            _SSF_TLSC_SH_REJECT(s, "extension not allowed here", SSF_TLS_ALERT_ILLEGAL_PARAMETER);
        }
        else
        {
            /* No, unsolicited; pre_shared_key included as no PSK is offered (4.2) */
            _SSF_TLSC_SH_REJECT(s, "unsolicited extension", SSF_TLS_ALERT_UNSUPPORTED_EXT);
        }
        pos += eLen;
    }

    /* Is key_share missing? A cookie-only HRR is not supported (4.1.4) */
    if (!hasKeyShare)
    {
        _SSF_TLSC_SH_REJECT(s, "missing key_share", (isHrr && !hasCookie) ?
                            SSF_TLS_ALERT_ILLEGAL_PARAMETER : SSF_TLS_ALERT_MISSING_EXTENSION);
    }
    return true;
}

#undef _SSF_TLSC_SH_REJECT

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
/* Test hook: replays a fixed RFC 8448 trace for the next ClientHello1; NULL clears              */
void _SSFTLSCInjectClientHelloForTest(const uint8_t *chOpt, size_t chLen,
                                      const uint8_t *x25519PrivOpt)
{
    SSF_REQUIRE(chLen <= SSF_TLSC_CH_SIZE);
    SSF_REQUIRE((chOpt == NULL) == (x25519PrivOpt == NULL));
    _utInjectCH = chOpt;
    _utInjectCHLen = chLen;
    _utInjectX25519 = x25519PrivOpt;
}

/* Test hook: replays a fixed HelloRetryRequest trace for the next ClientHello2; NULL clears     */
void _SSFTLSCInjectClientHello2ForTest(const uint8_t *ch2Opt, size_t ch2Len,
                                       const uint8_t *ecPrivOpt)
{
    SSF_REQUIRE(ch2Len <= SSF_TLSC_CH_SIZE);
    SSF_REQUIRE((ch2Opt == NULL) == (ecPrivOpt == NULL));
    _utInjectCH2 = ch2Opt;
    _utInjectCH2Len = ch2Len;
    _utInjectEC = ecPrivOpt;
}

/* Test hook: builds a ClientHello1, then parses body as a ServerHello or HelloRetryRequest      */
bool _SSFTLSCParseServerHelloExForTest(SSFTLSCSession_t *session, const uint8_t *body,
                                       size_t bodyLen, bool isHrr, uint16_t hrrGroup,
                                       uint16_t hrrSuite, uint8_t *alertOut, uint16_t *groupOut,
                                       uint8_t *pubOut, size_t *pubLenOut,
                                       const uint8_t **cookieOut, uint16_t *cookieLenOut)
{
    static uint8_t p384Pub[97];
    uint8_t random[32];
    uint8_t sid[32];
    uint8_t x25519Pub[32];
    SSFTLSCKeyShare_t shares[2];
    bool ok;

    memset(random, 0x11, sizeof(random));
    memset(sid, 0x22, sizeof(sid));
    memset(x25519Pub, 0x33, sizeof(x25519Pub));
    p384Pub[0] = 0x04u;
    shares[0].group = SSF_TLS_GROUP_X25519; shares[0].pub = x25519Pub; shares[0].len = 32u;
    shares[1].group = SSF_TLS_GROUP_SECP384R1; shares[1].pub = p384Pub; shares[1].len = 97u;
    ok = _SSFTLSCBuildClientHello(session, random, sid, (uint8_t)sizeof(sid), shares, 2u, NULL,
                                  0u);
    SSF_ASSERT(ok);
    session->hrrDone = (hrrGroup != 0u);
    session->hrrGroup = hrrGroup;
    session->hrrSuite = hrrSuite;
    session->pendingAlert = 0;
    ok = _SSFTLSCParseServerHello(session, body, bodyLen, isHrr, pubOut, pubLenOut, groupOut,
                                  cookieOut, cookieLenOut);
    *alertOut = ok ? 0u : session->pendingAlert;
    return ok;
}

bool _SSFTLSCParseServerHelloForTest(SSFTLSCSession_t *session, const uint8_t *body,
                                     size_t bodyLen, bool isHrr, uint8_t *alertOut)
{
    uint8_t pub[97];
    size_t pubLen;
    uint16_t group;
    const uint8_t *cookie;
    uint16_t cookieLen;

    return _SSFTLSCParseServerHelloExForTest(session, body, bodyLen, isHrr, 0u, 0u, alertOut,
                                             &group, pub, &pubLen, &cookie, &cookieLen);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Internal: completes the key exchange and derives the handshake traffic keys.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCDeriveHandshakeKeys(SSFTLSCSession_t *s,
                                        const uint8_t *serverPubKey, size_t serverPubKeyLen,
                                        uint16_t serverGroup)
{
    uint8_t sharedSecret[48];
    size_t sharedLen = 0;
    uint8_t ecdhSecret[SSF_ECDH_MAX_SECRET_SIZE];
    uint8_t earlySecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t derivedSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t handshakeSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t emptyHash[SSF_TLS_MAX_HASH_SIZE];
    uint8_t transcriptHash[SSF_TLS_MAX_HASH_SIZE];
    uint8_t zeroPSK[SSF_TLS_MAX_HASH_SIZE];
    uint8_t zeroIKM[SSF_TLS_MAX_HASH_SIZE];
    uint8_t key[SSF_TLS_MAX_KEY_SIZE];
    uint8_t iv[SSF_TLS_IV_SIZE];
    bool ok = false;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(serverPubKey != NULL);

    /* Is the server's group X25519? */
    if (serverGroup == SSF_TLS_GROUP_X25519)
    {
        /* Yes, complete the X25519 key exchange */
        if (!SSFX25519ComputeSecret(s->ephemeralPrivKey, serverPubKey, sharedSecret)) goto done;
        sharedLen = 32;
    }
    else if ((serverGroup == SSF_TLS_GROUP_SECP256R1) || (serverGroup == SSF_TLS_GROUP_SECP384R1))
    {
        /* No, complete the ECDH key exchange; the P-384 key follows the X25519 key */
        SSFECCurve_t curve = (serverGroup == SSF_TLS_GROUP_SECP256R1) ?
                              SSF_EC_CURVE_P256 : SSF_EC_CURVE_P384;
        const SSFECCurveParams_t *cp = SSFECGetCurveParams(curve);
        size_t secretLen;
        uint8_t *ecPriv = (serverGroup == SSF_TLS_GROUP_SECP384R1) ?
                           &s->ephemeralPrivKey[32] : s->ephemeralPrivKey;

        if (!SSFECDHComputeSecret(curve, ecPriv, cp->bytes,
                                  serverPubKey, serverPubKeyLen,
                                  ecdhSecret, sizeof(ecdhSecret), &secretLen))
        {
            SSF_TLS_TRACE_CRYPTO_ERROR(&s->trace, "ECDH compute secret failed (group=0x%04x)",
                                       serverGroup);
            goto done;
        }
        memcpy(sharedSecret, ecdhSecret, secretLen);
        sharedLen = secretLen;
    }
    else
    {
        /* No, unsupported group */
        SSF_TLS_TRACE_CRYPTO_ERROR(&s->trace, "Unsupported key exchange group 0x%04x",
                                   serverGroup);
        goto done;
    }

    /* Hash("") for deriving the "derived" secret */
    {
        SSFTLSTranscript_t tmp = { 0 };

        SSFTLSTranscriptInit(&tmp, s->hash);
        SSFTLSTranscriptHash(&tmp, emptyHash, sizeof(emptyHash));
        SSFTLSTranscriptDeInit(&tmp);
    }

    /* Early Secret = HKDF-Extract(0, 0), no PSK */
    memset(zeroPSK, 0, s->hashLen);
    memset(zeroIKM, 0, s->hashLen);
    SSFHKDFExtract(s->hash, zeroIKM, s->hashLen, zeroPSK, s->hashLen,
                   earlySecret, sizeof(earlySecret));

    /* derived = Derive-Secret(early_secret, "derived", Hash("")) */
    SSFTLSDeriveSecret(s->hash, earlySecret, s->hashLen,
                       "derived", emptyHash, s->hashLen,
                       derivedSecret, s->hashLen);

    /* Handshake Secret = HKDF-Extract(derived, shared_secret) */
    SSFHKDFExtract(s->hash, derivedSecret, s->hashLen, sharedSecret, sharedLen,
                   handshakeSecret, sizeof(handshakeSecret));

    /* Transcript hash up to ServerHello */
    SSFTLSTranscriptHash(&s->transcript, transcriptHash, sizeof(transcriptHash));
    /* Client/server handshake traffic secrets */
    SSFTLSDeriveSecret(s->hash, handshakeSecret, s->hashLen,
                       "c hs traffic", transcriptHash, s->hashLen,
                       s->clientHsTrafficSecret, s->hashLen);
    SSFTLSDeriveSecret(s->hash, handshakeSecret, s->hashLen,
                       "s hs traffic", transcriptHash, s->hashLen,
                       s->serverHsTrafficSecret, s->hashLen);

    /* Set up server handshake traffic keys for decryption */
    SSFTLSDeriveTrafficKeys(s->hash, s->serverHsTrafficSecret, s->hashLen,
                            key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    _SSFTLSCRecordStateSet(s, &s->recvState, &s->recvStateInited, key, iv);
    s->recvEncrypted = true;

    /* Client handshake traffic keys protect all the client sends from here (RFC 8446 6, 7.3) */
    SSFTLSDeriveTrafficKeys(s->hash, s->clientHsTrafficSecret, s->hashLen,
                            key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    _SSFTLSCRecordStateSet(s, &s->sendState, &s->sendStateInited, key, iv);
    s->sendEncrypted = true;

    /* Save handshake secret for later master secret derivation */
    memcpy(s->savedHandshakeSecret, handshakeSecret, s->hashLen);
    ok = true;

done:
    /* The ephemeral private keys are spent and no key schedule intermediate outlives this */
    _SSF_TLSC_SCRUB_N("ephemeralPrivKey", s->ephemeralPrivKey, sizeof(s->ephemeralPrivKey));
    _SSF_TLSC_SCRUB(sharedSecret);
    _SSF_TLSC_SCRUB(ecdhSecret);
    _SSF_TLSC_SCRUB(earlySecret);
    _SSF_TLSC_SCRUB(derivedSecret);
    _SSF_TLSC_SCRUB(handshakeSecret);
    _SSF_TLSC_SCRUB(key);
    _SSF_TLSC_SCRUB(iv);
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: derives the application traffic keys from the master secret.                       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCDeriveAppKeys(SSFTLSCSession_t *s, const uint8_t *handshakeSecret)
{
    uint8_t emptyHash[SSF_TLS_MAX_HASH_SIZE];
    uint8_t derivedSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t masterSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t zeroIKM[SSF_TLS_MAX_HASH_SIZE];
    uint8_t transcriptHash[SSF_TLS_MAX_HASH_SIZE];
    uint8_t key[SSF_TLS_MAX_KEY_SIZE];
    uint8_t iv[SSF_TLS_IV_SIZE];

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(handshakeSecret != NULL);

    /* Hash("") */
    {
        SSFTLSTranscript_t tmp = { 0 };

        SSFTLSTranscriptInit(&tmp, s->hash);
        SSFTLSTranscriptHash(&tmp, emptyHash, sizeof(emptyHash));
        SSFTLSTranscriptDeInit(&tmp);
    }

    /* derived = Derive-Secret(handshake_secret, "derived", Hash("")) */
    SSFTLSDeriveSecret(s->hash, handshakeSecret, s->hashLen,
                       "derived", emptyHash, s->hashLen,
                       derivedSecret, s->hashLen);

    /* Master Secret = HKDF-Extract(derived, 0) */
    memset(zeroIKM, 0, s->hashLen);
    SSFHKDFExtract(s->hash, derivedSecret, s->hashLen, zeroIKM, s->hashLen,
                   masterSecret, sizeof(masterSecret));

    /* Transcript hash up to server Finished */
    SSFTLSTranscriptHash(&s->transcript, transcriptHash, sizeof(transcriptHash));

    /* Application traffic secrets */
    SSFTLSDeriveSecret(s->hash, masterSecret, s->hashLen,
                       "c ap traffic", transcriptHash, s->hashLen,
                       s->clientAppTrafficSecret, s->hashLen);
    SSFTLSDeriveSecret(s->hash, masterSecret, s->hashLen,
                       "s ap traffic", transcriptHash, s->hashLen,
                       s->serverAppTrafficSecret, s->hashLen);

    /* Set up server application traffic keys for receiving; client send keys follow Finished */
    SSFTLSDeriveTrafficKeys(s->hash, s->serverAppTrafficSecret, s->hashLen,
                            key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    _SSFTLSCRecordStateSet(s, &s->recvState, &s->recvStateInited, key, iv);

    _SSF_TLSC_SCRUB(derivedSecret);
    _SSF_TLSC_SCRUB(masterSecret);
    _SSF_TLSC_SCRUB(key);
    _SSF_TLSC_SCRUB(iv);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Sets the trace callback for a TLS client session.                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSCSetTrace(SSFTLSCSession_t *session, SSFTLSTraceFn_t traceFnOpt, void *traceCtxOpt)
{
    SSF_REQUIRE(session != NULL);

    session->trace.fn = traceFnOpt;
    session->trace.userCtx = traceCtxOpt;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: crypto step that derives the handshake keys (ECDH + HKDF).                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCDeriveHSKeysWork(void *ctx)
{
    SSFTLSCCryptoWork_t *w = (SSFTLSCCryptoWork_t *)ctx;

    SSF_REQUIRE(w != NULL);
    SSF_REQUIRE(w->session != NULL);

    w->keyExchangeOk = _SSFTLSCDeriveHandshakeKeys(w->session, w->serverPubKey,
                                                   (size_t)w->serverPubKeyLen, w->serverGroup);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: maps a failed chain verification to its RFC 8446 6.2 alert.                         */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _SSFTLSCChainAlert(SSFX509VerifyCode_t code)
{
    SSF_REQUIRE((code > SSF_X509_VERIFY_OK) && (code < SSF_X509_VERIFY_MAX));

    switch (code)
    {
    case SSF_X509_VERIFY_ERR_VERSION:
    case SSF_X509_VERIFY_ERR_CRITICAL_EXT:
        return SSF_TLS_ALERT_UNSUPPORTED_CERTIFICATE;
    case SSF_X509_VERIFY_ERR_NOT_YET_VALID:
    case SSF_X509_VERIFY_ERR_EXPIRED:
        return SSF_TLS_ALERT_CERTIFICATE_EXPIRED;
    case SSF_X509_VERIFY_ERR_UNKNOWN_CA:
        return SSF_TLS_ALERT_UNKNOWN_CA;
    case SSF_X509_VERIFY_ERR_NOT_CA:
    case SSF_X509_VERIFY_ERR_CA_KEY_USAGE:
    case SSF_X509_VERIFY_ERR_PATH_LEN:
    case SSF_X509_VERIFY_ERR_NAME_CONSTRAINTS:
    case SSF_X509_VERIFY_ERR_EKU:
    case SSF_X509_VERIFY_ERR_LEAF_KEY_USAGE:
        return SSF_TLS_ALERT_CERTIFICATE_UNKNOWN;
    default:
        return SSF_TLS_ALERT_BAD_CERTIFICATE;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: crypto step that verifies the server certificate chain.                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCVerifyChainWork(void *ctx)
{
    SSFTLSCCryptoWork_t *w = (SSFTLSCCryptoWork_t *)ctx;

    SSF_REQUIRE(w != NULL);
    SSF_REQUIRE(w->session != NULL);

    w->chainVerifyOk = SSFX509VerifyChain(w->chainDerPtrs, w->chainDerLens, w->chainLen,
                                           w->session->trust.caDer,
                                           w->session->trust.caDerLen,
                                           w->session->trust.count,
                                           w->hostname, w->nowUnixSec, &w->chainVerifyErr);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: crypto step that verifies the server CertificateVerify signature.                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCVerifySigWork(void *ctx)
{
    SSFTLSCCryptoWork_t *w = (SSFTLSCCryptoWork_t *)ctx;
    bool verified = false;

    SSF_REQUIRE(w != NULL);

    /* Is the scheme Ed25519, which verifies over the raw content in contentHash? */
    if (w->sigScheme == SSF_TLS_SIG_ED25519)
    {
        /* Yes, verify it if the key and signature sizes are right */
        if ((w->leafPubKeyLen == SSF_ED25519_PUB_KEY_SIZE) &&
            (w->sigDataLen == SSF_ED25519_SIG_SIZE))
        {
            verified = SSFEd25519Verify(w->leafPubKey, w->contentHash, w->contentHashLen,
                                         w->sigData);
        }
    }
#if _SSF_TLSC_P256
    else if (w->sigScheme == SSF_TLS_SIG_ECDSA_SECP256R1_SHA256)
    {
        /* No, ECDSA P-256 */
        verified = SSFECDSAVerify(SSF_EC_CURVE_P256, w->leafPubKey, (size_t)w->leafPubKeyLen,
                                  w->contentHash, 32, w->sigData, (size_t)w->sigDataLen);
    }
#endif
#if _SSF_TLSC_P384
    else if (w->sigScheme == SSF_TLS_SIG_ECDSA_SECP384R1_SHA384)
    {
        /* No, ECDSA P-384 */
        verified = SSFECDSAVerify(SSF_EC_CURVE_P384, w->leafPubKey, (size_t)w->leafPubKeyLen,
                                  w->contentHash, 48, w->sigData, (size_t)w->sigDataLen);
    }
#endif
#if _SSF_TLSC_PSS
    else if (w->sigScheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA256)
    {
        /* No, RSA-PSS SHA-256, salt length the hash length */
        verified = SSFRSAVerifyPSS(w->leafPubKey, (size_t)w->leafPubKeyLen,
                                   SSF_RSA_HASH_SHA256,
                                   w->contentHash, 32, 32u,
                                   w->sigData, (size_t)w->sigDataLen);
    }
    else if (w->sigScheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA384)
    {
        /* No, RSA-PSS SHA-384, salt length the hash length */
        verified = SSFRSAVerifyPSS(w->leafPubKey, (size_t)w->leafPubKeyLen,
                                   SSF_RSA_HASH_SHA384,
                                   w->contentHash, 48, 48u,
                                   w->sigData, (size_t)w->sigDataLen);
    }
#endif
    /* No, any other scheme, rsa_pkcs1_* included, fails (RFC 8446 4.2.3) */
    w->sigVerifyOk = verified;
}

/* HelloRetryRequest sentinel random (RFC 8446 4.1.3) */
static const uint8_t _SSFTLSCHrrSentinel[32] = {
    0xCFu, 0x21u, 0xADu, 0x74u, 0xE5u, 0x9Au, 0x61u, 0x11u,
    0xBEu, 0x1Du, 0x8Cu, 0x02u, 0x1Eu, 0x65u, 0xB8u, 0x91u,
    0xC2u, 0xA2u, 0x11u, 0x16u, 0x7Au, 0xBBu, 0x8Cu, 0x5Eu,
    0x07u, 0x9Eu, 0x09u, 0xE2u, 0xC8u, 0xA8u, 0x33u, 0x9Cu
};

/* --------------------------------------------------------------------------------------------- */
/* Internal: SEND_CH state; sends the ClientHello and receives the ServerHello, resumable        */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCHandleSendCH(SSFTLSCSession_t *session)
{
    uint8_t *buf;
    uint8_t serverPubKey[97];
    size_t serverPubKeyLen = 0;
    uint16_t serverGroup = 0;
    SSFTLSIOResult_t r;

    SSF_REQUIRE(session != NULL);
    SSF_REQUIRE(session->inner != NULL);
    buf = session->hsBuf;

    /* Is this the entry substate? */
    if (session->helperStep == 0)
    {
        /* Yes, wait for the inner transport opened by open() to connect */
        SSFNetIOResult_t ir = session->inner->pollOpen(session->inner);

        /* Is the inner transport still connecting? */
        if ((ir == SSF_NET_IO_WANT_READ) || (ir == SSF_NET_IO_WANT_WRITE))
        { return SSF_TLS_IO_WANT_READ; }
        /* Did the inner open fail? */
        if (ir != SSF_NET_IO_SUCCESS)
        {
            /* Yes */
            if (ir == SSF_NET_IO_CLOSED) session->peerClosed = true;
            session->ioFailed = true;
            SSF_TLS_TRACE_HS_ERROR(&session->trace, "Inner transport open failed");
            return SSF_TLS_IO_ERROR;
        }

        /* Connected: initialize the handshake transcript */
        SSFTLSTranscriptInit(&session->transcript, SSF_HMAC_HASH_SHA256);
        session->hash = SSF_HMAC_HASH_SHA256;
        session->hashLen = 32;
        session->helperStep = 1;
    }

    for (;;)
    {
        switch (session->helperStep)
        {
        case 1:
        {
            /* Build ClientHello1 once: fresh random, session id and ephemeral keys */
            uint8_t random[32];
            uint8_t sid[32];
            uint8_t x25519Pub[32];
#if _SSF_TLSC_P384
            uint8_t ecPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            uint8_t ecPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t ecPubLen;
#endif
            SSFTLSCKeyShare_t shares[2];
            uint8_t shareCount = 1u;

            SSF_TLS_TRACE_HS_INFO(&session->trace, "Sending ClientHello to %.200s", session->host);
            if (!_SSFTLSCGetEntropy(random, sizeof(random)) ||
                !_SSFTLSCGetEntropy(sid, sizeof(sid)) ||
                !_SSFTLSCGetEntropy(session->ephemeralPrivKey, 32))
            { return SSF_TLS_IO_ERROR; }
            SSFX25519PubKeyFromPrivKey(session->ephemeralPrivKey, x25519Pub);

            /* X25519 and, when built, secp384r1 shares, which avoid most HelloRetryRequests */
            shares[0].group = SSF_TLS_GROUP_X25519;
            shares[0].pub = x25519Pub;
            shares[0].len = 32u;
#if _SSF_TLSC_P384
            if (!SSFECDSAKeyGen(SSF_EC_CURVE_P384, ecPriv, sizeof(ecPriv),
                                ecPub, sizeof(ecPub), &ecPubLen))
            { return SSF_TLS_IO_ERROR; }
            memcpy(&session->ephemeralPrivKey[32], ecPriv, 48);
            _SSF_TLSC_SCRUB(ecPriv);
            shares[1].group = SSF_TLS_GROUP_SECP384R1;
            shares[1].pub = ecPub;
            shares[1].len = (uint16_t)ecPubLen;
            shareCount = 2u;
#endif
            if (!_SSFTLSCBuildClientHello(session, random, sid, (uint8_t)sizeof(sid), shares,
                                          shareCount, NULL, 0u))
            {
                SSF_TLS_TRACE_HS_ERROR(&session->trace,
                                       "ClientHello does not fit hsScratch.clientHello");
                return SSF_TLS_IO_ERROR;
            }
#if SSF_CONFIG_TLSC_UNIT_TEST == 1
            /* Is a fixed trace's ClientHello and key injected? */
            if (_utInjectCH != NULL)
            {
                memcpy(session->hsScratch.clientHello, _utInjectCH, _utInjectCHLen);
                session->hsScratchLen = _utInjectCHLen;
                memcpy(session->ephemeralPrivKey, _utInjectX25519, 32u);
            }
#endif
            SSFTLSTranscriptUpdate(&session->transcript, session->hsScratch.clientHello,
                                   session->hsScratchLen);
            session->helperStep = 2;
        }
        /* fall through */
        case 2:
            r = _SSFTLSCSendPlainRecordOnce(session, SSF_TLS_CT_HANDSHAKE,
                                            session->hsScratch.clientHello, session->hsScratchLen);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            session->clientHelloSent = true;
            session->helperStep = 3;
            /* fall through */
        case 3:
        {
            uint8_t ccs = 0x01u;

            r = _SSFTLSCSendPlainRecordOnce(session, SSF_TLS_CT_CHANGE_CIPHER, &ccs, 1);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            session->helperStep = 4;
        }
        /* fall through */
        case 4:
        {
            const uint8_t *msg = NULL;
            size_t bodyLen = 0;
            uint8_t hsType = 0;
            size_t ptLen;

            /* ServerHello or HelloRetryRequest; the transcript is updated below */
            r = _SSFTLSCRecvHandshakeOnce(session, &msg, &bodyLen, &hsType, false);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            if (hsType != SSF_TLS_HS_SERVER_HELLO)
            { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Not ServerHello: type=%u", hsType);
              _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }
            if (!_SSFTLSCHandshakeAtRecordEnd(session, "ServerHello")) return SSF_TLS_IO_ERROR;
            buf = (uint8_t *)msg;                 /* In hsBuf: header + body */
            ptLen = 4u + bodyLen;

            /* Is it a HelloRetryRequest (RFC 8446 4.1.4)? */
            if ((ptLen >= 38u) && (memcmp(&buf[6], _SSFTLSCHrrSentinel, 32) == 0))
            {
                /* Yes, all its non-idempotent work runs here, then case 10 */
                uint16_t hrrGroup = 0;
                uint16_t hrrSuite;
                SSFHMACHash_t hrrHash;
                const uint8_t *hrrCookie = NULL;
                uint16_t hrrCookieLen = 0;

                SSF_TLS_TRACE_HS_INFO(&session->trace, "HelloRetryRequest received");

                if (!_SSFTLSCParseServerHello(session, &buf[4], ptLen - 4u, true, NULL, NULL,
                                              &hrrGroup, &hrrCookie, &hrrCookieLen))
                { return SSF_TLS_IO_ERROR; }

                hrrSuite = session->cipherSuite;
                hrrHash = session->hash;
                session->hrrDone = true;
                session->hrrGroup = hrrGroup;
                session->hrrSuite = hrrSuite;
                SSF_TLS_TRACE_HS_INFO(&session->trace, "HRR: suite=0x%04x group=0x%04x",
                                      hrrSuite, hrrGroup);

                /* Synthetic message_hash transcript reinit (RFC 8446 4.4.1) */
                {
                    uint8_t ch1Hash[SSF_TLS_MAX_HASH_SIZE];
                    uint8_t synthMsg[4 + SSF_TLS_MAX_HASH_SIZE];
                    uint16_t hLen = (hrrHash == SSF_HMAC_HASH_SHA384) ? 48u : 32u;

                    /* Is the HRR's hash other than the SHA-256 the transcript started with? */
                    if (hrrHash != SSF_HMAC_HASH_SHA256)
                    {
                        /* Yes, rehash ClientHello1 with it */
                        SSFTLSTranscript_t tmpT = { 0 };

                        SSFTLSTranscriptInit(&tmpT, hrrHash);
                        SSFTLSTranscriptUpdate(&tmpT, session->hsScratch.clientHello,
                                               session->hsScratchLen);
                        SSFTLSTranscriptHash(&tmpT, ch1Hash, sizeof(ch1Hash));
                        SSFTLSTranscriptDeInit(&tmpT);
                    }
                    else
                    {
                        /* No, the running transcript already holds ClientHello1's hash */
                        SSFTLSTranscriptHash(&session->transcript, ch1Hash, sizeof(ch1Hash));
                    }

                    synthMsg[0] = 254u;
                    _SSFTLSCPut24(&synthMsg[1], hLen);
                    memcpy(&synthMsg[4], ch1Hash, hLen);

                    SSFTLSTranscriptDeInit(&session->transcript);
                    SSFTLSTranscriptInit(&session->transcript, hrrHash);
                    session->hashLen = hLen;
                    SSFTLSTranscriptUpdate(&session->transcript, synthMsg, 4u + hLen);
                    SSFTLSTranscriptUpdate(&session->transcript, buf, ptLen);
                }

                /* Is the selected group an ECDH group, to rebuild ClientHello2 for (4.1.2)? */
                if ((hrrGroup == SSF_TLS_GROUP_SECP256R1) || (hrrGroup == SSF_TLS_GROUP_SECP384R1))
                {
                    /* Yes, keep ClientHello1's random and session id, replace the key share */
                    SSFECCurve_t curve = (hrrGroup == SSF_TLS_GROUP_SECP256R1) ?
                                          SSF_EC_CURVE_P256 : SSF_EC_CURVE_P384;
                    uint8_t ecPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
                    uint8_t ecPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
                    size_t ecPubLen;
                    const SSFECCurveParams_t *cp = SSFECGetCurveParams(curve);
                    uint8_t random[32];
                    uint8_t sid[32];
                    uint8_t sidLen = session->hsScratch.clientHello[38];
                    SSFTLSCKeyShare_t share;

                    if (!SSFECDSAKeyGen(curve, ecPriv, sizeof(ecPriv),
                                        ecPub, sizeof(ecPub), &ecPubLen))
                    { SSF_TLS_TRACE_CRYPTO_ERROR(&session->trace, "HRR: ECDH key gen failed");
                      return SSF_TLS_IO_ERROR; }

                    memcpy(session->ephemeralPrivKey, ecPriv, cp->bytes);
                    _SSF_TLSC_SCRUB(ecPriv);

                    /* Take ClientHello1's values first: hsScratch.clientHello is rebuilt */
                    memcpy(random, &session->hsScratch.clientHello[6], sizeof(random));
                    memcpy(sid, &session->hsScratch.clientHello[39], sidLen);
                    share.group = hrrGroup;
                    share.pub = ecPub;
                    share.len = (uint16_t)ecPubLen;
                    if (!_SSFTLSCBuildClientHello(session, random, sid, sidLen, &share, 1u,
                                                  hrrCookie, hrrCookieLen))
                    {
                        /* Never send ClientHello2 without the cookie */
                        SSF_TLS_TRACE_HS_ERROR(&session->trace,
                                               "HRR: ClientHello2 does not fit (cookie %u bytes)",
                                               hrrCookieLen);
                        _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_INTERNAL_ERROR);
                        return SSF_TLS_IO_ERROR;
                    }
#if SSF_CONFIG_TLSC_UNIT_TEST == 1
                    /* Is a fixed trace's ClientHello2 and key injected? */
                    if (_utInjectCH2 != NULL)
                    {
                        memcpy(session->hsScratch.clientHello, _utInjectCH2, _utInjectCH2Len);
                        session->hsScratchLen = _utInjectCH2Len;
                        memcpy(session->ephemeralPrivKey, _utInjectEC, cp->bytes);
                    }
#endif
                    SSFTLSTranscriptUpdate(&session->transcript, session->hsScratch.clientHello,
                                           session->hsScratchLen);

                    SSF_TLS_TRACE_HS_INFO(&session->trace,
                                          "HRR: ClientHello2 built with group 0x%04x", hrrGroup);
                    session->helperStep = 10;
                    continue;
                }
                else
                {
                    /* No, unsupported group */
                    SSF_TLS_TRACE_HS_ERROR(&session->trace, "HRR: unsupported group 0x%04x",
                                           hrrGroup);
                    return SSF_TLS_IO_ERROR;
                }
            }

            /* No, a ServerHello: parse it, rehash for SHA-384 if needed, stash for case 20 */
            SSFTLSTranscriptUpdate(&session->transcript, buf, ptLen);

            if (!_SSFTLSCParseServerHello(session, &buf[4], ptLen - 4u, false,
                                          serverPubKey, &serverPubKeyLen, &serverGroup, NULL,
                                          NULL))
            { return SSF_TLS_IO_ERROR; }
            SSF_TLS_TRACE_HS_INFO(&session->trace,
                                  "ServerHello: suite=0x%04x group=0x%04x keyLen=%zu",
                                  session->cipherSuite, serverGroup, serverPubKeyLen);

            /* Did the server choose a SHA-384 suite? */
            if (session->hash == SSF_HMAC_HASH_SHA384)
            {
                /* Yes, rebuild the transcript with SHA-384 */
                SSF_TLS_TRACE_CRYPTO_INFO(&session->trace,
                                          "Re-initializing transcript for SHA-384 (CH=%zu SH=%zu)",
                                          session->hsScratchLen, ptLen);
                if (session->hsScratchLen == 0)
                { SSF_TLS_TRACE_HS_ERROR(&session->trace,
                                         "ERROR: ClientHello was not saved (too large for buffer)");
                  return SSF_TLS_IO_ERROR; }
                SSFTLSTranscriptDeInit(&session->transcript);
                SSFTLSTranscriptInit(&session->transcript, SSF_HMAC_HASH_SHA384);
                SSFTLSTranscriptUpdate(&session->transcript,
                                       session->hsScratch.clientHello, session->hsScratchLen);
                SSFTLSTranscriptUpdate(&session->transcript, buf, ptLen);
            }

            /* Stash the results into cryptoWork, which lives as long as the session */
            session->cryptoWork.session = session;
            memcpy(session->cryptoWork.serverPubKey, serverPubKey, serverPubKeyLen);
            session->cryptoWork.serverPubKeyLen = (uint8_t)serverPubKeyLen;
            session->cryptoWork.serverGroup = serverGroup;
            session->helperStep = 20;
            continue;
        }
        case 10:
            /* HRR: send ClientHello2, built in case 4 */
            r = _SSFTLSCSendPlainRecordOnce(session, SSF_TLS_CT_HANDSHAKE,
                                            session->hsScratch.clientHello, session->hsScratchLen);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            session->helperStep = 11;
            /* fall through */
        case 11:
        {
            /* HRR: receive the second ServerHello; a second HRR is rejected */
            const uint8_t *msg = NULL;
            size_t bodyLen = 0;
            uint8_t hsType = 0;
            size_t ptLen;

            r = _SSFTLSCRecvHandshakeOnce(session, &msg, &bodyLen, &hsType, false);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            if (hsType != SSF_TLS_HS_SERVER_HELLO)
            { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Not ServerHello after HRR");
              _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }
            if (!_SSFTLSCHandshakeAtRecordEnd(session, "ServerHello")) return SSF_TLS_IO_ERROR;
            buf = (uint8_t *)msg;
            ptLen = 4u + bodyLen;

            if ((ptLen >= 38u) && (memcmp(&buf[6], _SSFTLSCHrrSentinel, 32) == 0))
            { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Double HRR not supported");
              _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }

            SSFTLSTranscriptUpdate(&session->transcript, buf, ptLen);

            if (!_SSFTLSCParseServerHello(session, &buf[4], ptLen - 4u, false,
                                          serverPubKey, &serverPubKeyLen, &serverGroup, NULL,
                                          NULL))
            { return SSF_TLS_IO_ERROR; }

            SSF_TLS_TRACE_HS_INFO(&session->trace,
                                  "ServerHello after HRR: suite=0x%04x group=0x%04x",
                                  session->cipherSuite, serverGroup);

            session->cryptoWork.session = session;
            memcpy(session->cryptoWork.serverPubKey, serverPubKey, serverPubKeyLen);
            session->cryptoWork.serverPubKeyLen = (uint8_t)serverPubKeyLen;
            session->cryptoWork.serverGroup = serverGroup;
            session->helperStep = 20;
            continue;
        }
        case 20:
            /* Done; the driver runs the ECDH + key schedule step on the next pollOpen() call */
            session->helperStep = 0;
            return SSF_TLS_IO_SUCCESS;
        default:
            return SSF_TLS_IO_ERROR;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: validates an EncryptedExtensions body (RFC 8446 4.3.1, 4.2)                         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCParseEncryptedExtensions(const uint8_t *body, size_t bodyLen,
                                             uint8_t *alertOut, uint16_t *recordLimitOut,
                                             const char *const *alpnOpt, uint8_t alpnCount,
                                             uint8_t *alpnChosenOut)
{
    size_t pos = 2;
    size_t end;
    bool hasSni = false;
    bool hasGroups = false;
    bool hasRecordLimit = false;
    uint8_t chosen = 0;

    SSF_REQUIRE(body != NULL);
    SSF_REQUIRE(alertOut != NULL);
    SSF_REQUIRE(recordLimitOut != NULL);
    SSF_REQUIRE((alpnOpt != NULL) || (alpnCount == 0u));
    SSF_REQUIRE(alpnChosenOut != NULL);

    *alertOut = SSF_TLS_ALERT_DECODE_ERROR;
    *recordLimitOut = 0;
    *alpnChosenOut = 0;

    /* The message is exactly extensions<0..2^16-1> (4.3.1) */
    if (bodyLen < 2u) return false;
    end = 2u + ((size_t)_SSFTLSCGet16(&body[0]));
    if (end != bodyLen) return false;

    /* pos never passes end, so the differences below cannot wrap */
    while (pos < end)
    {
        uint16_t eType;
        uint16_t eLen;

        if ((end - pos) < 4u) return false;
        eType = _SSFTLSCGet16(&body[pos]);
        eLen = _SSFTLSCGet16(&body[pos + 2u]);
        pos += 4;
        if (eLen > (end - pos)) return false;

        switch (eType)
        {
        case SSF_TLS_EXT_SERVER_NAME:
            /* Acknowledges the SNI sent, with empty extension_data (RFC 6066 3) */
            if (hasSni) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            hasSni = true;
            if (eLen != 0u) return false;
            break;
        case SSF_TLS_EXT_SUPPORTED_GROUPS:
            /* Informational server group preferences (4.2.7): a non-empty NamedGroupList */
            if (hasGroups) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            hasGroups = true;
            if ((eLen < 4u) || (_SSFTLSCGet16(&body[pos]) != (uint16_t)(eLen - 2u)) ||
                (((eLen - 2u) & 1u) != 0u))
            { return false; }
            break;
        case SSF_TLSC_EXT_RECORD_SIZE_LIMIT:
        {
            uint16_t limit;

            /* A single uint16 (RFC 8449 4): below 64 is illegal, above 2^14+1 is capped */
            if (hasRecordLimit) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            hasRecordLimit = true;
            if (eLen != 2u) return false;
            limit = _SSFTLSCGet16(&body[pos]);
            if (limit < SSF_TLSC_RSL_MIN)
            { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            *recordLimitOut = (limit > SSF_TLSC_RSL_MAX) ? (uint16_t)SSF_TLSC_RSL_MAX : limit;
            break;
        }
        case SSF_TLS_EXT_ALPN:
        {
            uint8_t i;

            /* Only if offered: exactly one non-empty name the client offered (RFC 7301 3.1) */
            if (alpnCount == 0u) { *alertOut = SSF_TLS_ALERT_UNSUPPORTED_EXT; return false; }
            if (chosen != 0u) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            if ((eLen < 4u) || (_SSFTLSCGet16(&body[pos]) != (uint16_t)(eLen - 2u)) ||
                ((size_t)body[pos + 2u] != (size_t)(eLen - 3u)))
            { return false; }
            for (i = 0; i < alpnCount; i++)
            {
                if ((_SSFTLSCAlpnLen(alpnOpt[i]) == (size_t)(eLen - 3u)) &&
                    (memcmp(alpnOpt[i], &body[pos + 3u], (size_t)(eLen - 3u)) == 0))
                { chosen = (uint8_t)(i + 1u); }
            }
            if (chosen == 0u) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            break;
        }
        case SSF_TLS_EXT_SUPPORTED_VERSIONS:
        case SSF_TLS_EXT_KEY_SHARE:
        case SSF_TLS_EXT_SIGNATURE_ALGS:
        case SSF_TLS_EXT_PSK_KEY_EXCHANGE:
            /* Offered, but not specified for EncryptedExtensions: illegal_parameter (4.2) */
            *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER;
            return false;
        default:
            /* Not offered by the ClientHello: unsupported_extension (4.2) */
            *alertOut = SSF_TLS_ALERT_UNSUPPORTED_EXT;
            return false;
        }
        pos += eLen;
    }

    *alpnChosenOut = chosen;
    *alertOut = 0;
    return true;
}

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
bool _SSFTLSCParseEncryptedExtensionsForTest(const uint8_t *body, size_t bodyLen,
                                             uint8_t *alertOut)
{
    uint16_t limit;
    uint8_t chosen;

    return _SSFTLSCParseEncryptedExtensions(body, bodyLen, alertOut, &limit, NULL, 0u, &chosen);
}

bool _SSFTLSCParseEncryptedExtensionsAlpnForTest(SSFTLSCSession_t *session, const uint8_t *body,
                                                 size_t bodyLen, uint8_t *alertOut)
{
    uint16_t limit;

    return _SSFTLSCParseEncryptedExtensions(body, bodyLen, alertOut, &limit, session->alpnProtos,
                                            session->alpnCount, &session->alpnChosen);
}

bool _SSFTLSCParseEncryptedExtensionsRslForTest(const uint8_t *body, size_t bodyLen,
                                                uint8_t *alertOut, uint16_t *recordLimitOut)
{
    uint8_t chosen;

    return _SSFTLSCParseEncryptedExtensions(body, bodyLen, alertOut, recordLimitOut, NULL, 0u,
                                            &chosen);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Internal: validates a CertificateRequest body (RFC 8446 4.3.2) and chooses the client scheme  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCParseCertificateRequest(const uint8_t *body, size_t bodyLen,
                                            SSFPKeyType_t keyType, uint16_t *schemeOut,
                                            const uint8_t **certAlgsOut, size_t *certAlgsLenOut,
                                            uint8_t *alertOut)
{
    size_t pos;
    size_t start;
    size_t end;
    size_t ctxLen;
    bool hasSigAlgs = false;
    uint16_t chosen = 0;
    const uint8_t *sigAlgs = NULL;
    size_t sigAlgsLen = 0;
    const uint8_t *certAlgs = NULL;
    size_t certAlgsLen = 0;

    SSF_REQUIRE(body != NULL);
    SSF_REQUIRE(schemeOut != NULL);
    SSF_REQUIRE(certAlgsOut != NULL);
    SSF_REQUIRE(certAlgsLenOut != NULL);
    SSF_REQUIRE(alertOut != NULL);

    *alertOut = SSF_TLS_ALERT_DECODE_ERROR;
    *schemeOut = 0;
    *certAlgsOut = NULL;
    *certAlgsLenOut = 0;

    /* certificate_request_context<0..2^8-1>, then extensions<2..2^16-1> filling the message */
    if (bodyLen < 1u) return false;
    ctxLen = body[0];
    if ((bodyLen - 1u) < (ctxLen + 2u)) return false;
    start = (1u + ctxLen) + 2u;
    end = start + ((size_t)_SSFTLSCGet16(&body[1u + ctxLen]));
    if ((end != bodyLen) || ((end - start) < 2u)) return false;
    /* Is there a context, used only for post-handshake authentication the client never offers? */
    if (ctxLen != 0u) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }

    /* pos never passes end, so the differences below cannot wrap */
    for (pos = start; pos < end; )
    {
        uint16_t eType;
        uint16_t eLen;
        size_t prev;

        if ((end - pos) < 4u) return false;
        eType = _SSFTLSCGet16(&body[pos]);
        eLen = _SSFTLSCGet16(&body[pos + 2u]);
        if (eLen > ((end - pos) - 4u)) return false;

        /* No extension type twice in one block (4.2), recognized or not */
        for (prev = start; prev < pos; prev += (4u + ((size_t)_SSFTLSCGet16(&body[prev + 2u]))))
        {
            if (_SSFTLSCGet16(&body[prev]) == eType)
            { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
        }

        switch (eType)
        {
        case SSF_TLS_EXT_SIGNATURE_ALGS:
        case SSF_TLSC_EXT_SIG_ALGS_CERT:
            /* SignatureSchemeList<2..2^16-2> filling the extension (4.2.3) */
            if ((eLen < 4u) || (_SSFTLSCGet16(&body[pos + 4u]) != (uint16_t)(eLen - 2u)) ||
                ((eLen & 1u) != 0u)) return false;
            /* Is it signature_algorithms_cert? */
            if (eType == SSF_TLSC_EXT_SIG_ALGS_CERT)
            {
                /* Yes, keep its list for the certificate signatures */
                certAlgs = &body[pos + 6u];
                certAlgsLen = (size_t)eLen - 2u;
                break;
            }
            hasSigAlgs = true;
            sigAlgs = &body[pos + 6u];
            sigAlgsLen = (size_t)eLen - 2u;
            {
                size_t k;

                for (k = 0; (k < sigAlgsLen) && (chosen == 0u); k += 2u)
                {
                    if (_SSFTLSCSchemeCanSign(_SSFTLSCGet16(&sigAlgs[k]),
                                              _SSFTLSCPKeyLeafType(keyType)))
                    {
                        chosen = _SSFTLSCGet16(&sigAlgs[k]);
                    }
                }
            }
            break;
        case SSF_TLS_EXT_SERVER_NAME:
        case SSF_TLS_EXT_SUPPORTED_GROUPS:
        case SSF_TLSC_EXT_RECORD_SIZE_LIMIT:
        case SSF_TLS_EXT_SUPPORTED_VERSIONS:
        case SSF_TLS_EXT_PSK_KEY_EXCHANGE:
        case SSF_TLS_EXT_KEY_SHARE:
        case SSF_TLS_EXT_ALPN:
            /* Recognized, but not specified for CertificateRequest: illegal_parameter (4.2) */
            *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER;
            return false;
        default:
            /* Anything else, e.g. certificate_authorities or oid_filters, is ignored (4.3.2) */
            break;
        }
        pos += (4u + ((size_t)eLen));
    }

    /* signature_algorithms MUST be present (4.3.2); a missing one is missing_extension (9.2) */
    if (!hasSigAlgs) { *alertOut = SSF_TLS_ALERT_MISSING_EXTENSION; return false; }

    /* Only a request accepted whole yields a scheme and lists */
    *schemeOut = chosen;
    *certAlgsOut = (certAlgs != NULL) ? certAlgs : sigAlgs;
    *certAlgsLenOut = (certAlgs != NULL) ? certAlgsLen : sigAlgsLen;
    *alertOut = 0;
    return true;
}

/* Forward declaration for client authentication (mutual TLS, RFC 8446 4.4.2, 4.4.3) */
static size_t _SSFTLSCSendRecordMax(const SSFTLSCSession_t *s);

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns the length of the client Certificate message.                               */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFTLSCClientCertMsgLen(const SSFTLSCSession_t *s)
{
    size_t len = 4u + 1u + 3u;
    uint8_t i;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE((s->clientChainLens != NULL) || (s->clientChainCount == 0u));

    for (i = 0; i < s->clientChainCount; i++)
    {
        len += ((3u + ((size_t)s->clientChainLens[i])) + 2u);
    }
    return len;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: copies the part of piece inside the window *off / *dst / *dstSize, then passes it   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCCopyPiece(size_t *off, uint8_t **dst, size_t *dstSize, const uint8_t *piece,
                              size_t pieceLen)
{
    size_t c;

    SSF_REQUIRE(off != NULL);
    SSF_REQUIRE(dst != NULL);
    SSF_REQUIRE(dstSize != NULL);
    SSF_REQUIRE(piece != NULL);

    if (*off >= pieceLen) { *off -= pieceLen; return; }
    c = pieceLen - *off;
    if (c > *dstSize) c = *dstSize;
    memcpy(*dst, &piece[*off], c);
    *dst += c;
    *dstSize -= c;
    *off = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: copies bytes off..off+dstSize of the client Certificate message, read in place      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCClientCertMsgCopy(const SSFTLSCSession_t *s, size_t off, uint8_t *dst,
                                      size_t dstSize)
{
    static const uint8_t noExts[2] = { 0, 0 };
    uint8_t hdr[8];
    uint8_t len24[3];
    size_t body;
    uint8_t i;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(dst != NULL);
    SSF_REQUIRE((s->clientChainDer != NULL) || (s->clientChainCount == 0u));

    body = _SSFTLSCClientCertMsgLen(s) - 4u;
    hdr[0] = SSF_TLS_HS_CERTIFICATE;
    _SSFTLSCPut24(&hdr[1], body);
    hdr[4] = 0;                                                  /* certificate_request_context */
    _SSFTLSCPut24(&hdr[5], body - 4u);                           /* certificate_list length */
    _SSFTLSCCopyPiece(&off, &dst, &dstSize, hdr, sizeof(hdr));
    for (i = 0; (i < s->clientChainCount) && (dstSize > 0u); i++)
    {
        _SSFTLSCPut24(len24, s->clientChainLens[i]);
        _SSFTLSCCopyPiece(&off, &dst, &dstSize, len24, sizeof(len24));
        _SSFTLSCCopyPiece(&off, &dst, &dstSize, s->clientChainDer[i], s->clientChainLens[i]);
        _SSFTLSCCopyPiece(&off, &dst, &dstSize, noExts, sizeof(noExts));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: sends a handshake message in records of the send limit; msg NULL is the Certificate */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCSendHandshakeOnce(SSFTLSCSession_t *s, const uint8_t *msg,
                                                  size_t msgLen)
{
    size_t chunk;
    SSFTLSIOResult_t r;

    SSF_REQUIRE(s != NULL);

    chunk = _SSFTLSCSendRecordMax(s);
    if (chunk > SSF_TLSC_HSBUF_SIZE) chunk = SSF_TLSC_HSBUF_SIZE;
    for (;;)
    {
        size_t n = 0;

        /* Is a new record to be cut? */
        if (!s->ioCtx.sendPending)
        {
            /* Yes, stage the next piece in hsBuf, idle as the server's handshake has ended */
            if (s->certSendOff >= msgLen) return SSF_TLS_IO_SUCCESS;
            n = msgLen - s->certSendOff;
            if (n > chunk) n = chunk;
            if (msg != NULL) memcpy(s->hsBuf, &msg[s->certSendOff], n);
            else
            {
                /* The Certificate message is generated from the chain as it is cut */
                _SSFTLSCClientCertMsgCopy(s, s->certSendOff, s->hsBuf, n);
                SSFTLSTranscriptUpdate(&s->transcript, s->hsBuf, n);
            }
            s->certSendOff += (uint32_t)n;
        }
        r = _SSFTLSCSendEncRecordOnce(s, SSF_TLS_CT_HANDSHAKE, s->hsBuf, n);
        /* Is a staged Finished piece encrypted or failed, so it can be wiped? */
        if ((msg != NULL) && (r != SSF_TLS_IO_WANT_WRITE))
        {
            _SSF_TLSC_SCRUB_N("clientFlightPiece", s->hsBuf, chunk);
        }
        if (r != SSF_TLS_IO_SUCCESS) return r;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: builds and signs the client CertificateVerify message in out (RFC 8446 4.4.3)       */
/* --------------------------------------------------------------------------------------------- */
static SSF_NOINLINE bool _SSFTLSCSignClientCV(const SSFTLSCSession_t *s, uint16_t scheme,
                                              const uint8_t *th, size_t thLen, uint8_t *out,
                                              size_t outSize, size_t *outLen)
{
    static const char ctx[] = "TLS 1.3, client CertificateVerify";
    uint8_t content[64u + sizeof(ctx) + SSF_TLS_MAX_HASH_SIZE];
    uint8_t h[SSF_SHA2_384_BYTE_SIZE];
    size_t contentLen;
    const SSFPKey_t *k;
    uint8_t *sig;
    size_t sigSize;
    size_t sigLen = 0;
    bool ok = false;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(th != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(outLen != NULL);

    k = s->clientKey;
    contentLen = (64u + sizeof(ctx)) + thLen;
    if ((k == NULL) || (thLen > SSF_TLS_MAX_HASH_SIZE) || (outSize < 8u) ||
        (!_SSFTLSCSchemeCanSign(scheme, _SSFTLSCPKeyLeafType(k->type)))) return false;
    sig = &out[8];
    sigSize = outSize - 8u;
    memset(content, 0x20, 64);
    memcpy(&content[64], ctx, sizeof(ctx));                   /* Includes the 0x00 separator */
    memcpy(&content[64u + sizeof(ctx)], th, thLen);

    switch (scheme)
    {
    case SSF_TLS_SIG_ED25519:
        if (sigSize < SSF_ED25519_SIG_SIZE) return false;
        ok = SSFEd25519Sign(k->priv, k->pub, content, contentLen, sig);
        sigLen = SSF_ED25519_SIG_SIZE;
        break;
#if _SSF_TLSC_ECDSA_SIGN
    case SSF_TLS_SIG_ECDSA_SECP256R1_SHA256:
    case SSF_TLS_SIG_ECDSA_SECP384R1_SHA384:
    {
        bool p256 = (scheme == SSF_TLS_SIG_ECDSA_SECP256R1_SHA256);

        if (sigSize < SSF_ECDSA_MAX_SIG_SIZE) return false;
        if (p256) SSFSHA256(content, contentLen, h, sizeof(h));
        else SSFSHA384(content, contentLen, h, sizeof(h));
        ok = SSFECDSASign(p256 ? SSF_EC_CURVE_P256 : SSF_EC_CURVE_P384, k->priv, k->privLen, h,
                          p256 ? SSF_SHA2_256_BYTE_SIZE : SSF_SHA2_384_BYTE_SIZE, sig, sigSize,
                          &sigLen);
        break;
    }
#endif /* _SSF_TLSC_ECDSA_SIGN */
#if _SSF_TLSC_PSS
    case SSF_TLS_SIG_RSA_PSS_RSAE_SHA256:
    case SSF_TLS_SIG_RSA_PSS_RSAE_SHA384:
    {
        bool s256 = (scheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA256);

        if (sigSize < SSF_RSA_MAX_SIG_SIZE) return false;
        if (s256) SSFSHA256(content, contentLen, h, sizeof(h));
        else SSFSHA384(content, contentLen, h, sizeof(h));
        ok = SSFRSASignPSS(k->rsaDer, k->rsaDerLen,
                           s256 ? SSF_RSA_HASH_SHA256 : SSF_RSA_HASH_SHA384, h,
                           s256 ? SSF_SHA2_256_BYTE_SIZE : SSF_SHA2_384_BYTE_SIZE, sig, sigSize,
                           &sigLen);
        break;
    }
#endif /* _SSF_TLSC_PSS */
    default:
        return false;
    }
    if ((!ok) || (sigLen > 0xFFFFu)) return false;
    out[0] = SSF_TLS_HS_CERTIFICATE_VERIFY;
    _SSFTLSCPut24(&out[1], 4u + sigLen);
    _SSFTLSCPut16(&out[4], scheme);
    _SSFTLSCPut16(&out[6], (uint16_t)sigLen);
    *outLen = 8u + sigLen;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns the modulus and exponent of a PKCS#1 RSA public or private key.             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCRsaNE(const uint8_t *der, size_t derLen, bool priv, const uint8_t **n,
                          uint32_t *nLen, const uint8_t **e, uint32_t *eLen)
{
    SSFASN1Cursor_t cur;
    SSFASN1Cursor_t seq;
    SSFASN1Cursor_t next;
    uint64_t version;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(n != NULL);
    SSF_REQUIRE(nLen != NULL);
    SSF_REQUIRE(e != NULL);
    SSF_REQUIRE(eLen != NULL);

    if (derLen > 0xFFFFFFFFu) return false;
    cur.buf = der;
    cur.bufLen = (uint32_t)derLen;
    if (!SSFASN1DecOpenConstructed(&cur, SSF_ASN1_TAG_SEQUENCE, &seq, &next)) return false;
    if (priv && (!SSFASN1DecGetIntU64(&seq, &version, &seq))) return false;
    return (SSFASN1DecGetUInt(&seq, n, nLen, &seq) && SSFASN1DecGetUInt(&seq, e, eLen, &seq));
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: true if the leaf certificate's public key is key's; parsed certificate out of line  */
/* --------------------------------------------------------------------------------------------- */
static SSF_NOINLINE bool _SSFTLSCClientCertMatchesKey(const uint8_t *der, uint32_t derLen,
                                                      const SSFPKey_t *key)
{
    SSFX509Cert_t leaf;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(key != NULL);

    if (!SSFX509Parse(der, derLen, &leaf)) return false;
    if ((_SSFTLSCLeafKeyType(&leaf) != _SSFTLSCPKeyLeafType(key->type)) ||
        (leaf.pubKeyUnusedBits != 0u))
    {
        return false;
    }
    /* Is it an RSA key, compared by modulus and exponent? */
    if (key->type == SSF_PKEY_TYPE_RSA)
    {
        /* Yes */
        const uint8_t *n1;
        const uint8_t *e1;
        const uint8_t *n2;
        const uint8_t *e2;
        uint32_t n1Len;
        uint32_t e1Len;
        uint32_t n2Len;
        uint32_t e2Len;

        return _SSFTLSCRsaNE(leaf.pubKey, leaf.pubKeyLen, false, &n1, &n1Len, &e1, &e1Len) &&
               _SSFTLSCRsaNE(key->rsaDer, key->rsaDerLen, true, &n2, &n2Len, &e2, &e2Len) &&
               (n1Len == n2Len) && (memcmp(n1, n2, n1Len) == 0) &&
               (e1Len == e2Len) && (memcmp(e1, e2, e1Len) == 0);
    }
    /* No, compare the public key bytes */
    return (leaf.pubKeyLen == key->pubLen) && (memcmp(leaf.pubKey, key->pub, key->pubLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: true if scheme is in the scheme list algs[0..algsLen).                              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCSchemeInList(uint16_t scheme, const uint8_t *algs, size_t algsLen)
{
    size_t k;

    SSF_REQUIRE((algs != NULL) || (algsLen == 0u));

    for (k = 0; (k + 1u) < algsLen; k += 2u)
    {
        if (_SSFTLSCGet16(&algs[k]) == scheme) return true;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: true if cert's own signature by its issuer is one of the listed schemes.            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCCertSigInList(const SSFX509Cert_t *cert, const uint8_t *algs, size_t algsLen)
{
    SSF_REQUIRE(cert != NULL);

    /* The ECDSA curve is the issuer's, unknown here; RSA-PSS is either rsae or pss (4.2.3) */
    if (SSFX509IsSigECDSASHA256(cert))
    {
        return _SSFTLSCSchemeInList(SSF_TLS_SIG_ECDSA_SECP256R1_SHA256, algs, algsLen);
    }
    if (SSFX509IsSigECDSASHA384(cert))
    {
        return _SSFTLSCSchemeInList(SSF_TLS_SIG_ECDSA_SECP384R1_SHA384, algs, algsLen);
    }
    if (SSFX509IsSigEd25519(cert))
    {
        return _SSFTLSCSchemeInList(SSF_TLS_SIG_ED25519, algs, algsLen);
    }
    if (SSFX509IsSigRSAPKCS1SHA256(cert)) return _SSFTLSCSchemeInList(0x0401u, algs, algsLen);
    if (SSFX509IsSigRSAPKCS1SHA384(cert)) return _SSFTLSCSchemeInList(0x0501u, algs, algsLen);
    if (SSFX509IsSigRSAPKCS1SHA512(cert)) return _SSFTLSCSchemeInList(0x0601u, algs, algsLen);
    if (SSFX509IsSigRSAPSSSHA256(cert))
    {
        return _SSFTLSCSchemeInList(SSF_TLS_SIG_RSA_PSS_RSAE_SHA256, algs, algsLen) ||
               _SSFTLSCSchemeInList(0x0809u, algs, algsLen);
    }
    if (SSFX509IsSigRSAPSSSHA384(cert))
    {
        return _SSFTLSCSchemeInList(SSF_TLS_SIG_RSA_PSS_RSAE_SHA384, algs, algsLen) ||
               _SSFTLSCSchemeInList(0x080au, algs, algsLen);
    }
    return false;                                            /* Not a scheme the client knows */
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: true if each client chain certificate is signed with a scheme in algs (4.4.2.3)     */
/* --------------------------------------------------------------------------------------------- */
static SSF_NOINLINE bool _SSFTLSCClientChainAcceptable(SSFTLSCSession_t *s, const uint8_t *algs,
                                                       size_t algsLen, bool nowValid,
                                                       uint64_t now)
{
    SSFX509Cert_t cert;
    bool ok = true;
    uint8_t i;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE((s->clientChainDer != NULL) || (s->clientChainCount == 0u));
    SSF_REQUIRE((s->clientChainLens != NULL) || (s->clientChainCount == 0u));

    for (i = 0; i < s->clientChainCount; i++)
    {
        /* Does the certificate fail to parse? */
        if (!SSFX509Parse(s->clientChainDer[i], s->clientChainLens[i], &cert))
        {
            /* Yes, warn and carry on */
            _SSF_TLSC_CERT_WARN(&s->trace, "Client certificate %u does not parse", i);
            ok = false;
            continue;
        }
        /* Is it the leaf, whose likely server refusals are traced but never enforced? */
        if (i == 0u)
        {
            /* Yes */
            if (cert.hasKeyUsage && ((cert.keyUsageBits & SSF_X509_KU_DIGITAL_SIGNATURE) == 0u))
            {
                _SSF_TLSC_CERT_WARN(&s->trace, "Client certificate Key Usage lacks "
                                    "digitalSignature: the server may refuse it");
            }
            if (cert.hasExtKeyUsage && !cert.ekuClientAuth && !cert.ekuAnyPurpose)
            {
                _SSF_TLSC_CERT_WARN(&s->trace, "Client certificate Extended Key Usage lacks "
                                    "clientAuth: the server may refuse it");
            }
            if (nowValid && !SSFX509IsValid(&cert, now))
            {
                _SSF_TLSC_CERT_WARN(&s->trace, "Client certificate is not valid at the "
                                    "current time: the server may refuse it");
            }
        }
        /* Is it a self-signed last certificate, exempt as a trust anchor is (4.4.2.2)? */
        if (((i + 1u) == s->clientChainCount) && (cert.subject.rawLen == cert.issuer.rawLen) &&
            (memcmp(cert.subject.raw, cert.issuer.raw, cert.subject.rawLen) == 0)) continue;
        if (!_SSFTLSCCertSigInList(&cert, algs, algsLen)) ok = false;
    }
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: handles a CertificateRequest, choosing the client scheme, 0 for an empty one        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCChooseClientScheme(SSFTLSCSession_t *s, const uint8_t *body, size_t bodyLen,
                                       bool nowValid, uint64_t now, uint16_t *schemeOut,
                                       uint8_t *alertOut)
{
    const uint8_t *certAlgs;
    size_t certAlgsLen;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(body != NULL);
    SSF_REQUIRE(schemeOut != NULL);
    SSF_REQUIRE(alertOut != NULL);

    if (!_SSFTLSCParseCertificateRequest(body, bodyLen,
                                         (s->clientChainCount != 0u) ? s->clientKey->type :
                                         SSF_PKEY_TYPE_NONE, schemeOut, &certAlgs, &certAlgsLen,
                                         alertOut)) return false;
    /* Is the chain signed with algorithms the server does not accept? */
    if ((s->clientChainCount != 0u) &&
        (!_SSFTLSCClientChainAcceptable(s, certAlgs, certAlgsLen, nowValid, now)) &&
        (*schemeOut != 0u))
    {
        _SSF_TLSC_CERT_WARN(&s->trace, "Client certificate chain is signed with an algorithm "
                            "the server does not accept: sending an empty Certificate");
        *schemeOut = 0;
    }
    return true;
}

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
bool _SSFTLSCParseCertificateRequestForTest(const uint8_t *body, size_t bodyLen,
                                            uint8_t *alertOut)
{
    uint16_t scheme;
    const uint8_t *algs;
    size_t algsLen;

    return _SSFTLSCParseCertificateRequest(body, bodyLen, SSF_PKEY_TYPE_NONE, &scheme, &algs,
                                           &algsLen, alertOut);
}

bool _SSFTLSCChooseClientSchemeForTest(const uint8_t *body, size_t bodyLen, SSFPKeyType_t keyType,
                                       uint16_t *schemeOut, uint8_t *alertOut)
{
    const uint8_t *algs;
    size_t algsLen;

    return _SSFTLSCParseCertificateRequest(body, bodyLen, keyType, schemeOut, &algs, &algsLen,
                                           alertOut);
}

bool _SSFTLSCChooseClientSchemeChainForTest(SSFTLSCSession_t *session, const uint8_t *body,
                                            size_t bodyLen, bool nowValid, uint64_t nowUnixSec,
                                            uint16_t *schemeOut, uint8_t *alertOut)
{
    return _SSFTLSCChooseClientScheme(session, body, bodyLen, nowValid, nowUnixSec, schemeOut,
                                      alertOut);
}

size_t _SSFTLSCClientCertMsgLenForTest(const SSFTLSCSession_t *session)
{
    return _SSFTLSCClientCertMsgLen(session);
}

void _SSFTLSCClientCertMsgCopyForTest(const SSFTLSCSession_t *session, size_t off, uint8_t *dst,
                                      size_t dstSize)
{
    _SSFTLSCClientCertMsgCopy(session, off, dst, dstSize);
}

bool _SSFTLSCSignClientCVForTest(SSFTLSCSession_t *session, uint16_t scheme,
                                 const uint8_t *transcriptHash, size_t hashLen, uint8_t *msgOut,
                                 size_t msgSize, size_t *msgLenOut)
{
    return _SSFTLSCSignClientCV(session, scheme, transcriptHash, hashLen, msgOut, msgSize,
                                msgLenOut);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Internal: parses a server Certificate message body (RFC 8446 4.4.2)                           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCParseCertificate(const uint8_t *body, size_t bodyLen,
                                     const uint8_t **chainDerPtrs, uint32_t *chainDerLens,
                                     uint8_t *chainLenOut, uint8_t *seenOut, uint8_t *alertOut)
{
    size_t pos;
    size_t listEnd;
    uint8_t count = 0;
    uint8_t seen = 0;

    SSF_REQUIRE(body != NULL);
    SSF_REQUIRE(chainDerPtrs != NULL);
    SSF_REQUIRE(chainDerLens != NULL);
    SSF_REQUIRE(chainLenOut != NULL);
    SSF_REQUIRE(seenOut != NULL);
    SSF_REQUIRE(alertOut != NULL);

    *chainLenOut = 0;
    *seenOut = 0;
    *alertOut = SSF_TLS_ALERT_DECODE_ERROR;

    /* certificate_request_context is empty for server authentication (4.4.2) */
    if (bodyLen < (1u + 3u)) return false;
    if (body[0] != 0u) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
    pos = 1;

    /* certificate_list fills the message exactly; an empty one MUST be rejected (4.4.2.4) */
    listEnd = (pos + 3u) + ((size_t)_SSFTLSCGet24(&body[pos]));
    pos += 3;
    if ((listEnd != bodyLen) || (pos == listEnd)) return false;

    /* Validate every entry, keep the first SSF_X509_CONFIG_MAX_CHAIN_DEPTH; no wrap below */
    while (pos < listEnd)
    {
        uint32_t certLen;
        uint16_t extLen;

        /* cert_data<1..2^24-1> */
        if ((listEnd - pos) < 3u) return false;
        certLen = _SSFTLSCGet24(&body[pos]);
        pos += 3;
        if ((certLen == 0u) || (certLen > (listEnd - pos))) return false;
        /* Is there room to keep this certificate? */
        if (count < SSF_X509_CONFIG_MAX_CHAIN_DEPTH)
        {
            chainDerPtrs[count] = &body[pos];
            chainDerLens[count] = certLen;
            count++;
        }
        if (seen < 0xffu) seen++;
        pos += certLen;

        /* extensions: none are solicited, as status_request and SCT are never sent (4.4.2) */
        if ((listEnd - pos) < 2u) return false;
        extLen = _SSFTLSCGet16(&body[pos]);
        pos += 2;
        if (extLen > (listEnd - pos)) return false;
        if (extLen != 0u) { *alertOut = SSF_TLS_ALERT_UNSUPPORTED_EXT; return false; }
        pos += extLen;
    }

    *chainLenOut = count;
    *seenOut = seen;
    *alertOut = 0;
    return true;
}

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
bool _SSFTLSCParseCertificateForTest(const uint8_t *body, size_t bodyLen,
                                     const uint8_t **ders, uint32_t *lens, uint8_t *countOut)
{
    uint8_t alert;
    uint8_t seen;

    return _SSFTLSCParseCertificate(body, bodyLen, ders, lens, countOut, &seen, &alert);
}

bool _SSFTLSCParseCertificateSeenForTest(const uint8_t *body, size_t bodyLen,
                                         const uint8_t **ders, uint32_t *lens, uint8_t *countOut,
                                         uint8_t *seenOut)
{
    uint8_t alert;

    return _SSFTLSCParseCertificate(body, bodyLen, ders, lens, countOut, seenOut, &alert);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Internal: saves the leaf certificate's public key and key type; parsed certificate out of line */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static bool _SSFTLSCSaveLeafKey(SSFTLSCSession_t *session, const uint8_t *der, uint32_t derLen)
{
    SSFX509Cert_t leaf;

    SSF_REQUIRE(session != NULL);
    SSF_REQUIRE(der != NULL);

    if (!SSFX509Parse(der, derLen, &leaf))
    {
        SSF_TLS_TRACE_CERT_ERROR(&session->trace, "Failed to parse leaf certificate");
        return false;
    }
    /* Is the server's key larger than any supported? */
    if (leaf.pubKeyLen > sizeof(session->hsScratch.leafPubKey))
    {
        SSF_TLS_TRACE_CERT_ERROR(&session->trace, "Leaf public key too large");
        return false;
    }
    memcpy(session->hsScratch.leafPubKey, leaf.pubKey, leaf.pubKeyLen);
    session->hsScratchLen = leaf.pubKeyLen;
    session->leafKeyType = _SSFTLSCLeafKeyType(&leaf);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: RECV_EE_CERT state; receives EncryptedExtensions and Certificate, resumable         */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCHandleRecvEECert(SSFTLSCSession_t *session)
{
    const uint8_t *buf = NULL;
    size_t bodyLen;
    uint8_t hsType;
    SSFTLSIOResult_t r;

    SSF_REQUIRE(session != NULL);

    switch (session->helperStep)
    {
    case 0:
        SSF_TLS_TRACE_CRYPTO_INFO(&session->trace, "Handshake keys derived");
        /* Servers may bundle several handshake messages per record */
        session->hsBufLen = 0;
        session->hsBufPos = 0;
        session->helperStep = 1;
        /* fall through */
    case 1:
        /* Receive EncryptedExtensions */
        r = _SSFTLSCRecvHandshakeOnce(session, &buf, &bodyLen, &hsType, true);
        if (r != SSF_TLS_IO_SUCCESS) return r;
        if (hsType != SSF_TLS_HS_ENCRYPTED_EXTENSIONS)
        { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Expected EE, got type=%u", hsType);
          _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }
        SSF_TLS_TRACE_HS_DEBUG(&session->trace, "EncryptedExtensions received");
        {
            uint8_t alert;

            if (!_SSFTLSCParseEncryptedExtensions(&buf[4], bodyLen, &alert,
                                                  &session->peerRecordLimit, session->alpnProtos,
                                                  session->alpnCount, &session->alpnChosen))
            {
                SSF_TLS_TRACE_HS_ERROR(&session->trace, "EncryptedExtensions rejected");
                _SSF_TLSC_ALERT(session, alert);
                return SSF_TLS_IO_ERROR;
            }
            /* Did the server accept the record_size_limit? */
            if (session->peerRecordLimit != 0u)
            {
                /* Yes */
                SSF_TLS_TRACE_HS_DEBUG(&session->trace, "record_size_limit: server accepts %u",
                                       session->peerRecordLimit);
            }
            /* Was ALPN offered? */
            if (session->alpnCount != 0u)
            {
                /* Yes, trace the server's choice */
                SSF_TLS_TRACE_HS_DEBUG(&session->trace, "ALPN: %s",
                                       (session->alpnChosen != 0u) ?
                                       session->alpnProtos[session->alpnChosen - 1u] :
                                       "server chose none");
            }
        }
        session->helperStep = 2;
        /* fall through */
    case 2:
        /* Receive any CertificateRequest, then the Certificate */
        for (;;)
        {
            uint8_t alert;

            r = _SSFTLSCRecvHandshakeOnce(session, &buf, &bodyLen, &hsType, true);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            /* Is it other than a first CertificateRequest, answered after Finished (4.3.2)? */
            if ((hsType != SSF_TLS_HS_CERTIFICATE_REQUEST) || session->certRequested) break;
            {
                SSFPortTick_t unixSys = 0;
                uint64_t now = 0;
                bool nowValid = false;

                /* Are there a client chain and trust anchors, so the time is needed? */
                if ((session->clientChainCount != 0u) && (session->trust.count > 0u))
                {
                    /* Yes, read it for the client certificate's validity warning */
                    nowValid = SSFRTCGetUnixNow(&unixSys);
                    now = (uint64_t)(unixSys / SSF_TICKS_PER_SEC);
                    if (now < SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC) nowValid = false;
                }
                if (!_SSFTLSCChooseClientScheme(session, &buf[4], bodyLen, nowValid, now,
                                                &session->clientScheme, &alert))
                {
                    SSF_TLS_TRACE_HS_ERROR(&session->trace, "CertificateRequest rejected");
                    _SSF_TLSC_ALERT(session, alert);
                    return SSF_TLS_IO_ERROR;
                }
            }
            session->certRequested = true;
            /* Is a client certificate to be sent? */
            if (session->clientScheme != 0u)
            {
                /* Yes */
                SSF_TLS_TRACE_HS_INFO(&session->trace, "CertificateRequest received: sending the "
                                      "client certificate, scheme 0x%04x", session->clientScheme);
            }
            else
            {
                SSF_TLS_TRACE_HS_INFO(&session->trace, "CertificateRequest received: %s, "
                                      "answering with an empty Certificate",
                                      (session->clientChainCount != 0u) ?
                                      "the client certificate fits no scheme the server lists" :
                                      "no client certificate");
            }
        }
        if (hsType != SSF_TLS_HS_CERTIFICATE)
        { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Expected Certificate, got type=%u", hsType);
          _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }
        SSF_TLS_TRACE_HS_INFO(&session->trace, "Certificate received (%zu bytes)", bodyLen);

        /* Parse the chain, save the leaf key and set up chain verification; no further I/O */
        {
            SSFTLSCCryptoWork_t *w = &session->cryptoWork;
            uint8_t alert;

            /* Parse straight into the crypto step's chain */
            if (!_SSFTLSCParseCertificate(&buf[4], bodyLen, w->chainDerPtrs, w->chainDerLens,
                                          &w->chainLen, &w->chainSeen, &alert))
            {
                SSF_TLS_TRACE_CERT_ERROR(&session->trace, "Certificate message malformed");
                _SSF_TLSC_ALERT(session, alert);
                return SSF_TLS_IO_ERROR;
            }
            SSF_TLS_TRACE_CERT_INFO(&session->trace, "Certificate chain: %u of %u cert(s) kept",
                                    w->chainLen, w->chainSeen);

            if (!_SSFTLSCSaveLeafKey(session, w->chainDerPtrs[0], w->chainDerLens[0]))
            {
                _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_BAD_CERTIFICATE);
                return SSF_TLS_IO_ERROR;
            }

            /* Are there trust anchors to verify the chain against? */
            if (session->trust.count > 0)
            {
                /* Yes, chain verification needs the time, valid only at or past the floor */
                uint64_t now;
                SSFPortTick_t unixSys = 0;
                bool nowValid;

                nowValid = SSFRTCGetUnixNow(&unixSys);
                now = (uint64_t)(unixSys / SSF_TICKS_PER_SEC);
                if (now < SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC) nowValid = false;

                session->cryptoWork.session = session;
                session->cryptoWork.hostname = session->hsHostname;
                session->cryptoWork.nowUnixSec = now;
                session->cryptoWork.nowValid = nowValid;
            }
            else
            {
                /* No, unauthenticated by opt-in only */
                session->cryptoWork.chainVerifyOk = false;
            }
        }
        session->helperStep = 0;
        return SSF_TLS_IO_SUCCESS;
    default:
        return SSF_TLS_IO_ERROR;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: parses a CertificateVerify body (RFC 8446 4.4.3)                                    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCParseCertificateVerify(const uint8_t *body, size_t bodyLen,
                                           uint16_t *schemeOut, uint16_t *sigLenOut,
                                           uint8_t *alertOut)
{
    uint16_t scheme;
    uint16_t sigLen;

    SSF_REQUIRE(body != NULL);
    SSF_REQUIRE(schemeOut != NULL);
    SSF_REQUIRE(sigLenOut != NULL);
    SSF_REQUIRE(alertOut != NULL);

    *schemeOut = 0;
    *sigLenOut = 0;

    /* The scheme and a non-empty signature, exactly filling the message */
    *alertOut = SSF_TLS_ALERT_DECODE_ERROR;
    if (bodyLen < 4) return false;
    scheme = _SSFTLSCGet16(&body[0]);
    sigLen = _SSFTLSCGet16(&body[2]);
    if ((sigLen == 0u) || ((4u + ((size_t)sigLen)) != bodyLen)) return false;
    *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER;

    /* Only offered handshake schemes; never rsa_pkcs1_* in CertificateVerify (4.2.3) */
    switch (scheme)
    {
    case SSF_TLS_SIG_ED25519:
    case SSF_TLS_SIG_ECDSA_SECP256R1_SHA256:
    case SSF_TLS_SIG_RSA_PSS_RSAE_SHA256:
    case SSF_TLS_SIG_ECDSA_SECP384R1_SHA384:
    case SSF_TLS_SIG_RSA_PSS_RSAE_SHA384:
        break;
    default:
        return false;
    }
    *schemeOut = scheme;
    *sigLenOut = sigLen;
    *alertOut = 0;
    return true;
}

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
bool _SSFTLSCParseCertificateVerifyForTest(const uint8_t *body, size_t bodyLen,
                                           uint16_t *schemeOut, uint16_t *sigLenOut)
{
    uint8_t alert;

    return _SSFTLSCParseCertificateVerify(body, bodyLen, schemeOut, sigLenOut, &alert);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Internal: RECV_CV state; receives the server CertificateVerify, resumable                     */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCHandleRecvCV(SSFTLSCSession_t *session)
{
    const uint8_t *buf = NULL;
    size_t bodyLen;
    uint8_t hsType;
    uint8_t cvTranscriptHash[SSF_TLS_MAX_HASH_SIZE];
    SSFTLSIOResult_t r;

    SSF_REQUIRE(session != NULL);

    switch (session->helperStep)
    {
    case 0:
        SSF_TLS_TRACE_CERT_INFO(&session->trace, "Certificate chain verified");
        session->helperStep = 1;
        /* fall through */
    case 1:
        /* Snapshot the transcript before CertificateVerify; idempotent while it is unchanged */
        SSFTLSTranscriptHash(&session->transcript, cvTranscriptHash, sizeof(cvTranscriptHash));
        SSF_TLS_TRACE_CRYPTO_DEBUG(&session->trace, "CV transcript hash (len=%u)",
                                   session->hashLen);

        r = _SSFTLSCRecvHandshakeOnce(session, &buf, &bodyLen, &hsType, true);
        if (r != SSF_TLS_IO_SUCCESS) return r;
        if (hsType != SSF_TLS_HS_CERTIFICATE_VERIFY)
        { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Expected CertVerify, got type=%u", hsType);
          _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }

        /* Parse and set up the VERIFY_SIG step; no further I/O */
        {
            const uint8_t *cvBody = &buf[4];
            uint16_t sigScheme;
            uint16_t sigDataLen;
            uint8_t signContent[64 + 33 + 1 + SSF_TLS_MAX_HASH_SIZE];
            size_t signContentLen = ((64u + 33u) + 1u) + session->hashLen;
            uint8_t contentHash[SSF_TLS_MAX_HASH_SIZE];
            const uint8_t *leafPubKey = session->hsScratch.leafPubKey;
            size_t leafPubKeyLen = session->hsScratchLen;
            bool isEd25519;
            size_t sigHashLen = 0;

            uint8_t alert;

            if (!_SSFTLSCParseCertificateVerify(cvBody, bodyLen, &sigScheme, &sigDataLen,
                                                &alert))
            { SSF_TLS_TRACE_CRYPTO_ERROR(&session->trace, "CertificateVerify rejected");
              _SSF_TLSC_ALERT(session, alert); return SSF_TLS_IO_ERROR; }
            if (!_SSFTLSCSchemeMatchesKey(sigScheme, session->leafKeyType))
            {
                SSF_TLS_TRACE_CRYPTO_ERROR(&session->trace,
                                           "CertificateVerify scheme 0x%04x does not fit the "
                                           "leaf key", sigScheme);
                _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
                return SSF_TLS_IO_ERROR;
            }

            SSF_TLS_TRACE_CRYPTO_INFO(&session->trace,
                                      "CertificateVerify: scheme=0x%04x sigLen=%u",
                                      sigScheme, sigDataLen);

            memset(signContent, 0x20, 64);
            memcpy(&signContent[64], "TLS 1.3, server CertificateVerify", 33);
            signContent[97] = 0x00;
            memcpy(&signContent[98], cvTranscriptHash, session->hashLen);

            SSF_TLS_TRACE_CRYPTO_DEBUG(&session->trace, "CV verify: scheme=0x%04x pubKeyLen=%zu",
                                       sigScheme, leafPubKeyLen);

            /* The content embeds the suite's transcript hash; the scheme's own hash then signs */
            isEd25519 = (sigScheme == SSF_TLS_SIG_ED25519);
            /* Is the scheme Ed25519? */
            if (isEd25519)
            {
                /* Yes, no pre-hash */
            }
            else if ((sigScheme == SSF_TLS_SIG_ECDSA_SECP256R1_SHA256) ||
                     (sigScheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA256))
            {
                /* No, a SHA-256 scheme */
                SSFSHA256(signContent, (uint32_t)signContentLen, contentHash, sizeof(contentHash));
                sigHashLen = 32u;
            }
            else if ((sigScheme == SSF_TLS_SIG_ECDSA_SECP384R1_SHA384) ||
                     (sigScheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA384))
            {
                /* No, a SHA-384 scheme */
                SSFSHA384(signContent, (uint32_t)signContentLen, contentHash, sizeof(contentHash));
                sigHashLen = 48u;
            }
            else
            {
                /* No, unsupported */
                SSF_TLS_TRACE_CRYPTO_ERROR(&session->trace,
                                           "Unsupported CV signature scheme 0x%04x", sigScheme);
                _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
                return SSF_TLS_IO_ERROR;
            }

            /* sigData points into hsBuf, which holds the message until the VERIFY_SIG step */
            {
                session->cryptoWork.session = session;
                session->cryptoWork.sigScheme = sigScheme;
                /* Is the scheme Ed25519, verified over the raw content? */
                if (isEd25519)
                {
                    /* Yes, store the content itself */
                    if (signContentLen > sizeof(session->cryptoWork.contentHash))
                    {
                        return SSF_TLS_IO_ERROR;
                    }
                    memcpy(session->cryptoWork.contentHash, signContent, signContentLen);
                    session->cryptoWork.contentHashLen = signContentLen;
                }
                else
                {
                    /* No, store the content's hash */
                    memcpy(session->cryptoWork.contentHash, contentHash, sigHashLen);
                    session->cryptoWork.contentHashLen = sigHashLen;
                }
                session->cryptoWork.sigData = &cvBody[4];
                session->cryptoWork.sigDataLen = (uint32_t)sigDataLen;
                session->cryptoWork.leafPubKey = leafPubKey;
                session->cryptoWork.leafPubKeyLen = (uint32_t)leafPubKeyLen;
            }
        }
        session->helperStep = 0;
        return SSF_TLS_IO_SUCCESS;
    default:
        return SSF_TLS_IO_ERROR;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: writes the client Finished over the transcript so far to out, returns its length    */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFTLSCBuildClientFinished(SSFTLSCSession_t *s, uint8_t *out)
{
    uint8_t verifyData[SSF_TLS_MAX_HASH_SIZE];
    uint8_t thash[SSF_TLS_MAX_HASH_SIZE];

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(out != NULL);

    SSFTLSTranscriptHash(&s->transcript, thash, sizeof(thash));
    SSFTLSComputeFinished(s->hash, s->clientHsTrafficSecret, s->hashLen,
                          thash, s->hashLen, verifyData, s->hashLen);
    out[0] = SSF_TLS_HS_FINISHED;
    _SSFTLSCPut24(&out[1], s->hashLen);
    memcpy(&out[4], verifyData, s->hashLen);
    _SSF_TLSC_SCRUB(verifyData);
    return (4u + ((size_t)s->hashLen));
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: switches sending to the client application traffic keys after the client Finished  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCEnterAppSendKeys(SSFTLSCSession_t *s)
{
    uint8_t key[SSF_TLS_MAX_KEY_SIZE];
    uint8_t iv[SSF_TLS_IV_SIZE];

    SSF_REQUIRE(s != NULL);

    SSFTLSDeriveTrafficKeys(s->hash, s->clientAppTrafficSecret, s->hashLen,
                            key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    _SSFTLSCRecordStateSet(s, &s->sendState, &s->sendStateInited, key, iv);
    _SSF_TLSC_SCRUB(key);
    _SSF_TLSC_SCRUB(iv);
    /* Handshake traffic secrets are spent; application secrets stay for KeyUpdate */
    _SSF_TLSC_SCRUB_N("clientHsTrafficSecret", s->clientHsTrafficSecret,
                      sizeof(s->clientHsTrafficSecret));
    _SSF_TLSC_SCRUB_N("serverHsTrafficSecret", s->serverHsTrafficSecret,
                      sizeof(s->serverHsTrafficSecret));
    SSF_TLS_TRACE_HS_INFO(&s->trace, "Handshake complete, connected (suite=0x%04x)",
                          s->cipherSuite);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: SIGN_CV crypto step; signs the CertificateVerify and appends the client Finished    */
/* --------------------------------------------------------------------------------------------- */
static SSF_NOINLINE bool _SSFTLSCSignCVStep(SSFTLSCSession_t *s)
{
    uint8_t thash[SSF_TLS_MAX_HASH_SIZE];
    size_t cvLen;

    SSF_REQUIRE(s != NULL);

    SSFTLSTranscriptHash(&s->transcript, thash, sizeof(thash));
    if (!_SSFTLSCSignClientCV(s, s->clientScheme, thash, s->hashLen, s->hsScratch.clientFlight,
                              sizeof(s->hsScratch.clientFlight) - (4u + SSF_TLS_MAX_HASH_SIZE),
                              &cvLen))
    {
        SSF_TLS_TRACE_CRYPTO_ERROR(&s->trace, "Client CertificateVerify signing failed");
        return false;
    }
    SSFTLSTranscriptUpdate(&s->transcript, s->hsScratch.clientFlight, cvLen);
    s->hsScratchLen = cvLen + _SSFTLSCBuildClientFinished(s, &s->hsScratch.clientFlight[cvLen]);
    SSF_TLS_TRACE_CRYPTO_INFO(&s->trace, "Client CertificateVerify signed (scheme 0x%04x)",
                              s->clientScheme);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: RECV_FIN_SEND_FIN state; verifies the server Finished, sends the client's; resumable */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCHandleRecvFinSendFin(SSFTLSCSession_t *session)
{
    const uint8_t *buf = NULL;
    size_t bodyLen;
    uint8_t hsType;
    uint8_t handshakeSecret[SSF_TLS_MAX_HASH_SIZE];
    /* [empty Certificate] Finished, the client's last flight sent as one record */
    uint8_t finishedMsg[SSF_TLSC_EMPTY_CERT_LEN + 4 + SSF_TLS_MAX_HASH_SIZE];
    size_t certLen;
    uint8_t finTranscriptHash[SSF_TLS_MAX_HASH_SIZE];
    uint8_t expectedVerifyData[SSF_TLS_MAX_HASH_SIZE];
    bool isFinishedOk;
    SSFTLSIOResult_t r;

    SSF_REQUIRE(session != NULL);

    switch (session->helperStep)
    {
    case 0:
        SSF_TLS_TRACE_CRYPTO_INFO(&session->trace, "CertificateVerify signature verified");
        session->helperStep = 1;
        /* fall through */
    case 1:
        /* Receive the server Finished; verify_data excludes it, so snapshot first (4.4.4) */
        SSFTLSTranscriptHash(&session->transcript, finTranscriptHash, sizeof(finTranscriptHash));
        r = _SSFTLSCRecvHandshakeOnce(session, &buf, &bodyLen, &hsType, true);
        if (r != SSF_TLS_IO_SUCCESS) return r;
        if (hsType != SSF_TLS_HS_FINISHED)
        { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Expected Finished, got type=%u", hsType);
          _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }
        /* Bytes after Finished would be under the wrong keys */
        if (!_SSFTLSCHandshakeAtRecordEnd(session, "Server Finished")) return SSF_TLS_IO_ERROR;
        SSF_TLS_TRACE_HS_DEBUG(&session->trace, "Server Finished received");
#if SSF_CONFIG_TLSC_UNIT_TEST == 1
        /* Is a corrupted server Finished being simulated? */
        if (_ssfTLSCUTCorruptServerFinished && (bodyLen > 0)) ((uint8_t *)buf)[4] ^= 0x01u;
#endif

        /* Compare verify_data in constant time; any mismatch terminates (RFC 8446 4.4.4) */
        SSFTLSComputeFinished(session->hash, session->serverHsTrafficSecret, session->hashLen,
                              finTranscriptHash, session->hashLen,
                              expectedVerifyData, session->hashLen);
        isFinishedOk = ((bodyLen == (size_t)session->hashLen) &&
                        SSFCryptCTMemEq(expectedVerifyData, &buf[4], session->hashLen));
        SSFCryptSecureZero(expectedVerifyData, sizeof(expectedVerifyData));
        /* Is the server Finished wrong? */
        if (!isFinishedOk)
        {
            SSF_TLS_TRACE_HS_ERROR(&session->trace, "Server Finished verify_data mismatch");
            _SSF_TLSC_ALERT(session, (bodyLen == (size_t)session->hashLen) ?
                            SSF_TLS_ALERT_DECRYPT_ERROR : SSF_TLS_ALERT_DECODE_ERROR);
            return SSF_TLS_IO_ERROR;
        }

        /* Derive the application traffic keys */
        memcpy(handshakeSecret, session->savedHandshakeSecret, session->hashLen);

        SSF_TLS_TRACE_CRYPTO_INFO(&session->trace, "Deriving application keys");
        isFinishedOk = _SSFTLSCDeriveAppKeys(session, handshakeSecret);
        /* The handshake secret is spent once the master secret is derived */
        _SSF_TLSC_SCRUB(handshakeSecret);
        _SSF_TLSC_SCRUB_N("savedHandshakeSecret", session->savedHandshakeSecret,
                          sizeof(session->savedHandshakeSecret));
        if (!isFinishedOk)
        { SSF_TLS_TRACE_CRYPTO_ERROR(&session->trace, "DeriveAppKeys failed");
          return SSF_TLS_IO_ERROR; }

        /* Is there client authentication, sent by the SEND_CLIENT_CERT..SEND_CV_FIN states? */
        if (session->clientScheme != 0u)
        {
            /* Yes */
            session->helperStep = 0;
            return SSF_TLS_IO_SUCCESS;
        }

        /* No, an empty Certificate, covered by Finished, answers a request (4.4.2, 4.4.4) */
        certLen = session->certRequested ? SSF_TLSC_EMPTY_CERT_LEN : 0u;
        /* Was a certificate requested? */
        if (certLen != 0u)
        {
            /* Yes, build the empty Certificate */
            memset(finishedMsg, 0, SSF_TLSC_EMPTY_CERT_LEN);
            finishedMsg[0] = SSF_TLS_HS_CERTIFICATE;
            _SSFTLSCPut24(&finishedMsg[1], SSF_TLSC_EMPTY_CERT_LEN - 4u);
            SSFTLSTranscriptUpdate(&session->transcript, finishedMsg, SSF_TLSC_EMPTY_CERT_LEN);
        }
        /* The client handshake send keys are already installed */
        (void)_SSFTLSCBuildClientFinished(session, &finishedMsg[certLen]);
        session->helperStep = 2;
        /* fall through */
    case 2:
        /* Send the client Finished; a resumed call sends the record already encrypted */
        certLen = session->certRequested ? SSF_TLSC_EMPTY_CERT_LEN : 0u;
        r = _SSFTLSCSendEncRecordOnce(session, SSF_TLS_CT_HANDSHAKE,
                                      finishedMsg, certLen + 4u + session->hashLen);
        _SSF_TLSC_SCRUB(finishedMsg);
        if (r != SSF_TLS_IO_SUCCESS) return r;
        _SSFTLSCEnterAppSendKeys(session);
        session->helperStep = 0;
        return SSF_TLS_IO_SUCCESS;
    default:
        return SSF_TLS_IO_ERROR;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Session lifecycle and the SSFNetTransport_t operations                                        */
/* --------------------------------------------------------------------------------------------- */
#define SSF_TLSC_MAGIC               (0x544c5343ul)   /* 'TLSC' */
#define SSF_TLSC_RECV_MAX_RECORDS    (4u)   /* Non-application records consumed per recv() call */

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns the session that owns transport t, its first member                         */
/* --------------------------------------------------------------------------------------------- */
typedef char _SSFTLSCTransportFirst_t[(offsetof(SSFTLSCSession_t, transport) == 0u) ? 1 : -1];

static SSFTLSCSession_t *_SSFTLSCSelf(SSFNetTransport_t *t)
{
    SSFTLSCSession_t *s;

    SSF_REQUIRE(t != NULL);
    s = (SSFTLSCSession_t *)(void *)t;
    SSF_REQUIRE(s->magic == SSF_TLSC_MAGIC);
    return s;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: wipes all per-connection state, keys included, and returns the session to IDLE      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCReset(SSFTLSCSession_t *s)
{
    SSFNetTransport_t transport;
    SSFNetTransport_t *inner;
    SSFTLSCTrustStore_t trust;
    SSFTLSTraceCtx_t trace;
    bool allowUnauthenticated;
    const uint8_t *const *clientChainDer;
    const uint32_t *clientChainLens;
    const SSFPKey_t *clientKey;
    uint8_t clientChainCount;
    const char *const *alpnProtos;
    uint8_t alpnCount;
    uint32_t magic;

    SSF_REQUIRE(s != NULL);

    /* Keep the configuration across the wipe */
    transport = s->transport;
    inner = s->inner;
    trust = s->trust;
    trace = s->trace;
    allowUnauthenticated = s->allowUnauthenticated;
    clientChainDer = s->clientChainDer;
    clientChainLens = s->clientChainLens;
    clientKey = s->clientKey;
    clientChainCount = s->clientChainCount;
    alpnProtos = s->alpnProtos;
    alpnCount = s->alpnCount;
    magic = s->magic;

    if (s->sendStateInited) SSFTLSRecordStateDeInit(&s->sendState);
    if (s->recvStateInited) SSFTLSRecordStateDeInit(&s->recvState);
    SSFCryptSecureZero(s, sizeof(*s));

    s->transport = transport;
    s->inner = inner;
    s->trust = trust;
    s->trace = trace;
    s->allowUnauthenticated = allowUnauthenticated;
    s->clientChainDer = clientChainDer;
    s->clientChainLens = clientChainLens;
    s->clientKey = clientKey;
    s->clientChainCount = clientChainCount;
    s->alpnProtos = alpnProtos;
    s->alpnCount = alpnCount;
    s->magic = magic;
    s->hsState = SSF_TLSC_HS_IDLE;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: wipes every secret and plaintext buffer and de-initializes the record states        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCWipeKeys(SSFTLSCSession_t *s)
{
    SSF_REQUIRE(s != NULL);

    if (s->sendStateInited) SSFTLSRecordStateDeInit(&s->sendState);
    if (s->recvStateInited) SSFTLSRecordStateDeInit(&s->recvState);
    s->sendStateInited = false;
    s->recvStateInited = false;
    s->sendEncrypted = false;
    s->recvEncrypted = false;
    _SSF_TLSC_SCRUB_N("ephemeralPrivKey", s->ephemeralPrivKey, sizeof(s->ephemeralPrivKey));
    _SSF_TLSC_SCRUB_N("savedHandshakeSecret", s->savedHandshakeSecret,
                      sizeof(s->savedHandshakeSecret));
    _SSF_TLSC_SCRUB_N("clientHsTrafficSecret", s->clientHsTrafficSecret,
                      sizeof(s->clientHsTrafficSecret));
    _SSF_TLSC_SCRUB_N("serverHsTrafficSecret", s->serverHsTrafficSecret,
                      sizeof(s->serverHsTrafficSecret));
    _SSF_TLSC_SCRUB_N("clientAppTrafficSecret", s->clientAppTrafficSecret,
                      sizeof(s->clientAppTrafficSecret));
    _SSF_TLSC_SCRUB_N("serverAppTrafficSecret", s->serverAppTrafficSecret,
                      sizeof(s->serverAppTrafficSecret));
    _SSF_TLSC_SCRUB_N("hsBuf", s->hsBuf, sizeof(s->hsBuf));
    _SSF_TLSC_SCRUB_N("ioCtx", &s->ioCtx, sizeof(s->ioCtx));
    _SSF_TLSC_SCRUB_N("cryptoWork", &s->cryptoWork, sizeof(s->cryptoWork));
    s->hsBufLen = 0;
    s->hsBufPos = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: makes one best-effort attempt to send an alert, protected once send keys exist      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCSendAlert(SSFTLSCSession_t *s, uint8_t level, uint8_t desc)
{
    uint8_t alert[2];

    SSF_REQUIRE(s != NULL);

    /* Has the transport failed? */
    if ((s->innerOpen == false) || s->ioFailed) return;
    /* Is a partly written record still pending? */
    if (_SSFTLSCSendPending(s) != SSF_TLS_IO_SUCCESS) return;
    alert[0] = level;
    alert[1] = desc;
    SSF_TLS_TRACE_ALERT(&s->trace, "Sending alert level=%u desc=%u", level, desc);
    /* Are send keys installed? */
    if (s->sendEncrypted)
    {
        /* Yes, send it protected */
        (void)_SSFTLSCSendEncRecordOnce(s, SSF_TLS_CT_ALERT, alert, sizeof(alert));
    }
    else
    {
        /* No, send it in plaintext */
        (void)_SSFTLSCSendPlainRecordOnce(s, SSF_TLS_CT_ALERT, alert, sizeof(alert));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: ends a failed connection; returns CLOSED if the peer closed, else ERROR             */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCFail(SSFTLSCSession_t *s)
{
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(s->inner != NULL);

    /* Has our own close_notify gone out, after which nothing follows (RFC 8446 6.1)? */
    if (s->closeNotifySent) { /* Silent */ }
    else if (s->peerCloseNotify)
    {
        /* No, answer close_notify with close_notify */
        _SSFTLSCSendAlert(s, 1u, SSF_TLS_ALERT_CLOSE_NOTIFY);
    }
    else if (s->peerAlerted == false)
    {
        /* No, announce the abort with the first failure's fatal alert (RFC 8446 6) */
        _SSFTLSCSendAlert(s, 2u, (s->pendingAlert != 0u) ? s->pendingAlert :
                                                           SSF_TLS_ALERT_INTERNAL_ERROR);
    }
    else { /* Silent after a peer alert */ }
    /* Wipe at once, not at close(): the connection is dead */
    _SSFTLSCWipeKeys(s);
    if (s->innerOpen) s->inner->close(s->inner);
    s->innerOpen = false;
    s->connected = false;
    s->hsState = SSF_TLSC_HS_ERROR;
    s->helperStep = 0;
    return s->peerClosed ? SSF_NET_IO_CLOSED : SSF_NET_IO_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: advances the handshake, running at most one public-key step per call               */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCDrive(SSFTLSCSession_t *s)
{
    SSFTLSIOResult_t r;

    SSF_REQUIRE(s != NULL);

    for (;;)
    {
        switch (s->hsState)
        {
        case SSF_TLSC_HS_COMPLETE:
            return SSF_NET_IO_SUCCESS;

        case SSF_TLSC_HS_ERROR:
            return s->peerClosed ? SSF_NET_IO_CLOSED : SSF_NET_IO_ERROR;

        case SSF_TLSC_HS_SEND_CH:
        case SSF_TLSC_HS_RECV_SH:
            r = _SSFTLSCHandleSendCH(s);
            if (r == SSF_TLS_IO_WANT_READ) return SSF_NET_IO_WANT_READ;
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            s->helperStep = 0;
            s->hsState = SSF_TLSC_HS_DERIVE_HS_KEYS;
            break;

        case SSF_TLSC_HS_DERIVE_HS_KEYS:
            s->cryptoWork.session = s;
            _SSFTLSCDeriveHSKeysWork(&s->cryptoWork);
            /* Is the server's key share unusable? */
            if (!s->cryptoWork.keyExchangeOk)
            {
                SSF_TLS_TRACE_CRYPTO_ERROR(&s->trace, "DeriveHandshakeKeys failed");
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
                return _SSFTLSCFail(s);
            }
            s->hsState = SSF_TLSC_HS_RECV_EE_CERT;
            return SSF_NET_IO_WANT_READ;

        case SSF_TLSC_HS_RECV_EE_CERT:
            r = _SSFTLSCHandleRecvEECert(s);
            if (r == SSF_TLS_IO_WANT_READ) return SSF_NET_IO_WANT_READ;
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            s->helperStep = 0;
            s->hsState = SSF_TLSC_HS_VERIFY_CHAIN;
            break;

        case SSF_TLSC_HS_VERIFY_CHAIN:
            /* Are there no trust anchors? */
            if (s->trust.count == 0u)
            {
                /* Yes, open() refused this without the opt-in; check again, never skip silently */
#if SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED == 1
                if (s->allowUnauthenticated == false) return _SSFTLSCFail(s);
                SSF_TLS_TRACE_CERT_ERROR(&s->trace, "Server NOT authenticated: no trust anchors, "
                                         "unauthenticated mode");
#else
                return _SSFTLSCFail(s);
#endif
            }
            else if (s->cryptoWork.nowValid == false)
            {
                /* No, but without a trusted time validity cannot be checked */
                SSF_TLS_TRACE_CERT_ERROR(&s->trace,
                                         "No trusted time (RTC unreadable or before "
                                         "SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC): cannot "
                                         "check certificate validity");
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_INTERNAL_ERROR);
                return _SSFTLSCFail(s);
            }
            else
            {
                /* No, verify the chain */
                _SSFTLSCVerifyChainWork(&s->cryptoWork);
                /* Did verification fail? */
                if (!s->cryptoWork.chainVerifyOk)
                {
                    /* Yes, explain the refusals a self-made certificate most often meets */
                    SSF_TLS_TRACE_CERT_ERROR(&s->trace, "Certificate chain verification failed: "
                                             "code %d, cert[%u]%s",
                                             (int)s->cryptoWork.chainVerifyErr.code,
                                             s->cryptoWork.chainVerifyErr.certIdx,
                                             (s->cryptoWork.chainVerifyErr.code ==
                                              SSF_X509_VERIFY_ERR_VERSION) ?
                                             " (an X.509 v1 or v2 certificate: v3 with a "
                                             "subjectAltName for the host is required)" :
                                             (s->cryptoWork.chainVerifyErr.code ==
                                              SSF_X509_VERIFY_ERR_HOSTNAME) ?
                                             " (no subjectAltName names the host; the Common "
                                             "Name is not used)" : "");
                    /* Was the chain cut at the configured depth? */
                    if (s->cryptoWork.chainSeen > s->cryptoWork.chainLen)
                    {
                        /* Yes */
                        SSF_TLS_TRACE_CERT_ERROR(&s->trace, "Certificate chain truncated: %u of "
                                                 "%u certs kept "
                                                 "(SSF_X509_CONFIG_MAX_CHAIN_DEPTH)",
                                                 s->cryptoWork.chainLen, s->cryptoWork.chainSeen);
                    }
                    _SSF_TLSC_ALERT(s, _SSFTLSCChainAlert(s->cryptoWork.chainVerifyErr.code));
                    return _SSFTLSCFail(s);
                }
            }
            s->hsState = SSF_TLSC_HS_RECV_CV;
            return SSF_NET_IO_WANT_READ;

        case SSF_TLSC_HS_RECV_CV:
            r = _SSFTLSCHandleRecvCV(s);
            if (r == SSF_TLS_IO_WANT_READ) return SSF_NET_IO_WANT_READ;
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            s->helperStep = 0;
            s->hsState = SSF_TLSC_HS_VERIFY_SIG;
            break;

        case SSF_TLSC_HS_VERIFY_SIG:
            _SSFTLSCVerifySigWork(&s->cryptoWork);
            /* Is the CertificateVerify signature invalid (4.4.3)? */
            if (!s->cryptoWork.sigVerifyOk)
            {
                SSF_TLS_TRACE_CRYPTO_ERROR(&s->trace, "CertificateVerify signature INVALID");
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_DECRYPT_ERROR);
                return _SSFTLSCFail(s);
            }
            s->hsState = SSF_TLSC_HS_RECV_FIN_SEND_FIN;
            return SSF_NET_IO_WANT_READ;

        case SSF_TLSC_HS_RECV_FIN_SEND_FIN:
            r = _SSFTLSCHandleRecvFinSendFin(s);
            if (r == SSF_TLS_IO_WANT_READ) return SSF_NET_IO_WANT_READ;
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            s->helperStep = 0;
            /* Is there client authentication? */
            if (s->clientScheme != 0u)
            {
                /* Yes, send the client flight */
                s->certSendOff = 0;
                s->hsState = SSF_TLSC_HS_SEND_CLIENT_CERT;
                break;
            }
            /* No, hsBuf now holds application data */
            s->hsBufLen = 0;
            s->hsBufPos = 0;
            s->connected = true;
            s->hsState = SSF_TLSC_HS_COMPLETE;
            return SSF_NET_IO_SUCCESS;

        case SSF_TLSC_HS_SEND_CLIENT_CERT:
            r = _SSFTLSCSendHandshakeOnce(s, NULL, _SSFTLSCClientCertMsgLen(s));
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            s->hsState = SSF_TLSC_HS_SIGN_CV;
            break;

        case SSF_TLSC_HS_SIGN_CV:
            if (!_SSFTLSCSignCVStep(s))
            {
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_INTERNAL_ERROR);
                return _SSFTLSCFail(s);
            }
            s->certSendOff = 0;
            s->hsState = SSF_TLSC_HS_SEND_CV_FIN;
            return SSF_NET_IO_WANT_WRITE;      /* The signature was this call's step */

        case SSF_TLSC_HS_SEND_CV_FIN:
            r = _SSFTLSCSendHandshakeOnce(s, s->hsScratch.clientFlight, s->hsScratchLen);
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            /* The Finished is now encrypted in sendRecordBuf, or the connection is failing */
            _SSF_TLSC_SCRUB_N("clientFlight", s->hsScratch.clientFlight,
                              sizeof(s->hsScratch.clientFlight));
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            _SSFTLSCEnterAppSendKeys(s);
            s->hsBufLen = 0;
            s->hsBufPos = 0;
            s->connected = true;
            s->hsState = SSF_TLSC_HS_COMPLETE;
            return SSF_NET_IO_SUCCESS;

        default:
            /* IDLE: not opened */
            return SSF_NET_IO_ERROR;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns the largest content sent in one protected record (RFC 8449 4)               */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFTLSCSendRecordMax(const SSFTLSCSession_t *s)
{
    size_t max = SSF_TLSC_CONFIG_MAX_SEND_RECORD;

    SSF_REQUIRE(s != NULL);

    /* Does the server's record_size_limit leave less room, minus the content type byte? */
    if ((s->peerRecordLimit != 0u) && ((((size_t)s->peerRecordLimit) - 1u) < max))
    { max = ((size_t)s->peerRecordLimit) - 1u; }
    return max;
}

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
SSFTLSIOResult_t _SSFTLSCSendHandshakeForTest(SSFTLSCSession_t *session, const uint8_t *msg,
                                              size_t msgLen)
{
    return _SSFTLSCSendHandshakeOnce(session, msg, msgLen);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the inner connection to hostStr:port was started and the handshake armed.     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCOpen(SSFNetTransport_t *t, SSFCStrIn_t hostStr, size_t hostSize,
                         uint16_t port)
{
    SSFTLSCSession_t *s;
    size_t hostLen;

    SSF_REQUIRE(hostStr != NULL);
    SSF_REQUIRE(hostSize > 0);
    s = _SSFTLSCSelf(t);
    SSF_REQUIRE(s->hsState == SSF_TLSC_HS_IDLE);

    if ((SSFStrLen(hostStr, hostSize, &hostLen) == false) || (hostLen == 0)) return false;
    if (hostLen >= SSF_TLSC_MAX_HOST_SIZE) return false;
    if (port == 0) return false;
    /* Is it an IPv6 literal, which could never be verified on IPv4-only SSF? */
    if (memchr(hostStr, ':', hostLen) != NULL)
    {
        SSF_TLS_TRACE_HS_ERROR(&s->trace, "IPv6 host '%s' refused: SSF is IPv4 only", hostStr);
        return false;
    }

    /* Fail closed: without trust anchors do not connect at all unless the caller opted in */
#if SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED == 1
    /* Are there no trust anchors and no opt-in? */
    if ((s->trust.count == 0u) && (s->allowUnauthenticated == false))
    {
        SSF_TLS_TRACE_CERT_ERROR(&s->trace, "No trust anchors: refusing to connect "
                                 "(SSFTLSCSetUnauthenticated() opts in)");
        return false;
    }
#else
    /* Are there no trust anchors? */
    if (s->trust.count == 0u)
    {
        SSF_TLS_TRACE_CERT_ERROR(&s->trace, "No trust anchors: refusing to connect");
        return false;
    }
#endif

    _SSFTLSCReset(s);
    /* SNI and certificate name; the caller's copy may go */
    memcpy(s->host, hostStr, hostLen + 1u);
    s->hsHostname = s->host;
    s->hsPort = port;

    if (s->inner->open(s->inner, s->host, sizeof(s->host), port) == false) return false;
    s->innerOpen = true;
    s->helperStep = 0;
    s->hsState = SSF_TLSC_HS_SEND_CH;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS once the handshake is complete, WANT_READ/WANT_WRITE while in progress.       */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCPollOpen(SSFNetTransport_t *t)
{
    return _SSFTLSCDrive(_SSFTLSCSelf(t));
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: post-handshake handshake messages (RFC 8446 4.6)                                    */
/* --------------------------------------------------------------------------------------------- */
/* NewSessionTicket body minimum; the ticket is never used, as there is no resumption */
#define SSF_TLSC_NST_MIN_BODY (14u)
#define SSF_TLSC_NO_KEY_UPDATE (0xFFu)

/* --------------------------------------------------------------------------------------------- */
/* Internal: feeds one record's plaintext to the post-handshake parser; false with the alert     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCPostHandshakeFeed(SSFTLSCSession_t *s, const uint8_t *rec, size_t recLen,
                                      uint8_t *alertOut, uint8_t *kuOut)
{
    size_t i = 0;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE((rec != NULL) || (recLen == 0u));
    SSF_REQUIRE(alertOut != NULL);
    SSF_REQUIRE(kuOut != NULL);

    *alertOut = 0;
    *kuOut = SSF_TLSC_NO_KEY_UPDATE;
    while (i < recLen)
    {
        size_t n;

        /* Is the message header still incomplete? */
        if (s->phHdrLen < sizeof(s->phHdr))
        {
            /* Yes, take its next byte; only NewSessionTicket and KeyUpdate are allowed */
            s->phHdr[s->phHdrLen++] = rec[i++];
            if (s->phHdrLen < sizeof(s->phHdr)) continue;
            s->phType = s->phHdr[0];
            s->phRemain = (((uint32_t)s->phHdr[1]) << 16) | (((uint32_t)s->phHdr[2]) << 8) |
                          ((uint32_t)s->phHdr[3]);
            /* Is it a NewSessionTicket? */
            if (s->phType == SSF_TLS_HS_NEW_SESSION_TICKET)
            {
                /* Yes, checked only for its minimum length and skipped */
                if (s->phRemain < SSF_TLSC_NST_MIN_BODY)
                { *alertOut = SSF_TLS_ALERT_DECODE_ERROR; return false; }
            }
            else if (s->phType == SSF_TLS_HS_KEY_UPDATE)
            {
                /* No, a KeyUpdate has a one-byte body */
                if (s->phRemain != 1u) { *alertOut = SSF_TLS_ALERT_DECODE_ERROR; return false; }
            }
            else { *alertOut = SSF_TLS_ALERT_UNEXPECTED_MSG; return false; }
            continue;
        }

        /* Is it a KeyUpdate, whose one byte is its request and must end the record? */
        if (s->phType == SSF_TLS_HS_KEY_UPDATE)
        {
            if (rec[i] > 1u) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            if ((i + 1u) != recLen) { *alertOut = SSF_TLS_ALERT_UNEXPECTED_MSG; return false; }
            *kuOut = rec[i];
        }
        n = recLen - i;
        if (n > s->phRemain) n = s->phRemain;
        i += n;
        s->phRemain -= (uint32_t)n;
        if (s->phRemain == 0u) s->phHdrLen = 0;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: false if a part-way handshake message is split by another record type (5.1)         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCRecordTypeAllowed(const SSFTLSCSession_t *s, uint8_t contentType)
{
    SSF_REQUIRE(s != NULL);

    return (contentType == SSF_TLS_CT_HANDSHAKE) || (s->phHdrLen == 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: secret = HKDF-Expand-Label(secret, "traffic upd", "", Hash.length) (RFC 8446 7.2)   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCNextTrafficSecret(const SSFTLSCSession_t *s, uint8_t *secret)
{
    uint8_t next[SSF_TLS_MAX_HASH_SIZE];

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(secret != NULL);

    SSFTLSHkdfExpandLabel(s->hash, secret, s->hashLen, "traffic upd", NULL, 0, next, s->hashLen);
    memcpy(secret, next, s->hashLen);
    _SSF_TLSC_SCRUB(next);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: moves secret to its next generation and installs its keys in state                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCUpdateTrafficKeys(SSFTLSCSession_t *s, uint8_t *secret,
                                      SSFTLSRecordState_t *state, bool *inited)
{
    uint8_t key[SSF_TLS_MAX_KEY_SIZE];
    uint8_t iv[SSF_TLS_IV_SIZE];

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(secret != NULL);
    SSF_REQUIRE(state != NULL);
    SSF_REQUIRE(inited != NULL);

    _SSFTLSCNextTrafficSecret(s, secret);
    SSFTLSDeriveTrafficKeys(s->hash, secret, s->hashLen, key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    _SSFTLSCRecordStateSet(s, state, inited, key, iv);
    _SSF_TLSC_SCRUB(key);
    _SSF_TLSC_SCRUB(iv);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: sends a KeyUpdate under the current client key, then moves sending to the next key  */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SSFTLSCSendKeyUpdate(SSFTLSCSession_t *s)
{
    static const uint8_t ku[5] = { SSF_TLS_HS_KEY_UPDATE, 0u, 0u, 1u, 0u };
    SSFTLSIOResult_t r;

    SSF_REQUIRE(s != NULL);

    /* Once encrypted the record is the old key's last, even while still being written */
    r = _SSFTLSCSendEncRecordOnce(s, SSF_TLS_CT_HANDSHAKE, ku, sizeof(ku));

    if (r == SSF_TLS_IO_ERROR) return r;
    _SSFTLSCUpdateTrafficKeys(s, s->clientAppTrafficSecret, &s->sendState, &s->sendStateInited);
    SSF_TLS_TRACE_CRYPTO_INFO(&s->trace, "KeyUpdate sent (%s); client key updated",
                              s->keyUpdateOwed ? "requested by the server" : "record limit");
    s->keyUpdateOwed = false;
    s->sendRecordsOnKey = 0;
    return r;
}

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
bool _SSFTLSCPostHandshakeFeedForTest(SSFTLSCSession_t *session, const uint8_t *rec,
                                      size_t recLen, uint8_t *alertOut, uint8_t *keyUpdateOut)
{
    return _SSFTLSCPostHandshakeFeed(session, rec, recLen, alertOut, keyUpdateOut);
}

void _SSFTLSCNextTrafficSecretForTest(const SSFTLSCSession_t *session, uint8_t *secret)
{
    _SSFTLSCNextTrafficSecret(session, secret);
}

bool _SSFTLSCRecordTypeAllowedForTest(const SSFTLSCSession_t *session, uint8_t contentType)
{
    return _SSFTLSCRecordTypeAllowed(session, contentType);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS with up to one record's worth of bytes accepted, else WANT_WRITE/CLOSED/ERROR */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCSend(SSFNetTransport_t *t, const uint8_t *buf, size_t bufLen,
                                     size_t *sentOut)
{
    SSFTLSCSession_t *s;
    SSFTLSIOResult_t r;
    size_t chunk;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(bufLen > 0);
    SSF_REQUIRE(sentOut != NULL);
    s = _SSFTLSCSelf(t);

    *sentOut = 0;
    if (s->connected == false) return SSF_NET_IO_ERROR;
    if (s->closeNotifySent) return SSF_NET_IO_ERROR;

    r = _SSFTLSCSendPending(s);
    if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
    if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);

    /* Is a KeyUpdate owed, by server request (4.6.3) or the per-key record limit (5.5)? */
    if (s->keyUpdateOwed || (s->sendRecordsOnKey >= SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS))
    {
        /* Yes, it goes first; the data follows on the next call if its record is pending */
        r = _SSFTLSCSendKeyUpdate(s);
        if (r == SSF_TLS_IO_ERROR) return _SSFTLSCFail(s);
        if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
    }

    chunk = _SSFTLSCSendRecordMax(s);
    if (bufLen < chunk) chunk = bufLen;
    r = _SSFTLSCSendEncRecordOnce(s, SSF_TLS_CT_APPLICATION, buf, chunk);
    if (r == SSF_TLS_IO_ERROR) return _SSFTLSCFail(s);
    s->sendRecordsOnKey++;
    /* Encrypted; any unsent tail stays pending */
    *sentOut = chunk;
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS with application bytes, else WANT_READ/CLOSED/ERROR.                          */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCRecv(SSFNetTransport_t *t, uint8_t *buf, size_t bufSize,
                                     size_t *gotOut)
{
    SSFTLSCSession_t *s;
    uint32_t i;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(bufSize > 0);
    SSF_REQUIRE(gotOut != NULL);
    s = _SSFTLSCSelf(t);

    *gotOut = 0;
    if (s->connected == false) return SSF_NET_IO_ERROR;

    /* Keep a partly written record moving even when the caller is only reading */
    if (_SSFTLSCSendPending(s) == SSF_TLS_IO_ERROR) return _SSFTLSCFail(s);

    for (i = 0; (s->hsBufPos >= s->hsBufLen) && (i < SSF_TLSC_RECV_MAX_RECORDS); i++)
    {
        uint8_t ct = 0;
        size_t ptLen = 0;
        SSFTLSIOResult_t r = _SSFTLSCRecvRecordOnce(s, s->hsBuf, SSF_TLSC_HSBUF_SIZE, &ptLen,
                                                    &ct);

        if (r == SSF_TLS_IO_WANT_READ) return SSF_NET_IO_WANT_READ;
        if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);

        /* Is it application data? */
        if (ct == SSF_TLS_CT_APPLICATION)
        {
            /* Yes, it must not split a post-handshake message */
            if (!_SSFTLSCRecordTypeAllowed(s, ct))
            {
                SSF_TLS_TRACE_HS_ERROR(&s->trace, "Application data inside a split "
                                       "post-handshake message");
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG);
                return _SSFTLSCFail(s);
            }
            /* An empty record yields nothing; read on */
            s->hsBufLen = ptLen;
            s->hsBufPos = 0;
        }
        else if (ct == SSF_TLS_CT_ALERT)
        {
            /* No, an alert ends the connection */
            if ((ptLen >= 2u) && (s->hsBuf[1] == SSF_TLS_ALERT_CLOSE_NOTIFY))
            { s->peerClosed = true; }
            return _SSFTLSCFail(s);
        }
        else if (ct == SSF_TLS_CT_HANDSHAKE)
        {
            /* No, a post-handshake message */
            uint8_t alert;
            uint8_t ku;

            if (!_SSFTLSCPostHandshakeFeed(s, s->hsBuf, ptLen, &alert, &ku))
            {
                SSF_TLS_TRACE_HS_ERROR(&s->trace, "Post-handshake message rejected");
                _SSF_TLSC_ALERT(s, alert);
                return _SSFTLSCFail(s);
            }
            /* Did a KeyUpdate end the record? */
            if (ku != SSF_TLSC_NO_KEY_UPDATE)
            {
                /* Yes, the server's next records use its next key (RFC 8446 4.6.3) */
                _SSFTLSCUpdateTrafficKeys(s, s->serverAppTrafficSecret, &s->recvState,
                                          &s->recvStateInited);
                /* One reply answers any number of requests */
                if (ku == 1u) s->keyUpdateOwed = true;
                SSF_TLS_TRACE_CRYPTO_INFO(&s->trace, "KeyUpdate received (%s); server key "
                                          "updated", (ku == 1u) ? "update requested" :
                                          "update not requested");
            }
            /* Nothing for the application */
            s->hsBufLen = 0;
            s->hsBufPos = 0;
        }
        else { _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG); return _SSFTLSCFail(s); }
    }
    if (s->hsBufPos >= s->hsBufLen) return SSF_NET_IO_WANT_READ;

    *gotOut = s->hsBufLen - s->hsBufPos;
    if (*gotOut > bufSize) *gotOut = bufSize;
    memcpy(buf, &s->hsBuf[s->hsBufPos], *gotOut);
    s->hsBufPos += *gotOut;
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Finishes sending: the partly written record, close_notify, then the inner shutdown().         */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCShutdown(SSFNetTransport_t *t)
{
    SSFTLSCSession_t *s;
    SSFTLSIOResult_t r;

    s = _SSFTLSCSelf(t);
    if (s->connected == false) return SSF_NET_IO_ERROR;

    /* Application data, or a close_notify resumed (RFC 8446 6.1) */
    r = _SSFTLSCSendPending(s);
    if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
    if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);

    /* Is close_notify still to be sent? */
    if (s->closeNotifySent == false)
    {
        /* Yes, a warning-level close_notify */
        static const uint8_t alert[2] = { 1u, SSF_TLS_ALERT_CLOSE_NOTIFY };

        SSF_TLS_TRACE_ALERT(&s->trace, "Sending alert level=%u desc=%u", alert[0], alert[1]);
        r = _SSFTLSCSendEncRecordOnce(s, SSF_TLS_CT_ALERT, alert, sizeof(alert));
        if (r == SSF_TLS_IO_ERROR) return _SSFTLSCFail(s);
        /* Encrypted; any unsent tail stays pending */
        s->closeNotifySent = true;
        if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
    }

    /* Everything is with the inner transport, which may buffer too */
    {
        SSFNetIOResult_t ir = s->inner->shutdown(s->inner);

        /* Is the inner shutdown done or in progress? */
        if ((ir == SSF_NET_IO_SUCCESS) || (ir == SSF_NET_IO_WANT_WRITE) ||
            (ir == SSF_NET_IO_WANT_READ))
        { return ir; }
        s->ioFailed = true;
        if (ir == SSF_NET_IO_CLOSED) s->peerClosed = true;
        return _SSFTLSCFail(s);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Ends the connection without blocking: best-effort close_notify, inner close, key wipe.        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCClose(SSFNetTransport_t *t)
{
    SSFTLSCSession_t *s;
    bool isHandshaking;

    s = _SSFTLSCSelf(t);
    isHandshaking = ((s->hsState != SSF_TLSC_HS_IDLE) && (s->hsState != SSF_TLSC_HS_COMPLETE) &&
                     (s->hsState != SSF_TLSC_HS_ERROR));

    /* Was shutdown() started but not finished? */
    if (s->closeNotifySent)
    {
        /* Yes, one last push */
        (void)_SSFTLSCSendPending(s);
    }
    else if (s->connected && s->sendEncrypted && (_SSFTLSCSendPending(s) == SSF_TLS_IO_SUCCESS))
    {
        /* No, connected: send a warning-level close_notify */
        uint8_t alert[2] = { 1u, SSF_TLS_ALERT_CLOSE_NOTIFY };

        (void)_SSFTLSCSendEncRecordOnce(s, SSF_TLS_CT_ALERT, alert, sizeof(alert));
    }
    else if (isHandshaking && s->clientHelloSent)
    {
        /* No, abandoning a handshake the peer has seen: user_canceled, close_notify (6.1) */
        _SSFTLSCSendAlert(s, 1u, SSF_TLS_ALERT_USER_CANCELED);
        _SSFTLSCSendAlert(s, 1u, SSF_TLS_ALERT_CLOSE_NOTIFY);
    }
    else { /* Nothing to announce */ }
    if (s->innerOpen) s->inner->close(s->inner);
    s->innerOpen = false;
    _SSFTLSCReset(s);
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes a TLS client session over inner.                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSCInit(SSFTLSCSession_t *session, SSFNetTransport_t *inner,
                 const SSFTLSCTrustStore_t *trustStoreOpt)
{
    SSF_REQUIRE(session != NULL);
    SSF_REQUIRE(session->magic != SSF_TLSC_MAGIC);
    SSF_REQUIRE(inner != NULL);
    SSF_REQUIRE(inner->open != NULL);
    SSF_REQUIRE(inner->pollOpen != NULL);
    SSF_REQUIRE(inner->send != NULL);
    SSF_REQUIRE(inner->recv != NULL);
    SSF_REQUIRE(inner->shutdown != NULL);
    SSF_REQUIRE(inner->close != NULL);

    memset(session, 0, sizeof(*session));
    session->transport.open = _SSFTLSCOpen;
    session->transport.pollOpen = _SSFTLSCPollOpen;
    session->transport.send = _SSFTLSCSend;
    session->transport.recv = _SSFTLSCRecv;
    session->transport.shutdown = _SSFTLSCShutdown;
    session->transport.close = _SSFTLSCClose;
    session->inner = inner;
    SSF_REQUIRE((trustStoreOpt == NULL) || (trustStoreOpt->count == 0u) ||
                ((trustStoreOpt->caDer != NULL) && (trustStoreOpt->caDerLen != NULL)));
    if (trustStoreOpt != NULL) session->trust = *trustStoreOpt;
    session->hsState = SSF_TLSC_HS_IDLE;
    session->magic = SSF_TLSC_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Closes any connection and wipes the session.                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSCDeInit(SSFTLSCSession_t *session)
{
    SSF_REQUIRE(session != NULL);
    SSF_REQUIRE(session->magic == SSF_TLSC_MAGIC);

    _SSFTLSCClose(&session->transport);
    SSFCryptSecureZero(session, sizeof(*session));
}

#if SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED == 1
/* --------------------------------------------------------------------------------------------- */
/* Opts in to, or out of, connecting without trust anchors.                                      */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSCSetUnauthenticated(SSFTLSCSession_t *session, bool allow)
{
    SSF_REQUIRE(session != NULL);
    SSF_REQUIRE(session->magic == SSF_TLSC_MAGIC);
    SSF_REQUIRE(session->hsState == SSF_TLSC_HS_IDLE);
    session->allowUnauthenticated = allow;
}
#endif /* SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED */

/* --------------------------------------------------------------------------------------------- */
/* Sets, or clears, the client certificate and key; see _net/README.md.                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFTLSCSetClientCert(SSFTLSCSession_t *session, const uint8_t *const *chainDerOpt,
                          const uint32_t *chainLensOpt, uint8_t chainCount,
                          const SSFPKey_t *keyOpt)
{
    size_t total = 4u;
    uint8_t i;

    SSF_REQUIRE(session != NULL);
    SSF_REQUIRE(session->magic == SSF_TLSC_MAGIC);
    SSF_REQUIRE(session->hsState == SSF_TLSC_HS_IDLE);

    session->clientChainDer = NULL;
    session->clientChainLens = NULL;
    session->clientKey = NULL;
    session->clientChainCount = 0;
    /* Is the request to clear? */
    if ((chainDerOpt == NULL) && (chainLensOpt == NULL) && (chainCount == 0u) && (keyOpt == NULL))
    {
        /* Yes */
        return true;
    }
    if ((chainDerOpt == NULL) || (chainLensOpt == NULL) || (chainCount == 0u) ||
        (keyOpt == NULL) ||
        (keyOpt->type == SSF_PKEY_TYPE_NONE)) return false;

    /* Every entry fits CertificateEntry, and the list fits certificate_list<0..2^24-1> */
    for (i = 0; i < chainCount; i++)
    {
        if ((chainDerOpt[i] == NULL) || (chainLensOpt[i] == 0u) || (chainLensOpt[i] > 0xFFFFFFu))
        {
            return false;
        }
        total += ((3u + ((size_t)chainLensOpt[i])) + 2u);
        if (total > 0xFFFFFFu) return false;
    }
    /* Does the leaf's public key differ from the key? */
    if (!_SSFTLSCClientCertMatchesKey(chainDerOpt[0], chainLensOpt[0], keyOpt))
    {
        SSF_TLS_TRACE_CERT_ERROR(&session->trace, "Client certificate does not match its key");
        return false;
    }
    session->clientChainDer = chainDerOpt;
    session->clientChainLens = chainLensOpt;
    session->clientKey = keyOpt;
    session->clientChainCount = chainCount;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: true if der[0..derLen) is exactly one X.509 certificate; parsed out of line         */
/* --------------------------------------------------------------------------------------------- */
static SSF_NOINLINE bool _SSFTLSCIsOneCert(const uint8_t *der, size_t derLen)
{
    SSFX509Cert_t cert;

    SSF_REQUIRE(der != NULL);

    return (derLen <= 0xFFFFFFFFu) && SSFX509Parse(der, (uint32_t)derLen, &cert);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: counts "-----BEGIN" and "-----END" markers in pem[0..pemLen)                        */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFTLSCPemMarkers(const char *pem, size_t pemLen)
{
    size_t n = 0;
    size_t i;

    SSF_REQUIRE(pem != NULL);

    for (i = 0; (i + 8u) <= pemLen; i++)
    {
        if ((memcmp(&pem[i], "-----END", 8u) == 0) ||
            (((i + 10u) <= pemLen) && (memcmp(&pem[i], "-----BEGIN", 10u) == 0)))
        {
            n++;
        }
    }
    return n;
}

/* --------------------------------------------------------------------------------------------- */
/* Builds a trust store from a PEM certificate or bundle; see _net/README.md.                    */
/* --------------------------------------------------------------------------------------------- */
SSFTLSCTrustResult_t SSFTLSCTrustFromPEM(const char *pem, size_t pemLen, uint8_t *poolOpt,
                                         size_t poolSize, const uint8_t **dersOpt,
                                         uint32_t *lensOpt, uint8_t maxCount,
                                         SSFTLSCTrustStore_t *storeOpt, size_t *poolUsedOut,
                                         uint8_t *countOut)
{
    SSFTLSCTrustResult_t r = SSF_TLSC_TRUST_OK;
    uint8_t limit = (uint8_t)((poolOpt == NULL) ? 255u : maxCount);
    size_t pos = 0;
    size_t used = 0;
    uint8_t count = 0;

    SSF_REQUIRE(pem != NULL);
    SSF_REQUIRE(poolUsedOut != NULL);
    SSF_REQUIRE(countOut != NULL);
    SSF_REQUIRE((poolOpt == NULL) ||
                ((dersOpt != NULL) && (lensOpt != NULL) && (storeOpt != NULL)));
    SSF_REQUIRE((poolOpt == NULL) || (((uintptr_t)&poolOpt[poolSize]) <= ((uintptr_t)pem)) ||
                (((uintptr_t)&pem[pemLen]) <= ((uintptr_t)poolOpt)));

    for (;;)
    {
        const char *label;
        size_t labelLen;
        size_t derLen;
        size_t start = pos;
        SSFPEMResult_t pr;

        /* Measuring decodes nowhere, as ssfpem ignores derSize without a buffer */
        pr = SSFPEMDecodeNext(pem, pemLen, &pos, &label, &labelLen,
                              (poolOpt != NULL) ? &poolOpt[used] : NULL,
                              (poolOpt != NULL) ? (poolSize - used) : 0u, &derLen);
        /* Is it the end, with no marker of a damaged block left in the trailing text? */
        if (pr == SSF_PEM_END)
        {
            /* Yes, a stray marker rejects the input instead of being dropped */
            if (_SSFTLSCPemMarkers(&pem[start], pemLen - start) != 0u)
            {
                r = SSF_TLSC_TRUST_ERR_PEM;
            }
            break;
        }
        if (pr == SSF_PEM_ERR_SIZE) { r = SSF_TLSC_TRUST_ERR_SIZE; break; }
        if ((pr != SSF_PEM_BLOCK) || (_SSFTLSCPemMarkers(&pem[start], pos - start) != 2u))
        {
            r = SSF_TLSC_TRUST_ERR_PEM;
            break;
        }
        if (!SSFPEMLabelIs(label, labelLen, "CERTIFICATE"))
        {
            r = SSF_TLSC_TRUST_ERR_LABEL;
            break;
        }
        if (count == limit) { r = SSF_TLSC_TRUST_ERR_COUNT; break; }
        /* Is the certificate decoded into the pool, not just measured? */
        if (poolOpt != NULL)
        {
            /* Yes, it must be exactly one X.509 certificate */
            if (!_SSFTLSCIsOneCert(&poolOpt[used], derLen))
            {
                r = SSF_TLSC_TRUST_ERR_CERT;
                break;
            }
            dersOpt[count] = &poolOpt[used];
            lensOpt[count] = (uint32_t)derLen;
        }
        used += derLen;
        count++;
    }
    if ((r == SSF_TLSC_TRUST_OK) && (count == 0u)) r = SSF_TLSC_TRUST_ERR_EMPTY;

    /* Fail closed: an error leaves an empty store, with count the block at fault */
    if (r != SSF_TLSC_TRUST_OK) used = 0;
    *poolUsedOut = used;
    *countOut = count;
    /* Was a store built, not just measured? */
    if (poolOpt != NULL)
    {
        /* Yes */
        storeOpt->caDer = (r == SSF_TLSC_TRUST_OK) ? dersOpt : NULL;
        storeOpt->caDerLen = (r == SSF_TLSC_TRUST_OK) ? lensOpt : NULL;
        storeOpt->count = (uint8_t)((r == SSF_TLSC_TRUST_OK) ? count : 0u);
    }
    return r;
}

/* --------------------------------------------------------------------------------------------- */
/* Sets, or clears, the ALPN protocol list; see _net/README.md.                                  */
/* --------------------------------------------------------------------------------------------- */
bool SSFTLSCSetALPN(SSFTLSCSession_t *session, const char *const *protosOpt, uint8_t count)
{
    size_t total = 0;
    uint8_t i;

    SSF_REQUIRE(session != NULL);
    SSF_REQUIRE(session->magic == SSF_TLSC_MAGIC);
    SSF_REQUIRE(session->hsState == SSF_TLSC_HS_IDLE);

    session->alpnProtos = NULL;
    session->alpnCount = 0;
    session->alpnChosen = 0;
    if ((protosOpt == NULL) && (count == 0u)) return true;
    if ((protosOpt == NULL) || (count == 0u)) return false;

    /* ProtocolName<1..2^8-1> (RFC 7301 3.1), the list within SSF_TLS_CONFIG_MAX_ALPN_LEN */
    for (i = 0; i < count; i++)
    {
        size_t n;

        n = _SSFTLSCAlpnLen(protosOpt[i]);

        if (n == 0u) return false;
        total += 1u + n;
        if (total > SSF_TLS_CONFIG_MAX_ALPN_LEN) return false;
    }
    session->alpnProtos = protosOpt;
    session->alpnCount = count;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the protocol the server chose with ALPN, or NULL; see _net/README.md.                 */
/* --------------------------------------------------------------------------------------------- */
const char *SSFTLSCGetALPN(const SSFTLSCSession_t *session)
{
    SSF_REQUIRE(session != NULL);
    SSF_REQUIRE(session->magic == SSF_TLSC_MAGIC);

    /* Is the handshake incomplete, as the choice precedes server authentication, or none made? */
    if ((session->hsState != SSF_TLSC_HS_COMPLETE) || (session->alpnChosen == 0u)) return NULL;
    return session->alpnProtos[session->alpnChosen - 1u];
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the current handshake state.                                                          */
/* --------------------------------------------------------------------------------------------- */
SSFTLSCHandshakeState_t SSFTLSCGetHandshakeState(const SSFTLSCSession_t *session)
{
    SSF_REQUIRE(session != NULL);
    SSF_REQUIRE(session->magic == SSF_TLSC_MAGIC);

    return session->hsState;
}
