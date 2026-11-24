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

/* Max SNI hostname length (RFC 1035 DNS FQDN is 255 characters). Used to
   bound reads from caller-supplied hostname pointers via SSFStrLen. */
#define SSF_TLSC_MAX_HOSTNAME_LEN (255u)

/* Largest fragment a compliant peer can send with the offered suites: a 2^14 + 1 byte           */
/* TLSInnerPlaintext (RFC 8446 5.4) plus the 16-byte AEAD tag. Anything longer is the peer's      */
/* record_overflow; anything longer than this build's buffers but within it is internal_error.  */
#define SSF_TLSC_RFC_MAX_CIPHERTEXT (16384u + 1u + SSF_TLS_AEAD_TAG_SIZE)

/* record_size_limit (RFC 8449 4): extension 28, a uint16 TLSInnerPlaintext limit (content,      */
/* content type and padding), 64..2^14+1 in TLS 1.3.                                             */
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

/* The chain limit is the verifier's, SSF_X509_CONFIG_MAX_CHAIN_DEPTH; the separate TLS option is */
/* gone, so a build still setting it is told rather than silently given a different limit.     */
#ifdef SSF_TLS_CONFIG_MAX_CHAIN_DEPTH
#error SSF_TLS_CONFIG_MAX_CHAIN_DEPTH is removed; ssftlsc uses SSF_X509_CONFIG_MAX_CHAIN_DEPTH.
#endif

/* Secret scrubbing. _SSF_TLSC_SCRUB wipes a secret at the end of its life; unit-test builds     */
/* then report the buffer to _SSFTLSCScrubTestHook so a test can confirm the wipe happened.      */
#if SSF_CONFIG_TLSC_UNIT_TEST == 1
void (*_SSFTLSCScrubTestHook)(void *ctx, const char *what, const void *buf, size_t len) = NULL;
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
/* Test hook: flips a bit of the received server Finished verify_data, as a peer whose Finished */
/* is wrong would send. Records are AEAD protected, so no on-path party can produce this.       */
bool _ssfTLSCUTCorruptServerFinished;
#endif

/* --------------------------------------------------------------------------------------------- */
/* Internal: binary encoding helpers (big-endian)                                                */
/* --------------------------------------------------------------------------------------------- */
static size_t _Put8(uint8_t *buf, uint8_t v) { buf[0] = v; return 1; }
static size_t _Put16(uint8_t *buf, uint16_t v)
{ buf[0] = (uint8_t)(v >> 8); buf[1] = (uint8_t)v; return 2; }
static size_t _Put24(uint8_t *buf, uint32_t v)
{ buf[0] = (uint8_t)(v >> 16); buf[1] = (uint8_t)(v >> 8); buf[2] = (uint8_t)v; return 3; }

static uint16_t _Get16(const uint8_t *buf) { return ((uint16_t)buf[0] << 8) | buf[1]; }
static uint32_t _Get24(const uint8_t *buf)
{ return ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2]; }

/* --------------------------------------------------------------------------------------------- */
/* Internal: platform entropy                                                                    */
/* --------------------------------------------------------------------------------------------- */
static bool _GetEntropy(uint8_t *buf, size_t len)
{
    if (len > 0xffffu) return false;
    return SSFPortGetEntropy(buf, (uint16_t)len);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: inner transport adapters used by the record layer. Each issues one send() or recv()  */
/* on the inner transport and returns at once. SUCCESS means the full count moved; WANT_WRITE /   */
/* WANT_READ means partial or no progress with the transport still usable; ERROR means it failed  */
/* or the peer closed (peerClosed is then set).                                                  */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _InnerSendOnce(SSFTLSCSession_t *s, const uint8_t *data, size_t len,
                                       size_t *sentOut)
{
    size_t sent = 0;
    SSFNetIOResult_t r;

    *sentOut = 0;
    if (len == 0) return SSF_TLS_IO_SUCCESS;
    r = s->inner->send(s->inner, data, len, &sent);
    if (r == SSF_NET_IO_SUCCESS)
    {
        *sentOut = sent;
        return (sent == len) ? SSF_TLS_IO_SUCCESS : SSF_TLS_IO_WANT_WRITE;
    }
    if ((r == SSF_NET_IO_WANT_WRITE) || (r == SSF_NET_IO_WANT_READ)) return SSF_TLS_IO_WANT_WRITE;
    if (r == SSF_NET_IO_CLOSED) s->peerClosed = true;
    s->ioFailed = true;
    return SSF_TLS_IO_ERROR;
}

static SSFTLSIOResult_t _InnerRecvOnce(SSFTLSCSession_t *s, uint8_t *data, size_t len,
                                       size_t *recvdOut)
{
    size_t got = 0;
    SSFNetIOResult_t r;

    *recvdOut = 0;
    if (len == 0) return SSF_TLS_IO_SUCCESS;
    r = s->inner->recv(s->inner, data, len, &got);
    if (r == SSF_NET_IO_SUCCESS)
    {
        *recvdOut = got;
        return (got == len) ? SSF_TLS_IO_SUCCESS : SSF_TLS_IO_WANT_READ;
    }
    if ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)) return SSF_TLS_IO_WANT_READ;
    if (r == SSF_NET_IO_CLOSED) s->peerClosed = true;
    s->ioFailed = true;
    return SSF_TLS_IO_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: continues writing the record in ioCtx.sendRecordBuf. SUCCESS once it is all out (or */
/* none was pending), WANT_WRITE if some remains, ERROR on transport failure.                    */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _SendPending(SSFTLSCSession_t *s)
{
    SSFTLSCIOCtx_t *io = &s->ioCtx;

    while (io->sendPending && (io->sendPos < io->sendTotal))
    {
        size_t sent = 0;
        SSFTLSIOResult_t r = _InnerSendOnce(s, &io->sendRecordBuf[io->sendPos],
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
static void _RecordStateSet(SSFTLSCSession_t *s, SSFTLSRecordState_t *state, bool *inited,
                            const uint8_t *key, const uint8_t *iv)
{
    if (*inited) SSFTLSRecordStateDeInit(state);
    SSFTLSRecordStateInit(state, s->cipherSuite, key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    *inited = true;
}

/* --------------------------------------------------------------------------------------------- */
/* Resumable record helpers. They use _InnerSendOnce / _InnerRecvOnce and keep partial progress  */
/* in session->ioCtx (sendRecordBuf/sendPending/sendPos/sendTotal for sends; hdr/hdrPos/          */
/* hdrComplete/fragLen/fragPos for receives). On WANT_READ / WANT_WRITE they keep that state and  */
/* return, so the next call resumes mid-record.                                                  */
/* --------------------------------------------------------------------------------------------- */

/* Send a plaintext record — resumable. */
static SSFTLSIOResult_t _SendPlainRecordOnce(SSFTLSCSession_t *s, uint8_t ct,
                                             const uint8_t *data, size_t len)
{
    SSFTLSCIOCtx_t *io = &s->ioCtx;

    /* First call for this record: frame header + data in send buffer. */
    if (!io->sendPending)
    {
        if ((size_t)5u + len > sizeof(io->sendRecordBuf)) return SSF_TLS_IO_ERROR;
        io->sendRecordBuf[0] = ct;
        io->sendRecordBuf[1] = 0x03u; io->sendRecordBuf[2] = 0x03u;
        io->sendRecordBuf[3] = (uint8_t)((len >> 8) & 0xFFu);
        io->sendRecordBuf[4] = (uint8_t)(len & 0xFFu);
        if (len > 0) memcpy(&io->sendRecordBuf[5], data, len);
        io->sendTotal = 5u + len;
        io->sendPos = 0;
        io->sendPending = true;
    }

    /* On WANT_WRITE sendPending/sendPos are kept so the next call resumes. */
    return _SendPending(s);
}

/* Send an encrypted record — resumable. */
static SSFTLSIOResult_t _SendEncRecordOnce(SSFTLSCSession_t *s, uint8_t ct,
                                           const uint8_t *data, size_t len)
{
    SSFTLSCIOCtx_t *io = &s->ioCtx;

    /* First call: encrypt once into sendRecordBuf. */
    if (!io->sendPending)
    {
        size_t recordLen;
        if (!SSFTLSRecordEncrypt(&s->sendState, ct, data, len,
                                 io->sendRecordBuf, sizeof(io->sendRecordBuf), &recordLen))
            return SSF_TLS_IO_ERROR;
        io->sendTotal = recordLen;
        io->sendPos = 0;
        io->sendPending = true;
    }

    return _SendPending(s);
}

/* Receive one record into session->recvBuf (header at [0..4], fragment after it, so encrypted   */
/* records decrypt in place) — resumable across partial reads.                                   */
/* Partial state lives in io->hdrPos/hdrComplete/fragLen/fragPos; on SUCCESS or ERROR the        */
/* state resets so the next call starts a fresh record.                                           */
static SSFTLSIOResult_t _RecvRecordOnce(SSFTLSCSession_t *s, uint8_t *pt, size_t ptSize,
                                        size_t *ptLen, uint8_t *contentType)
{
    SSFTLSCIOCtx_t *io = &s->ioCtx;

    /* Read 5-byte header (resumable). */
    while (!io->hdrComplete)
    {
        size_t recvd = 0;
        SSFTLSIOResult_t r = _InnerRecvOnce(s, &s->recvBuf[io->hdrPos],
                                          (size_t)SSF_TLS_RECORD_HEADER_SIZE - io->hdrPos,
                                          &recvd);
        io->hdrPos += recvd;
        if (r == SSF_TLS_IO_ERROR)
        {
            SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: header read failed");
            io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0; io->fragLen = 0;
            return SSF_TLS_IO_ERROR;
        }
        if (io->hdrPos >= SSF_TLS_RECORD_HEADER_SIZE)
        {
            io->hdrComplete = true;
            io->fragLen = _Get16(&s->recvBuf[3]);
            io->fragPos = 0;
            SSF_TLS_TRACE_REC_DEBUG(&s->trace,
                                    "RecvRecord: ct=%u ver=0x%04x fragLen=%u",
                                    s->recvBuf[0], _Get16(&s->recvBuf[1]), io->fragLen);
            /* Judge the header before reading the fragment: an unknown content type is        */
            /* unexpected_message (RFC 8446 5); a length over 2^14 + 256 is record_overflow     */
            /* (5.2). A legal length over this build's buffer is this client's limit, reported  */
            /* as internal_error (punch list: record size).                                      */
            if ((s->recvBuf[0] < SSF_TLS_CT_CHANGE_CIPHER) ||
                (s->recvBuf[0] > SSF_TLS_CT_APPLICATION))
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: unknown record type %u",
                                        s->recvBuf[0]);
                io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0; io->fragLen = 0;
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR;
            }
            if (io->fragLen > SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u + SSF_TLS_AEAD_TAG_SIZE)
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: fragment too large (%u)",
                                        io->fragLen);
                /* Over the RFC maximum, or (protected, once the server accepted our             */
                /* record_size_limit) over the limit advertised: the peer's record_overflow     */
                /* (RFC 8449 4). Otherwise a legal record larger than this build's buffer.      */
                _SSF_TLSC_ALERT(s, ((io->fragLen > SSF_TLSC_RFC_MAX_CIPHERTEXT) ||
                                    ((s->peerRecordLimit != 0u) &&
                                     (s->recvBuf[0] == SSF_TLS_CT_APPLICATION))) ?
                                   SSF_TLS_ALERT_RECORD_OVERFLOW : SSF_TLS_ALERT_INTERNAL_ERROR);
                io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0; io->fragLen = 0;
                return SSF_TLS_IO_ERROR;
            }
            break;
        }
        /* Partial header — resume next call. */
        return SSF_TLS_IO_WANT_READ;
    }

    /* Read fragment bytes into recvBuf (resumable). */
    while (io->fragPos < io->fragLen)
    {
        size_t recvd = 0;
        SSFTLSIOResult_t r = _InnerRecvOnce(s,
                                            &s->recvBuf[SSF_TLS_RECORD_HEADER_SIZE + io->fragPos],
                                            io->fragLen - io->fragPos, &recvd);
        io->fragPos += recvd;
        if (r == SSF_TLS_IO_ERROR)
        {
            SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: fragment read failed");
            io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0; io->fragLen = 0;
            return SSF_TLS_IO_ERROR;
        }
        if (io->fragPos >= io->fragLen) break;
        return SSF_TLS_IO_WANT_READ;
    }

    /* Record complete — dispatch. Reset the receive state; the header stays in recvBuf[0..4]  */
    /* as the AEAD additional data until the next record overwrites it.                        */
    {
        uint8_t hdr_ct = s->recvBuf[0];
        uint16_t fragLen = io->fragLen;
        io->hdrPos = 0; io->hdrComplete = false; io->fragPos = 0;

        /* RFC 8446 5: a plaintext change_cipher_spec of the single byte 0x01 may arrive after   */
        /* ClientHello and before the peer's Finished, and is dropped by the caller. Any other   */
        /* value, length or time is unexpected_message.                                          */
        if (hdr_ct == SSF_TLS_CT_CHANGE_CIPHER)
        {
            if (s->connected || (fragLen != 1u) ||
                (s->recvBuf[SSF_TLS_RECORD_HEADER_SIZE] != 0x01u))
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: unexpected change_cipher_spec");
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR;
            }
            *contentType = SSF_TLS_CT_CHANGE_CIPHER;
            *ptLen = 0;
            return SSF_TLS_IO_SUCCESS;
        }

        if (s->recvEncrypted)
        {
            bool ok;

            /* RFC 8446 5.2: once keys are active every record is protected, with outer type    */
            /* application_data. A plaintext handshake or alert record here was not sent by the  */
            /* peer and is unexpected_message; trusting it would let an on-path party inject    */
            /* handshake messages or a forged close_notify (truncation).                        */
            if (hdr_ct != SSF_TLS_CT_APPLICATION)
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace,
                                        "RecvRecord: plaintext record type %u after encryption",
                                        hdr_ct);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR;
            }
            /* The plaintext must fit the space offered (during reassembly, what is left of     */
            /* hsBuf); a shortfall is this build's limit, not a bad record.                     */
            if (((size_t)fragLen > SSF_TLS_AEAD_TAG_SIZE) &&
                (((size_t)fragLen - SSF_TLS_AEAD_TAG_SIZE) > ptSize))
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: %u bytes do not fit (%zu free)",
                                        fragLen, ptSize);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_INTERNAL_ERROR);
                return SSF_TLS_IO_ERROR;
            }
            /* Header and fragment are contiguous in recvBuf: decrypt the record in place. */
            ok = SSFTLSRecordDecrypt(&s->recvState, s->recvBuf,
                                     SSF_TLS_RECORD_HEADER_SIZE + (size_t)fragLen,
                                     pt, ptSize, ptLen, contentType);
            if (!ok)
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecordDecrypt failed (fragLen=%u seq=%llu)",
                                        fragLen, (unsigned long long)s->recvState.seqNum);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_BAD_RECORD_MAC); return SSF_TLS_IO_ERROR;
            }
            /* RFC 8446 5: a protected change_cipher_spec, or any unknown inner type, is        */
            /* unexpected_message.                                                              */
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
            /* Before keys: only handshake and alert records. application_data has no keys to   */
            /* decrypt with; anything else is an unknown type.                                   */
            if ((hdr_ct != SSF_TLS_CT_HANDSHAKE) && (hdr_ct != SSF_TLS_CT_ALERT))
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: unexpected plaintext type %u",
                                        hdr_ct);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR;
            }
            /* TLSPlaintext.length MUST NOT exceed 2^14 (RFC 8446 5.1), whatever space is free */
            if (fragLen > 16384u)
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: plaintext record of %u bytes",
                                        fragLen);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_RECORD_OVERFLOW);
                return SSF_TLS_IO_ERROR;
            }
            if (fragLen > ptSize)
            {
                /* Within 2^14 but not within the space offered: this build's limit. */
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: %u bytes do not fit (%zu free)",
                                        fragLen, ptSize);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_INTERNAL_ERROR);
                return SSF_TLS_IO_ERROR;
            }
            memcpy(pt, &s->recvBuf[SSF_TLS_RECORD_HEADER_SIZE], fragLen);
            *contentType = hdr_ct;
            *ptLen = fragLen;
        }

        /* RFC 8446 5.1 / 6: handshake records are never empty; an alert record holds exactly   */
        /* one two-byte alert.                                                                   */
        if ((*contentType == SSF_TLS_CT_HANDSHAKE) && (*ptLen == 0u))
        {
            SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: empty handshake record");
            _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_DECODE_ERROR); return SSF_TLS_IO_ERROR;
        }
        if (*contentType == SSF_TLS_CT_ALERT)
        {
            if (*ptLen != 2u)
            {
                SSF_TLS_TRACE_REC_ERROR(&s->trace, "RecvRecord: alert length %zu", *ptLen);
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_DECODE_ERROR); return SSF_TLS_IO_ERROR;
            }
            SSF_TLS_TRACE_ALERT(&s->trace, "RecvRecord: ALERT level=%u desc=%u", pt[0], pt[1]);
            if (pt[1] == SSF_TLS_ALERT_CERTIFICATE_REQUIRED)
            {
                SSF_TLS_TRACE_HS_ERROR(&s->trace, "Server requires a client certificate "
                                       "(certificate_required); none is configured");
            }
            /* close_notify is answered with close_notify; any other alert ends the connection */
            /* without a reply (RFC 8446 6.1, 6.2).                                             */
            if (pt[1] == SSF_TLS_ALERT_CLOSE_NOTIFY)
            {
                s->peerCloseNotify = true;
                s->peerClosed = true;
            }
            else s->peerAlerted = true;
        }
        return SSF_TLS_IO_SUCCESS;
    }
}

/* Receive one handshake message, reassembled in place in hsBuf from as many records as it takes */
/* (RFC 8446 5.1) — resumable. The message is returned in place and stays valid until the next */
/* call, which may move the unread bytes to the front of hsBuf: callers finish with a message, */
/* including any crypto step that reads it, before receiving the next. addToTranscript false   */
/* leaves the transcript to the caller (ServerHello / HelloRetryRequest).                      */
static SSFTLSIOResult_t _RecvHandshakeOnce(SSFTLSCSession_t *s, const uint8_t **msgOut,
                                           size_t *bodyLen, uint8_t *hsType, bool addToTranscript)
{
    for (;;)
    {
        size_t avail = s->hsBufLen - s->hsBufPos;
        uint8_t ct = 0;
        size_t ptLen = 0;
        SSFTLSIOResult_t r;

        /* A whole message buffered? */
        if (avail >= 4u)
        {
            size_t msgLen = (size_t)_Get24(&s->hsBuf[s->hsBufPos + 1u]);

            if ((4u + msgLen) > sizeof(s->hsBuf))
            {
                SSF_TLS_TRACE_HS_ERROR(&s->trace, "Handshake message of %lu bytes exceeds the "
                                       "%lu-byte buffer", (unsigned long)(4u + msgLen),
                                       (unsigned long)sizeof(s->hsBuf));
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_INTERNAL_ERROR);     /* This build's limit */
                return SSF_TLS_IO_ERROR;
            }
            if (avail >= (4u + msgLen))
            {
                *hsType = s->hsBuf[s->hsBufPos];
                *msgOut = &s->hsBuf[s->hsBufPos];
                *bodyLen = msgLen;
                if (addToTranscript) SSFTLSTranscriptUpdate(&s->transcript, *msgOut, 4u + msgLen);
                s->hsBufPos += 4u + msgLen;
                return SSF_TLS_IO_SUCCESS;
            }
        }

        /* No: move the unread bytes to the front, then append the next record's plaintext. */
        if (s->hsBufPos > 0u)
        {
            if (avail > 0u) memmove(s->hsBuf, &s->hsBuf[s->hsBufPos], avail);
            s->hsBufPos = 0;
            s->hsBufLen = avail;
        }
        r = _RecvRecordOnce(s, &s->hsBuf[s->hsBufLen], sizeof(s->hsBuf) - s->hsBufLen, &ptLen,
                            &ct);
        if (r != SSF_TLS_IO_SUCCESS) return r;

        /* A compatibility CCS may come between messages, never inside one: fragments of a     */
        /* message MUST NOT be interleaved with other records (RFC 8446 5.1).                 */
        if (ct == SSF_TLS_CT_CHANGE_CIPHER)
        {
            if (avail == 0u) continue;
            SSF_TLS_TRACE_HS_ERROR(&s->trace, "Record interleaved in a fragmented handshake "
                                   "message");
            _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG);
            return SSF_TLS_IO_ERROR;
        }
        if (ct != SSF_TLS_CT_HANDSHAKE)
        {
            if (ct != SSF_TLS_CT_ALERT) _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG);
            return SSF_TLS_IO_ERROR;
        }
        s->hsBufLen += ptLen;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: true if the record holding the last message ended with it. A message that ends a   */
/* key epoch (ServerHello, HelloRetryRequest, server Finished) must also end its record: the    */
/* next bytes are under different keys (RFC 8446 5.1).                                          */
/* --------------------------------------------------------------------------------------------- */
static bool _HandshakeAtRecordEnd(SSFTLSCSession_t *s, const char *what)
{
    if (s->hsBufPos == s->hsBufLen) return true;
    SSF_TLS_TRACE_HS_ERROR(&s->trace, "%s does not end its record (spans a key change)", what);
    _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns true if host is a literal IP address (no SNI may name it).                  */
/* --------------------------------------------------------------------------------------------- */
static bool _IsIPLiteral(const char *host)
{
    size_t len = 0;
    size_t i;
    uint32_t parts = 0;
    uint32_t digits = 0;
    uint32_t value = 0;
    bool hasColon = false;

    if (!SSFStrLen(host, SSF_TLSC_MAX_HOST_SIZE, &len) || (len == 0u)) return false;

    /* IPv6: a DNS name never contains ':'. Hex digits, ':' and '.' (embedded IPv4), then an    */
    /* optional "%zone" suffix.                                                                  */
    for (i = 0; (i < len) && (host[i] != '%'); i++)
    {
        char c = host[i];

        if (c == ':') { hasColon = true; continue; }
        if (!(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) ||
              ((c >= 'A') && (c <= 'F')) || (c == '.')))
        { hasColon = false; break; }
    }
    if (hasColon) return true;

    /* IPv4: exactly four dot-separated decimal parts of 1-3 digits, each at most 255. */
    for (i = 0; i <= len; i++)
    {
        char c = (i < len) ? host[i] : '.';

        if ((c >= '0') && (c <= '9'))
        {
            if (++digits > 3u) return false;
            value = (value * 10u) + (uint32_t)(c - '0');
        }
        else if ((c == '.') && (digits > 0u) && (value <= 255u))
        {
            parts++;
            digits = 0;
            value = 0;
        }
        else return false;
    }
    return (parts == 4u);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns true if a CertificateVerify scheme can be made with the leaf's key type.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SchemeMatchesKey(uint16_t scheme, SSFTLSCLeafKey_t key)
{
    /* RFC 8446 4.2.3: the ECDSA schemes also fix the curve; rsa_pss_rsae_* need an           */
    /* rsaEncryption key.                                                                       */
    switch (scheme)
    {
    case SSF_TLS_SIG_ECDSA_SECP256R1_SHA256: return (key == SSF_TLSC_LEAF_KEY_P256);
    case SSF_TLS_SIG_ECDSA_SECP384R1_SHA384: return (key == SSF_TLSC_LEAF_KEY_P384);
    case SSF_TLS_SIG_RSA_PSS_RSAE_SHA256:
    case SSF_TLS_SIG_RSA_PSS_RSAE_SHA384:    return (key == SSF_TLSC_LEAF_KEY_RSA);
    case SSF_TLS_SIG_ED25519:                return (key == SSF_TLSC_LEAF_KEY_ED25519);
    default:                                 return false;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns the key type of a parsed certificate (its subject public key).              */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSCLeafKey_t _LeafKeyType(const SSFX509Cert_t *cert)
{
    if (SSFX509IsKeyRSA(cert)) return SSF_TLSC_LEAF_KEY_RSA;
    if (SSFX509IsKeyP256(cert)) return SSF_TLSC_LEAF_KEY_P256;
    if (SSFX509IsKeyP384(cert)) return SSF_TLSC_LEAF_KEY_P384;
    if (SSFX509IsKeyEd25519(cert)) return SSF_TLSC_LEAF_KEY_ED25519;
    return SSF_TLSC_LEAF_KEY_UNKNOWN;
}

/* Maps a private key type to the leaf key type its certificate carries (UNKNOWN for none). */
static SSFTLSCLeafKey_t _PKeyLeafType(SSFPKeyType_t type)
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
bool _SSFTLSCIsIPLiteralForTest(const char *host) { return _IsIPLiteral(host); }
static bool _SaveLeafKey(SSFTLSCSession_t *session, const uint8_t *der, uint32_t derLen);
static uint8_t _ChainAlert(SSFX509VerifyCode_t code);

uint8_t _SSFTLSCChainAlertForTest(SSFX509VerifyCode_t code) { return _ChainAlert(code); }
bool _SSFTLSCSaveLeafKeyForTest(SSFTLSCSession_t *session, const uint8_t *der, uint32_t derLen)
{
    return _SaveLeafKey(session, der, derLen);
}

bool _SSFTLSCSchemeMatchesKeyForTest(uint16_t scheme, SSFTLSCLeafKey_t key)
{
    return _SchemeMatchesKey(scheme, key);
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

static void _WBytes(SSFTLSCWriter_t *w, const void *data, size_t len)
{
    if ((w->ok == false) || (len > (w->cap - w->pos))) { w->ok = false; return; }
    if (len > 0u) memcpy(&w->buf[w->pos], data, len);
    w->pos += len;
}
static void _W8(SSFTLSCWriter_t *w, uint8_t v) { _WBytes(w, &v, 1); }
static void _W16(SSFTLSCWriter_t *w, uint16_t v)
{
    uint8_t b[2];

    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
    _WBytes(w, b, sizeof(b));
}

/* One key share for _BuildClientHello(). */
typedef struct
{
    uint16_t group;
    const uint8_t *pub;
    uint16_t len;
} SSFTLSCKeyShare_t;

/* --------------------------------------------------------------------------------------------- */
/* Internal: builds the ClientHello into s->clientHelloMsg; the only builder, so ClientHello1 and */
/* ClientHello2 cannot drift apart. ClientHello2 passes ClientHello1's random and session id, the */
/* one share the HelloRetryRequest asked for, and its cookie extension_data, which is all RFC     */
/* 8446 4.1.2 lets change. Returns false if the message does not fit.                            */
/* --------------------------------------------------------------------------------------------- */
static bool _BuildClientHello(SSFTLSCSession_t *s, const uint8_t random[32], const uint8_t *sid,
                              uint8_t sidLen, const SSFTLSCKeyShare_t *shares, uint8_t shareCount,
                              const uint8_t *cookieExtOpt, uint16_t cookieExtLen)
{
    SSFTLSCWriter_t w;
    size_t extLenPos;
    size_t ksLen = 0;
    size_t hostLen = 0;
    uint8_t i;

    SSF_REQUIRE(sidLen <= 32u);
    SSF_REQUIRE((cookieExtOpt != NULL) || (cookieExtLen == 0u));
    for (i = 0; i < shareCount; i++) ksLen += 4u + shares[i].len;
    (void)SSFStrLen(s->host, sizeof(s->host), &hostLen);     /* Validated by open() */

    w.buf = s->clientHelloMsg;
    w.cap = sizeof(s->clientHelloMsg);
    w.pos = 0;
    w.ok = true;

    _W8(&w, SSF_TLS_HS_CLIENT_HELLO);
    _W8(&w, 0); _W16(&w, 0);                                  /* Length, patched below */
    _W16(&w, SSF_TLS_VERSION_12);                            /* legacy_version */
    _WBytes(&w, random, 32);
    _W8(&w, sidLen);
    _WBytes(&w, sid, sidLen);
    /* cipher_suites, in preference order. ChaCha20-Poly1305 first: ssfchacha20 is constant-time */
    /* while ssfaes (under AES-GCM and AES-CCM) is not, and it is fast without AES hardware.     */
    /* Then AES-128-GCM (mandatory to implement; SHA-256 is cheaper than SHA-384 on 32-bit       */
    /* cores), AES-256-GCM, AES-128-CCM.                                                         */
    _W16(&w, 8);
    _W16(&w, SSF_TLS_CS_CHACHA20_POLY1305_SHA256);
    _W16(&w, SSF_TLS_CS_AES_128_GCM_SHA256);
    _W16(&w, SSF_TLS_CS_AES_256_GCM_SHA384);
    _W16(&w, SSF_TLS_CS_AES_128_CCM_SHA256);
    _W8(&w, 1); _W8(&w, 0);                                  /* legacy_compression_methods */
    extLenPos = w.pos;
    _W16(&w, 0);                                             /* Extensions length, patched */

    _W16(&w, SSF_TLS_EXT_SUPPORTED_VERSIONS);                /* TLS 1.3 only */
    _W16(&w, 3); _W8(&w, 2); _W16(&w, SSF_TLS_VERSION_13);

    _W16(&w, SSF_TLS_EXT_SUPPORTED_GROUPS);
    _W16(&w, 8); _W16(&w, 6);
    _W16(&w, SSF_TLS_GROUP_X25519);
    _W16(&w, SSF_TLS_GROUP_SECP256R1);
    _W16(&w, SSF_TLS_GROUP_SECP384R1);

    _W16(&w, SSF_TLS_EXT_SIGNATURE_ALGS);
    _W16(&w, 16); _W16(&w, 14);
    _W16(&w, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256);
    _W16(&w, SSF_TLS_SIG_ECDSA_SECP384R1_SHA384);
    _W16(&w, SSF_TLS_SIG_RSA_PSS_RSAE_SHA256);
    _W16(&w, SSF_TLS_SIG_RSA_PSS_RSAE_SHA384);
    /* rsa_pkcs1_*: certificate signatures only, never accepted in CertificateVerify */
    _W16(&w, SSF_TLS_SIG_RSA_PKCS1_SHA256);
    _W16(&w, SSF_TLS_SIG_RSA_PKCS1_SHA384);
    _W16(&w, SSF_TLS_SIG_ED25519);

    _W16(&w, SSF_TLS_EXT_KEY_SHARE);
    _W16(&w, (uint16_t)(2u + ksLen)); _W16(&w, (uint16_t)ksLen);
    for (i = 0; i < shareCount; i++)
    {
        _W16(&w, shares[i].group);
        _W16(&w, shares[i].len);
        _WBytes(&w, shares[i].pub, shares[i].len);
    }

    _W16(&w, SSF_TLS_EXT_PSK_KEY_EXCHANGE);                  /* psk_dhe_ke, for servers that */
    _W16(&w, 2); _W8(&w, 1); _W8(&w, 1);                     /* insist on it                 */

    /* record_size_limit (RFC 8449 4): the receive buffer's TLSInnerPlaintext size, always sent */
    /* ("SHOULD advertise ... even if they have no need to limit"). Identical in ClientHello2.  */
    _W16(&w, SSF_TLSC_EXT_RECORD_SIZE_LIMIT);
    _W16(&w, 2); _W16(&w, (uint16_t)(SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u));

    if (cookieExtOpt != NULL)                                /* Echoed unchanged (4.2.2) */
    {
        _W16(&w, 44u);
        _W16(&w, cookieExtLen);
        _WBytes(&w, cookieExtOpt, cookieExtLen);
    }

    /* server_name (RFC 6066 3): "Literal IPv4 and IPv6 addresses are not permitted". */
    if ((hostLen > 0u) && !_IsIPLiteral(s->host))
    {
        _W16(&w, SSF_TLS_EXT_SERVER_NAME);
        _W16(&w, (uint16_t)(5u + hostLen)); _W16(&w, (uint16_t)(3u + hostLen));
        _W8(&w, 0);
        _W16(&w, (uint16_t)hostLen);
        _WBytes(&w, s->host, hostLen);
    }

    if ((w.ok == false) || ((w.pos - extLenPos - 2u) > 0xffffu)) return false;
    _Put16(&w.buf[extLenPos], (uint16_t)(w.pos - extLenPos - 2u));
    _Put24(&w.buf[1], (uint32_t)(w.pos - 4u));
    s->clientHelloLen = w.pos;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns the exact key_exchange length for a group's key share, else 0.              */
/* --------------------------------------------------------------------------------------------- */
static uint16_t _KeyShareLen(uint16_t group)
{
    if (group == SSF_TLS_GROUP_X25519) return 32u;
    if (group == SSF_TLS_GROUP_SECP256R1) return 65u;    /* Uncompressed SEC 1 point */
    if (group == SSF_TLS_GROUP_SECP384R1) return 97u;
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns true if the latest ClientHello carried a key share for group.               */
/* ClientHello1 carries X25519 and secp384r1; ClientHello2 only the group the HRR selected.      */
/* --------------------------------------------------------------------------------------------- */
static bool _KeyShareOffered(const SSFTLSCSession_t *s, uint16_t group)
{
    if (s->hrrDone) return (group == s->hrrGroup);
    return (group == SSF_TLS_GROUP_X25519) || (group == SSF_TLS_GROUP_SECP384R1);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: returns true if group is in the ClientHello supported_groups list.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _GroupSupported(uint16_t group)
{
    return (group == SSF_TLS_GROUP_X25519) || (group == SSF_TLS_GROUP_SECP256R1) ||
           (group == SSF_TLS_GROUP_SECP384R1);
}

#define _SSF_TLSC_SH_REJECT(s, what, alert) do { \
    SSF_TLS_TRACE_HS_ERROR(&(s)->trace, "ServerHello rejected: %s%s", (what), \
                           isHrr ? " (HelloRetryRequest)" : ""); \
    _SSF_TLSC_ALERT((s), (alert)); \
    return false; } while (0)

/* --------------------------------------------------------------------------------------------- */
/* Internal: validates and parses a ServerHello or HelloRetryRequest body (RFC 8446 4.1.3,       */
/* 4.1.4, 4.2). Sets the negotiated suite and hash. For a ServerHello returns the server key     */
/* share; for an HRR returns the selected group and any cookie (pointing into body). Returns     */
/* false, with a trace, on anything the RFC requires a client to abort on.                       */
/* --------------------------------------------------------------------------------------------- */
static bool _ParseServerHello(SSFTLSCSession_t *s, const uint8_t *body, size_t bodyLen,
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

    if (serverPubKeyLen != NULL) *serverPubKeyLen = 0;
    if (cookieOut != NULL) *cookieOut = NULL;
    if (cookieLenOut != NULL) *cookieLenOut = 0;
    *serverGroup = 0;

    /* legacy_version (ignored when supported_versions is present, 4.2.1) + random */
    if (bodyLen < 2u + 32u + 1u) _SSF_TLSC_SH_REJECT(s, "too short", SSF_TLS_ALERT_DECODE_ERROR);
    pos = 2u + 32u;

    /* legacy_session_id_echo MUST equal the ClientHello legacy_session_id (4.1.3) */
    sidLen = body[pos++];
    chSidLen = s->clientHelloMsg[38];
    chSid = &s->clientHelloMsg[39];
    if ((sidLen > 32u) || (pos + sidLen > bodyLen))
    { _SSF_TLSC_SH_REJECT(s, "session id length", SSF_TLS_ALERT_DECODE_ERROR); }
    if ((sidLen != chSidLen) || (memcmp(&body[pos], chSid, sidLen) != 0))
    { _SSF_TLSC_SH_REJECT(s, "session id echo mismatch", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
    pos += sidLen;

    /* cipher_suite: one we can run; after an HRR, the one the HRR chose (4.1.4) */
    if (pos + 2u + 1u + 2u > bodyLen)
    { _SSF_TLSC_SH_REJECT(s, "truncated", SSF_TLS_ALERT_DECODE_ERROR); }
    cs = _Get16(&body[pos]); pos += 2;
    switch (cs)
    {
    case SSF_TLS_CS_AES_128_GCM_SHA256:
        s->hash = SSF_HMAC_HASH_SHA256; s->hashLen = 32; s->keyLen = 16; break;
    case SSF_TLS_CS_AES_256_GCM_SHA384:
        s->hash = SSF_HMAC_HASH_SHA384; s->hashLen = 48; s->keyLen = 32; break;
    case SSF_TLS_CS_CHACHA20_POLY1305_SHA256:
        s->hash = SSF_HMAC_HASH_SHA256; s->hashLen = 32; s->keyLen = 32; break;
    case SSF_TLS_CS_AES_128_CCM_SHA256:        /* Record layer: ssftls / ssfaesccm, 16-byte tag */
        s->hash = SSF_HMAC_HASH_SHA256; s->hashLen = 32; s->keyLen = 16; break;
    default:                                   /* Not offered (4.1.3) */
        _SSF_TLSC_SH_REJECT(s, "cipher suite", SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    }
    if (s->hrrDone && (cs != s->hrrSuite))
    { _SSF_TLSC_SH_REJECT(s, "cipher suite changed after HRR", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
    s->cipherSuite = cs;

    /* legacy_compression_method MUST be 0 (4.1.3) */
    if (body[pos++] != 0u)
    { _SSF_TLSC_SH_REJECT(s, "compression method", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }

    /* extensions: the list must fill the rest of the body exactly */
    extEnd = pos + 2u + _Get16(&body[pos]);
    pos += 2;
    if (extEnd != bodyLen) _SSF_TLSC_SH_REJECT(s, "extensions length", SSF_TLS_ALERT_DECODE_ERROR);

    while (pos < extEnd)
    {
        uint16_t eType;
        uint16_t eLen;

        if (pos + 4u > extEnd)
        { _SSF_TLSC_SH_REJECT(s, "extension header", SSF_TLS_ALERT_DECODE_ERROR); }
        eType = _Get16(&body[pos]);
        eLen = _Get16(&body[pos + 2u]);
        pos += 4;
        if (pos + eLen > extEnd)
        { _SSF_TLSC_SH_REJECT(s, "extension length", SSF_TLS_ALERT_DECODE_ERROR); }

        if (eType == SSF_TLS_EXT_SUPPORTED_VERSIONS)
        {
            /* Selected version: exactly TLS 1.3 (4.2.1) */
            if (hasVersions)
            { _SSF_TLSC_SH_REJECT(s, "duplicate supported_versions",
                                  SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
            hasVersions = true;
            if ((eLen != 2u) || (_Get16(&body[pos]) != SSF_TLS_VERSION_13))
            { _SSF_TLSC_SH_REJECT(s, "supported_versions is not TLS 1.3",
                                  SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
        }
        else if (eType == SSF_TLS_EXT_KEY_SHARE)
        {
            uint16_t group;

            if (hasKeyShare)
            { _SSF_TLSC_SH_REJECT(s, "duplicate key_share", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
            hasKeyShare = true;
            if (eLen < 2u) _SSF_TLSC_SH_REJECT(s, "key_share length", SSF_TLS_ALERT_DECODE_ERROR);
            group = _Get16(&body[pos]);
            if (isHrr)
            {
                /* HRR: selected_group only. It MUST be in supported_groups and MUST NOT be a  */
                /* group the ClientHello already carried a share for (4.2.8).                  */
                if (eLen != 2u)
                { _SSF_TLSC_SH_REJECT(s, "key_share length", SSF_TLS_ALERT_DECODE_ERROR); }
                if (!_GroupSupported(group))
                { _SSF_TLSC_SH_REJECT(s, "group not offered", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
                if (_KeyShareOffered(s, group))
                { _SSF_TLSC_SH_REJECT(s, "group already has a key share",
                                      SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
            }
            else
            {
                /* ServerHello: one share, for a group the ClientHello sent a share for, with  */
                /* exactly that group's key length (4.2.8).                                    */
                uint16_t kLen;

                if (eLen < 4u)
                { _SSF_TLSC_SH_REJECT(s, "key_share length", SSF_TLS_ALERT_DECODE_ERROR); }
                kLen = _Get16(&body[pos + 2u]);
                if (eLen != 4u + kLen)
                { _SSF_TLSC_SH_REJECT(s, "key_share length", SSF_TLS_ALERT_DECODE_ERROR); }
                if (!_KeyShareOffered(s, group))
                { _SSF_TLSC_SH_REJECT(s, "group not offered", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
                if (kLen != _KeyShareLen(group))
                { _SSF_TLSC_SH_REJECT(s, "key share size", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
                if (serverPubKey != NULL) memcpy(serverPubKey, &body[pos + 4u], kLen);
                if (serverPubKeyLen != NULL) *serverPubKeyLen = kLen;
            }
            *serverGroup = group;
        }
        else if (isHrr && (eType == 44u))         /* cookie (4.2.2) */
        {
            if (hasCookie)
            { _SSF_TLSC_SH_REJECT(s, "duplicate cookie", SSF_TLS_ALERT_ILLEGAL_PARAMETER); }
            hasCookie = true;
            if ((eLen < 3u) || (_Get16(&body[pos]) != (uint16_t)(eLen - 2u)))
            { _SSF_TLSC_SH_REJECT(s, "cookie length", SSF_TLS_ALERT_DECODE_ERROR); }
            if (cookieOut != NULL) *cookieOut = &body[pos];   /* Whole extension_data */
            if (cookieLenOut != NULL) *cookieLenOut = eLen;
        }
        else
        {
            /* Anything else, pre_shared_key included (no PSK is offered), was not requested */
            /* and MUST be rejected with unsupported_extension (4.2).                         */
            _SSF_TLSC_SH_REJECT(s, "unsolicited extension", SSF_TLS_ALERT_UNSUPPORTED_EXT);
        }
        pos += eLen;
    }

    if (!hasVersions)
    { _SSF_TLSC_SH_REJECT(s, "missing supported_versions", SSF_TLS_ALERT_PROTOCOL_VERSION); }
    if (!hasKeyShare)                          /* No PSK-only mode */
    { _SSF_TLSC_SH_REJECT(s, "missing key_share", SSF_TLS_ALERT_MISSING_EXTENSION); }
    return true;
}

#undef _SSF_TLSC_SH_REJECT

/* --------------------------------------------------------------------------------------------- */
/* Internal: complete the key exchange and derive handshake traffic keys.                        */
/* --------------------------------------------------------------------------------------------- */
static bool _DeriveHandshakeKeys(SSFTLSCSession_t *s,
                                 const uint8_t *serverPubKey, size_t serverPubKeyLen,
                                 uint16_t serverGroup)
{
    uint8_t sharedSecret[48]; /* max for P-384 */
    size_t sharedLen = 0;
    uint8_t ecdhSecret[SSF_ECDH_MAX_SECRET_SIZE];
    uint8_t earlySecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t derivedSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t handshakeSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t emptyHash[SSF_TLS_MAX_HASH_SIZE];
    uint8_t transcriptHash[SSF_TLS_MAX_HASH_SIZE];
    uint8_t zeroPSK[SSF_TLS_MAX_HASH_SIZE];
    uint8_t zeroIKM[SSF_TLS_MAX_HASH_SIZE];
    uint8_t key[SSF_TLS_MAX_KEY_SIZE], iv[SSF_TLS_IV_SIZE];
    bool ok = false;

    /* Complete key exchange */
    if (serverGroup == SSF_TLS_GROUP_X25519)
    {
        if (!SSFX25519ComputeSecret(s->ephemeralPrivKey, serverPubKey, sharedSecret)) goto done;
        sharedLen = 32;
    }
    else if (serverGroup == SSF_TLS_GROUP_SECP256R1 || serverGroup == SSF_TLS_GROUP_SECP384R1)
    {
        SSFECCurve_t curve = (serverGroup == SSF_TLS_GROUP_SECP256R1) ?
                              SSF_EC_CURVE_P256 : SSF_EC_CURVE_P384;
        const SSFECCurveParams_t *cp = SSFECGetCurveParams(curve);
        size_t secretLen;
        /* P-384 private key is at ephemeralPrivKey[32] (after X25519 key at [0]) */
        /* P-256 private key would be at ephemeralPrivKey[0] (in HRR case) */
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
        SSF_TLS_TRACE_CRYPTO_ERROR(&s->trace, "Unsupported key exchange group 0x%04x",
                                   serverGroup);
        goto done;
    }

    /* Hash("") for deriving the "derived" secret */
    {
        SSFTLSTranscript_t tmp;
        SSFTLSTranscriptInit(&tmp, s->hash);
        SSFTLSTranscriptHash(&tmp, emptyHash, sizeof(emptyHash));
    }

    /* Early Secret = HKDF-Extract(0, 0) -- no PSK */
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
    _RecordStateSet(s, &s->recvState, &s->recvStateInited, key, iv);
    s->recvEncrypted = true;

    /* Client handshake traffic keys protect everything the client sends from here on: its     */
    /* Finished and any alert (RFC 8446 6, 7.3).                                               */
    SSFTLSDeriveTrafficKeys(s->hash, s->clientHsTrafficSecret, s->hashLen,
                            key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    _RecordStateSet(s, &s->sendState, &s->sendStateInited, key, iv);
    s->sendEncrypted = true;

    /* Save handshake secret for later master secret derivation */
    memcpy(s->savedHandshakeSecret, handshakeSecret, s->hashLen);
    ok = true;

done:
    /* Every path: the ephemeral private keys are spent (one ECDH attempt per handshake), and  */
    /* no intermediate of the key schedule outlives this function.                              */
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
/* Internal: derive application traffic keys from master secret.                                 */
/* --------------------------------------------------------------------------------------------- */
static bool _DeriveAppKeys(SSFTLSCSession_t *s, const uint8_t *handshakeSecret)
{
    uint8_t emptyHash[SSF_TLS_MAX_HASH_SIZE];
    uint8_t derivedSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t masterSecret[SSF_TLS_MAX_HASH_SIZE];
    uint8_t zeroIKM[SSF_TLS_MAX_HASH_SIZE];
    uint8_t transcriptHash[SSF_TLS_MAX_HASH_SIZE];
    uint8_t key[SSF_TLS_MAX_KEY_SIZE], iv[SSF_TLS_IV_SIZE];

    /* Hash("") */
    {
        SSFTLSTranscript_t tmp;
        SSFTLSTranscriptInit(&tmp, s->hash);
        SSFTLSTranscriptHash(&tmp, emptyHash, sizeof(emptyHash));
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

    /* Set up server application traffic keys for receiving.                                       */
    /* Client send keys are set up separately after sending client Finished.                      */
    SSFTLSDeriveTrafficKeys(s->hash, s->serverAppTrafficSecret, s->hashLen,
                            key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    _RecordStateSet(s, &s->recvState, &s->recvStateInited, key, iv);

    _SSF_TLSC_SCRUB(derivedSecret);
    _SSF_TLSC_SCRUB(masterSecret);
    _SSF_TLSC_SCRUB(key);
    _SSF_TLSC_SCRUB(iv);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Set trace callback for a TLS client session.                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSCSetTrace(SSFTLSCSession_t *session, SSFTLSTraceFn_t traceFn, void *traceCtx)
{
    SSF_REQUIRE(session != NULL);
    session->trace.fn = traceFn;
    session->trace.userCtx = traceCtx;
}

/* --------------------------------------------------------------------------------------------- */
/* Crypto step: derive handshake keys (ECDH + HKDF).                                             */
/* --------------------------------------------------------------------------------------------- */
static void _TLSCDeriveHSKeysWork(void *ctx)
{
    SSFTLSCCryptoWork_t *w = (SSFTLSCCryptoWork_t *)ctx;
    w->keyExchangeOk = _DeriveHandshakeKeys(w->session, w->serverPubKey,
                                             (size_t)w->serverPubKeyLen, w->serverGroup);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: the RFC 8446 6.2 alert for a failed chain verification. A host name the certificate */
/* does not name is bad_certificate, as OpenSSL and GnuTLS clients send.                         */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _ChainAlert(SSFX509VerifyCode_t code)
{
    SSF_REQUIRE((code > SSF_X509_VERIFY_OK) && (code < SSF_X509_VERIFY_MAX));

    switch (code)
    {
    case SSF_X509_VERIFY_ERR_VERSION:
    case SSF_X509_VERIFY_ERR_CRITICAL_EXT:
        return SSF_TLS_ALERT_UNSUPPORTED_CERTIFICATE;  /* "a certificate of an unsupported type" */
    case SSF_X509_VERIFY_ERR_NOT_YET_VALID:
    case SSF_X509_VERIFY_ERR_EXPIRED:
        return SSF_TLS_ALERT_CERTIFICATE_EXPIRED;      /* "expired or is not currently valid" */
    case SSF_X509_VERIFY_ERR_UNKNOWN_CA:
        return SSF_TLS_ALERT_UNKNOWN_CA;               /* "CA certificate could not be located" */
    case SSF_X509_VERIFY_ERR_NOT_CA:
    case SSF_X509_VERIFY_ERR_CA_KEY_USAGE:
    case SSF_X509_VERIFY_ERR_PATH_LEN:
    case SSF_X509_VERIFY_ERR_NAME_CONSTRAINTS:
    case SSF_X509_VERIFY_ERR_EKU:
    case SSF_X509_VERIFY_ERR_LEAF_KEY_USAGE:
        return SSF_TLS_ALERT_CERTIFICATE_UNKNOWN;      /* Valid, but CA or usage rules refuse it */
    default:
        return SSF_TLS_ALERT_BAD_CERTIFICATE;          /* Corrupt, does not verify, wrong host */
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Crypto step: verify certificate chain.                                                        */
/* --------------------------------------------------------------------------------------------- */
static void _TLSCVerifyChainWork(void *ctx)
{
    SSFTLSCCryptoWork_t *w = (SSFTLSCCryptoWork_t *)ctx;
    w->chainVerifyOk = SSFX509VerifyChain(w->chainDerPtrs, w->chainDerLens, w->chainLen,
                                           w->session->trust.caDer,
                                           w->session->trust.caDerLen,
                                           w->session->trust.count,
                                           w->hostname, w->nowUnixSec, &w->chainVerifyErr);
}

/* --------------------------------------------------------------------------------------------- */
/* Crypto step: verify CertificateVerify signature.                                              */
/* --------------------------------------------------------------------------------------------- */
static void _TLSCVerifySigWork(void *ctx)
{
    SSFTLSCCryptoWork_t *w = (SSFTLSCCryptoWork_t *)ctx;
    bool verified = false;

    if (w->sigScheme == SSF_TLS_SIG_ECDSA_SECP256R1_SHA256)
    {
        verified = SSFECDSAVerify(SSF_EC_CURVE_P256, w->leafPubKey, (size_t)w->leafPubKeyLen,
                                  w->contentHash, 32, w->sigData, (size_t)w->sigDataLen);
    }
    else if (w->sigScheme == SSF_TLS_SIG_ECDSA_SECP384R1_SHA384)
    {
        verified = SSFECDSAVerify(SSF_EC_CURVE_P384, w->leafPubKey, (size_t)w->leafPubKeyLen,
                                  w->contentHash, 48, w->sigData, (size_t)w->sigDataLen);
    }
    else if (w->sigScheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA256)
    {
        verified = SSFRSAVerifyPSS(w->leafPubKey, (size_t)w->leafPubKeyLen,
                                   SSF_RSA_HASH_SHA256,
                                   w->contentHash, 32, 32u, /* salt = hash length (RFC 8446) */
                                   w->sigData, (size_t)w->sigDataLen);
    }
    else if (w->sigScheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA384)
    {
        verified = SSFRSAVerifyPSS(w->leafPubKey, (size_t)w->leafPubKeyLen,
                                   SSF_RSA_HASH_SHA384,
                                   w->contentHash, 48, 48u, /* salt = hash length (RFC 8446) */
                                   w->sigData, (size_t)w->sigDataLen);
    }
    /* rsa_pkcs1_* is never verified here: not a TLS 1.3 handshake signature (RFC 8446 4.2.3) */
    else if (w->sigScheme == SSF_TLS_SIG_ED25519)
    {
        /* Ed25519 verifies over the raw sign content stored in contentHash.                    */
        if (w->leafPubKeyLen == SSF_ED25519_PUB_KEY_SIZE &&
            w->sigDataLen == SSF_ED25519_SIG_SIZE)
        {
            verified = SSFEd25519Verify(w->leafPubKey, w->contentHash, w->contentHashLen,
                                         w->sigData);
        }
    }
    w->sigVerifyOk = verified;
}

/* --------------------------------------------------------------------------------------------- */
/* Handshake state machine.                                                                      */
/* Each active-state helper runs one contiguous section of the handshake up to a crypto step (or */
/* to completion for the final step), resuming through helperStep on WANT_READ / WANT_WRITE. The */
/* driver then runs the crypto step on the next pollOpen() call, so no call does both I/O and a  */
/* public-key operation.                                                                         */
/* --------------------------------------------------------------------------------------------- */

/* State SEND_CH: await inner connect, send CH, recv SH (incl. HRR), parse; ECDH+HKDF follows.  */
/* RFC 8446 Section 4.1.3: HelloRetryRequest sentinel random. Used by case 4 for HRR detection */
/* and by case 11 to reject a double HRR.                                                       */
static const uint8_t _TlscHrrSentinel[32] = {
    0xCFu, 0x21u, 0xADu, 0x74u, 0xE5u, 0x9Au, 0x61u, 0x11u,
    0xBEu, 0x1Du, 0x8Cu, 0x02u, 0x1Eu, 0x65u, 0xB8u, 0x91u,
    0xC2u, 0xA2u, 0x11u, 0x16u, 0x7Au, 0xBBu, 0x8Cu, 0x5Eu,
    0x07u, 0x9Eu, 0x09u, 0xE2u, 0xC8u, 0xA8u, 0x33u, 0x9Cu
};

/* Resumable state machine. Substates:                                                           */
/*   0: entry — wait for the inner transport to connect + transcript init, advance to 1         */
/*   1: build ClientHello into session->clientHelloMsg + transcript update (non-idempotent)      */
/*   2: send ClientHello record                                                                   */
/*   3: send CCS record (middlebox compat)                                                        */
/*   4: recv ServerHello + HRR detect; non-HRR → parse + SHA-384 reinit + stash into cryptoWork  */
/*      → case 20. HRR → parse HRR + synthetic transcript reinit + build CH2 into clientHelloMsg */
/*      + transcript update → case 10.                                                            */
/*   10: (HRR) send CH2 record                                                                    */
/*   11: (HRR) recv second ServerHello + reject double-HRR + parse + stash → case 20             */
/*   20: done; the driver runs the ECDH + HKDF step next                                         */
/* Substate transitions use for-loop + switch + continue to jump between non-adjacent cases.     */
static SSFTLSIOResult_t _TlscHandleSendCH(SSFTLSCSession_t *session)
{
    uint8_t *buf = session->hsBuf;             /* ServerHello / HRR record, in place */
    uint8_t serverPubKey[97]; /* max SEC1 P-384 */
    size_t serverPubKeyLen = 0;
    uint16_t serverGroup = 0;
    SSFTLSIOResult_t r;

    if (session->helperStep == 0)
    {
        /* Wait for the inner transport opened by open() to connect. */
        SSFNetIOResult_t ir = session->inner->pollOpen(session->inner);

        if ((ir == SSF_NET_IO_WANT_READ) || (ir == SSF_NET_IO_WANT_WRITE))
        { return SSF_TLS_IO_WANT_READ; }
        if (ir != SSF_NET_IO_SUCCESS)
        {
            if (ir == SSF_NET_IO_CLOSED) session->peerClosed = true;
            session->ioFailed = true;
            SSF_TLS_TRACE_HS_ERROR(&session->trace, "Inner transport open failed");
            return SSF_TLS_IO_ERROR;
        }

        /* Connected: initialize the handshake transcript and build the ClientHello. */
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
            /* Build ClientHello1. Non-idempotent (fresh random, session id and ephemeral keys):  */
            /* runs once, then advances.                                                          */
            uint8_t random[32];
            uint8_t sid[32];
            uint8_t x25519Pub[32];
            uint8_t ecPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            uint8_t ecPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t ecPubLen;
            SSFTLSCKeyShare_t shares[2];

            SSF_TLS_TRACE_HS_INFO(&session->trace, "Sending ClientHello to %.200s", session->host);
            if (!_GetEntropy(random, sizeof(random)) || !_GetEntropy(sid, sizeof(sid)) ||
                !_GetEntropy(session->ephemeralPrivKey, 32))
            { return SSF_TLS_IO_ERROR; }
            SSFX25519PubKeyFromPrivKey(session->ephemeralPrivKey, x25519Pub);
            if (!SSFECDSAKeyGen(SSF_EC_CURVE_P384, ecPriv, sizeof(ecPriv),
                                ecPub, sizeof(ecPub), &ecPubLen))
            { return SSF_TLS_IO_ERROR; }
            memcpy(&session->ephemeralPrivKey[32], ecPriv, 48);
            _SSF_TLSC_SCRUB(ecPriv);

            /* X25519 and secp384r1 shares: avoids a HelloRetryRequest from most servers */
            shares[0].group = SSF_TLS_GROUP_X25519;
            shares[0].pub = x25519Pub;
            shares[0].len = 32u;
            shares[1].group = SSF_TLS_GROUP_SECP384R1;
            shares[1].pub = ecPub;
            shares[1].len = (uint16_t)ecPubLen;
            if (!_BuildClientHello(session, random, sid, (uint8_t)sizeof(sid), shares, 2u,
                                   NULL, 0u))
            {
                SSF_TLS_TRACE_HS_ERROR(&session->trace, "ClientHello does not fit clientHelloMsg");
                return SSF_TLS_IO_ERROR;
            }
            SSFTLSTranscriptUpdate(&session->transcript, session->clientHelloMsg,
                                   session->clientHelloLen);
            session->helperStep = 2;
        }
        /* fall through */
        case 2:
            r = _SendPlainRecordOnce(session, SSF_TLS_CT_HANDSHAKE,
                                     session->clientHelloMsg, session->clientHelloLen);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            session->clientHelloSent = true;
            session->helperStep = 3;
            /* fall through */
        case 3:
        {
            uint8_t ccs = 0x01u;
            r = _SendPlainRecordOnce(session, SSF_TLS_CT_CHANGE_CIPHER, &ccs, 1);
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

            /* ServerHello or HelloRetryRequest, reassembled if fragmented; the transcript is    */
            /* handled below (HelloRetryRequest message_hash rule, SHA-384 re-init).             */
            r = _RecvHandshakeOnce(session, &msg, &bodyLen, &hsType, false);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            if (hsType != SSF_TLS_HS_SERVER_HELLO)
            { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Not ServerHello: type=%u", hsType);
              _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }
            if (!_HandshakeAtRecordEnd(session, "ServerHello")) return SSF_TLS_IO_ERROR;
            buf = (uint8_t *)msg;                 /* In hsBuf: header + body */
            ptLen = 4u + bodyLen;

            /* HRR detection (RFC 8446 4.1.4) */
            if (ptLen >= 38u && memcmp(&buf[6], _TlscHrrSentinel, 32) == 0)
            {
                /* === HRR branch: all non-idempotent work runs here, then jumps to case 10. === */
                uint16_t hrrGroup = 0;
                uint16_t hrrSuite;
                SSFHMACHash_t hrrHash;
                const uint8_t *hrrCookie = NULL;
                uint16_t hrrCookieLen = 0;

                SSF_TLS_TRACE_HS_INFO(&session->trace, "HelloRetryRequest received");

                if (!_ParseServerHello(session, &buf[4], ptLen - 4u, true, NULL, NULL, &hrrGroup,
                                       &hrrCookie, &hrrCookieLen))
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

                    if (hrrHash != SSF_HMAC_HASH_SHA256)
                    {
                        SSFTLSTranscript_t tmpT;
                        SSFTLSTranscriptInit(&tmpT, hrrHash);
                        SSFTLSTranscriptUpdate(&tmpT, session->clientHelloMsg,
                                               session->clientHelloLen);
                        SSFTLSTranscriptHash(&tmpT, ch1Hash, sizeof(ch1Hash));
                    }
                    else
                    {
                        SSFTLSTranscriptHash(&session->transcript, ch1Hash, sizeof(ch1Hash));
                    }

                    synthMsg[0] = 254u;
                    _Put24(&synthMsg[1], hLen);
                    memcpy(&synthMsg[4], ch1Hash, hLen);

                    SSFTLSTranscriptInit(&session->transcript, hrrHash);
                    session->hashLen = hLen;
                    SSFTLSTranscriptUpdate(&session->transcript, synthMsg, 4u + hLen);
                    SSFTLSTranscriptUpdate(&session->transcript, buf, ptLen);
                }

                /* ClientHello2 is ClientHello1 with key_share replaced by the selected group and */
                /* the cookie added; random and session id stay the same (RFC 8446 4.1.2).        */
                if (hrrGroup == SSF_TLS_GROUP_SECP256R1 ||
                         hrrGroup == SSF_TLS_GROUP_SECP384R1)
                {
                    SSFECCurve_t curve = (hrrGroup == SSF_TLS_GROUP_SECP256R1) ?
                                          SSF_EC_CURVE_P256 : SSF_EC_CURVE_P384;
                    uint8_t ecPriv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
                    uint8_t ecPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
                    size_t ecPubLen;
                    const SSFECCurveParams_t *cp = SSFECGetCurveParams(curve);
                    uint8_t random[32];
                    uint8_t sid[32];
                    uint8_t sidLen = session->clientHelloMsg[38];
                    SSFTLSCKeyShare_t share;

                    if (!SSFECDSAKeyGen(curve, ecPriv, sizeof(ecPriv),
                                        ecPub, sizeof(ecPub), &ecPubLen))
                    { SSF_TLS_TRACE_CRYPTO_ERROR(&session->trace, "HRR: ECDH key gen failed");
                      return SSF_TLS_IO_ERROR; }

                    memcpy(session->ephemeralPrivKey, ecPriv, cp->bytes);
                    _SSF_TLSC_SCRUB(ecPriv);

                    /* clientHelloMsg is rebuilt in place, so take ClientHello1's values first. */
                    memcpy(random, &session->clientHelloMsg[6], sizeof(random));
                    memcpy(sid, &session->clientHelloMsg[39], sidLen);
                    share.group = hrrGroup;
                    share.pub = ecPub;
                    share.len = (uint16_t)ecPubLen;
                    if (!_BuildClientHello(session, random, sid, sidLen, &share, 1u,
                                           hrrCookie, hrrCookieLen))
                    {
                        /* Never send ClientHello2 without the cookie: the server must reject it. */
                        SSF_TLS_TRACE_HS_ERROR(&session->trace,
                                               "HRR: ClientHello2 does not fit (cookie %u bytes)",
                                               hrrCookieLen);
                        _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_INTERNAL_ERROR);
                        return SSF_TLS_IO_ERROR;
                    }
                    SSFTLSTranscriptUpdate(&session->transcript, session->clientHelloMsg,
                                           session->clientHelloLen);

                    SSF_TLS_TRACE_HS_INFO(&session->trace,
                                          "HRR: ClientHello2 built with group 0x%04x", hrrGroup);
                    session->helperStep = 10;
                    continue;
                }
                else
                {
                    SSF_TLS_TRACE_HS_ERROR(&session->trace, "HRR: unsupported group 0x%04x",
                                           hrrGroup);
                    return SSF_TLS_IO_ERROR;
                }
            }

            /* === Non-HRR branch: parse SH, optionally SHA-384 reinit, stash into cryptoWork, */
            /* jump to case 20 for dispatch.                                                   */
            SSFTLSTranscriptUpdate(&session->transcript, buf, ptLen);

            if (!_ParseServerHello(session, &buf[4], ptLen - 4u, false,
                                   serverPubKey, &serverPubKeyLen, &serverGroup, NULL, NULL))
            { return SSF_TLS_IO_ERROR; }
            SSF_TLS_TRACE_HS_INFO(&session->trace,
                                  "ServerHello: suite=0x%04x group=0x%04x keyLen=%zu",
                                  session->cipherSuite, serverGroup, serverPubKeyLen);

            if (session->hash == SSF_HMAC_HASH_SHA384)
            {
                SSF_TLS_TRACE_CRYPTO_INFO(&session->trace,
                                          "Re-initializing transcript for SHA-384 (CH=%zu SH=%zu)",
                                          session->clientHelloLen, ptLen);
                if (session->clientHelloLen == 0)
                { SSF_TLS_TRACE_HS_ERROR(&session->trace,
                                         "ERROR: ClientHello was not saved (too large for buffer)");
                  return SSF_TLS_IO_ERROR; }
                SSFTLSTranscriptInit(&session->transcript, SSF_HMAC_HASH_SHA384);
                SSFTLSTranscriptUpdate(&session->transcript,
                                       session->clientHelloMsg, session->clientHelloLen);
                SSFTLSTranscriptUpdate(&session->transcript, buf, ptLen);
            }

            /* Stash parse results into cryptoWork (session-lifetime — survives to case 20). */
            session->cryptoWork.session = session;
            memcpy(session->cryptoWork.serverPubKey, serverPubKey, serverPubKeyLen);
            session->cryptoWork.serverPubKeyLen = (uint8_t)serverPubKeyLen;
            session->cryptoWork.serverGroup = serverGroup;
            session->helperStep = 20;
            continue;
        }
        case 10:
            /* HRR: send CH2 from session->clientHelloMsg (built in case 4 HRR branch). */
            r = _SendPlainRecordOnce(session, SSF_TLS_CT_HANDSHAKE,
                                     session->clientHelloMsg, session->clientHelloLen);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            session->helperStep = 11;
            /* fall through */
        case 11:
        {
            /* HRR: recv second ServerHello, reassembled if fragmented. Reject double HRR. */
            const uint8_t *msg = NULL;
            size_t bodyLen = 0;
            uint8_t hsType = 0;
            size_t ptLen;

            r = _RecvHandshakeOnce(session, &msg, &bodyLen, &hsType, false);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            if (hsType != SSF_TLS_HS_SERVER_HELLO)
            { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Not ServerHello after HRR");
              _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }
            if (!_HandshakeAtRecordEnd(session, "ServerHello")) return SSF_TLS_IO_ERROR;
            buf = (uint8_t *)msg;
            ptLen = 4u + bodyLen;

            if (ptLen >= 38u && memcmp(&buf[6], _TlscHrrSentinel, 32) == 0)
            { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Double HRR not supported");
              _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }

            SSFTLSTranscriptUpdate(&session->transcript, buf, ptLen);

            if (!_ParseServerHello(session, &buf[4], ptLen - 4u, false,
                                   serverPubKey, &serverPubKeyLen, &serverGroup, NULL, NULL))
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
            /* Dispatch ECDH + HKDF. cryptoWork was populated in case 4 or case 11. */
            /* The driver runs the ECDH + key schedule step on the next pollOpen() call. */
            session->helperStep = 0;
            return SSF_TLS_IO_SUCCESS;
        default:
            return SSF_TLS_IO_ERROR;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: validates an EncryptedExtensions body (RFC 8446 4.3.1, 4.2). Returns true, else     */
/* false with the alert to send.                                                                 */
/* --------------------------------------------------------------------------------------------- */
static bool _ParseEncryptedExtensions(const uint8_t *body, size_t bodyLen, uint8_t *alertOut,
                                      uint16_t *recordLimitOut)
{
    size_t pos = 2;
    size_t end;
    bool hasSni = false;
    bool hasGroups = false;
    bool hasRecordLimit = false;

    *alertOut = SSF_TLS_ALERT_DECODE_ERROR;
    *recordLimitOut = 0;

    /* The message is exactly extensions<0..2^16-1> (4.3.1). */
    if (bodyLen < 2u) return false;
    end = 2u + (size_t)_Get16(&body[0]);
    if (end != bodyLen) return false;

    /* pos never passes end, so the differences below cannot wrap. */
    while (pos < end)
    {
        uint16_t eType;
        uint16_t eLen;

        if ((end - pos) < 4u) return false;
        eType = _Get16(&body[pos]);
        eLen = _Get16(&body[pos + 2u]);
        pos += 4;
        if (eLen > (end - pos)) return false;

        switch (eType)
        {
        case SSF_TLS_EXT_SERVER_NAME:
            /* Acknowledges the SNI the ClientHello sent, with empty extension_data (RFC 6066 3) */
            if (hasSni) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            hasSni = true;
            if (eLen != 0u) return false;
            break;
        case SSF_TLS_EXT_SUPPORTED_GROUPS:
            /* The server's group preferences (4.2.7), informational here: NamedGroupList is a   */
            /* non-empty list of 2-byte groups filling the extension.                            */
            if (hasGroups) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            hasGroups = true;
            if ((eLen < 4u) || (_Get16(&body[pos]) != (uint16_t)(eLen - 2u)) ||
                (((eLen - 2u) & 1u) != 0u))
            { return false; }
            break;
        case SSF_TLSC_EXT_RECORD_SIZE_LIMIT:
        {
            uint16_t limit;

            /* RFC 8449 4: a single uint16; below 64 MUST be illegal_parameter. Above 2^14+1 a  */
            /* client MAY abort; it is accepted and capped, since records never exceed it.      */
            if (hasRecordLimit) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            hasRecordLimit = true;
            if (eLen != 2u) return false;
            limit = _Get16(&body[pos]);
            if (limit < SSF_TLSC_RSL_MIN)
            { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            *recordLimitOut = (limit > SSF_TLSC_RSL_MAX) ? (uint16_t)SSF_TLSC_RSL_MAX : limit;
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
            /* Not offered by the ClientHello (ALPN, pre_shared_key, ...): unsupported_extension */
            /* (4.2).                                                                          */
            *alertOut = SSF_TLS_ALERT_UNSUPPORTED_EXT;
            return false;
        }
        pos += eLen;
    }

    *alertOut = 0;
    return true;
}

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
bool _SSFTLSCParseEncryptedExtensionsForTest(const uint8_t *body, size_t bodyLen,
                                             uint8_t *alertOut)
{
    uint16_t limit;

    return _ParseEncryptedExtensions(body, bodyLen, alertOut, &limit);
}

bool _SSFTLSCParseEncryptedExtensionsRslForTest(const uint8_t *body, size_t bodyLen,
                                                uint8_t *alertOut, uint16_t *recordLimitOut)
{
    return _ParseEncryptedExtensions(body, bodyLen, alertOut, recordLimitOut);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Internal: validates a CertificateRequest body (RFC 8446 4.3.2) and chooses the client's       */
/* CertificateVerify scheme: the first one in the server's signature_algorithms that a key of   */
/* keyType can make, or 0 (no key, SSF_PKEY_TYPE_NONE, or no such scheme: the client then sends */
/* an empty Certificate). *certAlgsOut / *certAlgsLenOut get the scheme list that certificate  */
/* signatures must come from (4.4.2.3): signature_algorithms_cert if sent, else                 */
/* signature_algorithms; they point into body. Returns true, or false with the alert to send   */
/* and *schemeOut 0.                                                                             */
/* --------------------------------------------------------------------------------------------- */
static bool _ParseCertificateRequest(const uint8_t *body, size_t bodyLen, SSFPKeyType_t keyType,
                                     uint16_t *schemeOut, const uint8_t **certAlgsOut,
                                     size_t *certAlgsLenOut, uint8_t *alertOut)
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

    *alertOut = SSF_TLS_ALERT_DECODE_ERROR;
    *schemeOut = 0;
    *certAlgsOut = NULL;
    *certAlgsLenOut = 0;

    /* certificate_request_context<0..2^8-1>, then extensions<2..2^16-1> filling the message */
    if (bodyLen < 1u) return false;
    ctxLen = body[0];
    if ((bodyLen - 1u) < (ctxLen + 2u)) return false;
    start = 1u + ctxLen + 2u;
    end = start + (size_t)_Get16(&body[1u + ctxLen]);
    if ((end != bodyLen) || ((end - start) < 2u)) return false;
    /* The context is for post-handshake authentication, which the client never offers */
    if (ctxLen != 0u) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }

    /* pos never passes end, so the differences below cannot wrap. */
    for (pos = start; pos < end; )
    {
        uint16_t eType;
        uint16_t eLen;
        size_t prev;

        if ((end - pos) < 4u) return false;
        eType = _Get16(&body[pos]);
        eLen = _Get16(&body[pos + 2u]);
        if (eLen > (end - pos - 4u)) return false;

        /* No extension type twice in one block (4.2), recognized or not */
        for (prev = start; prev < pos; prev += 4u + (size_t)_Get16(&body[prev + 2u]))
        {
            if (_Get16(&body[prev]) == eType)
            { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
        }

        switch (eType)
        {
        case SSF_TLS_EXT_SIGNATURE_ALGS:
        case SSF_TLSC_EXT_SIG_ALGS_CERT:
            /* SignatureSchemeList<2..2^16-2> filling the extension (4.2.3) */
            if ((eLen < 4u) || (_Get16(&body[pos + 4u]) != (uint16_t)(eLen - 2u)) ||
                ((eLen & 1u) != 0u)) return false;
            if (eType == SSF_TLSC_EXT_SIG_ALGS_CERT)
            {
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
                    if (_SchemeMatchesKey(_Get16(&sigAlgs[k]), _PKeyLeafType(keyType)))
                    {
                        chosen = _Get16(&sigAlgs[k]);
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
            /* Recognized, but not specified for CertificateRequest: illegal_parameter (4.2) */
            *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER;
            return false;
        default:
            /* certificate_authorities, oid_filters, signature_algorithms_cert, status_request, */
            /* SCT and anything unrecognized: ignored (4.3.2)                                  */
            break;
        }
        pos += 4u + (size_t)eLen;
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

/* --------------------------------------------------------------------------------------------- */
/* Internal: client authentication (mutual TLS, RFC 8446 4.4.2, 4.4.3).                          */
/* --------------------------------------------------------------------------------------------- */
static size_t _SendRecordMax(const SSFTLSCSession_t *s);

/* Length of the client Certificate message: header, empty context, certificate_list of        */
/* CertificateEntry { cert_data<1..2^24-1>, extensions<0..2^16-1> (empty) }.                    */
static size_t _ClientCertMsgLen(const SSFTLSCSession_t *s)
{
    size_t len = 4u + 1u + 3u;
    uint8_t i;

    for (i = 0; i < s->clientChainCount; i++) len += 3u + (size_t)s->clientChainLens[i] + 2u;
    return len;
}

/* Copies the part of piece[0..pieceLen) that falls in the window *off / *dst / *n, then moves  */
/* the window past the piece.                                                                     */
static void _CopyPiece(size_t *off, uint8_t **dst, size_t *n, const uint8_t *piece,
                       size_t pieceLen)
{
    size_t c;

    if (*off >= pieceLen) { *off -= pieceLen; return; }
    c = pieceLen - *off;
    if (c > *n) c = *n;
    memcpy(*dst, &piece[*off], c);
    *dst += c;
    *n -= c;
    *off = 0;
}

/* Copies bytes off..off+n of the client Certificate message to dst, without building it: the  */
/* certificates are read in place from the caller's memory, so a chain of any size is sent     */
/* record by record with no buffer of its size.                                                 */
static void _ClientCertMsgCopy(const SSFTLSCSession_t *s, size_t off, uint8_t *dst, size_t n)
{
    static const uint8_t noExts[2] = { 0, 0 };
    uint8_t hdr[8];
    uint8_t len24[3];
    size_t body = _ClientCertMsgLen(s) - 4u;
    uint8_t i;

    hdr[0] = SSF_TLS_HS_CERTIFICATE;
    _Put24(&hdr[1], body);
    hdr[4] = 0;                                                  /* certificate_request_context */
    _Put24(&hdr[5], body - 4u);                                  /* certificate_list length     */
    _CopyPiece(&off, &dst, &n, hdr, sizeof(hdr));
    for (i = 0; (i < s->clientChainCount) && (n > 0u); i++)
    {
        _Put24(len24, s->clientChainLens[i]);
        _CopyPiece(&off, &dst, &n, len24, sizeof(len24));
        _CopyPiece(&off, &dst, &n, s->clientChainDer[i], s->clientChainLens[i]);
        _CopyPiece(&off, &dst, &n, noExts, sizeof(noExts));
    }
}

/* Sends handshake bytes as as many records as the send limit takes; resumable, s->certSendOff */
/* counting what was sent. msg NULL: the client Certificate message, generated from the chain   */
/* and added to the transcript as it is cut. Otherwise msg[0..total), already in the transcript */
/* (CertificateVerify, Finished). Pieces are staged in hsBuf, idle here: the server's handshake */
/* ended at a record boundary.                                                                   */
static SSFTLSIOResult_t _SendHandshakeOnce(SSFTLSCSession_t *s, const uint8_t *msg, size_t total)
{
    size_t chunk = _SendRecordMax(s);
    SSFTLSIOResult_t r;

    if (chunk > sizeof(s->hsBuf)) chunk = sizeof(s->hsBuf);
    for (;;)
    {
        size_t n = 0;

        if (!s->ioCtx.sendPending)
        {
            if (s->certSendOff >= total) return SSF_TLS_IO_SUCCESS;
            n = total - s->certSendOff;
            if (n > chunk) n = chunk;
            if (msg != NULL) memcpy(s->hsBuf, &msg[s->certSendOff], n);
            else
            {
                _ClientCertMsgCopy(s, s->certSendOff, s->hsBuf, n);
                SSFTLSTranscriptUpdate(&s->transcript, s->hsBuf, n);
            }
            s->certSendOff += (uint32_t)n;
        }
        r = _SendEncRecordOnce(s, SSF_TLS_CT_HANDSHAKE, s->hsBuf, n);
        /* The Finished is staged here: wipe the piece once it is encrypted (or failing) */
        if ((msg != NULL) && (r != SSF_TLS_IO_WANT_WRITE))
        {
            _SSF_TLSC_SCRUB_N("clientFlightPiece", s->hsBuf, chunk);
        }
        if (r != SSF_TLS_IO_SUCCESS) return r;
    }
}

/* Builds the client CertificateVerify message in out: scheme, then the key's signature over 64  */
/* spaces, "TLS 1.3, client CertificateVerify", 0x00 and the transcript hash (4.4.3). The       */
/* content is hashed with the scheme's own hash (Ed25519: none). Out of line so the content     */
/* buffer stays out of the driver's frame.                                                       */
static SSF_NOINLINE bool _SignClientCV(const SSFTLSCSession_t *s, uint16_t scheme,
                                       const uint8_t *th, size_t thLen, uint8_t *out,
                                       size_t outSize, size_t *outLen)
{
    static const char ctx[] = "TLS 1.3, client CertificateVerify";
    uint8_t content[64u + sizeof(ctx) + SSF_TLS_MAX_HASH_SIZE];
    uint8_t h[SSF_SHA2_384_BYTE_SIZE];
    size_t contentLen = 64u + sizeof(ctx) + thLen;
    const SSFPKey_t *k = s->clientKey;
    uint8_t *sig = &out[8];
    size_t sigSize;
    size_t sigLen = 0;
    bool ok = false;

    if ((k == NULL) || (thLen > SSF_TLS_MAX_HASH_SIZE) || (outSize < 8u) ||
        !_SchemeMatchesKey(scheme, _PKeyLeafType(k->type))) return false;
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
    default:                            /* rsa_pss_rsae_sha256 / _sha384 (_SchemeMatchesKey) */
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
    }
    if (!ok || (sigLen > 0xFFFFu)) return false;
    out[0] = SSF_TLS_HS_CERTIFICATE_VERIFY;
    _Put24(&out[1], 4u + sigLen);
    _Put16(&out[4], scheme);
    _Put16(&out[6], (uint16_t)sigLen);
    *outLen = 8u + sigLen;
    return true;
}

/* Returns the RSA modulus and exponent of a PKCS#1 RSAPublicKey (pub) or RSAPrivateKey (priv). */
static bool _RsaNE(const uint8_t *der, size_t derLen, bool priv, const uint8_t **n,
                   uint32_t *nLen, const uint8_t **e, uint32_t *eLen)
{
    SSFASN1Cursor_t cur = { der, (uint32_t)derLen };
    SSFASN1Cursor_t seq;
    SSFASN1Cursor_t next;
    uint64_t version;

    if (derLen > 0xFFFFFFFFu) return false;
    if (!SSFASN1DecOpenConstructed(&cur, SSF_ASN1_TAG_SEQUENCE, &seq, &next)) return false;
    if (priv && !SSFASN1DecGetIntU64(&seq, &version, &seq)) return false;
    return SSFASN1DecGetUInt(&seq, n, nLen, &seq) && SSFASN1DecGetUInt(&seq, e, eLen, &seq);
}

/* True if the leaf certificate's public key is key's. Out of line: the parsed certificate     */
/* (about 1 KB) lives only during this call.                                                     */
static SSF_NOINLINE bool _ClientCertMatchesKey(const uint8_t *der, uint32_t derLen,
                                               const SSFPKey_t *key)
{
    SSFX509Cert_t leaf;

    if (!SSFX509Parse(der, derLen, &leaf)) return false;
    if ((_LeafKeyType(&leaf) != _PKeyLeafType(key->type)) || (leaf.pubKeyUnusedBits != 0u))
    {
        return false;
    }
    if (key->type == SSF_PKEY_TYPE_RSA)
    {
        const uint8_t *n1, *e1, *n2, *e2;
        uint32_t n1Len, e1Len, n2Len, e2Len;

        return _RsaNE(leaf.pubKey, leaf.pubKeyLen, false, &n1, &n1Len, &e1, &e1Len) &&
               _RsaNE(key->rsaDer, key->rsaDerLen, true, &n2, &n2Len, &e2, &e2Len) &&
               (n1Len == n2Len) && (memcmp(n1, n2, n1Len) == 0) &&
               (e1Len == e2Len) && (memcmp(e1, e2, e1Len) == 0);
    }
    return (leaf.pubKeyLen == key->pubLen) && (memcmp(leaf.pubKey, key->pub, key->pubLen) == 0);
}

/* True if scheme is in the scheme list algs[0..algsLen). */
static bool _SchemeInList(uint16_t scheme, const uint8_t *algs, size_t algsLen)
{
    size_t k;

    for (k = 0; (k + 1u) < algsLen; k += 2u) { if (_Get16(&algs[k]) == scheme) return true; }
    return false;
}

/* True if cert's own signature (by its issuer) is one of the listed schemes. The ECDSA curve   */
/* is the issuer's, not known here, so ecdsa-with-SHAx counts as the SHAx ECDSA scheme; RSA-PSS */
/* as either rsae or pss with its hash (RFC 8446 4.2.3).                                          */
static bool _CertSigInList(const SSFX509Cert_t *cert, const uint8_t *algs, size_t algsLen)
{
    if (SSFX509IsSigECDSASHA256(cert))
    {
        return _SchemeInList(SSF_TLS_SIG_ECDSA_SECP256R1_SHA256, algs, algsLen);
    }
    if (SSFX509IsSigECDSASHA384(cert))
    {
        return _SchemeInList(SSF_TLS_SIG_ECDSA_SECP384R1_SHA384, algs, algsLen);
    }
    if (SSFX509IsSigEd25519(cert)) return _SchemeInList(SSF_TLS_SIG_ED25519, algs, algsLen);
    if (SSFX509IsSigRSAPKCS1SHA256(cert)) return _SchemeInList(0x0401u, algs, algsLen);
    if (SSFX509IsSigRSAPKCS1SHA384(cert)) return _SchemeInList(0x0501u, algs, algsLen);
    if (SSFX509IsSigRSAPKCS1SHA512(cert)) return _SchemeInList(0x0601u, algs, algsLen);
    if (SSFX509IsSigRSAPSSSHA256(cert))
    {
        return _SchemeInList(SSF_TLS_SIG_RSA_PSS_RSAE_SHA256, algs, algsLen) ||
               _SchemeInList(0x0809u, algs, algsLen);
    }
    if (SSFX509IsSigRSAPSSSHA384(cert))
    {
        return _SchemeInList(SSF_TLS_SIG_RSA_PSS_RSAE_SHA384, algs, algsLen) ||
               _SchemeInList(0x080au, algs, algsLen);
    }
    return false;                                            /* Not a scheme the client knows */
}

/* True if every certificate of the client chain is signed with a scheme in algs (RFC 8446     */
/* 4.4.2.3); a self-signed last certificate is exempt, as trust anchors are (4.4.2.2). Also     */
/* traces, never enforces, what would make a server refuse the leaf: validity (when the time is */
/* trusted), Key Usage without digitalSignature, EKU without clientAuth. Out of line: one       */
/* parsed certificate (about 1 KB) at a time, only during this call.                             */
static SSF_NOINLINE bool _ClientChainAcceptable(SSFTLSCSession_t *s, const uint8_t *algs,
                                                size_t algsLen, bool nowValid, uint64_t now)
{
    SSFX509Cert_t cert;
    bool ok = true;
    uint8_t i;

    for (i = 0; i < s->clientChainCount; i++)
    {
        if (!SSFX509Parse(s->clientChainDer[i], s->clientChainLens[i], &cert))
        {
            _SSF_TLSC_CERT_WARN(&s->trace, "Client certificate %u does not parse", i);
            ok = false;
            continue;
        }
        if (i == 0u)
        {
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
        /* A self-signed last certificate (a root) is not validated, so any signature will do */
        if (((i + 1u) == s->clientChainCount) && (cert.subject.rawLen == cert.issuer.rawLen) &&
            (memcmp(cert.subject.raw, cert.issuer.raw, cert.subject.rawLen) == 0)) continue;
        if (!_CertSigInList(&cert, algs, algsLen)) ok = false;
    }
    return ok;
}

/* Handles a CertificateRequest: validates it and chooses the client's scheme, 0 for an empty  */
/* Certificate when no certificate is set, none of the server's schemes fits the key, or the   */
/* chain is signed with algorithms the server does not accept.                                   */
static bool _ChooseClientScheme(SSFTLSCSession_t *s, const uint8_t *body, size_t bodyLen,
                                bool nowValid, uint64_t now, uint16_t *schemeOut,
                                uint8_t *alertOut)
{
    const uint8_t *certAlgs;
    size_t certAlgsLen;

    if (!_ParseCertificateRequest(body, bodyLen,
                                  (s->clientChainCount != 0u) ? s->clientKey->type :
                                  SSF_PKEY_TYPE_NONE, schemeOut, &certAlgs, &certAlgsLen,
                                  alertOut)) return false;
    if ((s->clientChainCount != 0u) &&
        !_ClientChainAcceptable(s, certAlgs, certAlgsLen, nowValid, now) && (*schemeOut != 0u))
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

    return _ParseCertificateRequest(body, bodyLen, SSF_PKEY_TYPE_NONE, &scheme, &algs, &algsLen,
                                    alertOut);
}

bool _SSFTLSCChooseClientSchemeForTest(const uint8_t *body, size_t bodyLen, SSFPKeyType_t keyType,
                                       uint16_t *schemeOut, uint8_t *alertOut)
{
    const uint8_t *algs;
    size_t algsLen;

    return _ParseCertificateRequest(body, bodyLen, keyType, schemeOut, &algs, &algsLen,
                                    alertOut);
}

bool _SSFTLSCChooseClientSchemeChainForTest(SSFTLSCSession_t *session, const uint8_t *body,
                                            size_t bodyLen, bool nowValid, uint64_t nowUnixSec,
                                            uint16_t *schemeOut, uint8_t *alertOut)
{
    return _ChooseClientScheme(session, body, bodyLen, nowValid, nowUnixSec, schemeOut, alertOut);
}

size_t _SSFTLSCClientCertMsgLenForTest(const SSFTLSCSession_t *session)
{
    return _ClientCertMsgLen(session);
}

void _SSFTLSCClientCertMsgCopyForTest(const SSFTLSCSession_t *session, size_t off, uint8_t *dst,
                                      size_t n)
{
    _ClientCertMsgCopy(session, off, dst, n);
}

bool _SSFTLSCSignClientCVForTest(SSFTLSCSession_t *session, uint16_t scheme,
                                 const uint8_t *transcriptHash, size_t hashLen, uint8_t *msgOut,
                                 size_t msgSize, size_t *msgLenOut)
{
    return _SignClientCV(session, scheme, transcriptHash, hashLen, msgOut, msgSize, msgLenOut);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Internal: parses a server Certificate message body (RFC 8446 4.4.2). Returns true with up to */
/* SSF_X509_CONFIG_MAX_CHAIN_DEPTH certificate pointers (into body) and lengths, and the number  */
/* of entries sent (saturating at 255), else false.                                             */
/* --------------------------------------------------------------------------------------------- */
static bool _ParseCertificate(const uint8_t *body, size_t bodyLen,
                              const uint8_t **chainDerPtrs, uint32_t *chainDerLens,
                              uint8_t *chainLenOut, uint8_t *seenOut, uint8_t *alertOut)
{
    size_t pos;
    size_t listEnd;
    uint8_t count = 0;
    uint8_t seen = 0;

    *chainLenOut = 0;
    *seenOut = 0;
    *alertOut = SSF_TLS_ALERT_DECODE_ERROR;   /* Framing errors unless refined below */

    /* certificate_request_context<0..2^8-1> is empty for server authentication (4.4.2). */
    if (bodyLen < 1u + 3u) return false;
    if (body[0] != 0u) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
    pos = 1;

    /* certificate_list<0..2^24-1> fills the rest of the message exactly. An empty list is a  */
    /* server that sent no certificate, which the client MUST reject (4.4.2.4).                */
    listEnd = pos + 3u + (size_t)_Get24(&body[pos]);
    pos += 3;
    if ((listEnd != bodyLen) || (pos == listEnd)) return false;

    /* Every entry is validated; the first SSF_X509_CONFIG_MAX_CHAIN_DEPTH are kept. pos never */
    /* passes listEnd, so the differences below cannot wrap.                                   */
    while (pos < listEnd)
    {
        uint32_t certLen;
        uint16_t extLen;

        /* cert_data<1..2^24-1> */
        if ((listEnd - pos) < 3u) return false;
        certLen = _Get24(&body[pos]);
        pos += 3;
        if ((certLen == 0u) || (certLen > (listEnd - pos))) return false;
        if (count < SSF_X509_CONFIG_MAX_CHAIN_DEPTH)
        {
            chainDerPtrs[count] = &body[pos];
            chainDerLens[count] = certLen;
            count++;
        }
        if (seen < 0xffu) seen++;
        pos += certLen;

        /* extensions<0..2^16-1>: each must answer one the ClientHello sent (4.4.2). None of  */
        /* status_request or signed_certificate_timestamp is sent, so any is unsolicited.      */
        if ((listEnd - pos) < 2u) return false;
        extLen = _Get16(&body[pos]);
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
    return _ParseCertificate(body, bodyLen, ders, lens, countOut, &seen, &alert);
}

bool _SSFTLSCParseCertificateSeenForTest(const uint8_t *body, size_t bodyLen,
                                         const uint8_t **ders, uint32_t *lens, uint8_t *countOut,
                                         uint8_t *seenOut)
{
    uint8_t alert;
    return _ParseCertificate(body, bodyLen, ders, lens, countOut, seenOut, &alert);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* State RECV_EE_CERT: recv EE, recv Cert, parse chain, save leaf pubkey, dispatch chain verify. */
/* Resumable — substates 0 (init), 1 (recv EE), 2 (recv Cert + parse + dispatch).    */
/* --------------------------------------------------------------------------------------------- */
/* Internal: parses the leaf certificate and saves its public key and key type for the           */
/* CertificateVerify step. Returns false (bad_certificate) if it does not parse or the key does  */
/* not fit. Kept out of line: the parsed certificate (about 1.5 KB) then occupies the stack only */
/* during this call, not under the chain verification that _SSFTLSCDrive runs later.             */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static bool _SaveLeafKey(SSFTLSCSession_t *session, const uint8_t *der, uint32_t derLen)
{
    SSFX509Cert_t leaf;

    if (!SSFX509Parse(der, derLen, &leaf))
    {
        SSF_TLS_TRACE_CERT_ERROR(&session->trace, "Failed to parse leaf certificate");
        return false;
    }
    if (leaf.pubKeyLen > sizeof(session->clientHelloMsg))
    {
        SSF_TLS_TRACE_CERT_ERROR(&session->trace, "Leaf public key too large");
        return false;
    }
    memcpy(session->clientHelloMsg, leaf.pubKey, leaf.pubKeyLen);
    session->clientHelloLen = leaf.pubKeyLen;
    session->leafKeyType = _LeafKeyType(&leaf);
    return true;
}

static SSFTLSIOResult_t _TlscHandleRecvEECert(SSFTLSCSession_t *session)
{
    const uint8_t *buf = NULL;                 /* Message in place in hsBuf */
    size_t bodyLen;
    uint8_t hsType;
    SSFTLSIOResult_t r;

    switch (session->helperStep)
    {
    case 0:
        SSF_TLS_TRACE_CRYPTO_INFO(&session->trace, "Handshake keys derived");
        /* Initialize handshake message buffer (servers may bundle multiple HS msgs per record). */
        session->hsBufLen = 0;
        session->hsBufPos = 0;
        session->helperStep = 1;
        /* fall through */
    case 1:
        /* === Receive EncryptedExtensions === */
        r = _RecvHandshakeOnce(session, &buf, &bodyLen, &hsType, true);
        if (r != SSF_TLS_IO_SUCCESS) return r;
        if (hsType != SSF_TLS_HS_ENCRYPTED_EXTENSIONS)
        { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Expected EE, got type=%u", hsType);
          _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }
        SSF_TLS_TRACE_HS_DEBUG(&session->trace, "EncryptedExtensions received");
        {
            uint8_t alert;

            if (!_ParseEncryptedExtensions(&buf[4], bodyLen, &alert,
                                           &session->peerRecordLimit))
            {
                SSF_TLS_TRACE_HS_ERROR(&session->trace, "EncryptedExtensions rejected");
                _SSF_TLSC_ALERT(session, alert);
                return SSF_TLS_IO_ERROR;
            }
            if (session->peerRecordLimit != 0u)
            {
                SSF_TLS_TRACE_HS_DEBUG(&session->trace, "record_size_limit: server accepts %u",
                                       session->peerRecordLimit);
            }
        }
        session->helperStep = 2;
        /* fall through */
    case 2:
        /* === Receive [CertificateRequest] Certificate + parse + dispatch chain verify === */
        for (;;)
        {
            uint8_t alert;

            r = _RecvHandshakeOnce(session, &buf, &bodyLen, &hsType, true);
            if (r != SSF_TLS_IO_SUCCESS) return r;
            /* A CertificateRequest may sit between EncryptedExtensions and Certificate, once   */
            /* (RFC 8446 4.3.2). It is answered after the server Finished with an empty         */
            /* Certificate (4.4.2); a second one falls through to unexpected_message.          */
            if ((hsType != SSF_TLS_HS_CERTIFICATE_REQUEST) || session->certRequested) break;
            {
                SSFPortTick_t unixSys = 0;
                uint64_t now = 0;
                bool nowValid = false;

                /* The time, for the client certificate's validity warning: only with trust     */
                /* anchors, where SSFRTCInit() is required; the same floor as chain checking.  */
                if ((session->clientChainCount != 0u) && (session->trust.count > 0u))
                {
                    nowValid = SSFRTCGetUnixNow(&unixSys);
                    now = (uint64_t)(unixSys / SSF_TICKS_PER_SEC);
                    if (now < SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC) nowValid = false;
                }
                if (!_ChooseClientScheme(session, &buf[4], bodyLen, nowValid, now,
                                         &session->clientScheme, &alert))
                {
                    SSF_TLS_TRACE_HS_ERROR(&session->trace, "CertificateRequest rejected");
                    _SSF_TLSC_ALERT(session, alert);
                    return SSF_TLS_IO_ERROR;
                }
            }
            session->certRequested = true;
            if (session->clientScheme != 0u)
            {
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

        /* Parse chain + save leaf + dispatch verify. All synchronous — no further I/O. */
        {
            SSFTLSCCryptoWork_t *w = &session->cryptoWork;
            uint8_t alert;

            /* Parsed straight into the crypto step's chain: no copy, no chain array on the stack */
            if (!_ParseCertificate(&buf[4], bodyLen, w->chainDerPtrs, w->chainDerLens,
                                   &w->chainLen, &w->chainSeen, &alert))
            {
                SSF_TLS_TRACE_CERT_ERROR(&session->trace, "Certificate message malformed");
                _SSF_TLSC_ALERT(session, alert);
                return SSF_TLS_IO_ERROR;
            }
            SSF_TLS_TRACE_CERT_INFO(&session->trace, "Certificate chain: %u of %u cert(s) kept",
                                    w->chainLen, w->chainSeen);

            if (!_SaveLeafKey(session, w->chainDerPtrs[0], w->chainDerLens[0]))
            {
                _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_BAD_CERTIFICATE);
                return SSF_TLS_IO_ERROR;
            }

            if (session->trust.count > 0)
            {
                uint64_t now;
                SSFPortTick_t unixSys = 0;
                bool nowValid;

                /* SSFRTCGetUnixNow() reports ticks, and false if the RTC could not be read. A  */
                /* reading before the configured floor (an RTC that booted at 0) is no better.   */
                /* The VERIFY_CHAIN step refuses to check validity without a trusted time.       */
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
                session->cryptoWork.chainVerifyOk = false;  /* Not verified: opt-in only */
            }
        }
        session->helperStep = 0;
        return SSF_TLS_IO_SUCCESS;
    default:
        return SSF_TLS_IO_ERROR;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: parses a CertificateVerify body (RFC 8446 4.4.3). Returns true with the signature  */
/* scheme and length, else false.                                                                */
/* --------------------------------------------------------------------------------------------- */
static bool _ParseCertificateVerify(const uint8_t *body, size_t bodyLen, uint16_t *schemeOut,
                                    uint16_t *sigLenOut, uint8_t *alertOut)
{
    uint16_t scheme;
    uint16_t sigLen;

    *schemeOut = 0;
    *sigLenOut = 0;

    /* struct { SignatureScheme algorithm; opaque signature<0..2^16-1>; }, exactly filling the */
    /* message; an empty signature cannot verify and is rejected here.                         */
    *alertOut = SSF_TLS_ALERT_DECODE_ERROR;
    if (bodyLen < 4) return false;
    scheme = _Get16(&body[0]);
    sigLen = _Get16(&body[2]);
    if ((sigLen == 0u) || ((4u + (size_t)sigLen) != bodyLen)) return false;
    *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER;  /* Scheme not offered / not for handshakes */

    /* The scheme MUST be one offered in signature_algorithms that is defined for handshake    */
    /* signatures. rsa_pkcs1_* is offered only for certificate signatures and MUST NOT be used */
    /* in CertificateVerify (4.2.3); certificate chains signed with it are still accepted.     */
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
    return _ParseCertificateVerify(body, bodyLen, schemeOut, sigLenOut, &alert);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* Resumable — substates 0 (trace + advance), 1 (recv CV + parse + dispatch).                    */
/* Transcript snapshot is taken inside the switch at the start of step 1 each call because       */
/* the snapshot is idempotent while no new handshake bytes have been integrated (transcript is   */
/* only updated when _RecvHandshakeOnce succeeds, which we check before using the snapshot).     */
static SSFTLSIOResult_t _TlscHandleRecvCV(SSFTLSCSession_t *session)
{
    const uint8_t *buf = NULL;                 /* Message in place in hsBuf */
    size_t bodyLen;
    uint8_t hsType;
    uint8_t cvTranscriptHash[SSF_TLS_MAX_HASH_SIZE];
    SSFTLSIOResult_t r;

    switch (session->helperStep)
    {
    case 0:
        SSF_TLS_TRACE_CERT_INFO(&session->trace, "Certificate chain verified");
        session->helperStep = 1;
        /* fall through */
    case 1:
        /* Snapshot transcript BEFORE receiving CV. Idempotent while transcript unchanged.        */
        SSFTLSTranscriptHash(&session->transcript, cvTranscriptHash, sizeof(cvTranscriptHash));
        SSF_TLS_TRACE_CRYPTO_DEBUG(&session->trace, "CV transcript hash (len=%u)",
                                   session->hashLen);

        r = _RecvHandshakeOnce(session, &buf, &bodyLen, &hsType, true);
        if (r != SSF_TLS_IO_SUCCESS) return r;
        if (hsType != SSF_TLS_HS_CERTIFICATE_VERIFY)
        { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Expected CertVerify, got type=%u", hsType);
          _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }

        /* Parse + dispatch — synchronous, no further I/O. */
        {
            const uint8_t *cvBody = &buf[4];
            uint16_t sigScheme;
            uint16_t sigDataLen;
            uint8_t signContent[64 + 33 + 1 + SSF_TLS_MAX_HASH_SIZE];
            size_t signContentLen = 64u + 33u + 1u + session->hashLen;
            uint8_t contentHash[SSF_TLS_MAX_HASH_SIZE];
            const uint8_t *leafPubKey = session->clientHelloMsg;
            size_t leafPubKeyLen = session->clientHelloLen;
            bool isEd25519;
            size_t sigHashLen = 0;

            uint8_t alert;

            if (!_ParseCertificateVerify(cvBody, bodyLen, &sigScheme, &sigDataLen, &alert))
            { SSF_TLS_TRACE_CRYPTO_ERROR(&session->trace, "CertificateVerify rejected");
              _SSF_TLSC_ALERT(session, alert); return SSF_TLS_IO_ERROR; }
            if (!_SchemeMatchesKey(sigScheme, session->leafKeyType))
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

            /* The signed content embeds the transcript hash (the suite's hash, hashLen); the    */
            /* signature then hashes that content with the scheme's own hash. They differ when   */
            /* e.g. a SHA-384 signature runs under a SHA-256 suite, so track sigHashLen apart.   */
            isEd25519 = (sigScheme == SSF_TLS_SIG_ED25519);
            if (isEd25519)
            {
                /* No pre-hash */
            }
            else if (sigScheme == SSF_TLS_SIG_ECDSA_SECP256R1_SHA256 ||
                     sigScheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA256)
            {
                SSFSHA256(signContent, (uint32_t)signContentLen, contentHash, sizeof(contentHash));
                sigHashLen = 32u;
            }
            else if (sigScheme == SSF_TLS_SIG_ECDSA_SECP384R1_SHA384 ||
                     sigScheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA384)
            {
                SSFSHA384(signContent, (uint32_t)signContentLen, contentHash, sizeof(contentHash));
                sigHashLen = 48u;
            }
            else
            { SSF_TLS_TRACE_CRYPTO_ERROR(&session->trace,
                                         "Unsupported CV signature scheme 0x%04x", sigScheme);
              _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_ILLEGAL_PARAMETER); return SSF_TLS_IO_ERROR; }

            /* sigData points into hsBuf, which holds the message until the VERIFY_SIG step. */
            {
                session->cryptoWork.session = session;
                session->cryptoWork.sigScheme = sigScheme;
                if (isEd25519)
                {
                    if (signContentLen > sizeof(session->cryptoWork.contentHash))
                        return SSF_TLS_IO_ERROR;
                    memcpy(session->cryptoWork.contentHash, signContent, signContentLen);
                    session->cryptoWork.contentHashLen = signContentLen;
                }
                else
                {
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

/* Internal: writes the client Finished (RFC 8446 4.4.4) over the transcript so far to out;      */
/* returns its length, 4 + hashLen.                                                              */
/* --------------------------------------------------------------------------------------------- */
static size_t _BuildClientFinished(SSFTLSCSession_t *s, uint8_t *out)
{
    uint8_t verifyData[SSF_TLS_MAX_HASH_SIZE];
    uint8_t thash[SSF_TLS_MAX_HASH_SIZE];

    SSFTLSTranscriptHash(&s->transcript, thash, sizeof(thash));
    SSFTLSComputeFinished(s->hash, s->clientHsTrafficSecret, s->hashLen,
                          thash, s->hashLen, verifyData, s->hashLen);
    out[0] = SSF_TLS_HS_FINISHED;
    _Put24(&out[1], s->hashLen);
    memcpy(&out[4], verifyData, s->hashLen);
    _SSF_TLSC_SCRUB(verifyData);
    return 4u + (size_t)s->hashLen;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: after the client Finished is sent, switches sending to the client application      */
/* traffic keys and wipes the spent handshake traffic secrets.                                    */
/* --------------------------------------------------------------------------------------------- */
static void _EnterAppSendKeys(SSFTLSCSession_t *s)
{
    uint8_t key[SSF_TLS_MAX_KEY_SIZE], iv[SSF_TLS_IV_SIZE];

    SSFTLSDeriveTrafficKeys(s->hash, s->clientAppTrafficSecret, s->hashLen,
                            key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    _RecordStateSet(s, &s->sendState, &s->sendStateInited, key, iv);
    _SSF_TLSC_SCRUB(key);
    _SSF_TLSC_SCRUB(iv);
    /* Handshake traffic secrets are spent; application secrets stay for KeyUpdate. */
    _SSF_TLSC_SCRUB_N("clientHsTrafficSecret", s->clientHsTrafficSecret,
                      sizeof(s->clientHsTrafficSecret));
    _SSF_TLSC_SCRUB_N("serverHsTrafficSecret", s->serverHsTrafficSecret,
                      sizeof(s->serverHsTrafficSecret));
    SSF_TLS_TRACE_HS_INFO(&s->trace, "Handshake complete, connected (suite=0x%04x)",
                          s->cipherSuite);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: the SIGN_CV crypto step. Signs the CertificateVerify over the transcript through   */
/* the client Certificate, then appends the client Finished, which covers it. Both are built in */
/* clientHelloMsg, free by now (the server's leaf key it held is used), and SEND_CV_FIN streams */
/* them in as many records as the send limit takes.                                            */
/* --------------------------------------------------------------------------------------------- */
static SSF_NOINLINE bool _TlscSignClientCV(SSFTLSCSession_t *s)
{
    uint8_t thash[SSF_TLS_MAX_HASH_SIZE];
    size_t cvLen;

    SSFTLSTranscriptHash(&s->transcript, thash, sizeof(thash));
    if (!_SignClientCV(s, s->clientScheme, thash, s->hashLen, s->clientHelloMsg,
                       sizeof(s->clientHelloMsg) - (4u + SSF_TLS_MAX_HASH_SIZE), &cvLen))
    {
        SSF_TLS_TRACE_CRYPTO_ERROR(&s->trace, "Client CertificateVerify signing failed");
        return false;
    }
    SSFTLSTranscriptUpdate(&s->transcript, s->clientHelloMsg, cvLen);
    s->clientHelloLen = cvLen + _BuildClientFinished(s, &s->clientHelloMsg[cvLen]);
    SSF_TLS_TRACE_CRYPTO_INFO(&s->trace, "Client CertificateVerify signed (scheme 0x%04x)",
                              s->clientScheme);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* State RECV_FIN_SEND_FIN: receives and verifies the server Finished and derives the            */
/* application keys. Without client authentication it also sends the client Finished (after an */
/* empty Certificate when one was requested); with it, it returns there and the driver's        */
/* SEND_CLIENT_CERT / SIGN_CV / SEND_CV_FIN states send the client flight. Resumable: substeps */
/* 0 (trace), 1 (receive and verify the server Finished, derive), 2 (send the client Finished). */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSIOResult_t _TlscHandleRecvFinSendFin(SSFTLSCSession_t *session)
{
    const uint8_t *buf = NULL;                 /* Message in place in hsBuf */
    size_t bodyLen;
    uint8_t hsType;
    uint8_t handshakeSecret[SSF_TLS_MAX_HASH_SIZE];
    /* [empty Certificate] Finished: the client's last flight, sent as one record */
    uint8_t finishedMsg[SSF_TLSC_EMPTY_CERT_LEN + 4 + SSF_TLS_MAX_HASH_SIZE];
    size_t certLen;
    uint8_t finTranscriptHash[SSF_TLS_MAX_HASH_SIZE];
    uint8_t expectedVerifyData[SSF_TLS_MAX_HASH_SIZE];
    bool isFinishedOk;
    SSFTLSIOResult_t r;

    switch (session->helperStep)
    {
    case 0:
        SSF_TLS_TRACE_CRYPTO_INFO(&session->trace, "CertificateVerify signature verified");
        session->helperStep = 1;
        /* fall through */
    case 1:
        /* === Receive server Finished === */
        /* RFC 8446 4.4.4: verify_data covers the transcript up to, not including, Finished.   */
        /* _RecvHandshakeOnce adds Finished on success, so snapshot first. Repeating it on a    */
        /* WANT_READ retry is harmless: the transcript changes only when a message lands.       */
        SSFTLSTranscriptHash(&session->transcript, finTranscriptHash, sizeof(finTranscriptHash));
        r = _RecvHandshakeOnce(session, &buf, &bodyLen, &hsType, true);
        if (r != SSF_TLS_IO_SUCCESS) return r;
        if (hsType != SSF_TLS_HS_FINISHED)
        { SSF_TLS_TRACE_HS_ERROR(&session->trace, "Expected Finished, got type=%u", hsType);
          _SSF_TLSC_ALERT(session, SSF_TLS_ALERT_UNEXPECTED_MSG); return SSF_TLS_IO_ERROR; }
        /* Was silently discarded at connect: bytes after Finished would be under the wrong keys */
        if (!_HandshakeAtRecordEnd(session, "Server Finished")) return SSF_TLS_IO_ERROR;
        SSF_TLS_TRACE_HS_DEBUG(&session->trace, "Server Finished received");
#if SSF_CONFIG_TLSC_UNIT_TEST == 1
        if (_ssfTLSCUTCorruptServerFinished && (bodyLen > 0)) ((uint8_t *)buf)[4] ^= 0x01u;
#endif

        /* RFC 8446 4.4.4: verify_data = HMAC(finished_key(server hs secret), transcript).      */
        /* Compare in constant time; any mismatch MUST terminate the connection.                */
        SSFTLSComputeFinished(session->hash, session->serverHsTrafficSecret, session->hashLen,
                              finTranscriptHash, session->hashLen,
                              expectedVerifyData, session->hashLen);
        isFinishedOk = (bodyLen == (size_t)session->hashLen) &&
                       SSFCryptCTMemEq(expectedVerifyData, &buf[4], session->hashLen);
        SSFCryptSecureZero(expectedVerifyData, sizeof(expectedVerifyData));
        if (!isFinishedOk)
        {
            SSF_TLS_TRACE_HS_ERROR(&session->trace, "Server Finished verify_data mismatch");
            _SSF_TLSC_ALERT(session, (bodyLen == (size_t)session->hashLen) ?
                            SSF_TLS_ALERT_DECRYPT_ERROR : SSF_TLS_ALERT_DECODE_ERROR);
            return SSF_TLS_IO_ERROR;
        }

        /* === Derive application traffic keys + set up client HS send keys + build client Fin. */
        /* All synchronous; on completion advance to substep 2 which sends the client Finished. */
        memcpy(handshakeSecret, session->savedHandshakeSecret, session->hashLen);

        SSF_TLS_TRACE_CRYPTO_INFO(&session->trace, "Deriving application keys");
        isFinishedOk = _DeriveAppKeys(session, handshakeSecret);
        /* The handshake secret is spent once the master secret is derived. */
        _SSF_TLSC_SCRUB(handshakeSecret);
        _SSF_TLSC_SCRUB_N("savedHandshakeSecret", session->savedHandshakeSecret,
                          sizeof(session->savedHandshakeSecret));
        if (!isFinishedOk)
        { SSF_TLS_TRACE_CRYPTO_ERROR(&session->trace, "DeriveAppKeys failed");
          return SSF_TLS_IO_ERROR; }

        /* Client authentication: the Certificate, CertificateVerify and Finished follow in the  */
        /* driver's SEND_CLIENT_CERT / SIGN_CV / SEND_CV_FIN states.                            */
        if (session->clientScheme != 0u)
        {
            session->helperStep = 0;
            return SSF_TLS_IO_SUCCESS;
        }

        /* Asked for a certificate without one to send: an empty Certificate (empty request     */
        /* context, empty certificate_list) precedes Finished, and Finished covers it (RFC 8446 */
        /* 4.4.2, 4.4.4). The application secrets above end at the server Finished, as required.*/
        certLen = session->certRequested ? SSF_TLSC_EMPTY_CERT_LEN : 0u;
        if (certLen != 0u)
        {
            memset(finishedMsg, 0, SSF_TLSC_EMPTY_CERT_LEN);
            finishedMsg[0] = SSF_TLS_HS_CERTIFICATE;
            _Put24(&finishedMsg[1], SSF_TLSC_EMPTY_CERT_LEN - 4u);
            SSFTLSTranscriptUpdate(&session->transcript, finishedMsg, SSF_TLSC_EMPTY_CERT_LEN);
        }
        /* The client handshake send keys are already installed. */
        (void)_BuildClientFinished(session, &finishedMsg[certLen]);
        session->helperStep = 2;
        /* fall through */
    case 2:
        /* === Send client Finished === */
        /* On first call here the finishedMsg buffer is built above and passed to              */
        /* _SendEncRecordOnce, which encrypts into io->sendRecordBuf and sets sendPending.     */
        /* On resume (WANT_WRITE), the same-call local finishedMsg value is ignored by         */
        /* _SendEncRecordOnce (because sendPending==true) — the encrypted bytes in             */
        /* io->sendRecordBuf are what keep flowing.                                             */
        certLen = session->certRequested ? SSF_TLSC_EMPTY_CERT_LEN : 0u;
        r = _SendEncRecordOnce(session, SSF_TLS_CT_HANDSHAKE,
                               finishedMsg, certLen + 4u + session->hashLen);
        _SSF_TLSC_SCRUB(finishedMsg);             /* Now encrypted in ioCtx.sendRecordBuf */
        if (r != SSF_TLS_IO_SUCCESS) return r;
        _EnterAppSendKeys(session);
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
/* Returns the session that owns transport t.                                                    */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSCSession_t *_SSFTLSCSelf(SSFNetTransport_t *t)
{
    SSFTLSCSession_t *s;

    SSF_REQUIRE(t != NULL);
    s = (SSFTLSCSession_t *)t;
    SSF_REQUIRE(s->magic == SSF_TLSC_MAGIC);
    return s;
}

/* --------------------------------------------------------------------------------------------- */
/* Wipes all per-connection state, keys included, and returns the session to IDLE. The transport */
/* table, inner transport, trust store, trace callback and magic are kept.                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCReset(SSFTLSCSession_t *s)
{
    SSFNetTransport_t transport = s->transport;
    SSFNetTransport_t *inner = s->inner;
    SSFTLSCTrustStore_t trust = s->trust;
    SSFTLSTraceCtx_t trace = s->trace;
    bool allowUnauthenticated = s->allowUnauthenticated;
    const uint8_t *const *clientChainDer = s->clientChainDer;
    const uint32_t *clientChainLens = s->clientChainLens;
    const SSFPKey_t *clientKey = s->clientKey;
    uint8_t clientChainCount = s->clientChainCount;
    uint32_t magic = s->magic;

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
    s->magic = magic;
    s->hsState = SSF_TLSC_HS_IDLE;
}

/* --------------------------------------------------------------------------------------------- */
/* Wipes every secret and plaintext buffer of the connection and de-initializes the record      */
/* states. The connection cannot carry data afterwards.                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCWipeKeys(SSFTLSCSession_t *s)
{
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
    _SSF_TLSC_SCRUB_N("recvBuf", s->recvBuf, sizeof(s->recvBuf));
    _SSF_TLSC_SCRUB_N("ioCtx", &s->ioCtx, sizeof(s->ioCtx));
    _SSF_TLSC_SCRUB_N("cryptoWork", &s->cryptoWork, sizeof(s->cryptoWork));
    s->hsBufLen = 0;
    s->hsBufPos = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Best-effort single attempt to send an alert, protected if send keys are installed. Skipped   */
/* when the transport has failed or a partly written record is still pending.                   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCSendAlert(SSFTLSCSession_t *s, uint8_t level, uint8_t desc)
{
    uint8_t alert[2];

    if ((s->innerOpen == false) || s->ioFailed) return;
    if (_SendPending(s) != SSF_TLS_IO_SUCCESS) return;
    alert[0] = level;
    alert[1] = desc;
    SSF_TLS_TRACE_ALERT(&s->trace, "Sending alert level=%u desc=%u", level, desc);
    if (s->sendEncrypted) (void)_SendEncRecordOnce(s, SSF_TLS_CT_ALERT, alert, sizeof(alert));
    else (void)_SendPlainRecordOnce(s, SSF_TLS_CT_ALERT, alert, sizeof(alert));
}

/* --------------------------------------------------------------------------------------------- */
/* Ends a failed connection: closes the inner transport and enters ERROR. Returns the result for */
/* pollOpen(), send() or recv(): CLOSED if the peer closed, else ERROR.                          */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCFail(SSFTLSCSession_t *s)
{
    /* RFC 8446 6: announce the abort with the first failure's fatal alert (internal_error if   */
    /* none was recorded), answer close_notify with close_notify, and stay silent after a peer   */
    /* alert or a transport failure, or once our own close_notify is out (RFC 8446 6.1: nothing  */
    /* follows it). Sent before the wipe, while send keys still exist.                           */
    if (s->closeNotifySent) { /* Silent */ }
    else if (s->peerCloseNotify) _SSFTLSCSendAlert(s, 1u, SSF_TLS_ALERT_CLOSE_NOTIFY);
    else if (s->peerAlerted == false)
    {
        _SSFTLSCSendAlert(s, 2u, (s->pendingAlert != 0u) ? s->pendingAlert :
                                                           SSF_TLS_ALERT_INTERNAL_ERROR);
    }
    _SSFTLSCWipeKeys(s);                       /* At once, not at close(): the connection is dead */
    if (s->innerOpen) s->inner->close(s->inner);
    s->innerOpen = false;
    s->connected = false;
    s->hsState = SSF_TLSC_HS_ERROR;
    s->helperStep = 0;
    return s->peerClosed ? SSF_NET_IO_CLOSED : SSF_NET_IO_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Advances the handshake. Returns SUCCESS once complete, WANT_READ/WANT_WRITE while in progress, */
/* else CLOSED or ERROR. A receive state that completes its message continues into its crypto   */
/* step in the same call (ServerHello -> key exchange, Certificate -> chain verification,        */
/* CertificateVerify -> its signature); the crypto step then ends the call with WANT_READ, so a  */
/* call runs at most one public-key step.                                                        */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCDrive(SSFTLSCSession_t *s)
{
    SSFTLSIOResult_t r;

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
            r = _TlscHandleSendCH(s);
            if (r == SSF_TLS_IO_WANT_READ) return SSF_NET_IO_WANT_READ;
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            s->helperStep = 0;
            s->hsState = SSF_TLSC_HS_DERIVE_HS_KEYS;
            break;

        case SSF_TLSC_HS_DERIVE_HS_KEYS:
            s->cryptoWork.session = s;
            _TLSCDeriveHSKeysWork(&s->cryptoWork);
            if (!s->cryptoWork.keyExchangeOk)
            {
                SSF_TLS_TRACE_CRYPTO_ERROR(&s->trace, "DeriveHandshakeKeys failed");
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_ILLEGAL_PARAMETER);  /* Unusable key share */
                return _SSFTLSCFail(s);
            }
            s->hsState = SSF_TLSC_HS_RECV_EE_CERT;
            return SSF_NET_IO_WANT_READ;

        case SSF_TLSC_HS_RECV_EE_CERT:
            r = _TlscHandleRecvEECert(s);
            if (r == SSF_TLS_IO_WANT_READ) return SSF_NET_IO_WANT_READ;
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            s->helperStep = 0;
            s->hsState = SSF_TLSC_HS_VERIFY_CHAIN;
            break;

        case SSF_TLSC_HS_VERIFY_CHAIN:
            if (s->trust.count == 0u)
            {
                /* open() refuses this case without the opt-in; check again so verification can */
                /* never be skipped silently.                                                     */
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
                /* Without a set time, validity periods cannot be checked: fail rather than    */
                /* check at time 0 (which only ever fails, and for a misleading reason).       */
                SSF_TLS_TRACE_CERT_ERROR(&s->trace,
                                         "No trusted time (RTC unreadable or before "
                                         "SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC): cannot "
                                         "check certificate validity");
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_INTERNAL_ERROR);
                return _SSFTLSCFail(s);
            }
            else
            {
                _TLSCVerifyChainWork(&s->cryptoWork);
                if (!s->cryptoWork.chainVerifyOk)
                {
                    SSF_TLS_TRACE_CERT_ERROR(&s->trace, "Certificate chain verification failed: "
                                             "code %d, cert[%u]",
                                             (int)s->cryptoWork.chainVerifyErr.code,
                                             s->cryptoWork.chainVerifyErr.certIdx);
                    if (s->cryptoWork.chainSeen > s->cryptoWork.chainLen)
                    {
                        SSF_TLS_TRACE_CERT_ERROR(&s->trace, "Certificate chain truncated: %u of %u "
                                                 "certs kept (SSF_X509_CONFIG_MAX_CHAIN_DEPTH)",
                                                 s->cryptoWork.chainLen, s->cryptoWork.chainSeen);
                    }
                    _SSF_TLSC_ALERT(s, _ChainAlert(s->cryptoWork.chainVerifyErr.code));
                    return _SSFTLSCFail(s);
                }
            }
            s->hsState = SSF_TLSC_HS_RECV_CV;
            return SSF_NET_IO_WANT_READ;

        case SSF_TLSC_HS_RECV_CV:
            r = _TlscHandleRecvCV(s);
            if (r == SSF_TLS_IO_WANT_READ) return SSF_NET_IO_WANT_READ;
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            s->helperStep = 0;
            s->hsState = SSF_TLSC_HS_VERIFY_SIG;
            break;

        case SSF_TLSC_HS_VERIFY_SIG:
            _TLSCVerifySigWork(&s->cryptoWork);
            if (!s->cryptoWork.sigVerifyOk)
            {
                SSF_TLS_TRACE_CRYPTO_ERROR(&s->trace, "CertificateVerify signature INVALID");
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_DECRYPT_ERROR);       /* 4.4.3 */
                return _SSFTLSCFail(s);
            }
            s->hsState = SSF_TLSC_HS_RECV_FIN_SEND_FIN;
            return SSF_NET_IO_WANT_READ;

        case SSF_TLSC_HS_RECV_FIN_SEND_FIN:
            r = _TlscHandleRecvFinSendFin(s);
            if (r == SSF_TLS_IO_WANT_READ) return SSF_NET_IO_WANT_READ;
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            s->helperStep = 0;
            if (s->clientScheme != 0u)
            {
                s->certSendOff = 0;
                s->hsState = SSF_TLSC_HS_SEND_CLIENT_CERT;
                break;
            }
            s->hsBufLen = 0;                   /* hsBuf now holds application data */
            s->hsBufPos = 0;
            s->connected = true;
            s->hsState = SSF_TLSC_HS_COMPLETE;
            return SSF_NET_IO_SUCCESS;

        case SSF_TLSC_HS_SEND_CLIENT_CERT:
            r = _SendHandshakeOnce(s, NULL, _ClientCertMsgLen(s));
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            s->hsState = SSF_TLSC_HS_SIGN_CV;
            break;

        case SSF_TLSC_HS_SIGN_CV:
            if (!_TlscSignClientCV(s))
            {
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_INTERNAL_ERROR);
                return _SSFTLSCFail(s);
            }
            s->certSendOff = 0;
            s->hsState = SSF_TLSC_HS_SEND_CV_FIN;
            return SSF_NET_IO_WANT_WRITE;      /* The signature was this call's step */

        case SSF_TLSC_HS_SEND_CV_FIN:
            r = _SendHandshakeOnce(s, s->clientHelloMsg, s->clientHelloLen);
            if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
            /* The Finished is encrypted in sendRecordBuf now, or the connection is failing */
            _SSF_TLSC_SCRUB_N("clientFlight", s->clientHelloMsg, sizeof(s->clientHelloMsg));
            if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);
            _EnterAppSendKeys(s);
            s->hsBufLen = 0;                   /* hsBuf now holds application data */
            s->hsBufPos = 0;
            s->connected = true;
            s->hsState = SSF_TLSC_HS_COMPLETE;
            return SSF_NET_IO_SUCCESS;

        default:                               /* IDLE: not opened */
            return SSF_NET_IO_ERROR;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the inner connection to host:port was started and the handshake armed.        */
/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
/* Internal: largest content sent in one protected record: this build's send size, or less when */
/* the server's record_size_limit (RFC 8449 4) leaves room for the content type byte only.      */
/* --------------------------------------------------------------------------------------------- */
static size_t _SendRecordMax(const SSFTLSCSession_t *s)
{
    size_t max = SSF_TLSC_CONFIG_MAX_SEND_RECORD;

    if ((s->peerRecordLimit != 0u) && (((size_t)s->peerRecordLimit - 1u) < max))
    { max = (size_t)s->peerRecordLimit - 1u; }
    return max;
}

static bool _SSFTLSCOpen(SSFNetTransport_t *t, SSFCStrIn_t host, size_t hostSize, uint16_t port)
{
    SSFTLSCSession_t *s;
    size_t hostLen;

    SSF_REQUIRE(host != NULL);
    SSF_REQUIRE(hostSize > 0);
    s = _SSFTLSCSelf(t);
    SSF_REQUIRE(s->hsState == SSF_TLSC_HS_IDLE);

    if ((SSFStrLen(host, hostSize, &hostLen) == false) || (hostLen == 0)) return false;
    if (hostLen >= SSF_TLSC_MAX_HOST_SIZE) return false;
    if (port == 0) return false;
    /* IPv4 only (ssfnet.h), whatever the inner transport: an IPv6 literal could never be       */
    /* verified (ssfx509 matches IPv4 iPAddress SANs only), so refuse it before connecting.      */
    if (memchr(host, ':', hostLen) != NULL)
    {
        SSF_TLS_TRACE_HS_ERROR(&s->trace, "IPv6 host '%s' refused: SSF is IPv4 only", host);
        return false;
    }

    /* Fail closed: without trust anchors the server cannot be authenticated, so do not connect */
    /* at all (a ClientHello would already disclose the host name) unless the caller opted in.  */
#if SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED == 1
    if ((s->trust.count == 0u) && (s->allowUnauthenticated == false))
    {
        SSF_TLS_TRACE_CERT_ERROR(&s->trace, "No trust anchors: refusing to connect "
                                 "(SSFTLSCSetUnauthenticated() opts in)");
        return false;
    }
#else
    if (s->trust.count == 0u)
    {
        SSF_TLS_TRACE_CERT_ERROR(&s->trace, "No trust anchors: refusing to connect");
        return false;
    }
#endif

    _SSFTLSCReset(s);
    memcpy(s->host, host, hostLen + 1u);       /* SNI and certificate name; caller's copy may go */
    s->hsHostname = s->host;
    s->hsPort = port;

    if (s->inner->open(s->inner, s->host, sizeof(s->host), port) == false) return false;
    s->innerOpen = true;
    s->helperStep = 0;
    s->hsState = SSF_TLSC_HS_SEND_CH;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS once the handshake is complete, WANT_READ/WANT_WRITE while in progress, else  */
/* CLOSED or ERROR.                                                                              */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCPollOpen(SSFNetTransport_t *t)
{
    return _SSFTLSCDrive(_SSFTLSCSelf(t));
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: post-handshake handshake messages (RFC 8446 4.6). Feeds one record's plaintext to a */
/* parser that keeps its place across records, so a message may span them. NewSessionTicket is  */
/* skipped (no resumption); KeyUpdate is checked (4.6.3) and must end its record, as any key    */
/* change must (5.1); anything else, post-handshake CertificateRequest included (never offered), */
/* is unexpected_message. Returns false with the alert, else *kuOut is the KeyUpdate request   */
/* (0 / 1) that ended the record, or 0xFF for none.                                             */
/* --------------------------------------------------------------------------------------------- */
/* NewSessionTicket body minimum: lifetime 4, age_add 4, nonce<0..255> 1, ticket<1..2^16-1>    */
/* 2 + 1, extensions<0..2^16-2> 2. The ticket is not used (no resumption), so not parsed further. */
#define SSF_TLSC_NST_MIN_BODY (14u)
#define SSF_TLSC_NO_KEY_UPDATE (0xFFu)

static bool _PostHandshakeFeed(SSFTLSCSession_t *s, const uint8_t *rec, size_t len,
                               uint8_t *alertOut, uint8_t *kuOut)
{
    size_t i = 0;

    *alertOut = 0;
    *kuOut = SSF_TLSC_NO_KEY_UPDATE;
    while (i < len)
    {
        size_t n;

        if (s->phHdrLen < sizeof(s->phHdr))
        {
            s->phHdr[s->phHdrLen++] = rec[i++];
            if (s->phHdrLen < sizeof(s->phHdr)) continue;
            s->phType = s->phHdr[0];
            s->phRemain = ((uint32_t)s->phHdr[1] << 16) | ((uint32_t)s->phHdr[2] << 8) |
                          (uint32_t)s->phHdr[3];
            if (s->phType == SSF_TLS_HS_NEW_SESSION_TICKET)
            {
                if (s->phRemain < SSF_TLSC_NST_MIN_BODY)
                { *alertOut = SSF_TLS_ALERT_DECODE_ERROR; return false; }
            }
            else if (s->phType == SSF_TLS_HS_KEY_UPDATE)
            {
                if (s->phRemain != 1u) { *alertOut = SSF_TLS_ALERT_DECODE_ERROR; return false; }
            }
            else { *alertOut = SSF_TLS_ALERT_UNEXPECTED_MSG; return false; }
            continue;
        }

        /* Body bytes. A KeyUpdate's one byte is its request, and the record must end with it. */
        if (s->phType == SSF_TLS_HS_KEY_UPDATE)
        {
            if (rec[i] > 1u) { *alertOut = SSF_TLS_ALERT_ILLEGAL_PARAMETER; return false; }
            if ((i + 1u) != len) { *alertOut = SSF_TLS_ALERT_UNEXPECTED_MSG; return false; }
            *kuOut = rec[i];
        }
        n = len - i;
        if (n > s->phRemain) n = s->phRemain;
        i += n;
        s->phRemain -= (uint32_t)n;
        if (s->phRemain == 0u) s->phHdrLen = 0;                    /* Message done */
    }
    return true;
}

/* Internal: true unless a handshake message is part-way through and the record is not a        */
/* handshake record: no other record may come between its pieces (RFC 8446 5.1).               */
static bool _RecordTypeAllowed(const SSFTLSCSession_t *s, uint8_t contentType)
{
    return (contentType == SSF_TLS_CT_HANDSHAKE) || (s->phHdrLen == 0u);
}

/* Internal: secret = HKDF-Expand-Label(secret, "traffic upd", "", Hash.length) (RFC 8446 7.2). */
static void _NextTrafficSecret(const SSFTLSCSession_t *s, uint8_t *secret)
{
    uint8_t next[SSF_TLS_MAX_HASH_SIZE];

    SSFTLSHkdfExpandLabel(s->hash, secret, s->hashLen, "traffic upd", NULL, 0, next, s->hashLen);
    memcpy(secret, next, s->hashLen);
    _SSF_TLSC_SCRUB(next);
}

/* Internal: moves secret to its next generation and installs the keys derived from it in state; */
/* the previous secret and keys are gone.                                                         */
static void _UpdateTrafficKeys(SSFTLSCSession_t *s, uint8_t *secret, SSFTLSRecordState_t *state,
                               bool *inited)
{
    uint8_t key[SSF_TLS_MAX_KEY_SIZE], iv[SSF_TLS_IV_SIZE];

    _NextTrafficSecret(s, secret);
    SSFTLSDeriveTrafficKeys(s->hash, secret, s->hashLen, key, s->keyLen, iv, SSF_TLS_IV_SIZE);
    _RecordStateSet(s, state, inited, key, iv);
    _SSF_TLSC_SCRUB(key);
    _SSF_TLSC_SCRUB(iv);
}

/* Internal: sends a KeyUpdate (update_not_requested) under the current client key, then moves  */
/* sending to the next key. Call with nothing pending. Once encrypted the record is the old    */
/* key's last, so the switch happens even if it is still being written (WANT_WRITE).           */
static SSFTLSIOResult_t _SendKeyUpdate(SSFTLSCSession_t *s)
{
    static const uint8_t ku[5] = { SSF_TLS_HS_KEY_UPDATE, 0u, 0u, 1u, 0u };
    SSFTLSIOResult_t r = _SendEncRecordOnce(s, SSF_TLS_CT_HANDSHAKE, ku, sizeof(ku));

    if (r == SSF_TLS_IO_ERROR) return r;
    _UpdateTrafficKeys(s, s->clientAppTrafficSecret, &s->sendState, &s->sendStateInited);
    SSF_TLS_TRACE_CRYPTO_INFO(&s->trace, "KeyUpdate sent (%s); client key updated",
                              s->keyUpdateOwed ? "requested by the server" : "record limit");
    s->keyUpdateOwed = false;
    s->sendRecordsOnKey = 0;
    return r;
}

#if SSF_CONFIG_TLSC_UNIT_TEST == 1
bool _SSFTLSCPostHandshakeFeedForTest(SSFTLSCSession_t *session, const uint8_t *rec, size_t len,
                                      uint8_t *alertOut, uint8_t *keyUpdateOut)
{
    return _PostHandshakeFeed(session, rec, len, alertOut, keyUpdateOut);
}

void _SSFTLSCNextTrafficSecretForTest(const SSFTLSCSession_t *session, uint8_t *secret)
{
    _NextTrafficSecret(session, secret);
}

bool _SSFTLSCRecordTypeAllowedForTest(const SSFTLSCSession_t *session, uint8_t contentType)
{
    return _RecordTypeAllowed(session, contentType);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS with up to one record's worth of bytes accepted, WANT_WRITE if the previous    */
/* record is still being written, else CLOSED or ERROR. Accepted bytes are encrypted at once and  */
/* written as far as the inner transport allows; the remainder goes out on later calls.          */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCSend(SSFNetTransport_t *t, const uint8_t *buf, size_t len,
                                     size_t *sentOut)
{
    SSFTLSCSession_t *s;
    SSFTLSIOResult_t r;
    size_t chunk;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(len > 0);
    SSF_REQUIRE(sentOut != NULL);
    s = _SSFTLSCSelf(t);

    *sentOut = 0;
    if (s->connected == false) return SSF_NET_IO_ERROR;
    if (s->closeNotifySent) return SSF_NET_IO_ERROR;   /* ssfnet.h: not valid after shutdown() */

    r = _SendPending(s);
    if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
    if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);

    /* A KeyUpdate goes first when the server asked for one (it must precede the next          */
    /* application data, RFC 8446 4.6.3) or the current key has carried its share of records    */
    /* (5.5). Its record may still be pending: the data follows on the next call.               */
    if (s->keyUpdateOwed || (s->sendRecordsOnKey >= SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS))
    {
        r = _SendKeyUpdate(s);
        if (r == SSF_TLS_IO_ERROR) return _SSFTLSCFail(s);
        if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
    }

    chunk = _SendRecordMax(s);
    if (len < chunk) chunk = len;
    r = _SendEncRecordOnce(s, SSF_TLS_CT_APPLICATION, buf, chunk);
    if (r == SSF_TLS_IO_ERROR) return _SSFTLSCFail(s);
    s->sendRecordsOnKey++;
    *sentOut = chunk;                          /* Encrypted; any unsent tail stays pending */
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS with application bytes, WANT_READ if none are available yet, CLOSED on        */
/* close_notify or end of stream, else ERROR. A decrypted record larger than size is returned     */
/* across several calls.                                                                         */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCRecv(SSFNetTransport_t *t, uint8_t *buf, size_t size,
                                     size_t *gotOut)
{
    SSFTLSCSession_t *s;
    uint32_t i;

    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);
    SSF_REQUIRE(gotOut != NULL);
    s = _SSFTLSCSelf(t);

    *gotOut = 0;
    if (s->connected == false) return SSF_NET_IO_ERROR;

    /* Keep a partly written record moving even when the caller is only reading. */
    if (_SendPending(s) == SSF_TLS_IO_ERROR) return _SSFTLSCFail(s);

    for (i = 0; (s->hsBufPos >= s->hsBufLen) && (i < SSF_TLSC_RECV_MAX_RECORDS); i++)
    {
        uint8_t ct = 0;
        size_t ptLen = 0;
        SSFTLSIOResult_t r = _RecvRecordOnce(s, s->hsBuf, sizeof(s->hsBuf), &ptLen, &ct);

        if (r == SSF_TLS_IO_WANT_READ) return SSF_NET_IO_WANT_READ;
        if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);

        if (ct == SSF_TLS_CT_APPLICATION)
        {
            if (!_RecordTypeAllowed(s, ct))
            {
                SSF_TLS_TRACE_HS_ERROR(&s->trace, "Application data inside a split "
                                       "post-handshake message");
                _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG);
                return _SSFTLSCFail(s);
            }
            s->hsBufLen = ptLen;               /* An empty record yields nothing; read on */
            s->hsBufPos = 0;
        }
        else if (ct == SSF_TLS_CT_ALERT)
        {
            if ((ptLen >= 2u) && (s->hsBuf[1] == SSF_TLS_ALERT_CLOSE_NOTIFY))
            { s->peerClosed = true; }
            return _SSFTLSCFail(s);
        }
        else if (ct == SSF_TLS_CT_HANDSHAKE)
        {
            uint8_t alert;
            uint8_t ku;

            if (!_PostHandshakeFeed(s, s->hsBuf, ptLen, &alert, &ku))
            {
                SSF_TLS_TRACE_HS_ERROR(&s->trace, "Post-handshake message rejected");
                _SSF_TLSC_ALERT(s, alert);
                return _SSFTLSCFail(s);
            }
            if (ku != SSF_TLSC_NO_KEY_UPDATE)
            {
                /* The server's next records use its next key (RFC 8446 4.6.3) */
                _UpdateTrafficKeys(s, s->serverAppTrafficSecret, &s->recvState,
                                   &s->recvStateInited);
                if (ku == 1u) s->keyUpdateOwed = true;   /* One reply answers any number */
                SSF_TLS_TRACE_CRYPTO_INFO(&s->trace, "KeyUpdate received (%s); server key "
                                          "updated", (ku == 1u) ? "update requested" :
                                          "update not requested");
            }
            s->hsBufLen = 0;                   /* Nothing for the application */
            s->hsBufPos = 0;
        }
        else { _SSF_TLSC_ALERT(s, SSF_TLS_ALERT_UNEXPECTED_MSG); return _SSFTLSCFail(s); }
    }
    if (s->hsBufPos >= s->hsBufLen) return SSF_NET_IO_WANT_READ;

    *gotOut = s->hsBufLen - s->hsBufPos;
    if (*gotOut > size) *gotOut = size;
    memcpy(buf, &s->hsBuf[s->hsBufPos], *gotOut);
    s->hsBufPos += *gotOut;
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Finishes sending: writes out the record send() left partly written, then close_notify (RFC    */
/* 8446 6.1), then the inner transport's shutdown(). SUCCESS once all of it is delivered,        */
/* WANT_WRITE while bytes remain, CLOSED or ERROR if the connection fails. send() returns ERROR  */
/* afterwards; recv() still works.                                                               */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCShutdown(SSFNetTransport_t *t)
{
    SSFTLSCSession_t *s = _SSFTLSCSelf(t);
    SSFTLSIOResult_t r;

    if (s->connected == false) return SSF_NET_IO_ERROR;

    r = _SendPending(s);                       /* Application data, or a close_notify resumed */
    if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
    if (r != SSF_TLS_IO_SUCCESS) return _SSFTLSCFail(s);

    if (s->closeNotifySent == false)
    {
        static const uint8_t alert[2] = { 1u, SSF_TLS_ALERT_CLOSE_NOTIFY }; /* warning */

        SSF_TLS_TRACE_ALERT(&s->trace, "Sending alert level=%u desc=%u", alert[0], alert[1]);
        r = _SendEncRecordOnce(s, SSF_TLS_CT_ALERT, alert, sizeof(alert));
        if (r == SSF_TLS_IO_ERROR) return _SSFTLSCFail(s);
        s->closeNotifySent = true;             /* Encrypted; any unsent tail stays pending */
        if (r == SSF_TLS_IO_WANT_WRITE) return SSF_NET_IO_WANT_WRITE;
    }

    /* Everything is with the inner transport; it may buffer too. */
    {
        SSFNetIOResult_t ir = s->inner->shutdown(s->inner);

        if ((ir == SSF_NET_IO_SUCCESS) || (ir == SSF_NET_IO_WANT_WRITE) ||
            (ir == SSF_NET_IO_WANT_READ))
        { return ir; }
        s->ioFailed = true;
        if (ir == SSF_NET_IO_CLOSED) s->peerClosed = true;
        return _SSFTLSCFail(s);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Ends the connection: best-effort close_notify, closes the inner transport, wipes keys. Never   */
/* blocks; a record or close_notify the inner transport cannot take at once is dropped, which    */
/* shutdown() exists to prevent.                                                                 */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCClose(SSFNetTransport_t *t)
{
    SSFTLSCSession_t *s = _SSFTLSCSelf(t);
    bool isHandshaking = (s->hsState != SSF_TLSC_HS_IDLE) && (s->hsState != SSF_TLSC_HS_COMPLETE) &&
                         (s->hsState != SSF_TLSC_HS_ERROR);

    if (s->closeNotifySent)
    {
        (void)_SendPending(s);                 /* shutdown() unfinished: one last push */
    }
    else if (s->connected && s->sendEncrypted && (_SendPending(s) == SSF_TLS_IO_SUCCESS))
    {
        uint8_t alert[2] = { 1u, SSF_TLS_ALERT_CLOSE_NOTIFY }; /* warning, close_notify */
        (void)_SendEncRecordOnce(s, SSF_TLS_CT_ALERT, alert, sizeof(alert));
    }
    else if (isHandshaking && s->clientHelloSent)
    {
        /* RFC 8446 6.1: abandoning a handshake the peer has seen is user_canceled followed by */
        /* close_notify. Protected once handshake send keys exist, plaintext before.            */
        _SSFTLSCSendAlert(s, 1u, SSF_TLS_ALERT_USER_CANCELED);
        _SSFTLSCSendAlert(s, 1u, SSF_TLS_ALERT_CLOSE_NOTIFY);
    }
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
/* Sets, or clears, the client certificate and key; see ssftlsc.h.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFTLSCSetClientCert(SSFTLSCSession_t *session, const uint8_t *const *chainDer,
                          const uint32_t *chainLens, uint8_t chainCount, const SSFPKey_t *key)
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
    if ((chainDer == NULL) && (chainLens == NULL) && (chainCount == 0u) && (key == NULL))
    {
        return true;                                            /* Cleared */
    }
    if ((chainDer == NULL) || (chainLens == NULL) || (chainCount == 0u) || (key == NULL) ||
        (key->type == SSF_PKEY_TYPE_NONE)) return false;

    /* Every entry fits CertificateEntry, and the list fits certificate_list<0..2^24-1> */
    for (i = 0; i < chainCount; i++)
    {
        if ((chainDer[i] == NULL) || (chainLens[i] == 0u) || (chainLens[i] > 0xFFFFFFu))
        {
            return false;
        }
        total += 3u + (size_t)chainLens[i] + 2u;
        if (total > 0xFFFFFFu) return false;
    }
    if (!_ClientCertMatchesKey(chainDer[0], chainLens[0], key))
    {
        SSF_TLS_TRACE_CERT_ERROR(&session->trace, "Client certificate does not match its key");
        return false;
    }
    session->clientChainDer = chainDer;
    session->clientChainLens = chainLens;
    session->clientKey = key;
    session->clientChainCount = chainCount;
    return true;
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
