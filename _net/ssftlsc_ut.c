/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftlsc_ut.c                                                                                  */
/* Unit test for the TLS 1.3 client transport.                                                   */
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
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else /* _WIN32 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* _WIN32 */

#ifndef __APPLE__
#undef htons                         /* ssfport.h defines its own; see ssfnetsock.c */
#undef ntohs
#undef htonl
#undef ntohl
#endif /* __APPLE__ */

#include "ssfport.h"
#include "ssfassert.h"
#include "ssfnet.h"
#include "ssfnetsock.h"
#include "ssftlsc.h"
#include "ssfpkey.h"
#include "ssfecdsa.h"
#include "ssfed25519.h"
#include "ssfrsa.h"
#include "ssfsha2.h"
#include "ssftlsc_ut_client.h"

#if SSF_CONFIG_TLSC_UNIT_TEST == 1

#if SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED != 1
/* Its transport tests run without a trust store. */
#error The ssftlsc unit test needs SSF_TLSC_CONFIG_ALLOW_UNAUTHENTICATED 1.
#endif

/* --------------------------------------------------------------------------------------------- */
/* Test-side loopback listener. No TLS server is involved; handshakes against a real server are   */
/* exercised by interop testing (see ssftlsc_punchlist.md).                                      */
/* --------------------------------------------------------------------------------------------- */
#ifdef _WIN32
typedef SOCKET SSFTLSCUTFd_t;
#define SSF_TLSC_UT_INVALID          INVALID_SOCKET
#define SSF_TLSC_UT_CLOSE(s)         closesocket(s)
#define SSF_TLSC_UT_NFDS(s)          (0)
#else
typedef int SSFTLSCUTFd_t;
#define SSF_TLSC_UT_INVALID          (-1)
#define SSF_TLSC_UT_CLOSE(s)         close(s)
#define SSF_TLSC_UT_NFDS(s)          ((s) + 1)
#endif
#define SSF_TLSC_UT_WAIT_TICKS       (SSF_TICKS_PER_SEC * 5u)

static SSFNetSock_t _utSock;
static SSFTLSCSession_t _utSession;
static SSFTLSCSession_t _utSession2;

/* --------------------------------------------------------------------------------------------- */
/* Returns a listener on 127.0.0.1 and its port.                                                 */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSCUTFd_t _SSFTLSCUTListen(uint16_t *portOut)
{
    struct sockaddr_in sin;
    socklen_t len = (socklen_t)sizeof(sin);
    SSFTLSCUTFd_t l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    SSF_ASSERT(l != SSF_TLSC_UT_INVALID);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    SSF_ASSERT(inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr) == 1);
    SSF_ASSERT(bind(l, (struct sockaddr *)&sin, (socklen_t)sizeof(sin)) == 0);
    SSF_ASSERT(listen(l, 4) == 0);
    SSF_ASSERT(getsockname(l, (struct sockaddr *)&sin, &len) == 0);
    *portOut = (uint16_t)((((const uint8_t *)&sin.sin_port)[0] << 8) |
                          ((const uint8_t *)&sin.sin_port)[1]);
    return l;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if fd becomes readable within the wait.                                          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCUTReadable(SSFTLSCUTFd_t fd)
{
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    return (select(SSF_TLSC_UT_NFDS((int)fd), &rfds, NULL, NULL, &tv) > 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if len bytes at p are all zero.                                                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCUTIsZero(const void *p, size_t len)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;

    for (i = 0; i < len; i++) { if (b[i] != 0u) return false; }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Reads one whole TLS record from fd into out. Returns its length, or 0 on EOF / timeout.       */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFTLSCUTRecvRecord(SSFTLSCUTFd_t fd, uint8_t *out, size_t outSize)
{
    SSFPortTick_t end = SSFPortGetTick64() + SSF_TLSC_UT_WAIT_TICKS;
    size_t have = 0;
    size_t want = 5;

    while ((have < want) && (SSFPortGetTick64() < end))
    {
        int n;

        if (!_SSFTLSCUTReadable(fd)) continue;
        n = recv(fd, (char *)&out[have], (int)(want - have), 0);
        if (n <= 0) return 0;
        have += (size_t)n;
        if ((have == 5u) && (want == 5u))
        {
            want = 5u + (((size_t)out[3] << 8) | out[4]);
            SSF_ASSERT(want <= outSize);
        }
    }
    return (have == want) ? have : 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a connection reaches listener l within about 200 ms.                          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFTLSCUTConnectArrives(SSFTLSCUTFd_t l)
{
    SSFPortTick_t end = SSFPortGetTick64() + (SSF_TICKS_PER_SEC / 5u);

    do { if (_SSFTLSCUTReadable(l)) return true; } while (SSFPortGetTick64() < end);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Polls the session, accepting the connection on l when it arrives. Returns the first result    */
/* other than WANT_READ/WANT_WRITE, or the last one after stopAfterTicks. *peerOut receives the  */
/* accepted socket (invalid if none).                                                            */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCUTPoll(SSFTLSCUTFd_t l, SSFTLSCUTFd_t *peerOut,
                                       SSFPortTick_t stopAfterTicks)
{
    SSFNetTransport_t *t = &_utSession.transport;
    SSFPortTick_t end = SSFPortGetTick64() + stopAfterTicks;
    SSFNetIOResult_t r;

    do
    {
        r = t->pollOpen(t);
        if ((r != SSF_NET_IO_WANT_READ) && (r != SSF_NET_IO_WANT_WRITE)) return r;
        if ((*peerOut == SSF_TLSC_UT_INVALID) && (l != SSF_TLSC_UT_INVALID) &&
            _SSFTLSCUTReadable(l))
        { *peerOut = accept(l, NULL, NULL); }
    } while (SSFPortGetTick64() < end);
    return r;
}

/* --------------------------------------------------------------------------------------------- */
/* Certificate message parsing (RFC 8446 4.4.2). Bodies exclude the 4-byte handshake header.      */
/* Each array is exactly the message size, so AddressSanitizer catches any read past its end.    */
/* --------------------------------------------------------------------------------------------- */
#define SSF_TLSC_UT_CERT_OK(body, count) do { \
    const uint8_t *_d[SSF_X509_CONFIG_MAX_CHAIN_DEPTH]; \
    uint32_t _l[SSF_X509_CONFIG_MAX_CHAIN_DEPTH]; \
    uint8_t _n = 0xffu; \
    SSF_ASSERT(_SSFTLSCParseCertificateForTest((body), sizeof(body), _d, _l, &_n)); \
    SSF_ASSERT(_n == (count)); } while (0)
#define SSF_TLSC_UT_CERT_BAD(body) do { \
    const uint8_t *_d[SSF_X509_CONFIG_MAX_CHAIN_DEPTH]; \
    uint32_t _l[SSF_X509_CONFIG_MAX_CHAIN_DEPTH]; \
    uint8_t _n = 0xffu; \
    SSF_ASSERT(_SSFTLSCParseCertificateForTest((body), sizeof(body), _d, _l, &_n) == false); \
    SSF_ASSERT(_n == 0u); } while (0)

/* ctx 0; certs "AAA" and "BB", no extensions */
static const uint8_t _utCertTwo[] = { 0x00, 0x00, 0x00, 0x0f,
    0x00, 0x00, 0x03, 'A', 'A', 'A', 0x00, 0x00,
    0x00, 0x00, 0x02, 'B', 'B', 0x00, 0x00 };
/* ctx 0; one cert carrying a status_request extension, which the client never requested */
static const uint8_t _utCertExt[] = { 0x00, 0x00, 0x00, 0x0b,
    0x00, 0x00, 0x02, 'A', 'A', 0x00, 0x04, 0x00, 0x05, 0x00, 0x00 };
/* Server certificate_request_context MUST be empty */
static const uint8_t _utCertCtx[] = { 0x01, 0xff, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x03, 'A', 'A', 'A', 0x00, 0x00 };
/* Context length runs past the message: the list length is not inside the body */
static const uint8_t _utCertCtxOver[] = { 0x20, 0x00, 0x00, 0x00 };
/* Trailing byte after the certificate list */
static const uint8_t _utCertTrailing[] = { 0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x03, 'A', 'A', 'A', 0x00, 0x00, 0x00 };
/* List length runs past the message */
static const uint8_t _utCertListOver[] = { 0x00, 0x00, 0x00, 0x09,
    0x00, 0x00, 0x03, 'A', 'A', 'A', 0x00, 0x00 };
/* Empty cert_data (cert_data<1..2^24-1>) */
static const uint8_t _utCertEmptyCert[] = { 0x00, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x00, 0x00 };
/* Certificate extensions run past the list */
static const uint8_t _utCertExtOver[] = { 0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x03, 'A', 'A', 'A', 0x00, 0x05 };
/* Certificate entry ends before its extensions length */
static const uint8_t _utCertNoExtLen[] = { 0x00, 0x00, 0x00, 0x06,
    0x00, 0x00, 0x03, 'A', 'A', 'A' };
/* cert_data length runs past the list */
static const uint8_t _utCertDataOver[] = { 0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x09, 'A', 'A', 'A', 0x00, 0x00 };
/* Empty certificate list */
static const uint8_t _utCertEmptyList[] = { 0x00, 0x00, 0x00, 0x00 };
/* Shorter than the fixed fields */
static const uint8_t _utCertShort[] = { 0x00, 0x00, 0x00 };

/* --------------------------------------------------------------------------------------------- */
/* Builds a Certificate body of n one-byte certs into buf; the last entry's extension length is  */
/* lastExtLen with no extension bytes following. Returns the body length.                        */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFTLSCUTCertN(uint8_t *buf, size_t bufSize, uint32_t n, uint16_t lastExtLen)
{
    size_t pos = 4;
    uint32_t i;

    SSF_ASSERT(bufSize >= 4u + (n * 6u));
    for (i = 0; i < n; i++)
    {
        uint16_t ext = (i == (n - 1u)) ? lastExtLen : 0u;
        buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x01; buf[pos++] = (uint8_t)('A' + i);
        buf[pos++] = (uint8_t)(ext >> 8); buf[pos++] = (uint8_t)ext;
    }
    buf[0] = 0x00;
    buf[1] = (uint8_t)((pos - 4u) >> 16); buf[2] = (uint8_t)((pos - 4u) >> 8);
    buf[3] = (uint8_t)(pos - 4u);
    return pos;
}

static void _SSFTLSCUTParseCertificate(void)
{
    const uint8_t *d[SSF_X509_CONFIG_MAX_CHAIN_DEPTH];
    uint32_t l[SSF_X509_CONFIG_MAX_CHAIN_DEPTH];
    uint8_t n;
    uint8_t many[4u + ((SSF_X509_CONFIG_MAX_CHAIN_DEPTH + 1u) * 6u)];
    size_t manyLen;

    /* Well formed */
    SSF_TLSC_UT_CERT_OK(_utCertTwo, 2u);
    SSF_ASSERT(_SSFTLSCParseCertificateForTest(_utCertTwo, sizeof(_utCertTwo), d, l, &n));
    SSF_ASSERT((d[0] == &_utCertTwo[7]) && (l[0] == 3u));
    SSF_ASSERT((d[1] == &_utCertTwo[15]) && (l[1] == 2u));

    /* Malformed or not allowed for a server Certificate */
    SSF_TLSC_UT_CERT_BAD(_utCertExt);         /* Unsolicited certificate extension (4.4.2) */
    SSF_TLSC_UT_CERT_BAD(_utCertCtx);
    SSF_TLSC_UT_CERT_BAD(_utCertCtxOver);
    SSF_TLSC_UT_CERT_BAD(_utCertTrailing);
    SSF_TLSC_UT_CERT_BAD(_utCertListOver);
    SSF_TLSC_UT_CERT_BAD(_utCertEmptyCert);
    SSF_TLSC_UT_CERT_BAD(_utCertExtOver);
    SSF_TLSC_UT_CERT_BAD(_utCertNoExtLen);
    SSF_TLSC_UT_CERT_BAD(_utCertDataOver);
    SSF_TLSC_UT_CERT_BAD(_utCertEmptyList);
    SSF_TLSC_UT_CERT_BAD(_utCertShort);

    /* More certificates than SSF_X509_CONFIG_MAX_CHAIN_DEPTH (the verifier's limit, the only    */
    /* chain limit): the first ones are kept, every entry is still validated, and the number    */
    /* seen is reported so a failure caused by the truncation can say so.                      */
    manyLen = _SSFTLSCUTCertN(many, sizeof(many), SSF_X509_CONFIG_MAX_CHAIN_DEPTH + 1u, 0u);
    SSF_ASSERT(_SSFTLSCParseCertificateForTest(many, manyLen, d, l, &n));
    SSF_ASSERT(n == SSF_X509_CONFIG_MAX_CHAIN_DEPTH);
    SSF_ASSERT((d[0] == &many[7]) && (l[0] == 1u));
    {
        uint8_t seen = 0;

        SSF_ASSERT(_SSFTLSCParseCertificateSeenForTest(many, manyLen, d, l, &n, &seen));
        SSF_ASSERT((n == SSF_X509_CONFIG_MAX_CHAIN_DEPTH) &&
                   (seen == (uint8_t)(SSF_X509_CONFIG_MAX_CHAIN_DEPTH + 1u)));
        SSF_ASSERT(_SSFTLSCParseCertificateSeenForTest(_utCertTwo, sizeof(_utCertTwo), d, l, &n,
                                                       &seen));
        SSF_ASSERT((n == 2u) && (seen == 2u));
    }
    manyLen = _SSFTLSCUTCertN(many, sizeof(many), SSF_X509_CONFIG_MAX_CHAIN_DEPTH + 1u, 1u);
    SSF_ASSERT(_SSFTLSCParseCertificateForTest(many, manyLen, d, l, &n) == false);
}

/* --------------------------------------------------------------------------------------------- */
/* EncryptedExtensions validation (RFC 8446 4.3.1, 4.2). Exactly sized bodies; alert checked.     */
/* --------------------------------------------------------------------------------------------- */
#define SSF_TLSC_UT_EE(body, wantAlert) do { \
    uint8_t _a = 0xffu; \
    bool _ok = _SSFTLSCParseEncryptedExtensionsForTest((body), sizeof(body), &_a); \
    SSF_ASSERT(_ok == ((wantAlert) == 0u)); \
    SSF_ASSERT(_a == (wantAlert)); } while (0)

static const uint8_t _utEeEmpty[]    = { 0x00, 0x00 };
/* server_name acknowledgement: empty extension_data (RFC 6066 3) */
static const uint8_t _utEeSniAck[]   = { 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 };
/* supported_groups: the server's preferences, x25519 + secp256r1 */
static const uint8_t _utEeGroups[]   = { 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x06,
                                         0x00, 0x04, 0x00, 0x1d, 0x00, 0x17 };
static const uint8_t _utEeBoth[]     = { 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x0a, 0x00, 0x06, 0x00, 0x04,
                                         0x00, 0x1d, 0x00, 0x17 };
/* Offered by the ClientHello but not allowed in EncryptedExtensions: illegal_parameter */
static const uint8_t _utEeKeyShare[] = { 0x00, 0x08, 0x00, 0x33, 0x00, 0x04,
                                         0x00, 0x1d, 0x00, 0x00 };
static const uint8_t _utEeVersions[] = { 0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
static const uint8_t _utEeSigAlgs[]  = { 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04,
                                         0x00, 0x02, 0x04, 0x03 };
static const uint8_t _utEePskModes[] = { 0x00, 0x06, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01 };
static const uint8_t _utEeDupSni[]   = { 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00 };
/* Not offered by the ClientHello: unsupported_extension */
static const uint8_t _utEeAlpn[]     = { 0x00, 0x0b, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05,
                                         0x04, 'm', 'q', 't', 't' };
static const uint8_t _utEeRsl[]      = { 0x00, 0x06, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x00 };
static const uint8_t _utEePsk[]      = { 0x00, 0x06, 0x00, 0x29, 0x00, 0x02, 0x00, 0x00 };
static const uint8_t _utEeUnknown[]  = { 0x00, 0x04, 0xfa, 0xfa, 0x00, 0x00 };
/* Framing: decode_error */
static const uint8_t _utEeSniData[]  = { 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00 };
static const uint8_t _utEeGroupsOdd[] = { 0x00, 0x07, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x02, 0x00 };
static const uint8_t _utEeGroupsLen[] = { 0x00, 0x08, 0x00, 0x0a, 0x00, 0x04,
                                          0x00, 0x04, 0x00, 0x1d };
static const uint8_t _utEeGroupsNone[] = { 0x00, 0x06, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00 };
static const uint8_t _utEeTrailing[] = { 0x00, 0x00, 0x00 };
static const uint8_t _utEeListOver[] = { 0x00, 0x05, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t _utEeExtOver[]  = { 0x00, 0x04, 0x00, 0x0a, 0x00, 0x05 };
static const uint8_t _utEeShort[]    = { 0x00 };

/* record_size_limit (RFC 8449): value is the peer's TLSInnerPlaintext limit, 64..2^14+1 */
#define SSF_TLSC_UT_EE_RSL(body, wantAlert, wantLimit) do { \
    uint8_t _a = 0xffu; uint16_t _rl = 0xffffu; \
    bool _ok = _SSFTLSCParseEncryptedExtensionsRslForTest((body), sizeof(body), &_a, &_rl); \
    SSF_ASSERT(_ok == ((wantAlert) == 0u)); \
    SSF_ASSERT(_a == (wantAlert)); \
    if (_ok) { SSF_ASSERT(_rl == (wantLimit)); } } while (0)

static const uint8_t _utEeRslMax[]   = { 0x00, 0x06, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01 };
static const uint8_t _utEeRsl1024[]  = { 0x00, 0x06, 0x00, 0x1c, 0x00, 0x02, 0x04, 0x00 };
static const uint8_t _utEeRsl64[]    = { 0x00, 0x06, 0x00, 0x1c, 0x00, 0x02, 0x00, 0x40 };
static const uint8_t _utEeRsl63[]    = { 0x00, 0x06, 0x00, 0x1c, 0x00, 0x02, 0x00, 0x3f };
static const uint8_t _utEeRslOver[]  = { 0x00, 0x06, 0x00, 0x1c, 0x00, 0x02, 0xff, 0xff };
static const uint8_t _utEeRslLen3[]  = { 0x00, 0x07, 0x00, 0x1c, 0x00, 0x03, 0x04, 0x00, 0x00 };
static const uint8_t _utEeRslDup[]   = { 0x00, 0x0c, 0x00, 0x1c, 0x00, 0x02, 0x04, 0x00,
                                         0x00, 0x1c, 0x00, 0x02, 0x04, 0x00 };

static void _SSFTLSCUTRecordSizeLimitEE(void)
{
    uint8_t a;
    uint16_t rl;

    SSF_TLSC_UT_EE_RSL(_utEeRslMax, 0u, 16385u);
    SSF_TLSC_UT_EE_RSL(_utEeRsl1024, 0u, 1024u);
    SSF_TLSC_UT_EE_RSL(_utEeRsl64, 0u, 64u);                    /* Smallest allowed */
    SSF_TLSC_UT_EE_RSL(_utEeRsl63, SSF_TLS_ALERT_ILLEGAL_PARAMETER, 0u);
    SSF_TLSC_UT_EE_RSL(_utEeRslOver, 0u, 16385u);               /* Capped at 2^14+1 (a MAY) */
    SSF_TLSC_UT_EE_RSL(_utEeRslLen3, SSF_TLS_ALERT_DECODE_ERROR, 0u);
    SSF_TLSC_UT_EE_RSL(_utEeRslDup, SSF_TLS_ALERT_ILLEGAL_PARAMETER, 0u);
    /* Absent: not negotiated */
    SSF_ASSERT(_SSFTLSCParseEncryptedExtensionsRslForTest(_utEeGroups, sizeof(_utEeGroups),
                                                          &a, &rl));
    SSF_ASSERT(rl == 0u);
}

static void _SSFTLSCUTParseEncryptedExtensions(void)
{
    SSF_TLSC_UT_EE(_utEeEmpty, 0u);
    SSF_TLSC_UT_EE(_utEeSniAck, 0u);
    SSF_TLSC_UT_EE(_utEeGroups, 0u);
    SSF_TLSC_UT_EE(_utEeBoth, 0u);
    SSF_TLSC_UT_EE(_utEeKeyShare, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_EE(_utEeVersions, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_EE(_utEeSigAlgs, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_EE(_utEePskModes, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_EE(_utEeDupSni, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_EE(_utEeAlpn, SSF_TLS_ALERT_UNSUPPORTED_EXT);
    SSF_TLSC_UT_EE(_utEeRsl, 0u);         /* record_size_limit is offered: see below */
    SSF_TLSC_UT_EE(_utEePsk, SSF_TLS_ALERT_UNSUPPORTED_EXT);
    SSF_TLSC_UT_EE(_utEeUnknown, SSF_TLS_ALERT_UNSUPPORTED_EXT);
    SSF_TLSC_UT_EE(_utEeSniData, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_EE(_utEeGroupsOdd, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_EE(_utEeGroupsLen, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_EE(_utEeGroupsNone, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_EE(_utEeTrailing, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_EE(_utEeListOver, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_EE(_utEeExtOver, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_EE(_utEeShort, SSF_TLS_ALERT_DECODE_ERROR);
    _SSFTLSCUTRecordSizeLimitEE();
}

/* --------------------------------------------------------------------------------------------- */
/* CertificateRequest validation (RFC 8446 4.3.2, 4.2). Exactly sized bodies; alert checked.     */
/* --------------------------------------------------------------------------------------------- */
#define SSF_TLSC_UT_CR(body, wantAlert) do { \
    uint8_t _a = 0xffu; \
    bool _ok = _SSFTLSCParseCertificateRequestForTest((body), sizeof(body), &_a); \
    SSF_ASSERT(_ok == ((wantAlert) == 0u)); \
    SSF_ASSERT(_a == (wantAlert)); } while (0)

/* Empty context, signature_algorithms { ecdsa_secp256r1_sha256 } */
static const uint8_t _utCrMin[]       = { 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04,
                                          0x00, 0x02, 0x04, 0x03 };
/* As OpenSSL sends: signature_algorithms with several schemes, then certificate_authorities */
static const uint8_t _utCrWithCas[]   = { 0x00, 0x00, 0x14, 0x00, 0x0d, 0x00, 0x06,
                                          0x00, 0x04, 0x04, 0x03, 0x08, 0x04,
                                          0x00, 0x2f, 0x00, 0x06, 0x00, 0x04, 0x30, 0x02,
                                          0x31, 0x00 };
/* Allowed in CertificateRequest and ignored: status_request, SCT, oid_filters, sig_algs_cert */
static const uint8_t _utCrAllowed[]   = { 0x00, 0x00, 0x1e, 0x00, 0x05, 0x00, 0x00,
                                          0x00, 0x12, 0x00, 0x00,
                                          0x00, 0x30, 0x00, 0x02, 0x00, 0x00,
                                          0x00, 0x32, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03,
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07 };
/* Unrecognized extension before signature_algorithms: ignored (4.3.2) */
static const uint8_t _utCrUnknown[]   = { 0x00, 0x00, 0x0d, 0xfa, 0xfa, 0x00, 0x01, 0x00,
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
/* Non-empty context: only for post-handshake authentication, never offered */
static const uint8_t _utCrContext[]   = { 0x01, 0xaa, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04,
                                          0x00, 0x02, 0x04, 0x03 };
/* signature_algorithms missing */
static const uint8_t _utCrNoSigAlgs[] = { 0x00, 0x00, 0x06, 0x00, 0x2f, 0x00, 0x02, 0x00, 0x00 };
static const uint8_t _utCrOnlyUnk[]   = { 0x00, 0x00, 0x04, 0xfa, 0xfa, 0x00, 0x00 };
/* Extension list below its 2-byte minimum */
static const uint8_t _utCrNoExts[]    = { 0x00, 0x00, 0x00 };
/* Bad signature_algorithms bodies: empty list, odd list, list length mismatch */
static const uint8_t _utCrSigEmpty[]  = { 0x00, 0x00, 0x06, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x00 };
static const uint8_t _utCrSigOdd[]    = { 0x00, 0x00, 0x09, 0x00, 0x0d, 0x00, 0x05,
                                          0x00, 0x03, 0x04, 0x03, 0x08 };
static const uint8_t _utCrSigMis[]    = { 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04,
                                          0x00, 0x04, 0x04, 0x03 };
static const uint8_t _utCrSigShort[]  = { 0x00, 0x00, 0x05, 0x00, 0x0d, 0x00, 0x01, 0x00 };
/* Duplicates: signature_algorithms twice, an unknown extension twice */
static const uint8_t _utCrDupSig[]    = { 0x00, 0x00, 0x10, 0x00, 0x0d, 0x00, 0x04,
                                          0x00, 0x02, 0x04, 0x03,
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x04 };
static const uint8_t _utCrDupUnk[]    = { 0x00, 0x00, 0x10, 0xfa, 0xfa, 0x00, 0x00,
                                          0xfa, 0xfa, 0x00, 0x00,
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
/* Extensions the client sends that are not allowed in CertificateRequest */
static const uint8_t _utCrKeyShare[]  = { 0x00, 0x00, 0x0c, 0x00, 0x33, 0x00, 0x00,
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
static const uint8_t _utCrSni[]       = { 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
static const uint8_t _utCrGroups[]    = { 0x00, 0x00, 0x10, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02,
                                          0x00, 0x1d,
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
static const uint8_t _utCrVersions[]  = { 0x00, 0x00, 0x0e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
static const uint8_t _utCrPskModes[]  = { 0x00, 0x00, 0x0d, 0x00, 0x2d, 0x00, 0x01, 0x01,
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
/* ALPN is offered but not specified for CertificateRequest */
static const uint8_t _utCrAlpn[]      = { 0x00, 0x00, 0x13, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05,
                                          0x04, 'm', 'q', 't', 't',
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
static const uint8_t _utCrRsl[]       = { 0x00, 0x00, 0x0e, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x00,
                                          0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
/* Framing: list longer / shorter than the message, extension past the list, truncated */
static const uint8_t _utCrListOver[]  = { 0x00, 0x00, 0x09, 0x00, 0x0d, 0x00, 0x04,
                                          0x00, 0x02, 0x04, 0x03 };
static const uint8_t _utCrTrailing[]  = { 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04,
                                          0x00, 0x02, 0x04, 0x03, 0x00 };
static const uint8_t _utCrExtOver[]   = { 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x05,
                                          0x00, 0x02, 0x04, 0x03 };
/* An ignored extension claiming more bytes than the message holds */
static const uint8_t _utCrUnkOver[]   = { 0x00, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x04,
                                          0x00, 0x02, 0x04, 0x03, 0xfa, 0xfa, 0x00, 0x02 };
static const uint8_t _utCrCtxOver[]   = { 0x05, 0x00 };
static const uint8_t _utCrShort[]     = { 0x00, 0x00 };
static const uint8_t _utCrHdrShort[]  = { 0x00, 0x00, 0x03, 0x00, 0x0d, 0x00 };

static void _SSFTLSCUTParseCertificateRequest(void)
{
    SSF_TLSC_UT_CR(_utCrMin, 0u);
    SSF_TLSC_UT_CR(_utCrWithCas, 0u);
    SSF_TLSC_UT_CR(_utCrAllowed, 0u);
    SSF_TLSC_UT_CR(_utCrUnknown, 0u);
    SSF_TLSC_UT_CR(_utCrContext, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_CR(_utCrNoSigAlgs, SSF_TLS_ALERT_MISSING_EXTENSION);
    SSF_TLSC_UT_CR(_utCrOnlyUnk, SSF_TLS_ALERT_MISSING_EXTENSION);
    SSF_TLSC_UT_CR(_utCrNoExts, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrSigEmpty, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrSigOdd, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrSigMis, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrSigShort, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrDupSig, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_CR(_utCrDupUnk, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_CR(_utCrKeyShare, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_CR(_utCrSni, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_CR(_utCrGroups, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_CR(_utCrVersions, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_CR(_utCrPskModes, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_CR(_utCrRsl, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_CR(_utCrAlpn, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_CR(_utCrListOver, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrTrailing, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrExtOver, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrUnkOver, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrCtxOver, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrShort, SSF_TLS_ALERT_DECODE_ERROR);
    SSF_TLSC_UT_CR(_utCrHdrShort, SSF_TLS_ALERT_DECODE_ERROR);
}

/* --------------------------------------------------------------------------------------------- */
/* CertificateVerify parsing (RFC 8446 4.4.3, 4.2.3). Exactly sized bodies, as above.            */
/* --------------------------------------------------------------------------------------------- */
#define SSF_TLSC_UT_CV(body, ok, wantScheme, wantLen) do { \
    uint16_t _s = 0xffffu; uint16_t _l = 0xffffu; \
    SSF_ASSERT(_SSFTLSCParseCertificateVerifyForTest((body), sizeof(body), &_s, &_l) == (ok)); \
    SSF_ASSERT((_s == (wantScheme)) && (_l == (wantLen))); } while (0)

static const uint8_t _utCvEcdsa256[] = { 0x04, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc };
static const uint8_t _utCvEcdsa384[] = { 0x05, 0x03, 0x00, 0x02, 0xaa, 0xbb };
static const uint8_t _utCvPss256[]   = { 0x08, 0x04, 0x00, 0x02, 0xaa, 0xbb };
static const uint8_t _utCvPss384[]   = { 0x08, 0x05, 0x00, 0x02, 0xaa, 0xbb };
static const uint8_t _utCvEd25519[]  = { 0x08, 0x07, 0x00, 0x02, 0xaa, 0xbb };
/* rsa_pkcs1_* is for certificate signatures only, never a handshake signature (4.2.3) */
static const uint8_t _utCvPkcs1256[] = { 0x04, 0x01, 0x00, 0x02, 0xaa, 0xbb };
static const uint8_t _utCvPkcs1384[] = { 0x05, 0x01, 0x00, 0x02, 0xaa, 0xbb };
static const uint8_t _utCvPkcs1Sha1[] = { 0x02, 0x01, 0x00, 0x02, 0xaa, 0xbb };
/* Schemes the ClientHello did not offer */
static const uint8_t _utCvPssPss[]   = { 0x08, 0x09, 0x00, 0x02, 0xaa, 0xbb };
static const uint8_t _utCvPss512[]   = { 0x08, 0x06, 0x00, 0x02, 0xaa, 0xbb };
static const uint8_t _utCvEcdsa521[] = { 0x06, 0x03, 0x00, 0x02, 0xaa, 0xbb };
/* Framing */
static const uint8_t _utCvTrailing[] = { 0x04, 0x03, 0x00, 0x02, 0xaa, 0xbb, 0xcc };
static const uint8_t _utCvSigOver[]  = { 0x04, 0x03, 0x00, 0x05, 0xaa, 0xbb };
static const uint8_t _utCvEmptySig[] = { 0x04, 0x03, 0x00, 0x00 };
static const uint8_t _utCvShort[]    = { 0x04, 0x03, 0x00 };

static void _SSFTLSCUTParseCertificateVerify(void)
{
    SSF_TLSC_UT_CV(_utCvEcdsa256, true, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256, 3u);
    SSF_TLSC_UT_CV(_utCvEcdsa384, true, SSF_TLS_SIG_ECDSA_SECP384R1_SHA384, 2u);
    SSF_TLSC_UT_CV(_utCvPss256, true, SSF_TLS_SIG_RSA_PSS_RSAE_SHA256, 2u);
    SSF_TLSC_UT_CV(_utCvPss384, true, SSF_TLS_SIG_RSA_PSS_RSAE_SHA384, 2u);
    SSF_TLSC_UT_CV(_utCvEd25519, true, SSF_TLS_SIG_ED25519, 2u);
    SSF_TLSC_UT_CV(_utCvPkcs1256, false, 0u, 0u);
    SSF_TLSC_UT_CV(_utCvPkcs1384, false, 0u, 0u);
    SSF_TLSC_UT_CV(_utCvPkcs1Sha1, false, 0u, 0u);
    SSF_TLSC_UT_CV(_utCvPssPss, false, 0u, 0u);
    SSF_TLSC_UT_CV(_utCvPss512, false, 0u, 0u);
    SSF_TLSC_UT_CV(_utCvEcdsa521, false, 0u, 0u);
    SSF_TLSC_UT_CV(_utCvTrailing, false, 0u, 0u);
    SSF_TLSC_UT_CV(_utCvSigOver, false, 0u, 0u);
    SSF_TLSC_UT_CV(_utCvEmptySig, false, 0u, 0u);
    SSF_TLSC_UT_CV(_utCvShort, false, 0u, 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Polls the session until its first bytes (the ClientHello) reach the accepted peer, or the     */
/* usual wait elapses. Returns the last pollOpen() result. Waiting on the data, not a fixed      */
/* interval, keeps the test stable when the host is heavily loaded.                              */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFTLSCUTPollUntilClientHello(SSFTLSCUTFd_t l, SSFTLSCUTFd_t *peerOut)
{
    SSFNetTransport_t *t = &_utSession.transport;
    SSFPortTick_t end = SSFPortGetTick64() + SSF_TLSC_UT_WAIT_TICKS;
    SSFNetIOResult_t r;

    do
    {
        r = t->pollOpen(t);
        if ((r != SSF_NET_IO_WANT_READ) && (r != SSF_NET_IO_WANT_WRITE)) return r;
        if ((*peerOut == SSF_TLSC_UT_INVALID) && _SSFTLSCUTReadable(l))
        { *peerOut = accept(l, NULL, NULL); }
        if ((*peerOut != SSF_TLSC_UT_INVALID) && _SSFTLSCUTReadable(*peerOut)) return r;
    } while (SSFPortGetTick64() < end);
    return r;
}

/* --------------------------------------------------------------------------------------------- */
/* ClientHello fields, for comparing ClientHello1 with ClientHello2 (RFC 8446 4.1.2).             */
/* --------------------------------------------------------------------------------------------- */
#define SSF_TLSC_UT_MAX_EXTS (16u)
typedef struct
{
    const uint8_t *random;           /* 32 bytes                                                */
    const uint8_t *sid;
    uint8_t sidLen;
    const uint8_t *suites;           /* cipher_suites vector including its length               */
    size_t suitesLen;
    const uint8_t *comp;             /* legacy_compression_methods including its length         */
    size_t compLen;
    uint16_t extType[SSF_TLSC_UT_MAX_EXTS];
    const uint8_t *extData[SSF_TLSC_UT_MAX_EXTS];
    uint16_t extLen[SSF_TLSC_UT_MAX_EXTS];
    uint8_t extCount;
} SSFTLSCUTClientHello_t;

/* Parses a ClientHello record, asserting it is well formed. */
static void _SSFTLSCUTParseClientHello(const uint8_t *rec, size_t recLen,
                                       SSFTLSCUTClientHello_t *ch)
{
    const uint8_t *b = &rec[9];                   /* Body: after record and handshake headers */
    size_t len;
    size_t p;
    size_t end;

    SSF_ASSERT(recLen > 9u);
    SSF_ASSERT((rec[0] == SSF_TLS_CT_HANDSHAKE) && (rec[5] == SSF_TLS_HS_CLIENT_HELLO));
    len = ((size_t)rec[6] << 16) | ((size_t)rec[7] << 8) | rec[8];
    SSF_ASSERT((5u + ((size_t)rec[3] << 8 | rec[4])) == recLen);
    SSF_ASSERT((9u + len) == recLen);
    memset(ch, 0, sizeof(*ch));
    SSF_ASSERT((b[0] == 0x03u) && (b[1] == 0x03u));
    ch->random = &b[2];
    ch->sidLen = b[34];
    ch->sid = &b[35];
    p = 35u + ch->sidLen;
    ch->suites = &b[p];
    ch->suitesLen = 2u + (((size_t)b[p] << 8) | b[p + 1u]);
    p += ch->suitesLen;
    ch->comp = &b[p];
    ch->compLen = 1u + b[p];
    p += ch->compLen;
    end = p + 2u + (((size_t)b[p] << 8) | b[p + 1u]);
    SSF_ASSERT(end == len);
    p += 2u;
    while (p < end)
    {
        SSF_ASSERT(ch->extCount < SSF_TLSC_UT_MAX_EXTS);
        ch->extType[ch->extCount] = (uint16_t)(((uint16_t)b[p] << 8) | b[p + 1u]);
        ch->extLen[ch->extCount] = (uint16_t)(((uint16_t)b[p + 2u] << 8) | b[p + 3u]);
        ch->extData[ch->extCount] = &b[p + 4u];
        p += 4u + ch->extLen[ch->extCount];
        SSF_ASSERT(p <= end);
        ch->extCount++;
    }
}

/* Builds a plaintext HelloRetryRequest record answering ClientHello1 ch1: cipher suite suite,   */
/* selected group secp256r1, and a cookie of cookieLen bytes (0 for none). Returns its length.   */
static size_t _SSFTLSCUTBuildHrr(uint8_t *out, size_t outSize, const SSFTLSCUTClientHello_t *ch1,
                                 uint16_t suite, size_t cookieLen)
{
    static const uint8_t hrrRandom[32] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
        0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
        0x33, 0x9C };
    size_t p = 9;
    size_t extStart;
    size_t i;

    SSF_ASSERT(outSize >= 9u + 2u + 32u + 1u + ch1->sidLen + 3u + 2u + 6u + 6u + 6u + cookieLen);
    out[p++] = 0x03; out[p++] = 0x03;
    memcpy(&out[p], hrrRandom, 32); p += 32;
    out[p++] = ch1->sidLen; memcpy(&out[p], ch1->sid, ch1->sidLen); p += ch1->sidLen;
    out[p++] = (uint8_t)(suite >> 8); out[p++] = (uint8_t)suite;          /* cipher_suite */
    out[p++] = 0x00;                                         /* legacy_compression_method */
    extStart = p; p += 2;
    out[p++] = 0x00; out[p++] = 0x2b; out[p++] = 0x00; out[p++] = 0x02;   /* supported_versions */
    out[p++] = 0x03; out[p++] = 0x04;
    out[p++] = 0x00; out[p++] = 0x33; out[p++] = 0x00; out[p++] = 0x02;   /* key_share: group */
    out[p++] = 0x00; out[p++] = 0x17;
    if (cookieLen > 0u)
    {
        out[p++] = 0x00; out[p++] = 0x2c;                                  /* cookie */
        out[p++] = (uint8_t)((cookieLen + 2u) >> 8); out[p++] = (uint8_t)(cookieLen + 2u);
        out[p++] = (uint8_t)(cookieLen >> 8); out[p++] = (uint8_t)cookieLen;
        for (i = 0; i < cookieLen; i++) out[p++] = (uint8_t)(0xc0u + i);
    }
    out[extStart] = (uint8_t)((p - extStart - 2u) >> 8);
    out[extStart + 1u] = (uint8_t)(p - extStart - 2u);
    out[0] = SSF_TLS_CT_HANDSHAKE; out[1] = 0x03; out[2] = 0x03;
    out[3] = (uint8_t)((p - 5u) >> 8); out[4] = (uint8_t)(p - 5u);
    out[5] = SSF_TLS_HS_SERVER_HELLO;
    out[6] = (uint8_t)((p - 9u) >> 16);
    out[7] = (uint8_t)((p - 9u) >> 8);
    out[8] = (uint8_t)(p - 9u);
    return p;
}

/* Returns the index of extension type in ch, or -1. */
static int _SSFTLSCUTFindExt(const SSFTLSCUTClientHello_t *ch, uint16_t type)
{
    uint8_t i;

    for (i = 0; i < ch->extCount; i++) { if (ch->extType[i] == type) return (int)i; }
    return -1;
}

/* --------------------------------------------------------------------------------------------- */
/* Opens the session to listener l and reads ClientHello1 (into ch1Rec / ch1) and the            */
/* compatibility CCS. Returns the accepted peer, ready for the test to answer.                   */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSCUTFd_t _SSFTLSCUTRunToClientHello(SSFTLSCUTFd_t l, uint16_t port, uint8_t *ch1Rec,
                                                size_t ch1RecSize, SSFTLSCUTClientHello_t *ch1)
{
    SSFNetTransport_t *t = &_utSession.transport;
    SSFTLSCUTFd_t peer = SSF_TLSC_UT_INVALID;
    size_t n;
    uint8_t ccs[16];

    SSF_ASSERT(t->open(t, "localhost", sizeof("localhost"), port));
    (void)_SSFTLSCUTPollUntilClientHello(l, &peer);
    SSF_ASSERT(peer != SSF_TLSC_UT_INVALID);
    n = _SSFTLSCUTRecvRecord(peer, ch1Rec, ch1RecSize);
    _SSFTLSCUTParseClientHello(ch1Rec, n, ch1);
    SSF_ASSERT(_SSFTLSCUTRecvRecord(peer, ccs, sizeof(ccs)) == 6u);      /* Compatibility CCS */
    return peer;
}

/* --------------------------------------------------------------------------------------------- */
/* Drives a handshake to ClientHello1 against listener l, answers it with an HRR carrying a       */
/* cookie of cookieLen bytes, and returns the accepted peer with ch1 filled in (records kept in   */
/* ch1Rec, which must stay valid while ch1 is used).                                              */
/* --------------------------------------------------------------------------------------------- */
static SSFTLSCUTFd_t _SSFTLSCUTSendHrr(SSFTLSCUTFd_t l, uint16_t port, uint8_t *ch1Rec,
                                       size_t ch1RecSize, SSFTLSCUTClientHello_t *ch1,
                                       uint16_t suite, size_t cookieLen, uint8_t *hrrRec,
                                       size_t hrrRecSize, size_t *hrrRecLenOut)
{
    SSFNetTransport_t *t = &_utSession.transport;
    SSFTLSCUTFd_t peer = SSF_TLSC_UT_INVALID;
    size_t n;
    uint8_t ccs[16];

    (void)t;
    (void)n;
    (void)ccs;
    peer = _SSFTLSCUTRunToClientHello(l, port, ch1Rec, ch1RecSize, ch1);
    *hrrRecLenOut = _SSFTLSCUTBuildHrr(hrrRec, hrrRecSize, ch1, suite, cookieLen);
    SSF_ASSERT(send(peer, (const char *)hrrRec, (int)*hrrRecLenOut, 0) == (int)*hrrRecLenOut);
    return peer;
}

/* --------------------------------------------------------------------------------------------- */
/* ClientHello2 after a HelloRetryRequest is ClientHello1 with key_share replaced and the cookie  */
/* added; nothing else may change (RFC 8446 4.1.2). A cookie that cannot be echoed aborts.       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCUTClientHelloRetry(SSFTLSCUTFd_t l, uint16_t port)
{
    SSFNetTransport_t *t = &_utSession.transport;
    static uint8_t ch1Rec[1024];
    static uint8_t ch2Rec[1024];
    static uint8_t hrrRec[1200];
    SSFTLSCUTClientHello_t ch1;
    SSFTLSCUTClientHello_t ch2;
    SSFTLSCUTFd_t peer;
    size_t hrrLen;
    size_t n;
    uint8_t i;
    uint8_t j;
    int ks;
    int ck;
    static const char *const alpnBoth[] = { "x-amzn-mqtt-ca", "mqtt" };

    /* ---- Small cookie: ClientHello2 must match ClientHello1 field for field ---- */
    /* ALPN is set, so ClientHello2 must carry it unchanged too. */
    SSF_ASSERT(SSFTLSCSetALPN(&_utSession, alpnBoth, 2u));
    peer = _SSFTLSCUTSendHrr(l, port, ch1Rec, sizeof(ch1Rec), &ch1,
                             SSF_TLS_CS_AES_128_GCM_SHA256, 16u, hrrRec, sizeof(hrrRec), &hrrLen);
    /* Suite preference: ChaCha20-Poly1305 first (ssfchacha20 is constant-time, ssfaes is not), */
    /* then AES-128-GCM (SHA-256, mandatory to implement), AES-256-GCM, AES-128-CCM.            */
    {
        static const uint8_t wantSuites[] = { 0x00, 0x08, 0x13, 0x03, 0x13, 0x01,
                                              0x13, 0x02, 0x13, 0x04 };

        SSF_ASSERT(ch1.suitesLen == sizeof(wantSuites));
        SSF_ASSERT(memcmp(ch1.suites, wantSuites, sizeof(wantSuites)) == 0);
    }
    /* record_size_limit (RFC 8449), always offered: TLSInnerPlaintext limit = receive size + 1 */
    {
        int rsl = _SSFTLSCUTFindExt(&ch1, 28u);
        uint16_t v;

        SSF_ASSERT(rsl >= 0);
        SSF_ASSERT(ch1.extLen[rsl] == 2u);
        v = (uint16_t)(((uint16_t)ch1.extData[rsl][0] << 8) | ch1.extData[rsl][1]);
        SSF_ASSERT(v == (uint16_t)(SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u));
    }
    /* ALPN (RFC 7301 3.1): ProtocolNameList of the configured names, in order */
    {
        static const uint8_t wantAlpn[] = { 0x00, 0x14, 0x0e, 'x', '-', 'a', 'm', 'z', 'n', '-',
                                            'm', 'q', 't', 't', '-', 'c', 'a',
                                            0x04, 'm', 'q', 't', 't' };
        int alpn = _SSFTLSCUTFindExt(&ch1, SSF_TLS_EXT_ALPN);

        SSF_ASSERT(alpn >= 0);
        SSF_ASSERT(ch1.extLen[alpn] == sizeof(wantAlpn));
        SSF_ASSERT(memcmp(ch1.extData[alpn], wantAlpn, sizeof(wantAlpn)) == 0);
    }
    {
        SSFPortTick_t end = SSFPortGetTick64() + SSF_TLSC_UT_WAIT_TICKS;  /* Client reads HRR, */
        n = 0;                                                            /* sends ClientHello2 */
        while ((n == 0u) && (SSFPortGetTick64() < end))
        {
            (void)t->pollOpen(t);
            if (_SSFTLSCUTReadable(peer)) n = _SSFTLSCUTRecvRecord(peer, ch2Rec, sizeof(ch2Rec));
        }
    }
    SSF_ASSERT(n > 0u);
    _SSFTLSCUTParseClientHello(ch2Rec, n, &ch2);
    SSF_ASSERT(memcmp(ch2.random, ch1.random, 32) == 0);                  /* Same random */
    SSF_ASSERT((ch2.sidLen == ch1.sidLen) && (memcmp(ch2.sid, ch1.sid, ch1.sidLen) == 0));
    SSF_ASSERT((ch2.suitesLen == ch1.suitesLen) &&
               (memcmp(ch2.suites, ch1.suites, ch1.suitesLen) == 0));
    SSF_ASSERT((ch2.compLen == ch1.compLen) && (memcmp(ch2.comp, ch1.comp, ch1.compLen) == 0));
    /* Every ClientHello1 extension other than key_share is present unchanged, in order; the only */
    /* addition is the cookie, echoing the HRR's extension_data exactly.                         */
    j = 0;
    for (i = 0; i < ch1.extCount; i++)
    {
        while ((j < ch2.extCount) && (ch2.extType[j] == 44u)) j++;
        SSF_ASSERT(j < ch2.extCount);
        SSF_ASSERT(ch2.extType[j] == ch1.extType[i]);
        if (ch1.extType[i] != SSF_TLS_EXT_KEY_SHARE)
        {
            SSF_ASSERT((ch2.extLen[j] == ch1.extLen[i]) &&
                       (memcmp(ch2.extData[j], ch1.extData[i], ch1.extLen[i]) == 0));
        }
        j++;
    }
    ks = _SSFTLSCUTFindExt(&ch2, SSF_TLS_EXT_KEY_SHARE);
    SSF_ASSERT(ks >= 0);                    /* One share, for the group the HRR selected */
    SSF_ASSERT(ch2.extLen[ks] == (2u + 4u + 65u));
    SSF_ASSERT((ch2.extData[ks][2] == 0x00u) && (ch2.extData[ks][3] == 0x17u));
    ck = _SSFTLSCUTFindExt(&ch2, 44u);
    SSF_ASSERT(ck >= 0);
    SSF_ASSERT(ch2.extLen[ck] == (2u + 16u));
    SSF_ASSERT(memcmp(ch2.extData[ck], &hrrRec[hrrLen - (2u + 16u)], 2u + 16u) == 0);
    SSF_ASSERT(ch2.extCount == (ch1.extCount + 1u));
    t->close(t);
    (void)SSF_TLSC_UT_CLOSE(peer);
    SSF_ASSERT(SSFTLSCSetALPN(&_utSession, NULL, 0u));

    /* ---- Cookie too large to echo: the client must abort with internal_error, ---- */
    /* ---- never send ClientHello2 without the cookie                           ---- */
    peer = _SSFTLSCUTSendHrr(l, port, ch1Rec, sizeof(ch1Rec), &ch1,
                             SSF_TLS_CS_AES_128_GCM_SHA256, 900u, hrrRec, sizeof(hrrRec), &hrrLen);
    {
        SSFPortTick_t end = SSFPortGetTick64() + SSF_TLSC_UT_WAIT_TICKS;
        SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;

        while (((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)) &&
               (SSFPortGetTick64() < end))
        { r = t->pollOpen(t); }
        SSF_ASSERT(r == SSF_NET_IO_ERROR);
    }
    n = _SSFTLSCUTRecvRecord(peer, ch2Rec, sizeof(ch2Rec));
    SSF_ASSERT(n == 7u);                                  /* No ClientHello2: the alert */
    SSF_ASSERT((ch2Rec[0] == SSF_TLS_CT_ALERT) && (ch2Rec[5] == 2u) &&
               (ch2Rec[6] == SSF_TLS_ALERT_INTERNAL_ERROR));
    t->close(t);
    (void)SSF_TLSC_UT_CLOSE(peer);

    /* ---- Every suite the ClientHello offers is accepted when a HelloRetryRequest ---- */
    /* ---- selects it: the client answers with ClientHello2, not an alert          ---- */
    {
        static const uint16_t offered[] = { SSF_TLS_CS_AES_256_GCM_SHA384,
                                            SSF_TLS_CS_CHACHA20_POLY1305_SHA256,
                                            SSF_TLS_CS_AES_128_GCM_SHA256,
                                            SSF_TLS_CS_AES_128_CCM_SHA256 };
        size_t k;

        for (k = 0; k < (sizeof(offered) / sizeof(offered[0])); k++)
        {
            SSFPortTick_t end;

            peer = _SSFTLSCUTSendHrr(l, port, ch1Rec, sizeof(ch1Rec), &ch1, offered[k], 0u,
                                     hrrRec, sizeof(hrrRec), &hrrLen);
            end = SSFPortGetTick64() + SSF_TLSC_UT_WAIT_TICKS;
            n = 0;
            while ((n == 0u) && (SSFPortGetTick64() < end))
            {
                (void)t->pollOpen(t);
                if (_SSFTLSCUTReadable(peer))
                { n = _SSFTLSCUTRecvRecord(peer, ch2Rec, sizeof(ch2Rec)); }
            }
            SSF_ASSERT(n > 9u);
            SSF_ASSERT((ch2Rec[0] == SSF_TLS_CT_HANDSHAKE) &&
                       (ch2Rec[5] == SSF_TLS_HS_CLIENT_HELLO));
            t->close(t);
            (void)SSF_TLSC_UT_CLOSE(peer);
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Sends the handshake bytes msg[0..msgLen) as plaintext handshake records of frag[i] bytes (the  */
/* last size repeats), with a ChangeCipherSpec after the first record if ccsAfterFirst.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCUTSendFragments(SSFTLSCUTFd_t peer, const uint8_t *msg, size_t msgLen,
                                    const size_t *frag, size_t nFrag, bool ccsAfterFirst)
{
    static const uint8_t ccs[] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    size_t pos = 0;
    size_t i = 0;

    while (pos < msgLen)
    {
        uint8_t hdr[5];
        size_t n = frag[(i < nFrag) ? i : (nFrag - 1u)];

        if (n > (msgLen - pos)) n = msgLen - pos;
        hdr[0] = SSF_TLS_CT_HANDSHAKE; hdr[1] = 0x03; hdr[2] = 0x03;
        hdr[3] = (uint8_t)(n >> 8); hdr[4] = (uint8_t)n;
        SSF_ASSERT(send(peer, (const char *)hdr, (int)sizeof(hdr), 0) == (int)sizeof(hdr));
        SSF_ASSERT(send(peer, (const char *)&msg[pos], (int)n, 0) == (int)n);
        pos += n;
        if ((i == 0u) && ccsAfterFirst)
        { SSF_ASSERT(send(peer, (const char *)ccs, (int)sizeof(ccs), 0) == (int)sizeof(ccs)); }
        i++;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Polls the session until the peer has a record or the handshake ends. Returns the record      */
/* length (0 if none) and the final pollOpen() result in *rOut.                                  */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFTLSCUTPollForRecord(SSFTLSCUTFd_t peer, uint8_t *out, size_t outSize,
                                      SSFNetIOResult_t *rOut)
{
    SSFNetTransport_t *t = &_utSession.transport;
    SSFPortTick_t end = SSFPortGetTick64() + SSF_TLSC_UT_WAIT_TICKS;
    SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;

    while (SSFPortGetTick64() < end)
    {
        if ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)) r = t->pollOpen(t);
        if (_SSFTLSCUTReadable(peer)) break;
    }
    *rOut = r;
    return _SSFTLSCUTReadable(peer) ? _SSFTLSCUTRecvRecord(peer, out, outSize) : 0u;
}

/* --------------------------------------------------------------------------------------------- */
/* Item 3: a handshake message may span records (RFC 8446 5.1); fragments must not be           */
/* interleaved with other records, and a message must not span a key change.                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCUTFragmentedHandshake(SSFTLSCUTFd_t l, uint16_t port)
{
    SSFNetTransport_t *t = &_utSession.transport;
    static uint8_t ch1Rec[1024];
    static uint8_t hrrRec[1200];
    static uint8_t rec[2048];
    SSFTLSCUTClientHello_t ch1;
    SSFTLSCUTFd_t peer;
    SSFNetIOResult_t r;
    size_t hrrLen;
    size_t n;

    /* ---- Header split across records, then the rest: ClientHello2 follows ---- */
    {
        static const size_t frag[] = { 2u, 65535u };

        peer = _SSFTLSCUTRunToClientHello(l, port, ch1Rec, sizeof(ch1Rec), &ch1);
        hrrLen = _SSFTLSCUTBuildHrr(hrrRec, sizeof(hrrRec), &ch1,
                                    SSF_TLS_CS_AES_128_GCM_SHA256, 0u);
        _SSFTLSCUTSendFragments(peer, &hrrRec[5], hrrLen - 5u, frag, 2u, false);
        n = _SSFTLSCUTPollForRecord(peer, rec, sizeof(rec), &r);
        SSF_ASSERT((n > 9u) && (rec[0] == SSF_TLS_CT_HANDSHAKE) &&
                   (rec[5] == SSF_TLS_HS_CLIENT_HELLO));
        t->close(t);
        (void)SSF_TLSC_UT_CLOSE(peer);
    }

    /* ---- One byte per record: ClientHello2 follows ---- */
    {
        static const size_t frag[] = { 1u };

        peer = _SSFTLSCUTRunToClientHello(l, port, ch1Rec, sizeof(ch1Rec), &ch1);
        hrrLen = _SSFTLSCUTBuildHrr(hrrRec, sizeof(hrrRec), &ch1,
                                    SSF_TLS_CS_AES_128_GCM_SHA256, 0u);
        _SSFTLSCUTSendFragments(peer, &hrrRec[5], hrrLen - 5u, frag, 1u, false);
        n = _SSFTLSCUTPollForRecord(peer, rec, sizeof(rec), &r);
        SSF_ASSERT((n > 9u) && (rec[0] == SSF_TLS_CT_HANDSHAKE) &&
                   (rec[5] == SSF_TLS_HS_CLIENT_HELLO));
        t->close(t);
        (void)SSF_TLSC_UT_CLOSE(peer);
    }

    /* ---- A ChangeCipherSpec between fragments: unexpected_message ---- */
    {
        static const size_t frag[] = { 10u, 65535u };

        peer = _SSFTLSCUTRunToClientHello(l, port, ch1Rec, sizeof(ch1Rec), &ch1);
        hrrLen = _SSFTLSCUTBuildHrr(hrrRec, sizeof(hrrRec), &ch1,
                                    SSF_TLS_CS_AES_128_GCM_SHA256, 0u);
        _SSFTLSCUTSendFragments(peer, &hrrRec[5], hrrLen - 5u, frag, 2u, true);
        n = _SSFTLSCUTPollForRecord(peer, rec, sizeof(rec), &r);
        SSF_ASSERT(r == SSF_NET_IO_ERROR);
        SSF_ASSERT((n == 7u) && (rec[0] == SSF_TLS_CT_ALERT) &&
                   (rec[6] == SSF_TLS_ALERT_UNEXPECTED_MSG));
        t->close(t);
        (void)SSF_TLSC_UT_CLOSE(peer);
    }

    /* ---- More handshake bytes after the HRR in its record (the next message would ---- */
    /* ---- span a key change, RFC 8446 5.1): unexpected_message                       ---- */
    {
        static const size_t frag[] = { 65535u };
        static uint8_t msgs[1200];

        peer = _SSFTLSCUTRunToClientHello(l, port, ch1Rec, sizeof(ch1Rec), &ch1);
        hrrLen = _SSFTLSCUTBuildHrr(hrrRec, sizeof(hrrRec), &ch1,
                                    SSF_TLS_CS_AES_128_GCM_SHA256, 0u);
        memcpy(msgs, &hrrRec[5], hrrLen - 5u);
        msgs[hrrLen - 5u] = 0x0b; msgs[hrrLen - 4u] = 0x00;         /* An empty Certificate */
        msgs[hrrLen - 3u] = 0x00; msgs[hrrLen - 2u] = 0x00;
        _SSFTLSCUTSendFragments(peer, msgs, hrrLen - 1u, frag, 1u, false);
        n = _SSFTLSCUTPollForRecord(peer, rec, sizeof(rec), &r);
        SSF_ASSERT(r == SSF_NET_IO_ERROR);
        SSF_ASSERT((n == 7u) && (rec[0] == SSF_TLS_CT_ALERT) &&
                   (rec[6] == SSF_TLS_ALERT_UNEXPECTED_MSG));
        t->close(t);
        (void)SSF_TLSC_UT_CLOSE(peer);
    }

    /* ---- A message longer than this build can hold: internal_error, from its header ---- */
    {
        static const size_t frag[] = { 64u };
        static uint8_t big[64];

        peer = _SSFTLSCUTRunToClientHello(l, port, ch1Rec, sizeof(ch1Rec), &ch1);
        memset(big, 0, sizeof(big));
        /* A ServerHello whose body alone is as large as hsBuf: header + body cannot fit.   */
        big[0] = SSF_TLS_HS_SERVER_HELLO;
        big[1] = (uint8_t)(sizeof(_utSession.hsBuf) >> 16);
        big[2] = (uint8_t)(sizeof(_utSession.hsBuf) >> 8);
        big[3] = (uint8_t)sizeof(_utSession.hsBuf);
        _SSFTLSCUTSendFragments(peer, big, sizeof(big), frag, 1u, false);
        n = _SSFTLSCUTPollForRecord(peer, rec, sizeof(rec), &r);
        SSF_ASSERT(r == SSF_NET_IO_ERROR);
        SSF_ASSERT((n == 7u) && (rec[0] == SSF_TLS_CT_ALERT) &&
                   (rec[6] == SSF_TLS_ALERT_INTERNAL_ERROR));
        t->close(t);
        (void)SSF_TLSC_UT_CLOSE(peer);
    }

    /* ---- A plaintext record over 2^14 bytes is the peer's error: record_overflow ---- */
    /* ---- (RFC 8446 5.1), not this build's internal_error                          ---- */
    {
        static uint8_t over[5u + 16385u];

        peer = _SSFTLSCUTRunToClientHello(l, port, ch1Rec, sizeof(ch1Rec), &ch1);
        memset(over, 0, sizeof(over));
        over[0] = SSF_TLS_CT_HANDSHAKE; over[1] = 0x03; over[2] = 0x03;
        over[3] = (uint8_t)(16385u >> 8); over[4] = (uint8_t)16385u;
        over[5] = SSF_TLS_HS_SERVER_HELLO;
        SSF_ASSERT(send(peer, (const char *)over, (int)sizeof(over), 0) == (int)sizeof(over));
        n = _SSFTLSCUTPollForRecord(peer, rec, sizeof(rec), &r);
        SSF_ASSERT(r == SSF_NET_IO_ERROR);
        SSF_ASSERT((n == 7u) && (rec[0] == SSF_TLS_CT_ALERT) &&
                   (rec[6] == SSF_TLS_ALERT_RECORD_OVERFLOW));
        t->close(t);
        (void)SSF_TLSC_UT_CLOSE(peer);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Item 6: literal IP addresses are not host names and get no SNI (RFC 6066 3).                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCUTIPLiteral(void)
{
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("127.0.0.1"));
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("192.168.100.200"));
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("::1"));
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("2001:db8::8a2e:370:7334"));
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("fe80::1%eth0"));
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("::ffff:10.0.0.1"));
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("[::1]") == false);     /* Not a literal address */
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("localhost") == false);
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("test.mosquitto.org") == false);
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("1example.com") == false);
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("10.0.0.1.example") == false);
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("256.1.1.1") == false); /* Not IPv4: a name */
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("1.2.3") == false);
    SSF_ASSERT(_SSFTLSCIsIPLiteralForTest("1.2.3.4.5") == false);
}

/* --------------------------------------------------------------------------------------------- */
/* Item 7: a CertificateVerify scheme must fit the leaf certificate's key (RFC 8446 4.2.3: the  */
/* ECDSA schemes also fix the curve).                                                           */
/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
/* Saving the leaf key: test certificates generated for this suite (validity is not checked     */
/* here). A P-256 leaf, and an RSA-8192 leaf whose key is larger than the space kept for it.    */
/* --------------------------------------------------------------------------------------------- */
static const uint8_t _utLeafP256Der[] = {
    0x30, 0x82, 0x01, 0x73, 0x30, 0x82, 0x01, 0x1a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x55,
    0xd9, 0x91, 0xbb, 0x37, 0x5c, 0x41, 0x89, 0xa8, 0xfc, 0xb6, 0x9d, 0x52, 0x47, 0x57, 0x8e, 0xd4,
    0x5d, 0x8c, 0xd2, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x73, 0x73, 0x66, 0x2d,
    0x74, 0x65, 0x73, 0x74, 0x2d, 0x63, 0x61, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x32,
    0x33, 0x32, 0x32, 0x33, 0x35, 0x32, 0x35, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x32, 0x32, 0x33,
    0x32, 0x32, 0x33, 0x35, 0x32, 0x35, 0x5a, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x59, 0x30,
    0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xb6, 0x8d, 0xc9, 0x55, 0x8a, 0x59, 0x60, 0x97,
    0xa2, 0x26, 0x44, 0xd2, 0xca, 0x71, 0x4e, 0x5e, 0xa7, 0xfb, 0xc9, 0x1b, 0xf2, 0x4b, 0xd6, 0xd5,
    0x08, 0xe0, 0x25, 0xd5, 0xaf, 0xc6, 0x89, 0xd8, 0x36, 0xe9, 0x64, 0xf0, 0x3f, 0x52, 0x70, 0x66,
    0x9d, 0x34, 0xf4, 0x81, 0xd2, 0x89, 0x2b, 0xf2, 0x5f, 0x99, 0x40, 0xa9, 0x61, 0x9f, 0x2c, 0x84,
    0x0c, 0x34, 0x93, 0x34, 0xd8, 0x2b, 0xff, 0x9b, 0xa3, 0x48, 0x30, 0x46, 0x30, 0x14, 0x06, 0x03,
    0x55, 0x1d, 0x11, 0x04, 0x0d, 0x30, 0x0b, 0x82, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
    0x73, 0x74, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06,
    0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
    0x03, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47,
    0x00, 0x30, 0x44, 0x02, 0x20, 0x03, 0x9e, 0x8a, 0xe6, 0xf2, 0xfd, 0x9c, 0x1a, 0x88, 0xf0, 0x2a,
    0x09, 0x43, 0xa2, 0xe2, 0xc9, 0xf5, 0x7a, 0x30, 0xba, 0x4e, 0x25, 0xa6, 0x74, 0x53, 0xee, 0x7a,
    0x5b, 0xe2, 0x70, 0x80, 0x79, 0x02, 0x20, 0x2c, 0x6a, 0x61, 0x7a, 0x7f, 0x26, 0xff, 0xd8, 0x73,
    0x5b, 0x10, 0xc3, 0xa5, 0x0c, 0x46, 0x2a, 0xc4, 0xce, 0xe2, 0x25, 0xa5, 0x85, 0x04, 0xeb, 0xe9,
    0x60, 0x63, 0x58, 0x51, 0x86, 0x16, 0xe5
};

static const uint8_t _utLeafRsa8192Der[] = {
    0x30, 0x82, 0x08, 0xdc, 0x30, 0x82, 0x04, 0xc4, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x26,
    0x1c, 0xee, 0x6f, 0xeb, 0x08, 0x90, 0x4d, 0xe0, 0x93, 0xab, 0x46, 0x17, 0xd2, 0xba, 0x57, 0xcc,
    0x34, 0xb0, 0x04, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 0x62,
    0x69, 0x67, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x32, 0x34, 0x31, 0x34, 0x32, 0x32,
    0x33, 0x35, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x31, 0x31, 0x32, 0x31, 0x31, 0x34, 0x32, 0x32, 0x33,
    0x35, 0x5a, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, 0x62,
    0x69, 0x67, 0x30, 0x82, 0x04, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x04, 0x0f, 0x00, 0x30, 0x82, 0x04, 0x0a, 0x02, 0x82,
    0x04, 0x01, 0x00, 0x96, 0xf3, 0xeb, 0x71, 0xbc, 0x2f, 0xa3, 0x46, 0x6d, 0x6a, 0x72, 0x29, 0x54,
    0xca, 0xbe, 0xbc, 0xc5, 0x58, 0x1f, 0xbd, 0x0d, 0x4b, 0x72, 0x7d, 0x00, 0x0d, 0x32, 0xf1, 0x39,
    0x68, 0x56, 0x83, 0x63, 0xae, 0x72, 0x0d, 0xbe, 0xc8, 0xa9, 0x64, 0xe8, 0x7b, 0x09, 0xa1, 0x2a,
    0xbc, 0x0c, 0xf0, 0x60, 0x84, 0x23, 0x09, 0x4c, 0x12, 0xdc, 0xc8, 0x6a, 0x03, 0xdb, 0xdf, 0xe2,
    0xe7, 0x0e, 0xd9, 0xda, 0xce, 0x25, 0x05, 0x5c, 0xbc, 0x8c, 0xc8, 0x8f, 0x10, 0xf7, 0x5c, 0x32,
    0xcd, 0x83, 0xac, 0xa7, 0x85, 0xcd, 0xa3, 0x3a, 0xde, 0x8b, 0xa6, 0x3e, 0x8b, 0x4a, 0xe8, 0x34,
    0xdb, 0x69, 0xb1, 0x98, 0x41, 0xfe, 0xa0, 0x82, 0x04, 0x9b, 0xfc, 0x76, 0x81, 0x11, 0x24, 0x53,
    0xf2, 0xa4, 0x44, 0x6e, 0xdd, 0xfa, 0x9c, 0xb3, 0x8b, 0x56, 0x6d, 0xb5, 0xf9, 0x5d, 0x7f, 0xe0,
    0x2a, 0x5f, 0x5b, 0x46, 0x8f, 0x3f, 0x72, 0x67, 0xb6, 0x60, 0x56, 0xa1, 0x58, 0x40, 0xd7, 0x25,
    0xa4, 0xed, 0xed, 0x5a, 0x36, 0x51, 0xcd, 0x57, 0x15, 0xeb, 0xa5, 0x94, 0x5a, 0x6b, 0x22, 0xf9,
    0xd9, 0xce, 0x77, 0x8d, 0xe1, 0x24, 0x76, 0x88, 0xa8, 0xec, 0xfd, 0xb1, 0xc7, 0x6a, 0x8d, 0xf9,
    0xd3, 0x43, 0xd5, 0x78, 0xbb, 0x35, 0x53, 0x23, 0xf3, 0x7d, 0xb3, 0x61, 0xba, 0x1f, 0x9e, 0x89,
    0xdb, 0x1c, 0x36, 0x46, 0x87, 0x9a, 0xc0, 0x24, 0xb3, 0x48, 0xc4, 0x1c, 0x6a, 0x5b, 0x74, 0x46,
    0x47, 0xa0, 0x36, 0xa0, 0x5d, 0x12, 0xb4, 0xcd, 0xce, 0x03, 0x26, 0x5e, 0x6a, 0x0f, 0xa5, 0xdd,
    0xa3, 0x3a, 0x20, 0x79, 0xb2, 0xca, 0x39, 0x88, 0xf5, 0x0f, 0x04, 0x1c, 0x70, 0xd6, 0x6e, 0x4e,
    0x2c, 0x7d, 0xba, 0x20, 0x48, 0xfc, 0x7b, 0x61, 0x35, 0xbf, 0xa9, 0x12, 0xcf, 0xb1, 0x51, 0x33,
    0x18, 0x14, 0x8a, 0x0b, 0x2d, 0xe7, 0x2f, 0x56, 0xd0, 0x51, 0xff, 0x55, 0x4f, 0x42, 0x23, 0x6c,
    0xcb, 0xaf, 0x1d, 0xf7, 0xdc, 0x03, 0x6a, 0x13, 0x4d, 0x4c, 0xfa, 0x63, 0xd1, 0x64, 0xcc, 0x69,
    0x95, 0x37, 0x1e, 0x6d, 0x03, 0x6e, 0x76, 0xdb, 0xcd, 0xd6, 0xed, 0x2d, 0xce, 0xb8, 0xba, 0xa5,
    0xe3, 0x40, 0xf1, 0x8b, 0xea, 0x21, 0xf4, 0x12, 0x09, 0x69, 0x34, 0x02, 0x91, 0x44, 0xae, 0x16,
    0xbc, 0x4b, 0xf1, 0xdd, 0x85, 0xf9, 0xaf, 0x15, 0x3d, 0xc9, 0x23, 0xe5, 0x20, 0x45, 0x66, 0x9c,
    0x57, 0x03, 0xab, 0xd0, 0x9f, 0x04, 0x9b, 0xf6, 0x8f, 0x06, 0x44, 0x2d, 0x3e, 0x35, 0xde, 0x46,
    0xc2, 0x1b, 0x5c, 0xc1, 0xd1, 0x30, 0x68, 0x05, 0xf7, 0xb6, 0x8b, 0xcb, 0x2f, 0xf1, 0x17, 0x7b,
    0x2f, 0xe0, 0x7e, 0x80, 0xf2, 0x1d, 0x0e, 0x0c, 0x21, 0xaf, 0xff, 0xfe, 0xe0, 0x3e, 0x03, 0xb5,
    0xf5, 0x8a, 0x2f, 0x3f, 0x67, 0xfa, 0x28, 0x7b, 0x21, 0x61, 0xd0, 0x24, 0x7c, 0xd8, 0xa0, 0xe1,
    0x04, 0x77, 0x02, 0x8b, 0x4e, 0xce, 0xf4, 0x7f, 0x3d, 0xc3, 0x9a, 0xfc, 0x09, 0x64, 0x77, 0xdb,
    0x7a, 0x5c, 0xdf, 0x57, 0xa8, 0x7b, 0x94, 0x15, 0xb0, 0x5f, 0xe6, 0xee, 0x4f, 0x5b, 0xb7, 0x22,
    0x4c, 0xed, 0x05, 0x31, 0x47, 0xe6, 0xcd, 0x09, 0xd7, 0xfa, 0xcb, 0x5d, 0x11, 0x84, 0x72, 0xed,
    0x3c, 0x99, 0xef, 0x4b, 0x1b, 0x53, 0xdf, 0x0d, 0xbf, 0x30, 0xea, 0x8f, 0x36, 0xb9, 0x26, 0x10,
    0x58, 0xe9, 0xa4, 0x62, 0xe5, 0xa6, 0xab, 0x80, 0x46, 0xfb, 0xfa, 0x84, 0x59, 0xa5, 0x2d, 0x7f,
    0xca, 0xe9, 0x83, 0x80, 0xf9, 0x51, 0x57, 0xad, 0xc4, 0x0e, 0x56, 0xe4, 0x1e, 0xfc, 0xcc, 0x00,
    0x81, 0x39, 0x97, 0x0c, 0x8a, 0x51, 0x49, 0xfc, 0x26, 0xbc, 0xa6, 0x00, 0xf9, 0x71, 0xfb, 0x70,
    0x42, 0xd5, 0x39, 0x86, 0x03, 0xb1, 0xa3, 0xcd, 0x0a, 0x65, 0x4f, 0x1d, 0x43, 0x79, 0xc2, 0x5f,
    0xe1, 0xd6, 0xb8, 0x9d, 0xa1, 0x84, 0x63, 0xeb, 0xa3, 0xd4, 0xc1, 0x84, 0x2e, 0x78, 0x46, 0x63,
    0x8b, 0x9f, 0x63, 0xdd, 0x9f, 0x86, 0xd8, 0xfc, 0xb7, 0x0f, 0x59, 0x0b, 0x88, 0x64, 0x58, 0xd5,
    0xd2, 0x15, 0x5b, 0x58, 0xe1, 0x9f, 0xb3, 0xf7, 0x6f, 0xf1, 0x0c, 0x16, 0x76, 0x58, 0x77, 0x20,
    0xfa, 0x68, 0x88, 0xc4, 0x43, 0xfb, 0x3f, 0x20, 0x35, 0x9d, 0x34, 0x66, 0x42, 0xf4, 0xaa, 0x03,
    0xe9, 0x17, 0x19, 0x12, 0x61, 0x10, 0x7c, 0x1d, 0xd0, 0x39, 0x4c, 0xbe, 0xde, 0xd6, 0x45, 0xa1,
    0x63, 0x88, 0x9e, 0x42, 0x97, 0xa8, 0x10, 0x98, 0xcd, 0x54, 0xc9, 0x85, 0x1f, 0xb6, 0xab, 0xa9,
    0x07, 0x1e, 0x4a, 0x98, 0xc9, 0xe2, 0x93, 0xc1, 0x6c, 0x4a, 0x64, 0x79, 0x56, 0x6c, 0x98, 0x81,
    0xbc, 0xe4, 0x19, 0xf3, 0x62, 0xa1, 0xf1, 0xfc, 0x30, 0x16, 0x3c, 0x77, 0x21, 0xbb, 0xca, 0xd4,
    0xd4, 0x66, 0x7c, 0x31, 0x7d, 0x93, 0x61, 0xba, 0x7f, 0x94, 0xa1, 0xa3, 0x67, 0x27, 0xf0, 0x8f,
    0x34, 0xe6, 0x40, 0x00, 0x87, 0x84, 0xd0, 0x3f, 0x1e, 0xb5, 0xe9, 0xfd, 0x92, 0xa8, 0x0c, 0xfb,
    0x75, 0x55, 0x54, 0xd3, 0x35, 0x13, 0x37, 0xb3, 0x2f, 0xcf, 0x06, 0x06, 0xc4, 0xa3, 0x82, 0x2b,
    0x9c, 0x3e, 0x26, 0xab, 0x0e, 0xa4, 0xce, 0x1f, 0x2c, 0x7a, 0x2a, 0x39, 0x9d, 0x6e, 0xb4, 0xfe,
    0xe7, 0x59, 0x6b, 0xc8, 0x35, 0x47, 0x63, 0xb9, 0xa3, 0xf0, 0x81, 0x5e, 0x84, 0x29, 0xd5, 0xc9,
    0x82, 0x6d, 0x72, 0xae, 0xf4, 0xe4, 0x66, 0xf5, 0x85, 0xe7, 0x8c, 0xf9, 0xcd, 0x3f, 0x18, 0x0c,
    0xe8, 0xce, 0x1a, 0x96, 0x50, 0xad, 0x79, 0x55, 0x96, 0x47, 0x40, 0xc3, 0xbb, 0xbc, 0xa0, 0x06,
    0x12, 0x9e, 0xa5, 0x88, 0x45, 0x65, 0xb8, 0x9c, 0x97, 0xc4, 0x6e, 0xa5, 0x3c, 0x99, 0xb0, 0x92,
    0x03, 0x4b, 0x1e, 0x52, 0xa9, 0xb6, 0xd4, 0x31, 0x40, 0x86, 0x0b, 0x21, 0x04, 0xf5, 0x2b, 0x46,
    0xb5, 0x54, 0xd8, 0x44, 0x0e, 0x8d, 0x60, 0x5f, 0xc0, 0x05, 0x8a, 0xd0, 0xfc, 0xfc, 0x7a, 0x0a,
    0xeb, 0xcf, 0xc8, 0x3b, 0xec, 0x24, 0xc0, 0x1d, 0xf2, 0x6c, 0x42, 0x49, 0x99, 0x43, 0xe8, 0xbb,
    0x02, 0x82, 0xe6, 0x85, 0xc4, 0x1e, 0x60, 0x1b, 0xfa, 0x08, 0x6c, 0xea, 0x5a, 0x89, 0x6d, 0x11,
    0xfc, 0x27, 0x14, 0x52, 0xfa, 0xda, 0x30, 0x81, 0xc7, 0x22, 0xb6, 0x4a, 0x2c, 0x62, 0x78, 0xb0,
    0x37, 0x59, 0xcc, 0x1f, 0x20, 0xaf, 0x57, 0x2a, 0x72, 0xc9, 0xe7, 0xb9, 0xf2, 0x02, 0x45, 0x7c,
    0x07, 0x57, 0x7d, 0xf0, 0xb4, 0x3c, 0x26, 0xcb, 0xd7, 0xe1, 0x4c, 0xac, 0xf0, 0x9d, 0x7c, 0x03,
    0x47, 0x19, 0x45, 0x2c, 0x0e, 0xe5, 0x56, 0x09, 0xd8, 0x54, 0x51, 0x56, 0x10, 0x13, 0x7f, 0x47,
    0xfd, 0xfe, 0xf2, 0xd7, 0xf9, 0x29, 0x84, 0xbd, 0xe7, 0x35, 0xf8, 0x31, 0xfd, 0xdf, 0x66, 0x28,
    0x86, 0xa7, 0xee, 0x2b, 0x06, 0x84, 0xf8, 0x6d, 0x3d, 0xc5, 0xe9, 0xf4, 0xc1, 0x04, 0x46, 0x6d,
    0x7f, 0xbb, 0x22, 0x61, 0x28, 0xd8, 0xd0, 0x23, 0xd3, 0x85, 0xfe, 0xc6, 0x77, 0xa5, 0x9c, 0x2e,
    0x53, 0x76, 0xa0, 0x1c, 0xc6, 0x3a, 0x5f, 0xf5, 0x59, 0x01, 0xd8, 0x77, 0xd5, 0x86, 0xd2, 0xf2,
    0xa6, 0x45, 0xfb, 0xe0, 0x80, 0x00, 0x2f, 0xda, 0xbf, 0xc2, 0x32, 0x1f, 0x32, 0xd2, 0xea, 0x00,
    0xe4, 0x73, 0xe3, 0x8b, 0x64, 0x30, 0xd5, 0xeb, 0x30, 0xf6, 0x86, 0x86, 0x36, 0xb1, 0xdd, 0x37,
    0xae, 0x85, 0xb0, 0x80, 0x85, 0xb3, 0xd9, 0x53, 0x2c, 0x18, 0xe0, 0x59, 0xb3, 0x76, 0xba, 0x2e,
    0x7c, 0x03, 0x29, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x32, 0x30, 0x30, 0x30, 0x1d, 0x06, 0x03,
    0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xd8, 0x9c, 0x38, 0xc9, 0xa2, 0x35, 0x59, 0x18, 0x46,
    0xe5, 0xbc, 0xfb, 0x0f, 0xc9, 0x7a, 0x8b, 0xe2, 0xf7, 0x38, 0x1c, 0x30, 0x0f, 0x06, 0x03, 0x55,
    0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x04, 0x01, 0x00,
    0x26, 0x51, 0x1c, 0x5c, 0x7b, 0x3f, 0xe8, 0x7f, 0x6a, 0xfe, 0x9e, 0xdc, 0xfa, 0xbc, 0x0e, 0x25,
    0x99, 0x42, 0x62, 0x18, 0xc0, 0x31, 0x47, 0x39, 0xc3, 0xe8, 0x0a, 0x54, 0x37, 0x18, 0x6b, 0xb9,
    0x42, 0xa3, 0x4a, 0xbf, 0x8a, 0x9b, 0x57, 0xa7, 0x5f, 0xb3, 0x62, 0xb1, 0x7d, 0x6f, 0x29, 0xa2,
    0x25, 0xb3, 0x20, 0x83, 0x36, 0x6d, 0x36, 0x5f, 0x3a, 0x2f, 0x14, 0x71, 0xf6, 0xeb, 0xe3, 0xb9,
    0x6a, 0xab, 0xd4, 0xac, 0xed, 0x0d, 0xba, 0x87, 0x5e, 0xaf, 0xac, 0x01, 0x68, 0xa1, 0xac, 0x26,
    0xb9, 0x82, 0xc8, 0x38, 0x58, 0xa7, 0xf3, 0xcc, 0x30, 0x7a, 0x85, 0x4f, 0xe5, 0x25, 0xea, 0x03,
    0x0b, 0x9c, 0xb8, 0xde, 0x9e, 0xd4, 0x95, 0xd8, 0xc9, 0xf6, 0x56, 0x69, 0xb4, 0x58, 0x79, 0xd4,
    0xd1, 0xc8, 0x88, 0xd0, 0xe1, 0x0a, 0x3e, 0x82, 0xd0, 0xbf, 0x7c, 0x07, 0x28, 0x60, 0x36, 0xad,
    0x3d, 0x6c, 0x4e, 0xf9, 0xb5, 0xa8, 0x4e, 0x81, 0x27, 0xb8, 0x7d, 0xe7, 0x7a, 0xef, 0x02, 0x50,
    0x57, 0xf0, 0x71, 0xc8, 0x09, 0x40, 0xb9, 0xf9, 0x67, 0xb7, 0x53, 0x0d, 0xd3, 0x3a, 0x5d, 0xd0,
    0xa5, 0x7b, 0x34, 0x30, 0x05, 0x1c, 0xdd, 0xe3, 0x87, 0x86, 0x82, 0x05, 0x89, 0x1a, 0x38, 0xbb,
    0x99, 0xaf, 0x4a, 0x1e, 0x60, 0x4e, 0x01, 0xbb, 0xc4, 0x95, 0xb0, 0xff, 0x78, 0xa0, 0xc9, 0x4a,
    0x16, 0x19, 0xbe, 0x4c, 0xe7, 0x5d, 0xff, 0xf3, 0x14, 0xe8, 0x4c, 0x9d, 0x2a, 0x99, 0x72, 0xe4,
    0x53, 0x0d, 0x06, 0xc2, 0x05, 0xab, 0x87, 0xcc, 0xd2, 0xa6, 0x44, 0xb1, 0xd4, 0x75, 0xa6, 0x10,
    0x97, 0xba, 0xbd, 0x47, 0xd5, 0x60, 0x3f, 0xf7, 0x52, 0xcd, 0x7e, 0x5a, 0x57, 0x2c, 0x00, 0xf4,
    0x35, 0x65, 0xa2, 0x78, 0x31, 0xaa, 0x82, 0x63, 0xd0, 0xc4, 0x5f, 0xac, 0x5a, 0x60, 0x47, 0x76,
    0x2c, 0xd8, 0x8e, 0x70, 0x1b, 0xbe, 0x4d, 0x83, 0xe5, 0xb4, 0x27, 0x50, 0x70, 0x7e, 0x01, 0xed,
    0x86, 0x5e, 0x7e, 0x16, 0x93, 0xc0, 0x95, 0x5d, 0x93, 0x53, 0xa4, 0x8a, 0xe7, 0x50, 0x4b, 0xd0,
    0xcc, 0x2a, 0x31, 0x54, 0xc5, 0x1a, 0x3f, 0x45, 0x30, 0x30, 0x8c, 0x96, 0xfa, 0x93, 0xbd, 0x4e,
    0xf0, 0xdb, 0xf4, 0x12, 0x0e, 0x61, 0x57, 0xe1, 0x51, 0xa0, 0x5f, 0x99, 0x51, 0x7d, 0xcf, 0x5d,
    0x4f, 0xa5, 0x8a, 0x98, 0xca, 0xa2, 0xd5, 0x2f, 0xe2, 0x23, 0x4c, 0xe1, 0x5b, 0x3e, 0x97, 0x43,
    0xd5, 0x74, 0x70, 0xe6, 0x28, 0x8f, 0xd8, 0xf5, 0x5a, 0x35, 0xeb, 0x45, 0x8e, 0xec, 0x9a, 0xa2,
    0xaf, 0x18, 0x7b, 0x26, 0xa0, 0xc7, 0x8e, 0x43, 0x49, 0xcd, 0x1f, 0x14, 0x12, 0x5b, 0x51, 0x62,
    0x41, 0x51, 0xed, 0x8f, 0x29, 0x45, 0xab, 0xc0, 0x1d, 0xdf, 0x08, 0xb9, 0x8f, 0x83, 0x71, 0x6f,
    0xa2, 0x5b, 0xf7, 0x70, 0x34, 0xf6, 0xfb, 0x1d, 0xbe, 0xde, 0x8b, 0xa6, 0x8f, 0xa3, 0x76, 0x90,
    0x5a, 0x79, 0xea, 0x03, 0x4f, 0x81, 0xe6, 0x60, 0x8b, 0xd9, 0xc0, 0xe9, 0xc1, 0x31, 0xdf, 0xe7,
    0xe7, 0xc3, 0x9d, 0x70, 0x1a, 0x9f, 0x81, 0xe5, 0x36, 0x54, 0xe9, 0x73, 0xcd, 0x20, 0x6c, 0x50,
    0xac, 0x8c, 0xd9, 0x39, 0xcc, 0x49, 0x99, 0x43, 0x90, 0xbd, 0xf8, 0x57, 0x28, 0xf1, 0x38, 0x83,
    0x34, 0xaa, 0x36, 0xa4, 0x95, 0x28, 0x49, 0xc6, 0x08, 0x09, 0xec, 0x97, 0xca, 0xa0, 0x30, 0xae,
    0x94, 0x7e, 0x04, 0x23, 0x4c, 0xf3, 0xfc, 0x48, 0xef, 0x0c, 0x9b, 0xa9, 0xec, 0x74, 0xf3, 0xb4,
    0x2b, 0x0e, 0x59, 0xc6, 0xfc, 0x9f, 0xb0, 0xe6, 0x43, 0x6d, 0xfa, 0xde, 0xb2, 0xb9, 0x51, 0xfa,
    0x77, 0xd5, 0x1a, 0x54, 0x18, 0x66, 0x37, 0x2b, 0x09, 0x84, 0xb3, 0x53, 0x5b, 0x67, 0x9e, 0x84,
    0x1a, 0xb6, 0xb7, 0x47, 0x86, 0xb8, 0x15, 0x8d, 0xb5, 0xe1, 0x7f, 0x15, 0x71, 0x58, 0x4a, 0x8e,
    0x1d, 0xf0, 0x0e, 0x39, 0x97, 0x76, 0xa5, 0xda, 0x5c, 0x3d, 0x85, 0x42, 0x71, 0x62, 0x0b, 0x7a,
    0x0e, 0x6f, 0xdc, 0xf2, 0x6d, 0xda, 0x49, 0x7d, 0x8a, 0xc4, 0xda, 0x4a, 0x78, 0x47, 0x7f, 0xdb,
    0xbe, 0x7d, 0x2d, 0x19, 0x2b, 0x87, 0x57, 0x3a, 0xf1, 0x20, 0x9f, 0x03, 0xd2, 0x86, 0x8e, 0x83,
    0x2d, 0x36, 0xf8, 0x52, 0xc6, 0x62, 0x56, 0xb1, 0xb3, 0xe8, 0xd9, 0x4b, 0x7c, 0xd2, 0x2a, 0x08,
    0x3e, 0xa3, 0xeb, 0x6b, 0xa2, 0xd9, 0x36, 0x79, 0x1e, 0x50, 0x23, 0x19, 0x8d, 0x9e, 0xde, 0x82,
    0xfb, 0xe9, 0xfb, 0x9e, 0xc4, 0xdc, 0xb1, 0x45, 0x63, 0x1c, 0xb8, 0x64, 0xc6, 0xae, 0x46, 0xc6,
    0xf4, 0xc1, 0xdf, 0x05, 0x1b, 0xe0, 0x61, 0xf0, 0x8d, 0xef, 0x51, 0x3f, 0xd8, 0x4e, 0x74, 0xb8,
    0xca, 0x56, 0x16, 0x15, 0x62, 0x59, 0x16, 0xc0, 0xc2, 0x9b, 0xe2, 0x42, 0x84, 0x85, 0x39, 0x7a,
    0xf0, 0xce, 0x7b, 0x4b, 0x9f, 0xaa, 0x8c, 0x3e, 0xae, 0x0e, 0x73, 0x94, 0xcc, 0x5e, 0xab, 0x60,
    0xb2, 0xd6, 0x8c, 0xa3, 0x6f, 0xf7, 0x70, 0x1c, 0x00, 0x1c, 0x6c, 0xf7, 0x0f, 0xde, 0xbf, 0x21,
    0xd8, 0xeb, 0x79, 0x89, 0x74, 0x90, 0x4c, 0xa5, 0x29, 0x8a, 0xa2, 0xb6, 0xe7, 0xbd, 0x86, 0xe7,
    0xd2, 0xfe, 0x2b, 0x6d, 0x54, 0x47, 0xbf, 0xf0, 0xf6, 0x5a, 0xd6, 0x8d, 0x3f, 0x70, 0xe1, 0x1b,
    0xa3, 0x58, 0xf2, 0x2c, 0xb7, 0x31, 0x2c, 0xb4, 0xeb, 0x73, 0xa0, 0x66, 0x7b, 0xff, 0x67, 0xb0,
    0x00, 0xb5, 0xf5, 0xf9, 0x8f, 0x61, 0xa1, 0xbe, 0xd5, 0xae, 0x67, 0x52, 0x3b, 0x21, 0xaf, 0x2c,
    0x02, 0x58, 0x00, 0xaf, 0x5c, 0xf8, 0xfd, 0xce, 0xf2, 0xf0, 0xcb, 0x2a, 0xdf, 0x2f, 0x49, 0xb5,
    0x0a, 0x39, 0x45, 0xf4, 0x7b, 0x52, 0x26, 0x9e, 0xbb, 0x56, 0x87, 0x79, 0x04, 0x1d, 0xdb, 0x73,
    0x2b, 0xa4, 0x98, 0x26, 0xda, 0xf3, 0x2e, 0x1a, 0xdf, 0xf3, 0xe2, 0xbb, 0x0d, 0xc1, 0x54, 0xf2,
    0xd2, 0x5a, 0x13, 0xaa, 0xd3, 0x93, 0xc4, 0x23, 0x91, 0xd9, 0x6c, 0xd0, 0x42, 0xb6, 0x5c, 0x49,
    0x3d, 0xe2, 0x36, 0x2d, 0xcc, 0x34, 0xac, 0x99, 0x4d, 0x00, 0xfd, 0x93, 0x01, 0xac, 0xc5, 0xbe,
    0x80, 0x90, 0xb2, 0x81, 0xf7, 0x94, 0x33, 0xed, 0x03, 0x57, 0xb4, 0xc2, 0x02, 0xdb, 0x07, 0xdb,
    0xc5, 0xdf, 0xce, 0xd0, 0x15, 0xea, 0x6e, 0x43, 0x71, 0xe1, 0x3f, 0xc4, 0xf8, 0x3e, 0xad, 0xdb,
    0xc8, 0x4b, 0x8a, 0xd3, 0xc3, 0xb7, 0xde, 0x8a, 0xb0, 0x0d, 0xf4, 0x6e, 0x48, 0xba, 0xe9, 0x59,
    0xfa, 0x88, 0x72, 0x9e, 0x1d, 0x6d, 0x1a, 0x9f, 0xb5, 0x0a, 0xf3, 0x9f, 0x1d, 0xb3, 0x7a, 0x72,
    0x34, 0x09, 0xd8, 0xc2, 0x04, 0x99, 0x35, 0x03, 0x06, 0xdb, 0xd9, 0x5d, 0xb8, 0xbe, 0x09, 0xbf,
    0xcc, 0x3d, 0x79, 0xd9, 0x35, 0x9b, 0xb4, 0xae, 0xef, 0xb1, 0x1a, 0xa7, 0x6e, 0xcc, 0x62, 0x90,
    0xc7, 0x38, 0xb3, 0x51, 0xb2, 0x5d, 0x37, 0xd7, 0x0e, 0xa2, 0x52, 0x39, 0x3c, 0xd9, 0x2c, 0xf4,
    0x65, 0x1d, 0x07, 0x8e, 0x5f, 0x8e, 0xe7, 0x84, 0xc8, 0x05, 0x4f, 0x19, 0x12, 0xf3, 0x41, 0x59,
    0x0a, 0xe3, 0x3e, 0xd5, 0x48, 0x64, 0x64, 0x4b, 0x62, 0x14, 0x18, 0x5b, 0x63, 0x81, 0x9d, 0x7b,
    0x4d, 0xa7, 0xe6, 0xa4, 0xa2, 0xee, 0x22, 0x59, 0xfc, 0x92, 0xa6, 0xa3, 0x83, 0xe9, 0x7e, 0xd7,
    0xea, 0x30, 0x8b, 0x00, 0xdb, 0xfa, 0x04, 0x4b, 0x99, 0x2f, 0x67, 0xa3, 0x92, 0xd4, 0x5b, 0x36,
    0x97, 0x7d, 0x85, 0x72, 0x7a, 0x6a, 0xf1, 0x2c, 0x99, 0x6f, 0x0a, 0xdc, 0xc2, 0x27, 0xa4, 0x18
};

static void _SSFTLSCUTSaveLeafKey(void)
{
    static uint8_t bad[sizeof(_utLeafP256Der)];

    /* P-256: the SubjectPublicKey bit string (65-byte uncompressed point) and its type */
    memset(&_utSession2, 0, sizeof(_utSession2));
    SSF_ASSERT(_SSFTLSCSaveLeafKeyForTest(&_utSession2, _utLeafP256Der,
                                          (uint32_t)sizeof(_utLeafP256Der)));
    SSF_ASSERT(_utSession2.leafKeyType == SSF_TLSC_LEAF_KEY_P256);
    SSF_ASSERT(_utSession2.clientHelloLen == 65u);
    SSF_ASSERT(_utSession2.clientHelloMsg[0] == 0x04u);

    /* A key larger than clientHelloMsg is refused, not truncated */
    memset(&_utSession2, 0, sizeof(_utSession2));
    SSF_ASSERT(_SSFTLSCSaveLeafKeyForTest(&_utSession2, _utLeafRsa8192Der,
                                          (uint32_t)sizeof(_utLeafRsa8192Der)) == false);
    SSF_ASSERT(_utSession2.clientHelloLen == 0u);

    /* Not a certificate: truncated, and with its outer tag damaged */
    SSF_ASSERT(_SSFTLSCSaveLeafKeyForTest(&_utSession2, _utLeafP256Der,
                                          (uint32_t)sizeof(_utLeafP256Der) - 1u) == false);
    memcpy(bad, _utLeafP256Der, sizeof(bad));
    bad[0] = 0x31u;
    SSF_ASSERT(_SSFTLSCSaveLeafKeyForTest(&_utSession2, bad, (uint32_t)sizeof(bad)) == false);
    SSF_ASSERT(_utSession2.clientHelloLen == 0u);
    memset(&_utSession2, 0, sizeof(_utSession2));
}

/* --------------------------------------------------------------------------------------------- */
/* Client certificate (mutual TLS, RFC 8446 4.4.2 / 4.4.3): setting it, choosing the signature  */
/* scheme from a CertificateRequest, the streamed Certificate message and the CertificateVerify  */
/* signature. The handshake itself is exercised against real servers (wire tests).             */
/* --------------------------------------------------------------------------------------------- */

/* Finds needle in hay; returns its offset or SIZE_MAX. */
static size_t _SSFTLSCUTFind(const uint8_t *hay, size_t hayLen, const uint8_t *needle, size_t n)
{
    size_t i;
    for (i = 0; (i + n) <= hayLen; i++) { if (memcmp(&hay[i], needle, n) == 0) return i; }
    return (size_t)-1;
}

/* Sets a one-certificate chain. */
static bool _SSFTLSCUTSetOne(SSFTLSCSession_t *s, const uint8_t *cert, size_t certLen,
                             const SSFPKey_t *key)
{
    static const uint8_t *chain[1];
    static uint32_t lens[1];
    chain[0] = cert;
    lens[0] = (uint32_t)certLen;
    return SSFTLSCSetClientCert(s, chain, lens, 1u, key);
}

/* Checks a CertificateVerify message signed by key over the client context and hash. */
static void _SSFTLSCUTCheckClientCV(const uint8_t *msg, size_t msgLen, uint16_t scheme,
                                    const uint8_t *th, size_t thLen, const uint8_t *leaf,
                                    size_t leafLen, const SSFPKey_t *key)
{
    uint8_t content[64 + 34 + 48];
    uint8_t h[48];
    size_t contentLen = 64u + 34u + thLen;
    const uint8_t *sig;
    size_t sigLen;
    int pass;

    SSF_ASSERT(msgLen >= 8u);
    SSF_ASSERT((msg[0] == 15u) && ((((size_t)msg[1] << 16) | ((size_t)msg[2] << 8) | msg[3]) ==
                                   (msgLen - 4u)));
    SSF_ASSERT((((uint16_t)msg[4] << 8) | msg[5]) == scheme);
    sigLen = ((size_t)msg[6] << 8) | msg[7];
    SSF_ASSERT((8u + sigLen) == msgLen);
    sig = &msg[8];

    /* The signature verifies over the client context string, and not over the server one */
    for (pass = 0; pass < 2; pass++)
    {
        bool ok;
        memset(content, 0x20, 64);
        memcpy(&content[64], (pass == 0) ? "TLS 1.3, client CertificateVerify" :
                                           "TLS 1.3, server CertificateVerify", 33);
        content[97] = 0;
        memcpy(&content[98], th, thLen);
        if (scheme == SSF_TLS_SIG_ED25519)
        {
            ok = (sigLen == SSF_ED25519_SIG_SIZE) &&
                 SSFEd25519Verify(key->pub, content, contentLen, sig);
        }
        else if ((scheme == SSF_TLS_SIG_ECDSA_SECP256R1_SHA256) ||
                 (scheme == SSF_TLS_SIG_ECDSA_SECP384R1_SHA384))
        {
            bool p256 = (scheme == SSF_TLS_SIG_ECDSA_SECP256R1_SHA256);
            if (p256) SSFSHA256(content, contentLen, h, sizeof(h));
            else SSFSHA384(content, contentLen, h, sizeof(h));
            ok = SSFECDSAVerify(p256 ? SSF_EC_CURVE_P256 : SSF_EC_CURVE_P384, key->pub,
                                key->pubLen, h, p256 ? 32u : 48u, sig, sigLen);
        }
        else
        {
            static SSFX509Cert_t c;
            bool s256 = (scheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA256);
            SSF_ASSERT(SSFX509Parse(leaf, (uint32_t)leafLen, &c));
            if (s256) SSFSHA256(content, contentLen, h, sizeof(h));
            else SSFSHA384(content, contentLen, h, sizeof(h));
            ok = SSFRSAVerifyPSS(c.pubKey, c.pubKeyLen,
                                 s256 ? SSF_RSA_HASH_SHA256 : SSF_RSA_HASH_SHA384, h,
                                 s256 ? 32u : 48u, s256 ? 32u : 48u, sig, sigLen);
        }
        SSF_ASSERT(ok == (pass == 0));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Post-handshake messages (RFC 8446 4.6): NewSessionTicket skipped, KeyUpdate recognized and    */
/* checked (4.6.3, 5.1), anything else unexpected_message; messages may span records.            */
/* --------------------------------------------------------------------------------------------- */
#define SSF_TLSC_UT_NOKU (0xffu)

/* Feeds one record's plaintext; checks the result, alert and KeyUpdate request. */
static void _SSFTLSCUTPh(SSFTLSCSession_t *s, const uint8_t *rec, size_t len, bool wantOk,
                         uint8_t wantAlert, uint8_t wantKu)
{
    uint8_t alert = 0xeeu;
    uint8_t ku = 0xeeu;
    SSF_ASSERT(_SSFTLSCPostHandshakeFeedForTest(s, rec, len, &alert, &ku) == wantOk);
    SSF_ASSERT(alert == wantAlert);
    if (wantOk) { SSF_ASSERT(ku == wantKu); }
}

static void _SSFTLSCUTPostHandshake(void)
{
    /* NewSessionTicket: lifetime, age_add, nonce<0..255>, ticket<1..>, extensions<0..> */
    static const uint8_t nst[] = { 0x04, 0x00, 0x00, 0x10,
                                   0x00, 0x00, 0x1c, 0x20, 0x01, 0x02, 0x03, 0x04,
                                   0x01, 0xaa, 0x00, 0x02, 0xbb, 0xcc, 0x00, 0x00 };
    static const uint8_t ku0[] = { 0x18, 0x00, 0x00, 0x01, 0x00 };
    static const uint8_t ku1[] = { 0x18, 0x00, 0x00, 0x01, 0x01 };
    static const uint8_t kuBadVal[] = { 0x18, 0x00, 0x00, 0x01, 0x02 };
    static const uint8_t kuBadLen[] = { 0x18, 0x00, 0x00, 0x02, 0x00, 0x00 };
    static const uint8_t kuThenMore[] = { 0x18, 0x00, 0x00, 0x01, 0x00, 0x04 };
    static const uint8_t certReq[] = { 0x0d, 0x00, 0x00, 0x02, 0x00, 0x00 };
    static const uint8_t finished[] = { 0x14, 0x00, 0x00, 0x01, 0x00 };
    static const uint8_t unknownType[] = { 0x63, 0x00, 0x00, 0x01, 0x00 };
    static const uint8_t nstShort[] = { 0x04, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    /* The smallest ticket: 4 + 4 + nonce<0> 1 + ticket<1> 2 + 1 + extensions<0> 2 = 14 bytes */
    static const uint8_t nstMin[] = { 0x04, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x3c,
                                      0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x01, 0xaa, 0x00, 0x00 };
    /* 13 bytes: the ticket field empty */
    static const uint8_t nst13[] = { 0x04, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x3c,
                                     0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static uint8_t both[sizeof(nst) + sizeof(ku0)];
    SSFTLSCSession_t *s = &_utSession2;
    size_t i;

#define SSF_TLSC_UT_PH_RESET() memset(s, 0, sizeof(*s))
    /* A ticket, whole and then one byte per record */
    SSF_TLSC_UT_PH_RESET();
    _SSFTLSCUTPh(s, nst, sizeof(nst), true, 0u, SSF_TLSC_UT_NOKU);
    for (i = 0; i < sizeof(nst); i++) _SSFTLSCUTPh(s, &nst[i], 1u, true, 0u, SSF_TLSC_UT_NOKU);
    SSF_ASSERT((s->phHdrLen == 0u) && (s->phRemain == 0u));        /* Between messages */
    /* KeyUpdate, each request value; after a ticket in the same record */
    _SSFTLSCUTPh(s, ku0, sizeof(ku0), true, 0u, 0u);
    _SSFTLSCUTPh(s, ku1, sizeof(ku1), true, 0u, 1u);
    memcpy(both, nst, sizeof(nst));
    memcpy(&both[sizeof(nst)], ku1, sizeof(ku1));
    _SSFTLSCUTPh(s, both, sizeof(both), true, 0u, 1u);
    /* A KeyUpdate whose header ends one record and body is the next */
    _SSFTLSCUTPh(s, ku1, 4u, true, 0u, SSF_TLSC_UT_NOKU);
    _SSFTLSCUTPh(s, &ku1[4], 1u, true, 0u, 1u);
    _SSFTLSCUTPh(s, ku0, 2u, true, 0u, SSF_TLSC_UT_NOKU);
    _SSFTLSCUTPh(s, &ku0[2], 3u, true, 0u, 0u);
    /* Refused */
    SSF_TLSC_UT_PH_RESET();
    _SSFTLSCUTPh(s, kuBadVal, sizeof(kuBadVal), false, SSF_TLS_ALERT_ILLEGAL_PARAMETER, 0u);
    SSF_TLSC_UT_PH_RESET();
    _SSFTLSCUTPh(s, kuBadLen, sizeof(kuBadLen), false, SSF_TLS_ALERT_DECODE_ERROR, 0u);
    SSF_TLSC_UT_PH_RESET();                 /* A key change must end its record (5.1) */
    _SSFTLSCUTPh(s, kuThenMore, sizeof(kuThenMore), false, SSF_TLS_ALERT_UNEXPECTED_MSG, 0u);
    SSF_TLSC_UT_PH_RESET();                 /* post_handshake_auth was never offered */
    _SSFTLSCUTPh(s, certReq, sizeof(certReq), false, SSF_TLS_ALERT_UNEXPECTED_MSG, 0u);
    SSF_TLSC_UT_PH_RESET();
    _SSFTLSCUTPh(s, finished, sizeof(finished), false, SSF_TLS_ALERT_UNEXPECTED_MSG, 0u);
    SSF_TLSC_UT_PH_RESET();
    _SSFTLSCUTPh(s, unknownType, sizeof(unknownType), false, SSF_TLS_ALERT_UNEXPECTED_MSG, 0u);
    SSF_TLSC_UT_PH_RESET();
    _SSFTLSCUTPh(s, nstShort, sizeof(nstShort), false, SSF_TLS_ALERT_DECODE_ERROR, 0u);
    SSF_TLSC_UT_PH_RESET();
    _SSFTLSCUTPh(s, nstMin, sizeof(nstMin), true, 0u, SSF_TLSC_UT_NOKU);
    _SSFTLSCUTPh(s, nst13, sizeof(nst13), false, SSF_TLS_ALERT_DECODE_ERROR, 0u);
    /* Records of another type may not come between the pieces of a handshake message (5.1) */
    SSF_TLSC_UT_PH_RESET();
    SSF_ASSERT(_SSFTLSCRecordTypeAllowedForTest(s, SSF_TLS_CT_APPLICATION));
    _SSFTLSCUTPh(s, nst, 2u, true, 0u, SSF_TLSC_UT_NOKU);              /* Inside the header */
    SSF_ASSERT(!_SSFTLSCRecordTypeAllowedForTest(s, SSF_TLS_CT_APPLICATION));
    SSF_ASSERT(_SSFTLSCRecordTypeAllowedForTest(s, SSF_TLS_CT_HANDSHAKE));
    _SSFTLSCUTPh(s, &nst[2], 8u, true, 0u, SSF_TLSC_UT_NOKU);          /* Inside the body */
    SSF_ASSERT(!_SSFTLSCRecordTypeAllowedForTest(s, SSF_TLS_CT_APPLICATION));
    _SSFTLSCUTPh(s, &nst[10], sizeof(nst) - 10u, true, 0u, SSF_TLSC_UT_NOKU);
    SSF_ASSERT(_SSFTLSCRecordTypeAllowedForTest(s, SSF_TLS_CT_APPLICATION));   /* Complete */
    _SSFTLSCUTPh(s, ku1, 4u, true, 0u, SSF_TLSC_UT_NOKU);               /* KeyUpdate header */
    SSF_ASSERT(!_SSFTLSCRecordTypeAllowedForTest(s, SSF_TLS_CT_APPLICATION));
    _SSFTLSCUTPh(s, &ku1[4], 1u, true, 0u, 1u);
    SSF_ASSERT(_SSFTLSCRecordTypeAllowedForTest(s, SSF_TLS_CT_APPLICATION));
    SSF_TLSC_UT_PH_RESET();                 /* A refused type is refused from its header alone */
    _SSFTLSCUTPh(s, certReq, 4u, false, SSF_TLS_ALERT_UNEXPECTED_MSG, 0u);
#undef SSF_TLSC_UT_PH_RESET

    /* "traffic upd" (RFC 8446 7.2): expected values computed independently (Python hmac) */
    {
        static const uint8_t n1[32] = {
            0x2c, 0xec, 0xd0, 0xa1, 0x75, 0x06, 0xef, 0x5f, 0xa7, 0x3e, 0xdc, 0x06, 0x2d, 0x6e,
            0x7b, 0x53, 0x97, 0xcf, 0x07, 0x4e, 0xc1, 0xb4, 0xd8, 0xf9, 0x9a, 0x12, 0x07, 0x72,
            0x93, 0x2f, 0x0b, 0x45 };
        static const uint8_t n2[32] = {
            0x2d, 0x3f, 0xb1, 0xfe, 0x26, 0x7c, 0x2e, 0x01, 0x26, 0x35, 0x1c, 0xc1, 0x69, 0xaf,
            0xb7, 0xca, 0x25, 0xc0, 0xd8, 0x86, 0x71, 0x67, 0xc5, 0x5c, 0x55, 0x33, 0xe3, 0x71,
            0x55, 0x58, 0xa6, 0xb9 };
        static const uint8_t m1[48] = {
            0x40, 0x13, 0x31, 0xb6, 0x3e, 0x9d, 0x59, 0xf2, 0x02, 0xe8, 0xf0, 0x41, 0x04, 0x2d,
            0x95, 0x16, 0xf4, 0xcd, 0x7f, 0xa2, 0xe2, 0xee, 0x14, 0x63, 0x1d, 0x3b, 0x49, 0xfc,
            0x34, 0x0d, 0x7a, 0xf3, 0x7f, 0xc2, 0xc0, 0xc9, 0xf2, 0x52, 0xd8, 0x03, 0x6f, 0x81,
            0xec, 0x5b, 0x85, 0xcb, 0xe5, 0xdb };
        uint8_t secret[48];

        memset(s, 0, sizeof(*s));
        s->hash = SSF_HMAC_HASH_SHA256;
        s->hashLen = 32u;
        for (i = 0; i < 32u; i++) secret[i] = (uint8_t)i;
        _SSFTLSCNextTrafficSecretForTest(s, secret);
        SSF_ASSERT(memcmp(secret, n1, 32u) == 0);
        _SSFTLSCNextTrafficSecretForTest(s, secret);              /* Generation 2 */
        SSF_ASSERT(memcmp(secret, n2, 32u) == 0);
        s->hash = SSF_HMAC_HASH_SHA384;
        s->hashLen = 48u;
        for (i = 0; i < 48u; i++) secret[i] = (uint8_t)i;
        _SSFTLSCNextTrafficSecretForTest(s, secret);
        SSF_ASSERT(memcmp(secret, m1, 48u) == 0);
        memset(s, 0, sizeof(*s));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* recv() / send() after the handshake, over a fake inner transport: the test plays the server's */
/* record layer with known application secrets. Covers KeyUpdate in both directions and the    */
/* interleaving rule end to end.                                                                 */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _utFakeIn[2048];
static size_t _utFakeInLen;
static size_t _utFakeInPos;
static uint8_t _utFakeOut[2048];
static size_t _utFakeOutLen;
static bool _UTFakeOpen(SSFNetTransport_t *t, SSFCStrIn_t h, size_t hs, uint16_t p)
{ (void)t; (void)h; (void)hs; (void)p; return true; }
static SSFNetIOResult_t _UTFakePollOpen(SSFNetTransport_t *t)
{ (void)t; return SSF_NET_IO_SUCCESS; }
static SSFNetIOResult_t _UTFakeSend(SSFNetTransport_t *t, const uint8_t *b, size_t n, size_t *sent)
{
    (void)t;
    SSF_ASSERT((_utFakeOutLen + n) <= sizeof(_utFakeOut));
    memcpy(&_utFakeOut[_utFakeOutLen], b, n);
    _utFakeOutLen += n;
    *sent = n;
    return SSF_NET_IO_SUCCESS;
}
static SSFNetIOResult_t _UTFakeRecv(SSFNetTransport_t *t, uint8_t *b, size_t n, size_t *got)
{
    (void)t;
    *got = 0;
    if (_utFakeInPos >= _utFakeInLen) return SSF_NET_IO_WANT_READ;
    if (n > (_utFakeInLen - _utFakeInPos)) n = _utFakeInLen - _utFakeInPos;
    memcpy(b, &_utFakeIn[_utFakeInPos], n);
    _utFakeInPos += n;
    *got = n;
    return SSF_NET_IO_SUCCESS;
}
static SSFNetIOResult_t _UTFakeShutdown(SSFNetTransport_t *t)
{ (void)t; return SSF_NET_IO_SUCCESS; }
static void _UTFakeClose(SSFNetTransport_t *t) { (void)t; }
static SSFNetTransport_t _utFake = { _UTFakeOpen, _UTFakePollOpen, _UTFakeSend, _UTFakeRecv,
                                     _UTFakeShutdown, _UTFakeClose };

/* The test's view of the server: its send state (the client's receive key), the client's     */
/* send state, and the two secrets, one generation at a time.                                    */
static SSFTLSRecordState_t _utSrvSend;
static SSFTLSRecordState_t _utSrvRecv;
static uint8_t _utSrvSecret[32];
static uint8_t _utCliSecret[32];

static void _UTStateFrom(SSFTLSRecordState_t *st, const uint8_t *secret)
{
    uint8_t key[16], iv[SSF_TLS_IV_SIZE];
    SSFTLSDeriveTrafficKeys(SSF_HMAC_HASH_SHA256, secret, 32u, key, sizeof(key), iv, sizeof(iv));
    SSFTLSRecordStateInit(st, SSF_TLS_CS_AES_128_GCM_SHA256, key, sizeof(key), iv, sizeof(iv));
}

/* A connected session (TLS_AES_128_GCM_SHA256) over the fake transport, generation 0 keys. */
static void _UTAppSession(SSFTLSCSession_t *s)
{
    uint8_t key[16], iv[SSF_TLS_IV_SIZE];

    memset(_utSrvSecret, 0x11, sizeof(_utSrvSecret));
    memset(_utCliSecret, 0x22, sizeof(_utCliSecret));
    SSFTLSCInit(s, &_utFake, NULL);
    s->cipherSuite = SSF_TLS_CS_AES_128_GCM_SHA256;
    s->hash = SSF_HMAC_HASH_SHA256;
    s->hashLen = 32u;
    s->keyLen = 16u;
    memcpy(s->serverAppTrafficSecret, _utSrvSecret, 32u);
    memcpy(s->clientAppTrafficSecret, _utCliSecret, 32u);
    SSFTLSDeriveTrafficKeys(s->hash, _utSrvSecret, 32u, key, sizeof(key), iv, sizeof(iv));
    SSFTLSRecordStateInit(&s->recvState, s->cipherSuite, key, sizeof(key), iv, sizeof(iv));
    SSFTLSDeriveTrafficKeys(s->hash, _utCliSecret, 32u, key, sizeof(key), iv, sizeof(iv));
    SSFTLSRecordStateInit(&s->sendState, s->cipherSuite, key, sizeof(key), iv, sizeof(iv));
    s->recvStateInited = s->sendStateInited = true;
    s->recvEncrypted = s->sendEncrypted = true;
    s->connected = true;
    s->innerOpen = true;
    s->hsState = SSF_TLSC_HS_COMPLETE;
    memset(&_utSrvSend, 0, sizeof(_utSrvSend));          /* Test keys only: start them fresh */
    memset(&_utSrvRecv, 0, sizeof(_utSrvRecv));
    _UTStateFrom(&_utSrvSend, _utSrvSecret);
    _UTStateFrom(&_utSrvRecv, _utCliSecret);
    _utFakeInLen = _utFakeInPos = _utFakeOutLen = 0;
}

/* Queues one server record. */
static void _UTSrvRecord(uint8_t ct, const uint8_t *pt, size_t len)
{
    size_t n;
    SSF_ASSERT(SSFTLSRecordEncrypt(&_utSrvSend, ct, pt, len, &_utFakeIn[_utFakeInLen],
                                   sizeof(_utFakeIn) - _utFakeInLen, &n));
    _utFakeInLen += n;
}

/* Decrypts the next client record at *off; returns its type and plaintext. */
static uint8_t _UTCliRecord(size_t *off, uint8_t *pt, size_t ptSize, size_t *ptLen)
{
    uint8_t ct = 0;
    size_t recLen;
    SSF_ASSERT((*off + 5u) <= _utFakeOutLen);
    recLen = 5u + (((size_t)_utFakeOut[*off + 3u] << 8) | _utFakeOut[*off + 4u]);
    SSF_ASSERT(SSFTLSRecordDecrypt(&_utSrvRecv, &_utFakeOut[*off], recLen, pt, ptSize, ptLen,
                                   &ct));
    *off += recLen;
    return ct;
}

static void _SSFTLSCUTAppData(void)
{
    static const uint8_t nst[] = { 0x04, 0x00, 0x00, 0x10,
                                   0x00, 0x00, 0x1c, 0x20, 0x01, 0x02, 0x03, 0x04,
                                   0x01, 0xaa, 0x00, 0x02, 0xbb, 0xcc, 0x00, 0x00 };
    static const uint8_t ku1[] = { 0x18, 0x00, 0x00, 0x01, 0x01 };
    static const uint8_t ku0[] = { 0x18, 0x00, 0x00, 0x01, 0x00 };
    SSFTLSCSession_t *s = &_utSession2;
    SSFNetTransport_t *t = &s->transport;
    uint8_t buf[64];
    size_t n;
    size_t off;
    uint8_t ct;

    /* A ticket, then data: fine */
    _UTAppSession(s);
    _UTSrvRecord(SSF_TLS_CT_HANDSHAKE, nst, sizeof(nst));
    _UTSrvRecord(SSF_TLS_CT_APPLICATION, (const uint8_t *)"abc", 3u);
    SSF_ASSERT((t->recv(t, buf, sizeof(buf), &n) == SSF_NET_IO_SUCCESS) && (n == 3u) &&
               (memcmp(buf, "abc", 3u) == 0));
    SSFTLSCDeInit(s);

    /* Application data between the pieces of a split ticket: unexpected_message (5.1) */
    _UTAppSession(s);
    _UTSrvRecord(SSF_TLS_CT_HANDSHAKE, nst, 6u);
    _UTSrvRecord(SSF_TLS_CT_APPLICATION, (const uint8_t *)"abc", 3u);
    SSF_ASSERT(t->recv(t, buf, sizeof(buf), &n) == SSF_NET_IO_ERROR);
    SSF_ASSERT(s->pendingAlert == SSF_TLS_ALERT_UNEXPECTED_MSG);
    SSFTLSCDeInit(s);

    /* Server KeyUpdate (requested): data after it is under the server's next key; the client's */
    /* next send() is its own KeyUpdate under the old key, then the data under the next one.    */
    _UTAppSession(s);
    _UTSrvRecord(SSF_TLS_CT_HANDSHAKE, ku1, sizeof(ku1));
    SSFTLSRecordStateDeInit(&_utSrvSend);
    _SSFTLSCNextTrafficSecretForTest(s, _utSrvSecret);
    _UTStateFrom(&_utSrvSend, _utSrvSecret);
    _UTSrvRecord(SSF_TLS_CT_APPLICATION, (const uint8_t *)"abc", 3u);
    SSF_ASSERT((t->recv(t, buf, sizeof(buf), &n) == SSF_NET_IO_SUCCESS) && (n == 3u) &&
               (memcmp(buf, "abc", 3u) == 0));
    SSF_ASSERT(s->keyUpdateOwed);
    SSF_ASSERT((t->send(t, (const uint8_t *)"xyz", 3u, &n) == SSF_NET_IO_SUCCESS) && (n == 3u));
    off = 0;
    ct = _UTCliRecord(&off, buf, sizeof(buf), &n);
    SSF_ASSERT((ct == SSF_TLS_CT_HANDSHAKE) && (n == sizeof(ku0)) &&
               (memcmp(buf, ku0, sizeof(ku0)) == 0));                /* update_not_requested */
    SSFTLSRecordStateDeInit(&_utSrvRecv);
    _SSFTLSCNextTrafficSecretForTest(s, _utCliSecret);
    _UTStateFrom(&_utSrvRecv, _utCliSecret);
    ct = _UTCliRecord(&off, buf, sizeof(buf), &n);
    SSF_ASSERT((ct == SSF_TLS_CT_APPLICATION) && (n == 3u) && (memcmp(buf, "xyz", 3u) == 0));
    SSF_ASSERT(off == _utFakeOutLen);
    SSF_ASSERT(!s->keyUpdateOwed);
    /* No further KeyUpdate on the next send */
    _utFakeOutLen = 0;
    SSF_ASSERT(t->send(t, (const uint8_t *)"q", 1u, &n) == SSF_NET_IO_SUCCESS);
    off = 0;
    SSF_ASSERT(_UTCliRecord(&off, buf, sizeof(buf), &n) == SSF_TLS_CT_APPLICATION);
    SSF_ASSERT(off == _utFakeOutLen);
    SSFTLSCDeInit(s);

    /* The record limit: once reached, the next send() updates the client key first */
    _UTAppSession(s);
    s->sendRecordsOnKey = SSF_TLSC_CONFIG_KEY_UPDATE_RECORDS;
    SSF_ASSERT(t->send(t, (const uint8_t *)"xyz", 3u, &n) == SSF_NET_IO_SUCCESS);
    off = 0;
    SSF_ASSERT(_UTCliRecord(&off, buf, sizeof(buf), &n) == SSF_TLS_CT_HANDSHAKE);
    SSF_ASSERT((n == sizeof(ku0)) && (memcmp(buf, ku0, sizeof(ku0)) == 0));
    SSFTLSRecordStateDeInit(&_utSrvRecv);
    _SSFTLSCNextTrafficSecretForTest(s, _utCliSecret);
    _UTStateFrom(&_utSrvRecv, _utCliSecret);
    SSF_ASSERT(_UTCliRecord(&off, buf, sizeof(buf), &n) == SSF_TLS_CT_APPLICATION);
    SSF_ASSERT(s->sendRecordsOnKey == 1u);
    SSFTLSCDeInit(s);
    SSFTLSRecordStateDeInit(&_utSrvSend);
    SSFTLSRecordStateDeInit(&_utSrvRecv);
}

/* Trace capture for the client certificate warnings */
static char _utWarn[1024];
static void _SSFTLSCUTWarnTrace(SSFTLSTraceLevel_t level, SSFTLSTraceCategory_t cat,
                                const char *msg, void *ctx)
{
    (void)cat; (void)ctx;
    if ((level <= SSF_TLS_TRACE_WARN) && ((strlen(_utWarn) + strlen(msg) + 2u) < sizeof(_utWarn)))
    {
        strcat(_utWarn, msg);
        strcat(_utWarn, "|");
    }
}

/* Chooses the scheme for body with the session's certificate; returns it (0 = empty cert). */
static uint16_t _SSFTLSCUTChoose(SSFTLSCSession_t *s, const uint8_t *body, size_t len,
                                 bool nowValid, uint64_t now)
{
    uint16_t scheme = 0xffffu;
    uint8_t alert = 0xffu;
    _utWarn[0] = 0;
    SSF_ASSERT(_SSFTLSCChooseClientSchemeChainForTest(s, body, len, nowValid, now, &scheme,
                                                      &alert));
    SSF_ASSERT(alert == 0u);
    return scheme;
}

/* The certificate chain's own signatures must be ones the server accepts (RFC 8446 4.4.2.3),  */
/* from signature_algorithms_cert, else signature_algorithms; a self-signed last certificate is */
/* exempt (4.4.2.2). The leaf's validity, Key Usage and EKU are traced, never enforced.         */
static void _SSFTLSCUTClientChain(void)
{
    static SSFPKey_t kP256, kEd, kRsa, kNoKU, kNoEKU, kExp;
    static const uint8_t *ch[2];
    static uint32_t ln[2];
    static const uint8_t junk[10] = { 0x30, 0x08, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x05, 0x00 };
    /* signature_algorithms lists, and with signature_algorithms_cert */
    static const uint8_t cr0403[] = { 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04,
                                      0x00, 0x02, 0x04, 0x03 };
    static const uint8_t cr0807[] = { 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04,
                                      0x00, 0x02, 0x08, 0x07 };
    static const uint8_t cr0807c0403[] = { 0x00, 0x00, 0x10, 0x00, 0x0d, 0x00, 0x04,
                                           0x00, 0x02, 0x08, 0x07,
                                           0x00, 0x32, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
    static const uint8_t cr0403c0807[] = { 0x00, 0x00, 0x10, 0x00, 0x0d, 0x00, 0x04,
                                           0x00, 0x02, 0x04, 0x03,
                                           0x00, 0x32, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07 };
    static const uint8_t cr0804[] = { 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04,
                                      0x00, 0x02, 0x08, 0x04 };
    static const uint8_t cr0804o0403[] = { 0x00, 0x00, 0x0a, 0x00, 0x0d, 0x00, 0x06,
                                           0x00, 0x04, 0x08, 0x04, 0x04, 0x03 };
    static const uint8_t cr0403o0401[] = { 0x00, 0x00, 0x0a, 0x00, 0x0d, 0x00, 0x06,
                                           0x00, 0x04, 0x04, 0x03, 0x04, 0x01 };
    static const uint8_t crCertOdd[] = { 0x00, 0x00, 0x11, 0x00, 0x0d, 0x00, 0x04,
                                         0x00, 0x02, 0x04, 0x03,
                                         0x00, 0x32, 0x00, 0x05, 0x00, 0x03, 0x04, 0x03, 0x08 };
    SSFTLSCSession_t *s = &_utSession2;
    uint16_t scheme;
    uint8_t alert;

    SSF_ASSERT(SSFPKeyDecodeDER(_utClientP256Key, sizeof(_utClientP256Key), &kP256));
    SSF_ASSERT(SSFPKeyDecodeDER(_utClientEd25519Key, sizeof(_utClientEd25519Key), &kEd));
    SSF_ASSERT(SSFPKeyDecodeDER(_utClientRSA2048Key, sizeof(_utClientRSA2048Key), &kRsa));
    SSF_ASSERT(SSFPKeyDecodeDER(_utClientNoKUKey, sizeof(_utClientNoKUKey), &kNoKU));
    SSF_ASSERT(SSFPKeyDecodeDER(_utClientNoEKUKey, sizeof(_utClientNoEKUKey), &kNoEKU));
    SSF_ASSERT(SSFPKeyDecodeDER(_utClientExpiredKey, sizeof(_utClientExpiredKey), &kExp));
    SSFTLSCInit(s, &_utSock.transport, NULL);
    SSFTLSCSetTrace(s, _SSFTLSCUTWarnTrace, NULL);

    /* All the fixture leaves are signed ecdsa-with-SHA256 (ecdsa_secp256r1_sha256) */
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientP256Cert, sizeof(_utClientP256Cert), &kP256));
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0403, sizeof(cr0403), false, 0) ==
               SSF_TLS_SIG_ECDSA_SECP256R1_SHA256);
    SSF_ASSERT(_utWarn[0] == 0);                                     /* A good leaf: silent */
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0403c0807, sizeof(cr0403c0807), false, 0) == 0u);
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientEd25519Cert, sizeof(_utClientEd25519Cert), &kEd));
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0807, sizeof(cr0807), false, 0) == 0u);   /* chain no */
    SSF_ASSERT(strstr(_utWarn, "server does not accept") != NULL);
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0807c0403, sizeof(cr0807c0403), false, 0) ==
               SSF_TLS_SIG_ED25519);                         /* certificate list governs */
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientRSA2048Cert, sizeof(_utClientRSA2048Cert), &kRsa));
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0804, sizeof(cr0804), false, 0) == 0u);
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0804o0403, sizeof(cr0804o0403), false, 0) ==
               SSF_TLS_SIG_RSA_PSS_RSAE_SHA256);

    /* Chains: an intermediate is checked; a self-signed root is exempt, other RSA is not */
    ch[0] = _utClientP256Cert;
    ln[0] = (uint32_t)sizeof(_utClientP256Cert);
#define SSF_TLSC_UT_CHAIN2(second, body, want) do { \
    ch[1] = (second); ln[1] = (uint32_t)sizeof(second); \
    SSF_ASSERT(SSFTLSCSetClientCert(s, ch, ln, 2u, &kP256)); \
    SSF_ASSERT(_SSFTLSCUTChoose(s, (body), sizeof(body), false, 0) == (want)); } while (0)
    SSF_TLSC_UT_CHAIN2(_utClientIntCert, cr0403, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256);
    SSF_TLSC_UT_CHAIN2(_utClientRsaRootCert, cr0403, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256);
    SSF_TLSC_UT_CHAIN2(_utClientRsaSignedCert, cr0403, 0u);
    SSF_TLSC_UT_CHAIN2(_utClientRsaSignedCert, cr0403o0401, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256);
    SSF_TLSC_UT_CHAIN2(junk, cr0403, 0u);                     /* An intermediate that is no cert */
#undef SSF_TLSC_UT_CHAIN2

    /* A malformed signature_algorithms_cert is refused */
    scheme = 0xffffu;
    SSF_ASSERT(_SSFTLSCChooseClientSchemeChainForTest(s, crCertOdd, sizeof(crCertOdd), false, 0,
                                                      &scheme, &alert) == false);
    SSF_ASSERT((scheme == 0u) && (alert == SSF_TLS_ALERT_DECODE_ERROR));
    {
        /* An empty signature_algorithms_cert list (SignatureSchemeList<2..2^16-2>) */
        static const uint8_t crCertEmpty[] = { 0x00, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x04,
                                               0x00, 0x02, 0x04, 0x03,
                                               0x00, 0x32, 0x00, 0x02, 0x00, 0x00 };
        scheme = 0xffffu;
        SSF_ASSERT(_SSFTLSCChooseClientSchemeChainForTest(s, crCertEmpty, sizeof(crCertEmpty),
                                                          false, 0, &scheme, &alert) == false);
        SSF_ASSERT((scheme == 0u) && (alert == SSF_TLS_ALERT_DECODE_ERROR));
    }

    /* Leaf warnings: traced, the certificate is still sent */
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientNoKUCert, sizeof(_utClientNoKUCert), &kNoKU));
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0403, sizeof(cr0403), false, 0) != 0u);
    SSF_ASSERT((strstr(_utWarn, "digitalSignature") != NULL) &&
               (strstr(_utWarn, "clientAuth") == NULL));
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientNoEKUCert, sizeof(_utClientNoEKUCert), &kNoEKU));
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0403, sizeof(cr0403), false, 0) != 0u);
    SSF_ASSERT((strstr(_utWarn, "clientAuth") != NULL) &&
               (strstr(_utWarn, "digitalSignature") == NULL));
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientExpiredCert, sizeof(_utClientExpiredCert), &kExp));
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0403, sizeof(cr0403), true, 1780000000ull) != 0u);
    SSF_ASSERT(strstr(_utWarn, "not valid at") != NULL);
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0403, sizeof(cr0403), true, 1609000000ull) != 0u);
    SSF_ASSERT(_utWarn[0] == 0);                                  /* 2020-12-26: valid */
    SSF_ASSERT(_SSFTLSCUTChoose(s, cr0403, sizeof(cr0403), false, 1780000000ull) != 0u);
    SSF_ASSERT(_utWarn[0] == 0);                                  /* No trusted time */

    SSFTLSCDeInit(s);
    SSFPKeyWipe(&kP256);
    SSFPKeyWipe(&kEd);
    SSFPKeyWipe(&kRsa);
    SSFPKeyWipe(&kNoKU);
    SSFPKeyWipe(&kNoEKU);
    SSFPKeyWipe(&kExp);
}

static void _SSFTLSCUTClientCert(void)
{
    static SSFPKey_t kP256, kP384, kEd, kRsa, kNone;
    static uint8_t bad[sizeof(_utClientRSA2048Cert)];
    static uint8_t msg[1024];
    static uint8_t want[1024];
    static const uint8_t *chain2[2];
    static uint32_t lens2[2];
    SSFTLSCSession_t *s = &_utSession2;
    uint8_t th[48];
    size_t i;
    size_t len;
    size_t off;
    uint16_t scheme;
    uint8_t alert;

    SSF_ASSERT(SSFPKeyDecodeDER(_utClientP256Key, sizeof(_utClientP256Key), &kP256));
    SSF_ASSERT(SSFPKeyDecodeDER(_utClientP384Key, sizeof(_utClientP384Key), &kP384));
    SSF_ASSERT(SSFPKeyDecodeDER(_utClientEd25519Key, sizeof(_utClientEd25519Key), &kEd));
    SSF_ASSERT(SSFPKeyDecodeDER(_utClientRSA2048Key, sizeof(_utClientRSA2048Key), &kRsa));
    memset(&kNone, 0, sizeof(kNone));
    SSFTLSCInit(s, &_utSock.transport, NULL);

    /* ---- SSFTLSCSetClientCert: matching certificate and key, each key type ---- */
    SSF_ASSERT(s->clientChainCount == 0u);
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientP256Cert, sizeof(_utClientP256Cert), &kP256));
    SSF_ASSERT((s->clientChainCount == 1u) && (s->clientKey == &kP256));
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientP384Cert, sizeof(_utClientP384Cert), &kP384));
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientEd25519Cert, sizeof(_utClientEd25519Cert), &kEd));
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientRSA2048Cert, sizeof(_utClientRSA2048Cert), &kRsa));
    chain2[0] = _utClientP256Cert;
    lens2[0] = (uint32_t)sizeof(_utClientP256Cert);
    chain2[1] = _utClientIntCert;
    lens2[1] = (uint32_t)sizeof(_utClientIntCert);
    SSF_ASSERT(SSFTLSCSetClientCert(s, chain2, lens2, 2u, &kP256));
    SSF_ASSERT(s->clientChainCount == 2u);
    SSF_ASSERT(SSFTLSCSetClientCert(s, NULL, NULL, 0u, NULL));                /* Clear */
    SSF_ASSERT((s->clientChainCount == 0u) && (s->clientKey == NULL));

    /* ---- Refused, leaving no certificate set ---- */
#define SSF_TLSC_UT_CC_BAD(expr) do { \
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientP256Cert, sizeof(_utClientP256Cert), &kP256)); \
    SSF_ASSERT((expr) == false); \
    SSF_ASSERT((s->clientChainCount == 0u) && (s->clientKey == NULL)); } while (0)
    /* Another device's certificate, and certificates of another key type */
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, _utClientOtherCert, sizeof(_utClientOtherCert),
                                        &kP256));
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, _utClientEd25519Cert, sizeof(_utClientEd25519Cert),
                                        &kP256));
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, _utClientP256Cert, sizeof(_utClientP256Cert), &kRsa));
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, _utClientRSA2048Cert, sizeof(_utClientRSA2048Cert),
                                        &kP384));
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, _utClientP384Cert, sizeof(_utClientP384Cert),
                                        &kP256));
    /* The leaf's public key one byte off: EC point, RSA modulus */
    memcpy(bad, _utClientP256Cert, sizeof(_utClientP256Cert));
    off = _SSFTLSCUTFind(bad, sizeof(_utClientP256Cert), kP256.pub, kP256.pubLen);
    SSF_ASSERT(off != (size_t)-1);
    bad[off + kP256.pubLen - 1u] ^= 0x01u;
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, bad, sizeof(_utClientP256Cert), &kP256));
    memcpy(bad, _utClientRSA2048Cert, sizeof(_utClientRSA2048Cert));
    off = _SSFTLSCUTFind(bad, sizeof(bad), &kRsa.rsaDer[20], 32u);    /* Inside the modulus */
    SSF_ASSERT(off != (size_t)-1);
    bad[off + 16u] ^= 0x01u;
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, bad, sizeof(bad), &kRsa));
    /* Not a certificate, an empty entry, no key, a key that is no key, no chain */
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, _utClientP256Cert, sizeof(_utClientP256Cert) - 1u,
                                        &kP256));
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, _utClientP256Cert, 0u, &kP256));
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, _utClientP256Cert, sizeof(_utClientP256Cert), NULL));
    SSF_TLSC_UT_CC_BAD(_SSFTLSCUTSetOne(s, _utClientP256Cert, sizeof(_utClientP256Cert), &kNone));
    SSF_TLSC_UT_CC_BAD(SSFTLSCSetClientCert(s, chain2, lens2, 0u, &kP256));
    SSF_TLSC_UT_CC_BAD(SSFTLSCSetClientCert(s, NULL, lens2, 1u, &kP256));
    lens2[1] = 0u;                                          /* Empty intermediate entry */
    SSF_TLSC_UT_CC_BAD(SSFTLSCSetClientCert(s, chain2, lens2, 2u, &kP256));
    lens2[1] = 0x01000000u;                                 /* Over the 24-bit field */
    SSF_TLSC_UT_CC_BAD(SSFTLSCSetClientCert(s, chain2, lens2, 2u, &kP256));
    lens2[1] = (uint32_t)sizeof(_utClientIntCert);
#undef SSF_TLSC_UT_CC_BAD

    /* ---- Scheme choice: the server's first listed scheme the key can sign ---- */
    {
#define SSF_TLSC_UT_CS(body, key, wantScheme) do { \
    scheme = 0xffffu; alert = 0xffu; \
    SSF_ASSERT(_SSFTLSCChooseClientSchemeForTest((body), sizeof(body), (key), &scheme, &alert)); \
    SSF_ASSERT((scheme == (wantScheme)) && (alert == 0u)); } while (0)
        static const uint8_t crEcdsa256[] = { 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04,
                                              0x00, 0x02, 0x04, 0x03 };
        static const uint8_t crEdThen256[] = { 0x00, 0x00, 0x0a, 0x00, 0x0d, 0x00, 0x06,
                                               0x00, 0x04, 0x08, 0x07, 0x04, 0x03 };
        static const uint8_t crPss384First[] = { 0x00, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x08,
                                                 0x00, 0x06, 0x05, 0x03, 0x08, 0x05, 0x08, 0x04 };
        static const uint8_t crRsaUnusable[] = { 0x00, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x08,
                                                 0x00, 0x06, 0x04, 0x01, 0x05, 0x01, 0x08, 0x09 };
        static const uint8_t crBad[] = { 0x00, 0x00, 0x00 };

        SSF_TLSC_UT_CS(crEcdsa256, SSF_PKEY_TYPE_P256, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256);
        SSF_TLSC_UT_CS(crEcdsa256, SSF_PKEY_TYPE_P384, 0u);           /* P-384 key: no match */
        SSF_TLSC_UT_CS(crEcdsa256, SSF_PKEY_TYPE_ED25519, 0u);
        SSF_TLSC_UT_CS(crEcdsa256, SSF_PKEY_TYPE_RSA, 0u);
        SSF_TLSC_UT_CS(crEcdsa256, SSF_PKEY_TYPE_NONE, 0u);           /* No certificate */
        SSF_TLSC_UT_CS(crEdThen256, SSF_PKEY_TYPE_ED25519, SSF_TLS_SIG_ED25519);
        SSF_TLSC_UT_CS(crEdThen256, SSF_PKEY_TYPE_P256, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256);
        SSF_TLSC_UT_CS(crPss384First, SSF_PKEY_TYPE_P384, SSF_TLS_SIG_ECDSA_SECP384R1_SHA384);
        SSF_TLSC_UT_CS(crPss384First, SSF_PKEY_TYPE_RSA, SSF_TLS_SIG_RSA_PSS_RSAE_SHA384);
        SSF_TLSC_UT_CS(crPss384First, SSF_PKEY_TYPE_P256, 0u);
        /* PKCS#1 never signs a handshake, rsa_pss_pss needs a PSS-OID key (4.2.3) */
        SSF_TLSC_UT_CS(crRsaUnusable, SSF_PKEY_TYPE_RSA, 0u);
        /* A request refused after signature_algorithms chose a scheme reports no scheme */
        {
            static const uint8_t crLateBad[] = { 0x00, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x04,
                                                 0x00, 0x02, 0x04, 0x03, 0x00, 0x33, 0x00, 0x00 };
            static const uint8_t crLateDup[] = { 0x00, 0x00, 0x10, 0x00, 0x0d, 0x00, 0x04,
                                                 0x00, 0x02, 0x04, 0x03,
                                                 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
            scheme = 0xffffu;
            SSF_ASSERT(_SSFTLSCChooseClientSchemeForTest(crLateBad, sizeof(crLateBad),
                                                         SSF_PKEY_TYPE_P256, &scheme,
                                                         &alert) == false);
            SSF_ASSERT((scheme == 0u) && (alert == SSF_TLS_ALERT_ILLEGAL_PARAMETER));
            scheme = 0xffffu;
            SSF_ASSERT(_SSFTLSCChooseClientSchemeForTest(crLateDup, sizeof(crLateDup),
                                                         SSF_PKEY_TYPE_P256, &scheme,
                                                         &alert) == false);
            SSF_ASSERT((scheme == 0u) && (alert == SSF_TLS_ALERT_ILLEGAL_PARAMETER));
        }
        /* A malformed request is still refused with its alert */
        SSF_ASSERT(_SSFTLSCChooseClientSchemeForTest(crBad, sizeof(crBad), SSF_PKEY_TYPE_P256,
                                                     &scheme, &alert) == false);
        SSF_ASSERT(alert == SSF_TLS_ALERT_DECODE_ERROR);
#undef SSF_TLSC_UT_CS
    }

    /* ---- The client Certificate message, streamed in pieces ---- */
    SSF_ASSERT(SSFTLSCSetClientCert(s, chain2, lens2, 2u, &kP256));
    len = 0;
    want[len++] = 11u;                                                     /* certificate */
    {
        size_t body = 1u + 3u + (3u + sizeof(_utClientP256Cert) + 2u) +
                      (3u + sizeof(_utClientIntCert) + 2u);
        size_t list = body - 4u;
        want[len++] = (uint8_t)(body >> 16); want[len++] = (uint8_t)(body >> 8);
        want[len++] = (uint8_t)body;
        want[len++] = 0u;                                                  /* empty context */
        want[len++] = (uint8_t)(list >> 16); want[len++] = (uint8_t)(list >> 8);
        want[len++] = (uint8_t)list;
    }
    want[len++] = 0u; want[len++] = (uint8_t)(sizeof(_utClientP256Cert) >> 8);
    want[len++] = (uint8_t)sizeof(_utClientP256Cert);
    memcpy(&want[len], _utClientP256Cert, sizeof(_utClientP256Cert));
    len += sizeof(_utClientP256Cert);
    want[len++] = 0u; want[len++] = 0u;                                    /* no extensions */
    want[len++] = 0u; want[len++] = (uint8_t)(sizeof(_utClientIntCert) >> 8);
    want[len++] = (uint8_t)sizeof(_utClientIntCert);
    memcpy(&want[len], _utClientIntCert, sizeof(_utClientIntCert));
    len += sizeof(_utClientIntCert);
    want[len++] = 0u; want[len++] = 0u;
    SSF_ASSERT(_SSFTLSCClientCertMsgLenForTest(s) == len);
    {
        static const size_t steps[] = { 1u, 3u, 7u, 64u, 437u, 1024u };
        size_t k;
        for (k = 0; k < (sizeof(steps) / sizeof(steps[0])); k++)
        {
            memset(msg, 0xAA, sizeof(msg));
            for (off = 0; off < len; off += i)
            {
                i = ((len - off) < steps[k]) ? (len - off) : steps[k];
                _SSFTLSCClientCertMsgCopyForTest(s, off, &msg[off], i);
            }
            SSF_ASSERT(memcmp(msg, want, len) == 0);
        }
    }

    /* ---- CertificateVerify: signed over the client context, verifiable by the leaf key ---- */
    for (i = 0; i < sizeof(th); i++) th[i] = (uint8_t)(0xA0u + i);
#define SSF_TLSC_UT_CV_SIGN(cert, key, scheme, thLen) do { \
    SSF_ASSERT(_SSFTLSCUTSetOne(s, (cert), sizeof(cert), (key))); \
    SSF_ASSERT(_SSFTLSCSignClientCVForTest(s, (scheme), th, (thLen), msg, sizeof(msg), &len)); \
    _SSFTLSCUTCheckClientCV(msg, len, (scheme), th, (thLen), (cert), sizeof(cert), (key)); \
    } while (0)
    SSF_TLSC_UT_CV_SIGN(_utClientP256Cert, &kP256, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256, 32u);
    SSF_TLSC_UT_CV_SIGN(_utClientP256Cert, &kP256, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256, 48u);
    SSF_TLSC_UT_CV_SIGN(_utClientP384Cert, &kP384, SSF_TLS_SIG_ECDSA_SECP384R1_SHA384, 32u);
    SSF_TLSC_UT_CV_SIGN(_utClientEd25519Cert, &kEd, SSF_TLS_SIG_ED25519, 32u);
    SSF_TLSC_UT_CV_SIGN(_utClientEd25519Cert, &kEd, SSF_TLS_SIG_ED25519, 48u);
    SSF_TLSC_UT_CV_SIGN(_utClientRSA2048Cert, &kRsa, SSF_TLS_SIG_RSA_PSS_RSAE_SHA256, 32u);
    SSF_TLSC_UT_CV_SIGN(_utClientRSA2048Cert, &kRsa, SSF_TLS_SIG_RSA_PSS_RSAE_SHA384, 48u);
#undef SSF_TLSC_UT_CV_SIGN
    /* A scheme the key cannot make, and an output too small, are refused */
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientP256Cert, sizeof(_utClientP256Cert), &kP256));
    SSF_ASSERT(_SSFTLSCSignClientCVForTest(s, SSF_TLS_SIG_ED25519, th, 32u, msg, sizeof(msg),
                                           &len) == false);
    SSF_ASSERT(_SSFTLSCSignClientCVForTest(s, SSF_TLS_SIG_ECDSA_SECP256R1_SHA256, th, 32u, msg,
                                           16u, &len) == false);

    SSFTLSCDeInit(s);
    SSFPKeyWipe(&kP256);
    SSFPKeyWipe(&kP384);
    SSFPKeyWipe(&kEd);
    SSFPKeyWipe(&kRsa);
}

/* --------------------------------------------------------------------------------------------- */
/* Item D: each chain verification failure gets its RFC 8446 6.2 alert.                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCUTChainAlert(void)
{
    static const struct { SSFX509VerifyCode_t code; uint8_t alert; } map[] =
    {
        { SSF_X509_VERIFY_ERR_PARSE,            42u },  /* bad_certificate */
        { SSF_X509_VERIFY_ERR_SIG_ALG_MISMATCH, 42u },
        { SSF_X509_VERIFY_ERR_SIGNATURE,        42u },
        { SSF_X509_VERIFY_ERR_KEY_ID_MISMATCH,  42u },
        { SSF_X509_VERIFY_ERR_HOSTNAME,         42u },  /* As OpenSSL and GnuTLS send */
        { SSF_X509_VERIFY_ERR_VERSION,          43u },  /* unsupported_certificate */
        { SSF_X509_VERIFY_ERR_CRITICAL_EXT,     43u },
        { SSF_X509_VERIFY_ERR_NOT_YET_VALID,    45u },  /* certificate_expired */
        { SSF_X509_VERIFY_ERR_EXPIRED,          45u },
        { SSF_X509_VERIFY_ERR_NOT_CA,           46u },  /* certificate_unknown */
        { SSF_X509_VERIFY_ERR_CA_KEY_USAGE,     46u },
        { SSF_X509_VERIFY_ERR_PATH_LEN,         46u },
        { SSF_X509_VERIFY_ERR_NAME_CONSTRAINTS, 46u },
        { SSF_X509_VERIFY_ERR_EKU,              46u },
        { SSF_X509_VERIFY_ERR_LEAF_KEY_USAGE,   46u },
        { SSF_X509_VERIFY_ERR_UNKNOWN_CA,       48u },  /* unknown_ca */
    };
    size_t i;

    /* Every failure code is listed once */
    SSF_ASSERT((sizeof(map) / sizeof(map[0])) == (size_t)(SSF_X509_VERIFY_MAX - 1));
    for (i = 0; i < (sizeof(map) / sizeof(map[0])); i++)
    {
        SSF_ASSERT(_SSFTLSCChainAlertForTest(map[i].code) == map[i].alert);
    }
    /* A code that is not a failure is a caller error, not an alert */
    SSF_ASSERT_TEST(_SSFTLSCChainAlertForTest(SSF_X509_VERIFY_OK));
}

static void _SSFTLSCUTSchemeMatchesKey(void)
{
    static const struct { uint16_t scheme; SSFTLSCLeafKey_t key; } ok[] = {
        { SSF_TLS_SIG_ECDSA_SECP256R1_SHA256, SSF_TLSC_LEAF_KEY_P256 },
        { SSF_TLS_SIG_ECDSA_SECP384R1_SHA384, SSF_TLSC_LEAF_KEY_P384 },
        { SSF_TLS_SIG_RSA_PSS_RSAE_SHA256, SSF_TLSC_LEAF_KEY_RSA },
        { SSF_TLS_SIG_RSA_PSS_RSAE_SHA384, SSF_TLSC_LEAF_KEY_RSA },
        { SSF_TLS_SIG_ED25519, SSF_TLSC_LEAF_KEY_ED25519 } };
    static const uint16_t schemes[] = { SSF_TLS_SIG_ECDSA_SECP256R1_SHA256,
        SSF_TLS_SIG_ECDSA_SECP384R1_SHA384, SSF_TLS_SIG_RSA_PSS_RSAE_SHA256,
        SSF_TLS_SIG_RSA_PSS_RSAE_SHA384, SSF_TLS_SIG_ED25519 };
    static const SSFTLSCLeafKey_t keys[] = { SSF_TLSC_LEAF_KEY_UNKNOWN, SSF_TLSC_LEAF_KEY_P256,
        SSF_TLSC_LEAF_KEY_P384, SSF_TLSC_LEAF_KEY_RSA, SSF_TLSC_LEAF_KEY_ED25519 };
    size_t i;
    size_t j;
    size_t k;

    /* Exactly the listed pairs match; every other scheme x key pair is refused */
    for (i = 0; i < (sizeof(schemes) / sizeof(schemes[0])); i++)
    {
        for (j = 0; j < (sizeof(keys) / sizeof(keys[0])); j++)
        {
            bool want = false;

            for (k = 0; k < (sizeof(ok) / sizeof(ok[0])); k++)
            { if ((ok[k].scheme == schemes[i]) && (ok[k].key == keys[j])) want = true; }
            SSF_ASSERT(_SSFTLSCSchemeMatchesKeyForTest(schemes[i], keys[j]) == want);
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* ALPN (RFC 7301): SSFTLSCSetALPN() validation, the EncryptedExtensions answer and              */
/* SSFTLSCGetALPN(). The ClientHello side is checked on the wire in _SSFTLSCUTClientHelloRetry. */
/* --------------------------------------------------------------------------------------------- */
#define SSF_TLSC_UT_EE_ALPN(s, body, wantAlert, wantProto) do { \
    uint8_t _a = 0xffu; \
    bool _ok = _SSFTLSCParseEncryptedExtensionsAlpnForTest((s), (body), sizeof(body), &_a); \
    SSF_ASSERT(_ok == ((wantAlert) == 0u)); \
    SSF_ASSERT(_a == (wantAlert)); \
    SSF_ASSERT(SSFTLSCGetALPN(s) == NULL);    /* Not before the handshake completes */ \
    (s)->hsState = SSF_TLSC_HS_COMPLETE; \
    SSF_ASSERT(SSFTLSCGetALPN(s) == (_ok ? (wantProto) : NULL)); \
    (s)->hsState = SSF_TLSC_HS_IDLE; } while (0)

/* ALPN answers, each in an EncryptedExtensions body */
static const uint8_t _utEeAlpnAws[]   = { 0x00, 0x15, 0x00, 0x10, 0x00, 0x11, 0x00, 0x0f, 0x0e,
                                          'x', '-', 'a', 'm', 'z', 'n', '-', 'm', 'q', 't', 't',
                                          '-', 'c', 'a' };
static const uint8_t _utEeAlpnMqtt[]  = { 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00,     /* SNI ack too */
                                          0x00, 0x10, 0x00, 0x07, 0x00, 0x05, 0x04,
                                          'm', 'q', 't', 't' };
/* Not one the client offered: a prefix, a longer name, a different one */
static const uint8_t _utEeAlpnPrefix[] = { 0x00, 0x0a, 0x00, 0x10, 0x00, 0x06, 0x00, 0x04, 0x03,
                                           'm', 'q', 't' };
static const uint8_t _utEeAlpnLonger[] = { 0x00, 0x0c, 0x00, 0x10, 0x00, 0x08, 0x00, 0x06, 0x05,
                                           'm', 'q', 't', 't', 's' };
static const uint8_t _utEeAlpnSameLen[] = { 0x00, 0x0b, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05, 0x04,
                                            'm', 'q', 't', 'z' };
static const uint8_t _utEeAlpnH2[]    = { 0x00, 0x09, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02,
                                          'h', '2' };
static const uint8_t _utEeAlpnDup[]   = { 0x00, 0x16, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05, 0x04,
                                          'm', 'q', 't', 't',
                                          0x00, 0x10, 0x00, 0x07, 0x00, 0x05, 0x04,
                                          'm', 'q', 't', 't' };
/* Framing: not exactly one non-empty ProtocolName filling the extension */
static const uint8_t _utEeAlpnTwo[]   = { 0x00, 0x0e, 0x00, 0x10, 0x00, 0x0a, 0x00, 0x08,
                                          0x04, 'm', 'q', 't', 't', 0x02, 'h', '2' };
static const uint8_t _utEeAlpnEmptyName[] = { 0x00, 0x07, 0x00, 0x10, 0x00, 0x03, 0x00, 0x01,
                                              0x00 };
static const uint8_t _utEeAlpnEmptyList[] = { 0x00, 0x06, 0x00, 0x10, 0x00, 0x02, 0x00, 0x00 };
static const uint8_t _utEeAlpnNoList[] = { 0x00, 0x04, 0x00, 0x10, 0x00, 0x00 };
static const uint8_t _utEeAlpnListLen[] = { 0x00, 0x0b, 0x00, 0x10, 0x00, 0x07, 0x00, 0x06,
                                            0x04, 'm', 'q', 't', 't' };
static const uint8_t _utEeAlpnNameLen[] = { 0x00, 0x0b, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05,
                                            0x05, 'm', 'q', 't', 't' };
static const uint8_t _utEeAlpnShortNm[] = { 0x00, 0x0b, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05,
                                            0x03, 'm', 'q', 't', 't' };

static void _SSFTLSCUTAlpn(void)
{
    static const char *const both[] = { "x-amzn-mqtt-ca", "mqtt" };
    static const char *const one[] = { "mqtt" };
    static const char *const withNull[] = { "mqtt", NULL };
    static const char *const withEmpty[] = { "mqtt", "" };
    /* 255 bytes is the longest ProtocolName; 256 is too long */
    static char n255[256];
    static char n256[257];
    static const char *list255[1];
    static const char *list256[1];
    /* Names filling SSF_TLS_CONFIG_MAX_ALPN_LEN exactly (each name plus its length byte), */
    /* and one byte over                                                                   */
    static char fill[SSF_TLS_CONFIG_MAX_ALPN_LEN];
    static char over[SSF_TLS_CONFIG_MAX_ALPN_LEN + 1u];
    static const char *listFill[1];
    static const char *listOver[1];
    SSFTLSCSession_t *s = &_utSession2;

    memset(n255, 'a', 255); n255[255] = 0;
    memset(n256, 'a', 256); n256[256] = 0;
    list255[0] = n255;
    list256[0] = n256;
    memset(fill, 'f', sizeof(fill) - 1u); fill[sizeof(fill) - 1u] = 0;
    memset(over, 'o', sizeof(over) - 1u); over[sizeof(over) - 1u] = 0;
    listFill[0] = fill;
    listOver[0] = over;
    SSFTLSCInit(s, &_utSock.transport, NULL);

    /* ---- SSFTLSCSetALPN validation; a rejected list leaves none set ---- */
    SSF_ASSERT((s->alpnCount == 0u) && (SSFTLSCGetALPN(s) == NULL));
    SSF_ASSERT(SSFTLSCSetALPN(s, both, 2u));
    SSF_ASSERT((s->alpnProtos == both) && (s->alpnCount == 2u));
    SSF_ASSERT(SSFTLSCSetALPN(s, NULL, 0u));                          /* Cleared */
    SSF_ASSERT((s->alpnProtos == NULL) && (s->alpnCount == 0u));
    SSF_ASSERT(SSFTLSCSetALPN(s, one, 1u));
    SSF_ASSERT(SSFTLSCSetALPN(s, both, 0u) == false);                 /* Mismatched clear */
    SSF_ASSERT(s->alpnCount == 0u);
    SSF_ASSERT(SSFTLSCSetALPN(s, one, 1u));
    SSF_ASSERT(SSFTLSCSetALPN(s, NULL, 1u) == false);
    SSF_ASSERT(s->alpnCount == 0u);
    SSF_ASSERT(SSFTLSCSetALPN(s, withNull, 2u) == false);
    SSF_ASSERT(SSFTLSCSetALPN(s, withEmpty, 2u) == false);
    SSF_ASSERT(SSFTLSCSetALPN(s, list256, 1u) == false);
    SSF_ASSERT(s->alpnCount == 0u);
    SSF_ASSERT(SSFTLSCSetALPN(s, listOver, 1u) == false);
    SSF_ASSERT(SSFTLSCSetALPN(s, listFill, 1u));
#if SSF_TLS_CONFIG_MAX_ALPN_LEN >= 256u
    SSF_ASSERT(SSFTLSCSetALPN(s, list255, 1u));
#else
    SSF_ASSERT(SSFTLSCSetALPN(s, list255, 1u) == false);
#endif

    /* ---- EncryptedExtensions: exactly one offered name; GetALPN returns the caller's string -- */
    SSF_ASSERT(SSFTLSCSetALPN(s, both, 2u));
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnAws, 0u, both[0]);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnMqtt, 0u, both[1]);
    SSF_TLSC_UT_EE_ALPN(s, _utEeEmpty, 0u, NULL);                    /* Server chose none */
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnPrefix, SSF_TLS_ALERT_ILLEGAL_PARAMETER, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnLonger, SSF_TLS_ALERT_ILLEGAL_PARAMETER, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnH2, SSF_TLS_ALERT_ILLEGAL_PARAMETER, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnSameLen, SSF_TLS_ALERT_ILLEGAL_PARAMETER, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnDup, SSF_TLS_ALERT_ILLEGAL_PARAMETER, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnTwo, SSF_TLS_ALERT_DECODE_ERROR, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnEmptyName, SSF_TLS_ALERT_DECODE_ERROR, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnEmptyList, SSF_TLS_ALERT_DECODE_ERROR, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnNoList, SSF_TLS_ALERT_DECODE_ERROR, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnListLen, SSF_TLS_ALERT_DECODE_ERROR, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnNameLen, SSF_TLS_ALERT_DECODE_ERROR, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnShortNm, SSF_TLS_ALERT_DECODE_ERROR, NULL);
    /* A failed parse leaves no choice behind */
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnMqtt, 0u, both[1]);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnH2, SSF_TLS_ALERT_ILLEGAL_PARAMETER, NULL);
    /* A choice made, then the handshake fails: none reported */
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnMqtt, 0u, both[1]);
    s->hsState = SSF_TLSC_HS_ERROR;
    SSF_ASSERT(SSFTLSCGetALPN(s) == NULL);
    s->hsState = SSF_TLSC_HS_IDLE;
    /* Only the second name offered */
    SSF_ASSERT(SSFTLSCSetALPN(s, one, 1u));
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnMqtt, 0u, one[0]);
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnAws, SSF_TLS_ALERT_ILLEGAL_PARAMETER, NULL);
    /* Setting a new list forgets the last connection's choice */
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnMqtt, 0u, one[0]);
    SSF_ASSERT(SSFTLSCSetALPN(s, both, 2u));
    SSF_ASSERT(SSFTLSCGetALPN(s) == NULL);
    /* None offered: an ALPN answer is unsupported_extension */
    SSF_ASSERT(SSFTLSCSetALPN(s, NULL, 0u));
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnMqtt, SSF_TLS_ALERT_UNSUPPORTED_EXT, NULL);
    SSF_TLSC_UT_EE_ALPN(s, _utEeSniAck, 0u, NULL);

    /* ---- The list survives a connection reset; the choice does not ---- */
    SSF_ASSERT(SSFTLSCSetALPN(s, both, 2u));
    SSF_TLSC_UT_EE_ALPN(s, _utEeAlpnMqtt, 0u, both[1]);
    s->transport.close(&s->transport);
    SSF_ASSERT((s->alpnProtos == both) && (s->alpnCount == 2u));
    SSF_ASSERT(s->alpnChosen == 0u);

    /* ---- Called while open: a programming error ---- */
    s->hsState = SSF_TLSC_HS_COMPLETE;
    SSF_ASSERT_TEST(SSFTLSCSetALPN(s, one, 1u));
    s->hsState = SSF_TLSC_HS_IDLE;
    SSFTLSCDeInit(s);

    /* ---- The largest ClientHello1: a 255-byte host name and a full ALPN list. Its size is   */
    /* ---- the one the SSF_TLS_CONFIG_MAX_ALPN_LEN compile-time check is built on.           */
    {
        static char host[SSF_TLSC_MAX_HOST_SIZE];
        SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;
        uint8_t k;

        memset(host, 'h', sizeof(host) - 1u); host[sizeof(host) - 1u] = 0;
        SSFTLSCInit(s, &_utFake, NULL);
        SSFTLSCSetUnauthenticated(s, true);
        SSF_ASSERT(SSFTLSCSetALPN(s, listFill, 1u));
        _utFakeInLen = _utFakeInPos = _utFakeOutLen = 0;
        SSF_ASSERT(s->transport.open(&s->transport, host, sizeof(host), 443u));
        for (k = 0; (k < 20u) && (_utFakeOutLen == 0u) && (r != SSF_NET_IO_ERROR); k++)
        { r = s->transport.pollOpen(&s->transport); }
        SSF_ASSERT(_utFakeOutLen > 0u);
        SSF_ASSERT(sizeof(s->clientHelloMsg) == SSF_TLSC_CH_SIZE);
        SSF_ASSERT(s->clientHelloLen ==
                   (SSF_TLSC_CH1_MAX_NO_ALPN + 6u + SSF_TLS_CONFIG_MAX_ALPN_LEN));
        s->transport.close(&s->transport);
        SSFTLSCDeInit(s);
    }

    /* ---- no_application_protocol is traced; the text holds whether or not ALPN was offered */
    {
        static const uint8_t alert[] = { 2u, SSF_TLS_ALERT_NO_APPLICATION_PROTOCOL };
        uint8_t buf[16];
        size_t n;

        _UTAppSession(s);
        SSFTLSCSetTrace(s, _SSFTLSCUTWarnTrace, NULL);
        _utWarn[0] = 0;
        _UTSrvRecord(SSF_TLS_CT_ALERT, alert, sizeof(alert));
        SSF_ASSERT(s->transport.recv(&s->transport, buf, sizeof(buf), &n) == SSF_NET_IO_ERROR);
        SSF_ASSERT(strstr(_utWarn, "Server requires an ALPN protocol the client did not offer "
                                   "(no_application_protocol)") != NULL);
        SSFTLSCDeInit(s);
        SSFTLSRecordStateDeInit(&_utSrvSend);
        SSFTLSRecordStateDeInit(&_utSrvRecv);
    }
    SSFTLSCInit(s, &_utSock.transport, NULL);
    s->hsState = SSF_TLSC_HS_IDLE;
    SSFTLSCDeInit(s);
    SSF_ASSERT_TEST(SSFTLSCGetALPN(s));
}

/* --------------------------------------------------------------------------------------------- */
/* Item 6 on the wire: a ClientHello to a literal IP address carries no server_name.            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFTLSCUTNoSniForIP(SSFTLSCUTFd_t l, uint16_t port)
{
    SSFNetTransport_t *t = &_utSession.transport;
    static uint8_t chRec[1024];
    SSFTLSCUTClientHello_t ch;
    SSFTLSCUTFd_t peer = SSF_TLSC_UT_INVALID;
    size_t n;

    SSF_ASSERT(t->open(t, "127.0.0.1", sizeof("127.0.0.1"), port));
    (void)_SSFTLSCUTPollUntilClientHello(l, &peer);
    SSF_ASSERT(peer != SSF_TLSC_UT_INVALID);
    n = _SSFTLSCUTRecvRecord(peer, chRec, sizeof(chRec));
    _SSFTLSCUTParseClientHello(chRec, n, &ch);
    SSF_ASSERT(_SSFTLSCUTFindExt(&ch, SSF_TLS_EXT_SERVER_NAME) < 0);
    SSF_ASSERT(_SSFTLSCUTFindExt(&ch, SSF_TLS_EXT_ALPN) < 0);        /* None set: not offered */
    SSF_ASSERT(_SSFTLSCUTFindExt(&ch, SSF_TLS_EXT_KEY_SHARE) >= 0);   /* Otherwise intact */
    t->close(t);
    (void)SSF_TLSC_UT_CLOSE(peer);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs the ssftlsc unit test.                                                               */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSCUnitTest(void)
{
    SSFNetTransport_t *t = &_utSession.transport;
    static SSFTLSCUTFd_t l;           /* static: survives SSF_ASSERT_TEST's longjmp */
    static SSFTLSCUTFd_t peer;
    uint16_t port;
    uint16_t deadPort;
    uint8_t buf[512];
    size_t n;
    SSFNetIOResult_t r;

    _SSFTLSCUTParseCertificate();
    _SSFTLSCUTParseCertificateVerify();
    _SSFTLSCUTParseEncryptedExtensions();
    _SSFTLSCUTParseCertificateRequest();
    _SSFTLSCUTPostHandshake();
    _SSFTLSCUTAppData();
    _SSFTLSCUTIPLiteral();
    _SSFTLSCUTSchemeMatchesKey();
    _SSFTLSCUTSaveLeafKey();
    _SSFTLSCUTChainAlert();

    /* ---- Init: the session is a transport over ssfnetsock ---- */
    SSFNetSockInit(&_utSock);                 /* Also starts Winsock for the listener below */
    SSFTLSCInit(&_utSession, &_utSock.transport, NULL);
    SSF_ASSERT((void *)t == (void *)&_utSession);
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_IDLE);
    SSF_ASSERT(t->pollOpen(t) == SSF_NET_IO_ERROR);           /* Not opened */
    SSF_ASSERT(t->send(t, buf, 1, &n) == SSF_NET_IO_ERROR);   /* Not connected */
    SSF_ASSERT(t->recv(t, buf, sizeof(buf), &n) == SSF_NET_IO_ERROR);
    SSF_ASSERT(t->shutdown(t) == SSF_NET_IO_ERROR);           /* Not connected */
    t->close(t);                                              /* Close when idle is harmless */
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_IDLE);
    SSF_ASSERT_TEST(SSFTLSCInit(&_utSession, &_utSock.transport, NULL)); /* Already inited */
    {
        SSFNetTransport_t noShutdown = _utSock.transport;     /* shutdown() is passed through */

        noShutdown.shutdown = NULL;
        SSF_ASSERT_TEST(SSFTLSCInit(&_utSession2, &noShutdown, NULL));
    }

    /* ---- Rejected arguments ---- */
    l = _SSFTLSCUTListen(&port);
    SSF_ASSERT(t->open(t, "", 1, port) == false);
    SSF_ASSERT(t->open(t, "127.0.0.1", sizeof("127.0.0.1"), 0) == false);
    SSF_ASSERT(t->open(t, "127.0.0.1", 4, port) == false);    /* Not terminated within size */
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_IDLE);

    /* ---- Fail closed: with no trust anchors open() refuses and nothing is sent, not ---- */
    /* ---- even a ClientHello (which would disclose the host name in SNI)             ---- */
    SSF_ASSERT(t->open(t, "localhost", sizeof("localhost"), port) == false);
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_IDLE);
    SSF_ASSERT(_SSFTLSCUTConnectArrives(l) == false);
    t->close(t);
    {
        SSFTLSCTrustStore_t empty = { NULL, NULL, 0 };         /* Non-NULL store, no anchors */
        SSFNetTransport_t *t2 = &_utSession2.transport;

        SSFTLSCInit(&_utSession2, &_utSock.transport, &empty);
        SSF_ASSERT(t2->open(t2, "localhost", sizeof("localhost"), port) == false);
        SSF_ASSERT(_SSFTLSCUTConnectArrives(l) == false);
        SSFTLSCDeInit(&_utSession2);
    }
    _SSFTLSCUTClientCert();
    _SSFTLSCUTClientChain();
    _SSFTLSCUTAlpn();

    /* ---- Explicit opt-in to an unauthenticated connection, and back out ---- */
    SSFTLSCSetUnauthenticated(&_utSession, true);
    SSFTLSCSetUnauthenticated(&_utSession, false);
    SSF_ASSERT(t->open(t, "localhost", sizeof("localhost"), port) == false);
    SSF_ASSERT(_SSFTLSCUTConnectArrives(l) == false);
    SSFTLSCSetUnauthenticated(&_utSession, true);              /* For the transport tests below */

    /* ---- IPv4 only (ssfnet.h): an IPv6 literal is refused before any connection is made ---- */
    SSF_ASSERT(t->open(t, "::1", sizeof("::1"), port) == false);
    SSF_ASSERT(t->open(t, "fe80::1%eth0", sizeof("fe80::1%eth0"), port) == false);
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_IDLE);
    SSF_ASSERT(_SSFTLSCUTConnectArrives(l) == false);

    /* ---- Refused TCP connect ends in ERROR or CLOSED, and the session reopens ---- */
    deadPort = 0;
    {
        SSFTLSCUTFd_t d = _SSFTLSCUTListen(&deadPort);
        (void)SSF_TLSC_UT_CLOSE(d);
    }
    peer = SSF_TLSC_UT_INVALID;
    if (t->open(t, "127.0.0.1", sizeof("127.0.0.1"), deadPort))
    {
        r = _SSFTLSCUTPoll(SSF_TLSC_UT_INVALID, &peer, SSF_TLSC_UT_WAIT_TICKS);
        SSF_ASSERT((r == SSF_NET_IO_ERROR) || (r == SSF_NET_IO_CLOSED));
        SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_ERROR);
        SSF_ASSERT_TEST(t->open(t, "127.0.0.1", sizeof("127.0.0.1"), port)); /* Not closed */
        SSF_ASSERT_TEST(SSFTLSCSetUnauthenticated(&_utSession, false));     /* Only when idle */
        t->close(t);
    }
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_IDLE);

    /* ---- The handshake starts with a ClientHello record carrying SNI; a peer that ---- */
    /* ---- hangs up ends it with CLOSED                                               ---- */
    SSF_ASSERT(t->open(t, "localhost", sizeof("localhost"), port));
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_SEND_CH);
    peer = SSF_TLSC_UT_INVALID;
    r = _SSFTLSCUTPollUntilClientHello(l, &peer);
    SSF_ASSERT((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE));
    SSF_ASSERT(peer != SSF_TLSC_UT_INVALID);
    {
        int got = recv(peer, (char *)buf, (int)sizeof(buf), 0);
        size_t i;
        bool hasSni = false;

        SSF_ASSERT(got >= 9);
        SSF_ASSERT(buf[0] == SSF_TLS_CT_HANDSHAKE);           /* Record: handshake */
        SSF_ASSERT((buf[1] == 0x03u) && (buf[2] == 0x03u));   /* legacy_record_version */
        SSF_ASSERT(buf[5] == SSF_TLS_HS_CLIENT_HELLO);
        for (i = 0; (i + sizeof("localhost") - 1u) <= (size_t)got; i++)
        { if (memcmp(&buf[i], "localhost", sizeof("localhost") - 1u) == 0) hasSni = true; }
        SSF_ASSERT(hasSni);
    }
    (void)SSF_TLSC_UT_CLOSE(peer);
    peer = SSF_TLSC_UT_INVALID;
    r = _SSFTLSCUTPoll(SSF_TLSC_UT_INVALID, &peer, SSF_TLSC_UT_WAIT_TICKS);
    SSF_ASSERT(r == SSF_NET_IO_CLOSED);
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_ERROR);
    /* A failed connection wipes its secrets at once, before close(): here the ephemeral       */
    /* ClientHello keys, which were live when the peer hung up.                                 */
    SSF_ASSERT(_SSFTLSCUTIsZero(_utSession.ephemeralPrivKey, sizeof(_utSession.ephemeralPrivKey)));
    SSF_ASSERT(_utSession.sendStateInited == false);
    SSF_ASSERT(_utSession.recvStateInited == false);
    SSF_ASSERT(t->send(t, buf, 1, &n) == SSF_NET_IO_ERROR);
    t->close(t);

    /* ---- close() mid-handshake sends user_canceled, then close_notify (RFC 8446 6.1), ---- */
    /* ---- both warning level; plaintext here, since no keys exist before ServerHello   ---- */
    SSF_ASSERT(t->open(t, "localhost", sizeof("localhost"), port));
    peer = SSF_TLSC_UT_INVALID;
    r = _SSFTLSCUTPollUntilClientHello(l, &peer);
    SSF_ASSERT((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE));
    SSF_ASSERT(peer != SSF_TLSC_UT_INVALID);
    SSF_ASSERT(_SSFTLSCUTRecvRecord(peer, buf, sizeof(buf)) > 5u);
    SSF_ASSERT(buf[0] == SSF_TLS_CT_HANDSHAKE);
    SSF_ASSERT(_SSFTLSCUTRecvRecord(peer, buf, sizeof(buf)) == 6u);
    SSF_ASSERT(buf[0] == SSF_TLS_CT_CHANGE_CIPHER);
    t->close(t);
    {
        static const uint8_t canceled[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x5a };
        static const uint8_t closeNotify[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00 };

        SSF_ASSERT(_SSFTLSCUTRecvRecord(peer, buf, sizeof(buf)) == sizeof(canceled));
        SSF_ASSERT(memcmp(buf, canceled, sizeof(canceled)) == 0);
        SSF_ASSERT(_SSFTLSCUTRecvRecord(peer, buf, sizeof(buf)) == sizeof(closeNotify));
        SSF_ASSERT(memcmp(buf, closeNotify, sizeof(closeNotify)) == 0);
        SSF_ASSERT(_SSFTLSCUTRecvRecord(peer, buf, sizeof(buf)) == 0u);   /* Then EOF */
    }
    (void)SSF_TLSC_UT_CLOSE(peer);

    /* ---- HelloRetryRequest: ClientHello2 rules ---- */
    _SSFTLSCUTClientHelloRetry(l, port);

    /* ---- No SNI for a literal IP address ---- */
    _SSFTLSCUTNoSniForIP(l, port);

    /* ---- Handshake messages spanning records ---- */
    _SSFTLSCUTFragmentedHandshake(l, port);

    /* ---- A peer that answers with something other than TLS ends the handshake with ERROR ---- */
    SSF_ASSERT(t->open(t, "localhost", sizeof("localhost"), port));
    peer = SSF_TLSC_UT_INVALID;
    r = _SSFTLSCUTPollUntilClientHello(l, &peer);
    SSF_ASSERT((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE));
    SSF_ASSERT(peer != SSF_TLSC_UT_INVALID);
    (void)recv(peer, (char *)buf, (int)sizeof(buf), 0);
    {
        static const char http[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
        SSF_ASSERT(send(peer, http, (int)(sizeof(http) - 1u), 0) == (int)(sizeof(http) - 1u));
    }
    r = _SSFTLSCUTPoll(SSF_TLSC_UT_INVALID, &peer, SSF_TLSC_UT_WAIT_TICKS);
    SSF_ASSERT(r == SSF_NET_IO_ERROR);
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_ERROR);
    /* RFC 8446 6: the abort is announced with a fatal unexpected_message alert, in plaintext    */
    /* since no keys exist yet: record 21, legacy version, length 2, level fatal(2), desc 10.    */
    {
        static const uint8_t alert[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x0a };
        uint8_t got[sizeof(alert)];
        size_t have = 0;
        SSFPortTick_t end = SSFPortGetTick64() + SSF_TLSC_UT_WAIT_TICKS;

        while ((have < sizeof(alert)) && (SSFPortGetTick64() < end))
        {
            int n;

            if (!_SSFTLSCUTReadable(peer)) continue;
            n = recv(peer, (char *)&got[have], (int)(sizeof(got) - have), 0);
            if (n <= 0) break;
            have += (size_t)n;
        }
        SSF_ASSERT(have == sizeof(alert));
        SSF_ASSERT(memcmp(got, alert, sizeof(alert)) == 0);
    }
    t->close(t);
    (void)SSF_TLSC_UT_CLOSE(peer);

    /* ---- DeInit ---- */
    (void)SSF_TLSC_UT_CLOSE(l);
    SSFTLSCDeInit(&_utSession);
    SSF_ASSERT(_utSession.magic == 0);
    SSF_ASSERT_TEST(SSFTLSCDeInit(&_utSession));              /* Not initialized */
    SSFNetSockDeInit(&_utSock);
}
#endif /* SSF_CONFIG_TLSC_UNIT_TEST */
