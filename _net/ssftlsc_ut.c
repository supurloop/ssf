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
    const uint8_t *_d[SSF_TLS_CONFIG_MAX_CHAIN_DEPTH]; \
    uint32_t _l[SSF_TLS_CONFIG_MAX_CHAIN_DEPTH]; \
    uint8_t _n = 0xffu; \
    SSF_ASSERT(_SSFTLSCParseCertificateForTest((body), sizeof(body), _d, _l, &_n)); \
    SSF_ASSERT(_n == (count)); } while (0)
#define SSF_TLSC_UT_CERT_BAD(body) do { \
    const uint8_t *_d[SSF_TLS_CONFIG_MAX_CHAIN_DEPTH]; \
    uint32_t _l[SSF_TLS_CONFIG_MAX_CHAIN_DEPTH]; \
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
    const uint8_t *d[SSF_TLS_CONFIG_MAX_CHAIN_DEPTH];
    uint32_t l[SSF_TLS_CONFIG_MAX_CHAIN_DEPTH];
    uint8_t n;
    uint8_t many[4u + ((SSF_TLS_CONFIG_MAX_CHAIN_DEPTH + 1u) * 6u)];
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

    /* More certificates than SSF_TLS_CONFIG_MAX_CHAIN_DEPTH: the first ones are kept, but every */
    /* entry is still validated                                                                  */
    manyLen = _SSFTLSCUTCertN(many, sizeof(many), SSF_TLS_CONFIG_MAX_CHAIN_DEPTH + 1u, 0u);
    SSF_ASSERT(_SSFTLSCParseCertificateForTest(many, manyLen, d, l, &n));
    SSF_ASSERT(n == SSF_TLS_CONFIG_MAX_CHAIN_DEPTH);
    SSF_ASSERT((d[0] == &many[7]) && (l[0] == 1u));
    manyLen = _SSFTLSCUTCertN(many, sizeof(many), SSF_TLS_CONFIG_MAX_CHAIN_DEPTH + 1u, 1u);
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
    SSF_TLSC_UT_EE(_utEeRsl, SSF_TLS_ALERT_UNSUPPORTED_EXT);
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

    /* ---- Init: the session is a transport over ssfnetsock ---- */
    SSFNetSockInit(&_utSock);                 /* Also starts Winsock for the listener below */
    SSFTLSCInit(&_utSession, &_utSock.transport, NULL);
    SSF_ASSERT((void *)t == (void *)&_utSession);
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_IDLE);
    SSF_ASSERT(t->pollOpen(t) == SSF_NET_IO_ERROR);           /* Not opened */
    SSF_ASSERT(t->send(t, buf, 1, &n) == SSF_NET_IO_ERROR);   /* Not connected */
    SSF_ASSERT(t->recv(t, buf, sizeof(buf), &n) == SSF_NET_IO_ERROR);
    t->close(t);                                              /* Close when idle is harmless */
    SSF_ASSERT(SSFTLSCGetHandshakeState(&_utSession) == SSF_TLSC_HS_IDLE);
    SSF_ASSERT_TEST(SSFTLSCInit(&_utSession, &_utSock.transport, NULL)); /* Already inited */

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

    /* ---- Explicit opt-in to an unauthenticated connection, and back out ---- */
    SSFTLSCSetUnauthenticated(&_utSession, true);
    SSFTLSCSetUnauthenticated(&_utSession, false);
    SSF_ASSERT(t->open(t, "localhost", sizeof("localhost"), port) == false);
    SSF_ASSERT(_SSFTLSCUTConnectArrives(l) == false);
    SSFTLSCSetUnauthenticated(&_utSession, true);              /* For the transport tests below */

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
