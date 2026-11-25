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
#include <stdlib.h>
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
#include "ssfbase64.h"
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

/* True if a protected record of len bytes (header included) fits this build's receive buffer, */
/* which takes a TLSInnerPlaintext of SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1 plus the tag. Tests   */
/* that need larger records or messages skip themselves in smaller receive builds.             */
#define SSF_TLSC_UT_RECORD_FITS(len) \
    (((size_t)(len) - 5u) <= ((size_t)SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u + SSF_TLS_AEAD_TAG_SIZE))

/* True if len bytes fit this build's reassembly buffer (hsBuf, SSF_TLSC_CONFIG_MAX_RECV_RECORD */
/* + 1): what a plaintext record's content (before keys) and any handshake message, however   */
/* split into records, must fit.                                                               */
#define SSF_TLSC_UT_PLAIN_FITS(len) ((size_t)(len) <= ((size_t)SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u))

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

    /* The HelloRetryRequests below are plaintext records of at least 4 + 2 + 32 + 1 + 32 (session */
    /* id) + 2 + 1 + 2 + 6 (supported_versions) + 6 (key_share) + 6 + 16 (cookie) = 110 bytes   */
    if (!SSF_TLSC_UT_PLAIN_FITS(110u)) return;

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

    /* ---- A cookie making ClientHello2 exactly SSF_TLSC_CH_SIZE bytes: sent in one record, ---- */
    /* ---- which every allowed SSF_TLSC_CONFIG_MAX_SEND_RECORD holds; one byte more aborts   ---- */
    {
        uint8_t k;

        for (k = 0; k < 2u; k++)
        {
            SSFPortTick_t end;
            SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;
            size_t ch1Len;
            size_t cookieLen;

            peer = _SSFTLSCUTRunToClientHello(l, port, ch1Rec, sizeof(ch1Rec), &ch1);
            /* ClientHello2 = ClientHello1 - x25519 (4 + 32) - secp384r1 (4 + 97) shares        */
            /* + secp256r1 (4 + 65) + cookie extension (4 + 2 + cookieLen)                       */
            ch1Len = ((size_t)ch1Rec[3] << 8) | ch1Rec[4];
            cookieLen = SSF_TLSC_CH_SIZE + 62u - ch1Len + k;
            hrrLen = _SSFTLSCUTBuildHrr(hrrRec, sizeof(hrrRec), &ch1, SSF_TLS_CS_AES_128_GCM_SHA256,
                                        cookieLen);
            if ((hrrLen - 5u) > SSF_TLSC_CONFIG_MAX_RECV_RECORD)
            {
                /* A receive size this small cannot take a HelloRetryRequest with such a cookie */
                t->close(t);
                (void)SSF_TLSC_UT_CLOSE(peer);
                continue;
            }
            SSF_ASSERT(send(peer, (const char *)hrrRec, (int)hrrLen, 0) == (int)hrrLen);
            end = SSFPortGetTick64() + SSF_TLSC_UT_WAIT_TICKS;
            n = 0;
            while ((n == 0u) && (r != SSF_NET_IO_ERROR) && (SSFPortGetTick64() < end))
            {
                r = t->pollOpen(t);
                if (_SSFTLSCUTReadable(peer)) n = _SSFTLSCUTRecvRecord(peer, ch2Rec, sizeof(ch2Rec));
            }
            if (n == 0u) n = _SSFTLSCUTRecvRecord(peer, ch2Rec, sizeof(ch2Rec));
            if (k == 0u)
            {
                SSF_ASSERT(n == (5u + SSF_TLSC_CH_SIZE));                 /* One whole record */
                _SSFTLSCUTParseClientHello(ch2Rec, n, &ch2);
                ck = _SSFTLSCUTFindExt(&ch2, 44u);
                SSF_ASSERT((ck >= 0) && (ch2.extLen[ck] == (2u + cookieLen)));
            }
            else
            {
                SSF_ASSERT((n == 7u) && (ch2Rec[0] == SSF_TLS_CT_ALERT) &&
                           (ch2Rec[6] == SSF_TLS_ALERT_INTERNAL_ERROR));
            }
            t->close(t);
            (void)SSF_TLSC_UT_CLOSE(peer);
        }
    }

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

    /* The first four cases send a HelloRetryRequest without a cookie, a message of 4 + 2 + 32 */
    /* + 1 + 32 + 2 + 1 + 2 + 6 + 6 = 88 bytes, which must fit hsBuf whole however split; the  */
    /* fourth adds an empty Certificate header to its record: 92 bytes of plaintext            */
    if (SSF_TLSC_UT_PLAIN_FITS(92u))
    {
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
    SSF_ASSERT(_utSession2.hsScratchLen == 65u);
    SSF_ASSERT(_utSession2.hsScratch.leafPubKey[0] == 0x04u);

    /* A key larger than hsScratch.leafPubKey is refused, not truncated */
    memset(&_utSession2, 0, sizeof(_utSession2));
    SSF_ASSERT(_SSFTLSCSaveLeafKeyForTest(&_utSession2, _utLeafRsa8192Der,
                                          (uint32_t)sizeof(_utLeafRsa8192Der)) == false);
    SSF_ASSERT(_utSession2.hsScratchLen == 0u);

    /* Not a certificate: truncated, and with its outer tag damaged */
    SSF_ASSERT(_SSFTLSCSaveLeafKeyForTest(&_utSession2, _utLeafP256Der,
                                          (uint32_t)sizeof(_utLeafP256Der) - 1u) == false);
    memcpy(bad, _utLeafP256Der, sizeof(bad));
    bad[0] = 0x31u;
    SSF_ASSERT(_SSFTLSCSaveLeafKeyForTest(&_utSession2, bad, (uint32_t)sizeof(bad)) == false);
    SSF_ASSERT(_utSession2.hsScratchLen == 0u);
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
static uint8_t _utFakeIn[16512];      /* Room for a 2^14 + 18 byte record */
static size_t _utFakeInLen;
static size_t _utFakeInPos;
static uint8_t _utFakeOut[4096];
static size_t _utFakeOutLen;
static bool _UTFakeOpen(SSFNetTransport_t *t, SSFCStrIn_t h, size_t hs, uint16_t p)
{ (void)t; (void)h; (void)hs; (void)p; return true; }
static SSFNetIOResult_t _UTFakePollOpen(SSFNetTransport_t *t)
{ (void)t; return SSF_NET_IO_SUCCESS; }
/* When set, send() takes at most this many bytes, and every other call wants to write again */
static size_t _utFakeSendCap;
static bool _utFakeSendStall;
static SSFNetIOResult_t _UTFakeSend(SSFNetTransport_t *t, const uint8_t *b, size_t n, size_t *sent)
{
    (void)t;
    *sent = 0;
    if (_utFakeSendCap != 0u)
    {
        _utFakeSendStall = !_utFakeSendStall;
        if (_utFakeSendStall) return SSF_NET_IO_WANT_WRITE;
        if (n > _utFakeSendCap) n = _utFakeSendCap;
    }
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
        /* One plaintext record holds it: header, then the whole message */
        SSF_ASSERT((_utFakeOut[0] == SSF_TLS_CT_HANDSHAKE) &&
                   ((((size_t)_utFakeOut[3] << 8) | _utFakeOut[4]) == s->hsScratchLen) &&
                   (_utFakeOutLen >= (5u + s->hsScratchLen)));
        SSF_ASSERT(sizeof(s->hsScratch.clientHello) == SSF_TLSC_CH_SIZE);
        SSF_ASSERT(s->hsScratchLen ==
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
/* Plaintext record length (RFC 8446 5.1): over 2^14 bytes is the server's record_overflow at   */
/* every receive size; within 2^14 but over this build's buffer, internal_error. Over the fake  */
/* transport: the ClientHello goes out, then a plaintext handshake record of len bytes arrives. */
/* --------------------------------------------------------------------------------------------- */
/* Returns the alert the client sends, mid-handshake (no keys yet), for a record of type ct and */
/* len zero bytes (a handshake record starts like a ServerHello).                               */
static uint8_t _UTPreKeyRecordAlert(uint8_t ct, size_t len)
{
    SSFTLSCSession_t *s = &_utSession2;
    SSFNetTransport_t *t = &s->transport;
    SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;
    uint16_t k;
    uint8_t alert;

    SSF_ASSERT((5u + len) <= sizeof(_utFakeIn));
    SSFTLSCInit(s, &_utFake, NULL);
    SSFTLSCSetUnauthenticated(s, true);
    _utFakeInLen = _utFakeInPos = _utFakeOutLen = 0;
    SSF_ASSERT(t->open(t, "localhost", sizeof("localhost"), 443u));
    for (k = 0; (k < 20u) && (_utFakeOutLen == 0u); k++) (void)t->pollOpen(t);
    SSF_ASSERT(_utFakeOutLen > 0u);                            /* ClientHello sent */
    memset(_utFakeIn, 0, 5u + len);
    _utFakeIn[0] = ct; _utFakeIn[1] = 0x03; _utFakeIn[2] = 0x03;
    _utFakeIn[3] = (uint8_t)(len >> 8); _utFakeIn[4] = (uint8_t)len;
    if (ct == SSF_TLS_CT_HANDSHAKE) _utFakeIn[5] = SSF_TLS_HS_SERVER_HELLO;
    _utFakeInLen = 5u + len;
    for (k = 0; (k < 100u) && ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)); k++)
    {
        _utFakeOutLen = 0;
        r = t->pollOpen(t);
    }
    SSF_ASSERT(r == SSF_NET_IO_ERROR);
    /* The fatal alert, in plaintext: no keys yet */
    SSF_ASSERT((_utFakeOutLen == 7u) && (_utFakeOut[0] == SSF_TLS_CT_ALERT) &&
               (_utFakeOut[5] == 2u));
    alert = _utFakeOut[6];
    t->close(t);
    SSFTLSCDeInit(s);
    return alert;
}

/* Returns the alert the client sends for a plaintext handshake record of len bytes. */
static uint8_t _UTPlainRecordAlert(size_t len)
{
    return _UTPreKeyRecordAlert(SSF_TLS_CT_HANDSHAKE, len);
}

/* Returns the alert recv() sets on a connected session for a record of type ct, len bytes. */
static uint8_t _UTAppRecordAlert(uint8_t ct, size_t len)
{
    SSFTLSCSession_t *s = &_utSession2;
    uint8_t buf[16];
    size_t n;
    uint8_t alert;

    SSF_ASSERT((5u + len) <= sizeof(_utFakeIn));
    _UTAppSession(s);
    memset(_utFakeIn, 0, 5u + len);
    _utFakeIn[0] = ct; _utFakeIn[1] = 0x03; _utFakeIn[2] = 0x03;
    _utFakeIn[3] = (uint8_t)(len >> 8); _utFakeIn[4] = (uint8_t)len;
    if ((ct == SSF_TLS_CT_CHANGE_CIPHER) && (len > 0u)) _utFakeIn[5] = 0x01u;
    _utFakeInLen = 5u + len;
    SSF_ASSERT(s->transport.recv(&s->transport, buf, sizeof(buf), &n) == SSF_NET_IO_ERROR);
    alert = s->pendingAlert;
    SSFTLSCDeInit(s);
    SSFTLSRecordStateDeInit(&_utSrvSend);
    SSFTLSRecordStateDeInit(&_utSrvRecv);
    return alert;
}

/* A record whose type is wrong for the moment is unexpected_message whatever its length: the  */
/* type is judged at the header, before the size, so it is never blamed on this build's buffer */
/* (internal_error) or answered as an overflow.                                                 */
static void _SSFTLSCUTRecordTypeFirst(void)
{
    size_t lens[4];
    uint8_t nLens = 3u;
    uint8_t i;

    lens[0] = 2u;
    lens[1] = 100u;
    lens[2] = 16384u + 2u + SSF_TLS_AEAD_TAG_SIZE;                 /* Over every maximum */
    if ((SSF_TLSC_CONFIG_MAX_RECV_RECORD + 2u + SSF_TLS_AEAD_TAG_SIZE) <
        (16384u + 2u + SSF_TLS_AEAD_TAG_SIZE))
    {
        lens[nLens++] = SSF_TLSC_CONFIG_MAX_RECV_RECORD + 2u + SSF_TLS_AEAD_TAG_SIZE;
    }
    for (i = 0; i < nLens; i++)
    {
        /* No keys yet: application_data cannot be decrypted; change_cipher_spec is 1 byte */
        SSF_ASSERT(_UTPreKeyRecordAlert(SSF_TLS_CT_APPLICATION, lens[i]) ==
                   SSF_TLS_ALERT_UNEXPECTED_MSG);
        SSF_ASSERT(_UTPreKeyRecordAlert(SSF_TLS_CT_CHANGE_CIPHER, lens[i]) ==
                   SSF_TLS_ALERT_UNEXPECTED_MSG);
        /* Keys active: every record is protected; after the handshake no change_cipher_spec */
        SSF_ASSERT(_UTAppRecordAlert(SSF_TLS_CT_HANDSHAKE, lens[i]) ==
                   SSF_TLS_ALERT_UNEXPECTED_MSG);
        SSF_ASSERT(_UTAppRecordAlert(SSF_TLS_CT_ALERT, lens[i]) == SSF_TLS_ALERT_UNEXPECTED_MSG);
        SSF_ASSERT(_UTAppRecordAlert(SSF_TLS_CT_CHANGE_CIPHER, lens[i]) ==
                   SSF_TLS_ALERT_UNEXPECTED_MSG);
    }
    SSF_ASSERT(_UTAppRecordAlert(SSF_TLS_CT_CHANGE_CIPHER, 1u) == SSF_TLS_ALERT_UNEXPECTED_MSG);
    /* A one-byte change_cipher_spec during the handshake must be 0x01 */
    SSF_ASSERT(_UTPreKeyRecordAlert(SSF_TLS_CT_CHANGE_CIPHER, 1u) ==
               SSF_TLS_ALERT_UNEXPECTED_MSG);
}

/* --------------------------------------------------------------------------------------------- */
/* RFC 8448 3, Simple 1-RTT Handshake, replayed over the fake transport. The ClientHello and the */
/* client's x25519 key are injected (the client's own ClientHello differs: other extensions, a  */
/* P-384 share), so the transcript, and every secret and record after it, must match the RFC    */
/* byte for byte. The server's RSA-1024 certificate is not chain-verified (unauthenticated      */
/* mode: no trust anchors); its CertificateVerify is verified, and both Finished cover it.     */
/* --------------------------------------------------------------------------------------------- */
/* RFC 8448 3 (Simple 1-RTT Handshake), extracted from the RFC text by script and checked
   against an independent model (x25519, HKDF, AES-128-GCM) before use. */
/* client ephemeral x25519 private key (RFC 8448 3: {client} create an ephemeral x25519 key pair) */
static const uint8_t _utR8ClientPriv[32] = {
    0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2,
    0x78, 0x4b, 0xcb, 0xca, 0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42,
    0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05
};
/* ClientHello handshake message (RFC 8448 3: {client} construct a ClientHello handshake message) */
static const uint8_t _utR8ClientHello[196] = {
    0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81,
    0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2,
    0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d,
    0xec, 0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01,
    0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06,
    0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
    0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00,
    0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e,
    0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae,
    0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00,
    0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03,
    0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
    0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02,
    0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c,
    0x00, 0x02, 0x40, 0x01
};
/* server ServerHello record (RFC 8448 3: {server} send handshake record) */
static const uint8_t _utR8ShRecord[95] = {
    0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6,
    0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e, 0x60, 0x24, 0x9c,
    0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1,
    0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13, 0x01, 0x00, 0x00,
    0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88,
    0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72,
    0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1,
    0xb0, 0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
};
/* server EE, Certificate, CertificateVerify, Finished (protected) (RFC 8448 3: {server} send handshake record) */
static const uint8_t _utR8FlightRecord[679] = {
    0x17, 0x03, 0x03, 0x02, 0xa2, 0xd1, 0xff, 0x33, 0x4a, 0x56, 0xf5, 0xbf,
    0xf6, 0x59, 0x4a, 0x07, 0xcc, 0x87, 0xb5, 0x80, 0x23, 0x3f, 0x50, 0x0f,
    0x45, 0xe4, 0x89, 0xe7, 0xf3, 0x3a, 0xf3, 0x5e, 0xdf, 0x78, 0x69, 0xfc,
    0xf4, 0x0a, 0xa4, 0x0a, 0xa2, 0xb8, 0xea, 0x73, 0xf8, 0x48, 0xa7, 0xca,
    0x07, 0x61, 0x2e, 0xf9, 0xf9, 0x45, 0xcb, 0x96, 0x0b, 0x40, 0x68, 0x90,
    0x51, 0x23, 0xea, 0x78, 0xb1, 0x11, 0xb4, 0x29, 0xba, 0x91, 0x91, 0xcd,
    0x05, 0xd2, 0xa3, 0x89, 0x28, 0x0f, 0x52, 0x61, 0x34, 0xaa, 0xdc, 0x7f,
    0xc7, 0x8c, 0x4b, 0x72, 0x9d, 0xf8, 0x28, 0xb5, 0xec, 0xf7, 0xb1, 0x3b,
    0xd9, 0xae, 0xfb, 0x0e, 0x57, 0xf2, 0x71, 0x58, 0x5b, 0x8e, 0xa9, 0xbb,
    0x35, 0x5c, 0x7c, 0x79, 0x02, 0x07, 0x16, 0xcf, 0xb9, 0xb1, 0x18, 0x3e,
    0xf3, 0xab, 0x20, 0xe3, 0x7d, 0x57, 0xa6, 0xb9, 0xd7, 0x47, 0x76, 0x09,
    0xae, 0xe6, 0xe1, 0x22, 0xa4, 0xcf, 0x51, 0x42, 0x73, 0x25, 0x25, 0x0c,
    0x7d, 0x0e, 0x50, 0x92, 0x89, 0x44, 0x4c, 0x9b, 0x3a, 0x64, 0x8f, 0x1d,
    0x71, 0x03, 0x5d, 0x2e, 0xd6, 0x5b, 0x0e, 0x3c, 0xdd, 0x0c, 0xba, 0xe8,
    0xbf, 0x2d, 0x0b, 0x22, 0x78, 0x12, 0xcb, 0xb3, 0x60, 0x98, 0x72, 0x55,
    0xcc, 0x74, 0x41, 0x10, 0xc4, 0x53, 0xba, 0xa4, 0xfc, 0xd6, 0x10, 0x92,
    0x8d, 0x80, 0x98, 0x10, 0xe4, 0xb7, 0xed, 0x1a, 0x8f, 0xd9, 0x91, 0xf0,
    0x6a, 0xa6, 0x24, 0x82, 0x04, 0x79, 0x7e, 0x36, 0xa6, 0xa7, 0x3b, 0x70,
    0xa2, 0x55, 0x9c, 0x09, 0xea, 0xd6, 0x86, 0x94, 0x5b, 0xa2, 0x46, 0xab,
    0x66, 0xe5, 0xed, 0xd8, 0x04, 0x4b, 0x4c, 0x6d, 0xe3, 0xfc, 0xf2, 0xa8,
    0x94, 0x41, 0xac, 0x66, 0x27, 0x2f, 0xd8, 0xfb, 0x33, 0x0e, 0xf8, 0x19,
    0x05, 0x79, 0xb3, 0x68, 0x45, 0x96, 0xc9, 0x60, 0xbd, 0x59, 0x6e, 0xea,
    0x52, 0x0a, 0x56, 0xa8, 0xd6, 0x50, 0xf5, 0x63, 0xaa, 0xd2, 0x74, 0x09,
    0x96, 0x0d, 0xca, 0x63, 0xd3, 0xe6, 0x88, 0x61, 0x1e, 0xa5, 0xe2, 0x2f,
    0x44, 0x15, 0xcf, 0x95, 0x38, 0xd5, 0x1a, 0x20, 0x0c, 0x27, 0x03, 0x42,
    0x72, 0x96, 0x8a, 0x26, 0x4e, 0xd6, 0x54, 0x0c, 0x84, 0x83, 0x8d, 0x89,
    0xf7, 0x2c, 0x24, 0x46, 0x1a, 0xad, 0x6d, 0x26, 0xf5, 0x9e, 0xca, 0xba,
    0x9a, 0xcb, 0xbb, 0x31, 0x7b, 0x66, 0xd9, 0x02, 0xf4, 0xf2, 0x92, 0xa3,
    0x6a, 0xc1, 0xb6, 0x39, 0xc6, 0x37, 0xce, 0x34, 0x31, 0x17, 0xb6, 0x59,
    0x62, 0x22, 0x45, 0x31, 0x7b, 0x49, 0xee, 0xda, 0x0c, 0x62, 0x58, 0xf1,
    0x00, 0xd7, 0xd9, 0x61, 0xff, 0xb1, 0x38, 0x64, 0x7e, 0x92, 0xea, 0x33,
    0x0f, 0xae, 0xea, 0x6d, 0xfa, 0x31, 0xc7, 0xa8, 0x4d, 0xc3, 0xbd, 0x7e,
    0x1b, 0x7a, 0x6c, 0x71, 0x78, 0xaf, 0x36, 0x87, 0x90, 0x18, 0xe3, 0xf2,
    0x52, 0x10, 0x7f, 0x24, 0x3d, 0x24, 0x3d, 0xc7, 0x33, 0x9d, 0x56, 0x84,
    0xc8, 0xb0, 0x37, 0x8b, 0xf3, 0x02, 0x44, 0xda, 0x8c, 0x87, 0xc8, 0x43,
    0xf5, 0xe5, 0x6e, 0xb4, 0xc5, 0xe8, 0x28, 0x0a, 0x2b, 0x48, 0x05, 0x2c,
    0xf9, 0x3b, 0x16, 0x49, 0x9a, 0x66, 0xdb, 0x7c, 0xca, 0x71, 0xe4, 0x59,
    0x94, 0x26, 0xf7, 0xd4, 0x61, 0xe6, 0x6f, 0x99, 0x88, 0x2b, 0xd8, 0x9f,
    0xc5, 0x08, 0x00, 0xbe, 0xcc, 0xa6, 0x2d, 0x6c, 0x74, 0x11, 0x6d, 0xbd,
    0x29, 0x72, 0xfd, 0xa1, 0xfa, 0x80, 0xf8, 0x5d, 0xf8, 0x81, 0xed, 0xbe,
    0x5a, 0x37, 0x66, 0x89, 0x36, 0xb3, 0x35, 0x58, 0x3b, 0x59, 0x91, 0x86,
    0xdc, 0x5c, 0x69, 0x18, 0xa3, 0x96, 0xfa, 0x48, 0xa1, 0x81, 0xd6, 0xb6,
    0xfa, 0x4f, 0x9d, 0x62, 0xd5, 0x13, 0xaf, 0xbb, 0x99, 0x2f, 0x2b, 0x99,
    0x2f, 0x67, 0xf8, 0xaf, 0xe6, 0x7f, 0x76, 0x91, 0x3f, 0xa3, 0x88, 0xcb,
    0x56, 0x30, 0xc8, 0xca, 0x01, 0xe0, 0xc6, 0x5d, 0x11, 0xc6, 0x6a, 0x1e,
    0x2a, 0xc4, 0xc8, 0x59, 0x77, 0xb7, 0xc7, 0xa6, 0x99, 0x9b, 0xbf, 0x10,
    0xdc, 0x35, 0xae, 0x69, 0xf5, 0x51, 0x56, 0x14, 0x63, 0x6c, 0x0b, 0x9b,
    0x68, 0xc1, 0x9e, 0xd2, 0xe3, 0x1c, 0x0b, 0x3b, 0x66, 0x76, 0x30, 0x38,
    0xeb, 0xba, 0x42, 0xf3, 0xb3, 0x8e, 0xdc, 0x03, 0x99, 0xf3, 0xa9, 0xf2,
    0x3f, 0xaa, 0x63, 0x97, 0x8c, 0x31, 0x7f, 0xc9, 0xfa, 0x66, 0xa7, 0x3f,
    0x60, 0xf0, 0x50, 0x4d, 0xe9, 0x3b, 0x5b, 0x84, 0x5e, 0x27, 0x55, 0x92,
    0xc1, 0x23, 0x35, 0xee, 0x34, 0x0b, 0xbc, 0x4f, 0xdd, 0xd5, 0x02, 0x78,
    0x40, 0x16, 0xe4, 0xb3, 0xbe, 0x7e, 0xf0, 0x4d, 0xda, 0x49, 0xf4, 0xb4,
    0x40, 0xa3, 0x0c, 0xb5, 0xd2, 0xaf, 0x93, 0x98, 0x28, 0xfd, 0x4a, 0xe3,
    0x79, 0x4e, 0x44, 0xf9, 0x4d, 0xf5, 0xa6, 0x31, 0xed, 0xe4, 0x2c, 0x17,
    0x19, 0xbf, 0xda, 0xbf, 0x02, 0x53, 0xfe, 0x51, 0x75, 0xbe, 0x89, 0x8e,
    0x75, 0x0e, 0xdc, 0x53, 0x37, 0x0d, 0x2b
};
/* client Finished record (protected) (RFC 8448 3: {client} send handshake record) */
static const uint8_t _utR8ClientFinRecord[58] = {
    0x17, 0x03, 0x03, 0x00, 0x35, 0x75, 0xec, 0x4d, 0xc2, 0x38, 0xcc, 0xe6,
    0x0b, 0x29, 0x80, 0x44, 0xa7, 0x1e, 0x21, 0x9c, 0x56, 0xcc, 0x77, 0xb0,
    0x51, 0x7f, 0xe9, 0xb9, 0x3c, 0x7a, 0x4b, 0xfc, 0x44, 0xd8, 0x7f, 0x38,
    0xf8, 0x03, 0x38, 0xac, 0x98, 0xfc, 0x46, 0xde, 0xb3, 0x84, 0xbd, 0x1c,
    0xae, 0xac, 0xab, 0x68, 0x67, 0xd7, 0x26, 0xc4, 0x05, 0x46
};
/* server NewSessionTicket record (protected) (RFC 8448 3: {server} send handshake record) */
static const uint8_t _utR8NstRecord[227] = {
    0x17, 0x03, 0x03, 0x00, 0xde, 0x3a, 0x6b, 0x8f, 0x90, 0x41, 0x4a, 0x97,
    0xd6, 0x95, 0x9c, 0x34, 0x87, 0x68, 0x0d, 0xe5, 0x13, 0x4a, 0x2b, 0x24,
    0x0e, 0x6c, 0xff, 0xac, 0x11, 0x6e, 0x95, 0xd4, 0x1d, 0x6a, 0xf8, 0xf6,
    0xb5, 0x80, 0xdc, 0xf3, 0xd1, 0x1d, 0x63, 0xc7, 0x58, 0xdb, 0x28, 0x9a,
    0x01, 0x59, 0x40, 0x25, 0x2f, 0x55, 0x71, 0x3e, 0x06, 0x1d, 0xc1, 0x3e,
    0x07, 0x88, 0x91, 0xa3, 0x8e, 0xfb, 0xcf, 0x57, 0x53, 0xad, 0x8e, 0xf1,
    0x70, 0xad, 0x3c, 0x73, 0x53, 0xd1, 0x6d, 0x9d, 0xa7, 0x73, 0xb9, 0xca,
    0x7f, 0x2b, 0x9f, 0xa1, 0xb6, 0xc0, 0xd4, 0xa3, 0xd0, 0x3f, 0x75, 0xe0,
    0x9c, 0x30, 0xba, 0x1e, 0x62, 0x97, 0x2a, 0xc4, 0x6f, 0x75, 0xf7, 0xb9,
    0x81, 0xbe, 0x63, 0x43, 0x9b, 0x29, 0x99, 0xce, 0x13, 0x06, 0x46, 0x15,
    0x13, 0x98, 0x91, 0xd5, 0xe4, 0xc5, 0xb4, 0x06, 0xf1, 0x6e, 0x3f, 0xc1,
    0x81, 0xa7, 0x7c, 0xa4, 0x75, 0x84, 0x00, 0x25, 0xdb, 0x2f, 0x0a, 0x77,
    0xf8, 0x1b, 0x5a, 0xb0, 0x5b, 0x94, 0xc0, 0x13, 0x46, 0x75, 0x5f, 0x69,
    0x23, 0x2c, 0x86, 0x51, 0x9d, 0x86, 0xcb, 0xee, 0xac, 0x87, 0xaa, 0xc3,
    0x47, 0xd1, 0x43, 0xf9, 0x60, 0x5d, 0x64, 0xf6, 0x50, 0xdb, 0x4d, 0x02,
    0x3e, 0x70, 0xe9, 0x52, 0xca, 0x49, 0xfe, 0x51, 0x37, 0x12, 0x1c, 0x74,
    0xbc, 0x26, 0x97, 0x68, 0x7e, 0x24, 0x87, 0x46, 0xd6, 0xdf, 0x35, 0x30,
    0x05, 0xf3, 0xbc, 0xe1, 0x86, 0x96, 0x12, 0x9c, 0x81, 0x53, 0x55, 0x6b,
    0x3b, 0x6c, 0x67, 0x79, 0xb3, 0x7b, 0xf1, 0x59, 0x85, 0x68, 0x4f
};
/* client application_data record (RFC 8448 3: {client} send application_data record) */
static const uint8_t _utR8ClientAppRecord[72] = {
    0x17, 0x03, 0x03, 0x00, 0x43, 0xa2, 0x3f, 0x70, 0x54, 0xb6, 0x2c, 0x94,
    0xd0, 0xaf, 0xfa, 0xfe, 0x82, 0x28, 0xba, 0x55, 0xcb, 0xef, 0xac, 0xea,
    0x42, 0xf9, 0x14, 0xaa, 0x66, 0xbc, 0xab, 0x3f, 0x2b, 0x98, 0x19, 0xa8,
    0xa5, 0xb4, 0x6b, 0x39, 0x5b, 0xd5, 0x4a, 0x9a, 0x20, 0x44, 0x1e, 0x2b,
    0x62, 0x97, 0x4e, 0x1f, 0x5a, 0x62, 0x92, 0xa2, 0x97, 0x70, 0x14, 0xbd,
    0x1e, 0x3d, 0xea, 0xe6, 0x3a, 0xee, 0xbb, 0x21, 0x69, 0x49, 0x15, 0xe4
};
/* server application_data record (RFC 8448 3: {server} send application_data record) */
static const uint8_t _utR8ServerAppRecord[72] = {
    0x17, 0x03, 0x03, 0x00, 0x43, 0x2e, 0x93, 0x7e, 0x11, 0xef, 0x4a, 0xc7,
    0x40, 0xe5, 0x38, 0xad, 0x36, 0x00, 0x5f, 0xc4, 0xa4, 0x69, 0x32, 0xfc,
    0x32, 0x25, 0xd0, 0x5f, 0x82, 0xaa, 0x1b, 0x36, 0xe3, 0x0e, 0xfa, 0xf9,
    0x7d, 0x90, 0xe6, 0xdf, 0xfc, 0x60, 0x2d, 0xcb, 0x50, 0x1a, 0x59, 0xa8,
    0xfc, 0xc4, 0x9c, 0x4b, 0xf2, 0xe5, 0xf0, 0xa2, 0x1c, 0x00, 0x47, 0xc2,
    0xab, 0xf3, 0x32, 0x54, 0x0d, 0xd0, 0x32, 0xe1, 0x67, 0xc2, 0x95, 0x5d
};
/* application data, both directions (RFC 8448 3: {client} send application_data record) */
static const uint8_t _utR8AppData[50] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31
};
/* client close_notify record (RFC 8448 3: {client} send alert record) */
static const uint8_t _utR8ClientAlertRecord[24] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xc9, 0x87, 0x27, 0x60, 0x65, 0x56, 0x66,
    0xb7, 0x4d, 0x7f, 0xf1, 0x15, 0x3e, 0xfd, 0x6d, 0xb6, 0xd0, 0xb0, 0xe3
};
/* server close_notify record (RFC 8448 3: {server} send alert record) */
static const uint8_t _utR8ServerAlertRecord[24] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xb5, 0x8f, 0xd6, 0x71, 0x66, 0xeb, 0xf5,
    0x99, 0xd2, 0x47, 0x20, 0xcf, 0xbe, 0x7e, 0xfa, 0x7a, 0x88, 0x64, 0xa9
};
/* client_handshake_traffic_secret (RFC 8448 3: {server} derive secret 'tls13 c hs traffic') */
static const uint8_t _utR8CHsTraffic[32] = {
    0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35, 0xa7, 0x80, 0xb3, 0xab,
    0xf4, 0x5e, 0x2d, 0x8f, 0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96,
    0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21
};
/* server_handshake_traffic_secret (RFC 8448 3: {server} derive secret 'tls13 s hs traffic') */
static const uint8_t _utR8SHsTraffic[32] = {
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13,
    0xcb, 0x2d, 0x37, 0xb4, 0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d,
    0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38
};
/* client_application_traffic_secret_0 (RFC 8448 3: {server} derive secret 'tls13 c ap traffic') */
static const uint8_t _utR8CApTraffic[32] = {
    0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d, 0xc0, 0x5a, 0xf8, 0x88,
    0x9b, 0xce, 0x65, 0x52, 0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87,
    0xf7, 0x92, 0xeb, 0xb7, 0xc1, 0x75, 0x04, 0xa5
};
/* server_application_traffic_secret_0 (RFC 8448 3: {server} derive secret 'tls13 s ap traffic') */
static const uint8_t _utR8SApTraffic[32] = {
    0xa1, 0x1a, 0xf9, 0xf0, 0x55, 0x31, 0xf8, 0x56, 0xad, 0x47, 0x11, 0x6b,
    0x45, 0xa9, 0x50, 0x32, 0x82, 0x04, 0xb4, 0xf4, 0x4b, 0xfb, 0x6b, 0x3a,
    0x4b, 0x4f, 0x1f, 0x3f, 0xcb, 0x63, 0x16, 0x43
};

/* Returns the length of the record starting at _utFakeOut[off] (header included). */
static size_t _UTOutRecordLen(size_t off)
{
    SSF_ASSERT((off + 5u) <= _utFakeOutLen);
    return 5u + (((size_t)_utFakeOut[off + 3u] << 8) | _utFakeOut[off + 4u]);
}

/* Appends rec to the fake transport's input. */
static void _UTQueueRecord(const uint8_t *rec, size_t len)
{
    SSF_ASSERT((_utFakeInLen + len) <= sizeof(_utFakeIn));
    memcpy(&_utFakeIn[_utFakeInLen], rec, len);
    _utFakeInLen += len;
}

static void _SSFTLSCUTRfc8448Simple(void)
{
    SSFTLSCSession_t *s = &_utSession2;
    SSFNetTransport_t *t = &s->transport;
    SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;
    uint8_t buf[64];
    size_t off;
    size_t n;
    uint16_t k;
    bool hsChecked = false;

    if (!SSF_TLSC_UT_RECORD_FITS(sizeof(_utR8FlightRecord))) return;  /* The trace's flight */

    SSFTLSCInit(s, &_utFake, NULL);
    SSFTLSCSetUnauthenticated(s, true);
    _SSFTLSCInjectClientHelloForTest(_utR8ClientHello, sizeof(_utR8ClientHello), _utR8ClientPriv);
    _utFakeInLen = _utFakeInPos = _utFakeOutLen = 0;
    SSF_ASSERT(t->open(t, "server", sizeof("server"), 443u));
    for (k = 0; (k < 20u) && (_utFakeOutLen == 0u); k++) (void)t->pollOpen(t);
    _SSFTLSCInjectClientHelloForTest(NULL, 0u, NULL);

    /* ---- The ClientHello goes out as given (record version 0x0303; the RFC's is 0x0301) ---- */
    SSF_ASSERT(_UTOutRecordLen(0u) == (5u + sizeof(_utR8ClientHello)));
    SSF_ASSERT(_utFakeOut[0] == SSF_TLS_CT_HANDSHAKE);
    SSF_ASSERT(memcmp(&_utFakeOut[5], _utR8ClientHello, sizeof(_utR8ClientHello)) == 0);

    /* ---- ServerHello, then the protected flight: handshake secrets, then completion ---- */
    _UTQueueRecord(_utR8ShRecord, sizeof(_utR8ShRecord));
    _UTQueueRecord(_utR8FlightRecord, sizeof(_utR8FlightRecord));
    for (k = 0; (k < 50u) && ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)); k++)
    {
        r = t->pollOpen(t);
        if (!hsChecked && (s->hsState == SSF_TLSC_HS_RECV_EE_CERT))
        {
            /* Derived and not yet wiped */
            SSF_ASSERT(memcmp(s->clientHsTrafficSecret, _utR8CHsTraffic, 32u) == 0);
            SSF_ASSERT(memcmp(s->serverHsTrafficSecret, _utR8SHsTraffic, 32u) == 0);
            hsChecked = true;
        }
    }
    SSF_ASSERT(hsChecked);
    SSF_ASSERT(r == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(SSFTLSCGetHandshakeState(s) == SSF_TLSC_HS_COMPLETE);
    SSF_ASSERT((s->cipherSuite == SSF_TLS_CS_AES_128_GCM_SHA256) && (s->hashLen == 32u));
    SSF_ASSERT(memcmp(s->clientAppTrafficSecret, _utR8CApTraffic, 32u) == 0);
    SSF_ASSERT(memcmp(s->serverAppTrafficSecret, _utR8SApTraffic, 32u) == 0);

    /* ---- The client's Finished record, after the ClientHello and compatibility CCS ---- */
    off = _UTOutRecordLen(0u);
    SSF_ASSERT((_UTOutRecordLen(off) == 6u) && (_utFakeOut[off] == SSF_TLS_CT_CHANGE_CIPHER));
    off += 6u;
    SSF_ASSERT(_UTOutRecordLen(off) == sizeof(_utR8ClientFinRecord));
    SSF_ASSERT(memcmp(&_utFakeOut[off], _utR8ClientFinRecord, sizeof(_utR8ClientFinRecord)) == 0);
    SSF_ASSERT((off + sizeof(_utR8ClientFinRecord)) == _utFakeOutLen);

    /* ---- Application data: the ticket is skipped, the server's data decrypts ---- */
    _UTQueueRecord(_utR8NstRecord, sizeof(_utR8NstRecord));
    _UTQueueRecord(_utR8ServerAppRecord, sizeof(_utR8ServerAppRecord));
    n = 0;
    for (k = 0; (k < 10u) && (n == 0u); k++)
    {
        r = t->recv(t, buf, sizeof(buf), &n);
        SSF_ASSERT((r == SSF_NET_IO_SUCCESS) || (r == SSF_NET_IO_WANT_READ));
    }
    SSF_ASSERT((n == sizeof(_utR8AppData)) && (memcmp(buf, _utR8AppData, n) == 0));

    /* ---- The client's own data and close_notify are the RFC's records ---- */
    _utFakeOutLen = 0;
    SSF_ASSERT(t->send(t, _utR8AppData, sizeof(_utR8AppData), &n) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT((n == sizeof(_utR8AppData)) && (_utFakeOutLen == sizeof(_utR8ClientAppRecord)));
    SSF_ASSERT(memcmp(_utFakeOut, _utR8ClientAppRecord, sizeof(_utR8ClientAppRecord)) == 0);
    _utFakeOutLen = 0;
    SSF_ASSERT(t->shutdown(t) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(_utFakeOutLen == sizeof(_utR8ClientAlertRecord));
    SSF_ASSERT(memcmp(_utFakeOut, _utR8ClientAlertRecord, sizeof(_utR8ClientAlertRecord)) == 0);

    /* ---- The server's close_notify ends the connection ---- */
    _UTQueueRecord(_utR8ServerAlertRecord, sizeof(_utR8ServerAlertRecord));
    r = t->recv(t, buf, sizeof(buf), &n);
    SSF_ASSERT((r == SSF_NET_IO_CLOSED) && (n == 0u));
    t->close(t);
    SSFTLSCDeInit(s);
}

/* --------------------------------------------------------------------------------------------- */
/* RFC 8448 5 (HelloRetryRequest), 6 (Client Authentication) and 7 (Compatibility Mode), replayed */
/* like 3. The client must reproduce each trace's secrets and records; where it cannot (6: the  */
/* RFC does not give the client's private key, so the client signs with its own), it is checked */
/* against the trace up to the server Finished and its own flight is verified.                 */
/* --------------------------------------------------------------------------------------------- */
/* RFC 8448 5: extracted by script, checked with pyca/cryptography before use */
static const uint8_t _utR8s5ClientPriv[32] = {
    0x0e, 0xd0, 0x2f, 0x8e, 0x81, 0x17, 0xef, 0xc7, 0x5c, 0xa7, 0xac, 0x32,
    0xaa, 0x7e, 0x34, 0xed, 0xa6, 0x4c, 0xdc, 0x0d, 0xda, 0xd1, 0x54, 0xa5,
    0xe8, 0x52, 0x89, 0xf9, 0x59, 0xf6, 0x32, 0x04
};
static const uint8_t _utR8s5ClientHello[180] = {
    0x01, 0x00, 0x00, 0xb0, 0x03, 0x03, 0xb0, 0xb1, 0xc5, 0xa5, 0xaa, 0x37,
    0xc5, 0x91, 0x9f, 0x2e, 0xd1, 0xd5, 0xc6, 0xff, 0xf7, 0xfc, 0xb7, 0x84,
    0x97, 0x16, 0x94, 0x5a, 0x2b, 0x8c, 0xee, 0x92, 0x58, 0xa3, 0x46, 0x67,
    0x7b, 0x6f, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01,
    0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06,
    0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
    0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xe8, 0xe8, 0xe3,
    0xf3, 0xb9, 0x3a, 0x25, 0xed, 0x97, 0xa1, 0x4a, 0x7d, 0xca, 0xcb, 0x8a,
    0x27, 0x2c, 0x62, 0x88, 0xe5, 0x85, 0xc6, 0x48, 0x4d, 0x05, 0x26, 0x2f,
    0xca, 0xd0, 0x62, 0xad, 0x1f, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
    0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
    0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
    0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02,
    0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01
};
static const uint8_t _utR8s5HrrRecord[181] = {
    0x16, 0x03, 0x03, 0x00, 0xb0, 0x02, 0x00, 0x00, 0xac, 0x03, 0x03, 0xcf,
    0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e,
    0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07,
    0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c, 0x00, 0x13, 0x01, 0x00, 0x00,
    0x84, 0x00, 0x33, 0x00, 0x02, 0x00, 0x17, 0x00, 0x2c, 0x00, 0x74, 0x00,
    0x72, 0x71, 0xdc, 0xd0, 0x4b, 0xb8, 0x8b, 0xc3, 0x18, 0x91, 0x19, 0x39,
    0x8a, 0x00, 0x00, 0x00, 0x00, 0xee, 0xfa, 0xfc, 0x76, 0xc1, 0x46, 0xb8,
    0x23, 0xb0, 0x96, 0xf8, 0xaa, 0xca, 0xd3, 0x65, 0xdd, 0x00, 0x30, 0x95,
    0x3f, 0x4e, 0xdf, 0x62, 0x56, 0x36, 0xe5, 0xf2, 0x1b, 0xb2, 0xe2, 0x3f,
    0xcc, 0x65, 0x4b, 0x1b, 0x5b, 0x40, 0x31, 0x8d, 0x10, 0xd1, 0x37, 0xab,
    0xcb, 0xb8, 0x75, 0x74, 0xe3, 0x6e, 0x8a, 0x1f, 0x02, 0x5f, 0x7d, 0xfa,
    0x5d, 0x6e, 0x50, 0x78, 0x1b, 0x5e, 0xda, 0x4a, 0xa1, 0x5b, 0x0c, 0x8b,
    0xe7, 0x78, 0x25, 0x7d, 0x16, 0xaa, 0x30, 0x30, 0xe9, 0xe7, 0x84, 0x1d,
    0xd9, 0xe4, 0xc0, 0x34, 0x22, 0x67, 0xe8, 0xca, 0x0c, 0xaf, 0x57, 0x1f,
    0xb2, 0xb7, 0xcf, 0xf0, 0xf9, 0x34, 0xb0, 0x00, 0x2b, 0x00, 0x02, 0x03,
    0x04
};
static const uint8_t _utR8s5ClientHello2[512] = {
    0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0xb0, 0xb1, 0xc5, 0xa5, 0xaa, 0x37,
    0xc5, 0x91, 0x9f, 0x2e, 0xd1, 0xd5, 0xc6, 0xff, 0xf7, 0xfc, 0xb7, 0x84,
    0x97, 0x16, 0x94, 0x5a, 0x2b, 0x8c, 0xee, 0x92, 0x58, 0xa3, 0x46, 0x67,
    0x7b, 0x6f, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01,
    0x00, 0x01, 0xcd, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06,
    0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
    0x33, 0x00, 0x47, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04, 0xa6, 0xda,
    0x73, 0x92, 0xec, 0x59, 0x1e, 0x17, 0xab, 0xfd, 0x53, 0x59, 0x64, 0xb9,
    0x98, 0x94, 0xd1, 0x3b, 0xef, 0xb2, 0x21, 0xb3, 0xde, 0xf2, 0xeb, 0xe3,
    0x83, 0x0e, 0xac, 0x8f, 0x01, 0x51, 0x81, 0x26, 0x77, 0xc4, 0xd6, 0xd2,
    0x23, 0x7e, 0x85, 0xcf, 0x01, 0xd6, 0x91, 0x0c, 0xfb, 0x83, 0x95, 0x4e,
    0x76, 0xba, 0x73, 0x52, 0x83, 0x05, 0x34, 0x15, 0x98, 0x97, 0xe8, 0x06,
    0x57, 0x80, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00,
    0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08,
    0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02,
    0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2c, 0x00,
    0x74, 0x00, 0x72, 0x71, 0xdc, 0xd0, 0x4b, 0xb8, 0x8b, 0xc3, 0x18, 0x91,
    0x19, 0x39, 0x8a, 0x00, 0x00, 0x00, 0x00, 0xee, 0xfa, 0xfc, 0x76, 0xc1,
    0x46, 0xb8, 0x23, 0xb0, 0x96, 0xf8, 0xaa, 0xca, 0xd3, 0x65, 0xdd, 0x00,
    0x30, 0x95, 0x3f, 0x4e, 0xdf, 0x62, 0x56, 0x36, 0xe5, 0xf2, 0x1b, 0xb2,
    0xe2, 0x3f, 0xcc, 0x65, 0x4b, 0x1b, 0x5b, 0x40, 0x31, 0x8d, 0x10, 0xd1,
    0x37, 0xab, 0xcb, 0xb8, 0x75, 0x74, 0xe3, 0x6e, 0x8a, 0x1f, 0x02, 0x5f,
    0x7d, 0xfa, 0x5d, 0x6e, 0x50, 0x78, 0x1b, 0x5e, 0xda, 0x4a, 0xa1, 0x5b,
    0x0c, 0x8b, 0xe7, 0x78, 0x25, 0x7d, 0x16, 0xaa, 0x30, 0x30, 0xe9, 0xe7,
    0x84, 0x1d, 0xd9, 0xe4, 0xc0, 0x34, 0x22, 0x67, 0xe8, 0xca, 0x0c, 0xaf,
    0x57, 0x1f, 0xb2, 0xb7, 0xcf, 0xf0, 0xf9, 0x34, 0xb0, 0x00, 0x2d, 0x00,
    0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x15, 0x00,
    0xaf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t _utR8s5P256Priv[32] = {
    0xab, 0x54, 0x73, 0x46, 0x7e, 0x19, 0x34, 0x6c, 0xeb, 0x0a, 0x04, 0x14,
    0xe4, 0x1d, 0xa2, 0x1d, 0x4d, 0x24, 0x45, 0xbc, 0x30, 0x25, 0xaf, 0xe9,
    0x7c, 0x4e, 0x8d, 0xc8, 0xd5, 0x13, 0xda, 0x39
};
static const uint8_t _utR8s5ShRecord[128] = {
    0x16, 0x03, 0x03, 0x00, 0x7b, 0x02, 0x00, 0x00, 0x77, 0x03, 0x03, 0xbb,
    0x34, 0x1d, 0x84, 0x7f, 0xd7, 0x89, 0xc4, 0x7c, 0x38, 0x71, 0x72, 0xdc,
    0x0c, 0x9b, 0xf1, 0x47, 0xfc, 0xca, 0xcb, 0x50, 0x43, 0xd8, 0x6c, 0xa4,
    0xc5, 0x98, 0xd3, 0xff, 0x57, 0x1b, 0x98, 0x00, 0x13, 0x01, 0x00, 0x00,
    0x4f, 0x00, 0x33, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04, 0x58, 0x3e,
    0x05, 0x4b, 0x7a, 0x66, 0x67, 0x2a, 0xe0, 0x20, 0xad, 0x9d, 0x26, 0x86,
    0xfc, 0xc8, 0x5b, 0x5a, 0xd4, 0x1a, 0x13, 0x4a, 0x0f, 0x03, 0xee, 0x72,
    0xb8, 0x93, 0x05, 0x2b, 0xd8, 0x5b, 0x4c, 0x8d, 0xe6, 0x77, 0x6f, 0x5b,
    0x04, 0xac, 0x07, 0xd8, 0x35, 0x40, 0xea, 0xb3, 0xe3, 0xd9, 0xc5, 0x47,
    0xbc, 0x65, 0x28, 0xc4, 0x31, 0x7d, 0x29, 0x46, 0x86, 0x09, 0x3a, 0x6c,
    0xad, 0x7d, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
};
static const uint8_t _utR8s5FlightRecord[667] = {
    0x17, 0x03, 0x03, 0x02, 0x96, 0x99, 0xbe, 0xe2, 0x0b, 0xaf, 0x5b, 0x7f,
    0xc7, 0x27, 0xbf, 0xab, 0x62, 0x23, 0x92, 0x8a, 0x38, 0x1e, 0x6d, 0x0c,
    0xf9, 0xc4, 0xda, 0x65, 0x3f, 0x9d, 0x2a, 0x7b, 0x23, 0xf7, 0xde, 0x11,
    0xcc, 0xe8, 0x42, 0xd5, 0xcf, 0x75, 0x63, 0x17, 0x63, 0x45, 0x0f, 0xfb,
    0x8b, 0x0c, 0xc1, 0xd2, 0x38, 0xe6, 0x58, 0xaf, 0x7a, 0x12, 0xad, 0xc8,
    0x62, 0x43, 0x11, 0x4a, 0xb1, 0x4a, 0x1d, 0xa2, 0xfa, 0xe4, 0x26, 0x21,
    0xce, 0x48, 0x3f, 0xb6, 0x24, 0x2e, 0xab, 0xfa, 0xad, 0x52, 0x56, 0x6b,
    0x02, 0xb3, 0x1d, 0x2e, 0xdd, 0xed, 0xef, 0xeb, 0x80, 0xe6, 0x6a, 0x99,
    0x00, 0xd5, 0xf9, 0x73, 0xb4, 0x0c, 0x4f, 0xdf, 0x74, 0x71, 0x9e, 0xcf,
    0x1b, 0x68, 0xd7, 0xf9, 0xc3, 0xb6, 0xce, 0xb9, 0x03, 0xca, 0x13, 0xdd,
    0x1b, 0xb8, 0xf8, 0x18, 0x7a, 0xe3, 0x34, 0x17, 0xe1, 0xd1, 0x52, 0x52,
    0x2c, 0x58, 0x22, 0xa1, 0xa0, 0x3a, 0xd5, 0x2c, 0x83, 0x8c, 0x55, 0x95,
    0x3d, 0x61, 0x02, 0x22, 0x87, 0x4c, 0xce, 0x8e, 0x17, 0x90, 0xb2, 0x29,
    0xa2, 0xaa, 0x0b, 0x53, 0xc8, 0xd3, 0x77, 0xee, 0x72, 0x01, 0x82, 0x95,
    0x1d, 0xc6, 0x18, 0x1d, 0xc5, 0xd9, 0x0b, 0xd1, 0xf0, 0x10, 0x5e, 0xd1,
    0xe8, 0x4a, 0xa5, 0xf7, 0x59, 0x57, 0xc6, 0x66, 0x18, 0x97, 0x07, 0x9e,
    0x5e, 0xa5, 0x00, 0x74, 0x49, 0xe3, 0x19, 0x7b, 0xdc, 0x7c, 0x9b, 0xee,
    0xed, 0xdd, 0xea, 0xfd, 0xd8, 0x44, 0xaf, 0xa5, 0xc3, 0x15, 0xec, 0xfe,
    0x65, 0xe5, 0x76, 0xaf, 0xe9, 0x09, 0x81, 0x28, 0x80, 0x62, 0x0e, 0xc7,
    0x04, 0x8b, 0x42, 0xd7, 0xf5, 0xc7, 0x8d, 0x76, 0xf2, 0x99, 0xd6, 0xd8,
    0x25, 0x34, 0xbd, 0xd8, 0xf5, 0x12, 0xfe, 0xbc, 0x0e, 0xd3, 0x81, 0x4a,
    0xca, 0x47, 0x0c, 0xd8, 0x00, 0x0d, 0x3e, 0x1c, 0xb9, 0x96, 0x2b, 0x05,
    0x2f, 0xbb, 0x95, 0x0d, 0xf6, 0x83, 0xa5, 0x2c, 0x2b, 0xa7, 0x7e, 0xd3,
    0x71, 0x3b, 0x12, 0x29, 0x37, 0xa6, 0xe5, 0x17, 0x09, 0x64, 0xe2, 0xab,
    0x79, 0x69, 0xdc, 0xd9, 0x80, 0xb3, 0xdb, 0x9b, 0x45, 0x8d, 0xa7, 0x60,
    0x31, 0x24, 0xd6, 0xdc, 0x00, 0x5e, 0x4d, 0x6e, 0x04, 0xb4, 0xd0, 0xc4,
    0xba, 0xf3, 0x27, 0x5d, 0xb8, 0x27, 0xdb, 0xba, 0x0a, 0x6d, 0xb0, 0x96,
    0x72, 0x17, 0x1f, 0xc0, 0x57, 0xb3, 0x85, 0x1d, 0x7e, 0x02, 0x68, 0x41,
    0xe2, 0x97, 0x8f, 0xbd, 0x23, 0x46, 0xbb, 0xef, 0xdd, 0x03, 0x76, 0xbb,
    0x11, 0x08, 0xfe, 0x9a, 0xcc, 0x92, 0x18, 0x9f, 0x56, 0x50, 0xaa, 0x5e,
    0x85, 0xd8, 0xe8, 0xc7, 0xb6, 0x7a, 0xc5, 0x10, 0xdb, 0xa0, 0x03, 0xd3,
    0xd7, 0xe1, 0x63, 0x50, 0xbb, 0x66, 0xd4, 0x50, 0x13, 0xef, 0xd4, 0x4c,
    0x9b, 0x60, 0x7c, 0x0d, 0x31, 0x8c, 0x4c, 0x7d, 0x1a, 0x1f, 0x5c, 0xbc,
    0x57, 0xe2, 0x06, 0x11, 0x80, 0x4e, 0x37, 0x87, 0xd7, 0xb4, 0xa4, 0xb5,
    0xf0, 0x8e, 0xd8, 0xfd, 0x70, 0xbd, 0xae, 0xad, 0xe0, 0x22, 0x60, 0xb1,
    0x2a, 0xb8, 0x42, 0xef, 0x69, 0x0b, 0x4a, 0x3e, 0xe7, 0x91, 0x1e, 0x84,
    0x1b, 0x37, 0x4e, 0xcd, 0x5e, 0xbb, 0xbc, 0x2a, 0x54, 0xd0, 0x47, 0xb6,
    0x00, 0x33, 0x6d, 0xd7, 0xd0, 0xc8, 0x8b, 0x4b, 0xc1, 0x0e, 0x58, 0xee,
    0x6c, 0xb6, 0x56, 0xde, 0x72, 0x47, 0xfa, 0x20, 0xd8, 0xe9, 0x1d, 0xeb,
    0x84, 0x62, 0x86, 0x08, 0xcf, 0x80, 0x61, 0x5b, 0x62, 0xe9, 0x6c, 0x14,
    0x91, 0xc7, 0xac, 0x37, 0x55, 0xeb, 0x69, 0x01, 0x40, 0x5d, 0x34, 0x74,
    0xfe, 0x1a, 0xc7, 0x9d, 0x10, 0x6a, 0x0c, 0xee, 0x56, 0xc2, 0x57, 0x7f,
    0xc8, 0x84, 0x80, 0xf9, 0x6c, 0xb6, 0xb8, 0xc6, 0x81, 0xb7, 0xb6, 0x8b,
    0x53, 0xc1, 0x46, 0x09, 0x39, 0x08, 0xf3, 0x50, 0x88, 0x81, 0x75, 0xbd,
    0xfb, 0x0b, 0x1e, 0x31, 0xad, 0x61, 0xe3, 0x0b, 0xa0, 0xad, 0xfe, 0x6d,
    0x22, 0x3a, 0xa0, 0x3c, 0x07, 0x83, 0xb5, 0x00, 0x1a, 0x57, 0x58, 0x7c,
    0x32, 0x8a, 0x9a, 0xfc, 0xfc, 0xfb, 0x97, 0x8d, 0x1c, 0xd4, 0x32, 0x8f,
    0x7d, 0x9d, 0x60, 0x53, 0x0e, 0x63, 0x0b, 0xef, 0xd9, 0x6c, 0x0c, 0x81,
    0x6e, 0xe2, 0x0b, 0x01, 0x00, 0x76, 0x8a, 0xe2, 0xa6, 0xdf, 0x51, 0xfc,
    0x68, 0xf1, 0x72, 0x74, 0x0a, 0x79, 0xaf, 0x11, 0x39, 0x8e, 0xe3, 0xbe,
    0x12, 0x52, 0x49, 0x1f, 0xa9, 0xc6, 0x93, 0x47, 0x9e, 0x87, 0x7f, 0x94,
    0xab, 0x7c, 0x5f, 0x8c, 0xad, 0x48, 0x02, 0x03, 0xe6, 0xab, 0x7b, 0x87,
    0xdd, 0x71, 0xe8, 0xa0, 0x72, 0x91, 0x13, 0xdf, 0x17, 0xf5, 0xee, 0xe8,
    0x6c, 0xe1, 0x08, 0xd1, 0xd7, 0x20, 0x07, 0xec, 0x1c, 0xd1, 0x3c, 0x85,
    0xa6, 0xc1, 0x49, 0x62, 0x1e, 0x77, 0xb7, 0xd7, 0x8d, 0x80, 0x5a, 0x30,
    0xf0, 0xbe, 0x03, 0x0c, 0x31, 0x5e, 0x54
};
static const uint8_t _utR8s5ClientFinRecord[58] = {
    0x17, 0x03, 0x03, 0x00, 0x35, 0xd7, 0x4f, 0x19, 0x23, 0xc6, 0x62, 0xfd,
    0x34, 0x13, 0x7c, 0x6f, 0x50, 0x2f, 0x3d, 0xd2, 0xb9, 0x3d, 0x95, 0x1d,
    0x1b, 0x3b, 0xc9, 0x7e, 0x42, 0xaf, 0xe2, 0x3c, 0x31, 0xab, 0xea, 0x92,
    0xfe, 0x91, 0xb4, 0x74, 0x99, 0x9e, 0x85, 0xe3, 0xb7, 0x91, 0xce, 0x25,
    0x2f, 0xe8, 0xc3, 0xe9, 0xf9, 0x39, 0xa4, 0x12, 0x0c, 0xb2
};
static const uint8_t _utR8s5ClientAlertRecord[24] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0x2e, 0xa6, 0xcd, 0xf7, 0x49, 0x19, 0x60,
    0x23, 0xe2, 0xb3, 0xa4, 0x94, 0x91, 0x69, 0x55, 0x36, 0x42, 0x60, 0x47
};
static const uint8_t _utR8s5ServerAlertRecord[24] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0x51, 0x9f, 0xc5, 0x07, 0x5c, 0xb0, 0x88,
    0x43, 0x49, 0x75, 0x9f, 0xf9, 0xef, 0x6f, 0x01, 0x1b, 0xb4, 0xc6, 0xf2
};
static const uint8_t _utR8s5CHs[32] = {
    0x15, 0x8a, 0xa7, 0xab, 0x88, 0x55, 0x07, 0x35, 0x82, 0xb4, 0x1d, 0x67,
    0x4b, 0x40, 0x55, 0xca, 0xbc, 0xc5, 0x34, 0x72, 0x8f, 0x65, 0x93, 0x14,
    0x86, 0x1b, 0x4e, 0x08, 0xe2, 0x01, 0x15, 0x66
};
static const uint8_t _utR8s5SHs[32] = {
    0x34, 0x03, 0xe7, 0x81, 0xe2, 0xaf, 0x7b, 0x65, 0x08, 0xda, 0x28, 0x57,
    0x4f, 0x6e, 0x95, 0xa1, 0xab, 0xf1, 0x62, 0xde, 0x83, 0xa9, 0x79, 0x27,
    0xc3, 0x76, 0x72, 0xa4, 0xa0, 0xce, 0xf8, 0xa1
};
static const uint8_t _utR8s5CAp[32] = {
    0x75, 0xec, 0xf4, 0xb9, 0x72, 0x52, 0x5a, 0xa0, 0xdc, 0xd0, 0x57, 0xc9,
    0x94, 0x4d, 0x4c, 0xd5, 0xd8, 0x26, 0x71, 0xd8, 0x84, 0x31, 0x41, 0xd7,
    0xdc, 0x2a, 0x4f, 0xf1, 0x5a, 0x21, 0xdc, 0x51
};
static const uint8_t _utR8s5SAp[32] = {
    0x5c, 0x74, 0xf8, 0x7d, 0xf0, 0x42, 0x25, 0xdb, 0x0f, 0x82, 0x09, 0xc9,
    0xde, 0x64, 0x29, 0xe4, 0x94, 0x35, 0xfd, 0xef, 0xa7, 0xca, 0xd6, 0x18,
    0x64, 0x87, 0x4d, 0x12, 0xf3, 0x1c, 0xfc, 0x8d
};
/* RFC 8448 6: extracted by script, checked with pyca/cryptography before use */
static const uint8_t _utR8s6ClientPriv[32] = {
    0xc0, 0x40, 0xb2, 0xbb, 0x8f, 0x3a, 0xdd, 0xd2, 0x0f, 0xd4, 0x05, 0x8c,
    0x54, 0x70, 0x03, 0xa3, 0xc6, 0xf9, 0xc1, 0xcd, 0x91, 0x5d, 0x5e, 0x53,
    0x5c, 0x87, 0xd8, 0xd1, 0x91, 0xaa, 0xf0, 0x71
};
static const uint8_t _utR8s6ClientHello[192] = {
    0x01, 0x00, 0x00, 0xbc, 0x03, 0x03, 0x6a, 0x47, 0x22, 0x36, 0x32, 0x8b,
    0x83, 0xaf, 0x40, 0x38, 0x6d, 0x3a, 0x3e, 0x1f, 0x1c, 0xe6, 0x24, 0xfa,
    0x4e, 0xd8, 0x9a, 0xb8, 0x65, 0xa4, 0xff, 0x0f, 0x41, 0x44, 0xce, 0x3a,
    0xe2, 0x33, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01,
    0x00, 0x00, 0x8d, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06,
    0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
    0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00,
    0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x08, 0x9c, 0xc2,
    0x67, 0x1f, 0x73, 0x8d, 0x9a, 0x67, 0x1e, 0x5b, 0x2e, 0x46, 0x49, 0x81,
    0xd0, 0x5b, 0x76, 0xe3, 0x61, 0xaa, 0x22, 0xae, 0xa9, 0x1f, 0x1d, 0x49,
    0xca, 0x10, 0xa7, 0xa3, 0x62, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
    0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
    0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
    0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02,
    0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01
};
static const uint8_t _utR8s6ShRecord[95] = {
    0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0x3b,
    0x50, 0xfd, 0xf1, 0xc3, 0xd5, 0x72, 0xe4, 0x0e, 0x68, 0x95, 0x3e, 0x7f,
    0xff, 0x4e, 0x27, 0x58, 0x45, 0x9c, 0x59, 0xaf, 0xa0, 0x58, 0x2c, 0x0e,
    0xa0, 0x32, 0x87, 0x42, 0x55, 0xfe, 0x6e, 0x00, 0x13, 0x01, 0x00, 0x00,
    0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x6c, 0x2e, 0x50,
    0xe8, 0x65, 0x91, 0x9a, 0x6b, 0x5a, 0x12, 0xdf, 0xaf, 0x91, 0x8f, 0x92,
    0xb4, 0x42, 0x56, 0x7b, 0x0f, 0x89, 0xbc, 0x54, 0x47, 0x8c, 0x69, 0x21,
    0x36, 0x66, 0x58, 0xf0, 0x62, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
};
static const uint8_t _utR8s6FlightRecord[539] = {
    0x17, 0x03, 0x03, 0x02, 0x16, 0x6d, 0x0a, 0x7a, 0xc0, 0x79, 0xb3, 0x2a,
    0x94, 0xaa, 0x68, 0xc4, 0xe2, 0x89, 0x3e, 0x8b, 0xd0, 0xd3, 0xc1, 0x85,
    0xf5, 0x49, 0xc2, 0x36, 0xfb, 0xbc, 0xe3, 0xd6, 0x47, 0xf0, 0x8f, 0x3c,
    0x94, 0xa2, 0xbf, 0x42, 0x4d, 0x87, 0x08, 0x88, 0x36, 0x05, 0xad, 0x89,
    0x55, 0xf9, 0x77, 0x18, 0xb0, 0x21, 0x3d, 0xea, 0xd1, 0x3d, 0xfb, 0x23,
    0xeb, 0xb8, 0x38, 0x1d, 0xa5, 0x82, 0x75, 0x66, 0x12, 0xbc, 0xb5, 0xa5,
    0xd4, 0x08, 0x47, 0x71, 0x9f, 0xbe, 0x9f, 0x17, 0x9b, 0xfa, 0xe6, 0x56,
    0xf3, 0xec, 0xfd, 0x59, 0xa4, 0xc0, 0xd3, 0x51, 0x32, 0xce, 0x41, 0x8a,
    0x7e, 0x46, 0xf6, 0xb6, 0xa6, 0x06, 0x22, 0xf8, 0xa6, 0xc0, 0x6b, 0x28,
    0xd8, 0x33, 0x60, 0x16, 0x35, 0x63, 0xbe, 0x9c, 0x37, 0xf9, 0x7e, 0xb9,
    0x02, 0x32, 0x69, 0x24, 0xa7, 0x2b, 0x3e, 0xd8, 0xc8, 0x38, 0x12, 0x77,
    0xd1, 0x58, 0x1c, 0xab, 0x9c, 0x37, 0x15, 0xac, 0x24, 0x01, 0x39, 0x84,
    0x67, 0xad, 0x7e, 0xbf, 0xab, 0x3d, 0x0c, 0x34, 0x19, 0xe7, 0x50, 0x10,
    0x4f, 0x7d, 0x62, 0xc5, 0x02, 0x79, 0x01, 0xf2, 0xe4, 0xcd, 0x4c, 0xa5,
    0xb8, 0x07, 0x1e, 0xb0, 0x3d, 0x3c, 0x73, 0x2d, 0x83, 0x21, 0x50, 0x66,
    0xdf, 0xc4, 0xd2, 0x91, 0xd4, 0xc1, 0xff, 0x3b, 0x8d, 0x7e, 0x42, 0x98,
    0xf6, 0x77, 0xd4, 0xd5, 0x1d, 0xea, 0x11, 0x68, 0xd8, 0xf1, 0x6c, 0xb2,
    0x7b, 0xa4, 0x02, 0x66, 0x31, 0x3a, 0x1f, 0xed, 0xf9, 0xe2, 0x3c, 0xc7,
    0x7f, 0x76, 0x54, 0x50, 0xf9, 0xe9, 0x6f, 0x05, 0xd0, 0x8f, 0x3d, 0xa2,
    0x45, 0xb1, 0x4d, 0x49, 0x46, 0xf0, 0x7e, 0xc8, 0x1e, 0xed, 0x6d, 0x56,
    0xf2, 0x6b, 0xd5, 0x74, 0xf0, 0xb7, 0xf7, 0xc7, 0x04, 0x70, 0x37, 0xc1,
    0x6f, 0xce, 0x3b, 0x23, 0x75, 0x4e, 0x66, 0x2f, 0xad, 0x73, 0xe2, 0xb7,
    0x21, 0x3f, 0x6a, 0xf2, 0x96, 0x76, 0x9c, 0x99, 0xa1, 0xd3, 0x8e, 0x62,
    0x32, 0xe0, 0xec, 0x8d, 0xc4, 0xf8, 0x4d, 0x6a, 0xa6, 0xf7, 0xde, 0x38,
    0x87, 0xbe, 0x00, 0x57, 0x86, 0x2f, 0x90, 0x18, 0xe0, 0xab, 0x39, 0x67,
    0x05, 0xaa, 0x40, 0x90, 0xab, 0x5f, 0x2d, 0xff, 0x63, 0x25, 0xa5, 0x57,
    0xe7, 0x32, 0x0d, 0x4e, 0xff, 0xd4, 0x6b, 0xb4, 0xf9, 0x97, 0xd1, 0x63,
    0x20, 0x7c, 0xce, 0x66, 0x65, 0x29, 0x4a, 0xa4, 0x46, 0x55, 0x41, 0xe3,
    0xfe, 0x37, 0xee, 0x73, 0x50, 0x65, 0x9e, 0xa5, 0x50, 0xd6, 0xdc, 0xb6,
    0xaf, 0x3c, 0x51, 0x88, 0x52, 0xc7, 0xa1, 0x4c, 0x3c, 0xc1, 0x5b, 0xc3,
    0x2b, 0x32, 0x73, 0xbd, 0xf1, 0x75, 0x1d, 0xa1, 0x84, 0x20, 0x31, 0x35,
    0xb1, 0x17, 0xd3, 0x00, 0x20, 0x4f, 0xb1, 0x2d, 0x58, 0xca, 0x9a, 0xc3,
    0x4b, 0x68, 0xec, 0xa2, 0x70, 0x30, 0x83, 0x2f, 0x7a, 0x4b, 0x46, 0xd2,
    0xa5, 0x57, 0x57, 0xf6, 0x3f, 0xe8, 0xf6, 0xe8, 0x5a, 0xc4, 0x74, 0x69,
    0xe6, 0x19, 0x8d, 0xa8, 0x8a, 0x64, 0x58, 0x6b, 0xf2, 0x3c, 0x69, 0x59,
    0x0d, 0xe8, 0x22, 0x26, 0x3b, 0xe7, 0x5f, 0xd8, 0x36, 0x84, 0x72, 0x40,
    0xc4, 0x8f, 0x8c, 0x14, 0x5c, 0xd6, 0xbd, 0x69, 0x89, 0x62, 0xe7, 0xed,
    0xc2, 0x34, 0xeb, 0xe5, 0x92, 0x31, 0x35, 0x1e, 0xef, 0x8d, 0x76, 0x52,
    0xcf, 0x3b, 0x08, 0xab, 0x3a, 0xf6, 0xe5, 0xec, 0x74, 0xc5, 0x8a, 0x8d,
    0xa3, 0x4b, 0x39, 0xf9, 0xb0, 0xd6, 0xc4, 0x27, 0x9a, 0x9a, 0x1f, 0x82,
    0x07, 0x17, 0x29, 0xe7, 0x05, 0x9d, 0xd7, 0xf7, 0xb9, 0x5b, 0x94, 0x33,
    0xc4, 0x68, 0x4c, 0xe1, 0x89, 0x1a, 0x6d, 0x33, 0x43, 0x2d, 0x52, 0xed,
    0xdb, 0x0b, 0x8c, 0xee, 0x91, 0x81, 0xd4, 0x03, 0xec, 0xcc, 0x12, 0x99,
    0x1f, 0x1a, 0xd4, 0xaa, 0x62, 0xc3, 0x60, 0x49, 0x71, 0x3a, 0x7b, 0xb1,
    0x35, 0xfd, 0xda, 0x66, 0x61, 0xa0, 0x5a, 0x93, 0xf8, 0xc1, 0x6f
};
static const uint8_t _utR8s6ServerFlight[517] = {
    0x08, 0x00, 0x00, 0x24, 0x00, 0x22, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12,
    0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01,
    0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x27, 0x00, 0x00, 0x24, 0x00,
    0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02,
    0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06,
    0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x0b,
    0x00, 0x01, 0x3b, 0x00, 0x00, 0x01, 0x37, 0x00, 0x01, 0x32, 0x30, 0x82,
    0x01, 0x2e, 0x30, 0x81, 0xd5, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01,
    0x07, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
    0x02, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x08, 0x65, 0x63, 0x64, 0x73, 0x61, 0x32, 0x35, 0x36, 0x30, 0x1e,
    0x17, 0x0d, 0x31, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x34,
    0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30,
    0x31, 0x32, 0x34, 0x30, 0x30, 0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x65, 0x63, 0x64, 0x73, 0x61,
    0x32, 0x35, 0x36, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
    0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x08, 0xd5, 0x30, 0x16, 0x15, 0x75,
    0xf4, 0xcf, 0xe7, 0xf1, 0x54, 0xee, 0x34, 0x48, 0x18, 0x00, 0x86, 0x00,
    0x1e, 0x88, 0x43, 0x1a, 0x79, 0xee, 0x62, 0xee, 0x6e, 0x2f, 0x83, 0xef,
    0x38, 0xba, 0x61, 0xe9, 0xfb, 0x37, 0xf3, 0x4e, 0x00, 0x7a, 0x7d, 0xf4,
    0xd2, 0xf5, 0xb5, 0x6d, 0x1f, 0x04, 0xec, 0xe4, 0x5d, 0x62, 0x1f, 0x46,
    0x84, 0x06, 0xf5, 0xc3, 0xa1, 0x51, 0x58, 0x94, 0x8d, 0xd0, 0xa3, 0x1a,
    0x30, 0x18, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30,
    0x00, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02,
    0x07, 0x80, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
    0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xdf, 0x30,
    0xfd, 0x45, 0x07, 0xf5, 0xed, 0xd2, 0x2c, 0x1a, 0x6f, 0xf8, 0x6d, 0xb4,
    0x79, 0xca, 0x69, 0x3f, 0xee, 0xca, 0x3b, 0x71, 0xb3, 0xf9, 0xef, 0x55,
    0x6b, 0x29, 0x37, 0xc0, 0x59, 0x4d, 0x02, 0x20, 0x62, 0xe2, 0xa4, 0x72,
    0x50, 0xd3, 0x20, 0xfe, 0xa8, 0x3c, 0x7e, 0x2d, 0xcb, 0x5b, 0x76, 0xa5,
    0x0e, 0x02, 0x00, 0xc0, 0x9a, 0xdb, 0xd1, 0x3f, 0xee, 0x94, 0x6e, 0x51,
    0x3e, 0x01, 0x1d, 0x11, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x4b, 0x04, 0x03,
    0x00, 0x47, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd7, 0xa4, 0xd3, 0x4b, 0xd5,
    0x4f, 0x55, 0xfe, 0xe1, 0xa8, 0x96, 0x25, 0x67, 0x8c, 0x3d, 0xd5, 0xe5,
    0xf6, 0x0d, 0xac, 0x73, 0xec, 0x94, 0x0c, 0x5c, 0x7b, 0x93, 0x04, 0xa0,
    0x20, 0x84, 0xa9, 0x02, 0x20, 0x28, 0x9f, 0x59, 0x5e, 0xd4, 0x88, 0xb9,
    0xac, 0x68, 0x9a, 0x3d, 0x19, 0x2b, 0x1a, 0x8b, 0xb3, 0x8f, 0x34, 0xaf,
    0x78, 0x74, 0xc0, 0x59, 0xc9, 0x80, 0x6a, 0x1f, 0x38, 0x26, 0x93, 0x53,
    0xe8, 0x14, 0x00, 0x00, 0x20, 0x93, 0xb7, 0x0c, 0xdf, 0x47, 0x81, 0x98,
    0x5b, 0x96, 0x34, 0x5c, 0xaa, 0xc7, 0x01, 0xb4, 0xe7, 0x50, 0xd3, 0x04,
    0x2d, 0xf1, 0xa6, 0x89, 0xd8, 0xfa, 0xca, 0x81, 0x22, 0x51, 0x11, 0x3c,
    0x11
};
static const uint8_t _utR8s6ClientAlertRecord[24] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xe4, 0xad, 0x7d, 0x44, 0xc2, 0x92, 0x45,
    0x33, 0x9d, 0x35, 0x59, 0x62, 0xc7, 0x79, 0xb8, 0x9e, 0xf4, 0x4c, 0x58
};
static const uint8_t _utR8s6ServerAlertRecord[24] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0x1d, 0xec, 0xc5, 0xd6, 0xe6, 0x4b, 0xba,
    0x8a, 0x6f, 0x21, 0xb4, 0xfd, 0x07, 0x74, 0x97, 0xda, 0x2a, 0x90, 0xcb
};
static const uint8_t _utR8s6CHs[32] = {
    0xce, 0xc7, 0xa3, 0x0c, 0x68, 0x72, 0x07, 0x0f, 0x22, 0xa7, 0xee, 0xb0,
    0x65, 0x76, 0x8d, 0xb6, 0x7c, 0x45, 0xe2, 0x95, 0x33, 0xdb, 0x87, 0x99,
    0x08, 0xce, 0x6d, 0xc6, 0x6f, 0x59, 0x11, 0xde
};
static const uint8_t _utR8s6SHs[32] = {
    0x8b, 0x02, 0xd3, 0xc0, 0x04, 0x42, 0xa2, 0x72, 0x2c, 0x40, 0x98, 0xeb,
    0xe8, 0x67, 0x5b, 0x23, 0xe8, 0x01, 0x51, 0x0f, 0x0d, 0x7e, 0xd7, 0x78,
    0xd8, 0xeb, 0x0b, 0x8f, 0x42, 0xa1, 0x9a, 0x5e
};
static const uint8_t _utR8s6CAp[32] = {
    0x73, 0xc2, 0xe8, 0x90, 0xfa, 0x8d, 0x06, 0x72, 0x58, 0xd6, 0xd5, 0x0f,
    0xa9, 0x2f, 0xe4, 0x56, 0xb0, 0x98, 0xcf, 0x00, 0xd9, 0x72, 0x7e, 0xed,
    0x91, 0xe8, 0x89, 0x2e, 0xf4, 0xe6, 0xf8, 0x60
};
static const uint8_t _utR8s6SAp[32] = {
    0xc4, 0x9a, 0x91, 0xfa, 0xf5, 0x7f, 0x8c, 0x54, 0x5d, 0x50, 0x48, 0xa0,
    0x15, 0xbf, 0x84, 0x9f, 0xf6, 0x39, 0x42, 0xe4, 0xa7, 0xed, 0xcd, 0x31,
    0x9f, 0x8b, 0x43, 0x8a, 0x97, 0xc5, 0x2e, 0x21
};
/* RFC 8448 7: extracted by script, checked with pyca/cryptography before use */
static const uint8_t _utR8s7ClientPriv[32] = {
    0xde, 0xa0, 0x0b, 0x45, 0x69, 0x5d, 0xc7, 0x81, 0xf1, 0x9d, 0x34, 0xa6,
    0x2c, 0x1a, 0xfd, 0x31, 0xab, 0x43, 0x69, 0xaf, 0x1e, 0x85, 0x5a, 0x3b,
    0xbb, 0x25, 0x8d, 0x84, 0x42, 0xcd, 0xe6, 0xd7
};
static const uint8_t _utR8s7ClientHello[224] = {
    0x01, 0x00, 0x00, 0xdc, 0x03, 0x03, 0x4e, 0x64, 0x0a, 0x3f, 0x2c, 0x27,
    0x38, 0xf0, 0x9c, 0x94, 0x18, 0xbd, 0x78, 0xed, 0xcc, 0xd7, 0x55, 0x9d,
    0x05, 0x31, 0x19, 0x92, 0x76, 0xd4, 0xd9, 0x2a, 0x0e, 0x9e, 0xe9, 0xd7,
    0x7d, 0x09, 0x20, 0xa8, 0x0c, 0x16, 0x55, 0x81, 0xa8, 0xe0, 0xd0, 0x6c,
    0x00, 0x18, 0xd5, 0x4d, 0x3a, 0x06, 0xdd, 0x32, 0xcf, 0xd4, 0x05, 0x1e,
    0xb0, 0x26, 0xfa, 0xd3, 0xfd, 0x0b, 0xa9, 0x92, 0x69, 0xe6, 0xef, 0x00,
    0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x8d, 0x00,
    0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76,
    0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00,
    0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01,
    0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x33, 0x00, 0x26, 0x00,
    0x24, 0x00, 0x1d, 0x00, 0x20, 0x8e, 0x72, 0x92, 0xcf, 0x30, 0x56, 0xdb,
    0xb0, 0xd2, 0x5f, 0xcb, 0xe5, 0x5c, 0x10, 0x7d, 0xc9, 0xbb, 0xf8, 0x3d,
    0xd9, 0x70, 0x8f, 0x39, 0x20, 0x3b, 0xa3, 0x41, 0x24, 0x9a, 0x7d, 0x9b,
    0x63, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20,
    0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04,
    0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01,
    0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02,
    0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01
};
static const uint8_t _utR8s7ShRecord[127] = {
    0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03, 0xe5,
    0xdd, 0x59, 0x48, 0xc4, 0x35, 0xf7, 0xa3, 0x8f, 0x0f, 0x01, 0x30, 0x70,
    0x8d, 0xc3, 0x22, 0xd9, 0xdf, 0x09, 0xab, 0xd4, 0x83, 0x81, 0x17, 0xc1,
    0x83, 0xa7, 0xbb, 0x6d, 0x99, 0x4f, 0x2c, 0x20, 0xa8, 0x0c, 0x16, 0x55,
    0x81, 0xa8, 0xe0, 0xd0, 0x6c, 0x00, 0x18, 0xd5, 0x4d, 0x3a, 0x06, 0xdd,
    0x32, 0xcf, 0xd4, 0x05, 0x1e, 0xb0, 0x26, 0xfa, 0xd3, 0xfd, 0x0b, 0xa9,
    0x92, 0x69, 0xe6, 0xef, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
    0x24, 0x00, 0x1d, 0x00, 0x20, 0x3e, 0x30, 0xf0, 0xf4, 0xba, 0x55, 0x1a,
    0xfd, 0x62, 0x76, 0x83, 0x41, 0x17, 0x5f, 0x52, 0x65, 0xe4, 0xda, 0xf0,
    0xc8, 0x84, 0x16, 0x17, 0xaa, 0x4f, 0xaf, 0xdd, 0x21, 0x42, 0x32, 0x0c,
    0x22, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
};
static const uint8_t _utR8s7CcsRecord[6] = {
    0x14, 0x03, 0x03, 0x00, 0x01, 0x01
};
static const uint8_t _utR8s7FlightRecord[679] = {
    0x17, 0x03, 0x03, 0x02, 0xa2, 0x48, 0xde, 0x89, 0x1d, 0x9c, 0x36, 0x24,
    0xa6, 0x7a, 0x6c, 0x6f, 0x06, 0x01, 0xab, 0x7a, 0xc2, 0x0c, 0x1f, 0x6a,
    0x9e, 0x14, 0xd2, 0xe6, 0x00, 0x7e, 0x99, 0x9e, 0x13, 0x03, 0x67, 0xa8,
    0xaf, 0x1b, 0xcf, 0xea, 0x94, 0x98, 0xfb, 0xce, 0x19, 0xdf, 0x45, 0x05,
    0xee, 0xce, 0x3a, 0x25, 0xda, 0x52, 0x3c, 0xbe, 0x55, 0xea, 0x1b, 0x3b,
    0xda, 0x4e, 0x91, 0x99, 0x5e, 0x45, 0x5d, 0x50, 0x0a, 0x4f, 0xaa, 0x62,
    0x27, 0xb7, 0x11, 0x1e, 0x1c, 0x85, 0x47, 0xe2, 0xd7, 0xc1, 0x79, 0xdb,
    0x21, 0x53, 0x03, 0xd2, 0x58, 0x27, 0xf3, 0xcd, 0x18, 0xf4, 0x8f, 0x64,
    0x91, 0x32, 0x8c, 0xf5, 0xc0, 0xf8, 0x14, 0xd3, 0x88, 0x15, 0x0b, 0xd9,
    0xe9, 0x26, 0x4a, 0xae, 0x49, 0x1d, 0xb6, 0x99, 0x50, 0x69, 0xbe, 0xa1,
    0x76, 0x65, 0xd5, 0xe0, 0xc8, 0x17, 0x28, 0x4d, 0x4a, 0xc2, 0x18, 0x80,
    0x05, 0x4c, 0x36, 0x57, 0x33, 0x1e, 0x23, 0xa9, 0x30, 0x4d, 0xc8, 0x8a,
    0x15, 0xc0, 0x4e, 0xc8, 0x0b, 0xd3, 0x85, 0x2b, 0xf7, 0xf9, 0xd3, 0xc6,
    0x61, 0x5b, 0x15, 0xfa, 0xc8, 0x3b, 0xbc, 0xa0, 0x31, 0xc6, 0xd2, 0x31,
    0x0d, 0x9f, 0x5d, 0x7a, 0x4b, 0x02, 0x0a, 0x4f, 0x7c, 0x19, 0x06, 0x2b,
    0x65, 0xc0, 0x5a, 0x1d, 0x32, 0x64, 0xb5, 0x57, 0xec, 0x9d, 0x8e, 0x0f,
    0x7c, 0xee, 0x27, 0xe3, 0x6f, 0x79, 0x30, 0x39, 0xde, 0x8d, 0xd9, 0x6e,
    0xdf, 0xca, 0x90, 0x09, 0xe0, 0x65, 0x10, 0x34, 0xbf, 0xf3, 0x1d, 0x7f,
    0x34, 0x9e, 0xec, 0xe0, 0x1d, 0x99, 0xfc, 0xb5, 0xfc, 0xab, 0x84, 0x0d,
    0x77, 0x07, 0xc7, 0x22, 0x99, 0xc3, 0xb5, 0xd0, 0x45, 0x64, 0xe8, 0x80,
    0xa3, 0x3c, 0x5e, 0x84, 0x6c, 0x76, 0x2e, 0x3d, 0x92, 0x2b, 0xb5, 0x53,
    0x03, 0xd1, 0xd8, 0x7c, 0xc0, 0xf0, 0x65, 0x73, 0xf1, 0x7d, 0xcb, 0x9b,
    0x8f, 0xfd, 0x35, 0xbb, 0xd8, 0x83, 0xc1, 0xcb, 0x3a, 0xa2, 0x4f, 0xcc,
    0x32, 0x50, 0x05, 0xf7, 0x68, 0xce, 0x2f, 0xb6, 0x24, 0xca, 0x97, 0xb6,
    0xc4, 0xd9, 0x8e, 0x17, 0xf3, 0x5b, 0xc2, 0xc7, 0x94, 0x0a, 0x06, 0x10,
    0x0c, 0x2d, 0x44, 0x8d, 0xb7, 0x18, 0x0b, 0x2d, 0x86, 0x21, 0x64, 0x43,
    0x5c, 0x9c, 0x21, 0x0e, 0x98, 0x60, 0x39, 0x4e, 0x05, 0xaa, 0xb2, 0x3f,
    0xf1, 0xb0, 0x20, 0x3f, 0x66, 0x2c, 0x58, 0x8d, 0xa5, 0xbc, 0x44, 0x11,
    0x47, 0x7a, 0x30, 0xb4, 0x11, 0x36, 0xc4, 0x88, 0xa0, 0xa6, 0x3f, 0xca,
    0xb5, 0xc1, 0x5a, 0xc6, 0x13, 0x22, 0x6d, 0xae, 0x82, 0x7a, 0x1d, 0x1f,
    0xe9, 0x5e, 0xce, 0x6b, 0x30, 0xbc, 0xee, 0x15, 0x60, 0xa8, 0xd4, 0x08,
    0xd2, 0x64, 0x55, 0x5e, 0x76, 0x0f, 0x9b, 0xfc, 0x62, 0x4c, 0x2c, 0x87,
    0xfd, 0x04, 0x56, 0xc9, 0xbf, 0xb4, 0x1b, 0xcd, 0x1a, 0x7b, 0x21, 0x27,
    0x86, 0xd2, 0xb6, 0x7f, 0xd5, 0x78, 0x04, 0xfa, 0xcf, 0xa1, 0xee, 0xf7,
    0xcf, 0x29, 0x19, 0xd8, 0xb9, 0x98, 0xc9, 0x78, 0x9f, 0x76, 0x3b, 0x4d,
    0x9c, 0xaa, 0x09, 0x3a, 0x9d, 0xed, 0x43, 0x17, 0x5d, 0x46, 0xa7, 0x6b,
    0x4d, 0x54, 0xf0, 0xce, 0x0c, 0x5d, 0x22, 0x59, 0xb6, 0x07, 0xe3, 0x0a,
    0x9d, 0x24, 0x12, 0x63, 0x87, 0x4f, 0xa5, 0x9d, 0x6f, 0x57, 0x0d, 0xc4,
    0x0d, 0x83, 0xa2, 0xd8, 0x3b, 0xf9, 0xe9, 0x85, 0x0d, 0x45, 0x4c, 0x57,
    0x80, 0x65, 0x35, 0xa8, 0x99, 0x8a, 0xe0, 0x35, 0x7d, 0xf9, 0x2f, 0x00,
    0xb9, 0x66, 0x73, 0x44, 0xc2, 0x41, 0x14, 0xcc, 0xc9, 0xef, 0x53, 0x91,
    0x24, 0xb2, 0x04, 0xe7, 0xe6, 0xe7, 0x48, 0xc3, 0x0a, 0x28, 0xa3, 0xd1,
    0xd1, 0x83, 0x99, 0x72, 0x43, 0xea, 0xcc, 0xbb, 0xd3, 0x3b, 0x0c, 0x11,
    0x15, 0xa0, 0x32, 0x71, 0x06, 0xa1, 0xe6, 0xa7, 0x52, 0x71, 0xd4, 0x98,
    0x30, 0x86, 0xf6, 0x32, 0xff, 0x0e, 0xb8, 0xb4, 0xc6, 0x31, 0x02, 0xcb,
    0xce, 0xf5, 0xbb, 0x72, 0xda, 0xe1, 0x27, 0x9d, 0x5d, 0xe8, 0xeb, 0x19,
    0x09, 0x6d, 0x8c, 0xdb, 0x07, 0xfa, 0x8e, 0xa9, 0x89, 0x78, 0x8f, 0xac,
    0x23, 0xe6, 0x6e, 0x04, 0x88, 0xc1, 0x93, 0xf3, 0xf3, 0xfe, 0xa8, 0xc8,
    0x83, 0x88, 0x96, 0xbf, 0x3a, 0xe4, 0xb6, 0x84, 0x8d, 0x42, 0xce, 0xd4,
    0xbd, 0xf4, 0x1a, 0xbe, 0x6f, 0xc3, 0x31, 0xb4, 0x42, 0x25, 0xe7, 0xa1,
    0xf7, 0xd3, 0x56, 0x41, 0x47, 0xd5, 0x45, 0x8e, 0x71, 0xaa, 0x90, 0x9c,
    0xb0, 0x2b, 0xe9, 0x58, 0xbb, 0xc4, 0x2e, 0x3a, 0xa5, 0xa2, 0x7c, 0xc6,
    0xea, 0xf4, 0xb6, 0xfe, 0x51, 0xae, 0x44, 0x95, 0x69, 0x4d, 0x8a, 0xb6,
    0x32, 0x0a, 0xab, 0x92, 0x01, 0x83, 0xfd, 0x5b, 0x31, 0xa3, 0x59, 0x04,
    0x2f, 0xbd, 0x67, 0x39, 0x1e, 0xc5, 0xe4, 0xd1, 0x89, 0x2a, 0x2e, 0x52,
    0x10, 0x14, 0x1a, 0x49, 0x4e, 0x93, 0x01, 0xb2, 0x4a, 0x11, 0x3c, 0x47,
    0x4c, 0x7f, 0x2a, 0x73, 0x45, 0x78, 0x47
};
static const uint8_t _utR8s7ClientFinRecord[58] = {
    0x17, 0x03, 0x03, 0x00, 0x35, 0x32, 0xd0, 0x30, 0xe2, 0x73, 0x77, 0x3a,
    0x86, 0x96, 0xc7, 0x99, 0x98, 0x1a, 0xf6, 0xce, 0xd0, 0x7f, 0x87, 0x48,
    0x2e, 0x81, 0x56, 0x5e, 0x39, 0x4e, 0x87, 0xc8, 0x67, 0xf3, 0x3d, 0xf3,
    0xd6, 0x5b, 0x75, 0x06, 0xf1, 0xa6, 0x26, 0xaf, 0x91, 0xd4, 0x82, 0x1d,
    0x5f, 0x7a, 0x1f, 0x21, 0x0e, 0xf8, 0xdd, 0x3c, 0x6d, 0x16
};
static const uint8_t _utR8s7ClientAlertRecord[24] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0x0f, 0x62, 0x91, 0x55, 0x38, 0x2d, 0xba,
    0x23, 0xc4, 0xe2, 0xc5, 0xf7, 0xf8, 0x4e, 0x6f, 0x2e, 0xd3, 0x08, 0x3d
};
static const uint8_t _utR8s7ServerAlertRecord[24] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xb7, 0x25, 0x7b, 0x0f, 0xec, 0xaf, 0x69,
    0xd4, 0xf0, 0x9e, 0x3f, 0x89, 0x1e, 0x2a, 0x25, 0xd1, 0xe2, 0x88, 0x45
};
static const uint8_t _utR8s7CHs[32] = {
    0x2c, 0x3c, 0xb2, 0x4a, 0x10, 0x81, 0xed, 0xb5, 0x95, 0x18, 0xee, 0x68,
    0x61, 0xe8, 0x9a, 0x6b, 0x72, 0xb3, 0x80, 0x1a, 0xfe, 0x77, 0x13, 0xe4,
    0xcb, 0xbc, 0x21, 0xc0, 0x79, 0x5b, 0xf8, 0x31
};
static const uint8_t _utR8s7SHs[32] = {
    0xca, 0xce, 0x3d, 0x55, 0x5c, 0xc1, 0xc5, 0x77, 0xcf, 0x97, 0x0c, 0xff,
    0x28, 0xcf, 0x97, 0x8d, 0x6a, 0x98, 0x00, 0x08, 0x54, 0x42, 0xe1, 0x8d,
    0x69, 0x5b, 0x50, 0xf3, 0x15, 0x1d, 0x18, 0xc8
};
static const uint8_t _utR8s7CAp[32] = {
    0x74, 0x3e, 0x4c, 0x6b, 0x56, 0xcf, 0x39, 0x09, 0xd1, 0xb0, 0x6d, 0x01,
    0x95, 0x6c, 0xcd, 0x2c, 0x4b, 0x37, 0x75, 0x84, 0x49, 0xae, 0xc4, 0x1d,
    0x98, 0xda, 0xe4, 0x49, 0x24, 0xea, 0xa2, 0x99
};
static const uint8_t _utR8s7SAp[32] = {
    0xb6, 0xb8, 0x14, 0x4a, 0xa3, 0x35, 0xed, 0x30, 0x59, 0xc0, 0xc9, 0xc8,
    0xf0, 0xec, 0xab, 0xf7, 0xaf, 0xc9, 0x4a, 0xf6, 0x64, 0x3b, 0xde, 0xcd,
    0xfd, 0x92, 0x10, 0x18, 0x8f, 0xab, 0x74, 0x51
};

/* Starts a replay: injects ClientHello1 (and ClientHello2 for an HRR trace), opens, and polls */
/* until ClientHello1 is out; checks it went out as given.                                     */
static void _UTR8Start(SSFTLSCSession_t *s, const uint8_t *ch1, size_t ch1Len,
                       const uint8_t *x25519Priv, const uint8_t *ch2Opt, size_t ch2Len,
                       const uint8_t *p256PrivOpt)
{
    SSFNetTransport_t *t = &s->transport;
    uint16_t k;

    SSFTLSCInit(s, &_utFake, NULL);
    SSFTLSCSetUnauthenticated(s, true);
    _SSFTLSCInjectClientHelloForTest(ch1, ch1Len, x25519Priv);
    _SSFTLSCInjectClientHello2ForTest(ch2Opt, ch2Len, p256PrivOpt);
    _utFakeInLen = _utFakeInPos = _utFakeOutLen = 0;
    SSF_ASSERT(t->open(t, "server", sizeof("server"), 443u));
    for (k = 0; (k < 20u) && (_utFakeOutLen == 0u); k++) (void)t->pollOpen(t);
    _SSFTLSCInjectClientHelloForTest(NULL, 0u, NULL);
    SSF_ASSERT(_UTOutRecordLen(0u) == (5u + ch1Len));
    SSF_ASSERT((_utFakeOut[0] == SSF_TLS_CT_HANDSHAKE) && (memcmp(&_utFakeOut[5], ch1, ch1Len) == 0));
}

/* Polls to the end of the handshake with the queued server records; checks the handshake      */
/* traffic secrets while they exist and the application ones after.                            */
static void _UTR8Finish(SSFTLSCSession_t *s, const uint8_t *cHs, const uint8_t *sHs,
                        const uint8_t *cAp, const uint8_t *sAp)
{
    SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;
    bool hsChecked = false;
    uint16_t k;

    for (k = 0; (k < 60u) && ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)); k++)
    {
        r = s->transport.pollOpen(&s->transport);
        if (!hsChecked && (s->hsState == SSF_TLSC_HS_RECV_EE_CERT))
        {
            SSF_ASSERT(memcmp(s->clientHsTrafficSecret, cHs, 32u) == 0);
            SSF_ASSERT(memcmp(s->serverHsTrafficSecret, sHs, 32u) == 0);
            hsChecked = true;
        }
    }
    _SSFTLSCInjectClientHello2ForTest(NULL, 0u, NULL);
    SSF_ASSERT(hsChecked && (r == SSF_NET_IO_SUCCESS));
    SSF_ASSERT(SSFTLSCGetHandshakeState(s) == SSF_TLSC_HS_COMPLETE);
    SSF_ASSERT(memcmp(s->clientAppTrafficSecret, cAp, 32u) == 0);
    SSF_ASSERT(memcmp(s->serverAppTrafficSecret, sAp, 32u) == 0);
}

/* Returns the offset of the next client record at or after *off that is not a CCS, advancing  */
/* *off past it.                                                                                */
static size_t _UTR8NextOut(size_t *off)
{
    size_t at;

    while ((*off < _utFakeOutLen) && (_utFakeOut[*off] == SSF_TLS_CT_CHANGE_CIPHER))
    {
        SSF_ASSERT(_UTOutRecordLen(*off) == 6u);
        *off += 6u;
    }
    at = *off;
    *off += _UTOutRecordLen(at);
    SSF_ASSERT(*off <= _utFakeOutLen);
    return at;
}

/* Ends a replay: the client's close_notify is the trace's record; the server's closes. */
static void _UTR8Close(SSFTLSCSession_t *s, const uint8_t *cAlert, const uint8_t *sAlert)
{
    SSFNetTransport_t *t = &s->transport;
    uint8_t buf[16];
    size_t n;

    _utFakeOutLen = 0;
    SSF_ASSERT(t->shutdown(t) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT((_utFakeOutLen == 24u) && (memcmp(_utFakeOut, cAlert, 24u) == 0));
    _UTQueueRecord(sAlert, 24u);
    SSF_ASSERT((t->recv(t, buf, sizeof(buf), &n) == SSF_NET_IO_CLOSED) && (n == 0u));
    t->close(t);
    SSFTLSCDeInit(s);
}

/* RFC 8448 7: compatibility mode, a 32-byte session id and a server change_cipher_spec after */
/* its ServerHello (the client sends its own after ClientHello, which 5 also allows).          */
static void _SSFTLSCUTRfc8448Compat(void)
{
    SSFTLSCSession_t *s = &_utSession2;
    size_t off = 0;
    size_t at;

    if (!SSF_TLSC_UT_RECORD_FITS(sizeof(_utR8s7FlightRecord))) return;  /* The trace's flight */

    _UTR8Start(s, _utR8s7ClientHello, sizeof(_utR8s7ClientHello), _utR8s7ClientPriv, NULL, 0u,
               NULL);
    _UTQueueRecord(_utR8s7ShRecord, sizeof(_utR8s7ShRecord));
    _UTQueueRecord(_utR8s7CcsRecord, sizeof(_utR8s7CcsRecord));
    _UTQueueRecord(_utR8s7FlightRecord, sizeof(_utR8s7FlightRecord));
    _UTR8Finish(s, _utR8s7CHs, _utR8s7SHs, _utR8s7CAp, _utR8s7SAp);
    (void)_UTR8NextOut(&off);                                     /* ClientHello */
    at = _UTR8NextOut(&off);
    SSF_ASSERT(_UTOutRecordLen(at) == sizeof(_utR8s7ClientFinRecord));
    SSF_ASSERT(memcmp(&_utFakeOut[at], _utR8s7ClientFinRecord, sizeof(_utR8s7ClientFinRecord)) == 0);
    SSF_ASSERT(off == _utFakeOutLen);
    _UTR8Close(s, _utR8s7ClientAlertRecord, _utR8s7ServerAlertRecord);
}

/* RFC 8448 5: ClientHello1 offers x25519 only; the HelloRetryRequest selects secp256r1 with a */
/* cookie; ClientHello2 (injected, with the trace's P-256 key) and the transcript's            */
/* message_hash (RFC 8446 4.4.1) must give the trace's secrets and records.                    */
static void _SSFTLSCUTRfc8448Hrr(void)
{
    SSFTLSCSession_t *s = &_utSession2;
    size_t off = 0;
    size_t at;

    if (!SSF_TLSC_UT_RECORD_FITS(sizeof(_utR8s5FlightRecord))) return;  /* The trace's flight */

    _UTR8Start(s, _utR8s5ClientHello, sizeof(_utR8s5ClientHello), _utR8s5ClientPriv,
               _utR8s5ClientHello2, sizeof(_utR8s5ClientHello2), _utR8s5P256Priv);
    _UTQueueRecord(_utR8s5HrrRecord, sizeof(_utR8s5HrrRecord));
    _UTQueueRecord(_utR8s5ShRecord, sizeof(_utR8s5ShRecord));
    _UTQueueRecord(_utR8s5FlightRecord, sizeof(_utR8s5FlightRecord));
    _UTR8Finish(s, _utR8s5CHs, _utR8s5SHs, _utR8s5CAp, _utR8s5SAp);
    (void)_UTR8NextOut(&off);                                     /* ClientHello1 */
    at = _UTR8NextOut(&off);                                      /* ClientHello2, as given */
    SSF_ASSERT(_UTOutRecordLen(at) == (5u + sizeof(_utR8s5ClientHello2)));
    SSF_ASSERT(memcmp(&_utFakeOut[at + 5u], _utR8s5ClientHello2, sizeof(_utR8s5ClientHello2)) == 0);
    at = _UTR8NextOut(&off);
    SSF_ASSERT(_UTOutRecordLen(at) == sizeof(_utR8s5ClientFinRecord));
    SSF_ASSERT(memcmp(&_utFakeOut[at], _utR8s5ClientFinRecord, sizeof(_utR8s5ClientFinRecord)) == 0);
    SSF_ASSERT(off == _utFakeOutLen);
    _UTR8Close(s, _utR8s5ClientAlertRecord, _utR8s5ServerAlertRecord);
}

/* RFC 8448 6: the server (ECDSA P-256) asks for a client certificate. The trace's client key   */
/* is not published, so the client answers with its own RSA-2048 certificate: everything to the */
/* server Finished, and the application keys, still match the trace; the client's Certificate, */
/* CertificateVerify (rsa_pss_rsae_sha256, as in the trace) and Finished are checked against   */
/* the transcript they extend.                                                                  */
static void _SSFTLSCUTRfc8448ClientAuth(void)
{
    static SSFPKey_t key;
    static uint8_t flight[1024];
    static uint8_t th[2048];
    SSFTLSCSession_t *s = &_utSession2;
    SSFTLSRecordState_t cliHs;
    SSFX509Cert_t cert;
    const size_t certLen = sizeof(_utClientRSA2048Cert);
    size_t flightLen = 0;
    size_t thLen = 0;
    size_t off = 0;
    size_t at;
    size_t n;
    uint8_t ct;
    uint8_t h[32];
    uint8_t vd[32];
    uint16_t sigLen;
    static const char ctx[] = "TLS 1.3, client CertificateVerify";
    static uint8_t content[64 + sizeof(ctx) + 32];

    if (!SSF_TLSC_UT_RECORD_FITS(sizeof(_utR8s6FlightRecord))) return;  /* The trace's flight */

    SSF_ASSERT(SSFPKeyDecodeDER(_utClientRSA2048Key, sizeof(_utClientRSA2048Key), &key));
    _UTR8Start(s, _utR8s6ClientHello, sizeof(_utR8s6ClientHello), _utR8s6ClientPriv, NULL, 0u,
               NULL);
    s->hsState = SSF_TLSC_HS_IDLE;                                /* Set while not open */
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientRSA2048Cert, certLen, &key));
    s->hsState = SSF_TLSC_HS_RECV_SH;
    _UTQueueRecord(_utR8s6ShRecord, sizeof(_utR8s6ShRecord));
    _UTQueueRecord(_utR8s6FlightRecord, sizeof(_utR8s6FlightRecord));
    _UTR8Finish(s, _utR8s6CHs, _utR8s6SHs, _utR8s6CAp, _utR8s6SAp);
    SSF_ASSERT(s->clientScheme == SSF_TLS_SIG_RSA_PSS_RSAE_SHA256);

    /* The client's protected flight under the trace's client handshake key, joined */
    memset(&cliHs, 0, sizeof(cliHs));
    _UTStateFrom(&cliHs, _utR8s6CHs);
    (void)_UTR8NextOut(&off);                                     /* ClientHello */
    while (off < _utFakeOutLen)
    {
        at = _UTR8NextOut(&off);
        SSF_ASSERT(SSFTLSRecordDecrypt(&cliHs, &_utFakeOut[at], _UTOutRecordLen(at),
                                       &flight[flightLen], sizeof(flight) - flightLen, &n, &ct));
        SSF_ASSERT(ct == SSF_TLS_CT_HANDSHAKE);
        flightLen += n;
    }
    SSFTLSRecordStateDeInit(&cliHs);

    /* Certificate: context empty, one entry, no extensions */
    SSF_ASSERT(flightLen > (13u + certLen));
    SSF_ASSERT((flight[0] == SSF_TLS_HS_CERTIFICATE) && (flight[4] == 0u));
    SSF_ASSERT(memcmp(&flight[11], _utClientRSA2048Cert, certLen) == 0);
    SSF_ASSERT((flight[11u + certLen] == 0u) && (flight[12u + certLen] == 0u));
    /* Transcript: the trace's ClientHello, ServerHello and server flight, then this flight */
    memcpy(&th[thLen], _utR8s6ClientHello, sizeof(_utR8s6ClientHello));
    thLen += sizeof(_utR8s6ClientHello);
    memcpy(&th[thLen], &_utR8s6ShRecord[5], sizeof(_utR8s6ShRecord) - 5u);
    thLen += sizeof(_utR8s6ShRecord) - 5u;
    memcpy(&th[thLen], _utR8s6ServerFlight, sizeof(_utR8s6ServerFlight));
    thLen += sizeof(_utR8s6ServerFlight);
    memcpy(&th[thLen], flight, 13u + certLen);
    thLen += 13u + certLen;
    /* CertificateVerify: rsa_pss_rsae_sha256 over the client context, verified with the leaf */
    at = 13u + certLen;
    SSF_ASSERT((flight[at] == SSF_TLS_HS_CERTIFICATE_VERIFY) && (flight[at + 4u] == 0x08u) &&
               (flight[at + 5u] == 0x04u));
    sigLen = (uint16_t)(((uint16_t)flight[at + 6u] << 8) | flight[at + 7u]);
    SSFSHA256(th, (uint32_t)thLen, h, sizeof(h));
    memset(content, 0x20, 64);
    memcpy(&content[64], ctx, sizeof(ctx));
    memcpy(&content[64u + sizeof(ctx)], h, sizeof(h));
    SSFSHA256(content, (uint32_t)sizeof(content), h, sizeof(h));
    SSF_ASSERT(SSFX509Parse(_utClientRSA2048Cert, (uint32_t)certLen, &cert));
    SSF_ASSERT(SSFRSAVerifyPSS(cert.pubKey, cert.pubKeyLen, SSF_RSA_HASH_SHA256, h, 32u, 32u,
                               &flight[at + 8u], sigLen));
    memcpy(&th[thLen], &flight[at], 8u + (size_t)sigLen);
    thLen += 8u + (size_t)sigLen;
    /* Finished over all of it, keyed from the trace's client handshake secret */
    at += 8u + (size_t)sigLen;
    SSF_ASSERT((flightLen == (at + 36u)) && (flight[at] == SSF_TLS_HS_FINISHED));
    SSFSHA256(th, (uint32_t)thLen, h, sizeof(h));
    SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256, _utR8s6CHs, 32u, h, 32u, vd, sizeof(vd));
    SSF_ASSERT(memcmp(&flight[at + 4u], vd, 32u) == 0);

    /* The application keys match the trace, so its close_notify records do too */
    _UTR8Close(s, _utR8s6ClientAlertRecord, _utR8s6ServerAlertRecord);
}

/* --------------------------------------------------------------------------------------------- */
/* Negative tests on the server flight (step 2 checks), built on the RFC 8448 3 replay: the test */
/* knows the server's handshake key, so it changes the flight's plaintext, re-encrypts it and   */
/* feeds it. Each case: the alert the client sends (decrypted with the trace's client handshake */
/* key), no application keys, and every secret and buffer of the session wiped.                 */
/* --------------------------------------------------------------------------------------------- */
/* RFC 8448 3: the server's protected flight as plaintext: EncryptedExtensions (40), Certificate */
/* (445), CertificateVerify (136), Finished (36) */
static const uint8_t _utR8FlightPayload[657] = {
    0x08, 0x00, 0x00, 0x24, 0x00, 0x22, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12,
    0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01,
    0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0xb9, 0x00, 0x00, 0x01, 0xb5,
    0x00, 0x01, 0xb0, 0x30, 0x82, 0x01, 0xac, 0x30, 0x82, 0x01, 0x15, 0xa0,
    0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x0e,
    0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72,
    0x73, 0x61, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x37, 0x33, 0x30,
    0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30,
    0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x30, 0x0e,
    0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72,
    0x73, 0x61, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00,
    0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xbb, 0x49, 0x8f, 0x82,
    0x79, 0x30, 0x3d, 0x98, 0x08, 0x36, 0x39, 0x9b, 0x36, 0xc6, 0x98, 0x8c,
    0x0c, 0x68, 0xde, 0x55, 0xe1, 0xbd, 0xb8, 0x26, 0xd3, 0x90, 0x1a, 0x24,
    0x61, 0xea, 0xfd, 0x2d, 0xe4, 0x9a, 0x91, 0xd0, 0x15, 0xab, 0xbc, 0x9a,
    0x95, 0x13, 0x7a, 0xce, 0x6c, 0x1a, 0xf1, 0x9e, 0xaa, 0x6a, 0xf9, 0x8c,
    0x7c, 0xed, 0x43, 0x12, 0x09, 0x98, 0xe1, 0x87, 0xa8, 0x0e, 0xe0, 0xcc,
    0xb0, 0x52, 0x4b, 0x1b, 0x01, 0x8c, 0x3e, 0x0b, 0x63, 0x26, 0x4d, 0x44,
    0x9a, 0x6d, 0x38, 0xe2, 0x2a, 0x5f, 0xda, 0x43, 0x08, 0x46, 0x74, 0x80,
    0x30, 0x53, 0x0e, 0xf0, 0x46, 0x1c, 0x8c, 0xa9, 0xd9, 0xef, 0xbf, 0xae,
    0x8e, 0xa6, 0xd1, 0xd0, 0x3e, 0x2b, 0xd1, 0x93, 0xef, 0xf0, 0xab, 0x9a,
    0x80, 0x02, 0xc4, 0x74, 0x28, 0xa6, 0xd3, 0x5a, 0x8d, 0x88, 0xd7, 0x9f,
    0x7f, 0x1e, 0x3f, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x1a, 0x30, 0x18,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30,
    0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x85, 0xaa, 0xd2, 0xa0, 0xe5,
    0xb9, 0x27, 0x6b, 0x90, 0x8c, 0x65, 0xf7, 0x3a, 0x72, 0x67, 0x17, 0x06,
    0x18, 0xa5, 0x4c, 0x5f, 0x8a, 0x7b, 0x33, 0x7d, 0x2d, 0xf7, 0xa5, 0x94,
    0x36, 0x54, 0x17, 0xf2, 0xea, 0xe8, 0xf8, 0xa5, 0x8c, 0x8f, 0x81, 0x72,
    0xf9, 0x31, 0x9c, 0xf3, 0x6b, 0x7f, 0xd6, 0xc5, 0x5b, 0x80, 0xf2, 0x1a,
    0x03, 0x01, 0x51, 0x56, 0x72, 0x60, 0x96, 0xfd, 0x33, 0x5e, 0x5e, 0x67,
    0xf2, 0xdb, 0xf1, 0x02, 0x70, 0x2e, 0x60, 0x8c, 0xca, 0xe6, 0xbe, 0xc1,
    0xfc, 0x63, 0xa4, 0x2a, 0x99, 0xbe, 0x5c, 0x3e, 0xb7, 0x10, 0x7c, 0x3c,
    0x54, 0xe9, 0xb9, 0xeb, 0x2b, 0xd5, 0x20, 0x3b, 0x1c, 0x3b, 0x84, 0xe0,
    0xa8, 0xb2, 0xf7, 0x59, 0x40, 0x9b, 0xa3, 0xea, 0xc9, 0xd9, 0x1d, 0x40,
    0x2d, 0xcc, 0x0c, 0xc8, 0xf8, 0x96, 0x12, 0x29, 0xac, 0x91, 0x87, 0xb4,
    0x2b, 0x4d, 0xe1, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x84, 0x08, 0x04, 0x00,
    0x80, 0x5a, 0x74, 0x7c, 0x5d, 0x88, 0xfa, 0x9b, 0xd2, 0xe5, 0x5a, 0xb0,
    0x85, 0xa6, 0x10, 0x15, 0xb7, 0x21, 0x1f, 0x82, 0x4c, 0xd4, 0x84, 0x14,
    0x5a, 0xb3, 0xff, 0x52, 0xf1, 0xfd, 0xa8, 0x47, 0x7b, 0x0b, 0x7a, 0xbc,
    0x90, 0xdb, 0x78, 0xe2, 0xd3, 0x3a, 0x5c, 0x14, 0x1a, 0x07, 0x86, 0x53,
    0xfa, 0x6b, 0xef, 0x78, 0x0c, 0x5e, 0xa2, 0x48, 0xee, 0xaa, 0xa7, 0x85,
    0xc4, 0xf3, 0x94, 0xca, 0xb6, 0xd3, 0x0b, 0xbe, 0x8d, 0x48, 0x59, 0xee,
    0x51, 0x1f, 0x60, 0x29, 0x57, 0xb1, 0x54, 0x11, 0xac, 0x02, 0x76, 0x71,
    0x45, 0x9e, 0x46, 0x44, 0x5c, 0x9e, 0xa5, 0x8c, 0x18, 0x1e, 0x81, 0x8e,
    0x95, 0xb8, 0xc3, 0xfb, 0x0b, 0xf3, 0x27, 0x84, 0x09, 0xd3, 0xbe, 0x15,
    0x2a, 0x3d, 0xa5, 0x04, 0x3e, 0x06, 0x3d, 0xda, 0x65, 0xcd, 0xf5, 0xae,
    0xa2, 0x0d, 0x53, 0xdf, 0xac, 0xd4, 0x2f, 0x74, 0xf3, 0x14, 0x00, 0x00,
    0x20, 0x9b, 0x9b, 0x14, 0x1d, 0x90, 0x63, 0x37, 0xfb, 0xd2, 0xcb, 0xdc,
    0xe7, 0x1d, 0xf4, 0xde, 0xda, 0x4a, 0xb4, 0x2c, 0x30, 0x95, 0x72, 0xcb,
    0x7f, 0xff, 0xee, 0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18
};
#define SSF_TLSC_UT_R8_EE_LEN (40u)
#define SSF_TLSC_UT_R8_CERT_LEN (445u)
#define SSF_TLSC_UT_R8_CV_LEN (136u)

/* Offsets of the flight's messages */
#define SSF_TLSC_UT_R8_CERT_AT (SSF_TLSC_UT_R8_EE_LEN)
#define SSF_TLSC_UT_R8_CV_AT (SSF_TLSC_UT_R8_CERT_AT + SSF_TLSC_UT_R8_CERT_LEN)
#define SSF_TLSC_UT_R8_FIN_AT (SSF_TLSC_UT_R8_CV_AT + SSF_TLSC_UT_R8_CV_LEN)

/* Scrub hook: counts the wipes reported by name and checks each buffer is zero when reported. */
#define SSF_TLSC_UT_MAX_SCRUBS (64u)
static const char *_utScrubWhat[SSF_TLSC_UT_MAX_SCRUBS];
static uint8_t _utScrubCount;
static void _UTScrubRecord(void *ctx, const char *what, const void *buf, size_t len)
{
    size_t i;

    (void)ctx;
    for (i = 0; i < len; i++) SSF_ASSERT(((const uint8_t *)buf)[i] == 0u);
    if (_utScrubCount < SSF_TLSC_UT_MAX_SCRUBS) _utScrubWhat[_utScrubCount++] = what;
}
static bool _UTScrubbed(const char *what)
{
    uint8_t i;

    for (i = 0; i < _utScrubCount; i++) { if (strcmp(_utScrubWhat[i], what) == 0) return true; }
    return false;
}

/* True if buf[0..len) is all zero. */
static bool _UTZero(const void *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) { if (((const uint8_t *)buf)[i] != 0u) return false; }
    return true;
}

/* Every secret, key and plaintext buffer of a session is zero (after a failure or a close). */
static void _UTSessionWiped(const SSFTLSCSession_t *s)
{
    SSF_ASSERT(_UTZero(s->ephemeralPrivKey, sizeof(s->ephemeralPrivKey)));
    SSF_ASSERT(_UTZero(s->savedHandshakeSecret, sizeof(s->savedHandshakeSecret)));
    SSF_ASSERT(_UTZero(s->clientHsTrafficSecret, sizeof(s->clientHsTrafficSecret)));
    SSF_ASSERT(_UTZero(s->serverHsTrafficSecret, sizeof(s->serverHsTrafficSecret)));
    SSF_ASSERT(_UTZero(s->clientAppTrafficSecret, sizeof(s->clientAppTrafficSecret)));
    SSF_ASSERT(_UTZero(s->serverAppTrafficSecret, sizeof(s->serverAppTrafficSecret)));
    SSF_ASSERT(_UTZero(s->hsBuf, sizeof(s->hsBuf)));
    SSF_ASSERT(_UTZero(s->recvBuf, sizeof(s->recvBuf)));
    SSF_ASSERT(!s->sendStateInited && !s->recvStateInited);
}

/* Replays RFC 8448 3 with the server flight flight[0..len) (corruptRecord: also flip a byte of */
/* its ciphertext); returns the alert the client sent, 0 if the handshake completed.           */
static uint8_t _UTR8FlightAlert(const uint8_t *flight, size_t len, bool corruptRecord)
{
    SSFTLSCSession_t *s = &_utSession2;
    SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;
    SSFTLSRecordState_t st;
    uint8_t pt[16];
    size_t n;
    size_t off = 0;
    size_t at;
    uint8_t ct;
    uint8_t alert;
    uint16_t k;

    _UTR8Start(s, _utR8ClientHello, sizeof(_utR8ClientHello), _utR8ClientPriv, NULL, 0u, NULL);
    _UTQueueRecord(_utR8ShRecord, sizeof(_utR8ShRecord));
    memset(&st, 0, sizeof(st));
    _UTStateFrom(&st, _utR8SHsTraffic);
    SSF_ASSERT(SSFTLSRecordEncrypt(&st, SSF_TLS_CT_HANDSHAKE, flight, len,
                                   &_utFakeIn[_utFakeInLen], sizeof(_utFakeIn) - _utFakeInLen, &n));
    SSFTLSRecordStateDeInit(&st);
    if (corruptRecord) _utFakeIn[_utFakeInLen + 5u + 10u] ^= 0x01u;
    _utFakeInLen += n;
    for (k = 0; (k < 60u) && ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)); k++)
    {
        r = s->transport.pollOpen(&s->transport);
    }
    if (r == SSF_NET_IO_SUCCESS)
    {
        s->transport.close(&s->transport);
        SSFTLSCDeInit(s);
        return 0u;
    }
    SSF_ASSERT(r == SSF_NET_IO_ERROR);
    /* The failure wiped the session at once, before close() */
    _UTSessionWiped(s);
    /* After ClientHello (and the CCS): one alert, protected with the client handshake key */
    (void)_UTR8NextOut(&off);
    at = _UTR8NextOut(&off);
    SSF_ASSERT(off == _utFakeOutLen);
    memset(&st, 0, sizeof(st));
    _UTStateFrom(&st, _utR8CHsTraffic);
    SSF_ASSERT(SSFTLSRecordDecrypt(&st, &_utFakeOut[at], _UTOutRecordLen(at), pt, sizeof(pt), &n,
                                   &ct));
    SSFTLSRecordStateDeInit(&st);
    SSF_ASSERT((ct == SSF_TLS_CT_ALERT) && (n == 2u) && (pt[0] == 2u));
    alert = pt[1];
    s->transport.close(&s->transport);
    SSFTLSCDeInit(s);
    return alert;
}

/* Recomputes the server Finished at f[finAt..] (verify_data) over the trace's ClientHello and */
/* ServerHello and f[0..finAt), so a change before it is caught by its own check, not the     */
/* Finished's.                                                                                 */
static void _UTR8FixFinished(uint8_t *f, size_t finAt)
{
    static uint8_t th[1024];
    size_t n = 0;
    uint8_t h[32];

    memcpy(&th[n], _utR8ClientHello, sizeof(_utR8ClientHello)); n += sizeof(_utR8ClientHello);
    memcpy(&th[n], &_utR8ShRecord[5], sizeof(_utR8ShRecord) - 5u); n += sizeof(_utR8ShRecord) - 5u;
    SSF_ASSERT((n + finAt) <= sizeof(th));
    memcpy(&th[n], f, finAt); n += finAt;
    SSFSHA256(th, (uint32_t)n, h, sizeof(h));
    SSFTLSComputeFinished(SSF_HMAC_HASH_SHA256, _utR8SHsTraffic, 32u, h, 32u, &f[finAt + 4u], 32u);
}

static void _SSFTLSCUTServerFlightNegative(void)
{
    static uint8_t f[sizeof(_utR8FlightPayload) + 16u];
    const size_t L = sizeof(_utR8FlightPayload);
    const size_t cv = SSF_TLSC_UT_R8_CV_AT;
    const size_t fin = SSF_TLSC_UT_R8_FIN_AT;
    const size_t cert = SSF_TLSC_UT_R8_CERT_AT;

    /* The trace's flight, re-encrypted, a few bytes longer in some cases */
    if (!SSF_TLSC_UT_RECORD_FITS(sizeof(_utR8FlightRecord) + 16u)) return;

    /* ---- Control: the flight unchanged completes, with the trace's secrets wiped as used ---- */
    _utScrubCount = 0;
    _SSFTLSCScrubTestHook = _UTScrubRecord;
    SSF_ASSERT(_UTR8FlightAlert(_utR8FlightPayload, L, false) == 0u);
    _SSFTLSCScrubTestHook = NULL;
    SSF_ASSERT(_UTScrubbed("ephemeralPrivKey") && _UTScrubbed("sharedSecret") &&
               _UTScrubbed("ecdhSecret") && _UTScrubbed("earlySecret") &&
               _UTScrubbed("derivedSecret") && _UTScrubbed("handshakeSecret") &&
               _UTScrubbed("masterSecret") && _UTScrubbed("savedHandshakeSecret") &&
               _UTScrubbed("clientHsTrafficSecret") && _UTScrubbed("serverHsTrafficSecret") &&
               _UTScrubbed("key") && _UTScrubbed("iv"));

    /* ---- Finished: one bit of verify_data; one byte too long ---- */
    memcpy(f, _utR8FlightPayload, L); f[fin + 4u + 7u] ^= 0x01u;
    SSF_ASSERT(_UTR8FlightAlert(f, L, false) == SSF_TLS_ALERT_DECRYPT_ERROR);
    memcpy(f, _utR8FlightPayload, L); f[fin + 3u] = 0x21u; f[L] = 0x00u;
    SSF_ASSERT(_UTR8FlightAlert(f, L + 1u, false) == SSF_TLS_ALERT_DECODE_ERROR);

    /* ---- CertificateVerify: one bit of the signature; PKCS#1 (never in TLS 1.3); ECDSA ---- */
    /* ---- with the RSA certificate                                                       ---- */
    memcpy(f, _utR8FlightPayload, L);
    _UTR8FixFinished(f, fin);                                     /* Unchanged: still valid */
    SSF_ASSERT(memcmp(f, _utR8FlightPayload, L) == 0);
    f[cv + 8u + 20u] ^= 0x01u;
    _UTR8FixFinished(f, fin);                  /* A Finished that agrees: only the signature is bad */
    SSF_ASSERT(_UTR8FlightAlert(f, L, false) == SSF_TLS_ALERT_DECRYPT_ERROR);
    memcpy(f, _utR8FlightPayload, L); f[cv + 4u] = 0x04u; f[cv + 5u] = 0x01u;
    SSF_ASSERT(_UTR8FlightAlert(f, L, false) == SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    memcpy(f, _utR8FlightPayload, L); f[cv + 4u] = 0x04u; f[cv + 5u] = 0x03u;
    SSF_ASSERT(_UTR8FlightAlert(f, L, false) == SSF_TLS_ALERT_ILLEGAL_PARAMETER);

    /* ---- Certificate: DER that does not parse; an empty list (RFC 8446 4.4.2.4) ---- */
    memcpy(f, _utR8FlightPayload, L); f[cert + 11u] = 0x31u;      /* Not a SEQUENCE */
    SSF_ASSERT(_UTR8FlightAlert(f, L, false) == SSF_TLS_ALERT_BAD_CERTIFICATE);
    {
        static const uint8_t empty[] = { SSF_TLS_HS_CERTIFICATE, 0x00, 0x00, 0x04,
                                         0x00, 0x00, 0x00, 0x00 };
        size_t n = 0;

        memcpy(&f[n], _utR8FlightPayload, cert); n += cert;
        memcpy(&f[n], empty, sizeof(empty)); n += sizeof(empty);
        memcpy(&f[n], &_utR8FlightPayload[cv], L - cv); n += L - cv;
        SSF_ASSERT(_UTR8FlightAlert(f, n, false) == SSF_TLS_ALERT_DECODE_ERROR);
    }

    /* ---- EncryptedExtensions with an extension the client did not offer ---- */
    {
        size_t n = 0;

        f[n++] = SSF_TLS_HS_ENCRYPTED_EXTENSIONS; f[n++] = 0x00;
        f[n++] = _utR8FlightPayload[2]; f[n++] = (uint8_t)(_utR8FlightPayload[3] + 4u);
        f[n++] = _utR8FlightPayload[4]; f[n++] = (uint8_t)(_utR8FlightPayload[5] + 4u);
        f[n++] = 0xfa; f[n++] = 0xfa; f[n++] = 0x00; f[n++] = 0x00;
        memcpy(&f[n], &_utR8FlightPayload[6], L - 6u); n += L - 6u;
        SSF_ASSERT(_UTR8FlightAlert(f, n, false) == SSF_TLS_ALERT_UNSUPPORTED_EXT);
    }

    /* ---- Order: CertificateVerify before Certificate; a message after the Finished (keys ---- */
    /* ---- change at the Finished, which must end its record: RFC 8446 5.1)                ---- */
    {
        size_t n = 0;

        memcpy(&f[n], _utR8FlightPayload, cert); n += cert;
        memcpy(&f[n], &_utR8FlightPayload[cv], SSF_TLSC_UT_R8_CV_LEN); n += SSF_TLSC_UT_R8_CV_LEN;
        memcpy(&f[n], &_utR8FlightPayload[cert], SSF_TLSC_UT_R8_CERT_LEN);
        n += SSF_TLSC_UT_R8_CERT_LEN;
        memcpy(&f[n], &_utR8FlightPayload[fin], L - fin); n += L - fin;
        SSF_ASSERT(_UTR8FlightAlert(f, n, false) == SSF_TLS_ALERT_UNEXPECTED_MSG);
    }
    memcpy(f, _utR8FlightPayload, L);
    f[L] = 0x04u; f[L + 1u] = 0x00u; f[L + 2u] = 0x00u; f[L + 3u] = 0x00u;
    SSF_ASSERT(_UTR8FlightAlert(f, L + 4u, false) == SSF_TLS_ALERT_UNEXPECTED_MSG);

    /* ---- The record itself: one bit of the ciphertext ---- */
    SSF_ASSERT(_UTR8FlightAlert(_utR8FlightPayload, L, true) == SSF_TLS_ALERT_BAD_RECORD_MAC);

    /* ---- After a completed handshake and close(), nothing of the session remains ---- */
    {
        SSFTLSCSession_t *s = &_utSession2;
        SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;
        SSFTLSRecordState_t st;
        uint16_t k;

        _UTR8Start(s, _utR8ClientHello, sizeof(_utR8ClientHello), _utR8ClientPriv, NULL, 0u,
                   NULL);
        _UTQueueRecord(_utR8ShRecord, sizeof(_utR8ShRecord));
        _UTQueueRecord(_utR8FlightRecord, sizeof(_utR8FlightRecord));
        for (k = 0; (k < 60u) && ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)); k++)
        {
            r = s->transport.pollOpen(&s->transport);
        }
        SSF_ASSERT(r == SSF_NET_IO_SUCCESS);
        /* Handshake secrets are gone already; the application ones stay for KeyUpdate */
        SSF_ASSERT(_UTZero(s->clientHsTrafficSecret, sizeof(s->clientHsTrafficSecret)));
        SSF_ASSERT(_UTZero(s->serverHsTrafficSecret, sizeof(s->serverHsTrafficSecret)));
        SSF_ASSERT(_UTZero(s->savedHandshakeSecret, sizeof(s->savedHandshakeSecret)));
        SSF_ASSERT(_UTZero(s->ephemeralPrivKey, sizeof(s->ephemeralPrivKey)));
        SSF_ASSERT(!_UTZero(s->clientAppTrafficSecret, sizeof(s->clientAppTrafficSecret)));
        (void)st;
        s->transport.close(&s->transport);
        _UTSessionWiped(s);
        SSFTLSCDeInit(s);
    }
}

/* A session mid-handshake: handshake keys active (generation 0 test keys), waiting for        */
/* EncryptedExtensions, not yet connected: where an on-path party would inject plaintext.      */
static void _UTMidHandshakeSession(SSFTLSCSession_t *s)
{
    _UTAppSession(s);
    s->connected = false;
    s->hsState = SSF_TLSC_HS_RECV_EE_CERT;
    s->helperStep = 0;
    SSFTLSTranscriptInit(&s->transcript, SSF_HMAC_HASH_SHA256);
}

/* Polls once the queued records are in; returns the pollOpen() result. */
static SSFNetIOResult_t _UTMidPoll(SSFTLSCSession_t *s)
{
    SSFNetIOResult_t r = SSF_NET_IO_WANT_READ;
    uint8_t k;

    for (k = 0; (k < 8u) && ((r == SSF_NET_IO_WANT_READ) || (r == SSF_NET_IO_WANT_WRITE)) &&
                (_utFakeInPos < _utFakeInLen); k++)
    {
        r = s->transport.pollOpen(&s->transport);
    }
    return r;
}

/* Queues a plaintext record of type ct. */
static void _UTPlainRecord(uint8_t ct, const uint8_t *data, size_t len)
{
    SSF_ASSERT((_utFakeInLen + 5u + len) <= sizeof(_utFakeIn));
    _utFakeIn[_utFakeInLen++] = ct;
    _utFakeIn[_utFakeInLen++] = 0x03; _utFakeIn[_utFakeInLen++] = 0x03;
    _utFakeIn[_utFakeInLen++] = (uint8_t)(len >> 8); _utFakeIn[_utFakeInLen++] = (uint8_t)len;
    memcpy(&_utFakeIn[_utFakeInLen], data, len);
    _utFakeInLen += len;
}

/* Between the ServerHello and the server Finished: keys are active, the handshake still runs. */
/* A plaintext handshake or alert record is unexpected_message (it would be an injected       */
/* message or a forged alert); the compatibility change_cipher_spec, one byte 0x01, is dropped */
/* and the handshake goes on; any other change_cipher_spec is unexpected_message.             */
static void _SSFTLSCUTMidHandshakeRecords(void)
{
    static const uint8_t ee[] = { SSF_TLS_HS_ENCRYPTED_EXTENSIONS, 0x00, 0x00, 0x02, 0x00, 0x00 };
    static const uint8_t closeNotify[] = { 0x01, 0x00 };
    static const uint8_t ccs1[] = { 0x01 };
    static const uint8_t ccs2[] = { 0x01, 0x01 };
    static const uint8_t ccsBad[] = { 0x02 };
    SSFTLSCSession_t *s = &_utSession2;
    uint8_t k;

    /* ---- Injected plaintext: an EncryptedExtensions, a close_notify ---- */
    for (k = 0; k < 2u; k++)
    {
        _UTMidHandshakeSession(s);
        if (k == 0u) _UTPlainRecord(SSF_TLS_CT_HANDSHAKE, ee, sizeof(ee));
        else _UTPlainRecord(SSF_TLS_CT_ALERT, closeNotify, sizeof(closeNotify));
        SSF_ASSERT(_UTMidPoll(s) == SSF_NET_IO_ERROR);
        SSF_ASSERT(s->pendingAlert == SSF_TLS_ALERT_UNEXPECTED_MSG);
        SSFTLSCDeInit(s);
        SSFTLSRecordStateDeInit(&_utSrvSend);
        SSFTLSRecordStateDeInit(&_utSrvRecv);
    }

    /* ---- The compatibility change_cipher_spec, then the real (protected) EE: accepted ---- */
    _UTMidHandshakeSession(s);
    _UTPlainRecord(SSF_TLS_CT_CHANGE_CIPHER, ccs1, sizeof(ccs1));
    _UTSrvRecord(SSF_TLS_CT_HANDSHAKE, ee, sizeof(ee));
    SSF_ASSERT(_UTMidPoll(s) == SSF_NET_IO_WANT_READ);
    SSF_ASSERT((s->pendingAlert == 0u) && (s->hsState == SSF_TLSC_HS_RECV_EE_CERT) &&
               (s->helperStep == 2u));                            /* Now waiting for Certificate */
    SSFTLSCDeInit(s);
    SSFTLSRecordStateDeInit(&_utSrvSend);
    SSFTLSRecordStateDeInit(&_utSrvRecv);

    /* ---- A change_cipher_spec of two bytes, or of another value ---- */
    for (k = 0; k < 2u; k++)
    {
        _UTMidHandshakeSession(s);
        if (k == 0u) _UTPlainRecord(SSF_TLS_CT_CHANGE_CIPHER, ccs2, sizeof(ccs2));
        else _UTPlainRecord(SSF_TLS_CT_CHANGE_CIPHER, ccsBad, sizeof(ccsBad));
        SSF_ASSERT(_UTMidPoll(s) == SSF_NET_IO_ERROR);
        SSF_ASSERT(s->pendingAlert == SSF_TLS_ALERT_UNEXPECTED_MSG);
        SSFTLSCDeInit(s);
        SSFTLSRecordStateDeInit(&_utSrvSend);
        SSFTLSRecordStateDeInit(&_utSrvRecv);
    }
}

static void _SSFTLSCUTPlainOverflow(void)
{
    /* Over 2^14: the server's error, whatever this build's receive size */
    SSF_ASSERT(_UTPlainRecordAlert(16385u) == SSF_TLS_ALERT_RECORD_OVERFLOW);
    SSF_ASSERT(_UTPlainRecordAlert(16384u + 1u + SSF_TLS_AEAD_TAG_SIZE) ==
               SSF_TLS_ALERT_RECORD_OVERFLOW);
    SSF_ASSERT(_UTPlainRecordAlert(16384u + 2u + SSF_TLS_AEAD_TAG_SIZE) ==
               SSF_TLS_ALERT_RECORD_OVERFLOW);
    /* Up to 2^14 is legal. Within hsBuf (receive size + 1) it is parsed, here refused as a */
    /* ServerHello; beyond hsBuf, or beyond the record buffer (receive size + 17, caught at */
    /* the header), it is this build's limit: internal_error.                                */
    {
        size_t fits = SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u;
        uint8_t a;

        if (fits > 16384u) fits = 16384u;
        a = _UTPlainRecordAlert(fits);
        SSF_ASSERT((a != SSF_TLS_ALERT_RECORD_OVERFLOW) && (a != SSF_TLS_ALERT_INTERNAL_ERROR));
    }
#if (SSF_TLSC_CONFIG_MAX_RECV_RECORD + 2u) <= 16384u
    SSF_ASSERT(_UTPlainRecordAlert(SSF_TLSC_CONFIG_MAX_RECV_RECORD + 2u) ==
               SSF_TLS_ALERT_INTERNAL_ERROR);
    SSF_ASSERT(_UTPlainRecordAlert(16384u) == SSF_TLS_ALERT_INTERNAL_ERROR);
#endif
#if (SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u + SSF_TLS_AEAD_TAG_SIZE + 1u) <= 16384u
    SSF_ASSERT(_UTPlainRecordAlert(SSF_TLSC_CONFIG_MAX_RECV_RECORD + 1u +
                                   SSF_TLS_AEAD_TAG_SIZE + 1u) == SSF_TLS_ALERT_INTERNAL_ERROR);
#endif

    /* Protected records (application_data outside), judged at the header: over 2^14 + 1 +   */
    /* the tag is record_overflow; over this build's buffer but within it, record_overflow   */
    /* only once the server accepted our record_size_limit (RFC 8449 4), else internal_error. */
    {
        SSFTLSCSession_t *s = &_utSession2;
        uint8_t buf[16];
        size_t n;
        uint8_t k;

        for (k = 0; k < 4u; k++)
        {
            size_t len = (k < 2u) ? (16384u + 2u + SSF_TLS_AEAD_TAG_SIZE) :
                                    (SSF_TLSC_CONFIG_MAX_RECV_RECORD + 2u + SSF_TLS_AEAD_TAG_SIZE);
            uint8_t want = SSF_TLS_ALERT_RECORD_OVERFLOW;

            /* Over this build's buffer yet within the RFC maximum: small receive builds only */
            if ((k >= 2u) && (len > (16384u + 1u + SSF_TLS_AEAD_TAG_SIZE))) continue;
            if (k == 2u) want = SSF_TLS_ALERT_INTERNAL_ERROR;
            _UTAppSession(s);
            s->peerRecordLimit = ((k & 1u) != 0u) ? 1024u : 0u;
            _utFakeIn[0] = SSF_TLS_CT_APPLICATION; _utFakeIn[1] = 0x03; _utFakeIn[2] = 0x03;
            _utFakeIn[3] = (uint8_t)(len >> 8); _utFakeIn[4] = (uint8_t)len;
            _utFakeInLen = 5u;
            SSF_ASSERT(s->transport.recv(&s->transport, buf, sizeof(buf), &n) == SSF_NET_IO_ERROR);
            SSF_ASSERT(s->pendingAlert == want);
            SSFTLSCDeInit(s);
            SSFTLSRecordStateDeInit(&_utSrvSend);
            SSFTLSRecordStateDeInit(&_utSrvRecv);
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* ServerHello / HelloRetryRequest extensions (RFC 8446 4.2) against a ClientHello1 the hook     */
/* builds: session id 32 x 0x22, shares x25519 and secp384r1.                                    */
/* --------------------------------------------------------------------------------------------- */
/* Builds a ServerHello body (TLS_AES_128_GCM_SHA256) with supported_versions, key_share (an     */
/* x25519 share, or secp256r1 selected for an HRR) and then extra[0..extraLen). Returns length. */
static size_t _UTShBody(uint8_t *out, bool isHrr, const uint8_t *extra, size_t extraLen)
{
    size_t p = 0;
    size_t extStart;

    out[p++] = 0x03; out[p++] = 0x03;
    memset(&out[p], isHrr ? 0xcfu : 0x5au, 32u); p += 32u;             /* random: not checked here */
    out[p++] = 32u; memset(&out[p], 0x22, 32u); p += 32u;               /* session id echo */
    out[p++] = 0x13; out[p++] = 0x01;                                    /* cipher_suite */
    out[p++] = 0x00;                                                     /* compression */
    extStart = p; p += 2u;
    out[p++] = 0x00; out[p++] = 0x2b; out[p++] = 0x00; out[p++] = 0x02;  /* supported_versions */
    out[p++] = 0x03; out[p++] = 0x04;
    out[p++] = 0x00; out[p++] = 0x33;                                    /* key_share */
    if (isHrr) { out[p++] = 0x00; out[p++] = 0x02; out[p++] = 0x00; out[p++] = 0x17; }
    else
    {
        out[p++] = 0x00; out[p++] = 0x24; out[p++] = 0x00; out[p++] = 0x1d;
        out[p++] = 0x00; out[p++] = 0x20; memset(&out[p], 0x09, 32u); p += 32u;
    }
    memcpy(&out[p], extra, extraLen); p += extraLen;
    out[extStart] = (uint8_t)((p - extStart - 2u) >> 8);
    out[extStart + 1u] = (uint8_t)(p - extStart - 2u);
    return p;
}

#define SSF_TLSC_UT_SH(isHrr, extra, wantAlert) do { \
    uint8_t _a = 0xffu; size_t _n = _UTShBody(sh, (isHrr), (extra), sizeof(extra)); \
    bool _ok = _SSFTLSCParseServerHelloForTest(&_utSession2, sh, _n, (isHrr), &_a); \
    SSF_ASSERT(_ok == ((wantAlert) == 0u)); \
    SSF_ASSERT(_a == (wantAlert)); } while (0)

/* Extensions the client recognizes (it sends them), none specified for ServerHello: */
/* illegal_parameter (4.2)                                                          */
static const uint8_t _utShSni[]      = { 0x00, 0x00, 0x00, 0x00 };
static const uint8_t _utShGroups[]   = { 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d };
static const uint8_t _utShSigAlgs[]  = { 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03 };
static const uint8_t _utShPskModes[] = { 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01 };
static const uint8_t _utShRsl[]      = { 0x00, 0x1c, 0x00, 0x02, 0x40, 0x00 };
static const uint8_t _utShAlpn[]     = { 0x00, 0x10, 0x00, 0x07, 0x00, 0x05, 0x04,
                                         'm', 'q', 't', 't' };
static const uint8_t _utShCookie[]   = { 0x00, 0x2c, 0x00, 0x03, 0x00, 0x01, 0xaa };
/* Not sent by the client: unsupported_extension (4.2) */
static const uint8_t _utShPsk[]      = { 0x00, 0x29, 0x00, 0x02, 0x00, 0x00 };
static const uint8_t _utShEarly[]    = { 0x00, 0x2a, 0x00, 0x00 };
static const uint8_t _utShStatus[]   = { 0x00, 0x05, 0x00, 0x00 };
static const uint8_t _utShUnknown[]  = { 0xfa, 0xfa, 0x00, 0x00 };
static const uint8_t _utShNone[]     = { 0x00 };                 /* sizeof 1: trimmed below */
/* Duplicates of the allowed ones: illegal_parameter */
static const uint8_t _utShDupVer[]   = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
static const uint8_t _utShDupCookie[] = { 0x00, 0x2c, 0x00, 0x03, 0x00, 0x01, 0xaa,
                                          0x00, 0x2c, 0x00, 0x03, 0x00, 0x01, 0xbb };

/* --------------------------------------------------------------------------------------------- */
/* ServerHello / HelloRetryRequest parser, every check (RFC 8446 4.1.3, 4.1.4, 4.2.1, 4.2.8,     */
/* 4.2.2): against the hook's ClientHello1 (session id 32 x 0x22, x25519 and secp384r1 shares),  */
/* or after a HelloRetryRequest that chose secp256r1 and TLS_AES_128_GCM_SHA256.                */
/* --------------------------------------------------------------------------------------------- */
/* Builds a body: session id sidLen x sidByte, suite, compression, then the extension block     */
/* ext[0..extLen) (its length field included only when withExts).                               */
static size_t _UTShRaw(uint8_t *out, uint8_t sidLen, uint8_t sidByte, uint16_t suite,
                       uint8_t comp, bool withExts, const uint8_t *ext, size_t extLen)
{
    size_t p = 0;

    out[p++] = 0x03; out[p++] = 0x03;
    memset(&out[p], 0x5a, 32u); p += 32u;
    out[p++] = sidLen; memset(&out[p], sidByte, sidLen); p += sidLen;
    out[p++] = (uint8_t)(suite >> 8); out[p++] = (uint8_t)suite;
    out[p++] = comp;
    if (withExts)
    {
        out[p++] = (uint8_t)(extLen >> 8); out[p++] = (uint8_t)extLen;
        if (extLen > 0u) { memcpy(&out[p], ext, extLen); p += extLen; }
    }
    return p;
}

/* Appends an extension of type, its data (len bytes of fill, or data) to ext / *extLen. */
static void _UTExt(uint8_t *ext, size_t *extLen, uint16_t type, const uint8_t *data, size_t len)
{
    ext[(*extLen)++] = (uint8_t)(type >> 8); ext[(*extLen)++] = (uint8_t)type;
    ext[(*extLen)++] = (uint8_t)(len >> 8); ext[(*extLen)++] = (uint8_t)len;
    if (len > 0u) { memcpy(&ext[*extLen], data, len); *extLen += len; }
}

/* supported_versions TLS 1.3, then a ServerHello key_share for group with a kLen-byte key */
/* (its length field kLenField), or an HRR key_share of group alone when kLen is 0.        */
static size_t _UTShExts(uint8_t *ext, uint16_t group, uint16_t kLen, uint16_t kLenField)
{
    static const uint8_t v13[] = { 0x03, 0x04 };
    uint8_t ks[4 + 97];
    size_t n = 0;

    _UTExt(ext, &n, SSF_TLS_EXT_SUPPORTED_VERSIONS, v13, sizeof(v13));
    ks[0] = (uint8_t)(group >> 8); ks[1] = (uint8_t)group;
    if (kLen == 0u) { _UTExt(ext, &n, SSF_TLS_EXT_KEY_SHARE, ks, 2u); return n; }
    ks[2] = (uint8_t)(kLenField >> 8); ks[3] = (uint8_t)kLenField;
    memset(&ks[4], 0x09, kLen);
    if (group != SSF_TLS_GROUP_X25519) ks[4] = 0x04u;                  /* Uncompressed point */
    _UTExt(ext, &n, SSF_TLS_EXT_KEY_SHARE, ks, 4u + kLen);
    return n;
}

typedef struct
{
    uint8_t alert;
    uint16_t group;
    uint8_t pub[97];
    size_t pubLen;
    const uint8_t *cookie;
    size_t cookieOff;                /* cookie's offset in the body (it points into the copy) */
    uint16_t cookieLen;
} SSFTLSCUTShOut_t;

/* Parses body (afterHrr: as the ServerHello after an HRR for secp256r1 / AES-128-GCM) from a */
/* heap copy of exactly len bytes, so a read past the message is an ASan report.              */
static bool _UTSh(const uint8_t *body, size_t len, bool isHrr, bool afterHrr,
                  SSFTLSCUTShOut_t *o)
{
    uint8_t *copy = (uint8_t *)malloc((len > 0u) ? len : 1u);
    bool ok;

    SSF_ASSERT(copy != NULL);
    if (len > 0u) memcpy(copy, body, len);
    memset(o, 0xa5, sizeof(*o));
    ok = _SSFTLSCParseServerHelloExForTest(&_utSession2, copy, len, isHrr,
                                           afterHrr ? SSF_TLS_GROUP_SECP256R1 : 0u,
                                           afterHrr ? SSF_TLS_CS_AES_128_GCM_SHA256 : 0u,
                                           &o->alert, &o->group, o->pub, &o->pubLen,
                                           &o->cookie, &o->cookieLen);
    o->cookieOff = (ok && (o->cookie != NULL)) ? (size_t)(o->cookie - copy) : 0u;
    free(copy);
    return ok;
}

#define SSF_TLSC_UT_SHR(body, len, isHrr, afterHrr, want) do { \
    SSFTLSCUTShOut_t _o; \
    SSF_ASSERT(!_UTSh((body), (len), (isHrr), (afterHrr), &_o)); \
    SSF_ASSERT(_o.alert == (want)); } while (0)

static void _SSFTLSCUTServerHelloChecks(void)
{
    static const uint16_t suites[] = { SSF_TLS_CS_AES_128_GCM_SHA256, SSF_TLS_CS_AES_256_GCM_SHA384,
                                       SSF_TLS_CS_CHACHA20_POLY1305_SHA256,
                                       SSF_TLS_CS_AES_128_CCM_SHA256 };
    static const uint8_t wantHashLen[] = { 32u, 48u, 32u, 32u };
    static const uint8_t wantKeyLen[] = { 16u, 32u, 32u, 16u };
    static const uint8_t cookie[] = { 0x00, 0x03, 0xc1, 0xc2, 0xc3 };
    static uint8_t ext[512];
    static uint8_t sh[640];
    SSFTLSCSession_t *s = &_utSession2;
    SSFTLSCUTShOut_t o;
    size_t e;
    size_t n;
    uint8_t i;

    SSFTLSCInit(s, &_utSock.transport, NULL);

    /* ---- Accepted ServerHellos: key, group, and each suite's hash and key length ---- */
    for (i = 0; i < 4u; i++)
    {
        e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 32u);
        n = _UTShRaw(sh, 32u, 0x22, suites[i], 0u, true, ext, e);
        SSF_ASSERT(_UTSh(sh, n, false, false, &o) && (o.alert == 0u));
        SSF_ASSERT((o.group == SSF_TLS_GROUP_X25519) && (o.pubLen == 32u) && (o.pub[1] == 0x09u));
        SSF_ASSERT((s->cipherSuite == suites[i]) && (s->hashLen == wantHashLen[i]) &&
                   (s->keyLen == wantKeyLen[i]));
        SSF_ASSERT(s->hash == ((i == 1u) ? SSF_HMAC_HASH_SHA384 : SSF_HMAC_HASH_SHA256));
    }
    e = _UTShExts(ext, SSF_TLS_GROUP_SECP384R1, 97u, 97u);
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_256_GCM_SHA384, 0u, true, ext, e);
    SSF_ASSERT(_UTSh(sh, n, false, false, &o) && (o.group == SSF_TLS_GROUP_SECP384R1) &&
               (o.pubLen == 97u) && (o.pub[0] == 0x04u));
    /* Extension order does not matter: key_share first */
    {
        static uint8_t rev[128];
        size_t r = 0;
        static const uint8_t v13[] = { 0x03, 0x04 };

        e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 32u);
        memcpy(rev, &ext[6], e - 6u); r = e - 6u;                     /* key_share */
        _UTExt(rev, &r, SSF_TLS_EXT_SUPPORTED_VERSIONS, v13, sizeof(v13));
        n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, rev, r);
        SSF_ASSERT(_UTSh(sh, n, false, false, &o) && (o.group == SSF_TLS_GROUP_X25519));
    }

    /* ---- Framing: decode_error ---- */
    e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 32u);
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, 34u, false, false, SSF_TLS_ALERT_DECODE_ERROR);       /* Too short */
    SSF_TLSC_UT_SHR(sh, 34u + 1u + 32u + 1u, false, false, SSF_TLS_ALERT_DECODE_ERROR);
    n = _UTShRaw(sh, 33u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_DECODE_ERROR);         /* sid over 32 */
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, 34u + 1u + 20u, false, false, SSF_TLS_ALERT_DECODE_ERROR); /* Into sid */
    SSF_TLSC_UT_SHR(sh, n - 1u, false, false, SSF_TLS_ALERT_DECODE_ERROR);     /* Block short */
    sh[n] = 0u;
    SSF_TLSC_UT_SHR(sh, n + 1u, false, false, SSF_TLS_ALERT_DECODE_ERROR);     /* Trailing */
    {
        size_t k = 6u + 2u;                                           /* key_share length */
        e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 32u);
        ext[k] = 0x00; ext[k + 1u] = 0x60;                            /* Past the block */
        n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
        SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_DECODE_ERROR);
        e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 32u);
        ext[e++] = 0xfa; ext[e++] = 0xfa; ext[e++] = 0x00;            /* Half a header */
        n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
        SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_DECODE_ERROR);
        /* The last extension's data cut off by the end of the message (block length counts */
        /* only what is there): supported_versions, then a key_share key                     */
        e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 32u);
        memmove(ext, &ext[6], e - 6u); e -= 6u;                       /* key_share first */
        ext[e++] = 0x00; ext[e++] = 0x2b; ext[e++] = 0x00; ext[e++] = 0x02;
        n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
        SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_DECODE_ERROR);
        e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 32u) - 20u;     /* 20 key bytes missing */
        n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
        SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_DECODE_ERROR);
    }

    /* ---- Session id, cipher suite, compression: illegal_parameter ---- */
    e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 32u);
    n = _UTShRaw(sh, 31u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);    /* Echo length */
    n = _UTShRaw(sh, 0u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    n = _UTShRaw(sh, 32u, 0x23, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);    /* Echo bytes */
    n = _UTShRaw(sh, 32u, 0x22, 0x1305u, 0u, true, ext, e);                  /* CCM_8: not offered */
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    n = _UTShRaw(sh, 32u, 0x22, 0xc02fu, 0u, true, ext, e);                  /* A TLS 1.2 suite */
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 1u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);    /* Compression */

    /* ---- key_share in a ServerHello ---- */
    {
        static const uint8_t v13[] = { 0x03, 0x04 };

        e = 0;
        _UTExt(ext, &e, SSF_TLS_EXT_SUPPORTED_VERSIONS, v13, sizeof(v13));
        n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
        SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_MISSING_EXTENSION); /* None */
        e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 32u);
        memcpy(&ext[e], &ext[6], 4u + 36u); e += 4u + 36u;             /* A second key_share */
        n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
        SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    }
    e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 0u, 0u);                     /* Group only */
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_DECODE_ERROR);
    /* key_share of 0 or 1 bytes, last in the message: ServerHello and HelloRetryRequest */
    for (i = 0; i < 4u; i++)
    {
        static const uint8_t v13[] = { 0x03, 0x04 };
        static const uint8_t g[] = { 0x00 };

        e = 0;
        _UTExt(ext, &e, SSF_TLS_EXT_SUPPORTED_VERSIONS, v13, sizeof(v13));
        _UTExt(ext, &e, SSF_TLS_EXT_KEY_SHARE, g, (size_t)(i & 1u));
        n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
        SSF_TLSC_UT_SHR(sh, n, (i >= 2u), false, SSF_TLS_ALERT_DECODE_ERROR);
    }
    e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 31u);                   /* Length field off */
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_DECODE_ERROR);
    e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 31u, 31u);                   /* Wrong size */
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    e = _UTShExts(ext, SSF_TLS_GROUP_SECP384R1, 65u, 65u);
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    e = _UTShExts(ext, SSF_TLS_GROUP_SECP256R1, 65u, 65u);                /* No share sent */
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    e = _UTShExts(ext, 0x001eu, 56u, 56u);                                /* x448: not offered */
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);

    /* ---- HelloRetryRequest: selected_group, cookie ---- */
    e = _UTShExts(ext, SSF_TLS_GROUP_SECP256R1, 0u, 0u);
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_ASSERT(_UTSh(sh, n, true, false, &o) && (o.group == SSF_TLS_GROUP_SECP256R1) &&
               (o.cookie == NULL) && (o.cookieLen == 0u));
    e = _UTShExts(ext, SSF_TLS_GROUP_SECP256R1, 0u, 0u);
    _UTExt(ext, &e, 44u, cookie, sizeof(cookie));
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_ASSERT(_UTSh(sh, n, true, false, &o) && (o.cookieLen == sizeof(cookie)) &&
               (o.cookieOff == (n - sizeof(cookie))));                /* Whole extension_data */
    e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 0u, 0u);                     /* Share already sent */
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, true, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    e = _UTShExts(ext, 0x001eu, 0u, 0u);                                  /* Not supported */
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, true, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    e = _UTShExts(ext, SSF_TLS_GROUP_SECP256R1, 65u, 65u);                /* A share, not a group */
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, true, false, SSF_TLS_ALERT_DECODE_ERROR);
    {
        static const uint8_t ckEmpty[] = { 0x00, 0x00 };
        static const uint8_t ckShort[] = { 0x00 };
        static const uint8_t ckLen[] = { 0x00, 0x04, 0xc1, 0xc2, 0xc3 };
        const uint8_t *bad[3] = { ckEmpty, ckShort, ckLen };
        const size_t badLen[3] = { sizeof(ckEmpty), sizeof(ckShort), sizeof(ckLen) };

        for (i = 0; i < 3u; i++)
        {
            e = _UTShExts(ext, SSF_TLS_GROUP_SECP256R1, 0u, 0u);
            _UTExt(ext, &e, 44u, bad[i], badLen[i]);
            n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
            SSF_TLSC_UT_SHR(sh, n, true, false, SSF_TLS_ALERT_DECODE_ERROR);
        }
    }

    /* ---- A HelloRetryRequest that would change nothing (no key_share, no cookie) is       ---- */
    /* ---- illegal_parameter (4.1.4); a cookie-only one is not supported (missing_extension) ---- */
    {
        static const uint8_t v13[] = { 0x03, 0x04 };

        e = 0;
        _UTExt(ext, &e, SSF_TLS_EXT_SUPPORTED_VERSIONS, v13, sizeof(v13));
        n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
        SSF_TLSC_UT_SHR(sh, n, true, false, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
        _UTExt(ext, &e, 44u, cookie, sizeof(cookie));
        n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
        SSF_TLSC_UT_SHR(sh, n, true, false, SSF_TLS_ALERT_MISSING_EXTENSION);
    }

    /* ---- The ServerHello after a HelloRetryRequest (secp256r1, AES-128-GCM) ---- */
    e = _UTShExts(ext, SSF_TLS_GROUP_SECP256R1, 65u, 65u);
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_ASSERT(_UTSh(sh, n, false, true, &o) && (o.group == SSF_TLS_GROUP_SECP256R1) &&
               (o.pubLen == 65u));
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_256_GCM_SHA384, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, true, SSF_TLS_ALERT_ILLEGAL_PARAMETER);     /* Suite changed */
    e = _UTShExts(ext, SSF_TLS_GROUP_X25519, 32u, 32u);                   /* Not the HRR's group */
    n = _UTShRaw(sh, 32u, 0x22, SSF_TLS_CS_AES_128_GCM_SHA256, 0u, true, ext, e);
    SSF_TLSC_UT_SHR(sh, n, false, true, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSFTLSCDeInit(s);
}

/* Builds a TLS 1.2 ServerHello body, as a server unaware of supported_versions sends: its own */
/* session id of sidLen bytes, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, then the extension block */
/* ext[0..extLen) if withExts (a TLS 1.2 ServerHello may have none). Returns the length.       */
static size_t _UTSh12Body(uint8_t *out, uint8_t sidLen, bool withExts, const uint8_t *ext,
                          size_t extLen)
{
    size_t p = 0;

    out[p++] = 0x03; out[p++] = 0x03;
    memset(&out[p], 0x44, 32u); p += 32u;
    out[p++] = sidLen; memset(&out[p], 0x77, sidLen); p += sidLen;
    out[p++] = 0xc0; out[p++] = 0x2f;
    out[p++] = 0x00;
    if (withExts)
    {
        out[p++] = (uint8_t)(extLen >> 8); out[p++] = (uint8_t)extLen;
        if (extLen > 0u) { memcpy(&out[p], ext, extLen); p += extLen; }
    }
    return p;
}

/* A ServerHello that did not negotiate TLS 1.3 is protocol_version, whatever else is in it:   */
/* checked before the session id echo, cipher suite and extensions, which a TLS 1.2 server    */
/* fills its own way.                                                                          */
static void _SSFTLSCUTServerHelloVersion(void)
{
    /* renegotiation_info, extended_master_secret, SNI acknowledgement, ec_point_formats */
    static const uint8_t ext12[] = { 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x01,
                                     0x00 };
    /* key_share only: shaped like TLS 1.3 but without supported_versions */
    static const uint8_t ksOnly[] = { 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
                                      0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                                      0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                                      0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                                      0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09 };
    static uint8_t sh[256];
    uint8_t a = 0xffu;
    size_t n;
    uint8_t sidLen;

    SSFTLSCInit(&_utSession2, &_utSock.transport, NULL);
    for (sidLen = 0; sidLen <= 32u; sidLen = (uint8_t)(sidLen + 16u))
    {
        /* Typical TLS 1.2 extensions, none at all, an empty block */
        n = _UTSh12Body(sh, sidLen, true, ext12, sizeof(ext12));
        SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, sh, n, false, &a));
        SSF_ASSERT(a == SSF_TLS_ALERT_PROTOCOL_VERSION);
        n = _UTSh12Body(sh, sidLen, false, NULL, 0u);
        SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, sh, n, false, &a));
        SSF_ASSERT(a == SSF_TLS_ALERT_PROTOCOL_VERSION);
        n = _UTSh12Body(sh, sidLen, true, NULL, 0u);
        SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, sh, n, false, &a));
        SSF_ASSERT(a == SSF_TLS_ALERT_PROTOCOL_VERSION);
    }
    /* TLS 1.3 shaped, supported_versions missing: ServerHello and HRR */
    {
        static uint8_t body[256];
        size_t p = 0;

        body[p++] = 0x03; body[p++] = 0x03; memset(&body[p], 0x5a, 32u); p += 32u;
        body[p++] = 32u; memset(&body[p], 0x22, 32u); p += 32u;
        body[p++] = 0x13; body[p++] = 0x01; body[p++] = 0x00;
        body[p++] = 0x00; body[p++] = (uint8_t)sizeof(ksOnly);
        memcpy(&body[p], ksOnly, sizeof(ksOnly)); p += sizeof(ksOnly);
        SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, body, p, false, &a));
        SSF_ASSERT(a == SSF_TLS_ALERT_PROTOCOL_VERSION);
        SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, body, p, true, &a));
        SSF_ASSERT(a == SSF_TLS_ALERT_PROTOCOL_VERSION);
        /* Framing errors stay decode_error: stray bytes after the last extension, an        */
        /* extension running past the block, a block length past the body, a body ending   */
        /* inside the cipher suite                                                           */
        body[p] = 0x00; body[p + 1u] = 0x00;
        body[p - sizeof(ksOnly) - 1u] = (uint8_t)(sizeof(ksOnly) + 2u);
        SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, body, p + 2u, false, &a));
        SSF_ASSERT(a == SSF_TLS_ALERT_DECODE_ERROR);
        body[p - sizeof(ksOnly) - 1u] = (uint8_t)sizeof(ksOnly);
        body[p - sizeof(ksOnly) + 3u] = 0x30;                     /* key_share length 0x0030 */
        SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, body, p, false, &a));
        SSF_ASSERT(a == SSF_TLS_ALERT_DECODE_ERROR);
        body[p - sizeof(ksOnly) + 3u] = 0x24;
        body[p - sizeof(ksOnly) - 1u] = (uint8_t)(sizeof(ksOnly) + 1u);
        SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, body, p, false, &a));
        SSF_ASSERT(a == SSF_TLS_ALERT_DECODE_ERROR);
        SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, body, 2u + 32u + 1u + 32u + 1u,
                                                    false, &a));
        SSF_ASSERT(a == SSF_TLS_ALERT_DECODE_ERROR);
    }
    /* supported_versions present but not TLS 1.3 stays illegal_parameter (4.2.1) */
    {
        static const uint8_t v12[] = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x03 };

        n = _UTSh12Body(sh, 32u, true, v12, sizeof(v12));
        memset(&sh[35], 0x22, 32u);                               /* Echo the session id */
        sh[67] = 0x13; sh[68] = 0x01;                             /* A TLS 1.3 suite */
        SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, sh, n, false, &a));
        SSF_ASSERT(a == SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    }
    SSFTLSCDeInit(&_utSession2);
}

static void _SSFTLSCUTServerHelloExts(void)
{
    static uint8_t sh[256];
    uint8_t a = 0xffu;
    size_t n;

    SSFTLSCInit(&_utSession2, &_utSock.transport, NULL);

    /* ---- The harness: a plain ServerHello and HRR are accepted; a wrong echo is not ---- */
    n = _UTShBody(sh, false, _utShNone, 0u);
    SSF_ASSERT(_SSFTLSCParseServerHelloForTest(&_utSession2, sh, n, false, &a) && (a == 0u));
    n = _UTShBody(sh, true, _utShNone, 0u);
    SSF_ASSERT(_SSFTLSCParseServerHelloForTest(&_utSession2, sh, n, true, &a) && (a == 0u));
    n = _UTShBody(sh, false, _utShNone, 0u);
    sh[35] ^= 0x01u;                                              /* First session id byte */
    SSF_ASSERT(!_SSFTLSCParseServerHelloForTest(&_utSession2, sh, n, false, &a));
    SSF_ASSERT(a == SSF_TLS_ALERT_ILLEGAL_PARAMETER);

    /* ---- ServerHello ---- */
    SSF_TLSC_UT_SH(false, _utShSni, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(false, _utShGroups, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(false, _utShSigAlgs, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(false, _utShPskModes, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(false, _utShRsl, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(false, _utShAlpn, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(false, _utShCookie, SSF_TLS_ALERT_ILLEGAL_PARAMETER);   /* HRR only */
    SSF_TLSC_UT_SH(false, _utShPsk, SSF_TLS_ALERT_UNSUPPORTED_EXT);
    SSF_TLSC_UT_SH(false, _utShEarly, SSF_TLS_ALERT_UNSUPPORTED_EXT);
    SSF_TLSC_UT_SH(false, _utShStatus, SSF_TLS_ALERT_UNSUPPORTED_EXT);
    SSF_TLSC_UT_SH(false, _utShUnknown, SSF_TLS_ALERT_UNSUPPORTED_EXT);
    SSF_TLSC_UT_SH(false, _utShDupVer, SSF_TLS_ALERT_ILLEGAL_PARAMETER);

    /* ---- HelloRetryRequest: cookie allowed (once); the rest as for ServerHello ---- */
    SSF_TLSC_UT_SH(true, _utShCookie, 0u);
    SSF_TLSC_UT_SH(true, _utShDupCookie, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(true, _utShSni, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(true, _utShGroups, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(true, _utShSigAlgs, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(true, _utShPskModes, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(true, _utShRsl, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(true, _utShAlpn, SSF_TLS_ALERT_ILLEGAL_PARAMETER);
    SSF_TLSC_UT_SH(true, _utShPsk, SSF_TLS_ALERT_UNSUPPORTED_EXT);
    SSF_TLSC_UT_SH(true, _utShEarly, SSF_TLS_ALERT_UNSUPPORTED_EXT);
    SSF_TLSC_UT_SH(true, _utShUnknown, SSF_TLS_ALERT_UNSUPPORTED_EXT);
    SSFTLSCDeInit(&_utSession2);
}

/* --------------------------------------------------------------------------------------------- */
/* Client flight split into records (_SendHandshakeOnce): every protected record within the     */
/* server's record_size_limit, the pieces joining up to the message, across short writes.       */
/* --------------------------------------------------------------------------------------------- */
/* The most content one record of the client flight carries: the server's record_size_limit    */
/* less the content type byte (RFC 8449 4), the build's send size, and hsBuf, which stages it.  */
static size_t _UTFlightCap(const SSFTLSCSession_t *s)
{
    size_t cap = SSF_TLSC_CONFIG_MAX_SEND_RECORD;

    if ((s->peerRecordLimit != 0u) && ((size_t)(s->peerRecordLimit - 1u) < cap))
    { cap = (size_t)(s->peerRecordLimit - 1u); }
    if (sizeof(s->hsBuf) < cap) cap = sizeof(s->hsBuf);
    return cap;
}

/* Sends msg (NULL: the client Certificate) until done, the fake transport writing short.       */
/* Returns the number of records; their contents, joined, go to joined / *joinedLen.           */
static size_t _UTSendFlight(SSFTLSCSession_t *s, const uint8_t *msg, size_t total,
                            uint8_t *joined, size_t joinedSize, size_t *joinedLen)
{
    static uint8_t pt[SSF_TLSC_CONFIG_MAX_SEND_RECORD + 1u];
    size_t off = 0;
    size_t records = 0;
    size_t n;
    uint16_t tries;
    SSFTLSIOResult_t r = SSF_TLS_IO_WANT_WRITE;

    _utFakeOutLen = 0;
    s->certSendOff = 0;
    for (tries = 0; (tries < 2000u) && (r == SSF_TLS_IO_WANT_WRITE); tries++)
    {
        r = _SSFTLSCSendHandshakeForTest(s, msg, total);
    }
    SSF_ASSERT(r == SSF_TLS_IO_SUCCESS);
    *joinedLen = 0;
    while (off < _utFakeOutLen)
    {
        SSF_ASSERT(_UTCliRecord(&off, pt, sizeof(pt), &n) == SSF_TLS_CT_HANDSHAKE);
        SSF_ASSERT(n <= _UTFlightCap(s));
        SSF_ASSERT((*joinedLen + n) <= joinedSize);
        memcpy(&joined[*joinedLen], pt, n);
        *joinedLen += n;
        records++;
    }
    return records;
}

static void _SSFTLSCUTSendFlight(void)
{
    static SSFPKey_t key;
    static uint8_t msg[520];                        /* An RSA-4096 CertificateVerify's size */
    static uint8_t joined[2048];
    static uint8_t want[2048];
    SSFTLSCSession_t *s = &_utSession2;
    const size_t certLen = sizeof(_utClientP256Cert);
    uint8_t th[32];
    uint8_t wantTh[32];
    size_t len;
    size_t i;

    for (i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(i * 7u + 1u);
    SSF_ASSERT(SSFPKeyDecodeDER(_utClientP256Key, sizeof(_utClientP256Key), &key));

    /* ---- The RFC 8449 minimum, 64: 63 content bytes a record, 9 records for 520 bytes ---- */
    _UTAppSession(s);
    s->peerRecordLimit = 64u;
    _utFakeSendCap = 7u;
    SSF_ASSERT(_UTFlightCap(s) == 63u);
    SSF_ASSERT(_UTSendFlight(s, msg, sizeof(msg), joined, sizeof(joined), &len) == 9u);
    SSF_ASSERT((len == sizeof(msg)) && (memcmp(joined, msg, sizeof(msg)) == 0));
    /* ---- A limit of 512 (GnuTLS's smallest): 511 + 9 ---- */
    s->peerRecordLimit = 512u;
    SSF_ASSERT(_UTSendFlight(s, msg, sizeof(msg), joined, sizeof(joined), &len) ==
               ((sizeof(msg) + _UTFlightCap(s) - 1u) / _UTFlightCap(s)));
    SSF_ASSERT((len == sizeof(msg)) && (memcmp(joined, msg, sizeof(msg)) == 0));
    /* ---- No limit from the server: the build's send size, or hsBuf if smaller ---- */
    s->peerRecordLimit = 0u;
    _utFakeSendCap = 0u;
    SSF_ASSERT(_UTSendFlight(s, msg, sizeof(msg), joined, sizeof(joined), &len) ==
               ((sizeof(msg) + _UTFlightCap(s) - 1u) / _UTFlightCap(s)));
    SSF_ASSERT((len == sizeof(msg)) && (memcmp(joined, msg, sizeof(msg)) == 0));

    /* ---- The client Certificate, streamed from the caller's chain into records and the    */
    /* ---- transcript: Certificate { context 0, list { cert, no extensions } }              */
    s->hsState = SSF_TLSC_HS_IDLE;
    SSF_ASSERT(_SSFTLSCUTSetOne(s, _utClientP256Cert, certLen, &key));
    s->hsState = SSF_TLSC_HS_COMPLETE;
    want[0] = SSF_TLS_HS_CERTIFICATE;
    want[1] = 0u; want[2] = (uint8_t)((certLen + 9u) >> 8); want[3] = (uint8_t)(certLen + 9u);
    want[4] = 0u;
    want[5] = 0u; want[6] = (uint8_t)((certLen + 5u) >> 8); want[7] = (uint8_t)(certLen + 5u);
    want[8] = 0u; want[9] = (uint8_t)(certLen >> 8); want[10] = (uint8_t)certLen;
    memcpy(&want[11], _utClientP256Cert, certLen);
    want[11u + certLen] = 0u; want[12u + certLen] = 0u;
    s->peerRecordLimit = 64u;
    _utFakeSendCap = 5u;
    SSFTLSTranscriptInit(&s->transcript, SSF_HMAC_HASH_SHA256);
    SSF_ASSERT(_UTSendFlight(s, NULL, certLen + 13u, joined, sizeof(joined), &len) ==
               ((certLen + 13u + 62u) / 63u));
    SSF_ASSERT((len == (certLen + 13u)) && (memcmp(joined, want, len) == 0));
    SSFTLSTranscriptHash(&s->transcript, th, sizeof(th));
    SSFSHA256(want, (uint32_t)len, wantTh, sizeof(wantTh));
    SSF_ASSERT(memcmp(th, wantTh, sizeof(th)) == 0);          /* Each byte hashed exactly once */
    _utFakeSendCap = 0u;
    _utFakeSendStall = false;
    SSFTLSCDeInit(s);
    SSFTLSRecordStateDeInit(&_utSrvSend);
    SSFTLSRecordStateDeInit(&_utSrvRecv);
}

/* --------------------------------------------------------------------------------------------- */
/* Trust store loading: SSFTLSCTrustFromPEM() over PEM bundles built from the DER fixtures.      */
/* --------------------------------------------------------------------------------------------- */
/* Appends text to buf. */
static void _UTPemText(char *buf, size_t size, size_t *len, const char *text)
{
    size_t n = strlen(text);

    SSF_ASSERT((*len + n) < size);
    memcpy(&buf[*len], text, n);
    *len += n;
    buf[*len] = 0;
}

/* Appends a PEM block: label, der in 64-column Base64 lines, each line ended with eol. */
static void _UTPemAdd(char *buf, size_t size, size_t *len, const char *label, const uint8_t *der,
                      size_t derLen, const char *eol)
{
    static char b64[4096];
    char line[80];
    size_t b64Len;
    size_t i;

    SSF_ASSERT(SSFBase64Encode(der, derLen, b64, sizeof(b64), &b64Len));
    _UTPemText(buf, size, len, "-----BEGIN ");
    _UTPemText(buf, size, len, label);
    _UTPemText(buf, size, len, "-----");
    _UTPemText(buf, size, len, eol);
    for (i = 0; i < b64Len; i += 64u)
    {
        size_t k = ((b64Len - i) < 64u) ? (b64Len - i) : 64u;

        memcpy(line, &b64[i], k); line[k] = 0;
        _UTPemText(buf, size, len, line);
        _UTPemText(buf, size, len, eol);
    }
    _UTPemText(buf, size, len, "-----END ");
    _UTPemText(buf, size, len, label);
    _UTPemText(buf, size, len, "-----");
    _UTPemText(buf, size, len, eol);
}

/* Loads pem into the test's pool and arrays; checks the result, *countOut and *poolUsedOut, and */
/* that a failure leaves an empty store.                                                        */
static uint8_t _utTrustPool[4096];
static const uint8_t *_utTrustDers[4];
static uint32_t _utTrustLens[4];
static SSFTLSCTrustStore_t _utTrustStore;
static void _UTTrust(const char *pem, size_t pemLen, size_t poolSize, uint8_t maxCount,
                     SSFTLSCTrustResult_t want, uint8_t wantCount, size_t wantUsed)
{
    size_t used = 0xffffu;
    uint8_t count = 0xffu;
    SSFTLSCTrustResult_t r;

    _utTrustStore.caDer = (const uint8_t **)(uintptr_t)1u;       /* Stale contents: replaced */
    _utTrustStore.caDerLen = (const uint32_t *)(uintptr_t)1u;
    _utTrustStore.count = 99u;
    r = SSFTLSCTrustFromPEM(pem, pemLen, _utTrustPool, poolSize, _utTrustDers, _utTrustLens,
                            maxCount, &_utTrustStore, &used, &count);
    SSF_ASSERT(r == want);
    SSF_ASSERT(count == wantCount);
    if (r == SSF_TLSC_TRUST_OK)
    {
        SSF_ASSERT(used == wantUsed);
        SSF_ASSERT((_utTrustStore.caDer == _utTrustDers) &&
                   (_utTrustStore.caDerLen == _utTrustLens) &&
                   (_utTrustStore.count == wantCount));
    }
    else
    {
        SSF_ASSERT(used == 0u);
        SSF_ASSERT((_utTrustStore.caDer == NULL) && (_utTrustStore.caDerLen == NULL) &&
                   (_utTrustStore.count == 0u));
    }
}

/* Builds pem: the P-256 certificate, then the Ed25519 one with its BEGIN line replaced by      */
/* beginLine (NULL: no BEGIN line at all). Returns the length.                                  */
static size_t _UTPemDamagedBegin(char *pem, size_t size, const char *beginLine)
{
    static char tmp[2048];
    size_t len = 0;
    size_t tmpLen = 0;
    const char *body;

    _UTPemAdd(pem, size, &len, "CERTIFICATE", _utClientP256Cert, sizeof(_utClientP256Cert), "\n");
    _UTPemAdd(tmp, sizeof(tmp), &tmpLen, "CERTIFICATE", _utClientEd25519Cert,
              sizeof(_utClientEd25519Cert), "\n");
    body = strchr(tmp, '\n') + 1;                               /* After the BEGIN line */
    if (beginLine != NULL) _UTPemText(pem, size, &len, beginLine);
    _UTPemText(pem, size, &len, body);
    return len;
}

static void _SSFTLSCUTTrustFromPEM(void)
{
    static char pem[8192];
    static char big[160000];
    static uint8_t bad[sizeof(_utClientP256Cert) + 1u];
    static const uint8_t junk[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    const size_t l1 = sizeof(_utClientP256Cert);
    const size_t l2 = sizeof(_utClientEd25519Cert);
    const size_t l3 = sizeof(_utClientRSA2048Cert);
    size_t len;
    size_t used;
    size_t i;
    uint8_t count;
    char *p;

    /* ---- One certificate ---- */
    len = 0;
    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientP256Cert, l1, "\n");
    _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_OK, 1u, l1);
    SSF_ASSERT((_utTrustDers[0] == _utTrustPool) && (_utTrustLens[0] == l1));
    SSF_ASSERT(memcmp(_utTrustDers[0], _utClientP256Cert, l1) == 0);

    /* ---- A bundle: CRLF, text before, between and after the blocks (RFC 7468 5.2) ---- */
    len = 0;
    _UTPemText(pem, sizeof(pem), &len, "# Bundle\r\nIssuer: test\r\n");
    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientP256Cert, l1, "\r\n");
    _UTPemText(pem, sizeof(pem), &len, "\r\n# Second\r\n");
    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientEd25519Cert, l2, "\r\n");
    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientRSA2048Cert, l3, "\r\n");
    _UTPemText(pem, sizeof(pem), &len, "trailing text\r\n");
    _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_OK, 3u, l1 + l2 + l3);
    SSF_ASSERT((_utTrustLens[0] == l1) && (_utTrustLens[1] == l2) && (_utTrustLens[2] == l3));
    SSF_ASSERT(memcmp(_utTrustDers[0], _utClientP256Cert, l1) == 0);
    SSF_ASSERT(memcmp(_utTrustDers[1], _utClientEd25519Cert, l2) == 0);
    SSF_ASSERT(memcmp(_utTrustDers[2], _utClientRSA2048Cert, l3) == 0);
    SSF_ASSERT((_utTrustDers[1] == &_utTrustPool[l1]) &&
               (_utTrustDers[2] == &_utTrustPool[l1 + l2]));
    /* The store is one Init() accepts */
    SSFTLSCInit(&_utSession2, &_utSock.transport, &_utTrustStore);
    SSF_ASSERT(_utSession2.trust.count == 3u);
    SSFTLSCDeInit(&_utSession2);

    /* ---- Measuring: no pool or arrays; sizes reported ---- */
    used = 0; count = 0;
    SSF_ASSERT(SSFTLSCTrustFromPEM(pem, len, NULL, 0u, NULL, NULL, 0u, NULL, &used, &count) ==
               SSF_TLSC_TRUST_OK);
    SSF_ASSERT((used == (l1 + l2 + l3)) && (count == 3u));

    /* ---- Pool exactly full, then one byte short: the third block does not fit ---- */
    _UTTrust(pem, len, l1 + l2 + l3, 4u, SSF_TLSC_TRUST_OK, 3u, l1 + l2 + l3);
    _UTTrust(pem, len, l1 + l2 + l3 - 1u, 4u, SSF_TLSC_TRUST_ERR_SIZE, 2u, 0u);
    /* ---- More certificates than maxCount: the failing one's index ---- */
    _UTTrust(pem, len, sizeof(_utTrustPool), 2u, SSF_TLSC_TRUST_ERR_COUNT, 2u, 0u);
    _UTTrust(pem, len, sizeof(_utTrustPool), 0u, SSF_TLSC_TRUST_ERR_COUNT, 0u, 0u);
    _UTTrust(pem, len, sizeof(_utTrustPool), 3u, SSF_TLSC_TRUST_OK, 3u, l1 + l2 + l3);

    /* ---- Any block other than CERTIFICATE rejects the bundle ---- */
    {
        static const char *const labels[] = { "PRIVATE KEY", "TRUSTED CERTIFICATE",
                                              "X509 CERTIFICATE", "CERTIFICATE REQUEST",
                                              "certificate" };
        size_t k;

        for (k = 0; k < (sizeof(labels) / sizeof(labels[0])); k++)
        {
            len = 0;
            _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientP256Cert, l1, "\n");
            _UTPemAdd(pem, sizeof(pem), &len, labels[k], _utClientEd25519Cert, l2, "\n");
            _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_ERR_LABEL, 1u, 0u);
            /* Measuring checks labels too */
            SSF_ASSERT(SSFTLSCTrustFromPEM(pem, len, NULL, 0u, NULL, NULL, 0u, NULL, &used,
                                           &count) == SSF_TLSC_TRUST_ERR_LABEL);
            SSF_ASSERT((used == 0u) && (count == 1u));
        }
    }

    /* ---- Malformed PEM: bad Base64, a BEGIN with no END ---- */
    len = 0;
    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientP256Cert, l1, "\n");
    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientEd25519Cert, l2, "\n");
    p = strstr(&pem[1], "-----BEGIN");
    SSF_ASSERT(p != NULL);
    p[40] = '!';
    _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_ERR_PEM, 1u, 0u);
    len = 0;
    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientP256Cert, l1, "\n");
    _UTPemText(pem, sizeof(pem), &len, "-----BEGIN CERTIFICATE-----\nMIIB\n");
    _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_ERR_PEM, 1u, 0u);

    /* ---- A damaged BEGIN line makes ssfpem read the block as text: its END line, left in   */
    /* ---- the text between blocks, rejects the bundle rather than dropping the certificate */
    {
        static const char *const begins[] = { "----BEGIN CERTIFICATE-----\n",
                                              " -----BEGIN CERTIFICATE-----\n",
                                              "-----begin CERTIFICATE-----\n",
                                              "-----BEGINCERTIFICATE-----\n",
                                              "BEGIN CERTIFICATE\n", NULL };
        size_t k;

        for (k = 0; k < (sizeof(begins) / sizeof(begins[0])); k++)
        {
            len = _UTPemDamagedBegin(pem, sizeof(pem), begins[k]);
            _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_ERR_PEM, 1u, 0u);
            SSF_ASSERT(SSFTLSCTrustFromPEM(pem, len, NULL, 0u, NULL, NULL, 0u, NULL, &used,
                                           &count) == SSF_TLSC_TRUST_ERR_PEM);
            SSF_ASSERT((used == 0u) && (count == 1u));
        }
        /* A stray marker in text before, between or after the blocks */
        {
            static const char *const strays[] = { "-----BEGIN", "-----END", "x------END x" };
            size_t w;

            for (k = 0; k < (sizeof(strays) / sizeof(strays[0])); k++)
            {
                for (w = 0; w < 3u; w++)
                {
                    len = 0;
                    if (w == 0u) { _UTPemText(pem, sizeof(pem), &len, strays[k]); }
                    _UTPemText(pem, sizeof(pem), &len, "\n");
                    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientP256Cert, l1, "\n");
                    if (w == 1u) { _UTPemText(pem, sizeof(pem), &len, strays[k]); }
                    _UTPemText(pem, sizeof(pem), &len, "\n");
                    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientEd25519Cert, l2,
                              "\n");
                    if (w == 2u) { _UTPemText(pem, sizeof(pem), &len, strays[k]); }
                    _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_ERR_PEM,
                             (uint8_t)((w == 2u) ? 2u : w), 0u);
                }
            }
        }
        /* Dashes that are not a marker are text */
        len = 0;
        _UTPemText(pem, sizeof(pem), &len, "---- END ----\n------\n-----BEGINS here\n");
        _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientP256Cert, l1, "\n");
        _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_ERR_PEM, 0u, 0u);
        len = 0;
        _UTPemText(pem, sizeof(pem), &len, "---- END ----\n------\n- ---BEGIN here\n");
        _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientP256Cert, l1, "\n");
        _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_OK, 1u, l1);
    }

    /* ---- A CERTIFICATE that is not one X.509 certificate: trailing byte, other DER ---- */
    memcpy(bad, _utClientP256Cert, l1);
    bad[l1] = 0;
    len = 0;
    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", bad, sizeof(bad), "\n");
    _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_ERR_CERT, 0u, 0u);
    len = 0;
    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientP256Cert, l1, "\n");
    _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", junk, sizeof(junk), "\n");
    _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_ERR_CERT, 1u, 0u);
    /* Measuring has no DER to parse: it checks the PEM and labels only */
    SSF_ASSERT(SSFTLSCTrustFromPEM(pem, len, NULL, 0u, NULL, NULL, 0u, NULL, &used, &count) ==
               SSF_TLSC_TRUST_OK);
    SSF_ASSERT((used == (l1 + sizeof(junk))) && (count == 2u));

    /* ---- No certificate at all: fails closed ---- */
    _UTTrust(pem, 0u, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_ERR_EMPTY, 0u, 0u);
    len = 0;
    _UTPemText(pem, sizeof(pem), &len, "# nothing here\n");
    _UTTrust(pem, len, sizeof(_utTrustPool), 4u, SSF_TLSC_TRUST_ERR_EMPTY, 0u, 0u);
    SSF_ASSERT(SSFTLSCTrustFromPEM(pem, len, NULL, 0u, NULL, NULL, 0u, NULL, &used, &count) ==
               SSF_TLSC_TRUST_ERR_EMPTY);
    SSF_ASSERT((used == 0u) && (count == 0u));

    /* ---- 255 certificates is the most a store holds; 256 is ERR_COUNT, measuring included -- */
    len = 0;
    for (i = 0; i < 256u; i++)
    {
        _UTPemAdd(big, sizeof(big), &len, "CERTIFICATE", _utClientEd25519Cert, l2, "\n");
        if (i == 254u)
        {
            SSF_ASSERT(SSFTLSCTrustFromPEM(big, len, NULL, 0u, NULL, NULL, 0u, NULL, &used,
                                           &count) == SSF_TLSC_TRUST_OK);
            SSF_ASSERT((count == 255u) && (used == (255u * l2)));
        }
    }
    SSF_ASSERT(SSFTLSCTrustFromPEM(big, len, NULL, 0u, NULL, NULL, 0u, NULL, &used, &count) ==
               SSF_TLSC_TRUST_ERR_COUNT);
    SSF_ASSERT((used == 0u) && (count == 255u));

    /* ---- The pool may sit right after or before the PEM text, but not overlap it ---- */
    {
        static char area[4096];
        size_t pemAt;

        len = 0;
        _UTPemAdd(area, sizeof(area), &len, "CERTIFICATE", _utClientP256Cert, l1, "\n");
        SSF_ASSERT((len + l1) < sizeof(area));
        SSF_ASSERT(SSFTLSCTrustFromPEM(area, len, (uint8_t *)&area[len], sizeof(area) - len,
                                       _utTrustDers, _utTrustLens, 4u, &_utTrustStore, &used,
                                       &count) == SSF_TLSC_TRUST_OK);
        SSF_ASSERT(memcmp(_utTrustDers[0], _utClientP256Cert, l1) == 0);
        pemAt = sizeof(area) - len;                                /* PEM at the end */
        len = 0;
        _UTPemAdd(pem, sizeof(pem), &len, "CERTIFICATE", _utClientP256Cert, l1, "\n");
        memmove(&area[pemAt], pem, len);
        SSF_ASSERT(SSFTLSCTrustFromPEM(&area[pemAt], len, (uint8_t *)area, pemAt, _utTrustDers,
                                       _utTrustLens, 4u, &_utTrustStore, &used, &count) ==
                   SSF_TLSC_TRUST_OK);
        SSF_ASSERT(memcmp(_utTrustDers[0], _utClientP256Cert, l1) == 0);
        /* Overlapping: in place, pool starting inside the text, pool ending inside it */
        SSF_ASSERT_TEST(SSFTLSCTrustFromPEM(&area[pemAt], len, (uint8_t *)&area[pemAt], len,
                                            _utTrustDers, _utTrustLens, 4u, &_utTrustStore,
                                            &used, &count));
        SSF_ASSERT_TEST(SSFTLSCTrustFromPEM(&area[pemAt], len, (uint8_t *)&area[pemAt + 1u],
                                            len - 1u, _utTrustDers, _utTrustLens, 4u,
                                            &_utTrustStore, &used, &count));
        SSF_ASSERT_TEST(SSFTLSCTrustFromPEM(&area[pemAt], len, (uint8_t *)&area[pemAt - 8u],
                                            9u, _utTrustDers, _utTrustLens, 4u,
                                            &_utTrustStore, &used, &count));
    }

    /* ---- Programming errors ---- */
    SSF_ASSERT_TEST(SSFTLSCTrustFromPEM(NULL, 0u, NULL, 0u, NULL, NULL, 0u, NULL, &used, &count));
    SSF_ASSERT_TEST(SSFTLSCTrustFromPEM(pem, len, NULL, 0u, NULL, NULL, 0u, NULL, NULL, &count));
    SSF_ASSERT_TEST(SSFTLSCTrustFromPEM(pem, len, NULL, 0u, NULL, NULL, 0u, NULL, &used, NULL));
    SSF_ASSERT_TEST(SSFTLSCTrustFromPEM(pem, len, _utTrustPool, sizeof(_utTrustPool), NULL,
                                        _utTrustLens, 4u, &_utTrustStore, &used, &count));
    SSF_ASSERT_TEST(SSFTLSCTrustFromPEM(pem, len, _utTrustPool, sizeof(_utTrustPool),
                                        _utTrustDers, NULL, 4u, &_utTrustStore, &used, &count));
    SSF_ASSERT_TEST(SSFTLSCTrustFromPEM(pem, len, _utTrustPool, sizeof(_utTrustPool),
                                        _utTrustDers, _utTrustLens, 4u, NULL, &used, &count));
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
    _SSFTLSCUTSendFlight();
    _SSFTLSCUTServerHelloExts();
    _SSFTLSCUTServerHelloVersion();
    _SSFTLSCUTServerHelloChecks();
    _SSFTLSCUTPlainOverflow();
    _SSFTLSCUTRecordTypeFirst();
    _SSFTLSCUTMidHandshakeRecords();
    _SSFTLSCUTRfc8448Simple();
    _SSFTLSCUTRfc8448Compat();
    _SSFTLSCUTRfc8448Hrr();
    _SSFTLSCUTRfc8448ClientAuth();
    _SSFTLSCUTServerFlightNegative();
    _SSFTLSCUTClientChain();
    _SSFTLSCUTAlpn();
    _SSFTLSCUTTrustFromPEM();

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
