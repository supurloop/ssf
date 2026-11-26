/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfnetsock_ut.c                                                                               */
/* Unit test for the plaintext TCP transport and its non-blocking name resolution.               */
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
#include "ssf.h"
#include "ssfassert.h"
#include "ssfnet.h"
#include "ssfnetsock.h"

#if SSF_CONFIG_NETSOCK_UNIT_TEST == 1

/* --------------------------------------------------------------------------------------------- */
/* Test-side sockets. Everything runs over loopback, so no network access is needed.             */
/* --------------------------------------------------------------------------------------------- */
#ifdef _WIN32
typedef SOCKET SSFNetSockUTFd_t;
#define SSF_NETSOCK_UT_INVALID       INVALID_SOCKET
#define SSF_NETSOCK_UT_CLOSE(s)      closesocket(s)
#define SSF_NETSOCK_UT_NFDS(a, b)    (0)
#else
typedef int SSFNetSockUTFd_t;
#define SSF_NETSOCK_UT_INVALID       (-1)
#define SSF_NETSOCK_UT_CLOSE(s)      close(s)
#define SSF_NETSOCK_UT_NFDS(a, b)    ((((a) > (b)) ? (a) : (b)) + 1)
#endif

#define SSF_NETSOCK_UT_WAIT_TICKS    (SSF_TICKS_PER_SEC * 5u)
#define SSF_NETSOCK_UT_NXDOMAIN_TICKS (SSF_TICKS_PER_SEC * 30u)
#define SSF_NETSOCK_UT_INSTANCES     (SSF_NETSOCK_CONFIG_MAX_LOOKUPS + 1u)

typedef struct
{
    SSFNetSockUTFd_t v4;             /* 127.0.0.1:port */
    SSFNetSockUTFd_t v6;             /* [::1]:port, or invalid where IPv6 loopback is missing */
    uint16_t port;
} SSFNetSockUTListener_t;

static SSFNetSock_t _utSocks[SSF_NETSOCK_UT_INSTANCES];
extern bool _ssfNetSockUTNoCancel;   /* ssfnetsock.c test hook */

/* --------------------------------------------------------------------------------------------- */
/* Opens loopback listeners on one ephemeral port for IPv4 and, if available, IPv6.              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockUTListen(SSFNetSockUTListener_t *l)
{
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    socklen_t len = (socklen_t)sizeof(sin);
    int on = 1;

    SSF_REQUIRE(l != NULL);

    l->v4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SSF_ASSERT(l->v4 != SSF_NETSOCK_UT_INVALID);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    SSF_ASSERT(inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr) == 1);
    SSF_ASSERT(bind(l->v4, (struct sockaddr *)&sin, (socklen_t)sizeof(sin)) == 0);
    SSF_ASSERT(listen(l->v4, 8) == 0);
    SSF_ASSERT(getsockname(l->v4, (struct sockaddr *)&sin, &len) == 0);
    l->port = (uint16_t)((((const uint8_t *)&sin.sin_port)[0] << 8) |
                         ((const uint8_t *)&sin.sin_port)[1]);

    l->v6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    /* No IPv6 socket available? */
    if (l->v6 == SSF_NETSOCK_UT_INVALID) return;
    (void)setsockopt(l->v6, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&on, (socklen_t)sizeof(on));
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = sin.sin_port;
    SSF_ASSERT(inet_pton(AF_INET6, "::1", &sin6.sin6_addr) == 1);
    /* IPv6 loopback unusable? */
    if ((bind(l->v6, (struct sockaddr *)&sin6, (socklen_t)sizeof(sin6)) != 0) ||
        (listen(l->v6, 8) != 0))
    {
        /* Yes, run IPv4 only */
        (void)SSF_NETSOCK_UT_CLOSE(l->v6);
        l->v6 = SSF_NETSOCK_UT_INVALID;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Closes the listeners.                                                                         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockUTUnlisten(SSFNetSockUTListener_t *l)
{
    SSF_REQUIRE(l != NULL);

    (void)SSF_NETSOCK_UT_CLOSE(l->v4);
    if (l->v6 != SSF_NETSOCK_UT_INVALID) (void)SSF_NETSOCK_UT_CLOSE(l->v6);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the accepted peer of a connection that has reached either listener.                   */
/* --------------------------------------------------------------------------------------------- */
static SSFNetSockUTFd_t _SSFNetSockUTAccept(const SSFNetSockUTListener_t *l)
{
    fd_set rfds;
    struct timeval tv;
    SSFNetSockUTFd_t peer;
    int max6;

    SSF_REQUIRE(l != NULL);

    FD_ZERO(&rfds);
    FD_SET(l->v4, &rfds);
    if (l->v6 != SSF_NETSOCK_UT_INVALID) FD_SET(l->v6, &rfds);
    max6 = ((l->v6 != SSF_NETSOCK_UT_INVALID) ? ((int)l->v6) : 0);
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    SSF_ASSERT(select(SSF_NETSOCK_UT_NFDS((int)l->v4, max6), &rfds, NULL, NULL, &tv) > 0);
    /* Connection arrived on the IPv4 listener? */
    if (FD_ISSET(l->v4, &rfds)) peer = accept(l->v4, NULL, NULL);
    else peer = accept(l->v6, NULL, NULL);
    SSF_ASSERT(peer != SSF_NETSOCK_UT_INVALID);
    return peer;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the first pollOpen() result other than WANT_READ/WANT_WRITE, polling for up to ticks. */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetSockUTPollOpen(SSFNetSock_t *s, SSFPortTick_t ticks)
{
    SSFPortTick_t end;
    SSFNetIOResult_t r;

    SSF_REQUIRE(s != NULL);

    end = (SSFPortGetTick64() + ticks);
    do
    {
        r = s->transport.pollOpen(&s->transport);
        if ((r != SSF_NET_IO_WANT_READ) && (r != SSF_NET_IO_WANT_WRITE)) return r;
    } while (SSFPortGetTick64() < end);
    return r;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true once open() succeeds, retrying while abandoned lookups finish and are reaped.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockUTOpenRetry(SSFNetSock_t *s, const char *hostStr, uint16_t port)
{
    SSFPortTick_t end;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(hostStr != NULL);

    end = (SSFPortGetTick64() + SSF_NETSOCK_UT_WAIT_TICKS);
    do
    {
        if (s->transport.open(&s->transport, hostStr, (strlen(hostStr) + 1), port)) return true;
    } while (SSFPortGetTick64() < end);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Verifies an open connection carries bytes both ways, then closes it.                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockUTEcho(SSFNetSock_t *s, const SSFNetSockUTListener_t *l)
{
    static const uint8_t ping[] = { 'p', 'i', 'n', 'g' };
    uint8_t buf[sizeof(ping)];
    SSFNetSockUTFd_t peer;
    size_t sent = 0;
    size_t got = 0;
    SSFPortTick_t end;
    SSFNetIOResult_t r;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(l != NULL);

    peer = _SSFNetSockUTAccept(l);
    SSF_ASSERT(s->transport.send(&s->transport, ping, sizeof(ping), &sent) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(sent == sizeof(ping));
    SSF_ASSERT(recv(peer, (char *)buf, (int)sizeof(buf), MSG_WAITALL) == (int)sizeof(buf));
    SSF_ASSERT(memcmp(buf, ping, sizeof(ping)) == 0);
    SSF_ASSERT(send(peer, (const char *)ping, (int)sizeof(ping), 0) == (int)sizeof(ping));

    memset(buf, 0, sizeof(buf));
    end = (SSFPortGetTick64() + SSF_NETSOCK_UT_WAIT_TICKS);
    do
    {
        size_t n = 0;

        r = s->transport.recv(&s->transport, (buf + got), (sizeof(buf) - got), &n);
        SSF_ASSERT((r == SSF_NET_IO_SUCCESS) || (r == SSF_NET_IO_WANT_READ));
        got += n;
    } while ((got < sizeof(buf)) && (SSFPortGetTick64() < end));
    SSF_ASSERT(got == sizeof(buf));
    SSF_ASSERT(memcmp(buf, ping, sizeof(ping)) == 0);

    /* shutdown() succeeds at once and on repeat, and recv() stays valid after it */
    SSF_ASSERT(s->transport.shutdown(&s->transport) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(s->transport.shutdown(&s->transport) == SSF_NET_IO_SUCCESS);

    /* Peer close is reported as CLOSED */
    (void)SSF_NETSOCK_UT_CLOSE(peer);
    end = (SSFPortGetTick64() + SSF_NETSOCK_UT_WAIT_TICKS);
    do
    {
        size_t n = 0;

        r = s->transport.recv(&s->transport, buf, sizeof(buf), &n);
    } while ((r == SSF_NET_IO_WANT_READ) && (SSFPortGetTick64() < end));
    SSF_ASSERT(r == SSF_NET_IO_CLOSED);

    s->transport.close(&s->transport);
    SSF_ASSERT(s->state == SSF_NETSOCK_STATE_CLOSED);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs the ssfnetsock unit test.                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFNetSockUnitTest(void)
{
    SSFNetSockUTListener_t l;
    SSFNetSock_t *s = &_utSocks[0];
    SSFNetTransport_t *t = &s->transport;
    char longHost[SSF_NETSOCK_CONFIG_MAX_HOST_SIZE + 1];
    uint16_t deadPort;
    uint32_t i;

    /* Init/DeInit; Init also starts Winsock, which the listeners below need */
    SSFNetSockInit(s);
    SSF_ASSERT(s->state == SSF_NETSOCK_STATE_CLOSED);
    SSF_ASSERT(s->lookup == SSF_NETSOCK_NO_LOOKUP);
    SSF_ASSERT(t->pollOpen(t) == SSF_NET_IO_ERROR);           /* Not opened */
    SSF_ASSERT(t->shutdown(t) == SSF_NET_IO_ERROR);           /* Not connected */
    SSF_ASSERT_TEST(SSFNetSockInit(s));                        /* Already initialized */
    _SSFNetSockUTListen(&l);

    /* Rejected arguments */
    SSF_ASSERT(t->open(t, "", 1, l.port) == false);
    SSF_ASSERT(t->open(t, "127.0.0.1", sizeof("127.0.0.1"), 0) == false);
    SSF_ASSERT(t->open(t, "127.0.0.1", 4, l.port) == false);  /* Not terminated within size */
    memset(longHost, 'a', sizeof(longHost));
    longHost[sizeof(longHost) - 1] = 0;                        /* MAX_HOST_SIZE characters */
    SSF_ASSERT(t->open(t, longHost, sizeof(longHost), l.port) == false);
    SSF_ASSERT(s->state == SSF_NETSOCK_STATE_CLOSED);

    /* Literal IPv4 address: no lookup */
    SSF_ASSERT(t->open(t, "127.0.0.1", sizeof("127.0.0.1"), l.port));
    SSF_ASSERT(s->state != SSF_NETSOCK_STATE_RESOLVING);
    SSF_ASSERT(s->lookup == SSF_NETSOCK_NO_LOOKUP);
    SSF_ASSERT_TEST(t->open(t, "127.0.0.1", sizeof("127.0.0.1"), l.port));   /* Not closed */
    SSF_ASSERT(_SSFNetSockUTPollOpen(s, SSF_NETSOCK_UT_WAIT_TICKS) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(t->pollOpen(t) == SSF_NET_IO_SUCCESS);          /* Stays connected */
    _SSFNetSockUTEcho(s, &l);

    /* close() with received data unread ends with FIN, not RST, so the peer reads the last bytes */
    {
        static const uint8_t flight[64] = { 0 };
        SSFNetSockUTFd_t peer;
        uint8_t b[4];
        size_t sent = 0;
        int n;
        SSFPortTick_t end;

        SSF_ASSERT(t->open(t, "127.0.0.1", sizeof("127.0.0.1"), l.port));
        SSF_ASSERT(_SSFNetSockUTPollOpen(s, SSF_NETSOCK_UT_WAIT_TICKS) == SSF_NET_IO_SUCCESS);
        peer = _SSFNetSockUTAccept(&l);
        SSF_ASSERT(send(peer, (const char *)flight, (int)sizeof(flight), 0) == (int)sizeof(flight));
        end = (SSFPortGetTick64() + SSF_NETSOCK_UT_WAIT_TICKS); /* Flight reaches the client */
        while (SSFPortGetTick64() < end)
        {
            fd_set rfds;
            struct timeval tv = { 0, 0 };

            FD_ZERO(&rfds);
            FD_SET(s->sock, &rfds);
            if (select((int)s->sock + 1, &rfds, NULL, NULL, &tv) > 0) break;
        }
        SSF_ASSERT(t->send(t, (const uint8_t *)"X", 1, &sent) == SSF_NET_IO_SUCCESS);
        t->close(t);                                           /* Flight still unread */
        end = (SSFPortGetTick64() + (SSF_TICKS_PER_SEC / 5u)); /* FIN or RST reaches the peer */
        while (SSFPortGetTick64() < end) { }
        n = recv(peer, (char *)b, (int)sizeof(b), 0);
        SSF_ASSERT(n == 1);
        SSF_ASSERT(b[0] == 'X');
        n = recv(peer, (char *)b, (int)sizeof(b), 0);
        SSF_ASSERT(n == 0);                                    /* Orderly EOF, not ECONNRESET */
        (void)SSF_NETSOCK_UT_CLOSE(peer);
    }

    /* IPv4 only (ssfnet.h): an IPv6 literal is refused at open(), with nothing started */
    SSF_ASSERT(t->open(t, "::1", sizeof("::1"), l.port) == false);
    SSF_ASSERT(t->open(t, "2001:db8::1", sizeof("2001:db8::1"), l.port) == false);
    SSF_ASSERT(t->open(t, "::ffff:127.0.0.1", sizeof("::ffff:127.0.0.1"), l.port) == false);
    SSF_ASSERT(s->state == SSF_NETSOCK_STATE_CLOSED);
    SSF_ASSERT(s->lookup == SSF_NETSOCK_NO_LOOKUP);

    /* A host name never connects over IPv6: with only [::1] listening "localhost" must fail */
    {
        SSFNetSockUTListener_t v6only;
        SSFNetIOResult_t r;

        _SSFNetSockUTListen(&v6only);
        /* IPv6 loopback available? */
        if (v6only.v6 != SSF_NETSOCK_UT_INVALID)
        {
            /* Yes, leave only [::1]:port listening */
            (void)SSF_NETSOCK_UT_CLOSE(v6only.v4);
            v6only.v4 = SSF_NETSOCK_UT_INVALID;
            SSF_ASSERT(_SSFNetSockUTOpenRetry(s, "localhost", v6only.port));
            r = _SSFNetSockUTPollOpen(s, SSF_NETSOCK_UT_WAIT_TICKS);
            SSF_ASSERT((r == SSF_NET_IO_ERROR) || (r == SSF_NET_IO_CLOSED));
            SSF_ASSERT(s->state == SSF_NETSOCK_STATE_CLOSED);
            (void)SSF_NETSOCK_UT_CLOSE(v6only.v6);
        }
        else
        {
            /* No, nothing to test */
            (void)SSF_NETSOCK_UT_CLOSE(v6only.v4);
        }
    }

    /* Refused connect to a port nobody listens on */
    {
        SSFNetSockUTListener_t dead;

        _SSFNetSockUTListen(&dead);
        deadPort = dead.port;
        _SSFNetSockUTUnlisten(&dead);
    }
    /* Refusal not already detected by open()? */
    if (t->open(t, "127.0.0.1", sizeof("127.0.0.1"), deadPort))
    {
        /* Yes, pollOpen() reports it */
        SSFNetIOResult_t r = _SSFNetSockUTPollOpen(s, SSF_NETSOCK_UT_WAIT_TICKS);
        SSF_ASSERT((r == SSF_NET_IO_ERROR) || (r == SSF_NET_IO_CLOSED));
    }
    SSF_ASSERT(s->state == SSF_NETSOCK_STATE_CLOSED);

    /* Host name: open() returns at once in RESOLVING, pollOpen() finishes the job */
#if defined(_WIN32) || defined(__APPLE__) || defined(__GLIBC__)
    SSF_ASSERT(_SSFNetSockUTOpenRetry(s, "localhost", l.port));
    SSF_ASSERT(s->state == SSF_NETSOCK_STATE_RESOLVING);
    SSF_ASSERT(s->lookup != SSF_NETSOCK_NO_LOOKUP);
    SSF_ASSERT(_SSFNetSockUTPollOpen(s, SSF_NETSOCK_UT_WAIT_TICKS) == SSF_NET_IO_SUCCESS);
    SSF_ASSERT(s->lookup == SSF_NETSOCK_NO_LOOKUP);
    _SSFNetSockUTEcho(s, &l);

    /* close() mid-lookup returns at once and leaks no lookup slot */
    for (i = 0; i < (SSF_NETSOCK_CONFIG_MAX_LOOKUPS * 4u); i++)
    {
        SSF_ASSERT(_SSFNetSockUTOpenRetry(s, "localhost", l.port));
        t->close(t);
        SSF_ASSERT(s->state == SSF_NETSOCK_STATE_CLOSED);
        SSF_ASSERT(s->lookup == SSF_NETSOCK_NO_LOOKUP);
    }
    SSF_ASSERT(_SSFNetSockUTOpenRetry(s, "localhost", l.port));
    SSF_ASSERT(_SSFNetSockUTPollOpen(s, SSF_NETSOCK_UT_WAIT_TICKS) == SSF_NET_IO_SUCCESS);
    _SSFNetSockUTEcho(s, &l);

    /* Uncancelable lookups abandoned by close() and DeInit() are reaped, so open() works again */
    _ssfNetSockUTNoCancel = true;
    for (i = 0; i < (SSF_NETSOCK_CONFIG_MAX_LOOKUPS * 4u); i++)
    {
        SSF_ASSERT(_SSFNetSockUTOpenRetry(s, "localhost", l.port));
        t->close(t);
        SSF_ASSERT(s->state == SSF_NETSOCK_STATE_CLOSED);
    }
    SSFNetSockInit(&_utSocks[1]);
    SSF_ASSERT(_SSFNetSockUTOpenRetry(&_utSocks[1], "localhost", l.port));
    SSFNetSockDeInit(&_utSocks[1]);
    _ssfNetSockUTNoCancel = false;
    SSF_ASSERT(_SSFNetSockUTOpenRetry(s, "localhost", l.port));
    SSF_ASSERT(_SSFNetSockUTPollOpen(s, SSF_NETSOCK_UT_WAIT_TICKS) == SSF_NET_IO_SUCCESS);
    _SSFNetSockUTEcho(s, &l);

    /* Lookup slots are shared: one more lookup than slots is refused until one is released */
    for (i = 1; i < SSF_NETSOCK_UT_INSTANCES; i++) SSFNetSockInit(&_utSocks[i]);
    for (i = 0; i < SSF_NETSOCK_CONFIG_MAX_LOOKUPS; i++)
    {
        SSF_ASSERT(_SSFNetSockUTOpenRetry(&_utSocks[i], "localhost", l.port));
    }
    i = (SSF_NETSOCK_UT_INSTANCES - 1u);
    SSF_ASSERT(_utSocks[i].transport.open(&_utSocks[i].transport, "localhost",
                                          sizeof("localhost"), l.port) == false);
    SSF_ASSERT(_utSocks[i].state == SSF_NETSOCK_STATE_CLOSED);
    SSF_ASSERT(_utSocks[i].transport.open(&_utSocks[i].transport, "127.0.0.1",
                                          sizeof("127.0.0.1"), l.port));   /* Literal: no slot */
    SSF_ASSERT(_SSFNetSockUTPollOpen(&_utSocks[i], SSF_NETSOCK_UT_WAIT_TICKS) ==
               SSF_NET_IO_SUCCESS);
    _SSFNetSockUTEcho(&_utSocks[i], &l);
    SSF_ASSERT(_SSFNetSockUTPollOpen(&_utSocks[0], SSF_NETSOCK_UT_WAIT_TICKS) ==
               SSF_NET_IO_SUCCESS);                            /* Frees its slot */
    _SSFNetSockUTEcho(&_utSocks[0], &l);       /* Before the next connect, so accept() matches */
    SSF_ASSERT(_SSFNetSockUTOpenRetry(&_utSocks[i], "localhost", l.port));
    SSF_ASSERT(_SSFNetSockUTPollOpen(&_utSocks[i], SSF_NETSOCK_UT_WAIT_TICKS) ==
               SSF_NET_IO_SUCCESS);
    _SSFNetSockUTEcho(&_utSocks[i], &l);

    /* DeInit mid-lookup returns at once; the instance can be initialized again */
    for (i = 1; i < SSF_NETSOCK_UT_INSTANCES; i++) SSFNetSockDeInit(&_utSocks[i]);
    for (i = 1; i < SSF_NETSOCK_UT_INSTANCES; i++) SSFNetSockInit(&_utSocks[i]);
    for (i = 1; i < SSF_NETSOCK_UT_INSTANCES; i++) SSFNetSockDeInit(&_utSocks[i]);

    /* A name that cannot exist (RFC 6761) fails through pollOpen(), not open() */
    SSF_ASSERT(_SSFNetSockUTOpenRetry(s, "ssfnetsock-ut.invalid", l.port));
    SSF_ASSERT(s->state == SSF_NETSOCK_STATE_RESOLVING);
    SSF_ASSERT(_SSFNetSockUTPollOpen(s, SSF_NETSOCK_UT_NXDOMAIN_TICKS) == SSF_NET_IO_ERROR);
    SSF_ASSERT(s->state == SSF_NETSOCK_STATE_CLOSED);
    SSF_ASSERT(s->lookup == SSF_NETSOCK_NO_LOOKUP);
#else
    /* No asynchronous resolver: host names are refused rather than resolved by blocking */
    SSF_ASSERT(t->open(t, "localhost", sizeof("localhost"), l.port) == false);
    (void)i;
#endif

    _SSFNetSockUTUnlisten(&l);
    SSFNetSockDeInit(s);
    SSF_ASSERT(s->magic == 0);
    SSF_ASSERT_TEST(SSFNetSockDeInit(s));                      /* Not initialized */
}
#endif /* SSF_CONFIG_NETSOCK_UNIT_TEST */
