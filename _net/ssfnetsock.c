/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfnetsock.c                                                                                  */
/* Provides a plaintext TCP implementation of the ssfnet transport over BSD sockets or Winsock.  */
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
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else /* _WIN32 */
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif /* _WIN32 */

/* ssfport.h supplies its own byte order macros; drop the system ones so they are not redefined. */
#undef htons
#undef ntohs
#undef htonl
#undef ntohl

#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfstr.h"
#include "ssfnet.h"
#include "ssfnetsock.h"

/* --------------------------------------------------------------------------------------------- */
/* Platform shims                                                                                */
/* --------------------------------------------------------------------------------------------- */
#ifdef _WIN32
#define SSF_NETSOCK_INVALID          ((SSFNetSockHandle_t)INVALID_SOCKET)
#define SSF_NETSOCK_ERRNO()          WSAGetLastError()
#define SSF_NETSOCK_EWOULDBLOCK      WSAEWOULDBLOCK
#define SSF_NETSOCK_EINPROGRESS      WSAEWOULDBLOCK   /* Non-blocking connect() in progress */
#define SSF_NETSOCK_ECONNRESET       WSAECONNRESET
#define SSF_NETSOCK_ECONNABORTED     WSAECONNABORTED
#define SSF_NETSOCK_ESHUTDOWN        WSAESHUTDOWN
#define SSF_NETSOCK_CLOSE(s)         closesocket((SOCKET)(s))
#define SSF_NETSOCK_SEND_FLAGS       (0)
#define SSF_NETSOCK_FD(s)            ((SOCKET)(s))    /* Handle as the API wants it            */
#define SSF_NETSOCK_NFDS(s)          (0)              /* select() ignores nfds on Winsock      */
typedef int SSFNetSockLen_t;                          /* Address and option lengths            */
typedef int SSFNetSockIOLen_t;                        /* send()/recv() byte counts             */
#else /* _WIN32 */
#define SSF_NETSOCK_INVALID          ((SSFNetSockHandle_t)-1)
#define SSF_NETSOCK_ERRNO()          errno
#define SSF_NETSOCK_EWOULDBLOCK      EWOULDBLOCK
#define SSF_NETSOCK_EINPROGRESS      EINPROGRESS
#define SSF_NETSOCK_ECONNRESET       ECONNRESET
#define SSF_NETSOCK_ECONNABORTED     ECONNABORTED
#define SSF_NETSOCK_ESHUTDOWN        EPIPE
#define SSF_NETSOCK_CLOSE(s)         close(s)
#ifdef MSG_NOSIGNAL
#define SSF_NETSOCK_SEND_FLAGS       (MSG_NOSIGNAL)   /* No SIGPIPE on a reset peer */
#else
#define SSF_NETSOCK_SEND_FLAGS       (0)
#endif
#define SSF_NETSOCK_FD(s)            ((int)(s))
#define SSF_NETSOCK_NFDS(s)          ((int)(s) + 1)
typedef socklen_t SSFNetSockLen_t;
typedef size_t SSFNetSockIOLen_t;
#endif /* _WIN32 */

#define SSF_NETSOCK_INIT_MAGIC       (0x4e534f43ul)   /* 'NSOC' */
#define SSF_NETSOCK_PORT_STR_SIZE    (6u)             /* "65535" + NUL */

/* --------------------------------------------------------------------------------------------- */
/* Module variables                                                                              */
/* --------------------------------------------------------------------------------------------- */
#ifdef _WIN32
static uint32_t _wsaUsers;           /* Instances initialized; Winsock is up while non-zero */
#endif

/* --------------------------------------------------------------------------------------------- */
/* Local prototypes                                                                              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockOpen(SSFNetTransport_t *t, SSFCStrIn_t host, size_t hostSize, uint16_t port);
static SSFNetIOResult_t _SSFNetSockPollOpen(SSFNetTransport_t *t);
static SSFNetIOResult_t _SSFNetSockSend(SSFNetTransport_t *t, const uint8_t *buf, size_t len,
                              size_t *sentOut);
static SSFNetIOResult_t _SSFNetSockRecv(SSFNetTransport_t *t, uint8_t *buf, size_t size, size_t *gotOut);
static void _SSFNetSockClose(SSFNetTransport_t *t);

/* --------------------------------------------------------------------------------------------- */
/* Returns the instance that owns transport t.                                                   */
/* --------------------------------------------------------------------------------------------- */
static SSFNetSock_t *_SSFNetSockSelf(SSFNetTransport_t *t)
{
    SSFNetSock_t *s;

    SSF_REQUIRE(t != NULL);
    s = (SSFNetSock_t *)t;
    SSF_REQUIRE(s->magic == SSF_NETSOCK_INIT_MAGIC);
    return s;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the socket was set non-blocking, else false.                                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockSetNonBlocking(SSFNetSockHandle_t sock)
{
#ifdef _WIN32
    u_long on = 1;

    SSF_REQUIRE(sock != SSF_NETSOCK_INVALID);
    return (ioctlsocket((SOCKET)sock, FIONBIO, &on) == 0);
#else
    int flags;

    SSF_REQUIRE(sock != SSF_NETSOCK_INVALID);
    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return false;
    return (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0);
#endif
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the transport result for a failed send() or recv() errno.                             */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetSockMapIOError(int err, SSFNetIOResult_t wouldBlock)
{
    SSF_REQUIRE((wouldBlock == SSF_NET_IO_WANT_READ) || (wouldBlock == SSF_NET_IO_WANT_WRITE));

    if (err == SSF_NETSOCK_EWOULDBLOCK) return wouldBlock;
#ifndef _WIN32
    if (err == EAGAIN) return wouldBlock;
    if (err == EINTR) return wouldBlock;      /* Interrupted before any data moved; retry */
#endif
    if ((err == SSF_NETSOCK_ECONNRESET) || (err == SSF_NETSOCK_ECONNABORTED) ||
        (err == SSF_NETSOCK_ESHUTDOWN))
    { return SSF_NET_IO_CLOSED; }
    return SSF_NET_IO_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Closes the socket if open and marks the instance closed.                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockRelease(SSFNetSock_t *s)
{
    SSF_REQUIRE(s != NULL);

    if (s->sock != SSF_NETSOCK_INVALID) (void)SSF_NETSOCK_CLOSE(s->sock);
    s->sock = SSF_NETSOCK_INVALID;
    s->state = SSF_NETSOCK_STATE_CLOSED;
}

/* --------------------------------------------------------------------------------------------- */
/* Transport operations                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a connection attempt to host:port was started, else false.                    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockOpen(SSFNetTransport_t *t, SSFCStrIn_t host, size_t hostSize, uint16_t port)
{
    SSFNetSock_t *s;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    char portStr[SSF_NETSOCK_PORT_STR_SIZE];
    size_t hostLen;

    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE(host != NULL);
    SSF_REQUIRE(hostSize > 0);
    s = _SSFNetSockSelf(t);
    SSF_REQUIRE(s->state == SSF_NETSOCK_STATE_CLOSED);

    if ((SSFStrLen(host, hostSize, &hostLen) == false) || (hostLen == 0)) return false;
    if (port == 0) return false;
    (void)snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);

    /* Resolve. This is the one blocking step; see the header. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(host, portStr, &hints, &res) != 0) return false;

    /* Start a non-blocking connect to the first address that accepts the attempt. */
    for (ai = res; ai != NULL; ai = ai->ai_next)
    {
        SSFNetSockHandle_t sock;
        int rc;

        sock = (SSFNetSockHandle_t)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == SSF_NETSOCK_INVALID) continue;
        if (_SSFNetSockSetNonBlocking(sock) == false) { (void)SSF_NETSOCK_CLOSE(sock); continue; }

        rc = connect(SSF_NETSOCK_FD(sock), ai->ai_addr, (SSFNetSockLen_t)ai->ai_addrlen);
        if (rc == 0)
        {
            s->sock = sock;
            s->state = SSF_NETSOCK_STATE_CONNECTED;     /* Local or very fast peer */
            break;
        }
        if (SSF_NETSOCK_ERRNO() == SSF_NETSOCK_EINPROGRESS)
        {
            s->sock = sock;
            s->state = SSF_NETSOCK_STATE_CONNECTING;
            break;
        }
        (void)SSF_NETSOCK_CLOSE(sock);
    }
    freeaddrinfo(res);
    return (s->state != SSF_NETSOCK_STATE_CLOSED);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS once connected, WANT_WRITE while connecting, else CLOSED or ERROR.            */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetSockPollOpen(SSFNetTransport_t *t)
{
    SSFNetSock_t *s;
    fd_set wfds;
    fd_set efds;
    struct timeval tv;
    int rc;
    int err = 0;
    SSFNetSockLen_t errLen = (SSFNetSockLen_t)sizeof(err);

    SSF_REQUIRE(t != NULL);
    s = _SSFNetSockSelf(t);
    if (s->state == SSF_NETSOCK_STATE_CONNECTED) return SSF_NET_IO_SUCCESS;
    if (s->state != SSF_NETSOCK_STATE_CONNECTING) return SSF_NET_IO_ERROR;

    /* Writable means the connect finished, one way or the other; Winsock reports a failed      */
    /* connect through the exception set instead.                                               */
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    FD_SET(SSF_NETSOCK_FD(s->sock), &wfds);
    FD_SET(SSF_NETSOCK_FD(s->sock), &efds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    rc = select(SSF_NETSOCK_NFDS(s->sock), NULL, &wfds, &efds, &tv);
    if (rc < 0) { _SSFNetSockRelease(s); return SSF_NET_IO_ERROR; }
    if (rc == 0) return SSF_NET_IO_WANT_WRITE;

    if (getsockopt(SSF_NETSOCK_FD(s->sock), SOL_SOCKET, SO_ERROR, (char *)&err, &errLen) != 0)
    { _SSFNetSockRelease(s); return SSF_NET_IO_ERROR; }
    if ((err != 0) || FD_ISSET(SSF_NETSOCK_FD(s->sock), &efds))
    {
        _SSFNetSockRelease(s);
        return ((err == SSF_NETSOCK_ECONNRESET) || (err == SSF_NETSOCK_ECONNABORTED)) ?
               SSF_NET_IO_CLOSED : SSF_NET_IO_ERROR;
    }
    s->state = SSF_NETSOCK_STATE_CONNECTED;
    return SSF_NET_IO_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS with bytes accepted, WANT_WRITE if none could be, else CLOSED or ERROR.       */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetSockSend(SSFNetTransport_t *t, const uint8_t *buf, size_t len,
                              size_t *sentOut)
{
    SSFNetSock_t *s;
    SSFNetSockIOLen_t n;
    long rc;

    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(len > 0);
    SSF_REQUIRE(sentOut != NULL);
    s = _SSFNetSockSelf(t);

    *sentOut = 0;
    if (s->state != SSF_NETSOCK_STATE_CONNECTED) return SSF_NET_IO_ERROR;

    n = (len > (size_t)INT_MAX) ? (SSFNetSockIOLen_t)INT_MAX : (SSFNetSockIOLen_t)len;
    rc = (long)send(SSF_NETSOCK_FD(s->sock), (const char *)buf, n, SSF_NETSOCK_SEND_FLAGS);
    if (rc > 0) { *sentOut = (size_t)rc; return SSF_NET_IO_SUCCESS; }
    if (rc == 0) return SSF_NET_IO_WANT_WRITE;
    return _SSFNetSockMapIOError(SSF_NETSOCK_ERRNO(), SSF_NET_IO_WANT_WRITE);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS with bytes received, WANT_READ if none, CLOSED at end of stream, else ERROR.  */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetSockRecv(SSFNetTransport_t *t, uint8_t *buf, size_t size, size_t *gotOut)
{
    SSFNetSock_t *s;
    SSFNetSockIOLen_t n;
    long rc;

    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(size > 0);
    SSF_REQUIRE(gotOut != NULL);
    s = _SSFNetSockSelf(t);

    *gotOut = 0;
    if (s->state != SSF_NETSOCK_STATE_CONNECTED) return SSF_NET_IO_ERROR;

    n = (size > (size_t)INT_MAX) ? (SSFNetSockIOLen_t)INT_MAX : (SSFNetSockIOLen_t)size;
    rc = (long)recv(SSF_NETSOCK_FD(s->sock), (char *)buf, n, 0);
    if (rc > 0) { *gotOut = (size_t)rc; return SSF_NET_IO_SUCCESS; }
    if (rc == 0) return SSF_NET_IO_CLOSED;             /* Orderly shutdown by the peer */
    return _SSFNetSockMapIOError(SSF_NETSOCK_ERRNO(), SSF_NET_IO_WANT_READ);
}

/* --------------------------------------------------------------------------------------------- */
/* Closes the connection or attempt.                                                             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockClose(SSFNetTransport_t *t)
{
    SSF_REQUIRE(t != NULL);
    _SSFNetSockRelease(_SSFNetSockSelf(t));
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes a socket transport instance.                                                      */
/* --------------------------------------------------------------------------------------------- */
void SSFNetSockInit(SSFNetSock_t *s)
{
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(s->magic != SSF_NETSOCK_INIT_MAGIC);

#ifdef _WIN32
    if (_wsaUsers == 0)
    {
        WSADATA wsa;
        SSF_ASSERT(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    }
    _wsaUsers++;
#endif

    memset(s, 0, sizeof(*s));
    s->transport.open = _SSFNetSockOpen;
    s->transport.pollOpen = _SSFNetSockPollOpen;
    s->transport.send = _SSFNetSockSend;
    s->transport.recv = _SSFNetSockRecv;
    s->transport.close = _SSFNetSockClose;
    s->sock = SSF_NETSOCK_INVALID;
    s->state = SSF_NETSOCK_STATE_CLOSED;
    s->magic = SSF_NETSOCK_INIT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes a socket transport instance, closing any connection.                            */
/* --------------------------------------------------------------------------------------------- */
void SSFNetSockDeInit(SSFNetSock_t *s)
{
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(s->magic == SSF_NETSOCK_INIT_MAGIC);

    _SSFNetSockRelease(s);
    memset(s, 0, sizeof(*s));

#ifdef _WIN32
    SSF_ASSERT(_wsaUsers > 0);
    _wsaUsers--;
    if (_wsaUsers == 0) (void)WSACleanup();
#endif
}
