/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfnetsock.c                                                                                  */
/* Provides a plaintext TCP ssfnet transport over BSD sockets or Winsock, with non-blocking DNS. */
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
#define _GNU_SOURCE                  /* getaddrinfo_a() on glibc; must precede every system header */
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602          /* Windows 8: GetAddrInfoExW with OVERLAPPED */
#endif
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
#include <arpa/inet.h>
#ifdef __APPLE__
#include <dns_sd.h>
#endif /* __APPLE__ */
#endif /* _WIN32 */

#ifndef __APPLE__
/* ssfport.h supplies its own byte order macros; drop the system ones so they are not redefined. */
/* On macOS ssfport.h uses the system macros instead, so they stay.                              */
#undef htons
#undef ntohs
#undef htonl
#undef ntohl
#endif /* __APPLE__ */

#include "ssfport.h"
#include "ssf.h"
#include "ssfassert.h"
#include "ssfstr.h"
#include "ssfnet.h"
#include "ssfnetsock.h"

/* --------------------------------------------------------------------------------------------- */
/* Resolver backend                                                                              */
/* --------------------------------------------------------------------------------------------- */
#if defined(_WIN32)
#if _WIN32_WINNT < 0x0602
#error ssfnetsock needs _WIN32_WINNT >= 0x0602 (Windows 8) for asynchronous name resolution.
#endif
#define SSF_NETSOCK_RESOLVER_WIN     (1u)   /* GetAddrInfoExW + OVERLAPPED event */
#elif defined(__APPLE__)
#define SSF_NETSOCK_RESOLVER_DNSSD   (1u)   /* DNSServiceGetAddrInfo */
#elif defined(__GLIBC__) && defined(GAI_NOWAIT)
#define SSF_NETSOCK_RESOLVER_GAIA    (1u)   /* getaddrinfo_a */
#else
#define SSF_NETSOCK_RESOLVER_NONE    (1u)   /* Literal addresses only */
#endif

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
#define SSF_NETSOCK_DNSSD_MAX_READS  (8u)             /* Replies handled per pollOpen()        */

/* SSF_NETSOCK_ADDR_SIZE in the header must hold either address family.                          */
typedef char _SSFNetSockAddrSizeCheck_t[((sizeof(struct sockaddr_in) <= SSF_NETSOCK_ADDR_SIZE) &&
                                         (sizeof(struct sockaddr_in6) <= SSF_NETSOCK_ADDR_SIZE)) ?
                                        1 : -1];

typedef enum
{
    SSF_NETSOCK_LOOKUP_FREE,         /* Available                                               */
    SSF_NETSOCK_LOOKUP_OWNED,        /* In progress for an instance in RESOLVING                */
    SSF_NETSOCK_LOOKUP_ABANDONED     /* Closed while the OS could not cancel it; awaiting reap  */
} SSFNetSockLookupState_t;

typedef enum
{
    SSF_NETSOCK_LOOKUP_PENDING,
    SSF_NETSOCK_LOOKUP_DONE,
    SSF_NETSOCK_LOOKUP_FAILED
} SSFNetSockLookupResult_t;

/* One asynchronous name lookup. Its storage stays put until the OS is finished with it.         */
typedef struct
{
    SSFNetSockLookupState_t state;
#if defined(SSF_NETSOCK_RESOLVER_WIN)
    OVERLAPPED ov;                   /* hEvent is a manual-reset event while the lookup lives   */
    HANDLE cancel;
    PADDRINFOEXW result;
    ADDRINFOEXW hints;
    bool isComplete;                 /* GetAddrInfoExW finished synchronously with code rc      */
    INT rc;
    WCHAR host[SSF_NETSOCK_CONFIG_MAX_HOST_SIZE];
#elif defined(SSF_NETSOCK_RESOLVER_DNSSD)
    DNSServiceRef ref;
    bool isDone;                     /* At least one address and no reply pending               */
    bool isFailed;
    uint8_t negatives;               /* NoSuchRecord replies; two mean neither family exists    */
    uint8_t addrCount;
    uint8_t addrs[SSF_NETSOCK_CONFIG_MAX_ADDRS][SSF_NETSOCK_ADDR_SIZE];
#elif defined(SSF_NETSOCK_RESOLVER_GAIA)
    struct gaicb cb;
    struct addrinfo hints;
    char host[SSF_NETSOCK_CONFIG_MAX_HOST_SIZE];
#endif
} SSFNetSockLookup_t;

/* --------------------------------------------------------------------------------------------- */
/* Module variables                                                                              */
/* --------------------------------------------------------------------------------------------- */
static SSFNetSockLookup_t _lookups[SSF_NETSOCK_CONFIG_MAX_LOOKUPS];
#if SSF_CONFIG_NETSOCK_UNIT_TEST == 1
bool _ssfNetSockUTNoCancel;          /* Test hook: act as if the OS cannot cancel any lookup     */
#endif
#ifdef _WIN32
static uint32_t _wsaUsers;           /* Instances initialized                                   */
static bool _wsaIsStarted;           /* Winsock up; stays up while any lookup slot is in use    */
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
/* Returns the sockaddr length for an IPv4 or IPv6 family, else 0.                               */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFNetSockAddrLen(int family)
{
    if (family == AF_INET) return sizeof(struct sockaddr_in);
    if (family == AF_INET6) return sizeof(struct sockaddr_in6);
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Appends sa to the instance's address list. Other families and addresses past capacity are     */
/* ignored.                                                                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockAddAddr(SSFNetSock_t *s, const void *sa, size_t saLen)
{
    struct sockaddr_storage ss;
    size_t n;
    size_t len;

    SSF_REQUIRE(s != NULL);

    if ((sa == NULL) || (s->addrCount >= SSF_NETSOCK_CONFIG_MAX_ADDRS)) return;
    n = (saLen < sizeof(ss)) ? saLen : sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    memcpy(&ss, sa, n);                        /* Copy first; sa may not be aligned */
    len = _SSFNetSockAddrLen(ss.ss_family);
    if ((len == 0) || (n < len)) return;
    memset(s->addrs[s->addrCount], 0, SSF_NETSOCK_ADDR_SIZE);
    memcpy(s->addrs[s->addrCount], &ss, len);
    s->addrCount++;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if host is a literal IPv4 or IPv6 address, now in the address list, else false.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockParseLiteral(SSFNetSock_t *s, SSFCStrIn_t host)
{
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(host != NULL);

    memset(&sin, 0, sizeof(sin));
    if (inet_pton(AF_INET, host, &sin.sin_addr) == 1)
    {
        sin.sin_family = AF_INET;
#ifdef __APPLE__
        sin.sin_len = (uint8_t)sizeof(sin);
#endif
        _SSFNetSockAddAddr(s, &sin, sizeof(sin));
        return true;
    }
    memset(&sin6, 0, sizeof(sin6));
    if (inet_pton(AF_INET6, host, &sin6.sin6_addr) == 1)
    {
        sin6.sin6_family = AF_INET6;
#ifdef __APPLE__
        sin6.sin6_len = (uint8_t)sizeof(sin6);
#endif
        _SSFNetSockAddAddr(s, &sin6, sizeof(sin6));
        return true;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the length of address idx copied to ss with the instance's port filled in.            */
/* --------------------------------------------------------------------------------------------- */
static SSFNetSockLen_t _SSFNetSockAddrPrepare(const SSFNetSock_t *s, uint8_t idx,
                                              struct sockaddr_storage *ss)
{
    uint8_t *portBytes;
    size_t len;

    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(idx < s->addrCount);
    SSF_REQUIRE(ss != NULL);

    memset(ss, 0, sizeof(*ss));
    memcpy(ss, s->addrs[idx], SSF_NETSOCK_ADDR_SIZE);
    len = _SSFNetSockAddrLen(ss->ss_family);
    SSF_ASSERT(len != 0);                      /* Only IPv4 and IPv6 are ever stored */
    if (ss->ss_family == AF_INET) portBytes = (uint8_t *)&((struct sockaddr_in *)ss)->sin_port;
    else portBytes = (uint8_t *)&((struct sockaddr_in6 *)ss)->sin6_port;
    portBytes[0] = (uint8_t)(s->port >> 8);    /* Network byte order */
    portBytes[1] = (uint8_t)(s->port & 0xffu);
    return (SSFNetSockLen_t)len;
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
/* Resolver backends. Each provides:                                                             */
/*   Start(l, host, hostLen)  true if the lookup was started                                     */
/*   Poll(l, s)               PENDING, or DONE with addresses added to s, or FAILED; DONE and    */
/*                            FAILED release every OS resource the lookup held                   */
/*   Cancel(l)                true if released now, false if the OS still owns the storage       */
/*   Finished(l)              for an abandoned lookup: true once finished and released           */
/* --------------------------------------------------------------------------------------------- */
#if defined(SSF_NETSOCK_RESOLVER_WIN)

/* --------------------------------------------------------------------------------------------- */
/* Releases the lookup's result list and event.                                                  */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockLookupFree(SSFNetSockLookup_t *l)
{
    SSF_REQUIRE(l != NULL);

    if (l->result != NULL) FreeAddrInfoExW(l->result);
    l->result = NULL;
    if (l->ov.hEvent != NULL) (void)CloseHandle(l->ov.hEvent);
    l->ov.hEvent = NULL;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the lookup was started, else false.                                           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupStart(SSFNetSockLookup_t *l, SSFCStrIn_t host, size_t hostLen)
{
    INT rc;

    SSF_REQUIRE(l != NULL);
    SSF_REQUIRE(host != NULL);
    SSF_REQUIRE(hostLen < SSF_NETSOCK_CONFIG_MAX_HOST_SIZE);

    memset(&l->ov, 0, sizeof(l->ov));
    memset(&l->hints, 0, sizeof(l->hints));
    l->cancel = NULL;
    l->result = NULL;
    l->isComplete = false;
    l->rc = NO_ERROR;

    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host, (int)hostLen + 1, l->host,
                            (int)SSF_NETSOCK_CONFIG_MAX_HOST_SIZE) <= 0)
    { return false; }
    l->ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);   /* Manual reset: required with no  */
    if (l->ov.hEvent == NULL) return false;                 /* completion routine              */

    l->hints.ai_family = AF_UNSPEC;
    l->hints.ai_socktype = SOCK_STREAM;
    l->hints.ai_protocol = IPPROTO_TCP;
    rc = GetAddrInfoExW(l->host, NULL, NS_DNS, NULL, &l->hints, &l->result, NULL, &l->ov, NULL,
                        &l->cancel);
    if (rc == WSA_IO_PENDING) return true;
    if (rc == NO_ERROR)
    {
        l->isComplete = true;                  /* Answered at once; Poll() collects it */
        l->rc = rc;
        return true;
    }
    _SSFNetSockLookupFree(l);
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns PENDING, DONE with addresses added to s, or FAILED.                                   */
/* --------------------------------------------------------------------------------------------- */
static SSFNetSockLookupResult_t _SSFNetSockLookupPoll(SSFNetSockLookup_t *l, SSFNetSock_t *s)
{
    INT rc;
    PADDRINFOEXW ai;

    SSF_REQUIRE(l != NULL);
    SSF_REQUIRE(s != NULL);

    if (l->isComplete) rc = l->rc;
    else
    {
        rc = GetAddrInfoExOverlappedResult(&l->ov);
        if (rc == WSAEINPROGRESS) return SSF_NETSOCK_LOOKUP_PENDING;
    }
    if (rc != NO_ERROR) { _SSFNetSockLookupFree(l); return SSF_NETSOCK_LOOKUP_FAILED; }
    for (ai = l->result; ai != NULL; ai = ai->ai_next)
    { _SSFNetSockAddAddr(s, ai->ai_addr, (size_t)ai->ai_addrlen); }
    _SSFNetSockLookupFree(l);
    return SSF_NETSOCK_LOOKUP_DONE;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the lookup is finished and released, else false (still running).              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupFinished(SSFNetSockLookup_t *l)
{
    SSF_REQUIRE(l != NULL);

    if ((l->isComplete == false) && (GetAddrInfoExOverlappedResult(&l->ov) == WSAEINPROGRESS))
    { return false; }
    _SSFNetSockLookupFree(l);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the lookup was cancelled and released, else false (the OS still owns it).     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupCancel(SSFNetSockLookup_t *l)
{
    SSF_REQUIRE(l != NULL);

    /* Cancel signals the event with WSA_E_CANCELLED, but a provider that cannot be interrupted */
    /* keeps running and still owns ov and result until it finishes.                           */
    if (l->isComplete == false) (void)GetAddrInfoExCancel(&l->cancel);
    return _SSFNetSockLookupFinished(l);
}

#elif defined(SSF_NETSOCK_RESOLVER_DNSSD)

/* --------------------------------------------------------------------------------------------- */
/* Collects one DNSServiceGetAddrInfo reply into the lookup.                                     */
/* --------------------------------------------------------------------------------------------- */
static void DNSSD_API _SSFNetSockDNSSDReply(DNSServiceRef ref, DNSServiceFlags flags,
                                            uint32_t ifIndex, DNSServiceErrorType err,
                                            const char *hostname, const struct sockaddr *address,
                                            uint32_t ttl, void *ctx)
{
    SSFNetSockLookup_t *l = (SSFNetSockLookup_t *)ctx;

    (void)ref;
    (void)ifIndex;
    (void)hostname;
    (void)ttl;
    SSF_REQUIRE(l != NULL);

    if (err == kDNSServiceErr_NoError)
    {
        if (((flags & kDNSServiceFlagsAdd) != 0) && (address != NULL) &&
            (l->addrCount < SSF_NETSOCK_CONFIG_MAX_ADDRS))
        {
            size_t len = _SSFNetSockAddrLen(address->sa_family);

            if (len != 0)
            {
                memset(l->addrs[l->addrCount], 0, SSF_NETSOCK_ADDR_SIZE);
                memcpy(l->addrs[l->addrCount], address, len);
                l->addrCount++;
            }
        }
    }
    /* Other parameters are undefined on an error, so a negative answer cannot be tied to a     */
    /* family; one per family is expected, one each for IPv4 and IPv6.                          */
    else if (err == kDNSServiceErr_NoSuchRecord) { if (l->negatives < 2u) l->negatives++; }
    else l->isFailed = true;

    if ((flags & kDNSServiceFlagsMoreComing) == 0)
    {
        if (l->addrCount > 0) l->isDone = true;
        else if (l->negatives >= 2u) l->isFailed = true;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Ends the lookup. No reply is delivered after this.                                            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockLookupFree(SSFNetSockLookup_t *l)
{
    SSF_REQUIRE(l != NULL);

    if (l->ref != NULL) DNSServiceRefDeallocate(l->ref);
    l->ref = NULL;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the lookup was started, else false.                                           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupStart(SSFNetSockLookup_t *l, SSFCStrIn_t host, size_t hostLen)
{
    SSF_REQUIRE(l != NULL);
    SSF_REQUIRE(host != NULL);
    SSF_REQUIRE(hostLen < SSF_NETSOCK_CONFIG_MAX_HOST_SIZE);

    l->ref = NULL;
    l->isDone = false;
    l->isFailed = false;
    l->negatives = 0;
    l->addrCount = 0;
    if (DNSServiceGetAddrInfo(&l->ref, kDNSServiceFlagsReturnIntermediates, 0,
                              kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6, host,
                              _SSFNetSockDNSSDReply, l) != kDNSServiceErr_NoError)
    {
        l->ref = NULL;
        return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns PENDING, DONE with addresses added to s, or FAILED.                                   */
/* --------------------------------------------------------------------------------------------- */
static SSFNetSockLookupResult_t _SSFNetSockLookupPoll(SSFNetSockLookup_t *l, SSFNetSock_t *s)
{
    int fd;
    uint32_t i;

    SSF_REQUIRE(l != NULL);
    SSF_REQUIRE(s != NULL);

    fd = DNSServiceRefSockFD(l->ref);
    if (fd < 0) l->isFailed = true;

    /* DNSServiceProcessResult() blocks unless a reply is waiting, so check the socket first. */
    for (i = 0; (i < SSF_NETSOCK_DNSSD_MAX_READS) && (l->isDone == false) &&
                (l->isFailed == false); i++)
    {
        fd_set rfds;
        struct timeval tv;
        int rc;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if ((rc < 0) && (errno == EINTR)) break;
        if (rc < 0) { l->isFailed = true; break; }
        if (rc == 0) break;
        if (DNSServiceProcessResult(l->ref) != kDNSServiceErr_NoError) l->isFailed = true;
    }

    if (l->isFailed) { _SSFNetSockLookupFree(l); return SSF_NETSOCK_LOOKUP_FAILED; }
    if (l->isDone == false) return SSF_NETSOCK_LOOKUP_PENDING;
    for (i = 0; i < l->addrCount; i++)
    { _SSFNetSockAddAddr(s, l->addrs[i], SSF_NETSOCK_ADDR_SIZE); }
    _SSFNetSockLookupFree(l);
    return SSF_NETSOCK_LOOKUP_DONE;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true: deallocating the reference ends the lookup at once.                             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupCancel(SSFNetSockLookup_t *l)
{
    _SSFNetSockLookupFree(l);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true: a lookup is never left abandoned on this backend.                               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupFinished(SSFNetSockLookup_t *l)
{
    _SSFNetSockLookupFree(l);
    return true;
}

#elif defined(SSF_NETSOCK_RESOLVER_GAIA)

/* --------------------------------------------------------------------------------------------- */
/* Releases the lookup's result list.                                                            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockLookupFree(SSFNetSockLookup_t *l)
{
    SSF_REQUIRE(l != NULL);

    if (l->cb.ar_result != NULL) freeaddrinfo(l->cb.ar_result);
    l->cb.ar_result = NULL;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the lookup was started, else false.                                           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupStart(SSFNetSockLookup_t *l, SSFCStrIn_t host, size_t hostLen)
{
    struct gaicb *list[1];

    SSF_REQUIRE(l != NULL);
    SSF_REQUIRE(host != NULL);
    SSF_REQUIRE(hostLen < SSF_NETSOCK_CONFIG_MAX_HOST_SIZE);

    memset(&l->cb, 0, sizeof(l->cb));
    memset(&l->hints, 0, sizeof(l->hints));
    memcpy(l->host, host, hostLen + 1);        /* The resolver thread reads it until done */
    l->hints.ai_family = AF_UNSPEC;
    l->hints.ai_socktype = SOCK_STREAM;
    l->hints.ai_protocol = IPPROTO_TCP;
    l->cb.ar_name = l->host;
    l->cb.ar_service = NULL;
    l->cb.ar_request = &l->hints;
    l->cb.ar_result = NULL;
    list[0] = &l->cb;
    return (getaddrinfo_a(GAI_NOWAIT, list, 1, NULL) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns PENDING, DONE with addresses added to s, or FAILED.                                   */
/* --------------------------------------------------------------------------------------------- */
static SSFNetSockLookupResult_t _SSFNetSockLookupPoll(SSFNetSockLookup_t *l, SSFNetSock_t *s)
{
    int rc;
    struct addrinfo *ai;

    SSF_REQUIRE(l != NULL);
    SSF_REQUIRE(s != NULL);

    rc = gai_error(&l->cb);
    if (rc == EAI_INPROGRESS) return SSF_NETSOCK_LOOKUP_PENDING;
    if (rc != 0) { _SSFNetSockLookupFree(l); return SSF_NETSOCK_LOOKUP_FAILED; }
    for (ai = l->cb.ar_result; ai != NULL; ai = ai->ai_next)
    { _SSFNetSockAddAddr(s, ai->ai_addr, (size_t)ai->ai_addrlen); }
    _SSFNetSockLookupFree(l);
    return SSF_NETSOCK_LOOKUP_DONE;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the lookup is finished and released, else false (still running).              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupFinished(SSFNetSockLookup_t *l)
{
    SSF_REQUIRE(l != NULL);

    if (gai_error(&l->cb) == EAI_INPROGRESS) return false;
    _SSFNetSockLookupFree(l);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the lookup was cancelled and released, else false (the OS still owns it).     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupCancel(SSFNetSockLookup_t *l)
{
    SSF_REQUIRE(l != NULL);

    /* A request already being processed cannot be cancelled; it runs on and must keep its gaicb.*/
    if (gai_cancel(&l->cb) == EAI_NOTCANCELED) return _SSFNetSockLookupFinished(l);
    _SSFNetSockLookupFree(l);
    return true;
}

#else /* SSF_NETSOCK_RESOLVER_NONE */

/* --------------------------------------------------------------------------------------------- */
/* Returns false: this platform has no asynchronous resolver, so only literal addresses work.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupStart(SSFNetSockLookup_t *l, SSFCStrIn_t host, size_t hostLen)
{
    (void)l;
    (void)host;
    (void)hostLen;
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns FAILED; never reached because Start() never succeeds.                                 */
/* --------------------------------------------------------------------------------------------- */
static SSFNetSockLookupResult_t _SSFNetSockLookupPoll(SSFNetSockLookup_t *l, SSFNetSock_t *s)
{
    (void)l;
    (void)s;
    return SSF_NETSOCK_LOOKUP_FAILED;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true; there is never anything to release.                                             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockLookupCancel(SSFNetSockLookup_t *l) { (void)l; return true; }
static bool _SSFNetSockLookupFinished(SSFNetSockLookup_t *l) { (void)l; return true; }

#endif /* SSF_NETSOCK_RESOLVER_* */

/* --------------------------------------------------------------------------------------------- */
/* Stops Winsock once no instance is initialized and no lookup slot is in use.                   */
/* --------------------------------------------------------------------------------------------- */
#ifdef _WIN32
static void _SSFNetSockWSAStopIfIdle(void)
{
    uint32_t i;

    if ((_wsaIsStarted == false) || (_wsaUsers > 0)) return;
    for (i = 0; i < SSF_NETSOCK_CONFIG_MAX_LOOKUPS; i++)
    { if (_lookups[i].state != SSF_NETSOCK_LOOKUP_FREE) return; }
    (void)WSACleanup();
    _wsaIsStarted = false;
}
#endif /* _WIN32 */

/* --------------------------------------------------------------------------------------------- */
/* Frees every abandoned lookup the OS has finished with.                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockLookupReap(void)
{
    uint32_t i;

    for (i = 0; i < SSF_NETSOCK_CONFIG_MAX_LOOKUPS; i++)
    {
        SSFNetSockLookup_t *l = &_lookups[i];

        if ((l->state == SSF_NETSOCK_LOOKUP_ABANDONED) && _SSFNetSockLookupFinished(l))
        { l->state = SSF_NETSOCK_LOOKUP_FREE; }
    }
#ifdef _WIN32
    _SSFNetSockWSAStopIfIdle();
#endif
}

/* --------------------------------------------------------------------------------------------- */
/* Returns a free lookup slot index after reaping, else SSF_NETSOCK_NO_LOOKUP.                   */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _SSFNetSockLookupAlloc(void)
{
    uint32_t i;

    _SSFNetSockLookupReap();
    for (i = 0; i < SSF_NETSOCK_CONFIG_MAX_LOOKUPS; i++)
    { if (_lookups[i].state == SSF_NETSOCK_LOOKUP_FREE) return (uint8_t)i; }
    return SSF_NETSOCK_NO_LOOKUP;
}

/* --------------------------------------------------------------------------------------------- */
/* Cancels an owned lookup; one the OS cannot release yet is left abandoned for a later reap.    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockLookupAbandon(uint8_t idx)
{
    SSFNetSockLookup_t *l;

    SSF_REQUIRE(idx < SSF_NETSOCK_CONFIG_MAX_LOOKUPS);
    l = &_lookups[idx];
    SSF_ASSERT(l->state == SSF_NETSOCK_LOOKUP_OWNED);

#if SSF_CONFIG_NETSOCK_UNIT_TEST == 1
    /* Leave the lookup running untouched, as the OS does when it cannot cancel; reap frees it. */
    if (_ssfNetSockUTNoCancel) { l->state = SSF_NETSOCK_LOOKUP_ABANDONED; return; }
#endif
    l->state = _SSFNetSockLookupCancel(l) ? SSF_NETSOCK_LOOKUP_FREE : SSF_NETSOCK_LOOKUP_ABANDONED;
}

/* --------------------------------------------------------------------------------------------- */
/* Ends any lookup or socket and marks the instance closed.                                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFNetSockRelease(SSFNetSock_t *s)
{
    SSF_REQUIRE(s != NULL);

    if (s->lookup != SSF_NETSOCK_NO_LOOKUP) _SSFNetSockLookupAbandon(s->lookup);
    s->lookup = SSF_NETSOCK_NO_LOOKUP;

    /* Discard whatever has already arrived so the close is an orderly FIN, not an RST that can  */
    /* make the peer drop the last bytes sent. Non-blocking and bounded: data still in flight     */
    /* can yet cause an RST, which is no worse than before.                                       */
    if ((s->state == SSF_NETSOCK_STATE_CONNECTED) && (s->sock != SSF_NETSOCK_INVALID))
    {
        uint8_t drain[256];
        size_t drained = 0;

        while (drained < SSF_NETSOCK_CONFIG_CLOSE_DRAIN_MAX)
        {
            long rc = (long)recv(SSF_NETSOCK_FD(s->sock), (char *)drain,
                                 (SSFNetSockIOLen_t)sizeof(drain), 0);
            if (rc <= 0) break;                /* Empty (would block), end of stream, or error */
            drained += (size_t)rc;
        }
    }
    if (s->sock != SSF_NETSOCK_INVALID) (void)SSF_NETSOCK_CLOSE(s->sock);
    s->sock = SSF_NETSOCK_INVALID;
    s->state = SSF_NETSOCK_STATE_CLOSED;
    s->addrCount = 0;
    s->addrNext = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS if connected, WANT_WRITE while a connect is in progress, or ERROR once every  */
/* remaining address has failed (the instance is then closed).                                   */
/* --------------------------------------------------------------------------------------------- */
static SSFNetIOResult_t _SSFNetSockConnectNext(SSFNetSock_t *s)
{
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(s->sock == SSF_NETSOCK_INVALID);

    while (s->addrNext < s->addrCount)
    {
        struct sockaddr_storage ss;
        SSFNetSockLen_t len;
        SSFNetSockHandle_t sock;
        int rc;

        len = _SSFNetSockAddrPrepare(s, s->addrNext, &ss);
        s->addrNext++;
        sock = (SSFNetSockHandle_t)socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
        if (sock == SSF_NETSOCK_INVALID) continue;
        if (_SSFNetSockSetNonBlocking(sock) == false) { (void)SSF_NETSOCK_CLOSE(sock); continue; }

        rc = connect(SSF_NETSOCK_FD(sock), (struct sockaddr *)&ss, len);
        if (rc == 0)
        {
            s->sock = sock;
            s->state = SSF_NETSOCK_STATE_CONNECTED;     /* Local or very fast peer */
            return SSF_NET_IO_SUCCESS;
        }
        if (SSF_NETSOCK_ERRNO() == SSF_NETSOCK_EINPROGRESS)
        {
            s->sock = sock;
            s->state = SSF_NETSOCK_STATE_CONNECTING;
            return SSF_NET_IO_WANT_WRITE;
        }
        (void)SSF_NETSOCK_CLOSE(sock);
    }
    _SSFNetSockRelease(s);
    return SSF_NET_IO_ERROR;
}

/* --------------------------------------------------------------------------------------------- */
/* Transport operations                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a connection attempt to host:port was started, else false. Never blocks.      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFNetSockOpen(SSFNetTransport_t *t, SSFCStrIn_t host, size_t hostSize, uint16_t port)
{
    SSFNetSock_t *s;
    size_t hostLen;
    uint8_t idx;

    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE(host != NULL);
    SSF_REQUIRE(hostSize > 0);
    s = _SSFNetSockSelf(t);
    SSF_REQUIRE(s->state == SSF_NETSOCK_STATE_CLOSED);

    if ((SSFStrLen(host, hostSize, &hostLen) == false) || (hostLen == 0)) return false;
    if (hostLen >= SSF_NETSOCK_CONFIG_MAX_HOST_SIZE) return false;
    if (port == 0) return false;

    s->port = port;
    s->addrCount = 0;
    s->addrNext = 0;

    /* A literal address is parsed here and needs no lookup. */
    if (_SSFNetSockParseLiteral(s, host)) return (_SSFNetSockConnectNext(s) != SSF_NET_IO_ERROR);

    /* A host name is resolved asynchronously; pollOpen() collects the answer. */
    idx = _SSFNetSockLookupAlloc();
    if (idx == SSF_NETSOCK_NO_LOOKUP) return false;
    if (_SSFNetSockLookupStart(&_lookups[idx], host, hostLen) == false) return false;
    _lookups[idx].state = SSF_NETSOCK_LOOKUP_OWNED;
    s->lookup = idx;
    s->state = SSF_NETSOCK_STATE_RESOLVING;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SUCCESS once connected, WANT_READ while resolving, WANT_WRITE while connecting, else  */
/* CLOSED or ERROR once every address has failed.                                                */
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
    SSFNetIOResult_t r;

    SSF_REQUIRE(t != NULL);
    s = _SSFNetSockSelf(t);

    if (s->state == SSF_NETSOCK_STATE_CONNECTED) return SSF_NET_IO_SUCCESS;

    if (s->state == SSF_NETSOCK_STATE_RESOLVING)
    {
        SSFNetSockLookupResult_t lr = _SSFNetSockLookupPoll(&_lookups[s->lookup], s);

        if (lr == SSF_NETSOCK_LOOKUP_PENDING) return SSF_NET_IO_WANT_READ;
        _lookups[s->lookup].state = SSF_NETSOCK_LOOKUP_FREE;    /* Poll() released it */
        s->lookup = SSF_NETSOCK_NO_LOOKUP;
        if (lr == SSF_NETSOCK_LOOKUP_FAILED) { _SSFNetSockRelease(s); return SSF_NET_IO_ERROR; }
        return _SSFNetSockConnectNext(s);
    }

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
    if ((err == 0) && (FD_ISSET(SSF_NETSOCK_FD(s->sock), &efds) == 0))
    {
        s->state = SSF_NETSOCK_STATE_CONNECTED;
        return SSF_NET_IO_SUCCESS;
    }

    /* This address failed; move on to the next one. */
    (void)SSF_NETSOCK_CLOSE(s->sock);
    s->sock = SSF_NETSOCK_INVALID;
    r = _SSFNetSockConnectNext(s);
    if (r != SSF_NET_IO_ERROR) return r;
    return ((err == SSF_NETSOCK_ECONNRESET) || (err == SSF_NETSOCK_ECONNABORTED)) ?
           SSF_NET_IO_CLOSED : SSF_NET_IO_ERROR;
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
/* Closes the connection or attempt, abandoning any lookup in progress. Never blocks.            */
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
    if (_wsaIsStarted == false)
    {
        WSADATA wsa;
        SSF_ASSERT(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
        _wsaIsStarted = true;
    }
    _wsaUsers++;
#endif
    _SSFNetSockLookupReap();

    memset(s, 0, sizeof(*s));
    s->transport.open = _SSFNetSockOpen;
    s->transport.pollOpen = _SSFNetSockPollOpen;
    s->transport.send = _SSFNetSockSend;
    s->transport.recv = _SSFNetSockRecv;
    s->transport.close = _SSFNetSockClose;
    s->sock = SSF_NETSOCK_INVALID;
    s->state = SSF_NETSOCK_STATE_CLOSED;
    s->lookup = SSF_NETSOCK_NO_LOOKUP;
    s->magic = SSF_NETSOCK_INIT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes a socket transport instance, closing any connection. Never blocks.              */
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
#endif
    _SSFNetSockLookupReap();                   /* Also stops Winsock once idle */
}
