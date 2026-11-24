/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfnet.h                                                                                      */
/* Defines the non-blocking byte stream transport interface used by the network client modules.  */
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
#ifndef SSF_NET_H_INCLUDE
#define SSF_NET_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssf.h"

/* --------------------------------------------------------------------------------------------- */
/* Design                                                                                        */
/* --------------------------------------------------------------------------------------------- */
/* - A transport is a table of six non-blocking operations plus an implementation context. A    */
/*   client holds a pointer to it and never looks inside; an implementation embeds the table as  */
/*   the first member of its own struct and recovers itself from the pointer.                    */
/* - Every call returns immediately, name resolution included: an implementation must resolve    */
/*   a host name asynchronously and report progress through pollOpen(). A result of WANT_READ or */
/*   WANT_WRITE means nothing was done and the caller should try again after the transport       */
/*   becomes readable or writable, or after a short delay while opening.                         */
/* - Lifecycle: open() starts a connection; pollOpen() is called until it stops returning WANT_* */
/*   and reports SUCCESS or failure; send() and recv() are valid only after SUCCESS; close() is  */
/*   valid any time after open() and ends the connection unconditionally. After close() the      */
/*   transport may be opened again.                                                              */
/* - Graceful end: bytes send() accepted may still be buffered inside the transport (TLS holds a */
/*   partly written record). close() never waits, so it may drop them. A caller that needs them  */
/*   delivered calls shutdown() until it stops returning WANT_WRITE, then close(). shutdown() is */
/*   valid only after pollOpen() SUCCESS; send() is not valid after it, recv() still is.         */
/* - IPv4 only. SSF is not designed for an IPv6 stack: a host is a DNS name or a dotted IPv4    */
/*   address, a name is resolved to IPv4 addresses only, and open() returns false for an IPv6    */
/*   literal (any host containing ':'). A host with no IPv4 address fails to open.               */
/* - CLOSED is an orderly end by the peer or a reset; ERROR is anything else. Callers treat both */
/*   as fatal for the connection.                                                                */
/* - All calls come from one thread.                                                             */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
typedef enum
{
    SSF_NET_IO_MIN = -1,
    SSF_NET_IO_SUCCESS,              /* Operation made progress; see the count output           */
    SSF_NET_IO_WANT_READ,            /* Nothing done; retry when readable                       */
    SSF_NET_IO_WANT_WRITE,           /* Nothing done; retry when writable                       */
    SSF_NET_IO_CLOSED,               /* Peer closed or reset the connection                     */
    SSF_NET_IO_ERROR,                /* Local or network failure                                */
    SSF_NET_IO_MAX
} SSFNetIOResult_t;

typedef struct SSFNetTransport SSFNetTransport_t;

/* Begins connecting to host:port over IPv4. host is NUL terminated within hostSize. Returns    */
/* false if the attempt could not be started (bad or IPv6 host, no resources); true once it is   */
/* in progress or done.                                                                          */
typedef bool (*SSFNetOpenFn_t)(SSFNetTransport_t *t, SSFCStrIn_t host, size_t hostSize,
                               uint16_t port);

/* Advances a pending open(). SUCCESS when connected, WANT_READ/WANT_WRITE while in progress,    */
/* CLOSED or ERROR when the attempt failed.                                                      */
typedef SSFNetIOResult_t (*SSFNetPollOpenFn_t)(SSFNetTransport_t *t);

/* Writes up to len bytes. SUCCESS with *sentOut >= 1 bytes accepted (may be fewer than len);    */
/* WANT_WRITE with *sentOut == 0 when the transport cannot take any right now.                    */
typedef SSFNetIOResult_t (*SSFNetSendFn_t)(SSFNetTransport_t *t, const uint8_t *buf, size_t len,
                                           size_t *sentOut);

/* Reads up to size bytes. SUCCESS with *gotOut >= 1 bytes received; WANT_READ with *gotOut == 0 */
/* when none are available; CLOSED when the peer has finished sending.                            */
typedef SSFNetIOResult_t (*SSFNetRecvFn_t)(SSFNetTransport_t *t, uint8_t *buf, size_t size,
                                           size_t *gotOut);

/* Finishes sending: delivers every byte send() accepted and ends this side of the stream (for   */
/* TLS, close_notify). SUCCESS when done; WANT_WRITE while bytes remain (retry when writable);   */
/* CLOSED or ERROR if they cannot be delivered. A transport whose accepted bytes are already     */
/* committed (a socket) returns SUCCESS at once. Repeating it after SUCCESS returns SUCCESS.      */
typedef SSFNetIOResult_t (*SSFNetShutdownFn_t)(SSFNetTransport_t *t);

/* Ends the connection or attempt and releases its resources. Never waits; see shutdown().       */
typedef void (*SSFNetCloseFn_t)(SSFNetTransport_t *t);

struct SSFNetTransport
{
    SSFNetOpenFn_t open;
    SSFNetPollOpenFn_t pollOpen;
    SSFNetSendFn_t send;
    SSFNetRecvFn_t recv;
    SSFNetShutdownFn_t shutdown;
    SSFNetCloseFn_t close;
};

#ifdef __cplusplus
}
#endif

#endif /* SSF_NET_H_INCLUDE */
