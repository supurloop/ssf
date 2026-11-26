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
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
typedef enum
{
    SSF_NET_IO_MIN = -1,
    SSF_NET_IO_SUCCESS,              /* Operation made progress; see the count output */
    SSF_NET_IO_WANT_READ,            /* Nothing done; retry when readable */
    SSF_NET_IO_WANT_WRITE,           /* Nothing done; retry when writable */
    SSF_NET_IO_CLOSED,               /* Peer closed or reset the connection */
    SSF_NET_IO_ERROR,                /* Local or network failure */
    SSF_NET_IO_MAX
} SSFNetIOResult_t;

typedef struct SSFNetTransport SSFNetTransport_t;

/* Begins connecting to hostStr:port over IPv4; true if the attempt is in progress or done. */
typedef bool (*SSFNetOpenFn_t)(SSFNetTransport_t *t, SSFCStrIn_t hostStr, size_t hostSize,
                               uint16_t port);

/* Advances a pending open(); SUCCESS when connected, WANT_* while in progress. */
typedef SSFNetIOResult_t (*SSFNetPollOpenFn_t)(SSFNetTransport_t *t);

/* Writes up to bufLen bytes from buf; *sentOut is the number accepted. */
typedef SSFNetIOResult_t (*SSFNetSendFn_t)(SSFNetTransport_t *t, const uint8_t *buf, size_t bufLen,
                                           size_t *sentOut);

/* Reads up to bufSize bytes into buf; *gotOut is the number received. */
typedef SSFNetIOResult_t (*SSFNetRecvFn_t)(SSFNetTransport_t *t, uint8_t *buf, size_t bufSize,
                                           size_t *gotOut);

/* Delivers every accepted byte and ends this side of the stream; SUCCESS when done. */
typedef SSFNetIOResult_t (*SSFNetShutdownFn_t)(SSFNetTransport_t *t);

/* Ends the connection or attempt and releases its resources without waiting. */
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
