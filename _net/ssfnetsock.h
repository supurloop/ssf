/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfnetsock.h                                                                                  */
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
#ifndef SSF_NETSOCK_H_INCLUDE
#define SSF_NETSOCK_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"
#include "ssfnet.h"

/* --------------------------------------------------------------------------------------------- */
/* Design                                                                                        */
/* --------------------------------------------------------------------------------------------- */
/* - Plaintext TCP, no TLS, no authentication. Intended for hosted builds (Windows, Linux, macOS) */
/*   and as the reference for porting the transport to an embedded IP stack.                     */
/* - open() resolves the host with getaddrinfo(), which blocks for the duration of the lookup.    */
/*   Everything after that is non-blocking. A literal IPv4 or IPv6 address resolves immediately.  */
/* - One socket per instance. The instance must outlive the client that holds its transport.     */
/* - On Windows, Winsock is started by the first Init() and stopped by the last DeInit().         */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#ifdef _WIN32
typedef uintptr_t SSFNetSockHandle_t;          /* SOCKET without pulling winsock2.h into users */
#else
typedef int SSFNetSockHandle_t;
#endif

typedef enum
{
    SSF_NETSOCK_STATE_CLOSED,
    SSF_NETSOCK_STATE_CONNECTING,
    SSF_NETSOCK_STATE_CONNECTED
} SSFNetSockState_t;

typedef struct
{
    SSFNetTransport_t transport;     /* Must be first; this is what the client is handed        */
    SSFNetSockHandle_t sock;
    SSFNetSockState_t state;
    uint32_t magic;
} SSFNetSock_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* Prepares the instance and fills in its transport table. Pass &s->transport to the client.    */
void SSFNetSockInit(SSFNetSock_t *s);

/* Closes any open connection and releases the instance. */
void SSFNetSockDeInit(SSFNetSock_t *s);

#ifdef __cplusplus
}
#endif

#endif /* SSF_NETSOCK_H_INCLUDE */
