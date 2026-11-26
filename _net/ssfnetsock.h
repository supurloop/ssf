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
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#ifdef _WIN32
typedef uintptr_t SSFNetSockHandle_t;          /* SOCKET without pulling winsock2.h into users */
#else
typedef int SSFNetSockHandle_t;
#endif

#define SSF_NETSOCK_ADDR_SIZE (4u)    /* An IPv4 address, network byte order */
#define SSF_NETSOCK_NO_LOOKUP (0xffu)

typedef enum
{
    SSF_NETSOCK_STATE_CLOSED,
    SSF_NETSOCK_STATE_RESOLVING,
    SSF_NETSOCK_STATE_CONNECTING,
    SSF_NETSOCK_STATE_CONNECTED
} SSFNetSockState_t;

typedef struct
{
    SSFNetTransport_t transport;     /* Must be first; this is what the client is handed */
    SSFNetSockHandle_t sock;
    SSFNetSockState_t state;
    uint16_t port;                   /* Host byte order */
    uint8_t lookup;                  /* Lookup slot while RESOLVING, else SSF_NETSOCK_NO_LOOKUP */
    uint8_t addrCount;               /* Resolved addresses in addrs */
    uint8_t addrNext;                /* Next address to try */
    uint8_t addrs[SSF_NETSOCK_CONFIG_MAX_ADDRS][SSF_NETSOCK_ADDR_SIZE];  /* IPv4 addresses */
    uint32_t magic;
} SSFNetSock_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* Prepares the instance and fills in its transport table. Pass &s->transport to the client. */
void SSFNetSockInit(SSFNetSock_t *s);

/* Closes any open connection and releases the instance. */
void SSFNetSockDeInit(SSFNetSock_t *s);

#if SSF_CONFIG_NETSOCK_UNIT_TEST == 1
void SSFNetSockUnitTest(void);
#endif /* SSF_CONFIG_NETSOCK_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_NETSOCK_H_INCLUDE */
