/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhttphdr.h                                                                                  */
/* Builds HTTP/1.1 request heads and parses response heads (RFC 9112); no I/O.                   */
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
#ifndef SSF_HTTPHDR_H_INCLUDE
#define SSF_HTTPHDR_H_INCLUDE

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
#define SSF_HTTP_HDR_MAX_HEAD_SIZE (65535u)

/* A field to send: name and value, both NUL terminated and app owned */
typedef struct
{
    SSFCStrIn_t name;                /* A token (RFC 9110 5.1) */
    SSFCStrIn_t value;               /* Visible characters, spaces and tabs inside; may be "" */
} SSFHTTPHdrField_t;

/* A parsed field: offsets into the parsed buffer */
typedef struct
{
    uint16_t nameOff;
    uint16_t nameLen;                /* >= 1 */
    uint16_t valueOff;
    uint16_t valueLen;               /* May be 0 */
} SSFHTTPHdrFieldRef_t;

/* A parsed response head, valid only after ParseResponse() returns COMPLETE */
typedef struct
{
    uint16_t headLen;                /* Status line through the empty line, inclusive */
    uint16_t status;                 /* 100..599 */
    uint8_t versionMajor;            /* Digits of "HTTP/x.y" */
    uint8_t versionMinor;
    uint16_t reasonOff;              /* Reason phrase; may be empty */
    uint16_t reasonLen;
    uint16_t fieldCount;
    SSFHTTPHdrFieldRef_t fields[SSF_HTTP_CONFIG_MAX_FIELDS];
} SSFHTTPHdrResponse_t;

typedef enum
{
    SSF_HTTP_HDR_MALFORMED,          /* Not a valid head, or over a limit; stream unusable */
    SSF_HTTP_HDR_INCOMPLETE,         /* Valid so far; more bytes needed */
    SSF_HTTP_HDR_COMPLETE            /* A whole head starts the buffer; see headLen */
} SSFHTTPHdrParse_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* Writes the request line and Host field at buf[0]; false with *lenOut 0 if invalid or no fit */
bool SSFHTTPHdrReqBegin(uint8_t *buf, size_t bufSize, size_t *lenOut, SSFCStrIn_t methodStr,
                        SSFCStrIn_t targetStr, SSFCStrIn_t hostStr, uint16_t portOpt);

/* Appends "name: value CRLF"; false with *lenInOut unchanged if invalid or no fit */
bool SSFHTTPHdrReqAddField(uint8_t *buf, size_t bufSize, size_t *lenInOut, SSFCStrIn_t nameStr,
                           SSFCStrIn_t valueStr);

/* Appends the empty line that ends the head */
bool SSFHTTPHdrReqEnd(uint8_t *buf, size_t bufSize, size_t *lenInOut);

/* Parses a response head at the start of buf; COMPLETE, INCOMPLETE or MALFORMED */
SSFHTTPHdrParse_t SSFHTTPHdrParseResponse(const uint8_t *buf, size_t bufLen,
                                          SSFHTTPHdrResponse_t *respOut);

/* Finds the next field named nameStr at or after *indexInOut, case-insensitively */
bool SSFHTTPHdrFindField(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp, SSFCStrIn_t nameStr,
                         uint16_t *indexInOut, const uint8_t **valueOut, size_t *valueLenOut);

/* Returns how many fields are named nameStr */
uint16_t SSFHTTPHdrFieldCount(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                              SSFCStrIn_t nameStr);

/* Returns true if exactly one field is named nameStr and its value equals valueStr */
bool SSFHTTPHdrFieldIsOnly(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                           SSFCStrIn_t nameStr, SSFCStrIn_t valueStr, bool isCaseInsensitive);

/* Returns true if a list element of any field named nameStr equals tokenStr case-insensitively */
bool SSFHTTPHdrFieldHasToken(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                             SSFCStrIn_t nameStr, SSFCStrIn_t tokenStr);

#if SSF_CONFIG_HTTPHDR_UNIT_TEST == 1
void SSFHTTPHdrUnitTest(void);
#endif /* SSF_CONFIG_HTTPHDR_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_HTTPHDR_H_INCLUDE */
