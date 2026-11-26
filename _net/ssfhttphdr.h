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
/* Design                                                                                        */
/* --------------------------------------------------------------------------------------------- */
/* - The message head codec shared by SSF's HTTP users: the WebSocket handshake (ssfnetws) now,  */
/*   a full HTTP/1.1 client later. Pure functions over caller buffers; no state, no allocation,  */
/*   no I/O. Message bodies (Content-Length, chunked) are not handled here.                      */
/* - Building: Begin() writes the request line and Host, AddField() appends one field line,      */
/*   End() appends the empty line. Each returns false if the text would not fit or any string    */
/*   is not valid for its place; Begin() then sets the length to 0, the others leave it          */
/*   unchanged. App strings therefore can never inject a CR, LF or NUL into the head. Strings    */
/*   are NUL terminated; each NUL scan stops one byte past the space the string could occupy.    */
/*   Host is written by Begin() only: AddField() refuses any field named Host.                   */
/* - Parsing: ParseResponse() is strict to RFC 9112. It rejects a bare CR or LF, obs-fold, a     */
/*   space before a field colon, an invalid token in a field name, a control character in a      */
/*   value, a malformed status line and a head with more than SSF_HTTP_CONFIG_MAX_FIELDS fields. */
/*   Lenient head parsing is what makes request smuggling and response splitting possible.       */
/* - Parsing is stateless: call it again on the same buffer as more bytes arrive. INCOMPLETE     */
/*   means no error so far and more bytes are needed; a caller whose buffer is already full      */
/*   treats that as a head too large. COMPLETE gives headLen; bytes after it belong to the next  */
/*   layer (a body, or WebSocket frames) and are not examined.                                   */
/* - Parsed fields are zero-copy: each is an offset and length into the caller's buffer, which   */
/*   must stay unchanged while the result is used. Values have surrounding whitespace removed.   */
/*   Names compare case-insensitively; duplicate fields are kept in order.                       */
/* - A head is at most SSF_HTTP_HDR_MAX_HEAD_SIZE bytes, so offsets fit in 16 bits.              */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#define SSF_HTTP_HDR_MAX_HEAD_SIZE (65535u)

/* A field to send: name and value, both NUL terminated and app owned. */
typedef struct
{
    SSFCStrIn_t name;                /* A token (RFC 9110 5.1)                                  */
    SSFCStrIn_t value;               /* Visible characters, spaces and tabs inside; may be ""   */
} SSFHTTPHdrField_t;

/* A parsed field: offsets into the parsed buffer. */
typedef struct
{
    uint16_t nameOff;
    uint16_t nameLen;                /* >= 1                                                    */
    uint16_t valueOff;
    uint16_t valueLen;               /* May be 0                                                */
} SSFHTTPHdrFieldRef_t;

/* A parsed response head. Valid only after ParseResponse() returns COMPLETE. */
typedef struct
{
    uint16_t headLen;                /* Status line through the empty line, inclusive           */
    uint16_t status;                 /* 100..599                                                */
    uint8_t versionMajor;            /* Digits of "HTTP/x.y"                                    */
    uint8_t versionMinor;
    uint16_t reasonOff;              /* Reason phrase; may be empty                             */
    uint16_t reasonLen;
    uint16_t fieldCount;
    SSFHTTPHdrFieldRef_t fields[SSF_HTTP_CONFIG_MAX_FIELDS];
} SSFHTTPHdrResponse_t;

typedef enum
{
    SSF_HTTP_HDR_MALFORMED,          /* Not a valid head, or over a limit; stream unusable      */
    SSF_HTTP_HDR_INCOMPLETE,         /* Valid so far; more bytes needed                         */
    SSF_HTTP_HDR_COMPLETE            /* A whole head starts the buffer; see headLen             */
} SSFHTTPHdrParse_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* Request building. Begin() starts at buf[0] and writes "method SP target SP HTTP/1.1 CRLF" and */
/* "Host: host[:port] CRLF"; portOpt 0 omits the port. method is a token; target is an           */
/* origin-form path ("/a?b"), "*", or an authority or absolute URI, made of URI characters with  */
/* well-formed %XX escapes and no '#'; host is a DNS name or IPv4 address (letters, digits, '-', */
/* '.', '_', '~'). Returns false, with *lenOut 0, if anything is invalid or does not fit.        */
bool SSFHTTPHdrReqBegin(uint8_t *buf, size_t size, size_t *lenOut, SSFCStrIn_t method,
                        SSFCStrIn_t target, SSFCStrIn_t host, uint16_t portOpt);

/* Appends "name: value CRLF". The value may not start or end with a space or tab. */
bool SSFHTTPHdrReqAddField(uint8_t *buf, size_t size, size_t *lenInOut, SSFCStrIn_t name,
                           SSFCStrIn_t value);

/* Appends the empty line that ends the head. */
bool SSFHTTPHdrReqEnd(uint8_t *buf, size_t size, size_t *lenInOut);

/* Response parsing; see Design. Only the first SSF_HTTP_HDR_MAX_HEAD_SIZE bytes are looked at.  */
SSFHTTPHdrParse_t SSFHTTPHdrParseResponse(const uint8_t *buf, size_t len,
                                          SSFHTTPHdrResponse_t *respOut);

/* Field lookup on a COMPLETE result, buf being the buffer that was parsed. name is compared     */
/* case-insensitively.                                                                           */
/* Finds the first field named name at or after index *indexInOut. On success sets the value     */
/* and *indexInOut to the index after it, so repeated calls walk duplicates; else false.         */
bool SSFHTTPHdrFindField(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp, SSFCStrIn_t name,
                         uint16_t *indexInOut, const uint8_t **valueOut, size_t *valueLenOut);

/* Returns how many fields are named name. */
uint16_t SSFHTTPHdrFieldCount(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                              SSFCStrIn_t name);

/* Returns true if exactly one field is named name and its value equals value, compared          */
/* case-insensitively when isCaseInsensitive, else exactly.                                      */
bool SSFHTTPHdrFieldIsOnly(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                           SSFCStrIn_t name, SSFCStrIn_t value, bool isCaseInsensitive);

/* Returns true if any element of the comma-separated lists in all fields named name equals      */
/* token case-insensitively (RFC 9110 5.6.1; empty elements are skipped).                        */
bool SSFHTTPHdrFieldHasToken(const uint8_t *buf, const SSFHTTPHdrResponse_t *resp,
                             SSFCStrIn_t name, SSFCStrIn_t token);

#if SSF_CONFIG_HTTPHDR_UNIT_TEST == 1
void SSFHTTPHdrUnitTest(void);
#endif /* SSF_CONFIG_HTTPHDR_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_HTTPHDR_H_INCLUDE */
