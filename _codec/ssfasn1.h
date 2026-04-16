/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfasn1.h                                                                                     */
/* Provides ASN.1 DER (Distinguished Encoding Rules) encode/decode interface.                    */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#ifndef SSF_ASN1_H_INCLUDE
#define SSF_ASN1_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Limitations                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* Only single-byte tags are supported (tag numbers 0-30). High-tag-number form is not supported.*/
/* Only definite-length encoding is supported (no indefinite length).                            */
/* Maximum content length is 2^32-1 bytes (4-byte length field).                                 */
/* OID arc decoding supports up to SSF_ASN1_CONFIG_MAX_OID_ARCS arcs.                            */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* ASN.1 tag constants                                                                           */
/* --------------------------------------------------------------------------------------------- */

/* Universal class tags */
#define SSF_ASN1_TAG_BOOLEAN            ((uint8_t)0x01u)
#define SSF_ASN1_TAG_INTEGER            ((uint8_t)0x02u)
#define SSF_ASN1_TAG_BIT_STRING         ((uint8_t)0x03u)
#define SSF_ASN1_TAG_OCTET_STRING       ((uint8_t)0x04u)
#define SSF_ASN1_TAG_NULL               ((uint8_t)0x05u)
#define SSF_ASN1_TAG_OID                ((uint8_t)0x06u)
#define SSF_ASN1_TAG_UTF8_STRING        ((uint8_t)0x0Cu)
#define SSF_ASN1_TAG_PRINTABLE_STRING   ((uint8_t)0x13u)
#define SSF_ASN1_TAG_T61_STRING         ((uint8_t)0x14u) /* TeletexString (legacy) */
#define SSF_ASN1_TAG_IA5_STRING         ((uint8_t)0x16u)
#define SSF_ASN1_TAG_UTC_TIME           ((uint8_t)0x17u)
#define SSF_ASN1_TAG_GENERALIZED_TIME   ((uint8_t)0x18u)
#define SSF_ASN1_TAG_UNIVERSAL_STRING   ((uint8_t)0x1Cu)
#define SSF_ASN1_TAG_BMP_STRING         ((uint8_t)0x1Eu)
#define SSF_ASN1_TAG_SEQUENCE           ((uint8_t)0x30u)
#define SSF_ASN1_TAG_SET                ((uint8_t)0x31u)

/* Tag class bits */
#define SSF_ASN1_CLASS_UNIVERSAL        ((uint8_t)0x00u)
#define SSF_ASN1_CLASS_APPLICATION      ((uint8_t)0x40u)
#define SSF_ASN1_CLASS_CONTEXT          ((uint8_t)0x80u)
#define SSF_ASN1_CLASS_PRIVATE          ((uint8_t)0xC0u)

/* Constructed bit */
#define SSF_ASN1_CONSTRUCTED            ((uint8_t)0x20u)

/* Context-specific tag helpers (for X.509 OPTIONAL/IMPLICIT/EXPLICIT tagged fields) */
#define SSF_ASN1_CONTEXT_EXPLICIT(n)    ((uint8_t)(SSF_ASN1_CLASS_CONTEXT | SSF_ASN1_CONSTRUCTED | (n)))
#define SSF_ASN1_CONTEXT_IMPLICIT(n)    ((uint8_t)(SSF_ASN1_CLASS_CONTEXT | (n)))

/* --------------------------------------------------------------------------------------------- */
/* Decoder types and interface                                                                   */
/* --------------------------------------------------------------------------------------------- */

/* Zero-copy cursor into a DER buffer. Points to the current position. */
typedef struct SSFASN1Cursor
{
    const uint8_t *buf;    /* Current position in the DER buffer */
    uint32_t bufLen;       /* Remaining bytes from buf */
} SSFASN1Cursor_t;

/* Core TLV parser: reads tag, value pointer, value length, advances cursor.                     */
bool SSFASN1DecGetTLV(const SSFASN1Cursor_t *cursor, uint8_t *tagOut,
                      const uint8_t **valueOut, uint32_t *valueLenOut,
                      SSFASN1Cursor_t *next);

/* Enter a constructed element (SEQUENCE, SET, or context-tagged).                               */
bool SSFASN1DecOpenConstructed(const SSFASN1Cursor_t *cursor, uint8_t expectedTag,
                               SSFASN1Cursor_t *inner, SSFASN1Cursor_t *next);

/* Peek at the tag byte without advancing. */
bool SSFASN1DecPeekTag(const SSFASN1Cursor_t *cursor, uint8_t *tagOut);

/* Skip one complete TLV element. */
bool SSFASN1DecSkip(const SSFASN1Cursor_t *cursor, SSFASN1Cursor_t *next);

/* Returns true if the cursor has no remaining data. */
bool SSFASN1DecIsEmpty(const SSFASN1Cursor_t *cursor);

/* Primitive type decoders */
bool SSFASN1DecGetBool(const SSFASN1Cursor_t *cursor, bool *valOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetInt(const SSFASN1Cursor_t *cursor, const uint8_t **intBufOut,
                      uint32_t *intLenOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetIntU64(const SSFASN1Cursor_t *cursor, uint64_t *valOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetBitString(const SSFASN1Cursor_t *cursor, const uint8_t **bitsOut,
                            uint32_t *bitsLenOut, uint8_t *unusedBitsOut,
                            SSFASN1Cursor_t *next);
bool SSFASN1DecGetOctetString(const SSFASN1Cursor_t *cursor, const uint8_t **octetsOut,
                              uint32_t *octetsLenOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetNull(const SSFASN1Cursor_t *cursor, SSFASN1Cursor_t *next);
bool SSFASN1DecGetOID(const SSFASN1Cursor_t *cursor, uint32_t *oidArcsOut,
                      uint8_t oidArcsSize, uint8_t *oidArcsLenOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetOIDRaw(const SSFASN1Cursor_t *cursor, const uint8_t **oidRawOut,
                         uint32_t *oidRawLenOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetString(const SSFASN1Cursor_t *cursor, const uint8_t **strOut,
                         uint32_t *strLenOut, uint8_t *strTagOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetTime(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut,
                       SSFASN1Cursor_t *next);

/* --------------------------------------------------------------------------------------------- */
/* Encoder interface                                                                             */
/* --------------------------------------------------------------------------------------------- */

/* All encoders return the number of bytes written (or needed if buf is NULL). 0 on error.       */
/* When buf is NULL, the function measures the output size without writing (two-pass pattern).    */

uint32_t SSFASN1EncTagLen(uint8_t *buf, uint32_t bufSize, uint8_t tag, uint32_t contentLen);
uint32_t SSFASN1EncBool(uint8_t *buf, uint32_t bufSize, bool val);
uint32_t SSFASN1EncInt(uint8_t *buf, uint32_t bufSize, const uint8_t *intBuf, uint32_t intLen);
uint32_t SSFASN1EncIntU64(uint8_t *buf, uint32_t bufSize, uint64_t val);
uint32_t SSFASN1EncBitString(uint8_t *buf, uint32_t bufSize, const uint8_t *bits,
                             uint32_t bitsLen, uint8_t unusedBits);
uint32_t SSFASN1EncOctetString(uint8_t *buf, uint32_t bufSize, const uint8_t *octets,
                               uint32_t octetsLen);
uint32_t SSFASN1EncNull(uint8_t *buf, uint32_t bufSize);
uint32_t SSFASN1EncOIDRaw(uint8_t *buf, uint32_t bufSize, const uint8_t *oidRaw,
                          uint32_t oidRawLen);
uint32_t SSFASN1EncString(uint8_t *buf, uint32_t bufSize, uint8_t strTag,
                          const uint8_t *str, uint32_t strLen);
uint32_t SSFASN1EncUTCTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec);
uint32_t SSFASN1EncGeneralizedTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec);
uint32_t SSFASN1EncWrap(uint8_t *buf, uint32_t bufSize, uint8_t tag,
                        const uint8_t *content, uint32_t contentLen);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_ASN1_UNIT_TEST == 1
void SSFASN1UnitTest(void);
#endif /* SSF_CONFIG_ASN1_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_ASN1_H_INCLUDE */
