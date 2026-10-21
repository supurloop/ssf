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
/* Tag numbers 0-127 are supported (single-byte form for 0-30, two-byte high-tag form for 31-127).*/
/* Tag numbers >= 128 (requiring multiple extension bytes) are not supported.                    */
/* Only definite-length encoding is supported (no indefinite length).                            */
/* Maximum content length is 2^32-1 bytes (4-byte length field).                                 */
/* OID arc decoding supports up to SSF_ASN1_CONFIG_MAX_OID_ARCS arcs.                            */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* ASN.1 tag representation                                                                      */
/* --------------------------------------------------------------------------------------------- */
/* Tags are stored in a uint16_t:                                                                */
/*   - Bits 0-7 hold the first DER tag byte (class + P/C + low-5-bits of number, or 0x1F when   */
/*     the tag uses the two-byte high-tag-number form).                                          */
/*   - Bits 8-15 hold the extension byte for multi-byte tags (tag numbers 31-127). Zero for     */
/*     single-byte tags.                                                                         */
/* So existing single-byte constants remain numerically identical (e.g., SEQUENCE == 0x30).     */

/* --------------------------------------------------------------------------------------------- */
/* ASN.1 tag constants                                                                           */
/* --------------------------------------------------------------------------------------------- */

/* Universal class tags (single-byte form, number <= 30) */
#define SSF_ASN1_TAG_BOOLEAN            ((uint16_t)0x0001u)
#define SSF_ASN1_TAG_INTEGER            ((uint16_t)0x0002u)
#define SSF_ASN1_TAG_BIT_STRING         ((uint16_t)0x0003u)
#define SSF_ASN1_TAG_OCTET_STRING       ((uint16_t)0x0004u)
#define SSF_ASN1_TAG_NULL               ((uint16_t)0x0005u)
#define SSF_ASN1_TAG_OID                ((uint16_t)0x0006u)
#define SSF_ASN1_TAG_UTF8_STRING        ((uint16_t)0x000Cu)
#define SSF_ASN1_TAG_PRINTABLE_STRING   ((uint16_t)0x0013u)
#define SSF_ASN1_TAG_T61_STRING         ((uint16_t)0x0014u) /* TeletexString (legacy) */
#define SSF_ASN1_TAG_IA5_STRING         ((uint16_t)0x0016u)
#define SSF_ASN1_TAG_UTC_TIME           ((uint16_t)0x0017u)
#define SSF_ASN1_TAG_GENERALIZED_TIME   ((uint16_t)0x0018u)
#define SSF_ASN1_TAG_UNIVERSAL_STRING   ((uint16_t)0x001Cu)
#define SSF_ASN1_TAG_BMP_STRING         ((uint16_t)0x001Eu)
#define SSF_ASN1_TAG_SEQUENCE           ((uint16_t)0x0030u)
#define SSF_ASN1_TAG_SET                ((uint16_t)0x0031u)

/* Universal class tags (two-byte high-tag form, number >= 31) */
/* First DER byte: class=universal (00), P/C=primitive (0), low-5-bits=11111 -> 0x1F.            */
/* Extension byte: tag number (<=127 for single-extension-byte encoding).                        */
#define SSF_ASN1_TAG_DATE               ((uint16_t)((31u << 8) | 0x1Fu))  /* 0x1F1F */
#define SSF_ASN1_TAG_DATE_TIME          ((uint16_t)((33u << 8) | 0x1Fu))  /* 0x211F */

/* Tag class bits */
#define SSF_ASN1_CLASS_UNIVERSAL        ((uint8_t)0x00u)
#define SSF_ASN1_CLASS_APPLICATION      ((uint8_t)0x40u)
#define SSF_ASN1_CLASS_CONTEXT          ((uint8_t)0x80u)
#define SSF_ASN1_CLASS_PRIVATE          ((uint8_t)0xC0u)

/* Constructed bit */
#define SSF_ASN1_CONSTRUCTED            ((uint8_t)0x20u)

/* Context-specific tag helpers (for X.509 OPTIONAL/IMPLICIT/EXPLICIT tagged fields). Numbers    */
/* 0-30 only; beyond that, callers must construct the two-byte form themselves.                  */
#define SSF_ASN1_CONTEXT_EXPLICIT(n)    ((uint16_t)(SSF_ASN1_CLASS_CONTEXT | SSF_ASN1_CONSTRUCTED | (n)))
#define SSF_ASN1_CONTEXT_IMPLICIT(n)    ((uint16_t)(SSF_ASN1_CLASS_CONTEXT | (n)))

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
bool SSFASN1DecGetTLV(const SSFASN1Cursor_t *cursor, uint16_t *tagOut, const uint8_t **valueOut,
                      uint32_t *valueLenOut, SSFASN1Cursor_t *next);

/* Enter a constructed element (SEQUENCE, SET, or context-tagged).                               */
bool SSFASN1DecOpenConstructed(const SSFASN1Cursor_t *cursor, uint16_t expectedTag,
                               SSFASN1Cursor_t *inner, SSFASN1Cursor_t *next);

/* Peek at the tag without advancing. */
bool SSFASN1DecPeekTag(const SSFASN1Cursor_t *cursor, uint16_t *tagOut);

/* Skip one complete TLV element. */
bool SSFASN1DecSkip(const SSFASN1Cursor_t *cursor, SSFASN1Cursor_t *next);

/* Returns true if the cursor has no remaining data. */
bool SSFASN1DecIsEmpty(const SSFASN1Cursor_t *cursor);

/* Primitive type decoders */
bool SSFASN1DecGetBool(const SSFASN1Cursor_t *cursor, bool *valOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetInt(const SSFASN1Cursor_t *cursor, const uint8_t **intBufOut, uint32_t *intLenOut,
                      SSFASN1Cursor_t *next);
bool SSFASN1DecGetIntU64(const SSFASN1Cursor_t *cursor, uint64_t *valOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetBitString(const SSFASN1Cursor_t *cursor, const uint8_t **bitsOut,
                            uint32_t *bitsLenOut, uint8_t *unusedBitsOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetOctetString(const SSFASN1Cursor_t *cursor, const uint8_t **octetsOut,
                              uint32_t *octetsLenOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetNull(const SSFASN1Cursor_t *cursor, SSFASN1Cursor_t *next);
bool SSFASN1DecGetOID(const SSFASN1Cursor_t *cursor, uint32_t *oidArcsOut, uint8_t oidArcsSize,
                      uint8_t *oidArcsLenOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetOIDRaw(const SSFASN1Cursor_t *cursor, const uint8_t **oidRawOut,
                         uint32_t *oidRawLenOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetString(const SSFASN1Cursor_t *cursor, const uint8_t **strOut, uint32_t *strLenOut,
                         uint16_t *strTagOut, SSFASN1Cursor_t *next);
bool SSFASN1DecGetTime(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut, SSFASN1Cursor_t *next);
/* DATE: decodes a "YYYY-MM-DD" payload. Returns Unix seconds for 00:00:00 UTC of that date.     */
bool SSFASN1DecGetDate(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut, SSFASN1Cursor_t *next);
/* DATE-TIME: decodes a "YYYY-MM-DDTHH:MM:SS" payload (UTC). Returns Unix seconds.               */
bool SSFASN1DecGetDateTime(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut,
                           SSFASN1Cursor_t *next);

/* --------------------------------------------------------------------------------------------- */
/* Encoder interface                                                                             */
/* --------------------------------------------------------------------------------------------- */

/* All encoders return true on success and report the number of bytes written (or required if   */
/* buf == NULL) in *bytesWritten. On failure (invalid input, buffer too small, overflow) return */
/* false and set *bytesWritten = 0. When buf == NULL the encoder measures without writing       */
/* (two-pass pattern: call with NULL to size the buffer, then again to write).                  */
/* bytesWritten is required (non-NULL); asserted via SSF_REQUIRE.                                */

bool SSFASN1EncTagLen(uint8_t *buf, uint32_t bufSize, uint16_t tag, uint32_t contentLen,
                      uint32_t *bytesWritten);
bool SSFASN1EncBool(uint8_t *buf, uint32_t bufSize, bool val, uint32_t *bytesWritten);
bool SSFASN1EncInt(uint8_t *buf, uint32_t bufSize, const uint8_t *intBuf, uint32_t intLen,
                   uint32_t *bytesWritten);
bool SSFASN1EncIntU64(uint8_t *buf, uint32_t bufSize, uint64_t val, uint32_t *bytesWritten);
bool SSFASN1EncBitString(uint8_t *buf, uint32_t bufSize, const uint8_t *bits, uint32_t bitsLen,
                         uint8_t unusedBits, uint32_t *bytesWritten);
bool SSFASN1EncOctetString(uint8_t *buf, uint32_t bufSize, const uint8_t *octets,
                           uint32_t octetsLen, uint32_t *bytesWritten);
bool SSFASN1EncNull(uint8_t *buf, uint32_t bufSize, uint32_t *bytesWritten);
bool SSFASN1EncOIDRaw(uint8_t *buf, uint32_t bufSize, const uint8_t *oidRaw, uint32_t oidRawLen,
                      uint32_t *bytesWritten);
bool SSFASN1EncString(uint8_t *buf, uint32_t bufSize, uint16_t strTag, const uint8_t *str,
                      uint32_t strLen, uint32_t *bytesWritten);
bool SSFASN1EncUTCTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec, uint32_t *bytesWritten);
bool SSFASN1EncGeneralizedTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec,
                               uint32_t *bytesWritten);
/* DATE: encodes the date portion of unixSec as "YYYY-MM-DD" under tag [UNIVERSAL 31]. Sub-day   */
/* resolution is truncated (rounded down to midnight UTC).                                       */
bool SSFASN1EncDate(uint8_t *buf, uint32_t bufSize, uint64_t unixSec, uint32_t *bytesWritten);
/* DATE-TIME: encodes unixSec as "YYYY-MM-DDTHH:MM:SS" (UTC) under tag [UNIVERSAL 33].           */
bool SSFASN1EncDateTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec, uint32_t *bytesWritten);
bool SSFASN1EncWrap(uint8_t *buf, uint32_t bufSize, uint16_t tag, const uint8_t *content,
                    uint32_t contentLen, uint32_t *bytesWritten);

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
