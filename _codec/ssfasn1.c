/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfasn1.c                                                                                     */
/* Provides ASN.1 DER encode/decode implementation.                                              */
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
#include "ssfassert.h"
#include "ssfasn1.h"
#include "ssfdtime.h"

/* --------------------------------------------------------------------------------------------- */
/* Internal: parse tag + length from a DER buffer. Returns total header size (tag + length        */
/* bytes), or 0 if the buffer is too short or the encoding is invalid.                           */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFASN1ParseTL(const uint8_t *buf, uint32_t bufLen,
                                uint16_t *tagOut, uint32_t *contentLenOut)
{
    uint32_t pos = 0;
    uint32_t len;
    uint16_t tag;

    SSF_REQUIRE(tagOut != NULL);
    SSF_REQUIRE(contentLenOut != NULL);
    SSF_REQUIRE((buf != NULL) || (bufLen == 0u));

    if (bufLen < 2u) return 0;

    /* Tag byte. Low 5 bits != 0x1F -> single-byte tag. Low 5 bits == 0x1F -> high-tag-number   */
    /* form, read one extension byte (tag numbers 31-127 only; reject continuation).           */
    tag = buf[pos++];
    if ((tag & 0x1Fu) == 0x1Fu)
    {
        uint8_t ext;
        if (pos >= bufLen) return 0;
        ext = buf[pos++];
        /* Reject high-bit set: that means another extension byte follows (tag number >= 128),  */
        /* which the module does not support.                                                   */
        if ((ext & 0x80u) != 0u) return 0;
        /* DER §8.1.2.4.2 requires minimum number of extension bytes. With one extension byte, */
        /* the value must be >= 31 (otherwise the single-byte form would have been canonical). */
        if (ext < 31u) return 0;
        tag = (uint16_t)(tag | ((uint16_t)ext << 8));
        /* Still need at least one length byte after the two-byte tag. */
        if (pos >= bufLen) return 0;
    }
    *tagOut = tag;

    /* Length byte(s) */
    if (buf[pos] < 0x80u)
    {
        /* Short form: single byte */
        len = buf[pos++];
    }
    else if (buf[pos] == 0x80u)
    {
        /* Indefinite length: not supported in DER */
        return 0;
    }
    else
    {
        /* Long form: first byte = 0x80 | numLenBytes */
        uint8_t numLenBytes = buf[pos++] & 0x7Fu;
        if (numLenBytes > 4u) return 0; /* Too large */
        if (pos + numLenBytes > bufLen) return 0;

        len = 0;
        while (numLenBytes > 0u)
        {
            len = (len << 8) | buf[pos++];
            numLenBytes--;
        }
    }

    *contentLenOut = len;
    return pos; /* Total header size */
}

/* ========================================================================================== */
/* DECODER                                                                                    */
/* ========================================================================================== */

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetTLV(const SSFASN1Cursor_t *cursor, uint16_t *tagOut,
                      const uint8_t **valueOut, uint32_t *valueLenOut,
                      SSFASN1Cursor_t *next)
{
    uint32_t headerLen;
    uint32_t contentLen;
    uint16_t tag;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE((cursor->buf != NULL) || (cursor->bufLen == 0u));
    SSF_REQUIRE(tagOut != NULL);
    SSF_REQUIRE(valueOut != NULL);
    SSF_REQUIRE(valueLenOut != NULL);
    SSF_REQUIRE(next != NULL);

    headerLen = _SSFASN1ParseTL(cursor->buf, cursor->bufLen, &tag, &contentLen);
    if (headerLen == 0) return false;
    /* Overflow-safe: headerLen <= cursor->bufLen is guaranteed by _SSFASN1ParseTL. */
    if (contentLen > (cursor->bufLen - headerLen)) return false;

    *tagOut = tag;
    *valueOut = &cursor->buf[headerLen];
    *valueLenOut = contentLen;
    next->buf = &cursor->buf[headerLen + contentLen];
    next->bufLen = cursor->bufLen - headerLen - contentLen;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecOpenConstructed(const SSFASN1Cursor_t *cursor, uint16_t expectedTag,
                               SSFASN1Cursor_t *inner, SSFASN1Cursor_t *next)
{
    uint16_t tag;
    const uint8_t *value;
    uint32_t valueLen;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(inner != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next)) return false;
    if (tag != expectedTag) return false;

    inner->buf = value;
    inner->bufLen = valueLen;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecPeekTag(const SSFASN1Cursor_t *cursor, uint16_t *tagOut)
{
    uint16_t tag;
    uint32_t contentLen;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(tagOut != NULL);

    /* Delegate to _SSFASN1ParseTL so the multi-byte tag form decodes consistently. */
    if (_SSFASN1ParseTL(cursor->buf, cursor->bufLen, &tag, &contentLen) == 0) return false;
    *tagOut = tag;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecSkip(const SSFASN1Cursor_t *cursor, SSFASN1Cursor_t *next)
{
    uint16_t tag;
    const uint8_t *value;
    uint32_t valueLen;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(next != NULL);

    return SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next);
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecIsEmpty(const SSFASN1Cursor_t *cursor)
{
    SSF_REQUIRE(cursor != NULL);
    return (cursor->bufLen == 0);
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetBool(const SSFASN1Cursor_t *cursor, bool *valOut, SSFASN1Cursor_t *next)
{
    uint16_t tag;
    const uint8_t *value;
    uint32_t valueLen;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(valOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next)) return false;
    if (tag != SSF_ASN1_TAG_BOOLEAN || valueLen != 1u) return false;
    *valOut = (value[0] != 0x00u);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetInt(const SSFASN1Cursor_t *cursor, const uint8_t **intBufOut,
                      uint32_t *intLenOut, SSFASN1Cursor_t *next)
{
    uint16_t tag;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(intBufOut != NULL);
    SSF_REQUIRE(intLenOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, intBufOut, intLenOut, next)) return false;
    if (tag != SSF_ASN1_TAG_INTEGER) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetIntU64(const SSFASN1Cursor_t *cursor, uint64_t *valOut, SSFASN1Cursor_t *next)
{
    const uint8_t *intBuf;
    uint32_t intLen;
    uint32_t i;
    uint32_t start;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(valOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetInt(cursor, &intBuf, &intLen, next)) return false;

    /* Skip leading zero (sign byte for positive integers) */
    start = 0;
    if (intLen > 1u && intBuf[0] == 0x00u) start = 1;

    if ((intLen - start) > 8u) return false; /* Too large for uint64_t */

    *valOut = 0;
    for (i = start; i < intLen; i++)
    {
        *valOut = (*valOut << 8) | intBuf[i];
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetBitString(const SSFASN1Cursor_t *cursor, const uint8_t **bitsOut,
                            uint32_t *bitsLenOut, uint8_t *unusedBitsOut,
                            SSFASN1Cursor_t *next)
{
    uint16_t tag;
    const uint8_t *value;
    uint32_t valueLen;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(bitsOut != NULL);
    SSF_REQUIRE(bitsLenOut != NULL);
    SSF_REQUIRE(unusedBitsOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next)) return false;
    if (tag != SSF_ASN1_TAG_BIT_STRING) return false;
    if (valueLen < 1u) return false;

    *unusedBitsOut = value[0];
    *bitsOut = &value[1];
    *bitsLenOut = valueLen - 1u;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetOctetString(const SSFASN1Cursor_t *cursor, const uint8_t **octetsOut,
                              uint32_t *octetsLenOut, SSFASN1Cursor_t *next)
{
    uint16_t tag;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(octetsOut != NULL);
    SSF_REQUIRE(octetsLenOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, octetsOut, octetsLenOut, next)) return false;
    if (tag != SSF_ASN1_TAG_OCTET_STRING) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetNull(const SSFASN1Cursor_t *cursor, SSFASN1Cursor_t *next)
{
    uint16_t tag;
    const uint8_t *value;
    uint32_t valueLen;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next)) return false;
    if (tag != SSF_ASN1_TAG_NULL || valueLen != 0u) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetOIDRaw(const SSFASN1Cursor_t *cursor, const uint8_t **oidRawOut,
                         uint32_t *oidRawLenOut, SSFASN1Cursor_t *next)
{
    uint16_t tag;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(oidRawOut != NULL);
    SSF_REQUIRE(oidRawLenOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, oidRawOut, oidRawLenOut, next)) return false;
    if (tag != SSF_ASN1_TAG_OID) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetOID(const SSFASN1Cursor_t *cursor, uint32_t *oidArcsOut,
                      uint8_t oidArcsSize, uint8_t *oidArcsLenOut, SSFASN1Cursor_t *next)
{
    const uint8_t *raw;
    uint32_t rawLen;
    uint32_t pos;
    uint8_t arcCount = 0;
    uint32_t firstSubId;
    uint32_t arcByteCount;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(oidArcsOut != NULL);
    SSF_REQUIRE(oidArcsSize >= 2u);
    SSF_REQUIRE(oidArcsLenOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetOIDRaw(cursor, &raw, &rawLen, next)) return false;
    if (rawLen == 0) return false;

    /* Decode the first sub-identifier (base-128) which encodes arc0*40 + arc1.          */
    /* Non-canonical leading 0x80 is rejected; cap at 5 bytes to fit uint32_t.            */
    if ((raw[0] & 0x7Fu) == 0u && (raw[0] & 0x80u) != 0u) return false;
    firstSubId = 0;
    pos = 0;
    arcByteCount = 0;
    do
    {
        if (pos >= rawLen) return false;
        if (arcByteCount >= 5u) return false; /* Would overflow uint32_t */
        if ((arcByteCount == 4u) && ((firstSubId >> 25) != 0u)) return false;
        firstSubId = (firstSubId << 7) | (uint32_t)(raw[pos] & 0x7Fu);
        arcByteCount++;
    } while ((raw[pos++] & 0x80u) != 0u);

    /* Per X.690 §8.19.4: split first sub-id. arc0 ∈ {0,1,2}; if arc0 ∈ {0,1} then       */
    /* arc1 ∈ [0,39], so firstSubId < 80; else arc0 = 2 and arc1 = firstSubId - 80.       */
    if (firstSubId < 80u)
    {
        oidArcsOut[0] = firstSubId / 40u;
        oidArcsOut[1] = firstSubId % 40u;
    }
    else
    {
        oidArcsOut[0] = 2u;
        oidArcsOut[1] = firstSubId - 80u;
    }
    arcCount = 2;

    /* Remaining sub-identifiers: base-128 encoded arcs */
    while (pos < rawLen)
    {
        uint32_t arc = 0;
        if ((raw[pos] & 0x7Fu) == 0u && (raw[pos] & 0x80u) != 0u) return false;
        arcByteCount = 0;
        do
        {
            if (pos >= rawLen) return false;
            if (arcByteCount >= 5u) return false;
            if ((arcByteCount == 4u) && ((arc >> 25) != 0u)) return false;
            arc = (arc << 7) | (uint32_t)(raw[pos] & 0x7Fu);
            arcByteCount++;
        } while ((raw[pos++] & 0x80u) != 0u);

        if (arcCount >= oidArcsSize) return false;
        oidArcsOut[arcCount++] = arc;
    }

    *oidArcsLenOut = arcCount;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetString(const SSFASN1Cursor_t *cursor, const uint8_t **strOut,
                         uint32_t *strLenOut, uint16_t *strTagOut, SSFASN1Cursor_t *next)
{
    uint16_t tag;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(strOut != NULL);
    SSF_REQUIRE(strLenOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, strOut, strLenOut, next)) return false;

    /* Accept all string types per RFC 5280 §4.1.2.4 DirectoryString. New certs SHOULD use     */
    /* UTF-8 / Printable; legacy certs (e.g. early Entrust roots) carry TeletexString or       */
    /* UniversalString and verifiers MUST handle them.                                          */
    if (tag != SSF_ASN1_TAG_UTF8_STRING && tag != SSF_ASN1_TAG_PRINTABLE_STRING &&
        tag != SSF_ASN1_TAG_IA5_STRING && tag != SSF_ASN1_TAG_BMP_STRING &&
        tag != SSF_ASN1_TAG_T61_STRING && tag != SSF_ASN1_TAG_UNIVERSAL_STRING)
    {
        return false;
    }
    if (strTagOut != NULL) *strTagOut = tag;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: parse two ASCII digits. Returns false if either byte is not a digit.                */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFASN1Parse2Digit(const uint8_t *p, uint32_t *valOut)
{
    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(valOut != NULL);

    if (p[0] < (uint8_t)'0' || p[0] > (uint8_t)'9') return false;
    if (p[1] < (uint8_t)'0' || p[1] > (uint8_t)'9') return false;
    *valOut = (uint32_t)(p[0] - '0') * 10u + (uint32_t)(p[1] - '0');
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetTime(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut,
                       SSFASN1Cursor_t *next)
{
    uint16_t tag;
    const uint8_t *value;
    uint32_t valueLen;
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t second;
    uint32_t pos;
    SSFDTimeStruct_t ts;
    SSFPortTick_t unixSys;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(unixSecOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next)) return false;

    if (tag == SSF_ASN1_TAG_UTC_TIME)
    {
        /* DER X.509 profile requires exactly YYMMDDHHMMSSZ (13 bytes). */
        uint32_t yy;
        if (valueLen != 13u) return false;
        if (!_SSFASN1Parse2Digit(&value[0], &yy)) return false;
        year = yy + ((yy >= 50u) ? 1900u : 2000u);
        pos = 2;
    }
    else if (tag == SSF_ASN1_TAG_GENERALIZED_TIME)
    {
        /* DER X.509 profile requires exactly YYYYMMDDHHMMSSZ (15 bytes). */
        uint32_t hi;
        uint32_t lo;
        if (valueLen != 15u) return false;
        if (!_SSFASN1Parse2Digit(&value[0], &hi)) return false;
        if (!_SSFASN1Parse2Digit(&value[2], &lo)) return false;
        year = hi * 100u + lo;
        pos = 4;
    }
    else
    {
        return false;
    }

    if (!_SSFASN1Parse2Digit(&value[pos], &month)) return false;
    pos += 2;
    if (!_SSFASN1Parse2Digit(&value[pos], &day)) return false;
    pos += 2;
    if (!_SSFASN1Parse2Digit(&value[pos], &hour)) return false;
    pos += 2;
    if (!_SSFASN1Parse2Digit(&value[pos], &minute)) return false;
    pos += 2;
    if (!_SSFASN1Parse2Digit(&value[pos], &second)) return false;
    pos += 2;

    /* Trailing 'Z' required per DER X.509 profile (no offsets, no fractional seconds). */
    if (value[pos] != (uint8_t)'Z') return false;

    /* Year must fit in ssfdtime's supported range (1970 + [0..229]). Month must be >= 1 so    */
    /* (month - 1) fits in the 0-indexed ssfdtime contract.                                    */
    if (year < SSFDTIME_EPOCH_YEAR_MIN || year > SSFDTIME_EPOCH_YEAR_MAX) return false;
    if (month < 1u || month > 12u) return false;
    if (day < 1u) return false;

    /* SSFDTimeStructInit performs strict calendar validation (leap years, days-in-month,      */
    /* hour/min/sec ranges). Day and month translate to ssfdtime's 0-indexed convention.       */
    if (!SSFDTimeStructInit(&ts, (uint16_t)(year - SSFDTIME_EPOCH_YEAR_MIN),
                            (uint8_t)(month - 1u), (uint8_t)(day - 1u),
                            (uint8_t)hour, (uint8_t)minute, (uint8_t)second, 0u))
    {
        return false;
    }
    if (!SSFDTimeStructToUnix(&ts, &unixSys)) return false;

    *unixSecOut = (uint64_t)(unixSys / SSF_TICKS_PER_SEC);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: decode common Y/M/D digits from a DATE or DATE-TIME payload. Returns false on any   */
/* format or range violation. Populates ts[0] (year), ts[1] (month 1-12), ts[2] (day 1-31).     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFASN1ParseYMD(const uint8_t *p, uint32_t *year, uint32_t *month, uint32_t *day)
{
    uint32_t yHi, yLo;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(year != NULL);
    SSF_REQUIRE(month != NULL);
    SSF_REQUIRE(day != NULL);

    /* "YYYY-MM-DD" layout: digits at [0-3], [5-6], [8-9]; dashes at [4] and [7]. */
    if (!_SSFASN1Parse2Digit(&p[0], &yHi)) return false;
    if (!_SSFASN1Parse2Digit(&p[2], &yLo)) return false;
    if (p[4] != (uint8_t)'-') return false;
    if (!_SSFASN1Parse2Digit(&p[5], month)) return false;
    if (p[7] != (uint8_t)'-') return false;
    if (!_SSFASN1Parse2Digit(&p[8], day)) return false;
    *year = yHi * 100u + yLo;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: build a unix-second count from validated Y/M/D/H/M/S via ssfdtime.                  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFASN1YMDHMSToUnix(uint32_t year, uint32_t month, uint32_t day,
                                 uint32_t hour, uint32_t minute, uint32_t second,
                                 uint64_t *unixSecOut)
{
    SSFDTimeStruct_t ts;
    SSFPortTick_t unixSys;

    SSF_REQUIRE(unixSecOut != NULL);

    if (year < SSFDTIME_EPOCH_YEAR_MIN || year > SSFDTIME_EPOCH_YEAR_MAX) return false;
    if (month < 1u || month > 12u) return false;
    if (day < 1u) return false;
    if (hour > 23u || minute > 59u || second > 59u) return false;

    if (!SSFDTimeStructInit(&ts, (uint16_t)(year - SSFDTIME_EPOCH_YEAR_MIN),
                            (uint8_t)(month - 1u), (uint8_t)(day - 1u),
                            (uint8_t)hour, (uint8_t)minute, (uint8_t)second, 0u))
    {
        return false;
    }
    if (!SSFDTimeStructToUnix(&ts, &unixSys)) return false;

    *unixSecOut = (uint64_t)(unixSys / SSF_TICKS_PER_SEC);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetDate(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut,
                       SSFASN1Cursor_t *next)
{
    uint16_t tag;
    const uint8_t *value;
    uint32_t valueLen;
    uint32_t year;
    uint32_t month;
    uint32_t day;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(unixSecOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next)) return false;
    if (tag != SSF_ASN1_TAG_DATE) return false;
    if (valueLen != 10u) return false; /* "YYYY-MM-DD" */
    if (!_SSFASN1ParseYMD(value, &year, &month, &day)) return false;

    return _SSFASN1YMDHMSToUnix(year, month, day, 0u, 0u, 0u, unixSecOut);
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetDateTime(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut,
                           SSFASN1Cursor_t *next)
{
    uint16_t tag;
    const uint8_t *value;
    uint32_t valueLen;
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t second;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(unixSecOut != NULL);
    SSF_REQUIRE(next != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next)) return false;
    if (tag != SSF_ASN1_TAG_DATE_TIME) return false;
    if (valueLen != 19u) return false; /* "YYYY-MM-DDTHH:MM:SS" */

    if (!_SSFASN1ParseYMD(value, &year, &month, &day)) return false;
    if (value[10] != (uint8_t)'T') return false;
    if (!_SSFASN1Parse2Digit(&value[11], &hour)) return false;
    if (value[13] != (uint8_t)':') return false;
    if (!_SSFASN1Parse2Digit(&value[14], &minute)) return false;
    if (value[16] != (uint8_t)':') return false;
    if (!_SSFASN1Parse2Digit(&value[17], &second)) return false;

    return _SSFASN1YMDHMSToUnix(year, month, day, hour, minute, second, unixSecOut);
}

/* ========================================================================================== */
/* ENCODER                                                                                    */
/* ========================================================================================== */

/* --------------------------------------------------------------------------------------------- */
/* Internal: compute the number of bytes needed for a DER length field.                          */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFASN1LenFieldSize(uint32_t contentLen)
{
    if (contentLen < 0x80u) return 1;
    if (contentLen <= 0xFFu) return 2;
    if (contentLen <= 0xFFFFu) return 3;
    if (contentLen <= 0xFFFFFFu) return 4;
    return 5;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: write a DER length field into buf. Returns bytes written.                           */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFASN1WriteLenField(uint8_t *buf, uint32_t contentLen)
{
    SSF_REQUIRE(buf != NULL);

    if (contentLen < 0x80u)
    {
        buf[0] = (uint8_t)contentLen;
        return 1;
    }
    else if (contentLen <= 0xFFu)
    {
        buf[0] = 0x81u;
        buf[1] = (uint8_t)contentLen;
        return 2;
    }
    else if (contentLen <= 0xFFFFu)
    {
        buf[0] = 0x82u;
        buf[1] = (uint8_t)(contentLen >> 8);
        buf[2] = (uint8_t)(contentLen);
        return 3;
    }
    else if (contentLen <= 0xFFFFFFu)
    {
        buf[0] = 0x83u;
        buf[1] = (uint8_t)(contentLen >> 16);
        buf[2] = (uint8_t)(contentLen >> 8);
        buf[3] = (uint8_t)(contentLen);
        return 4;
    }
    else
    {
        buf[0] = 0x84u;
        buf[1] = (uint8_t)(contentLen >> 24);
        buf[2] = (uint8_t)(contentLen >> 16);
        buf[3] = (uint8_t)(contentLen >> 8);
        buf[4] = (uint8_t)(contentLen);
        return 5;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: number of bytes the DER tag field occupies.                                         */
/* Single-byte tag (low-5-bits != 0x1F): 1 byte. Two-byte tag (number 31-127): 2 bytes.          */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFASN1TagFieldSize(uint16_t tag)
{
    return ((tag & 0x1Fu) == 0x1Fu) ? 2u : 1u;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: write the DER tag field. Asserts buf is large enough.                               */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFASN1WriteTagField(uint8_t *buf, uint16_t tag)
{
    SSF_REQUIRE(buf != NULL);

    buf[0] = (uint8_t)(tag & 0xFFu);
    if ((tag & 0x1Fu) == 0x1Fu)
    {
        buf[1] = (uint8_t)((tag >> 8) & 0xFFu);
        return 2u;
    }
    return 1u;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncTagLen(uint8_t *buf, uint32_t bufSize, uint16_t tag, uint32_t contentLen,
                      uint32_t *bytesWritten)
{
    uint32_t tagLen;
    uint32_t headerLen;

    SSF_REQUIRE(bytesWritten != NULL);

    *bytesWritten = 0;
    tagLen = _SSFASN1TagFieldSize(tag);
    headerLen = tagLen + _SSFASN1LenFieldSize(contentLen);

    if (buf == NULL)
    {
        *bytesWritten = headerLen;
        return true;
    }
    if (bufSize < headerLen) return false;

    (void)_SSFASN1WriteTagField(buf, tag);
    _SSFASN1WriteLenField(&buf[tagLen], contentLen);
    *bytesWritten = headerLen;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncBool(uint8_t *buf, uint32_t bufSize, bool val, uint32_t *bytesWritten)
{
    const uint32_t total = 3u; /* tag(1) + len(1) + value(1) */

    SSF_REQUIRE(bytesWritten != NULL);

    *bytesWritten = 0;
    if (buf == NULL)
    {
        *bytesWritten = total;
        return true;
    }
    if (bufSize < total) return false;

    buf[0] = SSF_ASN1_TAG_BOOLEAN;
    buf[1] = 0x01u;
    buf[2] = val ? 0xFFu : 0x00u;
    *bytesWritten = total;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncInt(uint8_t *buf, uint32_t bufSize, const uint8_t *intBuf, uint32_t intLen,
                   uint32_t *bytesWritten)
{
    uint32_t headerLen;
    uint32_t total;

    SSF_REQUIRE(intBuf != NULL);
    SSF_REQUIRE(intLen > 0);
    SSF_REQUIRE(bytesWritten != NULL);

    *bytesWritten = 0;
    headerLen = 1u + _SSFASN1LenFieldSize(intLen);
    if (intLen > (0xFFFFFFFFu - headerLen)) return false; /* Overflow guard */
    total = headerLen + intLen;

    if (buf == NULL)
    {
        *bytesWritten = total;
        return true;
    }
    if (bufSize < total) return false;

    buf[0] = SSF_ASN1_TAG_INTEGER;
    _SSFASN1WriteLenField(&buf[1], intLen);
    memcpy(&buf[headerLen], intBuf, intLen);
    *bytesWritten = total;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncIntU64(uint8_t *buf, uint32_t bufSize, uint64_t val, uint32_t *bytesWritten)
{
    uint8_t intBuf[9];
    uint32_t intLen;
    uint32_t i;

    SSF_REQUIRE(bytesWritten != NULL);

    /* Encode as big-endian with minimal length, adding leading zero if high bit set */
    if (val == 0)
    {
        intBuf[0] = 0x00u;
        intLen = 1;
    }
    else
    {
        intLen = 0;
        for (i = 0; i < 8u; i++)
        {
            uint8_t b = (uint8_t)(val >> (56u - i * 8u));
            if (b != 0 || intLen > 0)
            {
                intBuf[intLen++] = b;
            }
        }
        if (intBuf[0] & 0x80u)
        {
            memmove(&intBuf[1], intBuf, intLen);
            intBuf[0] = 0x00u;
            intLen++;
        }
    }

    return SSFASN1EncInt(buf, bufSize, intBuf, intLen, bytesWritten);
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncBitString(uint8_t *buf, uint32_t bufSize, const uint8_t *bits, uint32_t bitsLen,
                         uint8_t unusedBits, uint32_t *bytesWritten)
{
    uint32_t contentLen;
    uint32_t headerLen;
    uint32_t total;

    SSF_REQUIRE((bits != NULL) || (bitsLen == 0u));
    SSF_REQUIRE(unusedBits <= 7u);
    SSF_REQUIRE(!((bitsLen == 0u) && (unusedBits != 0u)));
    SSF_REQUIRE(bytesWritten != NULL);

    *bytesWritten = 0;
    if (bitsLen == 0xFFFFFFFFu) return false; /* Overflow guard on contentLen = 1 + bitsLen */
    contentLen = 1u + bitsLen;
    headerLen = 1u + _SSFASN1LenFieldSize(contentLen);
    if (contentLen > (0xFFFFFFFFu - headerLen)) return false; /* Overflow guard on total */
    total = headerLen + contentLen;

    if (buf == NULL)
    {
        *bytesWritten = total;
        return true;
    }
    if (bufSize < total) return false;

    buf[0] = SSF_ASN1_TAG_BIT_STRING;
    _SSFASN1WriteLenField(&buf[1], contentLen);
    buf[headerLen] = unusedBits;
    if (bitsLen > 0) memcpy(&buf[headerLen + 1u], bits, bitsLen);
    *bytesWritten = total;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncOctetString(uint8_t *buf, uint32_t bufSize, const uint8_t *octets,
                           uint32_t octetsLen, uint32_t *bytesWritten)
{
    SSF_REQUIRE((octets != NULL) || (octetsLen == 0u));
    return SSFASN1EncWrap(buf, bufSize, SSF_ASN1_TAG_OCTET_STRING, octets, octetsLen,
                          bytesWritten);
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncNull(uint8_t *buf, uint32_t bufSize, uint32_t *bytesWritten)
{
    const uint32_t total = 2u;

    SSF_REQUIRE(bytesWritten != NULL);

    *bytesWritten = 0;
    if (buf == NULL)
    {
        *bytesWritten = total;
        return true;
    }
    if (bufSize < total) return false;

    buf[0] = SSF_ASN1_TAG_NULL;
    buf[1] = 0x00u;
    *bytesWritten = total;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncOIDRaw(uint8_t *buf, uint32_t bufSize, const uint8_t *oidRaw, uint32_t oidRawLen,
                      uint32_t *bytesWritten)
{
    SSF_REQUIRE(oidRaw != NULL);
    SSF_REQUIRE(oidRawLen > 0u);
    return SSFASN1EncWrap(buf, bufSize, SSF_ASN1_TAG_OID, oidRaw, oidRawLen, bytesWritten);
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncString(uint8_t *buf, uint32_t bufSize, uint16_t strTag, const uint8_t *str,
                      uint32_t strLen, uint32_t *bytesWritten)
{
    SSF_REQUIRE((str != NULL) || (strLen == 0u));
    return SSFASN1EncWrap(buf, bufSize, strTag, str, strLen, bytesWritten);
}

/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
/* Internal: resolve a Unix seconds count into a calendar struct via ssfdtime.                   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFASN1UnixSecToStruct(uint64_t unixSec, SSFDTimeStruct_t *ts)
{
    SSFPortTick_t unixSys;

    SSF_REQUIRE(ts != NULL);

    if (unixSec > SSFDTIME_UNIX_EPOCH_SEC_MAX) return false;
    unixSys = (SSFPortTick_t)unixSec * SSF_TICKS_PER_SEC;
    return SSFDTimeUnixToStruct(unixSys, ts, sizeof(*ts));
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncUTCTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec,
                       uint32_t *bytesWritten)
{
    /* Format: YYMMDDHHMMSSZ (13 bytes). Year range: 1970-2049 (YY ∈ 50..99 means 1950..1999    */
    /* per RFC 5280, but ssfdtime cannot represent pre-1970; YY ∈ 00..49 means 2000..2049).     */
    uint8_t timeStr[13];
    SSFDTimeStruct_t ts;
    uint32_t year;
    uint32_t month;
    uint32_t day;

    SSF_REQUIRE(bytesWritten != NULL);

    *bytesWritten = 0;
    if (!_SSFASN1UnixSecToStruct(unixSec, &ts)) return false;

    year = (uint32_t)ts.year + SSFDTIME_EPOCH_YEAR_MIN;
    if (year > 2049u) return false;

    month = (uint32_t)ts.month + 1u;
    day = (uint32_t)ts.day + 1u;

    year %= 100u;
    timeStr[0] = (uint8_t)('0' + year / 10u);
    timeStr[1] = (uint8_t)('0' + year % 10u);
    timeStr[2] = (uint8_t)('0' + month / 10u);
    timeStr[3] = (uint8_t)('0' + month % 10u);
    timeStr[4] = (uint8_t)('0' + day / 10u);
    timeStr[5] = (uint8_t)('0' + day % 10u);
    timeStr[6] = (uint8_t)('0' + ts.hour / 10u);
    timeStr[7] = (uint8_t)('0' + ts.hour % 10u);
    timeStr[8] = (uint8_t)('0' + ts.min / 10u);
    timeStr[9] = (uint8_t)('0' + ts.min % 10u);
    timeStr[10] = (uint8_t)('0' + ts.sec / 10u);
    timeStr[11] = (uint8_t)('0' + ts.sec % 10u);
    timeStr[12] = 'Z';

    return SSFASN1EncWrap(buf, bufSize, SSF_ASN1_TAG_UTC_TIME, timeStr, 13, bytesWritten);
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncGeneralizedTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec,
                               uint32_t *bytesWritten)
{
    /* Format: YYYYMMDDHHMMSSZ (15 bytes). Supported via ssfdtime: 1970-2199. */
    uint8_t timeStr[15];
    SSFDTimeStruct_t ts;
    uint32_t year;
    uint32_t month;
    uint32_t day;

    SSF_REQUIRE(bytesWritten != NULL);

    *bytesWritten = 0;
    if (!_SSFASN1UnixSecToStruct(unixSec, &ts)) return false;

    year = (uint32_t)ts.year + SSFDTIME_EPOCH_YEAR_MIN;
    month = (uint32_t)ts.month + 1u;
    day = (uint32_t)ts.day + 1u;

    timeStr[0] = (uint8_t)('0' + year / 1000u);
    timeStr[1] = (uint8_t)('0' + (year / 100u) % 10u);
    timeStr[2] = (uint8_t)('0' + (year / 10u) % 10u);
    timeStr[3] = (uint8_t)('0' + year % 10u);
    timeStr[4] = (uint8_t)('0' + month / 10u);
    timeStr[5] = (uint8_t)('0' + month % 10u);
    timeStr[6] = (uint8_t)('0' + day / 10u);
    timeStr[7] = (uint8_t)('0' + day % 10u);
    timeStr[8] = (uint8_t)('0' + ts.hour / 10u);
    timeStr[9] = (uint8_t)('0' + ts.hour % 10u);
    timeStr[10] = (uint8_t)('0' + ts.min / 10u);
    timeStr[11] = (uint8_t)('0' + ts.min % 10u);
    timeStr[12] = (uint8_t)('0' + ts.sec / 10u);
    timeStr[13] = (uint8_t)('0' + ts.sec % 10u);
    timeStr[14] = 'Z';

    return SSFASN1EncWrap(buf, bufSize, SSF_ASN1_TAG_GENERALIZED_TIME, timeStr, 15,
                          bytesWritten);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: format a 4-digit year + 2-digit month/day into a "YYYY-MM-DD" buffer.               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFASN1FormatDate(uint8_t *dst, uint32_t year, uint32_t month, uint32_t day)
{
    SSF_REQUIRE(dst != NULL);

    dst[0] = (uint8_t)('0' + year / 1000u);
    dst[1] = (uint8_t)('0' + (year / 100u) % 10u);
    dst[2] = (uint8_t)('0' + (year / 10u) % 10u);
    dst[3] = (uint8_t)('0' + year % 10u);
    dst[4] = (uint8_t)'-';
    dst[5] = (uint8_t)('0' + month / 10u);
    dst[6] = (uint8_t)('0' + month % 10u);
    dst[7] = (uint8_t)'-';
    dst[8] = (uint8_t)('0' + day / 10u);
    dst[9] = (uint8_t)('0' + day % 10u);
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncDate(uint8_t *buf, uint32_t bufSize, uint64_t unixSec, uint32_t *bytesWritten)
{
    /* Format: YYYY-MM-DD (10 bytes), wrapped in multi-byte tag [UNIVERSAL 31]. */
    uint8_t timeStr[10];
    SSFDTimeStruct_t ts;
    uint32_t year;
    uint32_t month;
    uint32_t day;

    SSF_REQUIRE(bytesWritten != NULL);

    *bytesWritten = 0;
    if (!_SSFASN1UnixSecToStruct(unixSec, &ts)) return false;

    year = (uint32_t)ts.year + SSFDTIME_EPOCH_YEAR_MIN;
    month = (uint32_t)ts.month + 1u;
    day = (uint32_t)ts.day + 1u;
    _SSFASN1FormatDate(timeStr, year, month, day);

    return SSFASN1EncWrap(buf, bufSize, SSF_ASN1_TAG_DATE, timeStr, 10, bytesWritten);
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncDateTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec,
                        uint32_t *bytesWritten)
{
    /* Format: YYYY-MM-DDTHH:MM:SS (19 bytes), wrapped in multi-byte tag [UNIVERSAL 33]. */
    uint8_t timeStr[19];
    SSFDTimeStruct_t ts;
    uint32_t year;
    uint32_t month;
    uint32_t day;

    SSF_REQUIRE(bytesWritten != NULL);

    *bytesWritten = 0;
    if (!_SSFASN1UnixSecToStruct(unixSec, &ts)) return false;

    year = (uint32_t)ts.year + SSFDTIME_EPOCH_YEAR_MIN;
    month = (uint32_t)ts.month + 1u;
    day = (uint32_t)ts.day + 1u;
    _SSFASN1FormatDate(timeStr, year, month, day);
    timeStr[10] = (uint8_t)'T';
    timeStr[11] = (uint8_t)('0' + ts.hour / 10u);
    timeStr[12] = (uint8_t)('0' + ts.hour % 10u);
    timeStr[13] = (uint8_t)':';
    timeStr[14] = (uint8_t)('0' + ts.min / 10u);
    timeStr[15] = (uint8_t)('0' + ts.min % 10u);
    timeStr[16] = (uint8_t)':';
    timeStr[17] = (uint8_t)('0' + ts.sec / 10u);
    timeStr[18] = (uint8_t)('0' + ts.sec % 10u);

    return SSFASN1EncWrap(buf, bufSize, SSF_ASN1_TAG_DATE_TIME, timeStr, 19, bytesWritten);
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1EncWrap(uint8_t *buf, uint32_t bufSize, uint16_t tag, const uint8_t *content,
                    uint32_t contentLen, uint32_t *bytesWritten)
{
    uint32_t tagLen;
    uint32_t headerLen;
    uint32_t total;

    SSF_REQUIRE((content != NULL) || (contentLen == 0u));
    SSF_REQUIRE(bytesWritten != NULL);

    *bytesWritten = 0;
    tagLen = _SSFASN1TagFieldSize(tag);
    headerLen = tagLen + _SSFASN1LenFieldSize(contentLen);
    if (contentLen > (0xFFFFFFFFu - headerLen)) return false; /* Overflow guard on total */
    total = headerLen + contentLen;

    if (buf == NULL)
    {
        *bytesWritten = total;
        return true;
    }
    if (bufSize < total) return false;

    (void)_SSFASN1WriteTagField(buf, tag);
    _SSFASN1WriteLenField(&buf[tagLen], contentLen);
    if (contentLen > 0u)
    {
        memcpy(&buf[headerLen], content, contentLen);
    }
    *bytesWritten = total;
    return true;
}
