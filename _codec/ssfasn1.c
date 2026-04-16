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

/* --------------------------------------------------------------------------------------------- */
/* Internal: parse tag + length from a DER buffer. Returns total header size (tag + length        */
/* bytes), or 0 if the buffer is too short or the encoding is invalid.                           */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _SSFASN1ParseTL(const uint8_t *buf, uint32_t bufLen,
                                uint8_t *tagOut, uint32_t *contentLenOut)
{
    uint32_t pos = 0;
    uint32_t len;

    if (bufLen < 2u) return 0;

    /* Tag byte (single-byte tags only; high-tag-number form not supported) */
    *tagOut = buf[pos++];
    if ((*tagOut & 0x1Fu) == 0x1Fu) return 0; /* Multi-byte tag not supported */

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
bool SSFASN1DecGetTLV(const SSFASN1Cursor_t *cursor, uint8_t *tagOut,
                      const uint8_t **valueOut, uint32_t *valueLenOut,
                      SSFASN1Cursor_t *next)
{
    uint32_t headerLen;
    uint32_t contentLen;
    uint8_t tag;

    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(tagOut != NULL);
    SSF_REQUIRE(valueOut != NULL);
    SSF_REQUIRE(valueLenOut != NULL);
    SSF_REQUIRE(next != NULL);

    headerLen = _SSFASN1ParseTL(cursor->buf, cursor->bufLen, &tag, &contentLen);
    if (headerLen == 0) return false;
    if ((headerLen + contentLen) > cursor->bufLen) return false;

    *tagOut = tag;
    *valueOut = &cursor->buf[headerLen];
    *valueLenOut = contentLen;
    next->buf = &cursor->buf[headerLen + contentLen];
    next->bufLen = cursor->bufLen - headerLen - contentLen;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecOpenConstructed(const SSFASN1Cursor_t *cursor, uint8_t expectedTag,
                               SSFASN1Cursor_t *inner, SSFASN1Cursor_t *next)
{
    uint8_t tag;
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
bool SSFASN1DecPeekTag(const SSFASN1Cursor_t *cursor, uint8_t *tagOut)
{
    SSF_REQUIRE(cursor != NULL);
    SSF_REQUIRE(tagOut != NULL);

    if (cursor->bufLen == 0) return false;
    *tagOut = cursor->buf[0];
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecSkip(const SSFASN1Cursor_t *cursor, SSFASN1Cursor_t *next)
{
    uint8_t tag;
    const uint8_t *value;
    uint32_t valueLen;

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
    uint8_t tag;
    const uint8_t *value;
    uint32_t valueLen;

    SSF_REQUIRE(valOut != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next)) return false;
    if (tag != SSF_ASN1_TAG_BOOLEAN || valueLen != 1u) return false;
    *valOut = (value[0] != 0x00u);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetInt(const SSFASN1Cursor_t *cursor, const uint8_t **intBufOut,
                      uint32_t *intLenOut, SSFASN1Cursor_t *next)
{
    uint8_t tag;

    SSF_REQUIRE(intBufOut != NULL);
    SSF_REQUIRE(intLenOut != NULL);

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

    SSF_REQUIRE(valOut != NULL);

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
    uint8_t tag;
    const uint8_t *value;
    uint32_t valueLen;

    SSF_REQUIRE(bitsOut != NULL);
    SSF_REQUIRE(bitsLenOut != NULL);
    SSF_REQUIRE(unusedBitsOut != NULL);

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
    uint8_t tag;

    SSF_REQUIRE(octetsOut != NULL);
    SSF_REQUIRE(octetsLenOut != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, octetsOut, octetsLenOut, next)) return false;
    if (tag != SSF_ASN1_TAG_OCTET_STRING) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetNull(const SSFASN1Cursor_t *cursor, SSFASN1Cursor_t *next)
{
    uint8_t tag;
    const uint8_t *value;
    uint32_t valueLen;

    if (!SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next)) return false;
    if (tag != SSF_ASN1_TAG_NULL || valueLen != 0u) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetOIDRaw(const SSFASN1Cursor_t *cursor, const uint8_t **oidRawOut,
                         uint32_t *oidRawLenOut, SSFASN1Cursor_t *next)
{
    uint8_t tag;

    SSF_REQUIRE(oidRawOut != NULL);
    SSF_REQUIRE(oidRawLenOut != NULL);

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

    SSF_REQUIRE(oidArcsOut != NULL);
    SSF_REQUIRE(oidArcsLenOut != NULL);

    if (!SSFASN1DecGetOIDRaw(cursor, &raw, &rawLen, next)) return false;
    if (rawLen == 0) return false;

    /* First byte encodes arcs 0 and 1: value = arc0 * 40 + arc1 */
    if (arcCount + 2u > oidArcsSize) return false;
    oidArcsOut[0] = raw[0] / 40u;
    oidArcsOut[1] = raw[0] % 40u;
    arcCount = 2;

    /* Remaining bytes: base-128 encoded arcs */
    pos = 1;
    while (pos < rawLen)
    {
        uint32_t arc = 0;
        do
        {
            if (pos >= rawLen) return false;
            arc = (arc << 7) | (raw[pos] & 0x7Fu);
        } while ((raw[pos++] & 0x80u) != 0);

        if (arcCount >= oidArcsSize) return false;
        oidArcsOut[arcCount++] = arc;
    }

    *oidArcsLenOut = arcCount;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
bool SSFASN1DecGetString(const SSFASN1Cursor_t *cursor, const uint8_t **strOut,
                         uint32_t *strLenOut, uint8_t *strTagOut, SSFASN1Cursor_t *next)
{
    uint8_t tag;

    SSF_REQUIRE(strOut != NULL);
    SSF_REQUIRE(strLenOut != NULL);

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
bool SSFASN1DecGetTime(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut,
                       SSFASN1Cursor_t *next)
{
    uint8_t tag;
    const uint8_t *value;
    uint32_t valueLen;
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t second;
    uint32_t pos;
    /* Days before each month (non-leap year) */
    static const uint16_t daysBeforeMonth[12] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };

    SSF_REQUIRE(unixSecOut != NULL);

    if (!SSFASN1DecGetTLV(cursor, &tag, &value, &valueLen, next)) return false;

    if (tag == SSF_ASN1_TAG_UTC_TIME)
    {
        /* Format: YYMMDDHHMMSSZ (13 bytes) */
        if (valueLen < 13u) return false;
        pos = 0;
        year = (uint32_t)(value[pos] - '0') * 10u + (uint32_t)(value[pos + 1u] - '0');
        pos += 2;
        year += (year >= 50u) ? 1900u : 2000u;
    }
    else if (tag == SSF_ASN1_TAG_GENERALIZED_TIME)
    {
        /* Format: YYYYMMDDHHMMSSZ (15 bytes) */
        if (valueLen < 15u) return false;
        pos = 0;
        year = (uint32_t)(value[pos] - '0') * 1000u + (uint32_t)(value[pos + 1u] - '0') * 100u +
               (uint32_t)(value[pos + 2u] - '0') * 10u + (uint32_t)(value[pos + 3u] - '0');
        pos += 4;
    }
    else
    {
        return false;
    }

    month = (uint32_t)(value[pos] - '0') * 10u + (uint32_t)(value[pos + 1u] - '0');
    pos += 2;
    day = (uint32_t)(value[pos] - '0') * 10u + (uint32_t)(value[pos + 1u] - '0');
    pos += 2;
    hour = (uint32_t)(value[pos] - '0') * 10u + (uint32_t)(value[pos + 1u] - '0');
    pos += 2;
    minute = (uint32_t)(value[pos] - '0') * 10u + (uint32_t)(value[pos + 1u] - '0');
    pos += 2;
    second = (uint32_t)(value[pos] - '0') * 10u + (uint32_t)(value[pos + 1u] - '0');

    /* Convert to Unix seconds */
    {
        uint64_t days = 0;
        uint32_t y;

        /* Days from 1970 to year */
        for (y = 1970u; y < year; y++)
        {
            days += 365u;
            if ((y % 4u == 0u) && ((y % 100u != 0u) || (y % 400u == 0u))) days++;
        }

        /* Days in current year */
        if (month >= 1u && month <= 12u)
        {
            days += daysBeforeMonth[month - 1u];
            /* Leap day */
            if (month > 2u && (year % 4u == 0u) &&
                ((year % 100u != 0u) || (year % 400u == 0u)))
            {
                days++;
            }
        }
        days += (day - 1u);

        *unixSecOut = days * 86400ull + hour * 3600ull + minute * 60ull + second;
    }
    return true;
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
uint32_t SSFASN1EncTagLen(uint8_t *buf, uint32_t bufSize, uint8_t tag, uint32_t contentLen)
{
    uint32_t headerLen = 1u + _SSFASN1LenFieldSize(contentLen);

    if (buf == NULL) return headerLen;
    if (bufSize < headerLen) return 0;

    buf[0] = tag;
    _SSFASN1WriteLenField(&buf[1], contentLen);
    return headerLen;
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncBool(uint8_t *buf, uint32_t bufSize, bool val)
{
    uint32_t total = 3u; /* tag(1) + len(1) + value(1) */

    if (buf == NULL) return total;
    if (bufSize < total) return 0;

    buf[0] = SSF_ASN1_TAG_BOOLEAN;
    buf[1] = 0x01u;
    buf[2] = val ? 0xFFu : 0x00u;
    return total;
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncInt(uint8_t *buf, uint32_t bufSize, const uint8_t *intBuf, uint32_t intLen)
{
    uint32_t headerLen;
    uint32_t total;

    SSF_REQUIRE(intBuf != NULL);
    SSF_REQUIRE(intLen > 0);

    headerLen = 1u + _SSFASN1LenFieldSize(intLen);
    total = headerLen + intLen;

    if (buf == NULL) return total;
    if (bufSize < total) return 0;

    buf[0] = SSF_ASN1_TAG_INTEGER;
    _SSFASN1WriteLenField(&buf[1], intLen);
    memcpy(&buf[headerLen], intBuf, intLen);
    return total;
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncIntU64(uint8_t *buf, uint32_t bufSize, uint64_t val)
{
    uint8_t intBuf[9];
    uint32_t intLen;
    uint32_t i;

    /* Encode as big-endian with minimal length, adding leading zero if high bit set */
    if (val == 0)
    {
        intBuf[0] = 0x00u;
        intLen = 1;
    }
    else
    {
        /* Find the most significant non-zero byte */
        intLen = 0;
        for (i = 0; i < 8u; i++)
        {
            uint8_t b = (uint8_t)(val >> (56u - i * 8u));
            if (b != 0 || intLen > 0)
            {
                intBuf[intLen++] = b;
            }
        }
        /* Add leading zero if high bit is set (positive number would look negative) */
        if (intBuf[0] & 0x80u)
        {
            memmove(&intBuf[1], intBuf, intLen);
            intBuf[0] = 0x00u;
            intLen++;
        }
    }

    return SSFASN1EncInt(buf, bufSize, intBuf, intLen);
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncBitString(uint8_t *buf, uint32_t bufSize, const uint8_t *bits,
                             uint32_t bitsLen, uint8_t unusedBits)
{
    uint32_t contentLen = 1u + bitsLen; /* unused-bits byte + data */
    uint32_t headerLen = 1u + _SSFASN1LenFieldSize(contentLen);
    uint32_t total = headerLen + contentLen;

    if (buf == NULL) return total;
    if (bufSize < total) return 0;

    buf[0] = SSF_ASN1_TAG_BIT_STRING;
    _SSFASN1WriteLenField(&buf[1], contentLen);
    buf[headerLen] = unusedBits;
    if (bitsLen > 0) memcpy(&buf[headerLen + 1u], bits, bitsLen);
    return total;
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncOctetString(uint8_t *buf, uint32_t bufSize, const uint8_t *octets,
                               uint32_t octetsLen)
{
    return SSFASN1EncWrap(buf, bufSize, SSF_ASN1_TAG_OCTET_STRING, octets, octetsLen);
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncNull(uint8_t *buf, uint32_t bufSize)
{
    uint32_t total = 2u;

    if (buf == NULL) return total;
    if (bufSize < total) return 0;

    buf[0] = SSF_ASN1_TAG_NULL;
    buf[1] = 0x00u;
    return total;
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncOIDRaw(uint8_t *buf, uint32_t bufSize, const uint8_t *oidRaw,
                          uint32_t oidRawLen)
{
    return SSFASN1EncWrap(buf, bufSize, SSF_ASN1_TAG_OID, oidRaw, oidRawLen);
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncString(uint8_t *buf, uint32_t bufSize, uint8_t strTag,
                          const uint8_t *str, uint32_t strLen)
{
    return SSFASN1EncWrap(buf, bufSize, strTag, str, strLen);
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncUTCTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec)
{
    /* Format: YYMMDDHHMMSSZ (13 bytes) */
    uint8_t timeStr[13];
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t second;
    uint32_t days;
    static const uint16_t daysInMonth[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    bool isLeap;

    days = (uint32_t)(unixSec / 86400ull);
    second = (uint32_t)(unixSec % 86400ull);
    hour = second / 3600u;
    minute = (second % 3600u) / 60u;
    second = second % 60u;

    /* Year from days since 1970 */
    year = 1970;
    for (;;)
    {
        isLeap = (year % 4u == 0u) && ((year % 100u != 0u) || (year % 400u == 0u));
        uint32_t daysInYear = isLeap ? 366u : 365u;
        if (days < daysInYear) break;
        days -= daysInYear;
        year++;
    }

    /* Month and day */
    isLeap = (year % 4u == 0u) && ((year % 100u != 0u) || (year % 400u == 0u));
    for (month = 0; month < 12u; month++)
    {
        uint32_t dim = daysInMonth[month];
        if (month == 1u && isLeap) dim++;
        if (days < dim) break;
        days -= dim;
    }
    month++;
    day = days + 1u;

    /* Encode YY */
    year %= 100u;
    timeStr[0] = (uint8_t)('0' + year / 10u);
    timeStr[1] = (uint8_t)('0' + year % 10u);
    timeStr[2] = (uint8_t)('0' + month / 10u);
    timeStr[3] = (uint8_t)('0' + month % 10u);
    timeStr[4] = (uint8_t)('0' + day / 10u);
    timeStr[5] = (uint8_t)('0' + day % 10u);
    timeStr[6] = (uint8_t)('0' + hour / 10u);
    timeStr[7] = (uint8_t)('0' + hour % 10u);
    timeStr[8] = (uint8_t)('0' + minute / 10u);
    timeStr[9] = (uint8_t)('0' + minute % 10u);
    timeStr[10] = (uint8_t)('0' + second / 10u);
    timeStr[11] = (uint8_t)('0' + second % 10u);
    timeStr[12] = 'Z';

    return SSFASN1EncWrap(buf, bufSize, SSF_ASN1_TAG_UTC_TIME, timeStr, 13);
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncGeneralizedTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec)
{
    /* Format: YYYYMMDDHHMMSSZ (15 bytes) */
    uint8_t timeStr[15];
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t second;
    uint32_t days;
    static const uint16_t daysInMonth[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    bool isLeap;

    days = (uint32_t)(unixSec / 86400ull);
    second = (uint32_t)(unixSec % 86400ull);
    hour = second / 3600u;
    minute = (second % 3600u) / 60u;
    second = second % 60u;

    year = 1970;
    for (;;)
    {
        isLeap = (year % 4u == 0u) && ((year % 100u != 0u) || (year % 400u == 0u));
        uint32_t daysInYear = isLeap ? 366u : 365u;
        if (days < daysInYear) break;
        days -= daysInYear;
        year++;
    }

    isLeap = (year % 4u == 0u) && ((year % 100u != 0u) || (year % 400u == 0u));
    for (month = 0; month < 12u; month++)
    {
        uint32_t dim = daysInMonth[month];
        if (month == 1u && isLeap) dim++;
        if (days < dim) break;
        days -= dim;
    }
    month++;
    day = days + 1u;

    timeStr[0] = (uint8_t)('0' + year / 1000u);
    timeStr[1] = (uint8_t)('0' + (year / 100u) % 10u);
    timeStr[2] = (uint8_t)('0' + (year / 10u) % 10u);
    timeStr[3] = (uint8_t)('0' + year % 10u);
    timeStr[4] = (uint8_t)('0' + month / 10u);
    timeStr[5] = (uint8_t)('0' + month % 10u);
    timeStr[6] = (uint8_t)('0' + day / 10u);
    timeStr[7] = (uint8_t)('0' + day % 10u);
    timeStr[8] = (uint8_t)('0' + hour / 10u);
    timeStr[9] = (uint8_t)('0' + hour % 10u);
    timeStr[10] = (uint8_t)('0' + minute / 10u);
    timeStr[11] = (uint8_t)('0' + minute % 10u);
    timeStr[12] = (uint8_t)('0' + second / 10u);
    timeStr[13] = (uint8_t)('0' + second % 10u);
    timeStr[14] = 'Z';

    return SSFASN1EncWrap(buf, bufSize, SSF_ASN1_TAG_GENERALIZED_TIME, timeStr, 15);
}

/* --------------------------------------------------------------------------------------------- */
uint32_t SSFASN1EncWrap(uint8_t *buf, uint32_t bufSize, uint8_t tag,
                        const uint8_t *content, uint32_t contentLen)
{
    uint32_t headerLen = 1u + _SSFASN1LenFieldSize(contentLen);
    uint32_t total = headerLen + contentLen;

    if (buf == NULL) return total;
    if (bufSize < total) return 0;

    buf[0] = tag;
    _SSFASN1WriteLenField(&buf[1], contentLen);
    if (contentLen > 0 && content != NULL)
    {
        memcpy(&buf[headerLen], content, contentLen);
    }
    return total;
}
