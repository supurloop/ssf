/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfasn1_ut.c                                                                                  */
/* Provides unit tests for the ssfasn1 ASN.1 DER encode/decode module.                          */
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

#if SSF_CONFIG_ASN1_UNIT_TEST == 1

void SSFASN1UnitTest(void)
{
    uint8_t buf[256];
    SSFASN1Cursor_t cursor;
    SSFASN1Cursor_t next;
    uint32_t len;

    /* ---- BOOLEAN encode/decode ---- */
    {
        bool val;

        SSF_ASSERT(SSFASN1EncBool(buf, sizeof(buf), true, &len) == true);
        SSF_ASSERT(len == 3u);
        SSF_ASSERT(buf[0] == 0x01u && buf[1] == 0x01u && buf[2] == 0xFFu);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetBool(&cursor, &val, &next) == true);
        SSF_ASSERT(val == true);
        SSF_ASSERT(SSFASN1DecIsEmpty(&next) == true);

        SSF_ASSERT(SSFASN1EncBool(buf, sizeof(buf), false, &len) == true);
        SSF_ASSERT(buf[2] == 0x00u);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetBool(&cursor, &val, &next) == true);
        SSF_ASSERT(val == false);
    }

    /* ---- INTEGER encode/decode: small values ---- */
    {
        uint64_t val;

        SSF_ASSERT(SSFASN1EncIntU64(buf, sizeof(buf), 0, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == true);
        SSF_ASSERT(val == 0);

        SSF_ASSERT(SSFASN1EncIntU64(buf, sizeof(buf), 127, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == true);
        SSF_ASSERT(val == 127);

        SSF_ASSERT(SSFASN1EncIntU64(buf, sizeof(buf), 128, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == true);
        SSF_ASSERT(val == 128);
        /* 128 requires leading zero: 02 02 00 80 */
        SSF_ASSERT(buf[0] == 0x02u && buf[1] == 0x02u && buf[2] == 0x00u && buf[3] == 0x80u);

        SSF_ASSERT(SSFASN1EncIntU64(buf, sizeof(buf), 256, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == true);
        SSF_ASSERT(val == 256);
    }

    /* ---- INTEGER: large value ---- */
    {
        uint64_t val;
        SSF_ASSERT(SSFASN1EncIntU64(buf, sizeof(buf), 0xDEADBEEFCAFEull, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == true);
        SSF_ASSERT(val == 0xDEADBEEFCAFEull);
    }

    /* ---- INTEGER: raw bytes ---- */
    {
        static const uint8_t rawInt[] = { 0x00u, 0xFFu, 0x01u };
        const uint8_t *intBuf;
        uint32_t intLen;

        SSF_ASSERT(SSFASN1EncInt(buf, sizeof(buf), rawInt, sizeof(rawInt), &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetInt(&cursor, &intBuf, &intLen, &next) == true);
        SSF_ASSERT(intLen == 3u);
        SSF_ASSERT(memcmp(intBuf, rawInt, 3) == 0);
    }

    /* ---- NULL encode/decode ---- */
    {
        SSF_ASSERT(SSFASN1EncNull(buf, sizeof(buf), &len) == true);
        SSF_ASSERT(len == 2u);
        SSF_ASSERT(buf[0] == 0x05u && buf[1] == 0x00u);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetNull(&cursor, &next) == true);
    }

    /* ---- BIT STRING encode/decode ---- */
    {
        static const uint8_t bits[] = { 0xFFu, 0x80u };
        const uint8_t *bitsOut;
        uint32_t bitsLenOut;
        uint8_t unusedBits;

        SSF_ASSERT(SSFASN1EncBitString(buf, sizeof(buf), bits, sizeof(bits), 1, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetBitString(&cursor, &bitsOut, &bitsLenOut, &unusedBits,
                   &next) == true);
        SSF_ASSERT(bitsLenOut == 2u);
        SSF_ASSERT(unusedBits == 1u);
        SSF_ASSERT(bitsOut[0] == 0xFFu && bitsOut[1] == 0x80u);
    }

    /* ---- OCTET STRING encode/decode ---- */
    {
        static const uint8_t data[] = { 0xDEu, 0xADu, 0xBEu, 0xEFu };
        const uint8_t *octets;
        uint32_t octetsLen;

        SSF_ASSERT(SSFASN1EncOctetString(buf, sizeof(buf), data, sizeof(data), &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetOctetString(&cursor, &octets, &octetsLen, &next) == true);
        SSF_ASSERT(octetsLen == 4u);
        SSF_ASSERT(memcmp(octets, data, 4) == 0);
    }

    /* ---- OID encode/decode: 2.5.4.3 (id-at-commonName) ---- */
    {
        static const uint8_t oidRaw[] = { 0x55u, 0x04u, 0x03u };
        const uint8_t *rawOut;
        uint32_t rawLenOut;
        uint32_t arcs[SSF_ASN1_CONFIG_MAX_OID_ARCS];
        uint8_t arcsLen;

        SSF_ASSERT(SSFASN1EncOIDRaw(buf, sizeof(buf), oidRaw, sizeof(oidRaw), &len) == true);
        cursor.buf = buf; cursor.bufLen = len;

        /* Raw decode */
        SSF_ASSERT(SSFASN1DecGetOIDRaw(&cursor, &rawOut, &rawLenOut, &next) == true);
        SSF_ASSERT(rawLenOut == 3u);
        SSF_ASSERT(memcmp(rawOut, oidRaw, 3) == 0);

        /* Arc decode */
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetOID(&cursor, arcs, SSF_ASN1_CONFIG_MAX_OID_ARCS, &arcsLen,
                   &next) == true);
        /* 0x55 = 2*40+5 → arcs 2,5; 0x04 → arc 4; 0x03 → arc 3 = OID 2.5.4.3 */
        SSF_ASSERT(arcsLen == 4u);
        SSF_ASSERT(arcs[0] == 2u && arcs[1] == 5u && arcs[2] == 4u && arcs[3] == 3u);
    }

    /* ---- OID: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption) with multi-byte arcs ---- */
    {
        static const uint8_t oidRaw[] = {
            0x2Au, 0x86u, 0x48u, 0x86u, 0xF7u, 0x0Du, 0x01u, 0x01u, 0x0Bu
        };
        uint32_t arcs[SSF_ASN1_CONFIG_MAX_OID_ARCS];
        uint8_t arcsLen;

        SSF_ASSERT(SSFASN1EncOIDRaw(buf, sizeof(buf), oidRaw, sizeof(oidRaw), &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetOID(&cursor, arcs, SSF_ASN1_CONFIG_MAX_OID_ARCS, &arcsLen,
                   &next) == true);
        SSF_ASSERT(arcsLen == 7u);
        SSF_ASSERT(arcs[0] == 1u);
        SSF_ASSERT(arcs[1] == 2u);
        SSF_ASSERT(arcs[2] == 840u);
        SSF_ASSERT(arcs[3] == 113549u);
        SSF_ASSERT(arcs[4] == 1u);
        SSF_ASSERT(arcs[5] == 1u);
        SSF_ASSERT(arcs[6] == 11u);
    }

    /* ---- PrintableString encode/decode ---- */
    {
        const uint8_t *strOut;
        uint32_t strLenOut;
        uint16_t strTag;

        SSF_ASSERT(SSFASN1EncString(buf, sizeof(buf), SSF_ASN1_TAG_PRINTABLE_STRING,
                                    (const uint8_t *)"US", 2, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetString(&cursor, &strOut, &strLenOut, &strTag, &next) == true);
        SSF_ASSERT(strLenOut == 2u);
        SSF_ASSERT(strTag == SSF_ASN1_TAG_PRINTABLE_STRING);
        SSF_ASSERT(memcmp(strOut, "US", 2) == 0);
    }

    /* ---- UTCTime encode/decode round-trip ---- */
    {
        /* 2024-06-15 12:00:00 UTC = Unix 1718452800 */
        uint64_t unixSec = 1718452800ull;
        uint64_t decoded;

        SSF_ASSERT(SSFASN1EncUTCTime(buf, sizeof(buf), unixSec, &len) == true);
        SSF_ASSERT(len > 0);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == unixSec);
    }

    /* ---- GeneralizedTime encode/decode round-trip ---- */
    {
        uint64_t unixSec = 1718452800ull;
        uint64_t decoded;

        SSF_ASSERT(SSFASN1EncGeneralizedTime(buf, sizeof(buf), unixSec, &len) == true);
        SSF_ASSERT(len > 0);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == unixSec);
    }

    /* ---- SEQUENCE: encode nested, decode with OpenConstructed ---- */
    {
        uint8_t inner[32];
        uint32_t innerLen = 0;
        uint32_t n;
        SSFASN1Cursor_t seqInner;
        uint64_t val;
        bool bval;

        /* Build inner content: INTEGER(42) + BOOLEAN(true) */
        SSF_ASSERT(SSFASN1EncIntU64(&inner[innerLen], sizeof(inner) - innerLen, 42, &n));
        innerLen += n;
        SSF_ASSERT(SSFASN1EncBool(&inner[innerLen], sizeof(inner) - innerLen, true, &n));
        innerLen += n;

        /* Wrap in SEQUENCE */
        SSF_ASSERT(SSFASN1EncWrap(buf, sizeof(buf), SSF_ASN1_TAG_SEQUENCE, inner, innerLen,
                                  &len) == true);
        SSF_ASSERT(len > 0);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &seqInner,
                   &next) == true);
        SSF_ASSERT(SSFASN1DecIsEmpty(&next) == true);

        SSF_ASSERT(SSFASN1DecGetIntU64(&seqInner, &val, &seqInner) == true);
        SSF_ASSERT(val == 42u);
        SSF_ASSERT(SSFASN1DecGetBool(&seqInner, &bval, &seqInner) == true);
        SSF_ASSERT(bval == true);
        SSF_ASSERT(SSFASN1DecIsEmpty(&seqInner) == true);
    }

    /* ---- Context-specific explicit tag [0] ---- */
    {
        uint8_t inner[16];
        uint32_t innerLen;
        SSFASN1Cursor_t tagInner;
        uint64_t val;

        SSF_ASSERT(SSFASN1EncIntU64(inner, sizeof(inner), 2, &innerLen) == true);
        SSF_ASSERT(SSFASN1EncWrap(buf, sizeof(buf), SSF_ASN1_CONTEXT_EXPLICIT(0), inner,
                                  innerLen, &len) == true);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_CONTEXT_EXPLICIT(0),
                   &tagInner, &next) == true);
        SSF_ASSERT(SSFASN1DecGetIntU64(&tagInner, &val, &tagInner) == true);
        SSF_ASSERT(val == 2u);
    }

    /* ---- PeekTag and Skip ---- */
    {
        uint32_t pos = 0;
        uint32_t n;
        uint16_t tag;

        SSF_ASSERT(SSFASN1EncIntU64(&buf[pos], sizeof(buf) - pos, 10, &n));
        pos += n;
        SSF_ASSERT(SSFASN1EncBool(&buf[pos], sizeof(buf) - pos, false, &n));
        pos += n;
        SSF_ASSERT(SSFASN1EncNull(&buf[pos], sizeof(buf) - pos, &n));
        pos += n;

        cursor.buf = buf; cursor.bufLen = pos;

        SSF_ASSERT(SSFASN1DecPeekTag(&cursor, &tag) == true);
        SSF_ASSERT(tag == SSF_ASN1_TAG_INTEGER);

        SSF_ASSERT(SSFASN1DecSkip(&cursor, &next) == true);
        SSF_ASSERT(SSFASN1DecPeekTag(&next, &tag) == true);
        SSF_ASSERT(tag == SSF_ASN1_TAG_BOOLEAN);

        SSF_ASSERT(SSFASN1DecSkip(&next, &next) == true);
        SSF_ASSERT(SSFASN1DecPeekTag(&next, &tag) == true);
        SSF_ASSERT(tag == SSF_ASN1_TAG_NULL);

        SSF_ASSERT(SSFASN1DecSkip(&next, &next) == true);
        SSF_ASSERT(SSFASN1DecIsEmpty(&next) == true);
    }

    /* ---- Two-pass encode: measure then write ---- */
    {
        uint32_t needed;
        uint32_t written;

        SSF_ASSERT(SSFASN1EncIntU64(NULL, 0, 999, &needed) == true);
        SSF_ASSERT(needed > 0);
        SSF_ASSERT(SSFASN1EncIntU64(buf, sizeof(buf), 999, &written) == true);
        SSF_ASSERT(written == needed);
    }

    /* ---- Incomplete/truncated TLV decode fails ---- */
    {
        uint8_t trunc[] = { 0x02u, 0x05u, 0x01u }; /* INTEGER length 5 but only 1 data byte */
        cursor.buf = trunc; cursor.bufLen = sizeof(trunc);
        uint64_t val;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == false);
    }

    /* ---- Wrong tag type fails ---- */
    {
        uint64_t val;
        SSF_ASSERT(SSFASN1EncBool(buf, sizeof(buf), true, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == false);
    }

    /* ---- Long-form length: 128+ bytes ---- */
    {
        uint8_t longData[200];
        const uint8_t *octets;
        uint32_t octetsLen;

        memset(longData, 0xABu, sizeof(longData));
        SSF_ASSERT(SSFASN1EncOctetString(buf, sizeof(buf), longData, 200, &len) == true);
        SSF_ASSERT(len > 0);
        /* Length should use long form (0x81 0xC8) */
        SSF_ASSERT(buf[1] == 0x81u);
        SSF_ASSERT(buf[2] == 200u);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetOctetString(&cursor, &octets, &octetsLen, &next) == true);
        SSF_ASSERT(octetsLen == 200u);
        SSF_ASSERT(octets[0] == 0xABu && octets[199] == 0xABu);
    }

    /* ====================================================================================== */
    /* Hardening regression tests                                                               */
    /* ====================================================================================== */

    /* ---- Fix #1: integer-overflow in TLV bounds check ---- */
    /* Craft a TLV whose advertised content length plus header wraps uint32_t. A bounds check  */
    /* using "headerLen + contentLen > bufLen" wraps and accepts the malformed TLV, causing    */
    /* out-of-bounds reads downstream.                                                          */
    {
        uint8_t trunc[6];
        const uint8_t *val;
        uint32_t valLen;
        uint16_t tag;

        trunc[0] = SSF_ASN1_TAG_OCTET_STRING;
        trunc[1] = 0x84u;         /* Long form, 4 length bytes follow */
        trunc[2] = 0xFFu;         /* contentLen = 0xFFFFFFFA */
        trunc[3] = 0xFFu;
        trunc[4] = 0xFFu;
        trunc[5] = 0xFAu;
        cursor.buf = trunc; cursor.bufLen = sizeof(trunc);
        SSF_ASSERT(SSFASN1DecGetTLV(&cursor, &tag, &val, &valLen, &next) == false);
    }

    /* ---- Fix #2a: OID arc0=2, arc1>=40 split correctly ---- */
    /* OID 2.100.3 encodes as 0x81 0x34 0x03 (first sub-id 180 → arc0=2, arc1=100).             */
    {
        static const uint8_t oidRaw[] = { 0x81u, 0x34u, 0x03u };
        uint32_t arcs[SSF_ASN1_CONFIG_MAX_OID_ARCS];
        uint8_t arcsLen;

        SSF_ASSERT(SSFASN1EncOIDRaw(buf, sizeof(buf), oidRaw, sizeof(oidRaw), &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetOID(&cursor, arcs, SSF_ASN1_CONFIG_MAX_OID_ARCS, &arcsLen,
                   &next) == true);
        SSF_ASSERT(arcsLen == 3u);
        SSF_ASSERT(arcs[0] == 2u);
        SSF_ASSERT(arcs[1] == 100u);
        SSF_ASSERT(arcs[2] == 3u);
    }

    /* ---- Fix #2b: OID first-byte >= 80 maps arc0=2 (not arc0=3) ---- */
    /* Single-byte first sub-id of 0x82 = 130 → arc0=2, arc1=50 per X.690 §8.19.4.              */
    {
        static const uint8_t oidRaw[] = { 0x82u, 0x01u }; /* Invalid continuation -> reject */
        uint32_t arcs[SSF_ASN1_CONFIG_MAX_OID_ARCS];
        uint8_t arcsLen;
        /* 0x82 has continuation bit set; to form first sub-id = 130 correctly needs 0x81 0x02 */
        static const uint8_t oidRaw2[] = { 0x81u, 0x02u, 0x05u }; /* first=130, arc3=5 */

        /* 0x82 0x01 is a valid 2-byte first sub-id = (2 << 7) | 1 = 257 */
        SSF_ASSERT(SSFASN1EncOIDRaw(buf, sizeof(buf), oidRaw, sizeof(oidRaw), &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetOID(&cursor, arcs, SSF_ASN1_CONFIG_MAX_OID_ARCS, &arcsLen,
                   &next) == true);
        /* 257 - 80 = 177 → arc0=2, arc1=177 */
        SSF_ASSERT(arcsLen == 2u);
        SSF_ASSERT(arcs[0] == 2u);
        SSF_ASSERT(arcs[1] == 177u);

        SSF_ASSERT(SSFASN1EncOIDRaw(buf, sizeof(buf), oidRaw2, sizeof(oidRaw2), &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetOID(&cursor, arcs, SSF_ASN1_CONFIG_MAX_OID_ARCS, &arcsLen,
                   &next) == true);
        /* (1<<7)|2 = 130; 130 - 80 = 50 → arc0=2, arc1=50, arc2=5 */
        SSF_ASSERT(arcsLen == 3u);
        SSF_ASSERT(arcs[0] == 2u);
        SSF_ASSERT(arcs[1] == 50u);
        SSF_ASSERT(arcs[2] == 5u);
    }

    /* ---- Fix #2c: OID non-canonical leading 0x80 rejected ---- */
    {
        static const uint8_t oidRaw[] = { 0x80u, 0x01u }; /* Leading 0x80 on first sub-id */
        uint32_t arcs[SSF_ASN1_CONFIG_MAX_OID_ARCS];
        uint8_t arcsLen;

        SSF_ASSERT(SSFASN1EncOIDRaw(buf, sizeof(buf), oidRaw, sizeof(oidRaw), &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetOID(&cursor, arcs, SSF_ASN1_CONFIG_MAX_OID_ARCS, &arcsLen,
                   &next) == false);
    }

    /* ---- Fix #3a: time with non-digit character rejected ---- */
    {
        /* UTCTime with 'A' in the year field */
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Du,
            'A','4','0','6','1','5','1','2','0','0','0','0','Z'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Fix #3b: time missing 'Z' terminator rejected ---- */
    {
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Du,
            '2','4','0','6','1','5','1','2','0','0','0','0','X'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Fix #3c: time wrong length rejected ---- */
    {
        /* UTCTime of 14 bytes (one extra) */
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Eu,
            '2','4','0','6','1','5','1','2','0','0','0','0','Z','X'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Fix #3d: month out of range rejected ---- */
    {
        /* Month = 13 */
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Du,
            '2','4','1','3','1','5','1','2','0','0','0','0','Z'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Fix #3e: day out of range for month rejected ---- */
    {
        /* Feb 30 */
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Du,
            '2','4','0','2','3','0','1','2','0','0','0','0','Z'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Fix #3f: hour out of range rejected ---- */
    {
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Du,
            '2','4','0','6','1','5','2','4','0','0','0','0','Z'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Fix #3g: leap second (60) rejected per DER X.509 profile ---- */
    {
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Du,
            '2','4','0','6','1','5','1','2','0','0','6','0','Z'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Fix #3h: leap-year Feb 29 accepted ---- */
    {
        /* 2024-02-29 00:00:00 UTC = Unix 1709164800 */
        static const uint8_t good[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Du,
            '2','4','0','2','2','9','0','0','0','0','0','0','Z'
        };
        uint64_t decoded;
        cursor.buf = good; cursor.bufLen = sizeof(good);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == 1709164800ull);
    }

    /* ---- Fix #3i: non-leap-year Feb 29 rejected ---- */
    {
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Du,
            '2','3','0','2','2','9','0','0','0','0','0','0','Z'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Time range #1: UTCTime 1970-01-01 (YY=70) accepted as Unix 0 ---- */
    {
        static const uint8_t good[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Du,
            '7','0','0','1','0','1','0','0','0','0','0','0','Z'
        };
        uint64_t decoded;
        cursor.buf = good; cursor.bufLen = sizeof(good);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == 0ull);
    }

    /* ---- Time range #2: UTCTime YY=69 (1969) rejected — ssfdtime range starts at 1970 ---- */
    {
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_UTC_TIME, 0x0Du,
            '6','9','0','1','0','1','0','0','0','0','0','0','Z'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Time range #3: GeneralizedTime 2199-12-31 23:59:59 accepted (upper bound) ---- */
    {
        static const uint8_t good[] = {
            SSF_ASN1_TAG_GENERALIZED_TIME, 0x0Fu,
            '2','1','9','9','1','2','3','1','2','3','5','9','5','9','Z'
        };
        uint64_t decoded;
        cursor.buf = good; cursor.bufLen = sizeof(good);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == 7258118399ull); /* 2199-12-31T23:59:59Z */
    }

    /* ---- Time range #4: GeneralizedTime 2200-01-01 rejected (above ssfdtime range) ---- */
    {
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_GENERALIZED_TIME, 0x0Fu,
            '2','2','0','0','0','1','0','1','0','0','0','0','0','0','Z'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Time range #5: GeneralizedTime 1969 rejected ---- */
    {
        static const uint8_t bad[] = {
            SSF_ASN1_TAG_GENERALIZED_TIME, 0x0Fu,
            '1','9','6','9','1','2','3','1','2','3','5','9','5','9','Z'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == false);
    }

    /* ---- Time range #6: encode UTCTime for year 2050 must fail (UTCTime ambiguous) ---- */
    /* Unix 2524608000 = 2050-01-01T00:00:00Z. UTCTime would encode YY=50 which decodes as      */
    /* 1950 per RFC 5280, silently corrupting the value. Encoder must refuse.                   */
    {
        uint32_t r;
        SSF_ASSERT(SSFASN1EncUTCTime(buf, sizeof(buf), 2524608000ull, &r) == false);
        SSF_ASSERT(r == 0u);
    }

    /* ---- Time range #7: encode GeneralizedTime above 2199 must fail ---- */
    {
        uint32_t r;
        SSF_ASSERT(SSFASN1EncGeneralizedTime(buf, sizeof(buf), 7258118400ull, &r) == false);
        SSF_ASSERT(r == 0u);
    }

    /* ---- Time range #8: round-trip GeneralizedTime at upper bound ---- */
    {
        uint64_t decoded;
        SSF_ASSERT(SSFASN1EncGeneralizedTime(buf, sizeof(buf), 7258118399ull, &len) == true);
        SSF_ASSERT(len > 0);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == 7258118399ull);
    }

    /* ---- Fix #5a: encoder rejects contentLen that would overflow total ---- */
    {
        static const uint8_t stub[1] = { 0x00u };
        uint32_t r;
        SSF_ASSERT(SSFASN1EncWrap(buf, sizeof(buf), SSF_ASN1_TAG_OCTET_STRING, stub,
                                  0xFFFFFFFEu, &r) == false);
        SSF_ASSERT(r == 0u);
    }

    /* ---- Fix #5b: SSFASN1EncBitString rejects UINT32_MAX bitsLen ---- */
    {
        static const uint8_t stub[1] = { 0x00u };
        uint32_t r;
        SSF_ASSERT(SSFASN1EncBitString(buf, sizeof(buf), stub, 0xFFFFFFFFu, 0u, &r) == false);
        SSF_ASSERT(r == 0u);
    }

    /* ---- Fix #5c: SSFASN1EncInt rejects intLen that would overflow total ---- */
    {
        static const uint8_t stub[1] = { 0x00u };
        uint32_t r;
        SSF_ASSERT(SSFASN1EncInt(buf, sizeof(buf), stub, 0xFFFFFFEu, &r) == false);
        SSF_ASSERT(r == 0u);
    }

    /* ====================================================================================== */
    /* Bool-return API conformance tests                                                        */
    /* ====================================================================================== */

    /* ---- API #1: measure mode (buf == NULL) returns true and reports required size ---- */
    {
        uint32_t needed = 0xDEADBEEFu;
        SSF_ASSERT(SSFASN1EncNull(NULL, 0, &needed) == true);
        SSF_ASSERT(needed == 2u);

        needed = 0xDEADBEEFu;
        SSF_ASSERT(SSFASN1EncBool(NULL, 0, true, &needed) == true);
        SSF_ASSERT(needed == 3u);

        needed = 0xDEADBEEFu;
        SSF_ASSERT(SSFASN1EncIntU64(NULL, 0, 999u, &needed) == true);
        SSF_ASSERT(needed == 4u); /* tag(1) + len(1) + 02 E7 */
    }

    /* ---- API #2: happy path returns true with bytesWritten == actual encoding length ---- */
    {
        uint32_t written = 0;
        SSF_ASSERT(SSFASN1EncNull(buf, sizeof(buf), &written) == true);
        SSF_ASSERT(written == 2u);
        SSF_ASSERT(buf[0] == 0x05u && buf[1] == 0x00u);

        written = 0;
        SSF_ASSERT(SSFASN1EncBool(buf, sizeof(buf), true, &written) == true);
        SSF_ASSERT(written == 3u);
        SSF_ASSERT(buf[0] == 0x01u && buf[1] == 0x01u && buf[2] == 0xFFu);
    }

    /* ---- API #3: buffer too small returns false and sets bytesWritten = 0 ---- */
    {
        uint32_t written = 0xBADu;
        SSF_ASSERT(SSFASN1EncNull(buf, 1u, &written) == false);
        SSF_ASSERT(written == 0u);

        written = 0xBADu;
        SSF_ASSERT(SSFASN1EncBool(buf, 2u, true, &written) == false);
        SSF_ASSERT(written == 0u);
    }

    /* ---- API #4: invalid/overflow input returns false ---- */
    {
        static const uint8_t stub[1] = { 0x00u };
        uint32_t written = 0xBADu;
        SSF_ASSERT(SSFASN1EncWrap(buf, sizeof(buf), SSF_ASN1_TAG_OCTET_STRING,
                                  stub, 0xFFFFFFFEu, &written) == false);
        SSF_ASSERT(written == 0u);
    }

    /* ---- API #5: measure mode matches actual-encode size across all encoders ---- */
    {
        static const uint8_t stub[4] = { 0xDEu, 0xADu, 0xBEu, 0xEFu };
        uint32_t needed;
        uint32_t written;

        SSF_ASSERT(SSFASN1EncOctetString(NULL, 0, stub, sizeof(stub), &needed) == true);
        SSF_ASSERT(SSFASN1EncOctetString(buf, sizeof(buf), stub, sizeof(stub), &written)
                   == true);
        SSF_ASSERT(needed == written);

        SSF_ASSERT(SSFASN1EncBitString(NULL, 0, stub, sizeof(stub), 0u, &needed) == true);
        SSF_ASSERT(SSFASN1EncBitString(buf, sizeof(buf), stub, sizeof(stub), 0u, &written)
                   == true);
        SSF_ASSERT(needed == written);

        SSF_ASSERT(SSFASN1EncOIDRaw(NULL, 0, stub, sizeof(stub), &needed) == true);
        SSF_ASSERT(SSFASN1EncOIDRaw(buf, sizeof(buf), stub, sizeof(stub), &written) == true);
        SSF_ASSERT(needed == written);

        SSF_ASSERT(SSFASN1EncString(NULL, 0, SSF_ASN1_TAG_PRINTABLE_STRING, stub, sizeof(stub),
                                    &needed) == true);
        SSF_ASSERT(SSFASN1EncString(buf, sizeof(buf), SSF_ASN1_TAG_PRINTABLE_STRING, stub,
                                    sizeof(stub), &written) == true);
        SSF_ASSERT(needed == written);

        SSF_ASSERT(SSFASN1EncWrap(NULL, 0, SSF_ASN1_TAG_SEQUENCE, stub, sizeof(stub),
                                  &needed) == true);
        SSF_ASSERT(SSFASN1EncWrap(buf, sizeof(buf), SSF_ASN1_TAG_SEQUENCE, stub, sizeof(stub),
                                  &written) == true);
        SSF_ASSERT(needed == written);

        SSF_ASSERT(SSFASN1EncTagLen(NULL, 0, SSF_ASN1_TAG_SEQUENCE, 100u, &needed) == true);
        SSF_ASSERT(SSFASN1EncTagLen(buf, sizeof(buf), SSF_ASN1_TAG_SEQUENCE, 100u, &written)
                   == true);
        SSF_ASSERT(needed == written);

        SSF_ASSERT(SSFASN1EncUTCTime(NULL, 0, 1718452800ull, &needed) == true);
        SSF_ASSERT(SSFASN1EncUTCTime(buf, sizeof(buf), 1718452800ull, &written) == true);
        SSF_ASSERT(needed == written);

        SSF_ASSERT(SSFASN1EncGeneralizedTime(NULL, 0, 1718452800ull, &needed) == true);
        SSF_ASSERT(SSFASN1EncGeneralizedTime(buf, sizeof(buf), 1718452800ull, &written)
                   == true);
        SSF_ASSERT(needed == written);
    }

    /* ====================================================================================== */
    /* DATE (tag 31) and DATE-TIME (tag 33) multi-byte-tag tests                               */
    /* ====================================================================================== */

    /* ---- DATE #1: round-trip 2024-06-15 (midnight-aligned Unix 1718409600) ---- */
    {
        uint64_t unixSec = 1718409600ull; /* 2024-06-15 00:00:00 UTC */
        uint64_t decoded;

        SSF_ASSERT(SSFASN1EncDate(buf, sizeof(buf), unixSec, &len) == true);
        /* DER: tag 0x1F 0x1F (2), length 0x0A (1), "2024-06-15" (10) = 13 bytes */
        SSF_ASSERT(len == 13u);
        SSF_ASSERT(buf[0] == 0x1Fu && buf[1] == 0x1Fu);
        SSF_ASSERT(buf[2] == 0x0Au);
        SSF_ASSERT(memcmp(&buf[3], "2024-06-15", 10) == 0);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetDate(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == unixSec);
        SSF_ASSERT(SSFASN1DecIsEmpty(&next) == true);
    }

    /* ---- DATE #2: encoder truncates sub-day resolution to midnight of the given day ---- */
    {
        uint64_t unixSec = 1718452800ull; /* 2024-06-15 12:00:00 UTC -> still 2024-06-15 */
        uint64_t decoded;

        SSF_ASSERT(SSFASN1EncDate(buf, sizeof(buf), unixSec, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetDate(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == 1718409600ull); /* Midnight of 2024-06-15 */
    }

    /* ---- DATE #3: leap-year Feb 29 round-trip ---- */
    {
        uint64_t unixSec = 1709164800ull; /* 2024-02-29 00:00:00 UTC */
        uint64_t decoded;

        SSF_ASSERT(SSFASN1EncDate(buf, sizeof(buf), unixSec, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetDate(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == unixSec);
    }

    /* ---- DATE #4: non-leap Feb 29 rejected on decode ---- */
    {
        /* Hand-craft: tag 0x1F 0x1F, len 0x0A, "2023-02-29" */
        static const uint8_t bad[] = {
            0x1Fu, 0x1Fu, 0x0Au,
            '2','0','2','3','-','0','2','-','2','9'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetDate(&cursor, &decoded, &next) == false);
    }

    /* ---- DATE #5: wrong content length rejected ---- */
    {
        /* "2024-06-1" (9 chars, short by one) */
        static const uint8_t bad[] = {
            0x1Fu, 0x1Fu, 0x09u,
            '2','0','2','4','-','0','6','-','1'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetDate(&cursor, &decoded, &next) == false);
    }

    /* ---- DATE #6: missing dash separator rejected ---- */
    {
        static const uint8_t bad[] = {
            0x1Fu, 0x1Fu, 0x0Au,
            '2','0','2','4','/','0','6','-','1','5'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetDate(&cursor, &decoded, &next) == false);
    }

    /* ---- DATE-TIME #1: round-trip 2024-06-15T12:00:00 (Unix 1718452800) ---- */
    {
        uint64_t unixSec = 1718452800ull;
        uint64_t decoded;

        SSF_ASSERT(SSFASN1EncDateTime(buf, sizeof(buf), unixSec, &len) == true);
        /* DER: tag 0x1F 0x21, length 0x13 (19), then "2024-06-15T12:00:00" */
        SSF_ASSERT(len == 22u);
        SSF_ASSERT(buf[0] == 0x1Fu && buf[1] == 0x21u);
        SSF_ASSERT(buf[2] == 0x13u);
        SSF_ASSERT(memcmp(&buf[3], "2024-06-15T12:00:00", 19) == 0);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetDateTime(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == unixSec);
    }

    /* ---- DATE-TIME #2: wrong 'T' separator rejected ---- */
    {
        static const uint8_t bad[] = {
            0x1Fu, 0x21u, 0x13u,
            '2','0','2','4','-','0','6','-','1','5',' ','1','2',':','0','0',':','0','0'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetDateTime(&cursor, &decoded, &next) == false);
    }

    /* ---- DATE-TIME #3: invalid hour rejected ---- */
    {
        static const uint8_t bad[] = {
            0x1Fu, 0x21u, 0x13u,
            '2','0','2','4','-','0','6','-','1','5','T','2','4',':','0','0',':','0','0'
        };
        uint64_t decoded;
        cursor.buf = bad; cursor.bufLen = sizeof(bad);
        SSF_ASSERT(SSFASN1DecGetDateTime(&cursor, &decoded, &next) == false);
    }

    /* ---- DATE-TIME #4: DATE decoder rejects DATE-TIME tag and vice versa ---- */
    {
        uint64_t unixSec = 1718452800ull;
        uint64_t decoded;

        SSF_ASSERT(SSFASN1EncDate(buf, sizeof(buf), unixSec, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetDateTime(&cursor, &decoded, &next) == false);

        SSF_ASSERT(SSFASN1EncDateTime(buf, sizeof(buf), unixSec, &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetDate(&cursor, &decoded, &next) == false);
    }

    /* ---- Generic TLV: Skip must walk past a DATE embedded in a SEQUENCE ---- */
    {
        uint8_t inner[32];
        uint32_t innerLen = 0;
        uint32_t n;
        SSFASN1Cursor_t seqInner;
        bool bval;
        uint64_t decoded;

        /* Build SEQUENCE { DATE 2024-06-15, BOOLEAN true } */
        SSF_ASSERT(SSFASN1EncDate(&inner[innerLen], sizeof(inner) - innerLen, 1718409600ull,
                                  &n) == true);
        innerLen += n;
        SSF_ASSERT(SSFASN1EncBool(&inner[innerLen], sizeof(inner) - innerLen, true, &n)
                   == true);
        innerLen += n;

        SSF_ASSERT(SSFASN1EncWrap(buf, sizeof(buf), SSF_ASN1_TAG_SEQUENCE, inner, innerLen,
                                  &len) == true);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &seqInner,
                   &next) == true);

        /* Walk past the DATE via generic Skip. This proves the TLV parser now handles the    */
        /* 2-byte high-tag-number form.                                                       */
        SSF_ASSERT(SSFASN1DecSkip(&seqInner, &seqInner) == true);
        SSF_ASSERT(SSFASN1DecGetBool(&seqInner, &bval, &seqInner) == true);
        SSF_ASSERT(bval == true);
        SSF_ASSERT(SSFASN1DecIsEmpty(&seqInner) == true);

        /* Also verify PeekTag returns the multi-byte tag value correctly. */
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &seqInner,
                   &next) == true);
        {
            uint16_t peeked;
            SSF_ASSERT(SSFASN1DecPeekTag(&seqInner, &peeked) == true);
            SSF_ASSERT(peeked == SSF_ASN1_TAG_DATE);
        }

        /* And decode the DATE normally from inside the sequence. */
        SSF_ASSERT(SSFASN1DecGetDate(&seqInner, &decoded, &seqInner) == true);
        SSF_ASSERT(decoded == 1718409600ull);
    }
}
#endif /* SSF_CONFIG_ASN1_UNIT_TEST */
