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

        len = SSFASN1EncBool(buf, sizeof(buf), true);
        SSF_ASSERT(len == 3u);
        SSF_ASSERT(buf[0] == 0x01u && buf[1] == 0x01u && buf[2] == 0xFFu);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetBool(&cursor, &val, &next) == true);
        SSF_ASSERT(val == true);
        SSF_ASSERT(SSFASN1DecIsEmpty(&next) == true);

        len = SSFASN1EncBool(buf, sizeof(buf), false);
        SSF_ASSERT(buf[2] == 0x00u);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetBool(&cursor, &val, &next) == true);
        SSF_ASSERT(val == false);
    }

    /* ---- INTEGER encode/decode: small values ---- */
    {
        uint64_t val;

        len = SSFASN1EncIntU64(buf, sizeof(buf), 0);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == true);
        SSF_ASSERT(val == 0);

        len = SSFASN1EncIntU64(buf, sizeof(buf), 127);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == true);
        SSF_ASSERT(val == 127);

        len = SSFASN1EncIntU64(buf, sizeof(buf), 128);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == true);
        SSF_ASSERT(val == 128);
        /* 128 requires leading zero: 02 02 00 80 */
        SSF_ASSERT(buf[0] == 0x02u && buf[1] == 0x02u && buf[2] == 0x00u && buf[3] == 0x80u);

        len = SSFASN1EncIntU64(buf, sizeof(buf), 256);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == true);
        SSF_ASSERT(val == 256);
    }

    /* ---- INTEGER: large value ---- */
    {
        uint64_t val;
        len = SSFASN1EncIntU64(buf, sizeof(buf), 0xDEADBEEFCAFEull);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == true);
        SSF_ASSERT(val == 0xDEADBEEFCAFEull);
    }

    /* ---- INTEGER: raw bytes ---- */
    {
        static const uint8_t rawInt[] = { 0x00u, 0xFFu, 0x01u };
        const uint8_t *intBuf;
        uint32_t intLen;

        len = SSFASN1EncInt(buf, sizeof(buf), rawInt, sizeof(rawInt));
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetInt(&cursor, &intBuf, &intLen, &next) == true);
        SSF_ASSERT(intLen == 3u);
        SSF_ASSERT(memcmp(intBuf, rawInt, 3) == 0);
    }

    /* ---- NULL encode/decode ---- */
    {
        len = SSFASN1EncNull(buf, sizeof(buf));
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

        len = SSFASN1EncBitString(buf, sizeof(buf), bits, sizeof(bits), 1);
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

        len = SSFASN1EncOctetString(buf, sizeof(buf), data, sizeof(data));
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

        len = SSFASN1EncOIDRaw(buf, sizeof(buf), oidRaw, sizeof(oidRaw));
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

        len = SSFASN1EncOIDRaw(buf, sizeof(buf), oidRaw, sizeof(oidRaw));
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
        uint8_t strTag;

        len = SSFASN1EncString(buf, sizeof(buf), SSF_ASN1_TAG_PRINTABLE_STRING,
                               (const uint8_t *)"US", 2);
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

        len = SSFASN1EncUTCTime(buf, sizeof(buf), unixSec);
        SSF_ASSERT(len > 0);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == unixSec);
    }

    /* ---- GeneralizedTime encode/decode round-trip ---- */
    {
        uint64_t unixSec = 1718452800ull;
        uint64_t decoded;

        len = SSFASN1EncGeneralizedTime(buf, sizeof(buf), unixSec);
        SSF_ASSERT(len > 0);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetTime(&cursor, &decoded, &next) == true);
        SSF_ASSERT(decoded == unixSec);
    }

    /* ---- SEQUENCE: encode nested, decode with OpenConstructed ---- */
    {
        uint8_t inner[32];
        uint32_t innerLen = 0;
        SSFASN1Cursor_t seqInner;
        uint64_t val;
        bool bval;

        /* Build inner content: INTEGER(42) + BOOLEAN(true) */
        innerLen += SSFASN1EncIntU64(&inner[innerLen], sizeof(inner) - innerLen, 42);
        innerLen += SSFASN1EncBool(&inner[innerLen], sizeof(inner) - innerLen, true);

        /* Wrap in SEQUENCE */
        len = SSFASN1EncWrap(buf, sizeof(buf), SSF_ASN1_TAG_SEQUENCE, inner, innerLen);
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

        innerLen = SSFASN1EncIntU64(inner, sizeof(inner), 2);
        len = SSFASN1EncWrap(buf, sizeof(buf), SSF_ASN1_CONTEXT_EXPLICIT(0), inner, innerLen);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_CONTEXT_EXPLICIT(0),
                   &tagInner, &next) == true);
        SSF_ASSERT(SSFASN1DecGetIntU64(&tagInner, &val, &tagInner) == true);
        SSF_ASSERT(val == 2u);
    }

    /* ---- PeekTag and Skip ---- */
    {
        uint32_t pos = 0;
        uint8_t tag;

        pos += SSFASN1EncIntU64(&buf[pos], sizeof(buf) - pos, 10);
        pos += SSFASN1EncBool(&buf[pos], sizeof(buf) - pos, false);
        pos += SSFASN1EncNull(&buf[pos], sizeof(buf) - pos);

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

        needed = SSFASN1EncIntU64(NULL, 0, 999);
        SSF_ASSERT(needed > 0);
        written = SSFASN1EncIntU64(buf, sizeof(buf), 999);
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
        len = SSFASN1EncBool(buf, sizeof(buf), true);
        cursor.buf = buf; cursor.bufLen = len;
        uint64_t val;
        SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == false);
    }

    /* ---- Long-form length: 128+ bytes ---- */
    {
        uint8_t longData[200];
        const uint8_t *octets;
        uint32_t octetsLen;

        memset(longData, 0xABu, sizeof(longData));
        len = SSFASN1EncOctetString(buf, sizeof(buf), longData, 200);
        SSF_ASSERT(len > 0);
        /* Length should use long form (0x81 0xC8) */
        SSF_ASSERT(buf[1] == 0x81u);
        SSF_ASSERT(buf[2] == 200u);

        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetOctetString(&cursor, &octets, &octetsLen, &next) == true);
        SSF_ASSERT(octetsLen == 200u);
        SSF_ASSERT(octets[0] == 0xABu && octets[199] == 0xABu);
    }
}
#endif /* SSF_CONFIG_ASN1_UNIT_TEST */
