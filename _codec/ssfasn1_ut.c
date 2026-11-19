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

    /* ---- AUDIT ASN1-9: encoders accept only tags they can encode as decodable DER ---- */
    {
        static const uint8_t ab[] = { 'a', 'b' };

        SSF_ASSERT(SSFASN1EncTagLen(buf, sizeof(buf), SSF_ASN1_TAG_SEQUENCE, 0u, &len) == true);
        SSF_ASSERT(SSFASN1EncTagLen(buf, sizeof(buf), SSF_ASN1_TAG_DATE, 0u, &len) == true);
        SSF_ASSERT((len == 3u) && (buf[0] == 0x1Fu) && (buf[1] == 0x1Fu));
        SSF_ASSERT_TEST(SSFASN1EncTagLen(buf, sizeof(buf), 0x001Fu, 0u, &len));
        SSF_ASSERT_TEST(SSFASN1EncTagLen(buf, sizeof(buf), 0x801Fu, 0u, &len));
        SSF_ASSERT_TEST(SSFASN1EncTagLen(buf, sizeof(buf), 0x0530u, 0u, &len));
        SSF_ASSERT_TEST(SSFASN1EncTagLen(buf, sizeof(buf), 0x0000u, 0u, &len));
        SSF_ASSERT_TEST(SSFASN1EncWrap(buf, sizeof(buf), 0x0530u, ab, sizeof(ab), &len));
        SSF_ASSERT(SSFASN1EncString(buf, sizeof(buf), SSF_ASN1_TAG_UTF8_STRING, ab, sizeof(ab),
                                    &len) == true);
        SSF_ASSERT_TEST(SSFASN1EncString(buf, sizeof(buf), SSF_ASN1_TAG_OCTET_STRING, ab,
                                         sizeof(ab), &len));
    }

    /* ---- AUDIT ASN1-10: string bodies must fit their type ---- */
    {
        static const uint8_t utf8Nul[] = { 0x0Cu, 0x03u, 'a', 0x00u, 'b' };
        static const uint8_t printNul[] = { 0x13u, 0x02u, 'a', 0x00u };
        static const uint8_t ia5Nul[] = { 0x16u, 0x02u, 0x00u, 'b' };
        static const uint8_t t61Nul[] = { 0x14u, 0x01u, 0x00u };
        static const uint8_t bmpOdd[] = { 0x1Eu, 0x03u, 0x00u, 'A', 0x00u };
        static const uint8_t univBad[] = { 0x1Cu, 0x06u, 0x00u, 0x00u, 0x00u, 'A', 0x00u, 0x00u };
        static const uint8_t utf8Ok[] = { 0x0Cu, 0x02u, 'a', 'b' };
        static const uint8_t bmpOk[] = { 0x1Eu, 0x02u, 0x00u, 'A' };
        static const uint8_t univOk[] = { 0x1Cu, 0x04u, 0x00u, 0x00u, 0x00u, 'A' };
        static const struct { const uint8_t *der; uint32_t len; } bad[] = {
            { utf8Nul, sizeof(utf8Nul) }, { printNul, sizeof(printNul) },
            { ia5Nul, sizeof(ia5Nul) }, { t61Nul, sizeof(t61Nul) },
            { bmpOdd, sizeof(bmpOdd) }, { univBad, sizeof(univBad) }
        };
        static const struct { const uint8_t *der; uint32_t len; } good[] = {
            { utf8Ok, sizeof(utf8Ok) }, { bmpOk, sizeof(bmpOk) }, { univOk, sizeof(univOk) }
        };
        const uint8_t *str;
        uint32_t strLen;
        uint16_t strTag;
        uint32_t i;

        for (i = 0; i < (uint32_t)(sizeof(bad) / sizeof(bad[0])); i++)
        {
            cursor.buf = bad[i].der; cursor.bufLen = bad[i].len;
            SSF_ASSERT(SSFASN1DecGetString(&cursor, &str, &strLen, &strTag, &next) == false);
        }
        for (i = 0; i < (uint32_t)(sizeof(good) / sizeof(good[0])); i++)
        {
            cursor.buf = good[i].der; cursor.bufLen = good[i].len;
            SSF_ASSERT(SSFASN1DecGetString(&cursor, &str, &strLen, &strTag, &next) == true);
            SSF_ASSERT((strLen == (good[i].len - 2u)) && (strTag == good[i].der[0]));
        }
    }

    /* ---- AUDIT ASN1-8 / ASN1-12 / ASN1-13: encoder and decoder contract edges ---- */
    {
        static const uint8_t bits80[] = { 0x80u };
        static const uint8_t bitsFF[] = { 0xFFu };
        static const uint8_t eoc[] = { 0x00u, 0x00u, 0x05u, 0x00u };
        static const uint8_t intOne[] = { 0x02u, 0x01u, 0x01u };
        uint8_t wrapBuf[16];
        SSFASN1Cursor_t inner;
        const uint8_t *val;
        uint32_t valLen;
        uint16_t tag;

        /* ASN1-8: EncBitString traps (DBC) on a bad unused count and on set padding bits */
        SSF_ASSERT(SSFASN1EncBitString(buf, sizeof(buf), bits80, 1u, 7u, &len) == true);
        SSF_ASSERT_TEST(SSFASN1EncBitString(buf, sizeof(buf), bitsFF, 1u, 7u, &len));
        SSF_ASSERT_TEST(SSFASN1EncBitString(buf, sizeof(buf), bits80, 1u, 8u, &len));

        /* ASN1-12: EncWrap may wrap content already placed in buf (in place, overlapping) */
        memset(wrapBuf, 0, sizeof(wrapBuf));
        memcpy(&wrapBuf[1], intOne, sizeof(intOne));
        SSF_ASSERT(SSFASN1EncWrap(wrapBuf, sizeof(wrapBuf), SSF_ASN1_TAG_SEQUENCE, &wrapBuf[1],
                                  sizeof(intOne), &len) == true);
        SSF_ASSERT((len == 5u) && (wrapBuf[0] == 0x30u) && (wrapBuf[1] == 0x03u));
        SSF_ASSERT(memcmp(&wrapBuf[2], intOne, sizeof(intOne)) == 0);

        /* ASN1-13: OpenConstructed requires a constructed tag; tag 0 (EOC) is not an element */
        cursor.buf = intOne; cursor.bufLen = sizeof(intOne);
        SSF_ASSERT_TEST(SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_INTEGER, &inner, &next));
        cursor.buf = eoc; cursor.bufLen = sizeof(eoc);
        SSF_ASSERT(SSFASN1DecGetTLV(&cursor, &tag, &val, &valLen, &next) == false);
        SSF_ASSERT(SSFASN1DecPeekTag(&cursor, &tag) == false);
        SSF_ASSERT(SSFASN1DecSkip(&cursor, &next) == false);
    }

    /* ---- AUDIT ASN1-6: EncUInt encodes a magnitude; EncInt requires minimal input ---- */
    {
        static const uint8_t m80[] = { 0x80u };
        static const uint8_t m0001[] = { 0x00u, 0x00u, 0x01u };
        static const uint8_t m00[] = { 0x00u };
        static const uint8_t m0000[] = { 0x00u, 0x00u };
        static const uint8_t m7F[] = { 0x7Fu };
        static const uint8_t m0080[] = { 0x00u, 0x80u };
        static const uint8_t mPad007F[] = { 0x00u, 0x7Fu };
        static const uint8_t mPadFF80[] = { 0xFFu, 0x80u };
        static const struct { const uint8_t *in; uint32_t inLen; uint8_t outLen;
                              uint8_t out[4]; } vec[] = {
            { m80, sizeof(m80), 4u, { 0x02u, 0x02u, 0x00u, 0x80u } },
            { m0001, sizeof(m0001), 3u, { 0x02u, 0x01u, 0x01u, 0x00u } },
            { m00, sizeof(m00), 3u, { 0x02u, 0x01u, 0x00u, 0x00u } },
            { m0000, sizeof(m0000), 3u, { 0x02u, 0x01u, 0x00u, 0x00u } },
            { m7F, sizeof(m7F), 3u, { 0x02u, 0x01u, 0x7Fu, 0x00u } }
        };
        const uint8_t *mag;
        uint32_t magLen;
        uint32_t measured;
        uint32_t i;

        for (i = 0; i < (uint32_t)(sizeof(vec) / sizeof(vec[0])); i++)
        {
            SSF_ASSERT(SSFASN1EncUInt(NULL, 0, vec[i].in, vec[i].inLen, &measured) == true);
            SSF_ASSERT(measured == vec[i].outLen);
            SSF_ASSERT(SSFASN1EncUInt(buf, sizeof(buf), vec[i].in, vec[i].inLen, &len) == true);
            SSF_ASSERT((len == vec[i].outLen) && (memcmp(buf, vec[i].out, len) == 0));
            cursor.buf = buf; cursor.bufLen = len;
            SSF_ASSERT(SSFASN1DecGetUInt(&cursor, &mag, &magLen, &next) == true);
        }
        SSF_ASSERT(SSFASN1EncUInt(buf, 3u, m80, sizeof(m80), &len) == false);

        /* EncInt writes a minimal two's-complement body as given, and traps on any other */
        SSF_ASSERT(SSFASN1EncInt(buf, sizeof(buf), m80, sizeof(m80), &len) == true);
        SSF_ASSERT((len == 3u) && (buf[2] == 0x80u));
        SSF_ASSERT(SSFASN1EncInt(buf, sizeof(buf), m0080, sizeof(m0080), &len) == true);
        SSF_ASSERT((len == 4u) && (buf[2] == 0x00u) && (buf[3] == 0x80u));
        SSF_ASSERT_TEST(SSFASN1EncInt(buf, sizeof(buf), mPad007F, sizeof(mPad007F), &len));
        SSF_ASSERT_TEST(SSFASN1EncInt(buf, sizeof(buf), mPadFF80, sizeof(mPadFF80), &len));
        SSF_ASSERT_TEST(SSFASN1EncInt(NULL, 0, mPad007F, sizeof(mPad007F), &len));
    }

    /* ---- AUDIT ASN1-5: BIT STRING unused count 0..7, 0 when empty, zero padding ---- */
    {
        static const uint8_t bsUnused8[] = { 0x03u, 0x02u, 0x08u, 0xFFu };
        static const uint8_t bsEmpty5[] = { 0x03u, 0x01u, 0x05u };
        static const uint8_t bsPad7[] = { 0x03u, 0x02u, 0x07u, 0xFFu };
        static const uint8_t bsPad1[] = { 0x03u, 0x02u, 0x01u, 0x81u };
        static const uint8_t bsEmpty[] = { 0x03u, 0x01u, 0x00u };
        static const uint8_t bs780[] = { 0x03u, 0x02u, 0x07u, 0x80u };
        static const uint8_t bs0FF[] = { 0x03u, 0x02u, 0x00u, 0xFFu };
        static const uint8_t bs1FFFE[] = { 0x03u, 0x03u, 0x01u, 0xFFu, 0xFEu };
        static const struct { const uint8_t *der; uint32_t len; } bad[] = {
            { bsUnused8, sizeof(bsUnused8) }, { bsEmpty5, sizeof(bsEmpty5) },
            { bsPad7, sizeof(bsPad7) }, { bsPad1, sizeof(bsPad1) }
        };
        static const struct { const uint8_t *der; uint32_t len; uint8_t unused; } good[] = {
            { bsEmpty, sizeof(bsEmpty), 0u }, { bs780, sizeof(bs780), 7u },
            { bs0FF, sizeof(bs0FF), 0u }, { bs1FFFE, sizeof(bs1FFFE), 1u }
        };
        static const uint8_t sentinel[1] = { 0x00u };
        const uint8_t *bits;
        uint32_t bitsLen;
        uint8_t unusedBits;
        uint32_t i;

        for (i = 0; i < (uint32_t)(sizeof(bad) / sizeof(bad[0])); i++)
        {
            cursor.buf = bad[i].der; cursor.bufLen = bad[i].len;
            next.buf = sentinel; next.bufLen = 0x5A5Au;
            SSF_ASSERT(SSFASN1DecGetBitString(&cursor, &bits, &bitsLen, &unusedBits,
                                              &next) == false);
            SSF_ASSERT((next.buf == sentinel) && (next.bufLen == 0x5A5Au));
        }
        for (i = 0; i < (uint32_t)(sizeof(good) / sizeof(good[0])); i++)
        {
            cursor.buf = good[i].der; cursor.bufLen = good[i].len;
            SSF_ASSERT(SSFASN1DecGetBitString(&cursor, &bits, &bitsLen, &unusedBits,
                                              &next) == true);
            SSF_ASSERT((unusedBits == good[i].unused) && (bitsLen == (good[i].len - 3u)));
        }
    }

    /* ---- AUDIT ASN1-4: BOOLEAN content must be 0x00 or 0xFF (X.690 11.1) ---- */
    {
        static const uint8_t b01[] = { 0x01u, 0x01u, 0x01u };
        static const uint8_t b7F[] = { 0x01u, 0x01u, 0x7Fu };
        static const uint8_t bFE[] = { 0x01u, 0x01u, 0xFEu };
        static const uint8_t b00[] = { 0x01u, 0x01u, 0x00u };
        static const uint8_t bFF[] = { 0x01u, 0x01u, 0xFFu };
        static const uint8_t *bad[] = { b01, b7F, bFE };
        static const uint8_t sentinel[1] = { 0x00u };
        bool bv;
        uint32_t i;

        for (i = 0; i < (uint32_t)(sizeof(bad) / sizeof(bad[0])); i++)
        {
            cursor.buf = bad[i]; cursor.bufLen = 3u;
            next.buf = sentinel; next.bufLen = 0x5A5Au;
            SSF_ASSERT(SSFASN1DecGetBool(&cursor, &bv, &next) == false);
            SSF_ASSERT((next.buf == sentinel) && (next.bufLen == 0x5A5Au));
        }
        cursor.buf = b00; cursor.bufLen = sizeof(b00);
        SSF_ASSERT((SSFASN1DecGetBool(&cursor, &bv, &next) == true) && (bv == false));
        cursor.buf = bFF; cursor.bufLen = sizeof(bFF);
        SSF_ASSERT((SSFASN1DecGetBool(&cursor, &bv, &next) == true) && (bv == true));
    }

    /* ---- AUDIT ASN1-3: GetInt requires a minimal two's-complement INTEGER ---- */
    {
        static const uint8_t iEmpty[] = { 0x02u, 0x00u };
        static const uint8_t iPad00[] = { 0x02u, 0x02u, 0x00u, 0x7Fu };
        static const uint8_t iPadFF[] = { 0x02u, 0x02u, 0xFFu, 0x80u };
        static const uint8_t iZero[] = { 0x02u, 0x01u, 0x00u };
        static const uint8_t i7F[] = { 0x02u, 0x01u, 0x7Fu };
        static const uint8_t i128[] = { 0x02u, 0x02u, 0x00u, 0x80u };
        static const uint8_t iNeg128[] = { 0x02u, 0x01u, 0x80u };
        static const uint8_t iNeg1[] = { 0x02u, 0x01u, 0xFFu };
        static const uint8_t iNeg129[] = { 0x02u, 0x02u, 0xFFu, 0x7Fu };
        static const struct { const uint8_t *der; uint32_t len; } bad[] = {
            { iEmpty, sizeof(iEmpty) }, { iPad00, sizeof(iPad00) }, { iPadFF, sizeof(iPadFF) }
        };
        static const struct { const uint8_t *der; uint32_t len; } good[] = {
            { iZero, sizeof(iZero) }, { i7F, sizeof(i7F) }, { i128, sizeof(i128) },
            { iNeg128, sizeof(iNeg128) }, { iNeg1, sizeof(iNeg1) }, { iNeg129, sizeof(iNeg129) }
        };
        const uint8_t *iBuf;
        uint32_t iLen;
        uint32_t i;

        for (i = 0; i < (uint32_t)(sizeof(bad) / sizeof(bad[0])); i++)
        {
            cursor.buf = bad[i].der; cursor.bufLen = bad[i].len;
            SSF_ASSERT(SSFASN1DecGetInt(&cursor, &iBuf, &iLen, &next) == false);
        }
        for (i = 0; i < (uint32_t)(sizeof(good) / sizeof(good[0])); i++)
        {
            cursor.buf = good[i].der; cursor.bufLen = good[i].len;
            SSF_ASSERT(SSFASN1DecGetInt(&cursor, &iBuf, &iLen, &next) == true);
            SSF_ASSERT((iBuf == &good[i].der[2]) && (iLen == (good[i].len - 2u)));
        }

        /* GetUInt: the same minimal forms, negatives rejected, sign octet removed */
        for (i = 0; i < (uint32_t)(sizeof(bad) / sizeof(bad[0])); i++)
        {
            cursor.buf = bad[i].der; cursor.bufLen = bad[i].len;
            SSF_ASSERT(SSFASN1DecGetUInt(&cursor, &iBuf, &iLen, &next) == false);
        }
        cursor.buf = iNeg128; cursor.bufLen = sizeof(iNeg128);
        SSF_ASSERT(SSFASN1DecGetUInt(&cursor, &iBuf, &iLen, &next) == false);
        cursor.buf = iNeg1; cursor.bufLen = sizeof(iNeg1);
        SSF_ASSERT(SSFASN1DecGetUInt(&cursor, &iBuf, &iLen, &next) == false);
        cursor.buf = iNeg129; cursor.bufLen = sizeof(iNeg129);
        SSF_ASSERT(SSFASN1DecGetUInt(&cursor, &iBuf, &iLen, &next) == false);
        cursor.buf = iZero; cursor.bufLen = sizeof(iZero);
        SSF_ASSERT(SSFASN1DecGetUInt(&cursor, &iBuf, &iLen, &next) == true);
        SSF_ASSERT((iLen == 1u) && (iBuf[0] == 0x00u) && (next.bufLen == 0u));
        cursor.buf = i7F; cursor.bufLen = sizeof(i7F);
        SSF_ASSERT(SSFASN1DecGetUInt(&cursor, &iBuf, &iLen, &next) == true);
        SSF_ASSERT((iLen == 1u) && (iBuf[0] == 0x7Fu));
        cursor.buf = i128; cursor.bufLen = sizeof(i128);
        SSF_ASSERT(SSFASN1DecGetUInt(&cursor, &iBuf, &iLen, &next) == true);
        SSF_ASSERT((iLen == 1u) && (iBuf == &i128[3]) && (iBuf[0] == 0x80u));
    }

    /* ---- AUDIT ASN1-2: long-form lengths must be minimal (X.690 10.1) ---- */
    {
        static const uint8_t len81For3[] = { 0x30u, 0x81u, 0x03u, 0x02u, 0x01u, 0x05u };
        static const uint8_t len82For3[] = { 0x30u, 0x82u, 0x00u, 0x03u, 0x02u, 0x01u, 0x05u };
        static const uint8_t len84For3[] = {
            0x30u, 0x84u, 0x00u, 0x00u, 0x00u, 0x03u, 0x02u, 0x01u, 0x05u
        };
        static uint8_t len82For128[4u + 128u];
        static uint8_t len81For128[3u + 128u];
        static uint8_t len82For256[4u + 256u];
        static const struct { const uint8_t *der; uint32_t len; } bad[] = {
            { len81For3, sizeof(len81For3) }, { len82For3, sizeof(len82For3) },
            { len84For3, sizeof(len84For3) }, { len82For128, sizeof(len82For128) }
        };
        SSFASN1Cursor_t inner;
        const uint8_t *val;
        uint32_t valLen;
        uint16_t tag;
        uint32_t i;

        memset(len82For128, 0, sizeof(len82For128));
        len82For128[0] = 0x30u; len82For128[1] = 0x82u; len82For128[2] = 0x00u;
        len82For128[3] = 0x80u;
        memset(len81For128, 0, sizeof(len81For128));
        len81For128[0] = 0x30u; len81For128[1] = 0x81u; len81For128[2] = 0x80u;
        memset(len82For256, 0, sizeof(len82For256));
        len82For256[0] = 0x30u; len82For256[1] = 0x82u; len82For256[2] = 0x01u;
        len82For256[3] = 0x00u;

        for (i = 0; i < (uint32_t)(sizeof(bad) / sizeof(bad[0])); i++)
        {
            cursor.buf = bad[i].der; cursor.bufLen = bad[i].len;
            SSF_ASSERT(SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &inner,
                                                 &next) == false);
            SSF_ASSERT(SSFASN1DecGetTLV(&cursor, &tag, &val, &valLen, &next) == false);
            SSF_ASSERT(SSFASN1DecSkip(&cursor, &next) == false);
            SSF_ASSERT(SSFASN1DecPeekTag(&cursor, &tag) == false);
        }

        /* Minimal long forms still decode */
        cursor.buf = len81For128; cursor.bufLen = sizeof(len81For128);
        SSF_ASSERT(SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &inner,
                                             &next) == true);
        SSF_ASSERT((inner.bufLen == 128u) && (next.bufLen == 0u));
        cursor.buf = len82For256; cursor.bufLen = sizeof(len82For256);
        SSF_ASSERT(SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &inner,
                                             &next) == true);
        SSF_ASSERT((inner.bufLen == 256u) && (next.bufLen == 0u));
    }

    /* ---- AUDIT ASN1-7: a decoder that returns false leaves *next untouched ---- */
    {
        /* Each input is followed by a trailing NULL so an unwanted advance is visible */
        static const uint8_t wrongTag[] = { 0x05u, 0x00u, 0x05u, 0x00u };
        static const uint8_t nullForNull[] = { 0x04u, 0x00u, 0x05u, 0x00u };
        static const uint8_t badBool[] = { 0x01u, 0x02u, 0xFFu, 0xFFu, 0x05u, 0x00u };
        static const uint8_t negInt[] = { 0x02u, 0x01u, 0xFFu, 0x05u, 0x00u };
        static const uint8_t bigInt[] = {
            0x02u, 0x0Au, 0x01u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x05u, 0x00u
        };
        static const uint8_t emptyBits[] = { 0x03u, 0x00u, 0x05u, 0x00u };
        static const uint8_t badNull[] = { 0x05u, 0x01u, 0x00u, 0x05u, 0x00u };
        static const uint8_t badTime[] = { 0x17u, 0x01u, 0x30u, 0x05u, 0x00u };
        static const uint8_t sentinel[1] = { 0x00u };
        SSFASN1Cursor_t inner;
        const uint8_t *p;
        uint32_t plen;
        uint8_t unused;
        uint16_t strTag;
        uint32_t arcs[8];
        uint8_t arcsLen;
        uint64_t u64;
        bool b;

        #define _ASN1_NO_ADVANCE(_der, _call) do { \
            cursor.buf = (_der); cursor.bufLen = (uint32_t)sizeof(_der); \
            next.buf = sentinel; next.bufLen = 0x5A5Au; \
            SSF_ASSERT((_call) == false); \
            SSF_ASSERT((next.buf == sentinel) && (next.bufLen == 0x5A5Au)); \
        } while (0)

        /* Wrong tag, every typed decoder */
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE,
                                                             &inner, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetBool(&cursor, &b, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetInt(&cursor, &p, &plen, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetIntU64(&cursor, &u64, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetBitString(&cursor, &p, &plen, &unused, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetOctetString(&cursor, &p, &plen, &next));
        _ASN1_NO_ADVANCE(nullForNull, SSFASN1DecGetNull(&cursor, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetOID(&cursor, arcs, 8u, &arcsLen, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetOIDRaw(&cursor, &p, &plen, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetString(&cursor, &p, &plen, &strTag, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetTime(&cursor, &u64, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetDate(&cursor, &u64, &next));
        _ASN1_NO_ADVANCE(wrongTag, SSFASN1DecGetDateTime(&cursor, &u64, &next));

        /* Right tag, bad content */
        _ASN1_NO_ADVANCE(badBool, SSFASN1DecGetBool(&cursor, &b, &next));
        _ASN1_NO_ADVANCE(negInt, SSFASN1DecGetIntU64(&cursor, &u64, &next));
        _ASN1_NO_ADVANCE(bigInt, SSFASN1DecGetIntU64(&cursor, &u64, &next));
        _ASN1_NO_ADVANCE(emptyBits, SSFASN1DecGetBitString(&cursor, &p, &plen, &unused, &next));
        _ASN1_NO_ADVANCE(badNull, SSFASN1DecGetNull(&cursor, &next));
        _ASN1_NO_ADVANCE(badTime, SSFASN1DecGetTime(&cursor, &u64, &next));
        #undef _ASN1_NO_ADVANCE

        /* A successful decode still advances past exactly one element */
        cursor.buf = wrongTag; cursor.bufLen = sizeof(wrongTag);
        SSF_ASSERT(SSFASN1DecGetNull(&cursor, &next) == true);
        SSF_ASSERT((next.buf == &wrongTag[2]) && (next.bufLen == 2u));
    }

    /* ---- AUDIT ASN1-1: IntU64 rejects negative, empty and non-minimal INTEGERs ---- */
    {
        static const uint8_t negOne[] = { 0x02u, 0x01u, 0xFFu };
        static const uint8_t neg128[] = { 0x02u, 0x01u, 0x80u };
        static const uint8_t empty[] = { 0x02u, 0x00u };
        static const uint8_t padded7F[] = { 0x02u, 0x02u, 0x00u, 0x7Fu };
        static const uint8_t padded1[] = { 0x02u, 0x03u, 0x00u, 0x00u, 0x01u };
        static const uint8_t zero[] = { 0x02u, 0x01u, 0x00u };
        static const uint8_t v127[] = { 0x02u, 0x01u, 0x7Fu };
        static const uint8_t v128[] = { 0x02u, 0x02u, 0x00u, 0x80u };
        static const uint8_t vMax[] = {
            0x02u, 0x09u, 0x00u, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu
        };
        static const struct { const uint8_t *der; uint32_t len; } bad[] = {
            { negOne, sizeof(negOne) }, { neg128, sizeof(neg128) }, { empty, sizeof(empty) },
            { padded7F, sizeof(padded7F) }, { padded1, sizeof(padded1) }
        };
        uint64_t val;
        uint32_t i;

        for (i = 0; i < (uint32_t)(sizeof(bad) / sizeof(bad[0])); i++)
        {
            cursor.buf = bad[i].der; cursor.bufLen = bad[i].len;
            SSF_ASSERT(SSFASN1DecGetIntU64(&cursor, &val, &next) == false);
        }
        cursor.buf = zero; cursor.bufLen = sizeof(zero);
        SSF_ASSERT((SSFASN1DecGetIntU64(&cursor, &val, &next) == true) && (val == 0u));
        cursor.buf = v127; cursor.bufLen = sizeof(v127);
        SSF_ASSERT((SSFASN1DecGetIntU64(&cursor, &val, &next) == true) && (val == 127u));
        cursor.buf = v128; cursor.bufLen = sizeof(v128);
        SSF_ASSERT((SSFASN1DecGetIntU64(&cursor, &val, &next) == true) && (val == 128u));
        cursor.buf = vMax; cursor.bufLen = sizeof(vMax);
        SSF_ASSERT((SSFASN1DecGetIntU64(&cursor, &val, &next) == true) && (val == UINT64_MAX));
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
        /* 0x55 = 2*40+5 -> arcs 2,5; 0x04 -> arc 4; 0x03 -> arc 3 = OID 2.5.4.3 */
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
    /* OID 2.100.3 encodes as 0x81 0x34 0x03 (first sub-id 180 -> arc0=2, arc1=100).            */
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
    /* Single-byte first sub-id of 0x82 = 130 -> arc0=2, arc1=50 per X.690 Sec. 8.19.4.         */
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
        /* 257 - 80 = 177 -> arc0=2, arc1=177 */
        SSF_ASSERT(arcsLen == 2u);
        SSF_ASSERT(arcs[0] == 2u);
        SSF_ASSERT(arcs[1] == 177u);

        SSF_ASSERT(SSFASN1EncOIDRaw(buf, sizeof(buf), oidRaw2, sizeof(oidRaw2), &len) == true);
        cursor.buf = buf; cursor.bufLen = len;
        SSF_ASSERT(SSFASN1DecGetOID(&cursor, arcs, SSF_ASN1_CONFIG_MAX_OID_ARCS, &arcsLen,
                   &next) == true);
        /* (1<<7)|2 = 130; 130 - 80 = 50 -> arc0=2, arc1=50, arc2=5 */
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

    /* ---- Time range #2: UTCTime YY=69 (1969) rejected -- ssfdtime range starts at 1970 ---- */
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

    /* ---- Branch sweep: every reject path in the decoder + encoder ------------------------ */
    /* Each block below targets a specific branch in ssfasn1.c that the existing happy-path     */
    /* and isolated-edge tests above never reach. The goal is to exercise every public-API      */
    /* reject path with the minimum input that triggers it; comments name the source line(s).   */
    {
        SSFASN1Cursor_t cur;
        uint16_t tag;
        const uint8_t *value;
        uint32_t valueLen;
        uint64_t u64;
        uint8_t scratch = 0;

        /* ssfasn1.c line 51: bufLen < 2u (cannot fit minimum tag+length). */
        {
            uint8_t der[1] = { 0x02u };
            cur.buf = der; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecGetTLV(&cur, &tag, &value, &valueLen, &next) == false);
        }

        /* line 59: high-tag-number form with no extension byte. */
        {
            uint8_t der[2] = { 0x1Fu, 0x00u };  /* 2nd byte read as length; no tag extension */
            cur.buf = der; cur.bufLen = 1u;     /* length 1 -> ParseTL bails after reading 0x1F */
            SSF_ASSERT(SSFASN1DecGetTLV(&cur, &tag, &value, &valueLen, &next) == false);
        }

        /* line 63: extension byte high bit set (multi-byte tag continuation not supported). */
        {
            uint8_t der[3] = { 0x1Fu, 0xFFu, 0x00u };
            cur.buf = der; cur.bufLen = 3u;
            SSF_ASSERT(SSFASN1DecGetTLV(&cur, &tag, &value, &valueLen, &next) == false);
        }

        /* line 66: non-canonical short-form tag (extension byte < 31, should have used 1-byte). */
        {
            uint8_t der[3] = { 0x1Fu, 0x1Eu, 0x00u };
            cur.buf = der; cur.bufLen = 3u;
            SSF_ASSERT(SSFASN1DecGetTLV(&cur, &tag, &value, &valueLen, &next) == false);
        }

        /* line 69: 2-byte tag consumed but no length byte follows. */
        {
            uint8_t der[2] = { 0x1Fu, 0x40u };
            cur.buf = der; cur.bufLen = 2u;
            SSF_ASSERT(SSFASN1DecGetTLV(&cur, &tag, &value, &valueLen, &next) == false);
        }

        /* line 79: indefinite-form length (0x80) is BER, forbidden in DER. */
        {
            uint8_t der[3] = { 0x30u, 0x80u, 0x00u };
            cur.buf = der; cur.bufLen = 3u;
            SSF_ASSERT(SSFASN1DecGetTLV(&cur, &tag, &value, &valueLen, &next) == false);
        }

        /* line 88: long-form length-of-length > 4 bytes. */
        {
            uint8_t der[6] = { 0x30u, 0x85u, 0x00u, 0x00u, 0x00u, 0x00u };
            cur.buf = der; cur.bufLen = 6u;
            SSF_ASSERT(SSFASN1DecGetTLV(&cur, &tag, &value, &valueLen, &next) == false);
        }

        /* line 89: long-form length declares more bytes than the buffer holds. */
        {
            uint8_t der[2] = { 0x30u, 0x82u };  /* claims 2 length bytes, none present */
            cur.buf = der; cur.bufLen = 2u;
            SSF_ASSERT(SSFASN1DecGetTLV(&cur, &tag, &value, &valueLen, &next) == false);
        }

        /* line 168: SSFASN1DecPeekTag returns false on a malformed header. */
        {
            uint8_t der[1] = { 0x02u };
            cur.buf = der; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecPeekTag(&cur, &tag) == false);
        }

        /* lines 150/151: SSFASN1DecOpenConstructed fails on TLV parse error AND on tag mismatch. */
        {
            uint8_t bad[1] = { 0x30u };
            SSFASN1Cursor_t inner;
            cur.buf = bad; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecOpenConstructed(&cur, SSF_ASN1_TAG_SEQUENCE, &inner, &next) == false);
        }
        {
            uint8_t intDer[3] = { 0x02u, 0x01u, 0x05u };
            SSFASN1Cursor_t inner;
            cur.buf = intDer; cur.bufLen = 3u;
            SSF_ASSERT(SSFASN1DecOpenConstructed(&cur, SSF_ASN1_TAG_SEQUENCE, &inner, &next) == false);
        }

        /* lines 204/205: DecGetBool TLV failure + tag/length checks. */
        {
            bool b;
            uint8_t bad[1] = { 0x01u };
            cur.buf = bad; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecGetBool(&cur, &b, &next) == false);
        }
        {
            bool b;
            uint8_t wrongTag[3] = { 0x02u, 0x01u, 0x01u };  /* INTEGER instead of BOOLEAN */
            cur.buf = wrongTag; cur.bufLen = 3u;
            SSF_ASSERT(SSFASN1DecGetBool(&cur, &b, &next) == false);
        }
        {
            bool b;
            uint8_t wrongLen[4] = { 0x01u, 0x02u, 0xFFu, 0x00u };  /* BOOLEAN with len 2 */
            cur.buf = wrongLen; cur.bufLen = 4u;
            SSF_ASSERT(SSFASN1DecGetBool(&cur, &b, &next) == false);
        }

        /* line 244: DecGetIntU64 rejects integers wider than 8 bytes after leading-zero strip. */
        {
            uint8_t big[12] = { 0x02u, 0x0Au, 0x00u, 0x80u, 0x01u, 0x02u, 0x03u, 0x04u,
                                0x05u, 0x06u, 0x07u, 0x08u };  /* 10 content -> strip 1 -> 9 > 8 */
            cur.buf = big; cur.bufLen = 12u;
            SSF_ASSERT(SSFASN1DecGetIntU64(&cur, &u64, &next) == false);
        }

        /* lines 268-270: DecGetBitString TLV fail, tag mismatch, zero-length value. */
        {
            const uint8_t *bits;
            uint32_t bitsLen;
            uint8_t unused;
            uint8_t bad[1] = { 0x03u };
            cur.buf = bad; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecGetBitString(&cur, &bits, &bitsLen, &unused, &next) == false);
        }
        {
            const uint8_t *bits;
            uint32_t bitsLen;
            uint8_t unused;
            uint8_t wrongTag[3] = { 0x04u, 0x01u, 0x00u };  /* OCTET STRING tag */
            cur.buf = wrongTag; cur.bufLen = 3u;
            SSF_ASSERT(SSFASN1DecGetBitString(&cur, &bits, &bitsLen, &unused, &next) == false);
        }
        {
            const uint8_t *bits;
            uint32_t bitsLen;
            uint8_t unused;
            uint8_t empty[2] = { 0x03u, 0x00u };  /* BIT STRING with valueLen 0 */
            cur.buf = empty; cur.bufLen = 2u;
            SSF_ASSERT(SSFASN1DecGetBitString(&cur, &bits, &bitsLen, &unused, &next) == false);
        }

        /* lines 289/290: DecGetOctetString TLV fail + tag mismatch. */
        {
            const uint8_t *octets;
            uint32_t octetsLen;
            uint8_t bad[1] = { 0x04u };
            cur.buf = bad; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecGetOctetString(&cur, &octets, &octetsLen, &next) == false);
        }
        {
            const uint8_t *octets;
            uint32_t octetsLen;
            uint8_t wrongTag[3] = { 0x02u, 0x01u, 0x05u };
            cur.buf = wrongTag; cur.bufLen = 3u;
            SSF_ASSERT(SSFASN1DecGetOctetString(&cur, &octets, &octetsLen, &next) == false);
        }

        /* lines 304/305: DecGetNull TLV fail + tag mismatch + non-zero value length. */
        {
            uint8_t bad[1] = { 0x05u };
            cur.buf = bad; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecGetNull(&cur, &next) == false);
        }
        {
            uint8_t wrongTag[2] = { 0x02u, 0x00u };
            cur.buf = wrongTag; cur.bufLen = 2u;
            SSF_ASSERT(SSFASN1DecGetNull(&cur, &next) == false);
        }
        {
            uint8_t nonEmpty[3] = { 0x05u, 0x01u, 0x00u };
            cur.buf = nonEmpty; cur.bufLen = 3u;
            SSF_ASSERT(SSFASN1DecGetNull(&cur, &next) == false);
        }

        /* lines 320/321: DecGetOIDRaw TLV fail + tag mismatch. */
        {
            const uint8_t *raw;
            uint32_t rawLen;
            uint8_t bad[1] = { 0x06u };
            cur.buf = bad; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecGetOIDRaw(&cur, &raw, &rawLen, &next) == false);
        }
        {
            const uint8_t *raw;
            uint32_t rawLen;
            uint8_t wrongTag[3] = { 0x02u, 0x01u, 0x05u };
            cur.buf = wrongTag; cur.bufLen = 3u;
            SSF_ASSERT(SSFASN1DecGetOIDRaw(&cur, &raw, &rawLen, &next) == false);
        }

        /* lines 343, 347, 353-355, 378, 382-384, 389: DecGetOID malformed-OID rejects. */
        {
            uint32_t arcs[16];
            uint8_t arcsLen;

            /* line 343: empty OID payload. */
            {
                uint8_t emptyOid[2] = { 0x06u, 0x00u };
                cur.buf = emptyOid; cur.bufLen = 2u;
                SSF_ASSERT(SSFASN1DecGetOID(&cur, arcs, 16u, &arcsLen, &next) == false);
            }
            /* line 347: non-canonical leading 0x80 in first sub-id. */
            {
                uint8_t nonCanon[3] = { 0x06u, 0x01u, 0x80u };
                cur.buf = nonCanon; cur.bufLen = 3u;
                SSF_ASSERT(SSFASN1DecGetOID(&cur, arcs, 16u, &arcsLen, &next) == false);
            }
            /* line 353: first sub-id continuation runs past raw end. */
            {
                uint8_t truncFirst[3] = { 0x06u, 0x01u, 0x81u };  /* high bit set, no follow */
                cur.buf = truncFirst; cur.bufLen = 3u;
                SSF_ASSERT(SSFASN1DecGetOID(&cur, arcs, 16u, &arcsLen, &next) == false);
            }
            /* line 354: first sub-id needs 6 continuation bytes to enter iter 6 with count=5. */
            {
                uint8_t bigFirst[8] = { 0x06u, 0x06u, 0x82u, 0x82u, 0x82u, 0x82u, 0x82u, 0x01u };
                cur.buf = bigFirst; cur.bufLen = 8u;
                SSF_ASSERT(SSFASN1DecGetOID(&cur, arcs, 16u, &arcsLen, &next) == false);
            }
            /* line 355: at iter 5, accumulated 4 x 0x7F = 0x0FFFFFFF; bit 25 set -> overflow. */
            {
                uint8_t firstOverflow[7] = { 0x06u, 0x05u, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x01u };
                cur.buf = firstOverflow; cur.bufLen = 7u;
                SSF_ASSERT(SSFASN1DecGetOID(&cur, arcs, 16u, &arcsLen, &next) == false);
            }
            /* line 378: non-canonical leading 0x80 on a subsequent arc. */
            {
                uint8_t nonCanon2[4] = { 0x06u, 0x02u, 0x2Au, 0x80u };  /* OK first, then 0x80 */
                cur.buf = nonCanon2; cur.bufLen = 4u;
                SSF_ASSERT(SSFASN1DecGetOID(&cur, arcs, 16u, &arcsLen, &next) == false);
            }
            /* line 382: subsequent arc continuation runs past raw end. */
            {
                uint8_t truncSub[4] = { 0x06u, 0x02u, 0x2Au, 0x81u };
                cur.buf = truncSub; cur.bufLen = 4u;
                SSF_ASSERT(SSFASN1DecGetOID(&cur, arcs, 16u, &arcsLen, &next) == false);
            }
            /* line 383: subsequent arc with 6 continuation bytes -> iter 6 count=5. */
            {
                uint8_t bigSub[9] = { 0x06u, 0x07u, 0x2Au, 0x82u, 0x82u, 0x82u, 0x82u, 0x82u,
                                      0x01u };
                cur.buf = bigSub; cur.bufLen = 9u;
                SSF_ASSERT(SSFASN1DecGetOID(&cur, arcs, 16u, &arcsLen, &next) == false);
            }
            /* line 384: subsequent arc 4-byte overflow (same shape as line 355's first arc). */
            {
                uint8_t subOverflow[8] = { 0x06u, 0x06u, 0x2Au, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x01u };
                cur.buf = subOverflow; cur.bufLen = 8u;
                SSF_ASSERT(SSFASN1DecGetOID(&cur, arcs, 16u, &arcsLen, &next) == false);
            }
            /* line 389: OID has more arcs than oidArcsSize. Limit caller buffer to 2. */
            {
                uint8_t threeArc[5] = { 0x06u, 0x03u, 0x2Au, 0x03u, 0x04u };  /* 1.2.3.4 */
                uint32_t smallBuf[2];
                cur.buf = threeArc; cur.bufLen = 5u;
                SSF_ASSERT(SSFASN1DecGetOID(&cur, smallBuf, 2u, &arcsLen, &next) == false);
            }
        }

        /* lines 408, 413: DecGetString TLV fail + tag-not-in-allowed-set. */
        {
            const uint8_t *str;
            uint32_t strLen;
            uint16_t strTag;
            uint8_t bad[1] = { 0x0Cu };
            cur.buf = bad; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecGetString(&cur, &str, &strLen, &strTag, &next) == false);
        }
        {
            const uint8_t *str;
            uint32_t strLen;
            uint16_t strTag;
            uint8_t notString[3] = { 0x02u, 0x01u, 0x01u };  /* INTEGER -> not in string set */
            cur.buf = notString; cur.bufLen = 3u;
            SSF_ASSERT(SSFASN1DecGetString(&cur, &str, &strLen, &strTag, &next) == false);
        }
        /* line 419: strTagOut == NULL is also a valid path (caller skips reading the tag). */
        {
            const uint8_t *str;
            uint32_t strLen;
            uint8_t utf[5] = { 0x0Cu, 0x03u, 'a', 'b', 'c' };
            cur.buf = utf; cur.bufLen = 5u;
            SSF_ASSERT(SSFASN1DecGetString(&cur, &str, &strLen, NULL, &next) == true);
        }

        /* line 457: DecGetTime TLV fail. */
        {
            uint8_t bad[1] = { 0x17u };
            cur.buf = bad; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        /* lines 463, 473: wrong content length for UTC vs GeneralizedTime. */
        {
            uint8_t shortUTC[5] = { 0x17u, 0x03u, '2', '4', 'Z' };
            cur.buf = shortUTC; cur.bufLen = 5u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        {
            uint8_t shortGT[5] = { 0x18u, 0x03u, '2', '0', 'Z' };
            cur.buf = shortGT; cur.bufLen = 5u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        /* lines 474/475: GeneralizedTime year hi/lo non-digit. */
        {
            uint8_t badYearHi[17] = {
                0x18u, 0x0Fu, 'X','0','2','4','0','1','0','1','1','2','3','4','5','6','Z'
            };
            cur.buf = badYearHi; cur.bufLen = 17u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        {
            uint8_t badYearLo[17] = {
                0x18u, 0x0Fu, '2','0','X','4','0','1','0','1','1','2','3','4','5','6','Z'
            };
            cur.buf = badYearLo; cur.bufLen = 17u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        /* lines 484, 486, 488, 490, 492: month / day / hour / min / sec non-digit. */
        {
            /* GeneralizedTime: pos starts at 4 after year, so month at 4-5. */
            uint8_t badMonth[17] = {
                0x18u, 0x0Fu, '2','0','2','4','X','1','0','1','1','2','3','4','5','6','Z'
            };
            cur.buf = badMonth; cur.bufLen = 17u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        {
            uint8_t badDay[17] = {
                0x18u, 0x0Fu, '2','0','2','4','0','6','X','5','1','2','3','4','5','6','Z'
            };
            cur.buf = badDay; cur.bufLen = 17u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        {
            uint8_t badHour[17] = {
                0x18u, 0x0Fu, '2','0','2','4','0','6','1','5','X','2','3','4','5','6','Z'
            };
            cur.buf = badHour; cur.bufLen = 17u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        {
            uint8_t badMin[17] = {
                0x18u, 0x0Fu, '2','0','2','4','0','6','1','5','1','2','X','4','5','6','Z'
            };
            cur.buf = badMin; cur.bufLen = 17u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        {
            uint8_t badSec[17] = {
                0x18u, 0x0Fu, '2','0','2','4','0','6','1','5','1','2','3','4','X','6','Z'
            };
            cur.buf = badSec; cur.bufLen = 17u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        /* line 501: year out of range (e.g. 1969 — below SSFDTIME_EPOCH_YEAR_MIN). */
        {
            uint8_t oldYear[17] = {
                0x18u, 0x0Fu, '1','9','6','9','0','1','0','1','0','0','0','0','0','0','Z'
            };
            cur.buf = oldYear; cur.bufLen = 17u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }
        /* line 502: month == 0. */
        {
            uint8_t monthZero[17] = {
                0x18u, 0x0Fu, '2','0','2','4','0','0','0','1','0','0','0','0','0','0','Z'
            };
            cur.buf = monthZero; cur.bufLen = 17u;
            SSF_ASSERT(SSFASN1DecGetTime(&cur, &u64, &next) == false);
        }

        /* lines 532/533/535/536/537: _SSFASN1ParseYMD branches via DecGetDate. Tag is 0x1F1F  */
        /* (multi-byte). Encode TL via the encoder so the tag-length serialization is correct. */
        {
            uint8_t der[64];
            uint32_t hdrLen;
            uint64_t decoded;
            uint8_t payload[10];

            /* line 532: year hi non-digit. "X024-06-15" */
            memcpy(payload, "X024-06-15", 10);
            SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_DATE, 10u, &hdrLen) == true);
            memcpy(&der[hdrLen], payload, 10);
            cur.buf = der; cur.bufLen = hdrLen + 10u;
            SSF_ASSERT(SSFASN1DecGetDate(&cur, &decoded, &next) == false);

            /* line 533: year lo non-digit. */
            memcpy(payload, "20X4-06-15", 10);
            SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_DATE, 10u, &hdrLen) == true);
            memcpy(&der[hdrLen], payload, 10);
            cur.buf = der; cur.bufLen = hdrLen + 10u;
            SSF_ASSERT(SSFASN1DecGetDate(&cur, &decoded, &next) == false);

            /* line 535: month non-digit. */
            memcpy(payload, "2024-X6-15", 10);
            SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_DATE, 10u, &hdrLen) == true);
            memcpy(&der[hdrLen], payload, 10);
            cur.buf = der; cur.bufLen = hdrLen + 10u;
            SSF_ASSERT(SSFASN1DecGetDate(&cur, &decoded, &next) == false);

            /* line 536: missing dash at offset 7 (tested in existing block; harmless to repeat). */
            memcpy(payload, "2024-06X15", 10);
            SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_DATE, 10u, &hdrLen) == true);
            memcpy(&der[hdrLen], payload, 10);
            cur.buf = der; cur.bufLen = hdrLen + 10u;
            SSF_ASSERT(SSFASN1DecGetDate(&cur, &decoded, &next) == false);

            /* line 537: day non-digit. */
            memcpy(payload, "2024-06-X5", 10);
            SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_DATE, 10u, &hdrLen) == true);
            memcpy(&der[hdrLen], payload, 10);
            cur.buf = der; cur.bufLen = hdrLen + 10u;
            SSF_ASSERT(SSFASN1DecGetDate(&cur, &decoded, &next) == false);
        }

        /* lines 553-556: _SSFASN1YMDHMSToUnix range checks via DecGetDateTime. */
        {
            uint8_t der[64];
            uint32_t hdrLen;
            uint64_t decoded;
            uint8_t payload[19];

            /* line 553: year out of range (1969). */
            memcpy(payload, "1969-01-01T00:00:00", 19);
            SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_DATE_TIME, 19u, &hdrLen)
                       == true);
            memcpy(&der[hdrLen], payload, 19);
            cur.buf = der; cur.bufLen = hdrLen + 19u;
            SSF_ASSERT(SSFASN1DecGetDateTime(&cur, &decoded, &next) == false);

            /* line 554: month == 0. */
            memcpy(payload, "2024-00-01T00:00:00", 19);
            SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_DATE_TIME, 19u, &hdrLen)
                       == true);
            memcpy(&der[hdrLen], payload, 19);
            cur.buf = der; cur.bufLen = hdrLen + 19u;
            SSF_ASSERT(SSFASN1DecGetDateTime(&cur, &decoded, &next) == false);

            /* line 555: day == 0. */
            memcpy(payload, "2024-06-00T00:00:00", 19);
            SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_DATE_TIME, 19u, &hdrLen)
                       == true);
            memcpy(&der[hdrLen], payload, 19);
            cur.buf = der; cur.bufLen = hdrLen + 19u;
            SSF_ASSERT(SSFASN1DecGetDateTime(&cur, &decoded, &next) == false);

            /* line 556: minute > 59 (and second > 59 covered together via OR short-circuit). */
            memcpy(payload, "2024-06-15T12:60:00", 19);
            SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_DATE_TIME, 19u, &hdrLen)
                       == true);
            memcpy(&der[hdrLen], payload, 19);
            cur.buf = der; cur.bufLen = hdrLen + 19u;
            SSF_ASSERT(SSFASN1DecGetDateTime(&cur, &decoded, &next) == false);
        }

        /* line 584: DecGetDate TLV fail. */
        {
            uint64_t decoded;
            uint8_t bad[1] = { 0x1Fu };  /* multi-byte tag start, no follow-up */
            cur.buf = bad; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecGetDate(&cur, &decoded, &next) == false);
        }

        /* line 610: DecGetDateTime TLV fail. */
        {
            uint64_t decoded;
            uint8_t bad[1] = { 0x1Fu };
            cur.buf = bad; cur.bufLen = 1u;
            SSF_ASSERT(SSFASN1DecGetDateTime(&cur, &decoded, &next) == false);
        }
        /* lines 616-620: DateTime hour / colon / minute / colon / second non-digit / wrong sep. */
        {
            uint8_t der[64];
            uint32_t hdrLen;
            uint64_t decoded;
            uint8_t payload[19];
            const char *bad_payloads[] = {
                "2024-06-15TX2:00:00",   /* hour non-digit (line 616) */
                "2024-06-15T12X00:00",   /* missing first colon (line 617) */
                "2024-06-15T12:X0:00",   /* minute non-digit (line 618) */
                "2024-06-15T12:00X00",   /* missing second colon (line 619) */
                "2024-06-15T12:00:X0"    /* second non-digit (line 620) */
            };
            size_t i;
            for (i = 0; i < sizeof(bad_payloads) / sizeof(bad_payloads[0]); i++) {
                memcpy(payload, bad_payloads[i], 19);
                SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_DATE_TIME, 19u, &hdrLen)
                           == true);
                memcpy(&der[hdrLen], payload, 19);
                cur.buf = der; cur.bufLen = hdrLen + 19u;
                SSF_ASSERT(SSFASN1DecGetDateTime(&cur, &decoded, &next) == false);
            }
        }

        /* Encoder side ------------------------------------------------------------------------ */

        /* lines 637, 659: 3-byte length-field path (contentLen in 0x100..0xFFFF). */
        {
            uint8_t der[300];
            uint32_t written;
            SSF_ASSERT(SSFASN1EncTagLen(der, sizeof(der), SSF_ASN1_TAG_OCTET_STRING, 300u,
                                        &written) == true);
            SSF_ASSERT(written == 4u);   /* 1 tag + 1 lead (0x82) + 2 length bytes */
            SSF_ASSERT(der[1] == 0x82u);
        }

        /* line 728: SSFASN1EncTagLen rejects an output buffer smaller than the header. */
        {
            uint8_t smallBuf[1];
            uint32_t written;
            SSF_ASSERT(SSFASN1EncTagLen(smallBuf, sizeof(smallBuf), SSF_ASN1_TAG_INTEGER, 5u,
                                        &written) == false);
        }

        /* line 771: SSFASN1EncInt rejects intLen that would overflow total. */
        {
            uint8_t der[16];
            uint32_t written;
            SSF_ASSERT(SSFASN1EncInt(der, sizeof(der), &scratch, 0xFFFFFFFEu, &written) == false);
        }

        /* lines 842, 850, 855: SSFASN1EncBitString overflow + buffer-too-small + empty bits. */
        {
            uint8_t der[16];
            uint32_t written;
            uint8_t stub = 0;

            /* line 842: bitsLen near uint32_t max trips total-overflow guard. */
            SSF_ASSERT(SSFASN1EncBitString(der, sizeof(der), &stub, 0xFFFFFFFEu, 0u, &written)
                       == false);

            /* line 850: bufSize too small for the contentLen+header. */
            {
                uint8_t smallBuf[3];
                SSF_ASSERT(SSFASN1EncBitString(smallBuf, sizeof(smallBuf), &stub, 4u, 0u, &written)
                           == false);
            }

            /* line 855: bitsLen == 0 path skips the memcpy; round-trip the result. */
            SSF_ASSERT(SSFASN1EncBitString(der, sizeof(der), NULL, 0u, 0u, &written) == true);
            SSF_ASSERT(written == 3u);
        }

        /* lines 936, 1034, 1057: encoder rejects unixSec values that cannot resolve to a date. */
        {
            uint8_t der[32];
            uint32_t written;
            uint64_t huge = 0xFFFFFFFFFFFFFFFFull;  /* > SSFDTIME_UNIX_EPOCH_SEC_MAX */
            SSF_ASSERT(SSFASN1EncUTCTime(der, sizeof(der), huge, &written) == false);
            SSF_ASSERT(SSFASN1EncDate(der, sizeof(der), huge, &written) == false);
            SSF_ASSERT(SSFASN1EncDateTime(der, sizeof(der), huge, &written) == false);
        }

        /* line 1098: SSFASN1EncDateTime rejects a buffer smaller than the encoded total. */
        {
            uint8_t smallBuf[10];
            uint32_t written;
            SSF_ASSERT(SSFASN1EncDateTime(smallBuf, sizeof(smallBuf), 1718452800ull, &written)
                       == false);
        }

        /* line 1102: SSFASN1EncWrap with contentLen == 0 skips the memcpy (NULL content OK). */
        {
            uint8_t der[8];
            uint32_t written;
            SSF_ASSERT(SSFASN1EncWrap(der, sizeof(der), SSF_ASN1_TAG_NULL, NULL, 0u, &written)
                       == true);
            SSF_ASSERT(written == 2u);  /* tag + 0-length */
        }
    }
}
#endif /* SSF_CONFIG_ASN1_UNIT_TEST */
