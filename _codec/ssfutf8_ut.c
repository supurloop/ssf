/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfutf8_ut.c                                                                                  */
/* Unit tests for the UTF-8 codec interface.                                                     */
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfutf8.h"

#if SSF_CONFIG_UTF8_UNIT_TEST == 1

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
/* One row of the well-formed UTF-8 byte sequence table (Unicode Table 3-7, RFC 3629 section 4)  */
typedef struct
{
    uint8_t len;
    uint8_t lo[SSF_UTF8_MAX_SEQ_LEN];
    uint8_t hi[SSF_UTF8_MAX_SEQ_LEN];
} SSFUTF8UTRow_t;

/* One well-formed sequence and the code point it decodes to */
typedef struct
{
    const char *s;
    size_t len;
    uint32_t cp;
} SSFUTF8UTGood_t;

/* One ill-formed sequence */
typedef struct
{
    const char *s;
    size_t len;
} SSFUTF8UTBad_t;

/* --------------------------------------------------------------------------------------------- */
/* Module variables                                                                              */
/* --------------------------------------------------------------------------------------------- */
static const SSFUTF8UTRow_t _ssfUTF8UTRows[] =
{
    { 1u, { 0x00u, 0x00u, 0x00u, 0x00u }, { 0x7Fu, 0x00u, 0x00u, 0x00u } },
    { 2u, { 0xC2u, 0x80u, 0x00u, 0x00u }, { 0xDFu, 0xBFu, 0x00u, 0x00u } },
    { 3u, { 0xE0u, 0xA0u, 0x80u, 0x00u }, { 0xE0u, 0xBFu, 0xBFu, 0x00u } },
    { 3u, { 0xE1u, 0x80u, 0x80u, 0x00u }, { 0xECu, 0xBFu, 0xBFu, 0x00u } },
    { 3u, { 0xEDu, 0x80u, 0x80u, 0x00u }, { 0xEDu, 0x9Fu, 0xBFu, 0x00u } },
    { 3u, { 0xEEu, 0x80u, 0x80u, 0x00u }, { 0xEFu, 0xBFu, 0xBFu, 0x00u } },
    { 4u, { 0xF0u, 0x90u, 0x80u, 0x80u }, { 0xF0u, 0xBFu, 0xBFu, 0xBFu } },
    { 4u, { 0xF1u, 0x80u, 0x80u, 0x80u }, { 0xF3u, 0xBFu, 0xBFu, 0xBFu } },
    { 4u, { 0xF4u, 0x80u, 0x80u, 0x80u }, { 0xF4u, 0x8Fu, 0xBFu, 0xBFu } },
};
static uint8_t _ssfUTF8UTBuf[8];

/* --------------------------------------------------------------------------------------------- */
/* Returns SSFUTF8DecodeNext's sequence length, or 0 after asserting seqLenOut was not written.  */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFUTF8UTDec(const uint8_t *str, size_t strLen, uint32_t *cpOut)
{
    size_t n = 0xA5u;

    SSF_REQUIRE(str != NULL);
    SSF_REQUIRE(cpOut != NULL);

    /* Was a sequence decoded? */
    if (SSFUTF8DecodeNext(str, strLen, cpOut, &n))
    {
        /* Yes */
        SSF_ASSERT((n >= 1u) && (n <= SSF_UTF8_MAX_SEQ_LEN) && (n <= strLen));
        return n;
    }
    /* No */
    SSF_ASSERT(n == 0xA5u);
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns SSFUTF8EncodeCP's output length, or 0 after asserting outLenOut was not written.      */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFUTF8UTEnc(uint32_t cp, uint8_t *out, size_t outSize)
{
    size_t n = 0xA5u;

    SSF_REQUIRE(out != NULL);

    /* Was the code point encoded? */
    if (SSFUTF8EncodeCP(cp, out, outSize, &n))
    {
        /* Yes */
        SSF_ASSERT((n >= 1u) && (n <= SSF_UTF8_MAX_SEQ_LEN) && (n <= outSize));
        return n;
    }
    /* No */
    SSF_ASSERT(n == 0xA5u);
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the reference decode of str: bytes used and *cpOut, or 0 if not well formed.          */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFUTF8UTRefDecode(const uint8_t *str, size_t strLen, uint32_t *cpOut)
{
    static const uint8_t leadMask[] = { 0x00u, 0x7Fu, 0x1Fu, 0x0Fu, 0x07u };
    size_t r;
    size_t i;
    uint32_t cp;
    const SSFUTF8UTRow_t *row;

    SSF_REQUIRE(str != NULL);
    SSF_REQUIRE(cpOut != NULL);

    /* Is the input empty? */
    if (strLen == 0u)
    {
        /* Yes, no sequence */
        return 0;
    }
    /* No */
    for (r = 0u; r < (sizeof(_ssfUTF8UTRows) / sizeof(_ssfUTF8UTRows[0])); r++)
    {
        row = &_ssfUTF8UTRows[r];
        /* Is the lead byte outside this row, or is the input too short for the row? */
        if ((str[0] < row->lo[0]) || (str[0] > row->hi[0]) || (strLen < row->len))
        {
            /* Yes, try the next row */
            continue;
        }
        /* No, check every trail byte against the row */
        cp = (uint32_t)(str[0] & leadMask[row->len]);
        for (i = 1u; i < row->len; i++)
        {
            /* Is the trail byte outside the row's range for its position? */
            if ((str[i] < row->lo[i]) || (str[i] > row->hi[i]))
            {
                /* Yes, not well formed */
                return 0;
            }
            /* No */
            cp = (cp * 64u) + (uint32_t)(str[i] - 0x80u);
        }
        *cpOut = cp;
        return row->len;
    }
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the reference decoder finds str well formed, NUL refused unless allowNul.     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFUTF8UTRefIsValid(const uint8_t *str, size_t strLen, bool allowNul)
{
    size_t n;
    uint32_t cp;

    SSF_REQUIRE(str != NULL);

    while (strLen > 0u)
    {
        n = _SSFUTF8UTRefDecode(str, strLen, &cp);
        /* Is the next sequence ill formed, or a refused NUL? */
        if ((n == 0u) || ((cp == 0u) && (!allowNul)))
        {
            /* Yes */
            return false;
        }
        /* No */
        str += n;
        strLen -= n;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts that the codec agrees with the reference on str, as one sequence and as a string.     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFUTF8UTAgree(const uint8_t *str, size_t strLen)
{
    uint32_t cp;
    uint32_t refCp;
    size_t n;
    size_t refN;
    size_t count;

    SSF_REQUIRE(str != NULL);

    cp = 0xA5A5A5A5ul;
    refCp = 0x5A5A5A5Aul;
    n = _SSFUTF8UTDec(str, strLen, &cp);
    refN = _SSFUTF8UTRefDecode(str, strLen, &refCp);
    SSF_ASSERT(n == refN);
    /* Did the reference decode a code point? */
    if (refN != 0u)
    {
        /* Yes, the codec gives the same one */
        SSF_ASSERT(cp == refCp);
    }
    else
    {
        /* No, the codec left cpOut alone */
        SSF_ASSERT(cp == 0xA5A5A5A5ul);
    }
    SSF_ASSERT(SSFUTF8IsValid(str, strLen, true) == _SSFUTF8UTRefIsValid(str, strLen, true));
    SSF_ASSERT(SSFUTF8IsValid(str, strLen, false) == _SSFUTF8UTRefIsValid(str, strLen, false));
    count = 7u;
    SSF_ASSERT(SSFUTF8Count(str, strLen, &count) == _SSFUTF8UTRefIsValid(str, strLen, true));
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts the decoder on every 1-, 2- and 3-byte input, and on 4-byte boundaries.               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFUTF8UTExhaustive(void)
{
    static const uint8_t edges[] = { 0x00u, 0x7Fu, 0x80u, 0x8Fu, 0x90u, 0x9Fu, 0xA0u, 0xBFu,
                                     0xC0u, 0xFFu };
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t cp;
    uint8_t s[SSF_UTF8_MAX_SEQ_LEN];

    for (a = 0u; a < 256u; a++)
    {
        s[0] = (uint8_t)a;
        _SSFUTF8UTAgree(s, 1u);
        for (b = 0u; b < 256u; b++)
        {
            s[1] = (uint8_t)b;
            _SSFUTF8UTAgree(s, 2u);
            for (c = 0u; c < 256u; c++)
            {
                s[2] = (uint8_t)c;
                SSF_ASSERT(_SSFUTF8UTDec(s, 3u, &cp) == _SSFUTF8UTRefDecode(s, 3u, &cp));
                SSF_ASSERT(SSFUTF8IsValid(s, 3u, true) == _SSFUTF8UTRefIsValid(s, 3u, true));
            }
        }
    }
    for (a = 0u; a < 256u; a++)
    {
        s[0] = (uint8_t)a;
        for (b = 0u; b < 256u; b++)
        {
            s[1] = (uint8_t)b;
            for (c = 0u; c < sizeof(edges); c++)
            {
                s[2] = edges[c];
                for (d = 0u; d < sizeof(edges); d++)
                {
                    s[3] = edges[d];
                    _SSFUTF8UTAgree(s, 4u);
                }
            }
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts that known well-formed and ill-formed sequences decode or fail as expected.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFUTF8UTKnown(void)
{
    static const SSFUTF8UTGood_t good[] =
    {
        { "\x00", 1u, 0x0000u }, { "A", 1u, 0x0041u }, { "\x7F", 1u, 0x007Fu },
        { "\xC2\x80", 2u, 0x0080u }, { "\xC3\xA9", 2u, 0x00E9u }, { "\xDF\xBF", 2u, 0x07FFu },
        { "\xE0\xA0\x80", 3u, 0x0800u }, { "\xE2\x82\xAC", 3u, 0x20ACu },
        { "\xED\x9F\xBF", 3u, 0xD7FFu }, { "\xEE\x80\x80", 3u, 0xE000u },
        { "\xEF\xBF\xBF", 3u, 0xFFFFu }, { "\xF0\x90\x80\x80", 4u, 0x10000ul },
        { "\xF0\x9F\x98\x80", 4u, 0x1F600ul }, { "\xF4\x8F\xBF\xBF", 4u, 0x10FFFFul },
    };
    static const SSFUTF8UTBad_t bad[] =
    {
        { "\x80", 1u }, { "\xBF", 1u }, { "\xC0\x80", 2u }, { "\xC1\xBF", 2u },
        { "\xE0\x80\x80", 3u }, { "\xE0\x9F\xBF", 3u }, { "\xED\xA0\x80", 3u },
        { "\xED\xBF\xBF", 3u }, { "\xF0\x80\x80\x80", 4u }, { "\xF0\x8F\xBF\xBF", 4u },
        { "\xF4\x90\x80\x80", 4u }, { "\xF5\x80\x80\x80", 4u }, { "\xF8\x88\x80\x80", 4u },
        { "\xFE", 1u }, { "\xFF", 1u }, { "\xC3\x28", 2u }, { "\xE2\x28\xA1", 3u },
        { "\xE2\x82\x28", 3u }, { "\xF0\x28\x8C\xBC", 4u }, { "\xF0\x90\x28\xBC", 4u },
        { "\xF0\x90\x8C\x28", 4u },
    };
    uint32_t i;
    size_t cut;
    uint32_t cp;

    for (i = 0u; i < (sizeof(good) / sizeof(good[0])); i++)
    {
        cp = 0xFFFFFFFFul;
        SSF_ASSERT(_SSFUTF8UTDec((const uint8_t *)good[i].s, good[i].len, &cp) ==
                   good[i].len);
        SSF_ASSERT(cp == good[i].cp);
        /* A longer buffer still decodes only the one sequence */
        memcpy(_ssfUTF8UTBuf, good[i].s, good[i].len);
        _ssfUTF8UTBuf[good[i].len] = 'z';
        SSF_ASSERT(_SSFUTF8UTDec(_ssfUTF8UTBuf, good[i].len + 1u, &cp) == good[i].len);
        SSF_ASSERT(cp == good[i].cp);
        /* Every cut-short form is refused, and cpOut is not written */
        for (cut = 0u; cut < good[i].len; cut++)
        {
            cp = 0x12345678ul;
            SSF_ASSERT(_SSFUTF8UTDec((const uint8_t *)good[i].s, cut, &cp) == 0u);
            SSF_ASSERT(cp == 0x12345678ul);
            SSF_ASSERT(SSFUTF8IsValid((const uint8_t *)good[i].s, cut, true) == (cut == 0u));
        }
        SSF_ASSERT(SSFUTF8IsValid((const uint8_t *)good[i].s, good[i].len, true));
        SSF_ASSERT(SSFUTF8IsValid((const uint8_t *)good[i].s, good[i].len, false) ==
                   (good[i].cp != 0u));
    }
    for (i = 0u; i < (sizeof(bad) / sizeof(bad[0])); i++)
    {
        cp = 0x12345678ul;
        SSF_ASSERT(_SSFUTF8UTDec((const uint8_t *)bad[i].s, bad[i].len, &cp) == 0u);
        SSF_ASSERT(cp == 0x12345678ul);
        SSF_ASSERT(SSFUTF8IsValid((const uint8_t *)bad[i].s, bad[i].len, true) == false);
        /* Valid text before the bad sequence does not hide it */
        _ssfUTF8UTBuf[0] = 'a';
        memcpy(&_ssfUTF8UTBuf[1], bad[i].s, bad[i].len);
        SSF_ASSERT(SSFUTF8IsValid(_ssfUTF8UTBuf, bad[i].len + 1u, true) == false);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts whole-string validation, NUL handling and code point counts.                          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFUTF8UTStrings(void)
{
    static const uint8_t mixed[] = "a\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80z";
    static const uint8_t nul[] = { 'a', 0x00u, 'b' };
    size_t count;

    /* Empty string: valid, zero code points */
    count = 99u;
    SSF_ASSERT(SSFUTF8IsValid(mixed, 0u, false));
    SSF_ASSERT(SSFUTF8Count(mixed, 0u, &count) && (count == 0u));

    /* Mixed 1..4-byte forms */
    SSF_ASSERT(SSFUTF8IsValid(mixed, sizeof(mixed) - 1u, false));
    SSF_ASSERT(SSFUTF8Count(mixed, sizeof(mixed) - 1u, &count) && (count == 5u));
    SSF_ASSERT(SSFUTF8Count(mixed, 1u, &count) && (count == 1u));

    /* Cut inside the 4-byte form: refused, count not written */
    count = 99u;
    SSF_ASSERT(SSFUTF8IsValid(mixed, sizeof(mixed) - 3u, true) == false);
    SSF_ASSERT((SSFUTF8Count(mixed, sizeof(mixed) - 3u, &count) == false) && (count == 99u));

    /* Embedded NUL: allowed only on request; Count counts it */
    SSF_ASSERT(SSFUTF8IsValid(nul, sizeof(nul), true));
    SSF_ASSERT(SSFUTF8IsValid(nul, sizeof(nul), false) == false);
    SSF_ASSERT(SSFUTF8IsValid(nul, 1u, false));
    SSF_ASSERT(SSFUTF8Count(nul, sizeof(nul), &count) && (count == 3u));

    /* An overlong NUL (C0 80, modified UTF-8) is refused even with allowNul */
    SSF_ASSERT(SSFUTF8IsValid((const uint8_t *)"\xC0\x80", 2u, true) == false);
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts the encoder on every code point and on out-of-range values and short buffers.         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFUTF8UTEncode(void)
{
    static const uint32_t refused[] = { 0xD800ul, 0xDBFFul, 0xDC00ul, 0xDFFFul, 0x110000ul,
                                        0x7FFFFFFFul, 0xFFFFFFFFul };
    uint32_t cp;
    uint32_t back;
    size_t n;
    size_t want;
    uint32_t i;

    for (cp = 0u; cp <= SSF_UTF8_MAX_CP; cp++)
    {
        /* Is it a surrogate? */
        if ((cp >= 0xD800ul) && (cp <= 0xDFFFul))
        {
            /* Yes, refused and nothing written */
            memset(_ssfUTF8UTBuf, 0xEE, sizeof(_ssfUTF8UTBuf));
            SSF_ASSERT(_SSFUTF8UTEnc(cp, _ssfUTF8UTBuf, sizeof(_ssfUTF8UTBuf)) == 0u);
            SSF_ASSERT(_ssfUTF8UTBuf[0] == 0xEEu);
            continue;
        }
        /* No, the shortest form, which decodes back to cp */
        want = (cp < 0x80ul) ? 1u : ((cp < 0x800ul) ? 2u : ((cp < 0x10000ul) ? 3u : 4u));
        n = _SSFUTF8UTEnc(cp, _ssfUTF8UTBuf, want);
        SSF_ASSERT(n == want);
        back = 0xFFFFFFFFul;
        SSF_ASSERT(_SSFUTF8UTRefDecode(_ssfUTF8UTBuf, n, &back) == n);
        SSF_ASSERT(back == cp);
        /* One byte short: refused and nothing written */
        memset(_ssfUTF8UTBuf, 0xEE, sizeof(_ssfUTF8UTBuf));
        SSF_ASSERT(_SSFUTF8UTEnc(cp, _ssfUTF8UTBuf, want - 1u) == 0u);
        SSF_ASSERT(_ssfUTF8UTBuf[0] == 0xEEu);
    }
    for (i = 0u; i < (sizeof(refused) / sizeof(refused[0])); i++)
    {
        memset(_ssfUTF8UTBuf, 0xEE, sizeof(_ssfUTF8UTBuf));
        SSF_ASSERT(_SSFUTF8UTEnc(refused[i], _ssfUTF8UTBuf, sizeof(_ssfUTF8UTBuf)) == 0u);
        SSF_ASSERT(_ssfUTF8UTBuf[0] == 0xEEu);
    }
    /* Exact bytes of a few forms */
    SSF_ASSERT((_SSFUTF8UTEnc(0x00E9ul, _ssfUTF8UTBuf, 2u) == 2u) &&
               (memcmp(_ssfUTF8UTBuf, "\xC3\xA9", 2u) == 0));
    SSF_ASSERT((_SSFUTF8UTEnc(0x20ACul, _ssfUTF8UTBuf, 3u) == 3u) &&
               (memcmp(_ssfUTF8UTBuf, "\xE2\x82\xAC", 3u) == 0));
    SSF_ASSERT((_SSFUTF8UTEnc(0x1F600ul, _ssfUTF8UTBuf, 4u) == 4u) &&
               (memcmp(_ssfUTF8UTBuf, "\xF0\x9F\x98\x80", 4u) == 0));
    SSF_ASSERT((_SSFUTF8UTEnc(0x10FFFFul, _ssfUTF8UTBuf, 4u) == 4u) &&
               (memcmp(_ssfUTF8UTBuf, "\xF4\x8F\xBF\xBF", 4u) == 0));
    /* Zero-size buffer */
    SSF_ASSERT(_SSFUTF8UTEnc(0x41ul, _ssfUTF8UTBuf, 0u) == 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts UTF-16 surrogate pair joining at every range edge.                                    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFUTF8UTPairs(void)
{
    static const uint16_t his[] = { 0xD7FFu, 0xD800u, 0xDBFFu, 0xDC00u };
    static const uint16_t los[] = { 0xDBFFu, 0xDC00u, 0xDFFFu, 0xE000u };
    uint32_t cp;
    uint32_t h;
    uint32_t l;
    bool ok;

    for (h = 0u; h < (sizeof(his) / sizeof(his[0])); h++)
    {
        for (l = 0u; l < (sizeof(los) / sizeof(los[0])); l++)
        {
            cp = 0x12345678ul;
            ok = SSFUTF8FromUTF16Pair(his[h], los[l], &cp);
            SSF_ASSERT(ok == (((h == 1u) || (h == 2u)) && ((l == 1u) || (l == 2u))));
            SSF_ASSERT(ok || (cp == 0x12345678ul));
        }
    }
    SSF_ASSERT(SSFUTF8FromUTF16Pair(0xD800u, 0xDC00u, &cp) && (cp == 0x10000ul));
    SSF_ASSERT(SSFUTF8FromUTF16Pair(0xDBFFu, 0xDFFFu, &cp) && (cp == 0x10FFFFul));
    SSF_ASSERT(SSFUTF8FromUTF16Pair(0xD83Du, 0xDE00u, &cp) && (cp == 0x1F600ul));
    SSF_ASSERT(SSFUTF8FromUTF16Pair(0xD800u, 0xDFFFu, &cp) && (cp == 0x103FFul));
    SSF_ASSERT(SSFUTF8FromUTF16Pair(0xDBFFu, 0xDC00u, &cp) && (cp == 0x10FC00ul));
    /* Swapped halves are refused */
    SSF_ASSERT(SSFUTF8FromUTF16Pair(0xDE00u, 0xD83Du, &cp) == false);
}

/* --------------------------------------------------------------------------------------------- */
/* Asserts that every interface refuses NULL pointers.                                           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFUTF8UTContracts(void)
{
    static uint32_t cp;
    static size_t count;
    static size_t seqLen;

    SSF_ASSERT_TEST(SSFUTF8DecodeNext(NULL, 1u, &cp, &seqLen));
    SSF_ASSERT_TEST(SSFUTF8DecodeNext((const uint8_t *)"a", 1u, NULL, &seqLen));
    SSF_ASSERT_TEST(SSFUTF8DecodeNext((const uint8_t *)"a", 1u, &cp, NULL));
    SSF_ASSERT_TEST(SSFUTF8IsValid(NULL, 0u, true));
    SSF_ASSERT_TEST(SSFUTF8EncodeCP(0x41ul, NULL, 4u, &seqLen));
    SSF_ASSERT_TEST(SSFUTF8EncodeCP(0x41ul, _ssfUTF8UTBuf, 4u, NULL));
    SSF_ASSERT_TEST(SSFUTF8FromUTF16Pair(0xD800u, 0xDC00u, NULL));
    SSF_ASSERT_TEST(SSFUTF8Count(NULL, 0u, &count));
    SSF_ASSERT_TEST(SSFUTF8Count((const uint8_t *)"a", 1u, NULL));
}

/* --------------------------------------------------------------------------------------------- */
/* Performs the UTF-8 codec unit test.                                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFUTF8UnitTest(void)
{
    _SSFUTF8UTKnown();
    _SSFUTF8UTStrings();
    _SSFUTF8UTPairs();
    _SSFUTF8UTEncode();
    _SSFUTF8UTExhaustive();
    _SSFUTF8UTContracts();
}
#endif /* SSF_CONFIG_UTF8_UNIT_TEST */
