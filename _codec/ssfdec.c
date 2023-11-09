/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfdec.c                                                                                      */
/* Provides integer to decimal string conversion interface.                                      */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2022 Supurloop Software LLC                                                         */
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
#include "ssfport.h"
#include "ssfdec.h"

/* --------------------------------------------------------------------------------------------- */
/* Module constants                                                                              */
/* --------------------------------------------------------------------------------------------- */
static const char *_ssfDecConv =
    "00010203040506070809"
    "10111213141516171819"
    "20212223242526272829"
    "30313233343536373839"
    "40414243444546474849"
    "50515253545556575859"
    "60616263646566676869"
    "70717273747576777879"
    "80818283848586878889"
    "90919293949596979899";

#define SSF_DEC_NUM_LIM (SSF_DEC_MAX_STR_LEN - 1)
static const uint64_t _ssfDecStrSizeLim[SSF_DEC_NUM_LIM] =
{ 
    9ull, 99ull, 999ull, 9999ull, 99999ull, 999999ull, 9999999ull, 99999999ull, 999999999ull,
    9999999999ull, 99999999999ull, 999999999999ull, 9999999999999ull, 99999999999999ull,
    999999999999999ull, 9999999999999999ull, 99999999999999999ull, 999999999999999999ull,
    9999999999999999999ull
};

/* --------------------------------------------------------------------------------------------- */
/* Returns number of digits written to str.                                                      */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFDecUIntToStr(uint64_t i, char *str)
{
    uint16_t o;

    if (i >= 10000)
    {
        size_t len;

        len = _SSFDecUIntToStr(i / 10000, str);
        str += len;
        i %= 10000;
        o = (uint16_t)((i / 100) << 1);
        *str++ = _ssfDecConv[o++];
        *str++ = _ssfDecConv[o];
        o = (i % 100) << 1;
        *str++ = _ssfDecConv[o++];
        *str = _ssfDecConv[o];
        return len + 4;
    }

    if (i >= 1000)
    {
        o = (uint16_t)((i / 100) << 1);
        *str++ = _ssfDecConv[o++];
        *str++ = _ssfDecConv[o];
        o = (i % 100) << 1;
        *str++ = _ssfDecConv[o++];
        *str = _ssfDecConv[o];
        return 4;
    }
    else if (i >= 100)
    {
        *str++ = ((char)(i / 100)) + '0';
        o = (i % 100) << 1;
        *str++ = _ssfDecConv[o++];
        *str = _ssfDecConv[o];
        return 3;
    }
    else if (i >= 10)
    {
        o = (uint16_t)(i << 1);
        *str++ = _ssfDecConv[o++];
        *str = _ssfDecConv[o];
        return 2;
    }
    *str = ((char)i) + '0';
    return 1;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns 0 if unable to convert i to decimal string, else number of bytes written to string.   */
/* --------------------------------------------------------------------------------------------- */
size_t SSFDecUIntToStr(uint64_t i, SSFCStrOut_t str, size_t strSize)
{
    char *tmp;

    SSF_ASSERT(str != NULL);

    /* Ensure that strSize big enough to fit i plus a NULL */
    if ((strSize <= 1) || ((strSize < (SSF_DEC_NUM_LIM + 2)) &&
                           (i > _ssfDecStrSizeLim[strSize - 2]))) { return 0; }

    /* Save str ptr, convert and advance str by dec str len, NULL terminate */
    tmp = str;
    str += _SSFDecUIntToStr(i, str);
    *str = 0;

    /* Return len (does not include NULL) */
    return (size_t)(str - tmp);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns 0 if unable to convert i to decimal string, else number of bytes written to string.   */
/* --------------------------------------------------------------------------------------------- */
size_t SSFDecIntToStr(int64_t i, SSFCStrOut_t str, size_t strSize)
{
    char *tmp;
    uint64_t u;

    SSF_ASSERT(str != NULL);

    if (i < 0)
    {
        /* Ensure that strSize big enough to fit -i plus a NULL */
        u = -i;
        if ((strSize <= 2) || ((strSize < (SSF_DEC_NUM_LIM + 3)) &&
                               (u > _ssfDecStrSizeLim[strSize - 3])))
        { return 0; }
        tmp = str;
        *str++ = '-';
        strSize--;
    }
    else
    {
        /* Ensure that strSize big enough to fit i plus a NULL */
        u = i;
        if ((strSize <= 1) || ((strSize < (SSF_DEC_NUM_LIM + 2)) &&
                               (u > _ssfDecStrSizeLim[strSize - 2])))
        { return 0; }
        tmp = str;
    }

    /* Convert and advance str by dec str len, NULL terminate */
    str += _SSFDecUIntToStr(u, str);
    *str = 0;

    /* Return len (does not include NULL) */
    return (size_t)(str - tmp);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns 0 if unable to convert i to decimal string, else number of bytes written to string.   */
/* --------------------------------------------------------------------------------------------- */
size_t SSFDecUIntToStrPadded(uint64_t i, SSFCStrOut_t str, size_t strSize, uint8_t minFieldWidth,
                             char padChar)
{
    size_t len;

    SSF_ASSERT(str != NULL);
    SSF_ASSERT(minFieldWidth >= 2);

    /* Have to fit minimum field width */
    if (minFieldWidth >= strSize) return 0;

    /* Do int to decimal string conversion */
    len = SSFDecUIntToStr(i, str, strSize);
    if (len == 0) return 0;

    /* Add pad if necessary */
    if (len < minFieldWidth)
    {
        char *dst;
        char *src;
        size_t padLen = minFieldWidth - len;

        /* Move decimal string by padLen */
        src = str + len;
        dst = src + padLen;
        do
        {
            *dst-- = *src--;
        } while (src != str);
        *dst = *src;

        /* Pad decimal string with padChar */
        memset(str, padChar, padLen);
        len += padLen;
    }
    return len;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns 0 if unable to convert i to decimal string, else number of bytes written to string.   */
/* --------------------------------------------------------------------------------------------- */
size_t SSFDecIntToStrPadded(int64_t i, SSFCStrOut_t str, size_t strSize, uint8_t minFieldWidth,
                            char padChar)
{
    size_t len;
    char *tmp = NULL;

    SSF_ASSERT(str != NULL);
    SSF_ASSERT(minFieldWidth >= 2);

    /* Have to fit minimum field width */
    if (minFieldWidth >= strSize) return 0;
    if (i < 0)
    {
        tmp = str;
        str++;
        strSize--;
        i = -i;
        minFieldWidth--;
    }

    /* Do int to decimal string conversion */
    len = SSFDecUIntToStr((uint64_t)i, str, strSize);
    if (len == 0) return 0;

    /* Add pad if necessary */
    if (len < minFieldWidth)
    {
        char *dst;
        char *src;
        size_t padLen = minFieldWidth - len;

        /* Move decimal string by padLen */
        src = str + len;
        dst = src + padLen;
        do
        {
            *dst-- = *src--;
        } while (src != str);
        *dst = *src;

        /* Pad decimal string with padChar */
        memset(str, padChar, padLen);
        len += padLen;
    }

    /* Place - if i was negative */
    if (tmp != NULL)
    {
        *tmp = '-';
        len++;
    }

    return len;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and val set to str's signed integer value, else false.                           */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFDecStrToInt(SSFCStrIn_t str, int64_t *val, SSFCStrIn_t *next, uint8_t *numDigits)
{
    #define SSF_DEC_MAX_SIGNED_DIGITS (19u)

    bool isNeg = false;
    uint64_t u64 = 0;
    uint8_t power = 0;
    char final = '7';

    SSF_REQUIRE(str != NULL);
    SSF_REQUIRE(val != NULL);

    /* Ignore leading whitespace */
    while ((*str != 0) && ((*str == ' ') || (*str == '\t'))) str++;
    if (*str == 0) return false;

    /* Look for - sign */
    if (*str == '-')
    {
        isNeg = true;
        final = '8';
        str++;
    }

    /* Must be at least 1 digit */
    if ((*str < '0') || (*str > '9')) return false;

    /* Process decimal digits */
    while (*str != 0)
    {
        /* Valid digit? */
        if ((*str >= '0') && (*str <= '9'))
        {
            /* Yes, overflow? */
            if ((power == (SSF_DEC_MAX_SIGNED_DIGITS - 1)) &&
                ((u64 > 922337203685477580) || (*str > final)))
                return false;
            if (power == SSF_DEC_MAX_SIGNED_DIGITS) return false;

            /* Accumulate digit and advance to next */
            u64 *= 10;
            u64 += (((uint64_t)*str) - '0');
            str++;
            power++;
            if (numDigits != NULL) (*numDigits)++;
        }
        /* No, considered the end of the number */
        else break;
    }

    /* Adjust sign */
    if (isNeg) *val = -((int64_t)u64);
    else *val = (int64_t)u64;
    if (next != NULL) *next = str;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and val set to str's unsigned integer value, else false.                         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFDecStrToUInt(SSFCStrIn_t str, uint64_t* val, SSFCStrIn_t* next, uint8_t* numDigits)
{
    #define SSF_DEC_MAX_UNSIGNED_DIGITS (20u)

    uint64_t u64 = 0;
    uint8_t power = 0;

    SSF_REQUIRE(str != NULL);
    SSF_REQUIRE(val != NULL);

    /* Ignore leading whitespace */
    while ((*str != 0) && ((*str == ' ') || (*str == '\t'))) str++;
    if (*str == 0)
        return false;

    /* Must be at least 1 digit */
    if ((*str < '0') || (*str > '9'))
        return false;

    /* Process decimal digits */
    if (numDigits != NULL) *numDigits = 0;
    while (*str != 0)
    {
        /* Valid digit? */
        if ((*str >= '0') && (*str <= '9'))
        {
            /* Yes, overflow? */
            if ((power == (SSF_DEC_MAX_UNSIGNED_DIGITS - 1)) &&
                ((u64 > 1844674407370955161) || (*str > '5')))
                return false;
            if (power == SSF_DEC_MAX_UNSIGNED_DIGITS) return false;

            /* Accumulate digit and advance to next */
            u64 *= 10;
            u64 += (((uint64_t)*str) - '0');
            str++;
            power++;
            if (numDigits != NULL) (*numDigits)++;
        }
        /* No, considered the end of the number */
        else break;
    }
    *val = u64;
    if (next != NULL) *next = str;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true and val set to str's signed integer value, else false.                           */
/* --------------------------------------------------------------------------------------------- */
bool SSFDecStrToXInt(SSFCStrIn_t str, int64_t *sval, uint64_t *uval)
{
    uint64_t i;
    int64_t sbase;
    uint64_t base;
    SSFCStrIn_t next;
    uint64_t tmp;
    bool negBase = false;
    bool negExp = false;
    uint64_t exponent = 0;
    uint64_t fraction = 0;
    uint8_t fractionDigits = 0;

    SSF_REQUIRE(str != NULL);
    SSF_REQUIRE(((sval != NULL) && (uval == NULL)) ||
                ((sval == NULL) && (uval != NULL)));

    /* Determine base */
    if (sval != NULL)
    {
        if (_SSFDecStrToInt(str, &sbase, &next, NULL) == false) return false;
        if (sbase < 0)
        {
            negBase = true;
            base = -sbase;
        }
        else base = sbase;
    }
    else
    {
        if (_SSFDecStrToUInt(str, &base, &next, NULL) == false) return false;
    }

    /* Is fraction present? */
    if (*next == '.')
    {
        /* Yes, determine fraction */
        next++;
        if (_SSFDecStrToUInt(next, &fraction, &next, &fractionDigits) == false) return false;
    }

    /* Is exponent present? */
    if (*next == 'e' || *next == 'E')
    {
        /* Yes, determine exponent */
        next++;
        if (*next == 0) return false;
        if (*next == '-') { next++; negExp = true; }
        else if (*next == '+') { next++; }
        if (_SSFDecStrToUInt(next, &exponent, &next, NULL) == false) return false;
    }

    /* Is negative exponent? */
    if (negExp)
    {
        /* Yes, fraction is not relevant and base must be scaled */
        fraction = 0;
        while (exponent)
        {
            base /= 10;
            if (base == 0) break;
            exponent--;
        }
    }
    else
    {
        /* No, must scale fraction and base */

        /* Round fraction if necessary */
        if (fractionDigits > exponent) i = ((uint64_t)fractionDigits) - exponent;
        else i = 0;
        while (i)
        {
            fraction /= 10;
            if (fraction == 0) break;
            i--;
        }

        /* Scale fraction if necessary */
        if (exponent > 1)
        {
            if (fractionDigits > exponent) i = ((uint64_t)fractionDigits) - exponent - 1;
            else i = exponent - fractionDigits;
            tmp = fraction;
            while (i)
            {
                tmp *= 10;

                /* Overflow? */
                if ((tmp / 10) != fraction) return false;

                fraction = tmp;
                i--;
            }
        }

        /* Scale base */
        tmp = base;
        while (exponent)
        {
            tmp *= 10;

            /* Check for overflow */
            if ((tmp / 10) != base) return false;

            base = tmp;
            exponent--;
        }
    }

    /* Compute final integer value */
    if (sval != NULL)
    {
        tmp = base + fraction;

        /* Check for overflow */
        if ((tmp < base) || (tmp < fraction)) return false;

        /* Make negative as necessary */
        if (negBase)
        {
            /* Check for signed overflow */
            if (tmp > 9223372036854775808ll) return false;
            *sval = -((int64_t)tmp);
        }
        else
        {
            /* Check for signed overflow */
            if (tmp > 9223372036854775807ll) return false;
            *sval = (int64_t)tmp;
        }
    }
    else
    {
        *uval = base + fraction;

        /* Check for overflow */
        if ((*uval < base) || (*uval < fraction)) return false;
    }

    return true;
}

