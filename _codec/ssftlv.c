/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftlv.c                                                                                      */
/* Provides encode/decoder interface for TAG/LENGTH/VALUE (aka TLV) data structures.             */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2021 Supurloop Software LLC                                                         */
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
#include "ssfport.h"
#include "ssfassert.h"
#include "ssftlv.h"

/* --------------------------------------------------------------------------------------------- */
/* SSF_TLV_ENABLE_FIXED_MODE == 1                                                                */
/* --------------------------------------------------------------------------------------------- */
/* Every TLV field in the TLV buffer is composed of a 1 byte TAG, followed by a 1 byte LEN,      */
/* followed by 0-255 LEN bytes of VALUE.                                                         */
/* Every TLV field in the TLV buffer may be followed immediately by another TLV field.           */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* SSF_TLV_ENABLE_FIXED_MODE == 0                                                                */
/* --------------------------------------------------------------------------------------------- */
/* Every TLV field in the TLV buffer is composed of a variable 1-4 byte TAG, followed by a       */
/* variable 1-4 byte LEN, followed by 0-2^30-1 LEN bytes of value.                               */
/* Every TLV field in the TLV buffer may be followed immediately by another TLV field.           */
/* The TAG and LEN are encoded in Big Endian byte order in the TLV buffer.                       */
/* The 2 most significant bits of TAG and LEN indicate the number of bytes used to represent TAG */
/* and LEN.                                                                                      */
/* TAG and LEN are encoded with the minimum number of bytes that can properly represent their    */
/* values.                                                                                       */
/* When both the values of TAG and LEN are < 64 then the TLV field encoding is the same as if    */
/* SSF_TLV_ENABLE_FIXED_MODE == 1.                                                               */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Local defines.                                                                                */
/* --------------------------------------------------------------------------------------------- */
#define _SSF_TLV_PUT_VAR_FIELD(tlv, v, vLen) \
    tlv->buf[tlv->bufLen] = ((vLen - 1) << 6); \
    if (v < 64ul) { \
        tlv->buf[tlv->bufLen] += (uint8_t)(v & 0xff); } \
    else if (v < 16384ul) { \
        tlv->buf[tlv->bufLen] += (v >> 8) & 0xff; \
        tlv->buf[tlv->bufLen + 1] = v & 0xff; } \
    else if (v < 4194304ul) { \
        tlv->buf[tlv->bufLen] += (v >> 16) & 0xff; \
        tlv->buf[tlv->bufLen + 1] = (v >> 8) & 0xff; \
        tlv->buf[tlv->bufLen + 2] = v & 0xff; } \
    else { \
        tlv->buf[tlv->bufLen] += (v >> 24) & 0xff; \
        tlv->buf[tlv->bufLen + 1] = (v >> 16) & 0xff; \
        tlv->buf[tlv->bufLen + 2] = (v >> 8) & 0xff; \
        tlv->buf[tlv->bufLen + 3] = v & 0xff; }

#define _SSF_TLV_GET_VAR_FIELD(tlv, index, v, vLen) \
    vLen = (tlv->buf[index] >> 6) + 1; \
    if (vLen > remaining) break; \
    v = tlv->buf[index] & 0x3f; \
    if (vLen >= 2) v = (v << 8) + tlv->buf[index + 1]; \
    if (vLen >= 3) v = (v << 8) + tlv->buf[index + 2]; \
    if (vLen == 4) v = (v << 8) + tlv->buf[index + 3];

#define _SSF_TLV_FIELD_CALC_LEN(v) (v < 64ul) ? 1 : ((v < 16384ul) ? 2: ((v < 4194304ul) ? 3 : 4))
#define _SSF_TLV_FIELD_READ_LEN(tlv, index, v) v = (tlv->buf[index] >> 6) + 1
#define _SSF_TLV_MAGIC (0x544C5621ul)

/* --------------------------------------------------------------------------------------------- */
/* Initializes a TLV data structure.                                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFTLVInit(SSFTLV_t *tlv, uint8_t *buf, uint32_t bufSize, uint32_t bufLen)
{
    SSF_REQUIRE(tlv != NULL);
    SSF_REQUIRE(tlv->magic != _SSF_TLV_MAGIC);
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(bufLen < bufSize);

    tlv->buf = buf;
    tlv->bufSize = bufSize;
    tlv->bufLen = bufLen;
    tlv->magic = _SSF_TLV_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes a TLV data structure.                                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFTLVDeInit(SSFTLV_t *tlv)
{
    SSF_REQUIRE(tlv != NULL);
    SSF_REQUIRE(tlv->magic == _SSF_TLV_MAGIC);

    memset(tlv, 0, sizeof(SSFTLV_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if val successfully put item into TLV, else false.                              */
/* --------------------------------------------------------------------------------------------- */
bool SSFTLVPut(SSFTLV_t *tlv, SSFTLVVar_t tag, const uint8_t *val, SSFTLVVar_t valLen)
{
    uint32_t remaining;
    uint8_t tagLen;
    uint8_t lenLen;

    SSF_REQUIRE(tlv != NULL);
    SSF_REQUIRE(tlv->magic == _SSF_TLV_MAGIC);
    SSF_REQUIRE(val != NULL);

#if SSF_TLV_ENABLE_FIXED_MODE == 0
    SSF_REQUIRE(tag < 1073741824ul);
    SSF_REQUIRE(valLen < 1073741824ul);

    tagLen = _SSF_TLV_FIELD_CALC_LEN(tag);
    lenLen = _SSF_TLV_FIELD_CALC_LEN(valLen);
#else
    tagLen = 1;
    lenLen = 1;
#endif

    SSF_ASSERT(tlv->bufLen <= tlv->bufSize);
    remaining = tlv->bufSize - tlv->bufLen;
    if (remaining >= (tagLen + lenLen + ((uint32_t) valLen)))
    {
#if SSF_TLV_ENABLE_FIXED_MODE == 1
        /* Add TAG field */
        tlv->buf[tlv->bufLen] = tag;
        tlv->bufLen++;

        /* Add LEN field*/
        tlv->buf[tlv->bufLen] = valLen;
        tlv->bufLen++;
#else
        /* Add TAG field */
        _SSF_TLV_PUT_VAR_FIELD(tlv, tag, tagLen);
        tlv->bufLen += tagLen;

        /* Add LEN field*/
        _SSF_TLV_PUT_VAR_FIELD(tlv, valLen, lenLen);
        tlv->bufLen += lenLen;
#endif
        /* Add VALUE field */
        memcpy(&tlv->buf[tlv->bufLen], val, valLen);
        tlv->bufLen += valLen;

        SSF_ENSURE(tlv->bufLen <= tlv->bufSize);
        return true;
    }
    /* No room to put item */
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if val and valLen contain desired TLV instance, else false.                      */
/* --------------------------------------------------------------------------------------------- */
bool SSFTLVRead(const SSFTLV_t *tlv, SSFTLVVar_t tag, uint16_t instance, uint8_t *val,
                uint32_t valSize, uint8_t **valPtr, SSFTLVVar_t *valLen)
{
    uint32_t remaining;
    SSFTLVVar_t curTag;
    SSFTLVVar_t curLen;
    uint8_t tagLen;
    uint8_t lenLen;
    uint32_t index = 0;

    SSF_REQUIRE(tlv != NULL);
    SSF_REQUIRE(tlv->magic == _SSF_TLV_MAGIC);
    SSF_REQUIRE(((val != NULL) && (valPtr == NULL)) ||
                ((val == NULL) && (valSize == 0) && (valPtr != NULL)));
    SSF_REQUIRE(valLen != NULL);

#if SSF_TLV_ENABLE_FIXED_MODE == 0
    SSF_REQUIRE(tag < 1073741824ul);
#else
    tagLen = 1;
    lenLen = 1;
#endif

    SSF_ASSERT(tlv->bufLen <= tlv->bufSize);
    remaining = tlv->bufLen;
    while (index < tlv->bufLen)
    {
#if SSF_TLV_ENABLE_FIXED_MODE == 1
        /* Interpret TAG field */
        if (tagLen > remaining) break;
        curTag = tlv->buf[index];
        index += tagLen;
        remaining -= tagLen;

        /* Interpret LEN field */
        if (lenLen > remaining) break;
        curLen = tlv->buf[index];
        index += tagLen;
        remaining -= tagLen;
#else
        /* Interpret TAG field */
        _SSF_TLV_FIELD_READ_LEN(tlv, index, tagLen);
        if (tagLen > remaining) break;
        _SSF_TLV_GET_VAR_FIELD(tlv, index, curTag, tagLen);
        index += tagLen;
        remaining -= tagLen;

        /* Interpret LEN field */
        _SSF_TLV_FIELD_READ_LEN(tlv, index, lenLen);
        if (lenLen > remaining) break;
        _SSF_TLV_GET_VAR_FIELD(tlv, index, curLen, lenLen);
        index += lenLen;
        remaining -= lenLen;
#endif
        /* Interpret VALUE field */
        if (curLen > remaining) break;

        /* Match desired tag? */
        if (tag == curTag)
        {
            /* Yes, desired instance? */
            if (instance == 0)
            {
                /* Yes, copy to user val buffer? */
                if (val != NULL)
                {
                    /* Yes, enough room in val to store data? */
                    if (curLen > valSize) break;

                    /* Yes, copy data to user val and set len */
                    memcpy(val, &tlv->buf[index], curLen);
                }
                /* No, set user pointer to value */
                else { *valPtr = &tlv->buf[index]; }
                
                /* Pass back value length */
                *valLen = curLen;
                return true;
            }
            /* No, decrement */
            else { instance--; }
        }
        index += curLen;
        remaining -= curLen;
    }
    return false;
}
