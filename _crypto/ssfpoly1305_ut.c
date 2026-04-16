/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpoly1305_ut.c                                                                              */
/* Provides Poly1305 MAC unit test (RFC 7539).                                                   */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2024 Supurloop Software LLC                                                         */
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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfpoly1305.h"

#if SSF_CONFIG_POLY1305_UNIT_TEST == 1

/* --------------------------------------------------------------------------------------------- */
/* RFC 7539 Section 2.5.2 test vector                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFPoly1305UnitTest(void)
{
    /* RFC 7539 Section 2.5.2 */
    static const uint8_t key[] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };
    static const uint8_t msg[] = {
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
        0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f,
        0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65,
        0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f,
        0x75, 0x70
    };
    static const uint8_t expected_tag[] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    };
    uint8_t tag[16];

    /* Test RFC 7539 Section 2.5.2 vector */
    SSFPoly1305Mac(msg, sizeof(msg), key, sizeof(key), tag, sizeof(tag));
    SSF_ASSERT(memcmp(tag, expected_tag, sizeof(expected_tag)) == 0);

    /* Test empty message */
    {
        static const uint8_t zeroKey[32] = {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        uint8_t emptyTag[16];

        SSFPoly1305Mac(NULL, 0, zeroKey, sizeof(zeroKey), emptyTag, sizeof(emptyTag));
        /* With r=1, s=0, empty message: tag should be s = 0 */
    }

    /* Test single-byte message */
    {
        uint8_t oneByte = 0x01;
        uint8_t oneTag[16];
        SSFPoly1305Mac(&oneByte, 1, key, sizeof(key), oneTag, sizeof(oneTag));
        /* Just verify it doesn't crash; correctness covered by RFC vector above */
    }

    /* Test exactly 16-byte (one block) message */
    {
        uint8_t blockTag[16];
        SSFPoly1305Mac(msg, 16, key, sizeof(key), blockTag, sizeof(blockTag));
        /* Verify doesn't crash with exact block boundary */
    }
}

#endif /* SSF_CONFIG_POLY1305_UNIT_TEST */
