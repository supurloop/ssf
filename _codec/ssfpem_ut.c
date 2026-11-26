/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpem_ut.c                                                                                   */
/* Provides unit tests for the PEM block decoder.                                                */
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
#include <stdio.h>
#include <string.h>
#include "ssfpem.h"
#include "ssfport.h"

#if SSF_CONFIG_PEM_UNIT_TEST == 1

/* Decodes text as one call; returns the result and fills the outputs. */
static SSFPEMResult_t _UTDecode(const char *textStr, size_t *pos, const char **label,
                                size_t *labelLen, uint8_t *der, size_t derSize, size_t *derLen)
{
    SSF_REQUIRE(textStr != NULL);
    SSF_REQUIRE(pos != NULL);
    SSF_REQUIRE(label != NULL);
    SSF_REQUIRE(labelLen != NULL);
    SSF_REQUIRE(derLen != NULL);

    return SSFPEMDecodeNext(textStr, strlen(textStr), pos, label, labelLen, der, derSize, derLen);
}

/* True if every byte of buf is zero. */
static bool _UTAllZero(const uint8_t *buf, size_t bufSize)
{
    size_t i;

    SSF_REQUIRE(buf != NULL);

    for (i = 0; i < bufSize; i++)
    {
        if (buf[i] != 0u) return false;
    }
    return true;
}

/* Expects textStr to fail with result r, leave *pos at 0 and zero the output buffer. */
static void _UTExpectErr(const char *textStr, SSFPEMResult_t r, size_t derSize)
{
    uint8_t der[64];
    size_t pos = 0;
    const char *label = NULL;
    size_t labelLen = 0;
    size_t derLen = 0;

    SSF_REQUIRE(textStr != NULL);
    SSF_REQUIRE(derSize <= sizeof(der));

    memset(der, 0xAA, sizeof(der));
    SSF_ASSERT(_UTDecode(textStr, &pos, &label, &labelLen, der, derSize, &derLen) == r);
    SSF_ASSERT(pos == 0u);
    SSF_ASSERT(_UTAllZero(der, derSize));
}

/* Scratch-wipe hook: records whether every exit left the decoder's scratch zeroed. */
static uint32_t _utScrubCalls;
static bool _utScrubDirty;
static void _UTScrubHook(const char *quad, size_t quadSize, const uint8_t *tri, size_t triSize)
{
    SSF_REQUIRE(quad != NULL);
    SSF_REQUIRE(tri != NULL);

    _utScrubCalls++;
    /* Any scratch byte left non-zero? */
    if ((!_UTAllZero((const uint8_t *)quad, quadSize)) || (!_UTAllZero(tri, triSize)))
    {
        /* Yes, record the leak */
        _utScrubDirty = true;
    }
}

/* Runs the PEM decoder unit tests. */
void SSFPEMUnitTest(void)
{
    uint8_t der[64];
    size_t pos;
    const char *label;
    size_t labelLen;
    size_t derLen;

    /* ---- One block, then END ---- */
    {
        const char *t = "-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n";
        pos = 0;
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_BLOCK);
        SSF_ASSERT(SSFPEMLabelIs(label, labelLen, "TEST"));
        SSF_ASSERT(label == (t + 11));
        SSF_ASSERT(derLen == 4u);
        SSF_ASSERT((der[0] == 0u) && (der[1] == 1u) && (der[2] == 2u) && (der[3] == 3u));
        SSF_ASSERT(pos == strlen(t));
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_END);
    }

    /* ---- END line at the very end of input, no trailing newline ---- */
    {
        const char *t = "-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----";
        pos = 0;
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_BLOCK);
        SSF_ASSERT((derLen == 4u) && (pos == strlen(t)));
    }

    /* ---- Explanatory text before, CRLF, Base64 split at odd places with spaces and tabs ---- */
    {
        const char *t = "Subject: test key\r\nnot base64 here!\r\n"
                        "-----BEGIN MULTI WORD LABEL-----\r\n"
                        "AA EC\r\n Aw\tQF\r\nBgc=\r\n"
                        "-----END MULTI WORD LABEL-----\r\ntrailer";
        pos = 0;
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_BLOCK);
        SSF_ASSERT(SSFPEMLabelIs(label, labelLen, "MULTI WORD LABEL"));
        SSF_ASSERT(derLen == 8u);
        SSF_ASSERT((der[0] == 0u) && (der[3] == 3u) && (der[7] == 7u));
        SSF_ASSERT(strcmp(t + pos, "trailer") == 0);
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_END);
    }

    /* ---- Two blocks in sequence ---- */
    {
        const char *t = "-----BEGIN ONE-----\nAQ==\n-----END ONE-----\n"
                        "-----BEGIN TWO-----\nAgI=\n-----END TWO-----\n";
        pos = 0;
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_BLOCK);
        SSF_ASSERT((SSFPEMLabelIs(label, labelLen, "ONE")) && (derLen == 1u) && (der[0] == 1u));
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_BLOCK);
        SSF_ASSERT((SSFPEMLabelIs(label, labelLen, "TWO")) && (derLen == 2u) && (der[1] == 2u));
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_END);
    }

    /* ---- NULL output only measures ---- */
    {
        const char *t = "-----BEGIN TEST-----\nAAECAwQF\n-----END TEST-----\n";
        pos = 0;
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, NULL, 0, &derLen) == SSF_PEM_BLOCK);
        SSF_ASSERT((derLen == 6u) && (pos == strlen(t)));
    }

    /* ---- Empty block body ---- */
    {
        const char *t = "-----BEGIN EMPTY-----\n-----END EMPTY-----\n";
        pos = 0;
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_BLOCK);
        SSF_ASSERT(derLen == 0u);
    }

    /* ---- No block at all ---- */
    {
        pos = 0;
        SSF_ASSERT(_UTDecode("", &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_END);
        SSF_ASSERT(_UTDecode("just text\n-----END X-----\n", &pos, &label, &labelLen, der,
                             sizeof(der), &derLen) == SSF_PEM_END);
    }

    /* ---- pemLen bounds the input: a block cut by pemLen is malformed ---- */
    {
        const char *t = "-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n";
        pos = 0;
        memset(der, 0xAA, sizeof(der));
        SSF_ASSERT(SSFPEMDecodeNext(t, (strlen(t) - 6u), &pos, &label, &labelLen, der, sizeof(der),
                                    &derLen) == SSF_PEM_ERR);
        SSF_ASSERT((pos == 0u) && (_UTAllZero(der, sizeof(der))));
    }

    /* ---- Output too small: ERR_SIZE, written bytes zeroed ---- */
    _UTExpectErr("-----BEGIN TEST-----\nAAECAwQF\n-----END TEST-----\n", SSF_PEM_ERR_SIZE, 5u);
    _UTExpectErr("-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n", SSF_PEM_ERR_SIZE, 3u);

    /* ---- Malformed blocks: ERR, nothing left in the output ---- */
    /* END label differs */
    _UTExpectErr("-----BEGIN TEST-----\nAAECAw==\n-----END TESTX-----\n", SSF_PEM_ERR, 64u);
    _UTExpectErr("-----BEGIN TEST-----\nAAECAw==\n-----END TES-----\n", SSF_PEM_ERR, 64u);
    /* No END line */
    _UTExpectErr("-----BEGIN TEST-----\nAAECAw==\n", SSF_PEM_ERR, 64u);
    /* Invalid Base64 character after good data (output must be wiped) */
    _UTExpectErr("-----BEGIN TEST-----\nAAECAwQF*AAA\n-----END TEST-----\n", SSF_PEM_ERR, 64u);
    /* Encapsulated headers (legacy encrypted PEM) are not Base64 */
    _UTExpectErr("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nAAEC\n"
                 "-----END RSA PRIVATE KEY-----\n", SSF_PEM_ERR, 64u);
    /* Data after padding */
    _UTExpectErr("-----BEGIN TEST-----\nAA==AAEC\n-----END TEST-----\n", SSF_PEM_ERR, 64u);
    /* Incomplete final group */
    _UTExpectErr("-----BEGIN TEST-----\nAAECA\n-----END TEST-----\n", SSF_PEM_ERR, 64u);
    /* Non-canonical padding bits */
    _UTExpectErr("-----BEGIN TEST-----\nAB==\n-----END TEST-----\n", SSF_PEM_ERR, 64u);
    /* BEGIN line not closed, or text after its dashes */
    _UTExpectErr("-----BEGIN TEST\nAAECAw==\n-----END TEST-----\n", SSF_PEM_ERR, 64u);
    _UTExpectErr("-----BEGIN TEST-----x\nAAECAw==\n-----END TEST-----\n", SSF_PEM_ERR, 64u);
    _UTExpectErr("-----BEGIN TEST-----AAAA\nAAECAw==\n-----END TEST-----\n", SSF_PEM_ERR, 64u);
    /* Control characters in the label */
    _UTExpectErr("-----BEGIN TE\tST-----\nAAECAw==\n-----END TE\tST-----\n", SSF_PEM_ERR, 64u);
    _UTExpectErr("-----BEGIN TE\x01ST-----\nAAECAw==\n-----END TE\x01ST-----\n", SSF_PEM_ERR,
                 64u);
    /* Text after the END line's dashes */
    _UTExpectErr("-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----x\n", SSF_PEM_ERR, 64u);
    /* Empty label, and a label longer than SSF_PEM_MAX_LABEL_LEN */
    _UTExpectErr("-----BEGIN -----\nAAECAw==\n-----END -----\n", SSF_PEM_ERR, 64u);
    {
        /* Labels of SSF_PEM_MAX_LABEL_LEN (accepted) and one more (refused) */
        char t[200];
        char lab[SSF_PEM_MAX_LABEL_LEN + 2u];
        size_t n;
        for (n = SSF_PEM_MAX_LABEL_LEN; n <= (SSF_PEM_MAX_LABEL_LEN + 1u); n++)
        {
            memset(lab, 'K', n);
            lab[n] = 0;
            SSF_ASSERT((snprintf(t, sizeof(t), "-----BEGIN %s-----\nAAECAw==\n-----END %s-----\n",
                                 lab, lab)) < ((int)sizeof(t)));
            /* Label at the maximum length? */
            if (n == SSF_PEM_MAX_LABEL_LEN)
            {
                /* Yes, it decodes */
                pos = 0;
                SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                           SSF_PEM_BLOCK);
                SSF_ASSERT(labelLen == SSF_PEM_MAX_LABEL_LEN);
            }
            else
            {
                /* No, one over the maximum is refused */
                _UTExpectErr(t, SSF_PEM_ERR, 64u);
            }
        }
    }

    /* ---- A malformed block leaves *pos where it was ---- */
    {
        const char *t = "-----BEGIN ONE-----\nAQ==\n-----END ONE-----\n"
                        "-----BEGIN TWO-----\nA*==\n-----END TWO-----\n";
        size_t first;
        pos = 0;
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_BLOCK);
        first = pos;
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_ERR);
        SSF_ASSERT(pos == first);
    }

    /* ---- BEGIN and END lines must start a line ---- */
    {
        const char *t;
        /* Mid-line BEGIN is text */
        pos = 0;
        t = "x-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n";
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_END);
        /* Indented BEGIN is text */
        pos = 0;
        t = " -----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n";
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_END);
        /* The real BEGIN after a mid-line one is found */
        pos = 0;
        t = "see -----BEGIN NOTE-----\n-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n";
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_BLOCK);
        SSF_ASSERT((SSFPEMLabelIs(label, labelLen, "TEST")) && (derLen == 4u));
        /* CR-only lines */
        pos = 0;
        t = "-----BEGIN TEST-----\rAAECAw==\r-----END TEST-----\r";
        SSF_ASSERT(_UTDecode(t, &pos, &label, &labelLen, der, sizeof(der), &derLen) ==
                   SSF_PEM_BLOCK);
        SSF_ASSERT((derLen == 4u) && (pos == strlen(t)));
    }
    /* END right after Base64 on the same line, or indented */
    _UTExpectErr("-----BEGIN TEST-----\nAAECAw==-----END TEST-----\n", SSF_PEM_ERR, 64u);
    _UTExpectErr("-----BEGIN TEST-----\nAAECAw==\n  -----END TEST-----\n", SSF_PEM_ERR, 64u);
    _UTExpectErr("-----BEGIN TEST-----\nAAECAw==\t-----END TEST-----\n", SSF_PEM_ERR, 64u);

    /* ---- Every exit leaves the decoder's scratch zeroed (success, END, errors) ---- */
    {
        /* Success, success padded, partial group, bad character, no END, no block */
        static const char *cases[] = {
            "-----BEGIN TEST-----\nQUJD\n-----END TEST-----\n",
            "-----BEGIN TEST-----\nQUJDQUI=\n-----END TEST-----\n",
            "-----BEGIN TEST-----\nQUJDQU\n-----END TEST-----\n",
            "-----BEGIN TEST-----\nQUJD*UJD\n-----END TEST-----\n",
            "-----BEGIN TEST-----\nQUJDQUJD\n",
            "no block here\n" };
        size_t k;
        _ssfPEMUTScrubHook = _UTScrubHook;
        for (k = 0; k < (sizeof(cases) / sizeof(cases[0])); k++)
        {
            _utScrubCalls = 0;
            _utScrubDirty = false;
            pos = 0;
            (void)_UTDecode(cases[k], &pos, &label, &labelLen, der, sizeof(der), &derLen);
            SSF_ASSERT((_utScrubCalls == 1u) && (!_utScrubDirty));
            /* Output too small for ERR_SIZE */
            _utScrubCalls = 0;
            pos = 0;
            (void)_UTDecode(cases[k], &pos, &label, &labelLen, der, 2u, &derLen);
            SSF_ASSERT((_utScrubCalls == 1u) && (!_utScrubDirty));
        }
        _ssfPEMUTScrubHook = NULL;
    }

    /* ---- SSFPEMLabelIs ---- */
    SSF_ASSERT(SSFPEMLabelIs("PRIVATE KEY", 11u, "PRIVATE KEY"));
    SSF_ASSERT(!SSFPEMLabelIs("PRIVATE KEY", 11u, "PRIVATE KE"));
    SSF_ASSERT(!SSFPEMLabelIs("PRIVATE KEY", 10u, "PRIVATE KEY"));
    SSF_ASSERT(!SSFPEMLabelIs("EC PRIVATE KEY", 14u, "PRIVATE KEY"));
}
#endif /* SSF_CONFIG_PEM_UNIT_TEST */
