/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpem_ut.c                                                                                   */
/* Provides unit tests for the PEM block encoder and decoder.                                    */
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

/* OpenSSL 4.0.3 output, used to check that SSFPEMEncode() reproduces it byte for byte:          */
/*   openssl ecparam -name prime256v1 -genkey -noout -out k.pem                                  */
/*   openssl req -x509 -key k.pem -subj "/CN=ssfpem test" -days 3650 -out crt.pem  (356 B DER)  */
/*   openssl req -new -key k.pem -subj "/CN=ssfpem test" -out csr.pem              (211 B DER)  */
/* 356 = 7 * 48 + 20 ends in "=", 211 = 4 * 48 + 19 ends in "==".                               */
static const char _utCertPem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBYDCCAQagAwIBAgIUVpTfX88GohZtSBEoqT5HXHT0VmIwCgYIKoZIzj0EAwIw\n"
    "FjEUMBIGA1UEAwwLc3NmcGVtIHRlc3QwHhcNMjYxMTI2MjAxNTQzWhcNMzYxMTIz\n"
    "MjAxNTQzWjAWMRQwEgYDVQQDDAtzc2ZwZW0gdGVzdDBZMBMGByqGSM49AgEGCCqG\n"
    "SM49AwEHA0IABJQvAJZQqnOy3bZs159xAhRGcclkAXC0bYYlNg402Uc7Hr90IR9x\n"
    "qS9eLg1rQw7CU4cAm7dm9KXpKgtD+vNpy4GjMjAwMB0GA1UdDgQWBBRty0VievVS\n"
    "bg5Wl0fTEC75BxIfIzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUC\n"
    "IDiBrFrOsIEhLFaAyB2BDWX42R3C2h2L6AtxbN44si/7AiEA+4qLXlYgrhnH3eSo\n"
    "iVJe010yGop8LCkKMV1X17qNl24=\n"
    "-----END CERTIFICATE-----\n";
static const char _utCsrPem[] =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIHQMHgCAQAwFjEUMBIGA1UEAwwLc3NmcGVtIHRlc3QwWTATBgcqhkjOPQIBBggq\n"
    "hkjOPQMBBwNCAASULwCWUKpzst22bNefcQIURnHJZAFwtG2GJTYONNlHOx6/dCEf\n"
    "cakvXi4Na0MOwlOHAJu3ZvSl6SoLQ/rzacuBoAAwCgYIKoZIzj0EAwIDSAAwRQIg\n"
    "PyEXqoXuJviwxvm1YJHI/53POdH6obb8UNzPksOzyTACIQCSrSIjBXZowqqJrhKF\n"
    "XftqouEFyrbQ95oUP6HFqcocnw==\n"
    "-----END CERTIFICATE REQUEST-----\n";

/* Largest input the encode checks use. */
#define SSF_PEM_UT_MAX_DER (320u)

/* True if ch may appear in an encoded Base64 line. */
static bool _UTIsB64Char(char ch)
{
    return (((ch >= 'A') && (ch <= 'Z')) || ((ch >= 'a') && (ch <= 'z')) ||
            ((ch >= '0') && (ch <= '9')) || (ch == '+') || (ch == '/') || (ch == '='));
}

/* Encodes der[0..derLen) under labelStr and checks its size, layout, padding and round trip. */
static void _UTEncodeCheck(const char *labelStr, const uint8_t *der, size_t derLen)
{
    static char pem[SSF_PEM_ENCODE_SIZE(SSF_PEM_MAX_LABEL_LEN, SSF_PEM_UT_MAX_DER) + 1u];
    uint8_t out[SSF_PEM_UT_MAX_DER];
    size_t labelLen;
    size_t need = 0;
    size_t len = 0;
    size_t p;
    size_t left;
    size_t pos = 0;
    const char *outLabel = NULL;
    size_t outLabelLen = 0;
    size_t outLen = 0;

    SSF_REQUIRE(labelStr != NULL);
    SSF_REQUIRE(derLen <= SSF_PEM_UT_MAX_DER);
    labelLen = strlen(labelStr);
    SSF_REQUIRE(labelLen <= SSF_PEM_MAX_LABEL_LEN);

    /* Measure, then encode into a buffer of exactly the reported size */
    SSF_ASSERT(SSFPEMEncode(labelStr, der, derLen, NULL, 0, &need));
    SSF_ASSERT(need == (SSF_PEM_ENCODE_SIZE(labelLen, derLen) - 1u));
    memset(pem, 0xAA, sizeof(pem));
    SSF_ASSERT(SSFPEMEncode(labelStr, der, derLen, pem, need + 1u, &len));
    SSF_ASSERT((len == need) && (pem[len] == 0) && (strlen(pem) == len));
    SSF_ASSERT((uint8_t)pem[len + 1u] == 0xAAu);

    /* BEGIN line */
    SSF_ASSERT(memcmp(pem, "-----BEGIN ", 11u) == 0);
    SSF_ASSERT(memcmp(&pem[11], labelStr, labelLen) == 0);
    SSF_ASSERT(memcmp(&pem[11u + labelLen], "-----\n", 6u) == 0);
    p = labelLen + 17u;

    /* Body: 64-character lines of 48 bytes, LF-terminated; padding only on the last line */
    for (left = derLen; left > 0u; )
    {
        size_t chunk = (left > 48u) ? 48u : left;
        size_t chars = 4u * ((chunk + 2u) / 3u);
        size_t pad = (3u - (chunk % 3u)) % 3u;
        size_t k;

        for (k = 0; k < chars; k++) SSF_ASSERT(_UTIsB64Char(pem[p + k]));
        for (k = 0; k < (chars - pad); k++) SSF_ASSERT(pem[p + k] != '=');
        for (k = chars - pad; k < chars; k++) SSF_ASSERT(pem[p + k] == '=');
        SSF_ASSERT((chunk == 48u) || (left == chunk));
        SSF_ASSERT(pem[p + chars] == '\n');
        p += chars + 1u;
        left -= chunk;
    }

    /* END line closes the block exactly */
    SSF_ASSERT(memcmp(&pem[p], "-----END ", 9u) == 0);
    SSF_ASSERT(memcmp(&pem[p + 9u], labelStr, labelLen) == 0);
    SSF_ASSERT(memcmp(&pem[p + 9u + labelLen], "-----\n", 6u) == 0);
    SSF_ASSERT((p + labelLen + 15u) == len);

    /* It decodes back to the same label and bytes */
    SSF_ASSERT(SSFPEMDecodeNext(pem, len, &pos, &outLabel, &outLabelLen, out, sizeof(out),
                                &outLen) == SSF_PEM_BLOCK);
    SSF_ASSERT((pos == len) && (outLabelLen == labelLen) && (outLen == derLen));
    SSF_ASSERT(memcmp(outLabel, labelStr, labelLen) == 0);
    SSF_ASSERT((derLen == 0u) || (memcmp(out, der, derLen) == 0));
}

/* True if the decoder accepts labelStr as the label of a block and returns it unchanged. */
static bool _UTDecoderAcceptsLabel(const char *labelStr)
{
    char t[160];
    uint8_t der[8];
    size_t pos = 0;
    const char *label = NULL;
    size_t labelLen = 0;
    size_t derLen = 0;
    int n;

    SSF_REQUIRE(labelStr != NULL);

    n = snprintf(t, sizeof(t), "-----BEGIN %s-----\nAAECAw==\n-----END %s-----\n", labelStr,
                 labelStr);
    SSF_ASSERT((n > 0) && (n < (int)sizeof(t)));
    return ((SSFPEMDecodeNext(t, (size_t)n, &pos, &label, &labelLen, der, sizeof(der),
                              &derLen) == SSF_PEM_BLOCK) &&
            (SSFPEMLabelIs(label, labelLen, labelStr)));
}

/* The encoder accepts labelStr exactly when the decoder does; an accepted one round trips. */
static void _UTLabelMatchesDecoder(const char *labelStr)
{
    static const uint8_t der[4] = { 0u, 1u, 2u, 3u };
    char pem[SSF_PEM_ENCODE_SIZE(SSF_PEM_MAX_LABEL_LEN + 8u, 4u)];
    size_t len;

    SSF_REQUIRE(labelStr != NULL);
    SSF_REQUIRE(strlen(labelStr) <= (SSF_PEM_MAX_LABEL_LEN + 8u));

    /* Does the decoder accept this label? */
    if (_UTDecoderAcceptsLabel(labelStr))
    {
        /* Yes, the encoder must too, and the block must round trip */
        _UTEncodeCheck(labelStr, der, sizeof(der));
    }
    else
    {
        /* No, the encoder must refuse it */
        SSF_ASSERT_TEST(SSFPEMEncode(labelStr, der, sizeof(der), pem, sizeof(pem), &len));
    }
}

/* Decodes the one block of pemStr, re-encodes it and expects the identical text. */
static void _UTReencodeExact(const char *pemStr, const char *labelStr)
{
    static uint8_t der[1024];
    static char pem[2048];
    size_t pos = 0;
    const char *label = NULL;
    size_t labelLen = 0;
    size_t derLen = 0;
    size_t len = 0;

    SSF_REQUIRE(pemStr != NULL);
    SSF_REQUIRE(labelStr != NULL);

    SSF_ASSERT(SSFPEMDecodeNext(pemStr, strlen(pemStr), &pos, &label, &labelLen, der,
                                sizeof(der), &derLen) == SSF_PEM_BLOCK);
    SSF_ASSERT(SSFPEMLabelIs(label, labelLen, labelStr));
    SSF_ASSERT(SSFPEMEncode(labelStr, der, derLen, pem, sizeof(pem), &len));
    SSF_ASSERT((len == strlen(pemStr)) && (strcmp(pem, pemStr) == 0));
}

/* Runs the PEM encoder unit tests. */
static void _UTEncode(void)
{
    static const uint8_t d4[4] = { 0u, 1u, 2u, 3u };
    static uint8_t pattern[SSF_PEM_UT_MAX_DER];
    char pem[128];
    size_t len;
    size_t n;

    for (n = 0; n < sizeof(pattern); n++) pattern[n] = (uint8_t)((n * 37u) + 11u);

    /* ---- Known output: the strings the decoder tests use ---- */
    len = 0;
    SSF_ASSERT(SSFPEMEncode("TEST", d4, sizeof(d4), pem, sizeof(pem), &len));
    SSF_ASSERT(strcmp(pem, "-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n") == 0);
    SSF_ASSERT(len == strlen(pem));
    SSF_ASSERT(SSFPEMEncode("EMPTY", NULL, 0, pem, sizeof(pem), &len));
    SSF_ASSERT(strcmp(pem, "-----BEGIN EMPTY-----\n-----END EMPTY-----\n") == 0);
    SSF_ASSERT(len == strlen(pem));
    SSF_ASSERT(SSFPEMEncode("EMPTY", d4, 0, pem, sizeof(pem), &len));
    SSF_ASSERT(strcmp(pem, "-----BEGIN EMPTY-----\n-----END EMPTY-----\n") == 0);

    /* ---- Every length 0..SSF_PEM_UT_MAX_DER: layout, padding, line breaks, round trip ---- */
    for (n = 0; n <= SSF_PEM_UT_MAX_DER; n++)
    {
        _UTEncodeCheck("CERTIFICATE", pattern, n);
    }
    _UTEncodeCheck("X", NULL, 0);

    /* ---- OpenSSL output reproduced byte for byte ---- */
    _UTReencodeExact(_utCertPem, "CERTIFICATE");
    _UTReencodeExact(_utCsrPem, "CERTIFICATE REQUEST");
    {
        /* SSF_PEM_ENCODE_SIZE as an array size, filled exactly */
        static uint8_t der[356];
        static char certPem[SSF_PEM_ENCODE_SIZE(11u, 356u)];
        size_t pos = 0;
        const char *label;
        size_t labelLen;
        size_t derLen;

        SSF_ASSERT(SSFPEMDecodeNext(_utCertPem, strlen(_utCertPem), &pos, &label, &labelLen, der,
                                    sizeof(der), &derLen) == SSF_PEM_BLOCK);
        SSF_ASSERT(derLen == sizeof(der));
        SSF_ASSERT(sizeof(certPem) == sizeof(_utCertPem));
        SSF_ASSERT(SSFPEMEncode("CERTIFICATE", der, derLen, certPem, sizeof(certPem), &len));
        SSF_ASSERT((len == (sizeof(certPem) - 1u)) && (strcmp(certPem, _utCertPem) == 0));
    }

    /* ---- Output too small: false, length still reported, buffer zeroed, rest untouched ---- */
    {
        static const size_t sizes[] = { 0u, 1u, 2u, 20u, 48u, 49u, 50u };
        size_t need = 0;
        size_t k;
        size_t j;

        SSF_ASSERT(SSFPEMEncode("TEST", d4, sizeof(d4), NULL, 0, &need));
        SSF_ASSERT(need == 49u);
        for (k = 0; k < (sizeof(sizes) / sizeof(sizes[0])); k++)
        {
            memset(pem, 0x5A, sizeof(pem));
            len = 0;
            /* Is this size enough for the block and its NUL? */
            if (sizes[k] > need)
            {
                /* Yes, it encodes */
                SSF_ASSERT(SSFPEMEncode("TEST", d4, sizeof(d4), pem, sizes[k], &len));
                SSF_ASSERT((len == need) && (strlen(pem) == need));
            }
            else
            {
                /* No, it fails, zeroes pem[0..size) and leaves the rest */
                SSF_ASSERT(!SSFPEMEncode("TEST", d4, sizeof(d4), pem, sizes[k], &len));
                SSF_ASSERT(len == need);
                SSF_ASSERT(_UTAllZero((const uint8_t *)pem, sizes[k]));
            }
            for (j = sizes[k]; j < sizeof(pem); j++) SSF_ASSERT(pem[j] == 0x5A);
        }
    }

    /* ---- Labels: the encoder accepts exactly what the decoder accepts ---- */
    {
        static const char *named[] = {
            "X", "CERTIFICATE", "CERTIFICATE REQUEST", "PRIVATE KEY", "EC PRIVATE KEY",
            "RSA PRIVATE KEY", "EC PARAMETERS", "MULTI WORD LABEL", "TEST", "ONE", "TWO",
            "EMPTY", "A-B", "A----B", " X", "X ", "A  B", " ", "-A", "",
            "A-", "-", "--", "-----", "A-----B", "A-----", "-----A", "TE\tST", "TE\x01ST",
            "A\nB", "A\rB", "\x7f", "A\x80", "\xff" };
        char lab[SSF_PEM_MAX_LABEL_LEN + 3u];
        char ch;
        size_t k;
        uint32_t combo;

        for (k = 0; k < (sizeof(named) / sizeof(named[0])); k++) _UTLabelMatchesDecoder(named[k]);

        /* Every one-byte label 0x01..0xFF */
        for (k = 1u; k <= 0xFFu; k++)
        {
            lab[0] = (char)k;
            lab[1] = 0;
            _UTLabelMatchesDecoder(lab);
        }

        /* Every two-character printable label */
        for (k = 0; k < (95u * 95u); k++)
        {
            lab[0] = (char)(' ' + (k / 95u));
            lab[1] = (char)(' ' + (k % 95u));
            lab[2] = 0;
            _UTLabelMatchesDecoder(lab);
        }

        /* Every label of 1..8 characters from { 'A', ' ', '-' }: all runs of dashes and spaces */
        for (n = 1u; n <= 8u; n++)
        {
            uint32_t combos = 1u;
            for (k = 0; k < n; k++) combos *= 3u;
            for (combo = 0; combo < combos; combo++)
            {
                uint32_t c = combo;
                for (k = 0; k < n; k++)
                {
                    ch = "A -"[c % 3u];
                    lab[k] = ch;
                    c /= 3u;
                }
                lab[n] = 0;
                _UTLabelMatchesDecoder(lab);
            }
        }

        /* Lengths SSF_PEM_MAX_LABEL_LEN - 1 .. + 2, plain and ending in '-' */
        for (n = SSF_PEM_MAX_LABEL_LEN - 1u; n <= (SSF_PEM_MAX_LABEL_LEN + 2u); n++)
        {
            memset(lab, 'K', n);
            lab[n] = 0;
            _UTLabelMatchesDecoder(lab);
            lab[n - 1u] = '-';
            _UTLabelMatchesDecoder(lab);
        }
    }

    /* ---- Argument contracts ---- */
    {
        char ov[128];

        SSF_ASSERT_TEST(SSFPEMEncode(NULL, d4, sizeof(d4), pem, sizeof(pem), &len));
        SSF_ASSERT_TEST(SSFPEMEncode("TEST", d4, sizeof(d4), pem, sizeof(pem), NULL));
        SSF_ASSERT_TEST(SSFPEMEncode("TEST", NULL, 1u, pem, sizeof(pem), &len));
        SSF_ASSERT_TEST(SSFPEMEncode("TEST", d4, (SIZE_MAX / 2u) + 1u, pem, sizeof(pem), &len));
        SSF_ASSERT_TEST(SSFPEMEncode("TEST", d4, (SIZE_MAX / 2u) + 1u, NULL, 0, &len));
        /* The largest derLen allowed is measured without overflow */
        SSF_ASSERT(SSFPEMEncode("TEST", d4, SIZE_MAX / 2u, NULL, 0, &len));
        SSF_ASSERT(len == (SSF_PEM_ENCODE_SIZE(4u, SIZE_MAX / 2u) - 1u));
        SSF_ASSERT(len > (SIZE_MAX / 2u));
        /* der inside pem, pem inside der, partial overlap either way */
        memset(ov, 0, sizeof(ov));
        SSF_ASSERT_TEST(SSFPEMEncode("TEST", (const uint8_t *)&ov[10], 4u, ov, sizeof(ov), &len));
        SSF_ASSERT_TEST(SSFPEMEncode("TEST", (const uint8_t *)ov, sizeof(ov), &ov[10], 8u, &len));
        SSF_ASSERT_TEST(SSFPEMEncode("TEST", (const uint8_t *)&ov[0], 12u, &ov[11], 100u, &len));
        SSF_ASSERT_TEST(SSFPEMEncode("TEST", (const uint8_t *)&ov[60], 12u, ov, 61u, &len));
        /* Overlap is checked even when the buffer is too small */
        SSF_ASSERT_TEST(SSFPEMEncode("TEST", (const uint8_t *)&ov[0], 4u, &ov[2], 4u, &len));
        /* Adjacent but not overlapping is fine, on either side */
        memcpy(ov, d4, sizeof(d4));
        SSF_ASSERT(SSFPEMEncode("TEST", (const uint8_t *)ov, 4u, &ov[4], 100u, &len));
        SSF_ASSERT(strcmp(&ov[4], "-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n") == 0);
        memcpy(&ov[100], d4, sizeof(d4));
        SSF_ASSERT(SSFPEMEncode("TEST", (const uint8_t *)&ov[100], 4u, ov, 100u, &len));
        SSF_ASSERT(strcmp(ov, "-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n") == 0);
        /* label inside pem (re-encoding in place over the decoded text) */
        memset(ov, 0, sizeof(ov));
        memcpy(&ov[60], "TEST", 5u);
        SSF_ASSERT_TEST(SSFPEMEncode(&ov[60], d4, sizeof(d4), ov, sizeof(ov), &len));
        SSF_ASSERT_TEST(SSFPEMEncode(&ov[60], d4, sizeof(d4), &ov[63], 65u, &len));
        SSF_ASSERT_TEST(SSFPEMEncode(&ov[60], d4, sizeof(d4), ov, 61u, &len));
        /* label adjacent to pem on either side is fine; its NUL may be overwritten */
        memcpy(ov, "TEST", 5u);
        SSF_ASSERT(SSFPEMEncode(ov, d4, sizeof(d4), &ov[4], 100u, &len));
        SSF_ASSERT(strcmp(&ov[4], "-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n") == 0);
        memcpy(&ov[100], "TEST", 5u);
        SSF_ASSERT(SSFPEMEncode(&ov[100], d4, sizeof(d4), ov, 100u, &len));
        SSF_ASSERT(strcmp(ov, "-----BEGIN TEST-----\nAAECAw==\n-----END TEST-----\n") == 0);
        /* pemSize 0 with NULL pemOpt is only a measure */
        SSF_ASSERT(SSFPEMEncode("TEST", d4, sizeof(d4), NULL, 0, &len) && (len == 49u));
    }
}

/* Runs the PEM decoder and encoder unit tests. */
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

    /* ---- SSFPEMEncode ---- */
    _UTEncode();
}
#endif /* SSF_CONFIG_PEM_UNIT_TEST */
