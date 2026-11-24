/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpem.c                                                                                      */
/* Provides a PEM (RFC 7468) block decoder.                                                      */
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
#include <string.h>
#include "ssfassert.h"
#include "ssfpem.h"
#include "ssfbase64.h"
#include "ssfcrypt.h"

/* --------------------------------------------------------------------------------------------- */
/* Local defines                                                                                 */
/* --------------------------------------------------------------------------------------------- */
#define SSF_PEM_DASHES     "-----"
#define SSF_PEM_DASHES_LEN (5u)
#define SSF_PEM_BEGIN      "-----BEGIN "
#define SSF_PEM_BEGIN_LEN  (11u)
#define SSF_PEM_END_TAG    "-----END "
#define SSF_PEM_END_LEN    (9u)

#if SSF_CONFIG_PEM_UNIT_TEST == 1
void (*_ssfPEMUTScrubHook)(const char *quad, size_t quadSize, const uint8_t *tri,
                           size_t triSize) = NULL;
#endif

/* --------------------------------------------------------------------------------------------- */
/* Returns true if pem[i..i+n) is inside pemLen and equals s.                                    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFPEMAt(const char *pem, size_t pemLen, size_t i, const char *s, size_t n)
{
    return ((pemLen - i) >= n) && (memcmp(&pem[i], s, n) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true for a line-end character.                                                        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFPEMIsEol(char ch)
{
    return (ch == '\n') || (ch == '\r');
}

/* --------------------------------------------------------------------------------------------- */
/* Skips spaces and tabs from i, then requires a line end (CR, LF or CRLF) or, if endOk, the end */
/* of input. Returns the offset past the line end, or 0 if something else follows.               */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFPEMLineEnd(const char *pem, size_t pemLen, size_t i, bool endOk)
{
    while ((i < pemLen) && ((pem[i] == ' ') || (pem[i] == '\t'))) i++;
    if (i == pemLen) return endOk ? i : 0;
    if (pem[i] == '\r')
    {
        i++;
        if ((i < pemLen) && (pem[i] == '\n')) i++;
        return i;
    }
    if (pem[i] == '\n') return i + 1u;
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Decodes the next PEM block at or after *pos; see ssfpem.h.                                    */
/* --------------------------------------------------------------------------------------------- */
SSFPEMResult_t SSFPEMDecodeNext(const char *pem, size_t pemLen, size_t *pos,
                                const char **labelOut, size_t *labelLenOut,
                                uint8_t *derOpt, size_t derSize, size_t *derLenOut)
{
    SSFPEMResult_t result = SSF_PEM_ERR;
    size_t i;
    size_t label;
    size_t labelLen;
    size_t written = 0;
    char quad[4] = { 0 };
    uint8_t quadLen = 0;
    uint8_t tri[3] = { 0 };
    size_t triLen;
    bool padded = false;

    SSF_REQUIRE(pem != NULL);
    SSF_REQUIRE(pos != NULL);
    SSF_REQUIRE(*pos <= pemLen);
    SSF_REQUIRE(labelOut != NULL);
    SSF_REQUIRE(labelLenOut != NULL);
    SSF_REQUIRE(derLenOut != NULL);

    /* Find the next BEGIN line: "-----BEGIN " at the start of a line */
    for (i = *pos; i < pemLen; i++)
    {
        if (((i == 0u) || _SSFPEMIsEol(pem[i - 1u])) &&
            _SSFPEMAt(pem, pemLen, i, SSF_PEM_BEGIN, SSF_PEM_BEGIN_LEN)) break;
    }
    if (i == pemLen) { result = SSF_PEM_END; goto out; }

    /* Label: printable characters up to the closing dashes, on the BEGIN line */
    label = i + SSF_PEM_BEGIN_LEN;
    for (i = label; (i < pemLen) && !_SSFPEMAt(pem, pemLen, i, SSF_PEM_DASHES,
                                                SSF_PEM_DASHES_LEN); i++)
    {
        if ((pem[i] < ' ') || (pem[i] > '~')) goto fail;
    }
    labelLen = i - label;
    if ((i == pemLen) || (labelLen == 0u) || (labelLen > SSF_PEM_MAX_LABEL_LEN)) goto fail;
    i = _SSFPEMLineEnd(pem, pemLen, i + SSF_PEM_DASHES_LEN, false);
    if (i == 0u) goto fail;

    /* Body: Base64 in groups of four characters, whitespace anywhere, up to the END line */
    while (i < pemLen)
    {
        char ch = pem[i];

        if ((ch == ' ') || (ch == '\t') || (ch == '\r') || (ch == '\n')) { i++; continue; }
        if (ch == '-')
        {
            /* Only "-----END <same label>-----" may follow, at the start of a line, after a  */
            /* complete group. i > 0 here: the BEGIN line precedes the body.                  */
            if ((quadLen != 0u) || !_SSFPEMIsEol(pem[i - 1u]) ||
                !_SSFPEMAt(pem, pemLen, i, SSF_PEM_END_TAG, SSF_PEM_END_LEN))
            {
                goto fail;
            }
            i += SSF_PEM_END_LEN;
            if (!_SSFPEMAt(pem, pemLen, i, &pem[label], labelLen)) goto fail;
            i += labelLen;
            if (!_SSFPEMAt(pem, pemLen, i, SSF_PEM_DASHES, SSF_PEM_DASHES_LEN)) goto fail;
            i = _SSFPEMLineEnd(pem, pemLen, i + SSF_PEM_DASHES_LEN, true);
            if (i == 0u) goto fail;

            *pos = i;
            *labelOut = &pem[label];
            *labelLenOut = labelLen;
            *derLenOut = written;
            result = SSF_PEM_BLOCK;
            goto out;
        }

        /* A Base64 character; nothing may follow a padded group */
        if (padded) goto fail;
        quad[quadLen++] = ch;
        i++;
        if (quadLen < 4u) continue;
        quadLen = 0;
        if (!SSFBase64Decode(quad, sizeof(quad), tri, sizeof(tri), &triLen) || (triLen == 0u))
        {
            goto fail;
        }
        if (triLen < 3u) padded = true;
        if (derOpt != NULL)
        {
            if ((derSize - written) < triLen) { result = SSF_PEM_ERR_SIZE; goto fail; }
            memcpy(&derOpt[written], tri, triLen);
        }
        written += triLen;
    }
    /* No END line */

fail:
    if ((derOpt != NULL) && (derSize > 0u)) SSFCryptSecureZero(derOpt, derSize);
out:
    /* The scratch holds key bytes (Base64 and decoded): wipe it on every return */
    SSFCryptSecureZero(quad, sizeof(quad));
    SSFCryptSecureZero(tri, sizeof(tri));
#if SSF_CONFIG_PEM_UNIT_TEST == 1
    if (_ssfPEMUTScrubHook != NULL) _ssfPEMUTScrubHook(quad, sizeof(quad), tri, sizeof(tri));
#endif
    return result;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if label[0..labelLen) equals the C string str.                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFPEMLabelIs(const char *label, size_t labelLen, const char *str)
{
    SSF_REQUIRE(label != NULL);
    SSF_REQUIRE(str != NULL);

    return (strlen(str) == labelLen) && (memcmp(label, str, labelLen) == 0);
}
