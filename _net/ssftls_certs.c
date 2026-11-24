/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssftls_certs.c                                                                                */
/* Provides loading of PEM-encoded root CA certificates for TLS trust store.                     */
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
#include <string.h>
#include <dirent.h>
#include "ssfassert.h"
#include "ssftls_certs.h"
#include "ssfbase64.h"

/* --------------------------------------------------------------------------------------------- */
/* Module data: static pool for DER-encoded certificate data.                                    */
/* --------------------------------------------------------------------------------------------- */
static uint8_t _certPool[SSF_TLS_CERTS_MAX_POOL];
static size_t _certPoolUsed;
static const uint8_t *_certPtrs[SSF_TLS_CERTS_MAX_CAS];
static uint32_t _certLens[SSF_TLS_CERTS_MAX_CAS];
static uint8_t _certCount;

/* --------------------------------------------------------------------------------------------- */
/* Internal: decode a PEM file to DER.                                                           */
/* Finds the Base64 content between BEGIN CERTIFICATE and END CERTIFICATE.                       */
/* --------------------------------------------------------------------------------------------- */
static bool _PemToDer(const char *pemData, size_t pemLen,
                      uint8_t *derOut, size_t derOutSize, size_t *derOutLen)
{
    const char *begin = "-----BEGIN CERTIFICATE-----";
    const char *end = "-----END CERTIFICATE-----";
    const char *b64Start;
    const char *b64End;
    char b64Buf[4096];
    size_t b64Len = 0;
    size_t i;

    /* Find the Base64 content between the markers */
    b64Start = strstr(pemData, begin);
    if (b64Start == NULL) return false;
    b64Start += strlen(begin);

    b64End = strstr(b64Start, end);
    if (b64End == NULL) return false;

    /* Strip whitespace and newlines, collect raw Base64 */
    for (i = 0; b64Start + i < b64End && b64Len < sizeof(b64Buf) - 1u; i++)
    {
        char c = b64Start[i];
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
        {
            b64Buf[b64Len++] = c;
        }
    }
    b64Buf[b64Len] = '\0';

    /* Base64 decode to DER */
    {
        size_t decoded;
        if (!SSFBase64Decode(b64Buf, b64Len, derOut, derOutSize, &decoded))
            return false;
        *derOutLen = decoded;
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Load all PEM files from the given directory into a trust store.                                */
/* --------------------------------------------------------------------------------------------- */
uint8_t SSFTLSCertsLoad(const char *certsDir, SSFTLSCTrustStore_t *trustOut)
{
    DIR *dir;
    struct dirent *entry;
    char path[256];

    SSF_REQUIRE(certsDir != NULL);
    SSF_REQUIRE(trustOut != NULL);

    _certPoolUsed = 0;
    _certCount = 0;
    memset(trustOut, 0, sizeof(*trustOut));

    dir = opendir(certsDir);
    if (dir == NULL) return 0;

    while ((entry = readdir(dir)) != NULL && _certCount < SSF_TLS_CERTS_MAX_CAS)
    {
        size_t nameLen = strlen(entry->d_name);
        FILE *f;
        char pemBuf[4096];
        size_t pemLen;
        uint8_t derBuf[SSF_TLS_CERTS_MAX_DER_SIZE];
        size_t derLen;

        /* Only process .pem files */
        if (nameLen < 5) continue;
        if (strcmp(&entry->d_name[nameLen - 4], ".pem") != 0) continue;

        /* Build full path */
        snprintf(path, sizeof(path), "%s/%s", certsDir, entry->d_name);

        /* Read the PEM file */
        f = fopen(path, "r");
        if (f == NULL) continue;
        pemLen = fread(pemBuf, 1, sizeof(pemBuf) - 1u, f);
        fclose(f);
        if (pemLen == 0) continue;
        pemBuf[pemLen] = '\0';

        /* Decode PEM to DER */
        if (!_PemToDer(pemBuf, pemLen, derBuf, sizeof(derBuf), &derLen)) continue;

        /* Store in the pool */
        if (_certPoolUsed + derLen > sizeof(_certPool)) continue;

        memcpy(&_certPool[_certPoolUsed], derBuf, derLen);
        _certPtrs[_certCount] = &_certPool[_certPoolUsed];
        _certLens[_certCount] = (uint32_t)derLen;
        _certPoolUsed += derLen;
        _certCount++;
    }

    closedir(dir);

    trustOut->caDer = _certPtrs;
    trustOut->caDerLen = _certLens;
    trustOut->count = _certCount;

    return _certCount;
}

/* --------------------------------------------------------------------------------------------- */
/* Free the loaded certificate data.                                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFTLSCertsUnload(void)
{
    _certPoolUsed = 0;
    _certCount = 0;
}
