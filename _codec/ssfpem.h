/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpem.h                                                                                      */
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
#ifndef SSF_PEM_H_INCLUDE
#define SSF_PEM_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */

/* Longest label accepted between "-----BEGIN " and "-----" (e.g. "ENCRYPTED PRIVATE KEY"). */
#define SSF_PEM_MAX_LABEL_LEN (40u)

typedef enum
{
    SSF_PEM_BLOCK,    /* A block was decoded; *pos is past its END line */
    SSF_PEM_END,      /* No further BEGIN line in the input */
    SSF_PEM_ERR,      /* Malformed block: bad BEGIN/END line, label mismatch, bad Base64 */
    SSF_PEM_ERR_SIZE, /* The decoded block does not fit in derSize bytes */
} SSFPEMResult_t;

/* --------------------------------------------------------------------------------------------- */
/* External Interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Decodes the next PEM block (RFC 7468) at or after offset *pos of pem[0..pemLen). */
SSFPEMResult_t SSFPEMDecodeNext(const char *pem, size_t pemLen, size_t *pos,
                                const char **labelOut, size_t *labelLenOut,
                                uint8_t *derOpt, size_t derSize, size_t *derLenOut);

/* Returns true if label[0..labelLen) equals the C string cmpStr. */
bool SSFPEMLabelIs(const char *label, size_t labelLen, const char *cmpStr);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_PEM_UNIT_TEST == 1
void SSFPEMUnitTest(void);
/* Called on every return of SSFPEMDecodeNext() with its scratch buffers, which must be zero. */
extern void (*_ssfPEMUTScrubHook)(const char *quad, size_t quadSize, const uint8_t *tri,
                                  size_t triSize);
#endif /* SSF_CONFIG_PEM_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_PEM_H_INCLUDE */
