/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpoly1305.h                                                                                 */
/* Provides Poly1305 message authentication code interface (RFC 7539).                           */
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

/* --------------------------------------------------------------------------------------------- */
/* Per US export restrictions for open source cryptographic software the Department of Commerce  */
/* has been notified of the inclusion of cryptographic software in the SSF. This is a copy of    */
/* the notice emailed on Nov 11, 2021:                                                           */
/* --------------------------------------------------------------------------------------------- */
/* Unrestricted Encryption Source Code Notification                                              */
/* To : crypt@bis.doc.gov; enc@nsa.gov                                                           */
/* Subject : Addition to SSF Source Code                                                         */
/* Department of Commerce                                                                        */
/* Bureau of Export Administration                                                               */
/* Office of Strategic Trade and Foreign Policy Controls                                         */
/* 14th Street and Pennsylvania Ave., N.W.                                                       */
/* Room 2705                                                                                     */
/* Washington, DC 20230                                                                          */
/* Re: Unrestricted Encryption Source Code Notification Commodity : Addition to SSF Source Code  */
/*                                                                                               */
/* Dear Sir / Madam,                                                                             */
/*                                                                                               */
/* Pursuant to paragraph(e)(1) of Part 740.13 of the U.S.Export Administration Regulations       */
/* ("EAR", 15 CFR Part 730 et seq.), we are providing this written notification of the Internet  */
/* location of the unrestricted, publicly available Source Code being added to the Small System  */
/* Framework (SSF) Source Code. SSF Source Code is a free embedded system application framework  */
/* developed by Supurloop Software LLC in the Public Interest. This notification serves as a     */
/* notification of an addition of new software to the SSF archive. This archive is updated from  */
/* time to time, but its location is constant. Therefore this notification serves as a one-time  */
/* notification for subsequent updates that may occur in the future to the software covered by   */
/* this notification. Such updates may add or enhance cryptographic functionality of the SSF.    */
/* The Internet location for the SSF Source Code is: https://github.com/supurloop/ssf            */
/*                                                                                               */
/* This site may be mirrored to a number of other sites located outside the United States.       */
/*                                                                                               */
/* The following software is being added to the SSF archive:                                     */
/*                                                                                               */
/* ssfchacha20.c, ssfchacha20.h - ChaCha20 stream cipher.                                       */
/* ssfpoly1305.c, ssfpoly1305.h - Poly1305 message authentication code.                         */
/* ssfchacha20poly1305.c, ssfchacha20poly1305.h - ChaCha20-Poly1305 AEAD.                       */
/*                                                                                               */
/* If you have any questions, please email me at xxx@xxx, or call me on (XXX) XXX-XXXX.          */
/*                                                                                               */
/* Sincerely,                                                                                    */
/* James Higgins                                                                                 */
/* President                                                                                     */
/* Supurloop Software LLC                                                                        */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSFPOLY1305_H_INCLUDE
#define SSFPOLY1305_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
#define SSF_POLY1305_KEY_SIZE (32u)
#define SSF_POLY1305_TAG_SIZE (16u)

/* Incremental Poly1305 context. Callers treat as opaque; pass by pointer to Begin/Update/End.   */
/* Holds the clamped r (5 × 26-bit limbs), s (4 × 32-bit LE words), precomputed r[1..4] * 5, the */
/* 130-bit accumulator h, a 16-byte partial-block buffer with fill length, and a validity        */
/* marker. Seeded by Begin, fed by Update, finalised and zeroised by End. Never reuse a context  */
/* across two messages — Poly1305 is a one-time MAC (see the ssfpoly1305.md key-reuse note).     */
/* Callers MUST zero the context before the first call to Begin (e.g. `... ctx = {0};`); End     */
/* leaves the context fully zeroed so a subsequent Begin on the same storage is also valid.      */
typedef struct SSFPoly1305Context
{
    uint32_t r0, r1, r2, r3, r4;         /* clamped r limbs */
    uint32_t s0, s1, s2, s3;              /* s = key[16..31] as 4 LE words */
    uint32_t rr0, rr1, rr2, rr3;          /* r1..r4 * 5 (precomputed reduction operands) */
    uint32_t h0, h1, h2, h3, h4;          /* 130-bit accumulator */
    uint8_t  buf[16];                     /* partial-block accumulator */
    uint8_t  bufLen;                      /* 0..15 — bytes currently in buf[] */
    uint32_t magic;                       /* context validity marker — 0 ⇒ uninitialised */
} SSFPoly1305Context_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* One-shot: compute Poly1305 tag over msg using the 32-byte one-time key. Convenience wrapper   */
/* over Begin/Update/End; preserves the original function signature and RFC 7539 test vectors.   */
void SSFPoly1305Mac(const uint8_t *msg, size_t msgLen,
                    const uint8_t *key, size_t keyLen,
                    uint8_t *tag, size_t tagSize);

/* One-shot tag verification: compute the Poly1305 tag over msg with key, then compare against   */
/* expectedTag in constant time. Returns true iff the tags match exactly. expectedTag is read    */
/* as exactly SSF_POLY1305_TAG_SIZE bytes — no truncation; for shorter compare semantics, use    */
/* SSFPoly1305Mac + SSFCryptCTMemEq directly. Bundles the CT-compare so callers cannot acciden-  */
/* tally pair Mac with a non-CT memcmp() and open a tag-recovery timing side channel.            */
bool SSFPoly1305Verify(const uint8_t *msg, size_t msgLen,
                       const uint8_t *key, size_t keyLen,
                       const uint8_t *expectedTag);

/* Incremental: initialize ctx with a 32-byte one-time key. Clamps r, derives s, precomputes     */
/* the r*5 reduction operands, and zeroes the accumulator. After Begin the context is ready for  */
/* a sequence of Update calls terminated by one End call. */
void SSFPoly1305Begin(SSFPoly1305Context_t *ctx,
                      const uint8_t *key, size_t keyLen);

/* Incremental: feed msgLen bytes of message into the MAC. Internally processes complete 16-byte */
/* blocks as they accumulate and stashes any trailing < 16-byte tail in the context for the next */
/* call. Can be invoked any number of times with any chunk sizes; the result is identical to a   */
/* single-buffer call over the concatenation of all Update inputs. */
void SSFPoly1305Update(SSFPoly1305Context_t *ctx,
                       const uint8_t *msg, size_t msgLen);

/* Incremental: finalize and write the 16-byte tag. Processes any remaining partial block with   */
/* the RFC 7539 0x01 high-bit marker, runs the final reduction, adds s, and emits the tag. Also  */
/* zeroises ctx on return to limit exposure of the one-time key material. After End the context  */
/* is invalid — Begin it again before reuse. */
void SSFPoly1305End(SSFPoly1305Context_t *ctx,
                    uint8_t *tag, size_t tagSize);

#if SSF_CONFIG_POLY1305_UNIT_TEST == 1
void SSFPoly1305UnitTest(void);
#endif /* SSF_CONFIG_POLY1305_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSFPOLY1305_H_INCLUDE */
