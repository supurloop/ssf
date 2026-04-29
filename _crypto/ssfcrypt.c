/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfcrypt.c                                                                                    */
/* Provides high-level cryptographic helpers (constant-time compare, secure zeroize).            */
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
#include <stddef.h>
#include "ssfcrypt.h"
#include "ssfassert.h"

/* --------------------------------------------------------------------------------------------- */
/* If the first n bytes at a and b are equal, inspecting every byte, returns true, else false.  */
/* --------------------------------------------------------------------------------------------- */
bool SSFCryptCTMemEq(const void *a, const void *b, size_t n)
{
    size_t i;
    const uint8_t *ap;
    const uint8_t *bp;
    volatile uint8_t diff = 0;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);

    ap = (const uint8_t *)a;
    bp = (const uint8_t *)b;

    /* volatile prevents the compiler from rewriting the OR-accumulator into an early exit */
    for (i = 0; i < n; i++) diff |= (uint8_t)(ap[i] ^ bp[i]);
    return (diff == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Securely zeroizes n bytes at p, defeating dead-store elimination via volatile writes.         */
/* --------------------------------------------------------------------------------------------- */
void SSFCryptSecureZero(void *p, size_t n)
{
    volatile uint8_t *v;
    size_t i;

    SSF_REQUIRE(p != NULL);

    v = (volatile uint8_t *)p;
    for (i = 0u; i < n; i++)
    {
        v[i] = 0u;
    }
}

