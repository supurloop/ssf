/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfprng.c                                                                                     */
/* Provides a cryptographically secure capable pseudo random number generator (PRNG).            */
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
#include <stdbool.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfaes.h"
#include "ssfprng.h"

/* --------------------------------------------------------------------------------------------- */
/* Module defines.                                                                               */
/* --------------------------------------------------------------------------------------------- */
#define SSF_PRNG_MAGIC (0x584C5845)

/* --------------------------------------------------------------------------------------------- */
/* Inits or reinits a PRNG context with entropy.                                                 */
/* --------------------------------------------------------------------------------------------- */
void SSFPRNGInitContext(SSFPRNGContext_t *context, const uint8_t *entropy, size_t entropyLen)
{
	SSF_REQUIRE(context != NULL);
	SSF_REQUIRE(entropy != NULL);
	SSF_REQUIRE(entropyLen == SSF_PRNG_ENTROPY_SIZE);

	memcpy(context->entropy, entropy, SSF_PRNG_ENTROPY_SIZE);
	memcpy(&context->count, entropy, sizeof(uint64_t));
	context->count = (~context->count) + 1;
	context->magic = SSF_PRNG_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Copies 1 to SSF_PRNG_RANDOM_MAX_SIZE bytes of random numbers into user buffer.                */
/* --------------------------------------------------------------------------------------------- */
void SSFPRNGGetRandom(SSFPRNGContext_t *context, uint8_t *random, size_t randomSize)
{
	uint8_t pt[SSF_AES_BLOCK_SIZE];
	uint8_t ct[SSF_AES_BLOCK_SIZE];

	SSF_REQUIRE(context != NULL);
	SSF_REQUIRE(random != NULL);
	SSF_REQUIRE((randomSize > 0) && (randomSize <= SSF_PRNG_RANDOM_MAX_SIZE));
	SSF_ASSERT(context->magic == SSF_PRNG_MAGIC);

	/* Prepare pt block with count, then advance count */
	memcpy(pt, &context->count, sizeof(uint64_t));
	memcpy(&pt[SSF_AES_BLOCK_SIZE >> 1], &context->count, sizeof(uint64_t));
	context->count++;

	/* Generate next 16 bytes of random numbers from entropy */
	SSFAES128BlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), context->entropy, SSF_PRNG_ENTROPY_SIZE);

	/* Copy requested number of random numbers to user buffer */
	memcpy(random, ct, randomSize);
}
