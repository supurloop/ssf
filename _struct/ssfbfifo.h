/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbfifo.h                                                                                    */
/* Provides a high performance byte fifo interface.                                              */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#ifndef SSF_BFIFO_INCLUDE_H
#define SSF_BFIFO_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ssfassert.h"
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
#define SSF_BFIFO_255   (255ul)
#define SSF_BFIFO_65535 (65535ul)

#if (SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE <= SSF_BFIFO_255) || \
    (SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255)
typedef uint8_t ssfbf_uint_t;
#elif SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE <= SSF_BFIFO_65535
typedef uint16_t ssfbf_uint_t;
#else
typedef uint32_t ssfbf_uint_t;
#endif

typedef struct SSFBFifo
{
    ssfbf_uint_t head;
    ssfbf_uint_t tail;
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE != SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255
    uint32_t size;
#endif
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
    ssfbf_uint_t mask;
#endif
    uint8_t *buffer;
    uint32_t magic;
} SSFBFifo_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBFifoInit(SSFBFifo_t *fifo, uint32_t fifoSize, uint8_t *buffer, uint32_t bufferSize);
void SSFBFifoDeInit(SSFBFifo_t *fifo);
void SSFBFifoPutByte(SSFBFifo_t *fifo, uint8_t inByte);
bool SSFBFifoPeekByte(const SSFBFifo_t *fifo, uint8_t *outByte);
bool SSFBFifoGetByte(SSFBFifo_t *fifo, uint8_t *outByte);
bool SSFBFifoIsEmpty(const SSFBFifo_t *fifo);
bool SSFBFifoIsFull(const SSFBFifo_t *fifo);
ssfbf_uint_t SSFBFifoSize(const SSFBFifo_t *fifo);
ssfbf_uint_t SSFBFifoLen(const SSFBFifo_t *fifo);
ssfbf_uint_t SSFBFifoUnused(const SSFBFifo_t *fifo);

#if SSF_BFIFO_MULTI_BYTE_ENABLE == 1
void SSFBFifoPutBytes(SSFBFifo_t *fifo, const uint8_t *inBytes, uint32_t inBytesLen);
bool SSFBFifoPeekBytes(const SSFBFifo_t *fifo, uint8_t *outBytes, uint32_t outBytesSize,
                       uint32_t *outBytesLen);
bool SSFBFifoGetBytes(SSFBFifo_t *fifo, uint8_t *outBytes, uint32_t outBytesSize,
                      uint32_t *outBytesLen);
#endif /* SSF_BFIFO_MULTI_BYTE_ENABLE */

/* --------------------------------------------------------------------------------------------- */
/* High performance external interface                                                           */
/* --------------------------------------------------------------------------------------------- */
#define SSF_BFIFO_IS_EMPTY(fp) ((fp)->head == (fp)->tail)

/* --------------------------------------------------------------------------------------------- */
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255
    #define SSF_BFIFO_IS_FULL(fp) (((ssfbf_uint_t)((fp)->head + 1)) == (fp)->tail)
#else
    #define SSF_BFIFO_IS_FULL(fp) (((ssfbf_uint_t)((fp)->head + 1) == (fp)->size) ? \
                                (fp)->tail == 0 : (fp)->tail == (ssfbf_uint_t)((fp)->head + 1))
#endif

/* --------------------------------------------------------------------------------------------- */
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255
    #define SSF_BFIFO_PUT_BYTE(fifo, inByte) do { \
    (fifo)->buffer[(fifo)->head] = inByte; \
    (fifo)->head++; \
    SSF_ENSURE((fifo)->head != (fifo)->tail); } while (0)

    #define SSF_BFIFO_GET_BYTE(fp, ob) do { \
    SSF_REQUIRE((fp)->head != (fp)->tail); \
    ob = (fp)->buffer[(fp)->tail]; \
    (fp)->tail++; } while(0)
#elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
    #define SSF_BFIFO_PUT_BYTE(fifo, inByte) do { \
    (fifo)->buffer[(fifo)->head] = inByte; \
    (fifo)->head++; \
    (fifo)->head &= (fifo)->mask; \
    SSF_ENSURE((fifo)->head != (fifo)->tail); } while (0)

    #define SSF_BFIFO_GET_BYTE(fifo, outByte) do { \
    SSF_REQUIRE((fifo)->head != (fifo)->tail); \
    outByte = (fifo)->buffer[(fifo)->tail]; \
    (fifo)->tail++; \
    (fifo)->tail &= (fifo)->mask; } while (0)
#else
    #define SSF_BFIFO_PUT_BYTE(fifo, inByte) do { \
    (fifo)->buffer[(fifo)->head] = inByte; \
    (fifo)->head++; \
    if ((fifo)->head == (fifo)->size) (fifo)->head = 0; \
    SSF_ENSURE((fifo)->head != (fifo)->tail); } while (0)

    #define SSF_BFIFO_GET_BYTE(fifo, outByte) do { \
    SSF_REQUIRE((fifo)->head != (fifo)->tail); \
    outByte = (fifo)->buffer[(fifo)->tail]; \
    (fifo)->tail++; \
    if ((fifo)->tail == (fifo)->size) (fifo)->tail = 0; } while (0)
#endif

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_BFIFO_UNIT_TEST == 1
void SSFBFifoUnitTest(void);
#endif /* SSF_CONFIG_BFIFO_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_BFIFO_INCLUDE_H */
