/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbfifo.c                                                                                    */
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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#include "ssfbfifo.h"

#define SSF_BFIFO_INIT_MAGIC (0x42120716ul)

/* --------------------------------------------------------------------------------------------- */
/* Initializes a byte fifo.                                                                      */
/* --------------------------------------------------------------------------------------------- */
void SSFBFifoInit(SSFBFifo_t *fifo, uint32_t fifoSize, uint8_t *buffer, uint32_t bufferSize)
{
    SSF_REQUIRE(fifo != NULL);
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255
    SSF_REQUIRE(fifoSize == SSF_BFIFO_255);
#elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
    SSF_REQUIRE(fifoSize > 0);
    SSF_REQUIRE((fifoSize & (((uint32_t)fifoSize) + 1)) == 0);
    SSF_REQUIRE(fifoSize <= SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE);
#else
    SSF_REQUIRE(fifoSize > 0);
    SSF_REQUIRE(fifoSize <= SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE);
#endif
    SSF_REQUIRE(buffer != NULL);
    SSF_REQUIRE(bufferSize > fifoSize);
    SSF_ASSERT(fifo->magic != SSF_BFIFO_INIT_MAGIC);

    fifo->head = 0;
    fifo->tail = 0;
    fifo->buffer = buffer;
    fifo->magic = SSF_BFIFO_INIT_MAGIC;

#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE != SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255
    fifo->size = fifoSize + 1;
#endif
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
    fifo->mask = fifoSize;
#endif
}

/* --------------------------------------------------------------------------------------------- */
/* Put a byte into the fifo.                                                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFBFifoPutByte(SSFBFifo_t *fifo, uint8_t inByte)
{
    SSF_REQUIRE(fifo != NULL);
    SSF_ASSERT(fifo->magic == SSF_BFIFO_INIT_MAGIC);

    fifo->buffer[fifo->head] = inByte;
    fifo->head++;
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
    fifo->head &= fifo->mask;
#elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY
    if (fifo->head == fifo->size) fifo->head = 0;
#endif
    SSF_ENSURE(fifo->head != fifo->tail);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if there is a byte in fifo and updates outByte, else false; byte never removed.  */
/* --------------------------------------------------------------------------------------------- */
bool SSFBFifoPeekByte(const SSFBFifo_t *fifo, uint8_t *outByte)
{
    SSF_REQUIRE(fifo != NULL);
    SSF_REQUIRE(outByte != NULL);
    SSF_ASSERT(fifo->magic == SSF_BFIFO_INIT_MAGIC);

    if (fifo->head == fifo->tail) return false;
    *outByte = fifo->buffer[fifo->tail];
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if there is a byte in fifo and updates outByte, else false; byte always removed. */
/* --------------------------------------------------------------------------------------------- */
bool SSFBFifoGetByte(SSFBFifo_t *fifo, uint8_t *outByte)
{
    SSF_REQUIRE(fifo != NULL);
    SSF_REQUIRE(outByte != NULL);
    SSF_ASSERT(fifo->magic == SSF_BFIFO_INIT_MAGIC);

    if (fifo->head == fifo->tail) return false;

    *outByte = fifo->buffer[fifo->tail];
    fifo->tail++;
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
    fifo->tail &= fifo->mask;
#elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY
    if (fifo->tail == fifo->size) fifo->tail = 0;
#endif
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if fifo is empty, else false.                                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFBFifoIsEmpty(const SSFBFifo_t *fifo)
{
    SSF_REQUIRE(fifo != NULL);
    SSF_ASSERT(fifo->magic == SSF_BFIFO_INIT_MAGIC);

    return fifo->head == fifo->tail;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if fifo is full, else false.                                                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFBFifoIsFull(const SSFBFifo_t *fifo)
{
    ssfbf_uint_t newHead;

    SSF_REQUIRE(fifo != NULL);
    SSF_ASSERT(fifo->magic == SSF_BFIFO_INIT_MAGIC);

    newHead = fifo->head + 1;
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
    newHead &= fifo->mask;
#elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY
    if (newHead == fifo->size) newHead = 0;
#endif
    return newHead == fifo->tail;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the maximum number of bytes the fifo can store.                                       */
/* --------------------------------------------------------------------------------------------- */
ssfbf_uint_t SSFBFifoSize(const SSFBFifo_t *fifo)
{
    SSF_REQUIRE(fifo != NULL);
    SSF_ASSERT(fifo->magic == SSF_BFIFO_INIT_MAGIC);

#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255
    return SSF_BFIFO_255;
#else
    return fifo->size - 1;
#endif
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the number of bytes in the fifo.                                                      */
/* --------------------------------------------------------------------------------------------- */
ssfbf_uint_t SSFBFifoLen(const SSFBFifo_t *fifo)
{
    ssfbf_uint_t used;

    SSF_REQUIRE(fifo != NULL);
    SSF_ASSERT(fifo->magic == SSF_BFIFO_INIT_MAGIC);

    if (fifo->head < fifo->tail)
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255
    {used = SSF_BFIFO_255 - (fifo->tail - fifo->head) + 1; }
#else
    {used = fifo->size - (fifo->tail - fifo->head); }
#endif
    else used = fifo->head - fifo->tail;

    return used;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the number of unused bytes in the fifo.                                               */
/* --------------------------------------------------------------------------------------------- */
ssfbf_uint_t SSFBFifoUnused(const SSFBFifo_t *fifo)
{
    return SSFBFifoSize(fifo) - SSFBFifoLen(fifo);
}

#if SSF_BFIFO_MULTI_BYTE_ENABLE == 1
/* --------------------------------------------------------------------------------------------- */
/* Puts bytes into the fifo.                                                                     */
/* --------------------------------------------------------------------------------------------- */
void SSFBFifoPutBytes(SSFBFifo_t *fifo, const uint8_t *inBytes, uint32_t inBytesLen)
{
    SSF_REQUIRE(fifo != NULL);
    SSF_REQUIRE(inBytes != NULL);
    SSF_ASSERT(fifo->magic == SSF_BFIFO_INIT_MAGIC);

    while (inBytesLen)
    {
        fifo->buffer[fifo->head] = *inBytes;
        fifo->head++;
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
        fifo->head &= fifo->mask;
#elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY
        if (fifo->head == fifo->size) fifo->head = 0;
#endif
        SSF_ENSURE(fifo->head != fifo->tail);
        inBytesLen--;
        inBytes++;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if bytes avail, copy up to size to out, update len, else false; fifo not changed.*/
/* --------------------------------------------------------------------------------------------- */
bool SSFBFifoPeekBytes(const SSFBFifo_t *fifo, uint8_t *outBytes, uint32_t outBytesSize,
                       uint32_t *outBytesLen)
{
    ssfbf_uint_t head;
    ssfbf_uint_t tail;

    SSF_REQUIRE(fifo != NULL);
    SSF_REQUIRE(outBytes != NULL);
    SSF_REQUIRE(outBytesLen != NULL);
    SSF_ASSERT(fifo->magic == SSF_BFIFO_INIT_MAGIC);

    if (fifo->head == fifo->tail) return false;

    head = fifo->head;
    tail = fifo->tail;
    *outBytesLen = 0;
    while (outBytesSize && (head != tail))
    {
        *outBytes = fifo->buffer[tail];
        tail++;
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
        tail &= fifo->mask;
#elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY
        if (tail == fifo->size) tail = 0;
#endif
        outBytesSize--;
        outBytes++;
        (*outBytesLen)++;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if bytes avail, removes up to size into out, updates len, else false.            */
/* --------------------------------------------------------------------------------------------- */
bool SSFBFifoGetBytes(SSFBFifo_t *fifo, uint8_t *outBytes, uint32_t outBytesSize,
                      uint32_t *outBytesLen)
{
    SSF_REQUIRE(fifo != NULL);
    SSF_REQUIRE(outBytes != NULL);
    SSF_REQUIRE(outBytesLen != NULL);
    SSF_ASSERT(fifo->magic == SSF_BFIFO_INIT_MAGIC);

    if (fifo->head == fifo->tail) return false;

    *outBytesLen = 0;
    while (outBytesSize && (fifo->head != fifo->tail))
    {
        *outBytes = fifo->buffer[fifo->tail];
        fifo->tail++;
#if SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1
        fifo->tail &= fifo->mask;
#elif SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE == SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY
        if (fifo->tail == fifo->size) fifo->tail = 0;
#endif
        outBytesSize--;
        outBytes++;
        (*outBytesLen)++;
    }
    return true;
}
#endif /* SSF_BFIFO_MULTI_BYTE_ENABLE */

