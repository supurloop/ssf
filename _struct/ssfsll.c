/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsll.c                                                                                      */
/* Provides a generic sorted linked list interface.                                              */
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
#include "ssfassert.h"
#include "ssfsll.h"

#define SSF_SLL_INIT_MAGIC (0x534C4C00ul)

/* --------------------------------------------------------------------------------------------- */
/* Initializes a new sorted linked list.                                                         */
/* --------------------------------------------------------------------------------------------- */
void SSFSLLInit(SSFSLL_t *sll, uint32_t maxSize, SSFSLLCompareFn_t compareFn,
                SSF_SLL_ORDER_t order)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(sll->magic != SSF_SLL_INIT_MAGIC);
    SSF_REQUIRE(maxSize > 0);
    SSF_REQUIRE(compareFn != NULL);
    SSF_REQUIRE((order > SSF_SLL_ORDER_MIN) && (order < SSF_SLL_ORDER_MAX));

    sll->head = NULL;
    sll->tail = NULL;
    sll->items = 0;
    sll->size = maxSize;
    sll->compareFn = compareFn;
    sll->order = order;
    sll->magic = SSF_SLL_INIT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes a sorted linked list.                                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFSLLDeInit(SSFSLL_t *sll)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);
    SSF_REQUIRE(SSFSLLIsEmpty(sll));

    memset(sll, 0, sizeof(SSFSLL_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if sorted linked list inited, else false.                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFSLLIsInited(SSFSLL_t *sll)
{
    SSF_REQUIRE(sll != NULL);

    return (sll->magic == SSF_SLL_INIT_MAGIC);
}

/* --------------------------------------------------------------------------------------------- */
/* Inserts item into sorted linked list in sorted order.                                         */
/* --------------------------------------------------------------------------------------------- */
void SSFSLLInsertItem(SSFSLL_t *sll, SSFSLLItem_t *inItem)
{
    SSFSLLItem_t *cur;
    int32_t cmp;

    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(inItem != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);
    SSF_REQUIRE(sll->items < sll->size);
    SSF_REQUIRE(inItem->sll == NULL);

    if (sll->head == NULL)
    {
        SSF_ASSERT(sll->items == 0);
        SSF_ASSERT(sll->tail == NULL);

        sll->head = inItem;
        sll->tail = inItem;
        inItem->next = NULL;
        inItem->prev = NULL;
    }
    else
    {
        cur = sll->head;
        while (cur != NULL)
        {
            cmp = sll->compareFn(inItem, cur);

            if (((sll->order == SSF_SLL_ORDER_ASCENDING) && (cmp <= 0)) ||
                ((sll->order == SSF_SLL_ORDER_DESCENDING) && (cmp >= 0)))
            {
                /* Insert inItem before cur */
                inItem->next = cur;
                inItem->prev = cur->prev;
                if (cur->prev != NULL)
                {
                    cur->prev->next = inItem;
                }
                else
                {
                    sll->head = inItem;
                }
                cur->prev = inItem;
                goto done;
            }
            cur = cur->next;
        }
        /* Insert at tail */
        inItem->next = NULL;
        inItem->prev = sll->tail;
        sll->tail->next = inItem;
        sll->tail = inItem;
    }
done:
    inItem->sll = sll;
    sll->items++;
}

/* --------------------------------------------------------------------------------------------- */
/* Removes a specific item from sorted linked list. Returns true if removed, else false.         */
/* --------------------------------------------------------------------------------------------- */
bool SSFSLLRemoveItem(SSFSLL_t *sll, SSFSLLItem_t *outItem)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(outItem != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);

    if (outItem->sll != sll) return false;

    SSF_ASSERT(sll->items > 0);

    if (outItem->prev != NULL) outItem->prev->next = outItem->next;
    else sll->head = outItem->next;

    if (outItem->next != NULL) outItem->next->prev = outItem->prev;
    else sll->tail = outItem->prev;

    outItem->next = NULL;
    outItem->prev = NULL;
    outItem->sll = NULL;
    sll->items--;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if head item peeked, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFSLLPeekHead(const SSFSLL_t *sll, SSFSLLItem_t **outItem)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(outItem != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);

    if (sll->head == NULL) return false;

    *outItem = sll->head;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if tail item peeked, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFSLLPeekTail(const SSFSLL_t *sll, SSFSLLItem_t **outItem)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(outItem != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);

    if (sll->tail == NULL) return false;

    *outItem = sll->tail;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if head item popped, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFSLLPopHead(SSFSLL_t *sll, SSFSLLItem_t **outItem)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(outItem != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);

    if (sll->head == NULL) return false;

    SSF_ASSERT(sll->items > 0);

    *outItem = sll->head;
    sll->head = sll->head->next;
    if (sll->head != NULL) sll->head->prev = NULL;
    else sll->tail = NULL;

    (*outItem)->next = NULL;
    (*outItem)->prev = NULL;
    (*outItem)->sll = NULL;
    sll->items--;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if tail item popped, else false.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFSLLPopTail(SSFSLL_t *sll, SSFSLLItem_t **outItem)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(outItem != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);

    if (sll->tail == NULL) return false;

    SSF_ASSERT(sll->items > 0);

    *outItem = sll->tail;
    sll->tail = sll->tail->prev;
    if (sll->tail != NULL) sll->tail->next = NULL;
    else sll->head = NULL;

    (*outItem)->next = NULL;
    (*outItem)->prev = NULL;
    (*outItem)->sll = NULL;
    sll->items--;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if list empty, else false.                                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFSLLIsEmpty(const SSFSLL_t *sll)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);
    return (sll->items == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if list full, else false.                                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFSLLIsFull(const SSFSLL_t *sll)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);
    return (sll->items == sll->size);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the max size of the list.                                                             */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFSLLSize(const SSFSLL_t *sll)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);
    return (sll->size);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the number of items in list.                                                          */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFSLLLen(const SSFSLL_t *sll)
{
    SSF_REQUIRE(sll != NULL);
    SSF_REQUIRE(sll->magic == SSF_SLL_INIT_MAGIC);
    return (sll->items);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the number of unused spots in list.                                                   */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFSLLUnused(const SSFSLL_t *sll)
{
    return SSFSLLSize(sll) - SSFSLLLen(sll);
}
