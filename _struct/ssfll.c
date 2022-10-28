/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfll.c                                                                                       */
/* Provides a generic linked list interface.                                                     */
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
#include "ssfll.h"

#define SSF_LL_INIT_MAGIC (0x44140918ul)

/* --------------------------------------------------------------------------------------------- */
/* Initializes a new linked list.                                                                */
/* --------------------------------------------------------------------------------------------- */
void SSFLLInit(SSFLL_t *ll, uint32_t maxSize)
{
    SSF_REQUIRE(ll != NULL);
    SSF_REQUIRE(ll->magic != SSF_LL_INIT_MAGIC);
    SSF_REQUIRE(maxSize > 0);

    ll->head = NULL;
    ll->tail = NULL;
    ll->items = 0;
    ll->size = maxSize;
    ll->magic = SSF_LL_INIT_MAGIC;
}

/* --------------------------------------------------------------------------------------------- */
/* Deinitializes a linked list.                                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFLLDeInit(SSFLL_t *ll)
{
    SSF_REQUIRE(ll != NULL);
    SSF_REQUIRE(ll->magic == SSF_LL_INIT_MAGIC);
    SSF_REQUIRE(SSFLLIsEmpty(ll));

    memset(ll, 0, sizeof(SSFLL_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if linked list inited, else false.                                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFLLIsInited(SSFLL_t *ll)
{
    SSF_REQUIRE(ll != NULL);

    return(ll->magic == SSF_LL_INIT_MAGIC);
}

/* --------------------------------------------------------------------------------------------- */
/* Put item into linked list.                                                                    */
/* --------------------------------------------------------------------------------------------- */
void SSFLLPutItem(SSFLL_t *ll, SSFLLItem_t *inItem, SSF_LL_LOC_t loc, SSFLLItem_t *locItem)
{
    SSF_REQUIRE(ll != NULL);
    SSF_REQUIRE(inItem != NULL);
    SSF_REQUIRE((loc > SSF_LL_LOC_MIN) && (loc < SSF_LL_LOC_MAX));
    SSF_REQUIRE((((loc == SSF_LL_LOC_HEAD) || (loc == SSF_LL_LOC_TAIL)) && (locItem == NULL)) ||
                (loc == SSF_LL_LOC_ITEM));
    SSF_REQUIRE(ll->magic == SSF_LL_INIT_MAGIC);
    SSF_REQUIRE(ll->items < ll->size);
    SSF_REQUIRE(inItem->ll == NULL);

    if (ll->head == NULL)
    {
        SSF_ASSERT(ll->items == 0);
        SSF_ASSERT(ll->tail == NULL);

        ll->head = inItem;
        ll->tail = inItem;
        inItem->next = NULL;
        inItem->prev = NULL;
    } else if ((loc == SSF_LL_LOC_HEAD) || ((loc == SSF_LL_LOC_ITEM) && (locItem == NULL)))
    {
        inItem->next = ll->head;
        inItem->prev = NULL;
        ll->head->prev = inItem;
        ll->head = inItem;
    } else if (loc == SSF_LL_LOC_TAIL)
    {
        inItem->next = NULL;
        inItem->prev = ll->tail;
        ll->tail->next = inItem;
        ll->tail = inItem;
    } else if (loc == SSF_LL_LOC_ITEM)
    {
        /* Insert inItem after locItem */
        SSF_ASSERT(locItem->ll == ll);
        inItem->next = locItem->next;
        locItem->next = inItem;
        inItem->prev = locItem;
        if (inItem->next == NULL) ll->tail = inItem;
    }
    inItem->ll = ll;
    ll->items++;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if item is found and removed, else false.                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFLLGetItem(SSFLL_t *ll, SSFLLItem_t **outItem, SSF_LL_LOC_t loc, SSFLLItem_t *locItem)
{
    SSF_REQUIRE(ll != NULL);
    SSF_REQUIRE(outItem != NULL);
    SSF_REQUIRE((loc > SSF_LL_LOC_MIN) && (loc < SSF_LL_LOC_MAX));
    SSF_REQUIRE((((loc == SSF_LL_LOC_HEAD) || (loc == SSF_LL_LOC_TAIL)) && (locItem == NULL)) ||
                ((loc == SSF_LL_LOC_ITEM) && (locItem != NULL)));
    SSF_REQUIRE(ll->magic == SSF_LL_INIT_MAGIC);

    if (ll->head != NULL)
    {
        SSF_ASSERT(ll->items > 0);
        SSF_ASSERT(ll->tail != NULL);

        switch (loc)
        {
        case SSF_LL_LOC_HEAD:
            *outItem = ll->head;
            ll->head = ll->head->next;
            if (ll->head != NULL) ll->head->prev = NULL;
            else ll->tail = NULL;
            break;
        case SSF_LL_LOC_TAIL:
            *outItem = ll->tail;
            ll->tail = ll->tail->prev;
            if (ll->tail != NULL) ll->tail->next = NULL;
            else ll->head = NULL;
            break;
        case SSF_LL_LOC_ITEM:
            /* Remove locItem, return in outItem */
            SSF_ASSERT(locItem->ll == ll);
            *outItem = locItem;
            if (locItem->prev) locItem->prev->next = locItem->next;
            else ll->head = locItem->next;
            if (locItem->next) locItem->next->prev = locItem->prev;
            else ll->tail = locItem->prev;
            break;
        case SSF_LL_LOC_MAX:
        default:
            SSF_ERROR();
        }
        (*outItem)->next = NULL;
        (*outItem)->prev = NULL;
        (*outItem)->ll = NULL;
        ll->items--;
        return true;
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if list empty, else false.                                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFLLIsEmpty(const SSFLL_t *ll)
{
    SSF_REQUIRE(ll != NULL);
    SSF_REQUIRE(ll->magic == SSF_LL_INIT_MAGIC);
    return (ll->items == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if list full, else false.                                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFLLIsFull(const SSFLL_t *ll)
{
    SSF_REQUIRE(ll != NULL);
    SSF_REQUIRE(ll->magic == SSF_LL_INIT_MAGIC);
    return (ll->items == ll->size);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the max size of the list.                                                             */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFLLSize(const SSFLL_t *ll)
{
    SSF_REQUIRE(ll != NULL);
    SSF_REQUIRE(ll->magic == SSF_LL_INIT_MAGIC);
    return (ll->size);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the number of items in list.                                                          */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFLLLen(const SSFLL_t *ll)
{
    SSF_REQUIRE(ll != NULL);
    SSF_REQUIRE(ll->magic == SSF_LL_INIT_MAGIC);
    return (ll->items);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the number of unused spots in list.                                                   */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFLLUnused(const SSFLL_t *ll)
{
    return SSFLLSize(ll) - SSFLLLen(ll);
}

