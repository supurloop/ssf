/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsll_ut.c                                                                                   */
/* Provides unit tests for ssfsll's sorted linked list interface.                                */
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
#include "ssfsll.h"
#include "ssfport.h"

#if SSF_CONFIG_SLL_UNIT_TEST == 1

#define SSFSLL_TEST_MAX_SIZE (128u)

typedef struct SSFSLLTest
{
    SSFSLLItem_t item;
    int32_t key;
} SSFSLLTest_t;

static SSFSLLTest_t _ssfsllItems[SSFSLL_TEST_MAX_SIZE + 1];
static SSFSLL_t _ssfsllTest;

/* --------------------------------------------------------------------------------------------- */
/* Comparison function: ascending by key.                                                        */
/* --------------------------------------------------------------------------------------------- */
static int32_t _SSFSLLTestCompare(const SSFSLLItem_t *a, const SSFSLLItem_t *b)
{
    const SSFSLLTest_t *ta = (const SSFSLLTest_t *)a;
    const SSFSLLTest_t *tb = (const SSFSLLTest_t *)b;

    if (ta->key < tb->key) return -1;
    if (ta->key > tb->key) return 1;
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Verifies list is in sorted order for the configured sort direction.                           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFSLLTestVerifySorted(const SSFSLL_t *sll)
{
    SSFSLLItem_t *cur;
    SSFSLLItem_t *next;

    cur = SSF_SLL_HEAD(sll);
    while (cur != NULL)
    {
        next = SSF_SLL_NEXT_ITEM(cur);
        if (next != NULL)
        {
            int32_t cmp = sll->compareFn(cur, next);
            if (sll->order == SSF_SLL_ORDER_ASCENDING)
            {
                SSF_ASSERT(cmp <= 0);
            }
            else
            {
                SSF_ASSERT(cmp >= 0);
            }
        }
        cur = next;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfsll's external interface.                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFSLLUnitTest(void)
{
    SSFSLLTest_t *outItem;
    uint32_t i;

    /* ---- SSF_ASSERT_TEST for NULL and invalid parameters ---- */
    SSF_ASSERT_TEST(SSFSLLInit(NULL, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare,
                               SSF_SLL_ORDER_ASCENDING));
    SSF_ASSERT_TEST(SSFSLLInit(&_ssfsllTest, 0, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING));
    SSF_ASSERT_TEST(SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, NULL,
                               SSF_SLL_ORDER_ASCENDING));
    SSF_ASSERT_TEST(SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare,
                               SSF_SLL_ORDER_MIN));
    SSF_ASSERT_TEST(SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare,
                               SSF_SLL_ORDER_MAX));

    SSF_ASSERT_TEST(SSFSLLInsertItem(NULL, (SSFSLLItem_t *)&_ssfsllItems[0]));
    SSF_ASSERT_TEST(SSFSLLInsertItem(&_ssfsllTest, NULL));

    SSF_ASSERT_TEST(SSFSLLRemoveItem(NULL, (SSFSLLItem_t *)&_ssfsllItems[0]));
    SSF_ASSERT_TEST(SSFSLLRemoveItem(&_ssfsllTest, NULL));

    SSF_ASSERT_TEST(SSFSLLPeekHead(NULL, (SSFSLLItem_t **)&outItem));
    SSF_ASSERT_TEST(SSFSLLPeekTail(NULL, (SSFSLLItem_t **)&outItem));
    SSF_ASSERT_TEST(SSFSLLPopHead(NULL, (SSFSLLItem_t **)&outItem));
    SSF_ASSERT_TEST(SSFSLLPopTail(NULL, (SSFSLLItem_t **)&outItem));

    SSF_ASSERT_TEST(SSFSLLIsEmpty(NULL));
    SSF_ASSERT_TEST(SSFSLLIsFull(NULL));
    SSF_ASSERT_TEST(SSFSLLSize(NULL));
    SSF_ASSERT_TEST(SSFSLLLen(NULL));
    SSF_ASSERT_TEST(SSFSLLUnused(NULL));

    /* ---- Init / DeInit ---- */
    SSF_ASSERT_TEST(SSFSLLDeInit(&_ssfsllTest));
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    SSF_ASSERT_TEST(SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare,
                               SSF_SLL_ORDER_ASCENDING));
    SSFSLLDeInit(&_ssfsllTest);
    SSF_ASSERT_TEST(SSFSLLDeInit(&_ssfsllTest));
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);

    /* ---- SSFSLLIsInited ---- */
    SSF_ASSERT(SSFSLLIsInited(&_ssfsllTest) == true);
    SSFSLLDeInit(&_ssfsllTest);
    SSF_ASSERT(SSFSLLIsInited(&_ssfsllTest) == false);

    /* ---- Empty list state ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == true);
    SSF_ASSERT(SSFSLLIsFull(&_ssfsllTest) == false);
    SSF_ASSERT(SSFSLLSize(&_ssfsllTest) == SSFSLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 0);
    SSF_ASSERT(SSFSLLUnused(&_ssfsllTest) == SSFSLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSF_SLL_HEAD(&_ssfsllTest) == NULL);
    SSF_ASSERT(SSF_SLL_TAIL(&_ssfsllTest) == NULL);
    SSF_ASSERT(SSFSLLPeekHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == false);
    SSF_ASSERT(SSFSLLPeekTail(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == false);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == false);
    SSF_ASSERT(SSFSLLPopTail(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == false);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- Ascending: insert single item ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 42;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == false);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 1);
    SSF_ASSERT(SSF_SLL_HEAD(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSF_ASSERT(SSF_SLL_TAIL(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSF_ASSERT(SSFSLLPeekHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem == &_ssfsllItems[0]);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 1);
    SSF_ASSERT(SSFSLLPeekTail(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem == &_ssfsllItems[0]);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem == &_ssfsllItems[0]);
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == true);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- Ascending: insert in order 3, 1, 2 -> sorted 1, 2, 3 ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 3;
    _ssfsllItems[1].key = 1;
    _ssfsllItems[2].key = 2;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[2]);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 3);
    _SSFSLLTestVerifySorted(&_ssfsllTest);
    /* Head should be key 1, tail should be key 3 */
    SSF_ASSERT(SSF_SLL_HEAD(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSF_ASSERT(SSF_SLL_TAIL(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[0]);
    /* Pop all ascending: 1, 2, 3 */
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 1);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 2);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 3);
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == true);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- Descending: insert in order 1, 3, 2 -> sorted 3, 2, 1 ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_DESCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 1;
    _ssfsllItems[1].key = 3;
    _ssfsllItems[2].key = 2;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[2]);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 3);
    _SSFSLLTestVerifySorted(&_ssfsllTest);
    /* Head should be key 3, tail should be key 1 */
    SSF_ASSERT(SSF_SLL_HEAD(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSF_ASSERT(SSF_SLL_TAIL(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[0]);
    /* Pop all descending: 3, 2, 1 */
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 3);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 2);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 1);
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == true);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- Ascending: duplicate keys maintain insertion stability ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 5;
    _ssfsllItems[1].key = 5;
    _ssfsllItems[2].key = 5;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[2]);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 3);
    _SSFSLLTestVerifySorted(&_ssfsllTest);
    /* All equal: insertion order preserved, newest at head */
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem == &_ssfsllItems[2]);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem == &_ssfsllItems[1]);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem == &_ssfsllItems[0]);
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == true);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- RemoveItem: remove from head, middle, tail ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 10;
    _ssfsllItems[1].key = 20;
    _ssfsllItems[2].key = 30;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[2]);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 3);

    /* Remove middle (key 20) */
    SSF_ASSERT(SSFSLLRemoveItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]) == true);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 2);
    SSF_ASSERT(SSF_SLL_HEAD(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSF_ASSERT(SSF_SLL_TAIL(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[2]);
    SSF_ASSERT(SSF_SLL_NEXT_ITEM((SSFSLLItem_t *)&_ssfsllItems[0]) ==
               (SSFSLLItem_t *)&_ssfsllItems[2]);
    SSF_ASSERT(SSF_SLL_PREV_ITEM((SSFSLLItem_t *)&_ssfsllItems[2]) ==
               (SSFSLLItem_t *)&_ssfsllItems[0]);

    /* Remove head (key 10) */
    SSF_ASSERT(SSFSLLRemoveItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]) == true);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 1);
    SSF_ASSERT(SSF_SLL_HEAD(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[2]);
    SSF_ASSERT(SSF_SLL_TAIL(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[2]);

    /* Remove tail (key 30) */
    SSF_ASSERT(SSFSLLRemoveItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[2]) == true);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 0);
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == true);
    SSF_ASSERT(SSF_SLL_HEAD(&_ssfsllTest) == NULL);
    SSF_ASSERT(SSF_SLL_TAIL(&_ssfsllTest) == NULL);

    /* Remove item not in list returns false */
    SSF_ASSERT(SSFSLLRemoveItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]) == false);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- PopTail ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 1;
    _ssfsllItems[1].key = 2;
    _ssfsllItems[2].key = 3;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[2]);
    /* Pop from tail: 3, 2, 1 */
    SSF_ASSERT(SSFSLLPopTail(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 3);
    SSF_ASSERT(SSFSLLPopTail(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 2);
    SSF_ASSERT(SSFSLLPopTail(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 1);
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == true);
    SSF_ASSERT(SSFSLLPopTail(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == false);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- Fill to capacity ascending ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    for (i = 0; i < SSFSLL_TEST_MAX_SIZE; i++)
    {
        _ssfsllItems[i].key = (int32_t)(SSFSLL_TEST_MAX_SIZE - i);
        SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[i]);
    }
    SSF_ASSERT(SSFSLLIsFull(&_ssfsllTest) == true);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == SSFSLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFSLLUnused(&_ssfsllTest) == 0);
    _SSFSLLTestVerifySorted(&_ssfsllTest);

    /* Verify insert on full list asserts */
    _ssfsllItems[SSFSLL_TEST_MAX_SIZE].key = 0;
    SSF_ASSERT_TEST(SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)
                                     &_ssfsllItems[SSFSLL_TEST_MAX_SIZE]));

    /* Verify insert of already-in-list item asserts */
    SSF_ASSERT_TEST(SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]));

    /* Pop all ascending and verify sorted order */
    for (i = 0; i < SSFSLL_TEST_MAX_SIZE; i++)
    {
        SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
        SSF_ASSERT(outItem->key == (int32_t)(i + 1));
    }
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == true);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- Fill to capacity descending ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_DESCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    for (i = 0; i < SSFSLL_TEST_MAX_SIZE; i++)
    {
        _ssfsllItems[i].key = (int32_t)(i + 1);
        SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[i]);
    }
    SSF_ASSERT(SSFSLLIsFull(&_ssfsllTest) == true);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == SSFSLL_TEST_MAX_SIZE);
    _SSFSLLTestVerifySorted(&_ssfsllTest);

    /* Pop all from head: should be descending SSFSLL_TEST_MAX_SIZE, ..., 2, 1 */
    for (i = 0; i < SSFSLL_TEST_MAX_SIZE; i++)
    {
        SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
        SSF_ASSERT(outItem->key == (int32_t)(SSFSLL_TEST_MAX_SIZE - i));
    }
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == true);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- Forward and backward traversal ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 30;
    _ssfsllItems[1].key = 10;
    _ssfsllItems[2].key = 20;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[2]);
    /* Ascending order: 10, 20, 30 */
    {
        SSFSLLItem_t *cur;

        /* Forward: head -> 10 -> 20 -> 30 -> NULL */
        cur = SSF_SLL_HEAD(&_ssfsllTest);
        SSF_ASSERT(((SSFSLLTest_t *)cur)->key == 10);
        cur = SSF_SLL_NEXT_ITEM(cur);
        SSF_ASSERT(((SSFSLLTest_t *)cur)->key == 20);
        cur = SSF_SLL_NEXT_ITEM(cur);
        SSF_ASSERT(((SSFSLLTest_t *)cur)->key == 30);
        cur = SSF_SLL_NEXT_ITEM(cur);
        SSF_ASSERT(cur == NULL);

        /* Backward: tail -> 30 -> 20 -> 10 -> NULL */
        cur = SSF_SLL_TAIL(&_ssfsllTest);
        SSF_ASSERT(((SSFSLLTest_t *)cur)->key == 30);
        cur = SSF_SLL_PREV_ITEM(cur);
        SSF_ASSERT(((SSFSLLTest_t *)cur)->key == 20);
        cur = SSF_SLL_PREV_ITEM(cur);
        SSF_ASSERT(((SSFSLLTest_t *)cur)->key == 10);
        cur = SSF_SLL_PREV_ITEM(cur);
        SSF_ASSERT(cur == NULL);
    }
    /* Clean up */
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(SSFSLLIsEmpty(&_ssfsllTest) == true);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- Ascending: already sorted insertion ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 1;
    _ssfsllItems[1].key = 2;
    _ssfsllItems[2].key = 3;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[2]);
    _SSFSLLTestVerifySorted(&_ssfsllTest);
    SSF_ASSERT(SSF_SLL_HEAD(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSF_ASSERT(SSF_SLL_TAIL(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[2]);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 1);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 2);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 3);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- Ascending: reverse sorted insertion ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 3;
    _ssfsllItems[1].key = 2;
    _ssfsllItems[2].key = 1;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[2]);
    _SSFSLLTestVerifySorted(&_ssfsllTest);
    SSF_ASSERT(SSF_SLL_HEAD(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[2]);
    SSF_ASSERT(SSF_SLL_TAIL(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 1);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 2);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 3);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- Remove and reinsert ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 10;
    _ssfsllItems[1].key = 20;
    _ssfsllItems[2].key = 30;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[2]);
    /* Remove key 20, change to key 5, reinsert */
    SSF_ASSERT(SSFSLLRemoveItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]) == true);
    _ssfsllItems[1].key = 5;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSF_ASSERT(SSFSLLLen(&_ssfsllTest) == 3);
    _SSFSLLTestVerifySorted(&_ssfsllTest);
    /* Order should be 5, 10, 30 */
    SSF_ASSERT(SSF_SLL_HEAD(&_ssfsllTest) == (SSFSLLItem_t *)&_ssfsllItems[1]);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 5);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 10);
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSF_ASSERT(outItem->key == 30);
    SSFSLLDeInit(&_ssfsllTest);

    /* ---- DeInit requires empty list ---- */
    SSFSLLInit(&_ssfsllTest, SSFSLL_TEST_MAX_SIZE, _SSFSLLTestCompare, SSF_SLL_ORDER_ASCENDING);
    memset(_ssfsllItems, 0, sizeof(_ssfsllItems));
    _ssfsllItems[0].key = 1;
    SSFSLLInsertItem(&_ssfsllTest, (SSFSLLItem_t *)&_ssfsllItems[0]);
    SSF_ASSERT_TEST(SSFSLLDeInit(&_ssfsllTest));
    SSF_ASSERT(SSFSLLPopHead(&_ssfsllTest, (SSFSLLItem_t **)&outItem) == true);
    SSFSLLDeInit(&_ssfsllTest);
}
#endif /* SSF_CONFIG_SLL_UNIT_TEST */
