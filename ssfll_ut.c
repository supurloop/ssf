/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfll_ut.c                                                                                    */
/* Provides unit tests for ssfll's linked list interface.                                        */
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
#include "ssfll.h"
#include "ssfport.h"

#if SSF_CONFIG_LL_UNIT_TEST == 1

    #define SLL_TEST_MAX_SIZE 128

typedef struct SSFLLTest
{
    SSFLLItem_t item;
    uint8_t data;
} SSFLLTest_t;

SSFLLTest_t _sllItems[SLL_TEST_MAX_SIZE + 1];
SSFLL_t _sllTest;

/* --------------------------------------------------------------------------------------------- */
/* Fills at head.                                                                                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFLLUnitTestFillAtHead(uint32_t num)
{
    uint32_t i;

    /* Fill list at head */
    for (i = 0; i < num - 1; i++)
    {
        SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[i], SSF_LL_LOC_HEAD, NULL);
        SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
        if (i == (SLL_TEST_MAX_SIZE - 1)) SSF_ASSERT(SSFLLIsFull(&_sllTest) == true);
        else SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
        SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
        SSF_ASSERT(SSFLLLen(&_sllTest) == (i + 1));
        SSF_ASSERT(SSFLLUnused(&_sllTest) == (SLL_TEST_MAX_SIZE - (i + 1)));
        SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[i]);
        SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);
    }
    SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[i], SSF_LL_LOC_HEAD, NULL);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    if (num == SLL_TEST_MAX_SIZE) SSF_ASSERT(SSFLLIsFull(&_sllTest) == true);
    else SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == num);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == (SLL_TEST_MAX_SIZE - num));
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[num - 1]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);
    if (num == SLL_TEST_MAX_SIZE)
    {
        SSF_ASSERT_TEST(SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[num - 1],
                                     SSF_LL_LOC_HEAD, NULL));
        SSF_ASSERT_TEST(SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[num], SSF_LL_LOC_HEAD,
                                     NULL));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Fills at tail.                                                                                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFLLUnitTestFillAtTail(uint32_t num)
{
    uint32_t i;

    /* Fill list at tail */
    for (i = 0; i < num - 1; i++)
    {
        SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[num - (i + 1)], SSF_LL_LOC_TAIL, NULL);
        SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
        SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
        SSF_ASSERT(SSFLLSize(&_sllTest) == num);
        SSF_ASSERT(SSFLLLen(&_sllTest) == (i + 1));
        SSF_ASSERT(SSFLLUnused(&_sllTest) == (num - (i + 1)));
        SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[num - 1]);
        SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[num - (i + 1)]);
    }
    SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[num - (i + 1)], SSF_LL_LOC_TAIL, NULL);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    SSF_ASSERT(SSFLLIsFull(&_sllTest) == true);
    SSF_ASSERT(SSFLLSize(&_sllTest) == num);
    SSF_ASSERT(SSFLLLen(&_sllTest) == num);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == 0);
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[num - 1]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);
    if (num == SLL_TEST_MAX_SIZE)
    {
        SSF_ASSERT_TEST(SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[num - 1],
                                     SSF_LL_LOC_TAIL, NULL));
        SSF_ASSERT_TEST(SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[num], SSF_LL_LOC_TAIL,
                                     NULL));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Empties from head.                                                                            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFLLUnitTestEmptyFromHead(uint32_t num)
{
    uint32_t i;
    SSFLLTest_t *outItem;

    /* Empty from head */
    for (i = 0; i < num - 1; i++)
    {
        SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_HEAD, NULL));
        SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
        SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
        SSF_ASSERT(SSFLLSize(&_sllTest) == num);
        SSF_ASSERT(SSFLLLen(&_sllTest) == (num - (i + 1)));
        SSF_ASSERT(SSFLLUnused(&_sllTest) == (i + 1));
        SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[num - (i + 2)]);
        SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);
    }
    SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_HEAD, NULL) == true);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == true);
    SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == num);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 0);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == num);
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == NULL);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == NULL);
    SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_HEAD, NULL) == false);
}

/* --------------------------------------------------------------------------------------------- */
/* Empties from tail.                                                                            */
/* --------------------------------------------------------------------------------------------- */
static void _SSFLLUnitTestEmptyFromTail(uint32_t num)
{
    uint32_t i;
    SSFLLTest_t *outItem;

    /* Empty from tail */
    for (i = 0; i < num - 1; i++)
    {
        SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_TAIL, NULL));
        SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
        SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
        SSF_ASSERT(SSFLLSize(&_sllTest) == num);
        SSF_ASSERT(SSFLLLen(&_sllTest) == (num - (i + 1)));
        SSF_ASSERT(SSFLLUnused(&_sllTest) == (i + 1));
        SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[num - 1]);
        SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[i + 1]);
    }
    SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_TAIL, NULL));
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == true);
    SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == num);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 0);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == num);
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == NULL);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == NULL);
    SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_TAIL, NULL) == false);
}

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfll's external interface.                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFLLUnitTest(void)
{
    SSFLLTest_t *outItem;

    SSF_ASSERT_TEST(SSFLLInit(NULL, SLL_TEST_MAX_SIZE));
    SSF_ASSERT_TEST(SSFLLInit(&_sllTest, 0));

    SSF_ASSERT_TEST(SSFLLPutItem(NULL, (SSFLLItem_t *)&_sllItems[0], SSF_LL_LOC_HEAD, NULL));
    SSF_ASSERT_TEST(SSFLLPutItem(&_sllTest, NULL, SSF_LL_LOC_HEAD, NULL));
    SSF_ASSERT_TEST(SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[0], SSF_LL_LOC_MAX, NULL));
    SSF_ASSERT_TEST(SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[0], SSF_LL_LOC_HEAD,
                                 (SSFLLItem_t *)&_sllItems[0]));
    SSF_ASSERT_TEST(SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[0], SSF_LL_LOC_TAIL,
                                 (SSFLLItem_t *)&_sllItems[0]));

    SSF_ASSERT_TEST(SSFLLGetItem(NULL, (SSFLLItem_t **)&outItem, SSF_LL_LOC_HEAD, NULL));
    SSF_ASSERT_TEST(SSFLLGetItem(&_sllTest, NULL, SSF_LL_LOC_HEAD, NULL));
    SSF_ASSERT_TEST(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_MAX, NULL));
    SSF_ASSERT_TEST(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_HEAD,
                                 (SSFLLItem_t *)&_sllItems[0]));
    SSF_ASSERT_TEST(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_TAIL,
                                 (SSFLLItem_t *)&_sllItems[0]));
    SSF_ASSERT_TEST(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_ITEM, NULL));

    SSF_ASSERT_TEST(SSFLLIsEmpty(NULL));
    SSF_ASSERT_TEST(SSFLLIsFull(NULL));
    SSF_ASSERT_TEST(SSFLLSize(NULL));
    SSF_ASSERT_TEST(SSFLLLen(NULL));
    SSF_ASSERT_TEST(SSFLLUnused(NULL));

    /* Initialize list */
    SSFLLInit(&_sllTest, SLL_TEST_MAX_SIZE);
    SSF_ASSERT_TEST(SSFLLInit(&_sllTest, SLL_TEST_MAX_SIZE));
    SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_HEAD, NULL) == false);
    SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_TAIL, NULL) == false);
    SSF_ASSERT_TEST(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_ITEM, NULL));
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == true);
    SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 0);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == NULL);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == NULL);

    _SSFLLUnitTestFillAtHead(SLL_TEST_MAX_SIZE);
    _SSFLLUnitTestEmptyFromHead(SLL_TEST_MAX_SIZE);

    _SSFLLUnitTestFillAtHead(SLL_TEST_MAX_SIZE);
    _SSFLLUnitTestEmptyFromTail(SLL_TEST_MAX_SIZE);

    _SSFLLUnitTestFillAtTail(SLL_TEST_MAX_SIZE);
    _SSFLLUnitTestEmptyFromHead(SLL_TEST_MAX_SIZE);

    _SSFLLUnitTestFillAtTail(SLL_TEST_MAX_SIZE);
    _SSFLLUnitTestEmptyFromTail(SLL_TEST_MAX_SIZE);

    /* Remove item tests from list with 1 item */
    _SSFLLUnitTestFillAtHead(1);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    if (SLL_TEST_MAX_SIZE == 1) SSF_ASSERT(SSFLLIsFull(&_sllTest) == true);
    else SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 1);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == SLL_TEST_MAX_SIZE - 1);
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);
    SSF_ASSERT_TEST(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_ITEM,
                                 (SSFLLItem_t *)&_sllItems[1]));
    SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_ITEM,
                            (SSFLLItem_t *)&_sllItems[0]) == true);
    SSF_ASSERT(outItem == &_sllItems[0]);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == true);
    SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 0);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == NULL);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == NULL);

    /* Insert and remove multiple item tests */
#if SLL_TEST_MAX_SIZE >= 2
    _SSFLLUnitTestFillAtHead(2);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    if (SLL_TEST_MAX_SIZE == 2) SSF_ASSERT(SSFLLIsFull(&_sllTest) == true);
    else SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 2);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == (SLL_TEST_MAX_SIZE - 2));
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[1]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);
    SSF_ASSERT_TEST(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_ITEM,
                                 (SSFLLItem_t *)&_sllItems[2]));

    SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_ITEM,
                            (SSFLLItem_t *)&_sllItems[0]) == true);
    SSF_ASSERT(outItem == &_sllItems[0]);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 1);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == (SLL_TEST_MAX_SIZE - 1));
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[1]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[1]);

    SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[0], SSF_LL_LOC_ITEM, NULL);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    if (SLL_TEST_MAX_SIZE == 2) SSF_ASSERT(SSFLLIsFull(&_sllTest) == true);
    else SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 2);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == (SLL_TEST_MAX_SIZE - 2));
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[1]);

    SSF_ASSERT_TEST(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_ITEM,
                                 (SSFLLItem_t *)&_sllItems[2]));
    SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_ITEM,
                            (SSFLLItem_t *)&_sllItems[0]) == true);
    SSF_ASSERT(outItem == &_sllItems[0]);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 1);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == (SLL_TEST_MAX_SIZE - 1));
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[1]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[1]);

    SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[0], SSF_LL_LOC_ITEM,
                 (SSFLLItem_t *)&_sllItems[1]);
    SSF_ASSERT_TEST(SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[2], SSF_LL_LOC_ITEM,
                                 (SSFLLItem_t *)&_sllItems[3]));
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    if (SLL_TEST_MAX_SIZE == 2) SSF_ASSERT(SSFLLIsFull(&_sllTest) == true);
    else SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 2);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == (SLL_TEST_MAX_SIZE - 2));
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[1]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);
#endif /* SLL_TEST_MAX_SIZE */

#if SLL_TEST_MAX_SIZE >= 3
    SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[2], SSF_LL_LOC_ITEM,
                 (SSFLLItem_t *)&_sllItems[1]);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    if (SLL_TEST_MAX_SIZE == 3) SSF_ASSERT(SSFLLIsFull(&_sllTest) == true);
    else SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 3);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == (SLL_TEST_MAX_SIZE - 3));
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[1]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);

    SSF_ASSERT(SSFLLGetItem(&_sllTest, (SSFLLItem_t **)&outItem, SSF_LL_LOC_ITEM,
                            (SSFLLItem_t *)&_sllItems[1]) == true);
    SSF_ASSERT(outItem == &_sllItems[1]);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 2);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == (SLL_TEST_MAX_SIZE - 2));
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[2]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[0]);

    SSFLLPutItem(&_sllTest, (SSFLLItem_t *)&_sllItems[1], SSF_LL_LOC_ITEM,
                 (SSFLLItem_t *)&_sllItems[0]);
    SSF_ASSERT(SSFLLIsEmpty(&_sllTest) == false);
    if (SLL_TEST_MAX_SIZE == 3) SSF_ASSERT(SSFLLIsFull(&_sllTest) == true);
    else SSF_ASSERT(SSFLLIsFull(&_sllTest) == false);
    SSF_ASSERT(SSFLLSize(&_sllTest) == SLL_TEST_MAX_SIZE);
    SSF_ASSERT(SSFLLLen(&_sllTest) == 3);
    SSF_ASSERT(SSFLLUnused(&_sllTest) == (SLL_TEST_MAX_SIZE - 3));
    SSF_ASSERT(SSF_LL_HEAD(&_sllTest) == (SSFLLItem_t *)&_sllItems[2]);
    SSF_ASSERT(SSF_LL_TAIL(&_sllTest) == (SSFLLItem_t *)&_sllItems[1]);
#endif /* SLL_TEST_MAX_SIZE */
}
#endif /* SSF_CONFIG_LL_UNIT_TEST */

