/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsll.h                                                                                      */
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
#ifndef SSF_SLL_INCLUDE_H
#define SSF_SLL_INCLUDE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* Sort order */
typedef enum
{
    SSF_SLL_ORDER_MIN = -1,
    SSF_SLL_ORDER_ASCENDING,
    SSF_SLL_ORDER_DESCENDING,
    SSF_SLL_ORDER_MAX,
} SSF_SLL_ORDER_t;

typedef struct SSFSLLItem SSFSLLItem_t;
typedef struct SSFSLL SSFSLL_t;

/* Comparison function pointer for sorting. */
/* Returns negative if a < b, 0 if a == b, positive if a > b. */
typedef int32_t (*SSFSLLCompareFn_t)(const SSFSLLItem_t *a, const SSFSLLItem_t *b);

struct SSFSLLItem
{
    SSFSLLItem_t *next;
    SSFSLLItem_t *prev;
    SSFSLL_t *sll;
};

struct SSFSLL
{
    SSFSLLItem_t *head;
    SSFSLLItem_t *tail;
    uint32_t items;
    uint32_t size;
    SSFSLLCompareFn_t compareFn;
    SSF_SLL_ORDER_t order;
    uint32_t magic;
};

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFSLLInit(SSFSLL_t *sll, uint32_t maxSize, SSFSLLCompareFn_t compareFn,
                SSF_SLL_ORDER_t order);
void SSFSLLDeInit(SSFSLL_t *sll);
bool SSFSLLIsInited(SSFSLL_t *sll);
void SSFSLLInsertItem(SSFSLL_t *sll, SSFSLLItem_t *inItem);
bool SSFSLLRemoveItem(SSFSLL_t *sll, SSFSLLItem_t *outItem);
bool SSFSLLPeekHead(const SSFSLL_t *sll, SSFSLLItem_t **outItem);
bool SSFSLLPeekTail(const SSFSLL_t *sll, SSFSLLItem_t **outItem);
bool SSFSLLPopHead(SSFSLL_t *sll, SSFSLLItem_t **outItem);
bool SSFSLLPopTail(SSFSLL_t *sll, SSFSLLItem_t **outItem);
bool SSFSLLIsEmpty(const SSFSLL_t *sll);
bool SSFSLLIsFull(const SSFSLL_t *sll);
uint32_t SSFSLLSize(const SSFSLL_t *sll);
uint32_t SSFSLLLen(const SSFSLL_t *sll);
uint32_t SSFSLLUnused(const SSFSLL_t *sll);

#define SSF_SLL_HEAD(sll) ((sll)->head)
#define SSF_SLL_TAIL(sll) ((sll)->tail)
#define SSF_SLL_NEXT_ITEM(item) ((item)->next)
#define SSF_SLL_PREV_ITEM(item) ((item)->prev)

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_SLL_UNIT_TEST == 1
void SSFSLLUnitTest(void);
#endif /* SSF_CONFIG_SLL_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_SLL_INCLUDE_H */
