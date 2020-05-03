/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfll.h                                                                                       */
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
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISE   */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_LL_INCLUDE_H
#define SSF_LL_INCLUDE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */
typedef enum SSF_LL_LOC
{
    SSF_LL_LOC_HEAD,
    SSF_LL_LOC_TAIL,
    SSF_LL_LOC_ITEM,
    SSF_LL_LOC_MAX,
} SSF_LL_LOC_t;

typedef struct SSFLLItem SSFLLItem_t;
typedef struct SSFLL SSFLL_t;

struct SSFLLItem
{
    SSFLLItem_t *next;
    SSFLLItem_t *prev;
    SSFLL_t *ll;
};

struct SSFLL
{
    SSFLLItem_t *head;
    SSFLLItem_t *tail;
    uint32_t items;
    uint32_t size;
    uint32_t magic;
};

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFLLInit(SSFLL_t *ll, uint32_t maxSize);
void SSFLLPutItem(SSFLL_t *ll, SSFLLItem_t *inItem, SSF_LL_LOC_t loc, SSFLLItem_t *locItem);
bool SSFLLGetItem(SSFLL_t *ll, SSFLLItem_t **outItem, SSF_LL_LOC_t loc, SSFLLItem_t *locItem);
bool SSFLLIsEmpty(const SSFLL_t *ll);
bool SSFLLIsFull(const SSFLL_t *ll);
uint32_t SSFLLSize(const SSFLL_t *ll);
uint32_t SSFLLLen(const SSFLL_t *ll);
uint32_t SSFLLUnused(const SSFLL_t *ll);

#define SSF_LL_PUT(ll, inItem, locItem) \
    SSFLLPutItem(ll, (SSFLLItem_t *)inItem, SSF_LL_LOC_ITEM, (SSFLLItem_t *)locItem)
#define SSF_LL_GET(ll, outItem, locItem) \
    SSFLLGetItem(ll, (SSFLLItem_t **)outItem, SSF_LL_LOC_ITEM, (SSFLLItem_t *)locItem)

#define SSF_LL_STACK_PUSH(ll, inItem) SSFLLPutItem(ll, (SSFLLItem_t *)inItem, SSF_LL_LOC_HEAD, \
                                                   NULL)
#define SSF_LL_STACK_POP(ll, outItem) SSFLLGetItem(ll, (SSFLLItem_t **)outItem, SSF_LL_LOC_HEAD, \
                                                   NULL)
#define SSF_LL_FIFO_PUSH(ll, inItem) SSFLLPutItem(ll, (SSFLLItem_t *)inItem, SSF_LL_LOC_HEAD, \
                                                  NULL)
#define SSF_LL_FIFO_POP(ll, outItem) SSFLLGetItem(ll, (SSFLLItem_t **)outItem, SSF_LL_LOC_TAIL, \
                                                  NULL)

#define SSF_LL_HEAD(ll) ((ll)->head)
#define SSF_LL_TAIL(ll) ((ll)->tail)
#define SSF_LL_NEXT_ITEM(item) ((item)->next)
#define SSF_LL_PREV_ITEM(item) ((item)->prev)

#if SSF_CONFIG_LL_UNIT_TEST == 1
void SSFLLUnitTest(void);
#endif /* SSF_CONFIG_LL_UNIT_TEST */

#endif

