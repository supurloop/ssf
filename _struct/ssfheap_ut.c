/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfheap_ut.c                                                                                  */
/* Provides debuggable, integrity checked heap interface.                                        */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2023 Supurloop Software LLC                                                         */
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
#include <stdio.h>
#include "ssfheap.h"
#include "ssfport.h"
#include "ssfassert.h"

#if SSF_CONFIG_HEAP_UNIT_TEST == 1

#define HEAP_SIZE (81970u)
uint8_t heap[HEAP_SIZE];
#define MAX_ALLOCS (HEAP_SIZE)
uint8_t* ptrs[MAX_ALLOCS];
#define APP_MARK 'a'
SSFHeapStatus_t heapStatusOut;
SSFHeapHandle_t heapHandle;
uint32_t frees, allocs, allocs1;

/* --------------------------------------------------------------------------------------------- */
/* Performs unit test on ssfheap's external interface.                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFHeapUnitTest(void)
{
    size_t i, j;
    uint32_t rindex;
    uint32_t rsize;

    /* Unit test is a Work In Progress (WIP) */

    for (j = SSFHeapInitMinMemSize(); j <= sizeof(heap); j++)
    {
        //printf("j:%d TA:%u A:%u F:%u\r\n", j, allocs1, allocs, frees);
        SSFHeapInit(&heapHandle, heap, j, 0xff, false);
        SSFHeapCheck(heapHandle);

        for (i = 0; i < 1000; i++)
        {
            rindex = rand() % j;
            rsize = rand() % j;

            if (ptrs[rindex] != NULL)
            {
                //printf("%u/%u:FREE  %d, %d\r\n", j, i, rindex, rsize);
                SSFHeapFree(heapHandle, &ptrs[rindex], NULL);
                frees++;
            }
            else
            {
                //printf("%u/%u:ALLOC %d, %d\r\n", j, i, rindex, rsize);
                SSFHeapMalloc(heapHandle, &ptrs[rindex], rsize, APP_MARK);
                allocs1++;

                if (ptrs[rindex] != NULL)
                {
                    allocs++;
                    // printf("ALSET %d, %d\r\n", rindex, rsize);
                     //memset(ptrs[rindex], 0x41, rsize);
                }

            }
            SSFHeapCheck(heapHandle);
            SSFHeapStatus(heapHandle, &heapStatusOut);
        }

        /* Free everything */
        for (i = 0; i < MAX_ALLOCS; i++)
        {
            if (ptrs[i] != NULL)
            {
                SSFHeapFree(heapHandle, &ptrs[i], NULL);
                SSFHeapCheck(heapHandle);
            }
        }
        SSFHeapStatus(heapHandle, &heapStatusOut);
        SSFHeapDeInit(&heapHandle, true);
    }
}
#endif /* SSF_CONFIG_HEAP_UNIT_TEST */

