/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* main.c                                                                                        */
/* Entry point for unit testing SSF components.                                                  */
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
#include <stdio.h>
#include "ssfassert.h"
#include "ssfbfifo.h"
#include "ssfll.h"
#include "ssfsm.h"
#include "ssfmpool.h"
#include "ssfport.h"
#include "ssfjson.h"
#include "ssfbase64.h"
#include "ssfhex.h"
#include "ssffcsum.h"
#include "ssfrs.h"
#include "ssfcrc16.h"
#include "ssfcrc32.h"

/* --------------------------------------------------------------------------------------------- */
/* SSF unit test entry point.                                                                    */
/* --------------------------------------------------------------------------------------------- */
void main(void)
{
#if SSF_CONFIG_BFIFO_UNIT_TEST == 1
    SSFBFifoUnitTest();
#endif /* SSF_CONFIG_BFIFO_UNIT_TEST */

#if SSF_CONFIG_LL_UNIT_TEST == 1
    SSFLLUnitTest();
#endif  /* SSF_CONFIG_LL_UNIT_TEST */

#if SSF_CONFIG_MPOOL_UNIT_TEST == 1
    SSFMPoolUnitTest();
#endif /* SSF_CONFIG_MPOOL_UNIT_TEST */

#if SSF_CONFIG_BASE64_UNIT_TEST == 1
    SSFBase64UnitTest();
#endif /* SSF_CONFIG_BASE64_UNIT_TEST */

#if SSF_CONFIG_HEX_UNIT_TEST == 1
    SSFHexUnitTest();
#endif /* SSF_CONFIG_BASE64_UNIT_TEST */

#if SSF_CONFIG_JSON_UNIT_TEST == 1
    SSFJsonUnitTest();
#endif /* SSF_CONFIG_JSON_UNIT_TEST */

#if SSF_CONFIG_FCSUM_UNIT_TEST == 1
    SSFFCSumUnitTest();
#endif /* SSF_CONFIG_FCSUM_UNIT_TEST */

#if SSF_CONFIG_SM_UNIT_TEST == 1
    SSFSMUnitTest();
#endif /* SSF_CONFIG_SM_UNIT_TEST */

#if SSF_CONFIG_RS_UNIT_TEST == 1
    SSFRSUnitTest();
#endif /* SSF_CONFIG_SM_UNIT_TEST */

#if SSF_CONFIG_CRC16_UNIT_TEST == 1
    SSFCRC16UnitTest();
#endif /* SSF_CONFIG_CRC16_UNIT_TEST */

#if SSF_CONFIG_CRC32_UNIT_TEST == 1
    SSFCRC32UnitTest();
#endif /* SSF_CONFIG_CRC32_UNIT_TEST */
}
