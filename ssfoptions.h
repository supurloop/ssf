/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfoptions.h                                                                                  */
/* Aggregator façade — pulls in every per-module configuration header from _opt/.                */
/* Existing code that #includes only "ssfoptions.h" continues to work unchanged.                  */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2022 Supurloop Software LLC                                                         */
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
#ifndef SSF_OPTIONS_H_INCLUDE
#define SSF_OPTIONS_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "ssfport.h"
#include "ssfassert.h"

/* Per-module option files. Each is also includable directly by its module's source. */
#include "ssfasn1_opt.h"
#include "ssfbfifo_opt.h"
#include "ssfbn_opt.h"
#include "ssfcfg_opt.h"
#include "ssfcli_opt.h"
#include "ssfdtime_opt.h"
#include "ssfec_opt.h"
#include "ssfgobj_opt.h"
#include "ssfheap_opt.h"
#include "ssfini_opt.h"
#include "ssfiso8601_opt.h"
#include "ssfjson_opt.h"
#include "ssflptask_opt.h"
#include "ssfmpool_opt.h"
#include "ssfrs_opt.h"
#include "ssfrsa_opt.h"
#include "ssfrtc_opt.h"
#include "ssfsm_opt.h"
#include "ssftls_opt.h"
#include "ssftlv_opt.h"
#include "ssfubjson_opt.h"
#include "ssfvted_opt.h"
#include "ssfx25519_opt.h"

#ifdef __cplusplus
}
#endif

#endif /* SSF_OPTIONS_H_INCLUDE */
