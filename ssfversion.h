/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfversion.h                                                                                  */
/* Provides SSF version.                                                                         */
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
#ifndef SSF_VERSION_H_INCLUDE
#define SSF_VERSION_H_INCLUDE

/* --------------------------------------------------------------------------------------------- */
/* Version History                                                                               */
/*                                                                                               */
/* 0.0.1 - Initial beta release.                                                                 */
/* 0.0.2 - Add Reed-Solomon GF(2^8) interface.                                                   */
/* 0.0.3 - Add XMODEM/CCITT-16 CRC16 and CCITT-32 CRC32 interfaces.                              */
/* 0.0.4 - Add SHA-2 and TLV encoder/decoder interfaces.                                         */
/*         Increased Windows and Linux build warning levels and fixed warnings.                  */
/* 0.0.5 - Add AES and AES-GCM interfaces.                                                       */
/*         Add build script for OS X.                                                            */
/*         Fix some build warnings for OS X.                                                     */
/*         Optimized bin to hex interface.                                                       */
/* 0.0.6 - Upgraded Visual Studio solution and project to Community 2022 version.                */
/*         Optimized Reed Solomon performance.                                                   */
/*         Added optional multi-thread support to FSM framework.                                 */
/*         Fixed bug in FSM framework where nextTimeout was computed incorrectly.                */
/*         Implemented Configuration Storage interface.                                          */
/*         Added PRNG interface which can generate cryptographically secure random numbers.      */
/*         Added macros to support SSF use from C++ modules.                                     */
/*         Minor formatting changes and compiler warning fixes.                                  */
/* 0.0.7 - Added deinitialization support.                                                       */
/*         Fixed ssfsm timer w/data memory leak.                                                 */
/*         Preliminary UBJSON interface.                                                         */
/* 0.0.8 - Added UBJSON interface.                                                               */
/*         Added enum lower bound checks.                                                        */
/*         Added ssfrs option for GF_MUL speed vs. space optimization.                           */
/*         Reorganized source code into module directories.                                      */
/* 0.0.9 - Added integer to decimal string conversion interface.                                 */
/*         Added date/time, RTC, and ISO8601 time interfaces.                                    */
/* 0.1.0 - Moved compile time options to ssfoptions.h.                                           */
/*       - Bug fixes and enhancements to UBJSON interface.                                       */
/*       - Added string to decimal integer conversion interface.                                 */
/*       - Added safe string interface.                                                          */
/*       - Added debuggable, integrity check heap interface.                                     */
/* 0.1.1 - Fix UBJSON parser bug that incorrectly converts unsigned int to a negative number.    */
/*       - Elimimate reentrancy problem in dtime interface.                                      */
/*       - Skip some dtime unit tests on 32-bit systems.                                         */
/*       - Fix various compiler warnings.                                                        */
/*       - Remove escaping of / in JSON string generator interface.                              */
/*       - Allow top level arrays in JSON interface.                                             */
/*       - Allow top level arrays in UBJSON interface.                                           */
/*       - Miscellaneous code clean up.                                                          */
/*       - Fix bug in fsm interface where a pending timer is not updated when StartTimer called. */
/*       - Updated fsm interface to have 1 level of nesting, a superstate.                       */
/*       - Beta version of generic object interface.                                             */
/*       - Better organized the source files in Visual Studio project.                           */
/* --------------------------------------------------------------------------------------------- */
#define SSF_VERSION_STR "0.1.1"

#endif /* SSF_VERSION_H_INCLUDE */
