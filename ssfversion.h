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
/* --------------------------------------------------------------------------------------------- */
#define SSF_VERSION "0.0.5"

#endif /* SSF_VERSION_H_INCLUDE */
