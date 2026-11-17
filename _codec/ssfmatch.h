/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfmatch.h                                                                                    */
/* Provides lightweight pattern matching interfaces.                                             */
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
#ifndef SSF_MATCH_H_INCLUDE
#define SSF_MATCH_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* Extracted parameter from path pattern matching */
typedef struct SSFMatchParam
{
    SSFCStrIn_t name;             /* parameter name (points into pattern string) */
    uint32_t nameLen;
    SSFCStrIn_t value;            /* parameter value (points into path string) */
    uint32_t valueLen;
} SSFMatchParam_t;

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Case-insensitive ASCII string comparison. Returns true if equal, else false.
 * Suitable for HTTP field-name matching (RFC 7230 §3.2). Not Unicode-aware. */
bool SSFMatchStrI(SSFCStrIn_t a, SSFCStrIn_t b);

/* Case-insensitive ASCII string comparison for a given length. POSIX strncasecmp-style:
 * stops at '\0' in either input, so passing a len larger than the actual string length
 * is safe. Returns true if equal. */
bool SSFMatchStrNI(SSFCStrIn_t a, SSFCStrIn_t b, uint32_t len);

/* Glob pattern matching — a deliberate subset of POSIX.1-2017 §2.13 ("Pattern Matching
 * Notation") supporting only '*' (any sequence, including empty) and '?' (any single
 * character). Bracket expressions '[...]' and '\' escapes are NOT supported; all other
 * characters match literally. Returns true if str matches pattern.
 *
 * Performance: the implementation is recursive. Patterns with multiple '*' wildcards
 * against long inputs can degrade toward exponential time (classic fnmatch backtracking
 * issue). Do not expose this interface to untrusted pattern inputs without an external
 * time bound; it is intended for system-owned patterns. */
bool SSFMatchGlob(SSFCStrIn_t pattern, SSFCStrIn_t str);

/* Case-insensitive glob (same subset and performance caveat as SSFMatchGlob). ASCII
 * case-folding only. */
bool SSFMatchGlobI(SSFCStrIn_t pattern, SSFCStrIn_t str);

/* URI path pattern matching with {param} placeholder extraction. {name} in the pattern
 * binds a single path segment (bytes up to the next '/', '?', or end). Byte-level literal
 * comparison — caller must percent-decode per RFC 3986 §2.1 before matching if normalized
 * comparison is required. Query strings (after '?') are tolerated but ignored. Loosely
 * aligns with the "simple string expansion" form of RFC 6570 §3.2.2 but is not a
 * conformant URI Template implementation. Empty placeholder names '{}' are rejected.
 * There is no escape for a literal '{' in the pattern — the '{' character always begins
 * a placeholder. Returns true if path matches pattern. */
bool SSFMatchPath(SSFCStrIn_t pattern, SSFCStrIn_t path, SSFMatchParam_t *paramsOut,
                  uint32_t paramsSize, uint32_t *numParamsOut);

/* MQTT topic filter matching per MQTT v3.1.1 §4.7. The filter is validated against §4.7.1.2
 * (malformed filters return false): '+' must occupy an entire level, '#' must be the last
 * character and preceded by '/' (or be the whole filter). Per §4.7.2, filters starting with
 * a wildcard character do NOT match topics beginning with '$'. Per §4.7.1.2 a trailing '/'
 * in the topic is treated as an optional empty final level (e.g. "sport/tennis/+" matches
 * "sport/tennis/ball/"). An empty filter matches only an empty topic — callers must ensure
 * the filter conforms to §4.7.3 (length >= 1) before invoking this function. Returns true
 * if topic matches filter. */
bool SSFMatchTopic(SSFCStrIn_t filter, SSFCStrIn_t topic);

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_MATCH_UNIT_TEST == 1
void SSFMatchUnitTest(void);
#endif /* SSF_CONFIG_MATCH_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_MATCH_H_INCLUDE */
