/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfgpath.h                                                                                    */
/* Provides the typed lookup path shared by ssfjson, ssfubjson and ssfgobj.                      */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
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
#ifndef SSF_GPATH_H_INCLUDE
#define SSF_GPATH_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Defines                                                                                       */
/* --------------------------------------------------------------------------------------------- */
/* Kind of one lookup path entry; END (0) terminates the path, so a zeroed path is empty */
typedef enum
{
    SSF_GPATH_MIN = -1,
    SSF_GPATH_END,
    SSF_GPATH_KEY,
    SSF_GPATH_INDEX,
    SSF_GPATH_MAX,
} SSFGPathKind_t;

/* One lookup path entry: an object member name or a pointer to an array element index */
typedef struct
{
    SSFGPathKind_t kind;
    union
    {
        SSFCStrIn_t key;
        const size_t *index;
    } u;
} SSFGPath_t;

/* Set entry e to member name k, index pointer i, or the path end; each argument read once */
#define SSF_GPATH_SET_KEY(e, k) \
        do { SSFGPath_t *_ssfGPathEntry = &(e); \
             _ssfGPathEntry->kind = SSF_GPATH_KEY; \
             _ssfGPathEntry->u.key = (k); } while (0)
#define SSF_GPATH_SET_INDEX(e, i) \
        do { SSFGPath_t *_ssfGPathEntry = &(e); \
             _ssfGPathEntry->kind = SSF_GPATH_INDEX; \
             _ssfGPathEntry->u.index = (i); } while (0)
#define SSF_GPATH_SET_END(e) \
        do { SSFGPath_t *_ssfGPathEntry = &(e); \
             _ssfGPathEntry->kind = SSF_GPATH_END; \
             _ssfGPathEntry->u.key = NULL; } while (0)

/* --------------------------------------------------------------------------------------------- */
/* External interface                                                                            */
/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
/* Returns true if every entry up to the first END is a known kind with its pointer set.         */
/* --------------------------------------------------------------------------------------------- */
static inline bool SSFGPathIsValid(const SSFGPath_t *path, uint8_t maxDepth)
{
    uint8_t i;

    SSF_REQUIRE(path != NULL);

    for (i = 0; i <= maxDepth; i++)
    {
        /* Is the entry's kind outside the enum? */
        if ((path[i].kind <= SSF_GPATH_MIN) || (path[i].kind >= SSF_GPATH_MAX))
        {
            /* Yes */
            return false;
        }
        /* No, is it the end of the path? */
        if (path[i].kind == SSF_GPATH_END) return true;
        /* No, is it a key without a name or an index without a variable? */
        if (((path[i].kind == SSF_GPATH_KEY) && (path[i].u.key == NULL)) ||
            ((path[i].kind == SSF_GPATH_INDEX) && (path[i].u.index == NULL)))
        {
            /* Yes */
            return false;
        }
        /* No, a usable entry */
    }
    return false;
}

#ifdef __cplusplus
}
#endif

#endif /* SSF_GPATH_H_INCLUDE */
