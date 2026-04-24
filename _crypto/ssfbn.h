/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbn.h                                                                                       */
/* Provides multi-precision big number arithmetic interface.                                     */
/* Supports ECC (P-256, P-384), RSA (2048, 4096), and DH key sizes.                             */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2024 Supurloop Software LLC                                                         */
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

/* --------------------------------------------------------------------------------------------- */
/* Per US export restrictions for open source cryptographic software the Department of Commerce  */
/* has been notified of the inclusion of cryptographic software in the SSF. This is a copy of    */
/* the notice emailed on Nov 11, 2021:                                                           */
/* --------------------------------------------------------------------------------------------- */
/* Unrestricted Encryption Source Code Notification                                              */
/* To : crypt@bis.doc.gov; enc@nsa.gov                                                           */
/* Subject : Addition to SSF Source Code                                                         */
/* Department of Commerce                                                                        */
/* Bureau of Export Administration                                                               */
/* Office of Strategic Trade and Foreign Policy Controls                                         */
/* 14th Street and Pennsylvania Ave., N.W.                                                       */
/* Room 2705                                                                                     */
/* Washington, DC 20230                                                                          */
/* Re: Unrestricted Encryption Source Code Notification Commodity : Addition to SSF Source Code  */
/*                                                                                               */
/* Dear Sir / Madam,                                                                             */
/*                                                                                               */
/* Pursuant to paragraph(e)(1) of Part 740.13 of the U.S.Export Administration Regulations       */
/* ("EAR", 15 CFR Part 730 et seq.), we are providing this written notification of the Internet  */
/* location of the unrestricted, publicly available Source Code being added to the Small System  */
/* Framework (SSF) Source Code. SSF Source Code is a free embedded system application framework  */
/* developed by Supurloop Software LLC in the Public Interest. This notification serves as a     */
/* notification of an addition of new software to the SSF archive. This archive is updated from  */
/* time to time, but its location is constant. Therefore this notification serves as a one-time  */
/* notification for subsequent updates that may occur in the future to the software covered by   */
/* this notification. Such updates may add or enhance cryptographic functionality of the SSF.    */
/* The Internet location for the SSF Source Code is: https://github.com/supurloop/ssf            */
/*                                                                                               */
/* This site may be mirrored to a number of other sites located outside the United States.       */
/*                                                                                               */
/* The following software is being added to the SSF archive:                                     */
/*                                                                                               */
/* ssfbn.c, ssfbn.h - Multi-precision big number arithmetic.                                     */
/*                                                                                               */
/* If you have any questions, please email me at xxx@xxx, or call me on (XXX) XXX-XXXX.          */
/*                                                                                               */
/* Sincerely,                                                                                    */
/* James Higgins                                                                                 */
/* President                                                                                     */
/* Supurloop Software LLC                                                                        */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_BN_H_INCLUDE
#define SSF_BN_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "ssfport.h"

/* --------------------------------------------------------------------------------------------- */
/* Limitations                                                                                   */
/* --------------------------------------------------------------------------------------------- */
/* SSF_BN_CONFIG_MAX_BITS controls the maximum big number size. Set to 384 for ECC-only, 2048   */
/* for RSA-2048/DH Group 14, or 4096 for RSA-4096/DH Group 16.                                  */
/* All operations with two or more operands require operands of equal limb count. The caller     */
/* must ensure operands are zero-padded to the same working size.                                */
/* Modular operations require that operands are less than the modulus.                           */
/* Modular exponentiation uses a constant-time square-and-multiply algorithm.                   */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* Defines and typedefs                                                                          */
/* --------------------------------------------------------------------------------------------- */

/* Limb type: 32-bit unsigned, double-limb 64-bit for carry propagation. */
typedef uint32_t SSFBNLimb_t;
typedef uint64_t SSFBNDLimb_t;

#define SSF_BN_LIMB_BITS       (32u)
#define SSF_BN_LIMB_MAX        (0xFFFFFFFFul)
#define SSF_BN_BITS_TO_LIMBS(bits) (((bits) + SSF_BN_LIMB_BITS - 1u) / SSF_BN_LIMB_BITS)

/* Maximum limb count derived from compile-time config. */
#define SSF_BN_MAX_LIMBS SSF_BN_BITS_TO_LIMBS(SSF_BN_CONFIG_MAX_BITS)

/* Maximum byte count for import/export. */
#define SSF_BN_MAX_BYTES ((SSF_BN_CONFIG_MAX_BITS + 7u) / 8u)

/* Big number: pointer to caller-supplied limb storage in little-endian limb order.             */
/* limbs[0] is the least significant limb.                                                       */
/*                                                                                                */
/* `len` is the number of active limbs for the current operation (1..cap).                       */
/* `cap` is the storage capacity — the number of SSFBNLimb_t entries available at *limbs. The    */
/* SSFBN_DEFINE macro below packages together the backing storage and the struct initializer so  */
/* that each SSFBN_t local consumes only (cap * 4) + 12 bytes on the stack instead of the full   */
/* SSF_BN_MAX_LIMBS * 4 + 8 of the previous embedded-array design. Producers / callers of an     */
/* SSFBN_t* must ensure the struct has valid backing storage and that any len they set satisfies */
/* len <= cap. Static SSFBN_t constants (the NIST primes, curve parameters) are initialized with */
/* a separately-declared SSFBNLimb_t[] array and pointed at via the struct initializer.          */
typedef struct SSFBN
{
    SSFBNLimb_t *limbs;
    uint16_t len;   /* Number of active limbs (1..cap). */
    uint16_t cap;   /* Storage capacity in limbs of the array pointed to by `limbs`. */
} SSFBN_t;

/* Declare an SSFBN_t backed by a fresh zero-initialized SSFBNLimb_t array of size `nlimbs`.     */
/* Expands to two declarations (a limb array + the struct) so it must appear in a scope that     */
/* admits multiple declarations (a function body or block — not an initializer expression).      */
/* Pick `nlimbs` to fit the widest operand the code path will see: SSF_EC_MAX_LIMBS (12) for     */
/* P-384-capable ECC code, SSF_BN_BITS_TO_LIMBS(256) (8) if limited to P-256, SSF_BN_MAX_LIMBS   */
/* for generic bignum / RSA code that must handle any width up to SSF_BN_CONFIG_MAX_BITS.        */
#define SSFBN_DEFINE(name, nlimbs) \
    SSFBNLimb_t name##_storage[(nlimbs)] = {0u}; \
    SSFBN_t name = { name##_storage, 0u, (uint16_t)(nlimbs) }

/* Montgomery reduction context for efficient modular exponentiation.                           */
/* Precomputed for a given modulus; reuse across multiple operations with the same modulus.      */
typedef struct SSFBNMont
{
    SSFBN_t mod;      /* Modulus. */
    SSFBN_t rr;       /* R^2 mod m, where R = 2^(len*32). */
    SSFBNLimb_t mp;   /* -m^(-1) mod 2^32. */
    uint16_t len;     /* Working limb count. */
} SSFBNMont_t;

/* Declare an SSFBNMont_t backed by fresh zero-initialized limb arrays for each embedded        */
/* SSFBN_t member (mod, rr), each of capacity `nlimbs`.                                          */
#define SSFBNMONT_DEFINE(name, nlimbs) \
    SSFBNLimb_t name##_mod_storage[(nlimbs)] = {0u}; \
    SSFBNLimb_t name##_rr_storage[(nlimbs)] = {0u}; \
    SSFBNMont_t name = { \
        { name##_mod_storage, 0u, (uint16_t)(nlimbs) }, \
        { name##_rr_storage,  0u, (uint16_t)(nlimbs) }, \
        0u, 0u \
    }

/* --------------------------------------------------------------------------------------------- */
/* External interface: initialization and conversion                                             */
/* --------------------------------------------------------------------------------------------- */

/* Set a to zero with the specified working limb count.                                          */
/* numLimbs must be >= 1 and <= SSF_BN_MAX_LIMBS.                                               */
void SSFBNSetZero(SSFBN_t *a, uint16_t numLimbs);

/* Set a to a small integer value with the specified working limb count.                         */
void SSFBNSetUint32(SSFBN_t *a, uint32_t val, uint16_t numLimbs);

/* Copy src to dst. dst->len is set to src->len.                                                 */
void SSFBNCopy(SSFBN_t *dst, const SSFBN_t *src);

/* Import from big-endian byte array. numLimbs sets the working limb count (zero-pads if data   */
/* is shorter). Returns false if data is too large for numLimbs.                                 */
bool SSFBNFromBytes(SSFBN_t *a, const uint8_t *data, size_t dataLen, uint16_t numLimbs);

/* Export to big-endian byte array. Writes exactly outSize bytes (zero-pads leading).            */
/* Returns false if outSize is too small to hold the value.                                      */
bool SSFBNToBytes(const SSFBN_t *a, uint8_t *out, size_t outSize);

/* --------------------------------------------------------------------------------------------- */
/* External interface: comparison                                                                */
/* --------------------------------------------------------------------------------------------- */

/* Returns true if a is zero.                                                                    */
bool SSFBNIsZero(const SSFBN_t *a);

/* Returns true if a equals 1.                                                                   */
bool SSFBNIsOne(const SSFBN_t *a);

/* Returns true if a is even (LSB of limbs[0] is 0).                                             */
bool SSFBNIsEven(const SSFBN_t *a);

/* Constant-time comparison. Returns 0 if equal, -1 if a < b, 1 if a > b.                       */
/* a and b must have the same limb count.                                                        */
int8_t SSFBNCmp(const SSFBN_t *a, const SSFBN_t *b);

/* --------------------------------------------------------------------------------------------- */
/* External interface: bit operations                                                            */
/* --------------------------------------------------------------------------------------------- */

/* Returns the index of the most significant set bit (0-based), or 0 if a is zero.              */
uint32_t SSFBNBitLen(const SSFBN_t *a);

/* Returns the value of bit at position pos (0 = LSB). Returns 0 if pos >= len * 32.            */
uint8_t SSFBNGetBit(const SSFBN_t *a, uint32_t pos);

/* Shift a left by 1 bit in place. High bit is lost if it overflows limb count.                  */
void SSFBNShiftLeft1(SSFBN_t *a);

/* Shift a right by 1 bit in place. LSB is lost.                                                 */
void SSFBNShiftRight1(SSFBN_t *a);

/* --------------------------------------------------------------------------------------------- */
/* External interface: basic arithmetic                                                          */
/* --------------------------------------------------------------------------------------------- */
/* All two-operand functions require a->len == b->len. Result has the same limb count.           */

/* r = a + b. Returns carry (0 or 1). r may alias a or b.                                       */
SSFBNLimb_t SSFBNAdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);

/* r = a - b. Returns borrow (0 or 1, where 1 means a < b). r may alias a or b.                 */
SSFBNLimb_t SSFBNSub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);

/* r = a * b. r->len is set to a->len + b->len. r must not alias a or b.                        */
/* r->len must not exceed SSF_BN_MAX_LIMBS; caller must ensure a->len + b->len <=                */
/* SSF_BN_MAX_LIMBS.                                                                             */
void SSFBNMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);

/* --------------------------------------------------------------------------------------------- */
/* External interface: modular arithmetic                                                        */
/* --------------------------------------------------------------------------------------------- */
/* All modular operations require operands a, b < mod. Result is always < mod.                   */

/* r = (a + b) mod m. r may alias a or b.                                                        */
void SSFBNModAdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);

/* r = (a - b) mod m. r may alias a or b.                                                        */
void SSFBNModSub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);

/* r = (a * b) mod m. r may alias a or b.                                                        */
/* Uses schoolbook multiply followed by Barrett or simple reduction.                             */
void SSFBNModMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);

/* r = a^(-1) mod m. Returns false if inverse does not exist (gcd(a, m) != 1).                   */
/* Uses Fermat's little theorem (a^(m-2) mod m) when m is prime, or binary extended GCD          */
/* otherwise.                                                                                    */
bool SSFBNModInv(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);

/* r = (a * b) mod m using NIST fast reduction for P-256 or P-384.                               */
/* mod must be SSF_BN_NIST_P256 or SSF_BN_NIST_P384.                                            */
/* Falls back to SSFBNModMul for other moduli.                                                   */
void SSFBNModMulNIST(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);

/* r = a mod m. a->len may be up to 2 * m->len. r->len is set to m->len.                        */
void SSFBNMod(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);

/* r = gcd(a, b) using binary GCD (Stein's algorithm). a and b must have the same len.          */
void SSFBNGcd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);

/* r = a^(-1) mod m using binary extended GCD. Works for any coprime a and m (m need not be     */
/* prime). Returns false if gcd(a, m) != 1.                                                      */
bool SSFBNModInvExt(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);

/* --------------------------------------------------------------------------------------------- */
/* External interface: Montgomery multiplication (efficient for RSA/DH)                          */
/* --------------------------------------------------------------------------------------------- */

/* Initialize Montgomery context for a given odd modulus.                                        */
/* Precomputes R^2 mod m and -m^(-1) mod 2^32.                                                  */
void SSFBNMontInit(SSFBNMont_t *ctx, const SSFBN_t *m);

/* r = Montgomery(a, b) = a * b * R^(-1) mod m.                                                  */
/* a and b must be in Montgomery form (i.e., a*R mod m). r may alias a or b.                     */
void SSFBNMontMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBNMont_t *ctx);

/* Convert a to Montgomery form: aR = a * R^2 * R^(-1) mod m = a * R mod m.                     */
void SSFBNMontConvertIn(SSFBN_t *aR, const SSFBN_t *a, const SSFBNMont_t *ctx);

/* Convert a from Montgomery form: a = aR * 1 * R^(-1) mod m.                                   */
void SSFBNMontConvertOut(SSFBN_t *a, const SSFBN_t *aR, const SSFBNMont_t *ctx);

/* --------------------------------------------------------------------------------------------- */
/* External interface: modular exponentiation                                                    */
/* --------------------------------------------------------------------------------------------- */

/* r = a^e mod m. Constant-time via Montgomery ladder with Montgomery multiplication.            */
/* Suitable for RSA, DH, and DSA operations.                                                     */
void SSFBNModExp(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m);

/* r = a^e mod m using precomputed Montgomery context.                                           */
/* Use when performing multiple exponentiations with the same modulus.                           */
void SSFBNModExpMont(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx);

/* --------------------------------------------------------------------------------------------- */
/* External interface: utility                                                                   */
/* --------------------------------------------------------------------------------------------- */

/* Constant-time conditional swap: if swap != 0, exchange a and b. a and b must have same len.   */
void SSFBNCondSwap(SSFBN_t *a, SSFBN_t *b, SSFBNLimb_t swap);

/* Constant-time conditional copy: if sel != 0, copy src to dst. Must have same len.             */
void SSFBNCondCopy(SSFBN_t *dst, const SSFBN_t *src, SSFBNLimb_t sel);

/* Securely zeroize a big number (prevents compiler from optimizing away the clear).             */
void SSFBNZeroize(SSFBN_t *a);

/* --------------------------------------------------------------------------------------------- */
/* NIST curve prime constants (defined in ssfbn.c)                                               */
/* --------------------------------------------------------------------------------------------- */
extern const SSFBN_t SSF_BN_NIST_P256;
extern const SSFBN_t SSF_BN_NIST_P384;

/* --------------------------------------------------------------------------------------------- */
/* Unit test                                                                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_CONFIG_BN_UNIT_TEST == 1
void SSFBNUnitTest(void);
#endif /* SSF_CONFIG_BN_UNIT_TEST */

#ifdef __cplusplus
}
#endif

#endif /* SSF_BN_H_INCLUDE */
