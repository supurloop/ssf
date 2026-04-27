# ssf

Small System Framework

A hardened, easily portable, API consistent, C source code library of production ready functionality for small memory embedded systems.

[Overview](#overview) | [Design Principles](#designprinciples) | [Porting](#porting) | [Interfaces](#interfaces) | [Conclusion](#conclusion)

<a id="overview"></a>

## Overview

This code framework was specifically designed:

1. To run on embedded systems that have constrained program and data memories.
2. To minimize the potential for common coding errors and immediately detect and report runtime errors.

Microprocessors with >4KB RAM and >32KB program memory should easily be able to utilize this framework.
Portions of the framework will work on even smaller microcontrollers.

<a id="designprinciples"></a>

## Design Principles

### No Dependencies 

When you use the SSF, you just need the SSF and not a single other external dependency except for a few C standard library calls. No new definitions for basic data types that complicate your code base and cloud your mind; SSF uses <stdint.h> and <stdbool.h> for basic data types.

### No Error Codes

Too often API error codes are ignored in part or in whole, or improperly handled due to overloaded encodings (ex. <0=error, 0=ignored, >0=length)

Either a SSF API call will always succeed, or it will return a boolean: true on success and false on failure.
That's it. Any function outputs are handled via the parameter list.
This makes application error handling simple to implement, and much less prone to errors.

### Militant Buffer and C String Overrun Protection

All SSF interfaces require the total allocated size of buffers and C strings to be passed as arguments.
The SSF API will never write beyond the end of a buffer or C string.
All C strings returned by a successful SSF API call are guaranteed to be NULL terminated.

Use the Safe C string SSF API to replace crash inducing strlen(), strcat(), strcpy(), and strcmp(), and other "safe" C library calls that don't always ensure NULL termination like strncpy().

### Design by Contract

To help ensure correctness the framework uses Design by Contract techniques to immediately catch common errors that tend to creep into systems and cause problems at the worst possible times.

Design by Contract uses assertions, conditional code that ensures that the state of the system at runtime is operating within the allowable tolerances. The assertion interface uses several macros that hint at the assertions purpose. SSF_REQUIRE() is used to check function input parameters. SSF_ENSURE() is used to check the return result of a function. SSF_ASSERT() is used to check any other system state. SSF_ERROR() always forces an assertion.

The framework does NOT use assertions when operating on inputs that likely come from external sources. For example, the SSF JSON parser will NOT assert if the input string is not valid JSON syntax, but it will assert if a NULL pointer is passed in as the pointer to the input.

The framework will also detect common errors like using interfaces before they have been properly initialized.

### Hardened and Tested

For the main port testing platforms of Windows, Linux, and Mac OS, all relevant compiler warnings are turned on. SSF compiles cleanly on them all.

SSF is linted using Visual Studio's static analysis tool with no warnings.
 
SSF has been reviewed for buffer overflows and general correctness by Claude Code.
 
Every SSF interface has a suite of unit tests that MUST PASS completely on all of the main port testing platforms.
 
The author uses various modules of SSF in several different commercial products using a variety of microcontrollers and toolchains.
 
<a id="porting"></a>

## Porting

This framework has been successfully ported and unit tested on the following platforms: Windows Visual Studio 32/64-bit, Linux 32/64-bit (GCC), MAC OS X, PIC32 (XC32), PIC24 (XC16), MSP430 (TI 15.12.3.LTS), and many others. You should only need to change [`ssfport.c` and `ssfport.h`](ssfport.md) to implement a successful port.

The code will compile cleanly and not report any analyzer(Lint) warnings under Windows in Visual Studio using the ssf.sln solution file.
The code will compile cleanly under Linux. ./build-linux.sh will create the ssf executable in the source directory.
The code will compile cleanly under OS X. ./build-macos.sh will create the ssf executable in the source directory.

The Windows, Linux, and Mac OS builds are setup to output all compiler warnings.

For other platforms there are only a few essential tasks that must be completed:

-   Copy the top level source files except main.c and some or all of the submodules into your project sources and add them to your build environment.
-   In ssfport.h make sure SSF_TICKS_PER_SEC is set to the number of system ticks per second on your platform.
-   Map SSFPortGetTick64() to an existing function that returns the number of system ticks since boot, or
    implement SSFPortGetTick64() in ssfport.c if a simple mapping is not possible.
-   In ssfport.h make sure to follow the instructions for the byte order macros.
-   Run the unit tests for the modules you intend to use.

Only a few modules in the framework use system ticks, so you can stub out SSFPortGetTick64() if it is not needed.
If the framework runs in a multi-threaded environment and uses non-reentrant modules define SSF_CONFIG_ENABLE_THREAD_SUPPORT and implement the OS synchronization primitives.

### SSFPortAssert()

For a production ready embedded system you should properly implement SSFPortAssert().

First, I recommend that it should somehow safely record the file and line number where the assertion occurred so that it can be reported on the next boot.

Second, the system should be automatically reset rather than sitting forever in a loop.

Third, the system should have a safe boot mode that kicks in if the system reboots quickly many times in a row.

### RTOS Support

You may have heard the terms bare-metal or superloop to describe single thread of execution systems that lack an OS.
This library is designed to primarily* run in a single thread of execution which avoids much of the overhead and pitfalls associated with RTOSes.
(*See Byte FIFO Interface for an explanation of how to deal with interrupts.)

Very few small memory systems need to have a threaded/tasked/real-time capable OS.
RTOSes introduce significant complexity, and in particular a dizzying amount of opportunity for introducing subtle race conditions (BUGS) that are easy to create and difficult to find and fix.

That said this framework can run perfectly fine with an RTOS, Windows, or Linux, so long as some precautions are taken.

Except for the finite state machine, RTC, and heap modules, all interfaces are reentrant.
This means that calls into those interfaces from different execution contexts will not interfere with each other.

For example, you can have linked list object A in task 1 and linked list object B in task 2 and they will be managed independently and correctly, so long as they are only accessed from the context of their respective task.

To ensure safe operation of the non-renetrant modules in a multi-threaded system SSF_SM_CONFIG_ENABLE_THREAD_SUPPORT must be enabled and synchronization macros must be implemented.

### Deinitialization

This library has added support to deinitialize interfaces that have initialization functions. Primarily deinitialization was added to allow the library to better integrate with unit test frameworks.

<a id="interfaces"></a>

## Interfaces

> **Size estimates** are for ARM Cortex-M (Thumb-2) compiled with maximum size optimization (-Os).
> Flash includes compiled code and any ROM lookup tables. Static RAM is memory permanently
> consumed by the module itself; it excludes user-allocated objects. Peak Stack is the maximum
> call-stack usage during any single API call, including all nested frames and local working
> buffers. Heap indicates whether the module calls `malloc`/`free` during normal operation.
> Reentrant indicates whether the module can be safely called from independent execution
> contexts simultaneously — i.e., it holds no shared mutable state between calls.

#### [Data Structures](_struct/README.md)

Efficient data structure primitives for embedded systems, designed to avoid dynamic memory fragmentation and catch misuse at runtime.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [Byte FIFO](_struct/ssfbfifo.md) | Interrupt-safe byte FIFO with single-byte and multi-byte put/get | ~900 B | — | ~80 B | — | Yes |
| [Linked List](_struct/ssfll.md) | Doubly-linked list supporting FIFO and stack behaviors | ~800 B | — | ~64 B | — | Yes |
| [Memory Pool](_struct/ssfmpool.md) | Fixed-size block memory pool with no fragmentation | ~800 B | — | ~96 B | — | Yes |
| [Heap](_struct/ssfheap.md) | Integrity-checked heap with double-free detection and mark-based ownership tracking | ~3.5 KB | — | ~96 B | — | No¹⁹ |

#### [Codecs](_codec/README.md)

Encoding and decoding interfaces for common data formats, all with strict buffer size enforcement and null-terminated output guarantees.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [Base64](_codec/ssfbase64.md) | Base64 encoder/decoder | ~700 B | — | ~64 B | — | Yes |
| [Hex ASCII](_codec/ssfhex.md) | Binary-to-hex ASCII encoder/decoder | ~600 B | — | ~64 B | — | Yes |
| [JSON](_codec/ssfjson.md) | JSON parser/generator with path-based field access and in-place update | ~7 KB | — | ~250 B⁹ | — | Yes |
| [TLV](_codec/ssftlv.md) | Type-Length-Value encoder/decoder | ~1.2 KB | — | ~96 B | — | Yes |
| [INI](_codec/ssfini.md) | INI file parser/generator | ~3.5 KB | — | ~64 B | — | Yes |
| [UBJSON](_codec/ssfubjson.md) | Universal Binary JSON parser/generator | ~9 KB | — | ~270 B¹⁰ | — | Yes |
| [Decimal](_codec/ssfdec.md) | Integer-to-decimal string converter | ~2.5 KB | — | ~96 B | — | Yes |
| [Safe Strings](_codec/ssfstr.md) | Safe C string interface replacing crash-prone standard functions | ~1.2 KB | — | ~64 B | — | Yes |
| [Generic Object](_codec/ssfgobj.md) | BETA: Hierarchical generic object parser/generator for cross-codec in-memory representation | ~3 KB | ~8 B | ~160 B¹¹ | yes¹⁵ | Yes¹⁷ |

⁹ Recursive parser; stack scales with `SSF_JSON_CONFIG_MAX_IN_DEPTH` (default 4). Estimate uses the default depth; each additional nesting level adds ~64 B.

¹⁰ Recursive parser; stack scales with `SSF_UBJSON_CONFIG_MAX_IN_DEPTH` (default 4). Estimate uses the default depth; each additional nesting level adds ~68 B.

¹¹ Recursive iteration; stack scales with `SSF_GOBJ_CONFIG_MAX_IN_DEPTH` (default 4). Estimate uses the default depth; each additional nesting level adds ~40 B.

¹⁷ No shared mutable state in production builds. Reentrancy depends on the platform `malloc`/`free` implementation; most production C libraries provide thread-safe allocators.

#### [Error Detection Codes (EDC)](_edc/README.md)

Data integrity interfaces for detecting transmission and storage errors.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [Fletcher Checksum](_edc/ssffcsum.md) | 16-bit Fletcher checksum | ~120 B | — | ~48 B | — | Yes |
| [CRC-16](_edc/ssfcrc16.md) | 16-bit CRC (XMODEM/CCITT-16) | ~650 B¹ | — | ~32 B | — | Yes |
| [CRC-32](_edc/ssfcrc32.md) | 32-bit CRC (CCITT-32) | ~1.2 KB² | — | ~32 B | — | Yes |

¹ Includes 512 B lookup table. ² Includes 1 KB lookup table.

#### [Error Correction Codes (ECC)](_ecc/README.md)

Forward error correction for recovering data corrupted during transmission or storage.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [Reed-Solomon](_ecc/README.md) | Reed-Solomon forward error correction encoder/decoder | ~4.5 KB³ | — | ~600 B¹² | — | Yes |

³ Includes ~768 B of GF(256) logarithm, exponent, and inverse lookup tables.

¹² Peak stack occurs in the error locator function, which holds four `GFPoly_t` working polynomials on the stack. Each polynomial is `SSF_RS_MAX_CHUNK_SIZE + SSF_RS_MAX_SYMBOLS` bytes (default 135 B). Stack scales with these configuration constants.

#### [Cryptography](_crypto/README.md)

Cryptographic primitives for hashing, encryption, and random number generation.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [SHA-1](_crypto/ssfsha1.md) | SHA-1 hash (RFC 3174; legacy-protocol use only — e.g., RFC 6455 WebSocket handshake) | ~1.5 KB²⁶ | — | ~400 B²⁷ | — | Yes |
| [SHA-2](_crypto/ssfsha2.md) | SHA-2 hash (SHA-224/256/384/512/512-224/512-256), one-shot and incremental | ~3 KB⁴ | — | ~800 B¹³ | — | Yes |
| [AES](_crypto/ssfaes.md) | AES block cipher (128/192/256-bit key) | ~2 KB⁵ | — | ~300 B¹⁴ | — | Yes |
| [AES-GCM](_crypto/ssfaesgcm.md) | AES-GCM authenticated encryption/decryption | ~3.5 KB⁶ | — | ~128 B | — | Yes |
| [AES-CCM](_crypto/ssfaesccm.md) | AES-CCM AEAD (RFC 3610, NIST SP 800-38C) | ~1.5 KB³⁶ | — | ~450 B³⁷ | — | Yes |
| [HMAC](_crypto/ssfhmac.md) | HMAC (RFC 2104) keyed-hash MAC over SHA-1 / SHA-256 / SHA-384 / SHA-512 | ~1 KB²⁸ | — | ~1.3 KB²⁹ | — | Yes |
| [HKDF](_crypto/ssfhkdf.md) | HKDF (RFC 5869) HMAC-based extract-and-expand key derivation | ~600 B³⁰ | — | ~1.5 KB³¹ | — | Yes |
| [Poly1305](_crypto/ssfpoly1305.md) | Poly1305 one-time MAC (RFC 7539/8439) | ~1.2 KB | — | ~250 B³² | — | Yes |
| [ChaCha20](_crypto/ssfchacha20.md) | ChaCha20 stream cipher (RFC 7539/8439) | ~1 KB | — | ~250 B³³ | — | Yes |
| [ChaCha20-Poly1305](_crypto/ssfchacha20poly1305.md) | ChaCha20-Poly1305 AEAD (RFC 7539/8439) | ~700 B³⁴ | — | ~400 B³⁵ | — | Yes |
| [Crypto Helpers](_crypto/ssfcrypt.md) | Constant-time byte-buffer equality and secure zeroize for sensitive memory | ~80 B | — | ~32 B | — | Yes |
| [Big Number](_crypto/ssfbn.md) | Multi-precision big-number arithmetic; foundation for RSA, ECC, and DH | ~10 KB | — | ~12 KB³⁸ | — | Yes |
| [Elliptic Curve](_crypto/ssfec.md) | NIST P-256 / P-384 point arithmetic (constant-time scalar mul, SEC 1 codec) | ~10 KB³⁹ | — | ~7 KB⁴⁰ | — | Yes |
| [ECDSA / ECDH](_crypto/ssfecdsa.md) | ECDSA signatures (RFC 6979 deterministic) + ECDH over NIST P-256 / P-384 | ~3.5 KB⁴¹ | — | ~16.5 KB⁴² | — | Yes |
| [X25519](_crypto/ssfx25519.md) | X25519 key agreement over Curve25519 (RFC 7748) — self-contained, constant-time | ~4 KB⁴³ | — | ~700 B⁴⁴ | — | Yes |
| [Ed25519](_crypto/ssfed25519.md) | Ed25519 signatures (RFC 8032 pure mode) — deterministic; uses SHA-512 from ssfsha2 | ~12 KB⁴⁵ | — | ~1.5 KB⁴⁶ | — | Yes |
| [RSA](_crypto/ssfrsa.md) | RSA-2048/3072/4096 signatures (PKCS#1 v1.5 and PSS) + key generation; PKCS#1 DER key format | ~15 KB⁴⁷ | — | ~12 KB⁴⁸ | — | Yes |
| [TLS 1.3](_crypto/ssftls.md) | TLS 1.3 core building blocks (key schedule, transcript hash, record layer); not a full TLS stack | ~2.5 KB⁴⁹ | — | ~1 KB⁵⁰ | — | Yes |
| [PRNG](_crypto/ssfprng.md) | Cryptographically capable pseudo-random number generator | ~500 B | — | ~96 B | — | Yes |

⁴ Includes ~896 B of SHA-256 and SHA-512 round constants. ⁵ Includes 512 B S-box and inverse S-box tables. ⁶ Requires AES module; figure is for GCM logic only.

¹³ SHA-512 block processing (`_SSFSHA2_64Block`) dominates: the message schedule `w[80]` of `uint64_t` alone consumes 640 B of stack. SHA-256 peak is ~400 B.

¹⁴ The AES key schedule is expanded into a local `w[60]` array of `uint32_t` (240 B) on every encrypt/decrypt call. The AES-256 key schedule is the worst case.

²⁶ No lookup tables; round constants are four 32-bit immediates inlined into the compression function. Code size is dominated by the 80-round block function.

²⁷ `_SSFSHA1ProcessBlock` allocates the message schedule `w[80]` as a local `uint32_t` array (320 B); the working variables and the call frame make up the remainder.

²⁸ Requires SHA-1 and/or SHA-2 modules; figure is for HMAC dispatch, padding, and key-handling logic only.

²⁹ Peak occurs with HMAC-SHA-512 and a key longer than the 128-byte block: `SSFHMACBegin` holds `keyPrime[128]` and `iKeyPad[128]` on its own frame, plus a temporary `SSFHMACContext_t` for the oversized-key pre-hash, on top of the SHA-512 backend's ~800 B schedule-dominated peak. HMAC-SHA-256 with a block-sized-or-smaller key is ~700 B.

³⁰ Requires HMAC and SHA modules; figure is for HKDF extract/expand logic only.

³¹ Peak occurs in `SSFHKDFExpand` with HKDF-SHA-512: the function frame holds `tPrev[64]`, `tCurr[64]`, and a live `SSFHMACContext_t` across the iteration loop, on top of each nested HMAC-SHA-512 call's own peak. HKDF-SHA-256 is ~1.2 KB.

³² Single-function implementation. The frame holds the 5 × 26-bit accumulator limbs, the clamped `r` and `s` halves of the key, the precomputed `r * 5` reduction operands, 64-bit multiply-accumulate working values, and a 16-byte partial-block buffer.

³³ `SSFChaCha20Encrypt` holds the 16-word `state` (64 B) and a 64-byte keystream `block` buffer; the nested `_SSFChaCha20Block` adds a 16-word working `x` array (64 B). No lookup tables — the round function uses only 32-bit add/XOR/rotate, which is why ChaCha20 is naturally constant-time.

³⁶ Requires AES module; figure is for CCM orchestration, the B₀ / counter block formatting, and CBC-MAC / CTR drivers only.

³⁷ Each outer frame (`SSFAESCCMEncrypt` or `Decrypt`) carries one or two 16-byte tag buffers, then calls `_SSFAESCCMComputeTag` or `_SSFAESCCMCtr` (each with two 16-byte working buffers), which in turn call `SSFAESXXXBlockEncrypt` whose key-schedule expansion dominates the path at ~300 B. The CCM-specific framing is small; the AES backend sets the peak.

³⁸ Peak occurs in `SSFBNModExp` performing a modular exponentiation. `SSFBNModExp` now uses a constant-time fixed-window (k=4) Montgomery exponentiation rather than a bit-by-bit ladder; the working set is dominated by a 16-entry table of Montgomery powers. At default `SSF_BN_CONFIG_MAX_BITS = 4096`: the outer frame holds an `SSFBNMont_t` via `SSFBNMONT_DEFINE` (mod + R² backing arrays + struct ≈ 1 KB), the nested `SSFBNModExpMont` carries `tableStorage[16][SSF_BN_MAX_LIMBS]` (~8 KB) plus three working `SSFBN_t` storage arrays (`aM`, `result`, `picked`, ~0.5 KB each = ~1.5 KB) plus the inner-block `one_storage` for the identity (~0.5 KB), and the deepest call (`SSFBNMontSquare`) adds a `t[(2 × SSF_BN_MAX_LIMBS) + 1]` working buffer (~1 KB). Stack scales approximately linearly with `SSF_BN_CONFIG_MAX_BITS`: ~6.5 KB at 2048, ~1.5 KB at 384 (ECC-only). All other entry points are far below this peak.

³⁹ Flash is dominated by the two NIST curve parameter tables — each carries six `SSFBN_t` constants (`p`, `a`, `b`, `gₓ`, `gᵧ`, `n`) whose fixed-size limb arrays scale with `SSF_BN_CONFIG_MAX_BITS`. At default 4096-bit BN width, each `SSFBN_t` is ~516 B in rodata, so twelve constants occupy ~6 KB — even though each curve only uses 32 or 48 meaningful bytes. Setting `SSF_BN_CONFIG_MAX_BITS = 384` for ECC-only builds cuts the rodata portion to ~0.6 KB and total flash to ~4.5 KB.

⁴⁰ Peak is in `SSFECScalarMul`: the outer frame holds two `SSFECPoint_t` (each = 3 × `SSFBN_t`, so ~3 KB at default 4096-bit BN width), the nested `_SSFECPointAddFull` adds six `SSFBN_t` working values (~3 KB), and the deeper `SSFBNModMul` call adds another ~1 KB. Scales linearly with `SSF_BN_CONFIG_MAX_BITS`: ~3.5 KB at 2048, ~0.8 KB at 384 (ECC-only). `SSFECScalarMulDual` has a similar peak (four `SSFECPoint_t` table entries, same inner depth).

⁴¹ Requires ECC and BN modules; figure is for sign / verify / ECDH orchestration, RFC 6979 deterministic-nonce HMAC-DRBG, and DER signature codec only. Key-gen pulls in [`ssfprng`](_crypto/ssfprng.md) too.

⁴² Peak is in `SSFECDSAVerify` on the `SSFECScalarMulDual` path (the 4-entry point table dominates at ~6.2 KB — footnote ⁴⁰). Verify was refactored in 2026 into three helpers (`_SSFECDSAVerifyInit`, `_SSFECDSAVerifyGetR`, `_SSFECDSAVerifyCheckR`) so that stage-local `SSFBN_t`s (`s`, `e`, `w` in Init; `G` in GetR; `Rx`, `Ry`, `v` in CheckR) are released at helper boundaries and don't compound with the deep scalar-multiply chain. Post-refactor the Verify outer frame is 5 `SSFBN_t` + 2 `SSFECPoint_t` = ~4.6 KB (was ~9.3 KB) and the chain peak is ~16.5 KB (was ~19.6 KB — a ~3 KB / 16 % reduction). `SSFECDSASign` uses `SSFECScalarMul` (not Dual) and peaks around ~15 KB; `SSFECDHComputeSecret` peaks around ~10 KB. All three scale linearly with `SSF_BN_CONFIG_MAX_BITS`: roughly halve the stack at 2048-bit BN width, ~1/13 at 384-bit (ECC-only).

⁴³ Self-contained — no `ssfbn` or `ssfec` dependency. Own GF(2²⁵⁵−19) arithmetic over 8 × 32-bit limbs (`_fe_t` = 32 B), a constant-time Montgomery ladder, one 32-byte field-prime constant, no lookup tables. Flash is largely independent of other config knobs.

⁴⁴ Peak is in `_x25519_scalar_mul`: 15 `_fe_t` field-element locals (32 B each) plus a 32 B clamped-scalar copy — ~500 B on the ladder frame — plus the nested `_fe_inv` / `_fe_mul` call chain adds ~200 B. Fixed at ~700 B regardless of `SSF_BN_CONFIG_MAX_BITS` (this module does not use `ssfbn`).

⁴⁵ Requires SHA-512 from `ssfsha2`; otherwise self-contained (own GF(2²⁵⁵−19) field arithmetic + twisted-Edwards point arithmetic + scalar-field reduction mod `L`, no `ssfbn` dependency). No precomputed base-point table — Sign and Verify compute scalar multiplication from the base point by double-and-add on demand. Flash is independent of `SSF_BN_CONFIG_MAX_BITS`.

⁴⁶ Peak is along the Sign path: the outer frame carries `h[64] + r_hash[64] + hram[64] + a[32] + nonce[32]` ≈ 256 B plus a `_ge_t R` (~128 B) and a full `SSFSHA2_64Context_t` (~280 B), then nests into `SSFSHA512Update` whose block processing peaks at ~800 B (the SHA-512 message schedule — footnote ¹³). Verify has a similar peak. Fixed regardless of `SSF_BN_CONFIG_MAX_BITS`.

⁴⁷ Requires BN, SHA-2, ASN.1, and PRNG modules; figure is for the RSA module itself — key parsing, PKCS#1 v1.5 + PSS padding, MGF1, CRT dispatch, prime generation, and Miller-Rabin. Disabling `SSF_RSA_CONFIG_ENABLE_KEYGEN` removes ~3 KB; disabling either signature scheme removes another ~1–2 KB.

⁴⁸ Peak is in `SSFRSAKeyGen`. Original monolithic implementation had 13 `SSFBN_t` + block-scope locals in one frame (~9 KB at default 4096-bit BN width), so the MillerRabin-nested chain (`_SSFRSAGenPrime` → `_SSFRSAMillerRabin` → `SSFBNModExp` → ladder) peaked at ~17.6 KB. Refactored in 2026 into three helpers (`_SSFRSAKeyGenPrimes`, `_SSFRSAKeyGenDerive`, `_SSFRSAKeyGenEncode`) so that stage-local `SSFBN_t`s die at helper boundaries: the outer now carries only 7 `SSFBN_t` (`p, q, n, d, dp, dq, qInv`) = ~3.6 KB, and the unused `phi` declaration was removed. Post-refactor chain peak is ~11.9 KB (~5.7 KB / 32 % reduction). Sign is ~13.4 KB (outer 8 `SSFBN_t` + `em[512]` + `m, s`, plus the private-op CRT chain). Verify is the cheapest — ~7 KB, because `e = 65537` is only 17 bits and the public-op ModExp scales with exponent bit-length. All three scale linearly with `SSF_BN_CONFIG_MAX_BITS`: halve the width, halve the stack.

⁴⁹ Requires HMAC, SHA-2, and one or more AEAD backends (AES-GCM / AES-CCM / ChaCha20-Poly1305); figure is for the TLS 1.3 primitives themselves — HKDF-Expand-Label, Derive-Secret, traffic-key derivation, transcript hash wrappers, and record-layer nonce construction + AEAD dispatch. No handshake state machine, certificate validation, or transport I/O is included.

⁵⁰ Peak is inherited from whichever AEAD backend the active cipher suite selects. All five supported suites now have comparable stack footprints in the few-hundred-byte range: AES-GCM and AES-CCM routes through the AES-backed dispatch (~450 B peak, dominated by the AES key schedule), and the ChaCha20-Poly1305 route (~400 B peak, dominated by the Poly1305 context and the ChaCha20 working state after the 2025 streaming refactor). The key-schedule and transcript-hash primitives on their own stay under ~1 KB. Overall TLS 1.3 record-layer peak is ~1 KB regardless of cipher suite.

³⁴ Requires ChaCha20 and Poly1305 modules; figure is for AEAD orchestration and the `_SSFCCPComputeTag` construction helper only.

³⁵ `_SSFCCPComputeTag` now streams the `auth ‖ pad ‖ ct ‖ pad ‖ lengths` construction through the incremental Poly1305 Begin/Update/End interface rather than materialising the full concatenation on the stack. Peak is ~`sizeof(SSFPoly1305Context_t)` (~100 B) + the per-message one-time-key buffer (32 B) + the nested ChaCha20 frame's working state — total ~400 B, independent of record size. (Before the 2025 refactor to the streaming Poly1305 API, the construction buffer was configurable via `SSF_CCP_POLY1305_MAX_INPUT` and defaulted to 17408 B.)

#### [Storage](_storage/README.md)

Reliable non-volatile storage with versioning and integrity checking for configuration data.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [Storage](_storage/README.md) | Version-controlled interface for reliably storing configuration to NV storage | ~1.2 KB | — | ~100 B | — | Yes |

#### [Finite State Machine](_fsm/README.md)

Event-driven state machine framework suitable for both bare-metal and RTOS environments.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [Finite State Machine](_fsm/README.md) | Event-driven finite state machine framework with optional RTOS integration | ~2.5 KB | ~150 B⁷ | ~64 B | yes¹⁶ | No¹⁹ |

⁷ Static RAM scales with `SSF_SM_MAX` (number of configured state machines). Estimate is for the default single-SM configuration; excludes user-supplied event and timer pool memory.

¹⁶ Events and timers are allocated from user-configured fixed-size pools (no heap). System `malloc` is called only when an event carries a data payload larger than `sizeof(pointer)` (4 B on ARM).

¹⁹ Enable `SSF_CONFIG_ENABLE_THREAD_SUPPORT` and implement the corresponding synchronization macros in `ssfport.h` to make this module safe for concurrent multi-context use.

#### [Debug](_debug/README.md)

Debug and diagnostic interfaces for runtime tracing.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [Debug Trace](_debug/ssftrace.md) | FIFO-backed debug trace buffer with automatic oldest-byte discard and optional mutex protection | ~200 B | — | ~48 B | — | Yes²⁰ |

²⁰ Each `SSFTrace_t` instance is independent. When `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`, the macros acquire and release a per-instance mutex around each access, making concurrent use from multiple contexts safe.

#### [Time](_time/README.md)

Time management interfaces covering raw tick time, calendar conversion, and ISO 8601 string formatting.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [RTC](_time/ssfrtc.md) | Unix time real-time clock interface | ~900 B | ~20 B⁸ | ~48 B | — | Yes¹⁸ |
| [Date/Time](_time/ssfdtime.md) | Unix time to calendar date/time struct conversion | ~1.8 KB | — | ~96 B | — | Yes |
| [ISO 8601](_time/ssfiso8601.md) | ISO 8601 date/time string formatting and parsing with timezone support | ~1.8 KB | — | ~120 B | — | Yes |

#### [User Interface](_ui/README.md)

User-facing input parsing and presentation interfaces.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [Argv Parser](_ui/ssfargv.md) | BETA: Command line string to gobj parser with `/opt val`, `//opt`, and backslash-escaped argument support | ~2 KB | — | ~120 B²¹ | yes²² | Yes |
| [CLI Framework](_ui/ssfcli.md) | BETA: Interactive CLI with command registration, argv dispatch, command history, and built-in help | ~2.5 KB | — | ~200 B²⁵ | yes²² | Yes²⁴ |
| [VT100 Line Editor](_ui/ssfvted.md) | BETA: ANSI/VT100 terminal line editor with cursor movement, character insert/delete, backspace, and configurable prompt | ~1.5 KB | — | ~80 B²³ | — | Yes²⁴ |

²¹ Excludes the recursive cost of `SSFGObjFindPath` if used by the caller to walk the result tree.

²² Each `SSFArgvInit` call allocates one mutable copy of the input command line via `SSF_MALLOC` (freed before return) plus per-node `SSFGObj_t` allocations (~48 B per cmd / opts / args / per-opt / per-arg) via `ssfgobj`. The full result tree is freed by `SSFArgvDeInit`.

²³ Peak stack is dominated by `strlen` calls after buffer mutations; bounded by `lineSize`. The escape-decoder state machine itself uses only a handful of bytes on the stack.

²⁴ Each `SSFVTEdContext_t` is fully self-contained and holds no shared state. Multiple independent contexts can be driven concurrently from separate threads; a single context must be accessed from only one thread at a time.

²⁵ Peak stack is dominated by the `SSFArgvInit` call inside `SSFCLIProcessChar` (local gobj pointers, path array, and the argv parser's own stack frame). Excludes the recursive cost of `SSFGObjFindPath` and the caller's command handler.

⁸ RTC static RAM holds two initialization flags and two 64-bit tick reference values.

¹⁵ Each `SSFGObjInit` call allocates one `SSFGObj_t` node struct (~48 B) via system `malloc`. `SSFGObjSetLabel` and `SSFGObjSet*` add further per-field allocations for labels and value data.

¹⁸ Concurrent calls to `SSFRTCGetUnixNow` from multiple contexts are safe (read-only after init). Enable `SSF_CONFIG_ENABLE_THREAD_SUPPORT` if `SSFRTCSetUnixNow` may be called concurrently with `SSFRTCGetUnixNow`.

<a id="conclusion"></a>

## Conclusion

I built this framework for primarily myself, although I hope you can find a good use for it.

Special thanks to my son, Calvin, for researching, implementing, and debugging the AES Block and AES-GCM interfaces!

Drop me a line if you have a question or comment.

Jim Higgins

President

Supurloop Software

jim@supurloop.com
