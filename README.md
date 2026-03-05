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

This framework has been successfully ported and unit tested on the following platforms: Windows Visual Studio 32/64-bit, Linux 32/64-bit (GCC), MAC OS X, PIC32 (XC32), PIC24 (XC16), MSP430 (TI 15.12.3.LTS), and many others. You should only need to change ssfport.c and ssfport.h to implement a successful port.

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
| [SHA-2](_crypto/ssfsha2.md) | SHA-2 hash (SHA-224/256/384/512/512-224/512-256), one-shot and incremental | ~3 KB⁴ | — | ~800 B¹³ | — | Yes |
| [AES](_crypto/ssfaes.md) | AES block cipher (128/192/256-bit key) | ~2 KB⁵ | — | ~300 B¹⁴ | — | Yes |
| [AES-GCM](_crypto/ssfaesgcm.md) | AES-GCM authenticated encryption/decryption | ~3.5 KB⁶ | — | ~128 B | — | Yes |
| [PRNG](_crypto/ssfprng.md) | Cryptographically capable pseudo-random number generator | ~500 B | — | ~96 B | — | Yes |

⁴ Includes ~896 B of SHA-256 and SHA-512 round constants. ⁵ Includes 512 B S-box and inverse S-box tables. ⁶ Requires AES module; figure is for GCM logic only.

¹³ SHA-512 block processing (`_SSFSHA2_64Block`) dominates: the message schedule `w[80]` of `uint64_t` alone consumes 640 B of stack. SHA-256 peak is ~400 B.

¹⁴ The AES key schedule is expanded into a local `w[60]` array of `uint32_t` (240 B) on every encrypt/decrypt call. The AES-256 key schedule is the worst case.

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

#### [Time](_time/README.md)

Time management interfaces covering raw tick time, calendar conversion, and ISO 8601 string formatting.

| Module | Description | Flash | Static RAM | Peak Stack | Heap | Reentrant |
|--------|-------------|-------|------------|------------|------|-----------|
| [RTC](_time/ssfrtc.md) | Unix time real-time clock interface | ~900 B | ~20 B⁸ | ~48 B | — | Yes¹⁸ |
| [Date/Time](_time/ssfdtime.md) | Unix time to calendar date/time struct conversion | ~1.8 KB | — | ~96 B | — | Yes |
| [ISO 8601](_time/ssfiso8601.md) | ISO 8601 date/time string formatting and parsing with timezone support | ~1.8 KB | — | ~120 B | — | Yes |

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
