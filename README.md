# ssf

Small System Framework

A collection of production ready software for small memory embedded systems.

## Overview

This code framework was designed:

1. To run on embedded systems that have constrained program and data memories.
2. To minimize the potential for common coding errors and detect and report runtime errors.

The framework implements the following modules:

#### [Data Structures](_struct/README.md)

Efficient data structure primitives for embedded systems, designed to avoid dynamic memory fragmentation and catch misuse at runtime.

| Module | Description |
|--------|-------------|
| [Byte FIFO](_struct/ssfbfifo.md) | Interrupt-safe byte FIFO with single-byte and multi-byte put/get |
| [Linked List](_struct/ssfll.md) | Doubly-linked list supporting FIFO and stack behaviors |
| [Memory Pool](_struct/ssfmpool.md) | Fixed-size block memory pool with no fragmentation |
| [Heap](_struct/ssfheap.md) | Integrity-checked heap with double-free detection and mark-based ownership tracking |

#### [Codecs](_codec/README.md)

Encoding and decoding interfaces for common data formats, all with strict buffer size enforcement and null-terminated output guarantees.

| Module | Description |
|--------|-------------|
| [Base64](_codec/ssfbase64.md) | Base64 encoder/decoder |
| [Hex ASCII](_codec/ssfhex.md) | Binary-to-hex ASCII encoder/decoder |
| [JSON](_codec/ssfjson.md) | JSON parser/generator with path-based field access and in-place update |
| [TLV](_codec/ssftlv.md) | Type-Length-Value encoder/decoder |
| [INI](_codec/ssfini.md) | INI file parser/generator |
| [UBJSON](_codec/ssfubjson.md) | Universal Binary JSON parser/generator |
| [Decimal](_codec/ssfdec.md) | Integer-to-decimal string converter |
| [Safe Strings](_codec/ssfstr.md) | Safe C string interface replacing crash-prone standard functions |
| [Generic Object](_codec/ssfgobj.md) | BETA: Hierarchical generic object parser/generator for cross-codec in-memory representation |

#### [Error Detection Codes (EDC)](_edc/README.md)

Data integrity interfaces for detecting transmission and storage errors.

| Module | Description |
|--------|-------------|
| [Fletcher Checksum](_edc/ssffcsum.md) | 16-bit Fletcher checksum |
| [CRC-16](_edc/ssfcrc16.md) | 16-bit CRC (XMODEM/CCITT-16) |
| [CRC-32](_edc/ssfcrc32.md) | 32-bit CRC (CCITT-32) |

#### [Error Correction Codes (ECC)](_ecc/README.md)

Forward error correction for recovering data corrupted during transmission or storage.

| Module | Description |
|--------|-------------|
| [Reed-Solomon](_ecc/README.md) | Reed-Solomon forward error correction encoder/decoder |

#### [Cryptography](_crypto/README.md)

Cryptographic primitives for hashing, encryption, and random number generation.

| Module | Description |
|--------|-------------|
| [SHA-2](_crypto/ssfsha2.md) | SHA-2 hash (SHA-224/256/384/512/512-224/512-256), one-shot and incremental |
| [AES](_crypto/ssfaes.md) | AES block cipher (128/192/256-bit key) |
| [AES-GCM](_crypto/ssfaesgcm.md) | AES-GCM authenticated encryption/decryption |
| [PRNG](_crypto/ssfprng.md) | Cryptographically capable pseudo-random number generator |

#### [Storage](_storage/README.md)

Reliable non-volatile storage with versioning and integrity checking for configuration data.

| Module | Description |
|--------|-------------|
| [Storage](_storage/README.md) | Version-controlled interface for reliably storing configuration to NV storage |

#### [Finite State Machine](_fsm/README.md)

Event-driven state machine framework suitable for both bare-metal and RTOS environments.

| Module | Description |
|--------|-------------|
| [Finite State Machine](_fsm/README.md) | Event-driven finite state machine framework with optional RTOS integration |

#### [Time](_time/README.md)

Time management interfaces covering raw tick time, calendar conversion, and ISO 8601 string formatting.

| Module | Description |
|--------|-------------|
| [RTC](_time/ssfrtc.md) | Unix time real-time clock interface |
| [Date/Time](_time/ssfdtime.md) | Unix time to calendar date/time struct conversion |
| [ISO 8601](_time/ssfiso8601.md) | ISO 8601 date/time string formatting and parsing with timezone support |

To give you an idea of the framework size here are some program memory estimates for each component compiled on an MSP430 with Level 3 optimization:
Byte FIFO, linked list, memory pool, Base64, Hex ASCII are each about 1000 bytes.
JSON parser/generator is about 7300-8800 bytes depending on configuration.
Finite state machine is about 2000 bytes.
Fletcher checksum is about 88 bytes.

Little RAM is used internally by the framework, most RAM usage occurs outside the framwork when declaring or initializing different objects.

Microprocessors with >4KB RAM and >32KB program memory should easily be able to utilize this framework.
And, as noted above, portions of the framework will work on much smaller micros.

## Porting

This framework has been successfully ported and unit tested on the following platforms: Windows Visual Studio 32/64-bit, Linux 32/64-bit (GCC), MAC OS X, PIC32 (XC32), PIC24 (XC16), and MSP430 (TI 15.12.3.LTS). You should only need to change ssfport.c and ssfport.h to implement a successful port.

The code will compile cleanly and not report any analyzer(Lint) warnings under Windows in Visual Studio using the ssf.sln solution file.7
The code will compile cleanly under Linux. ./build-linux.sh will create the ssf executable in the source directory.
The code will compile cleanly under OS X. ./build-macos.sh will create the ssf executable in the source directory.

The Windows, Linux, and Mac OS builds are setup to output all compiler warnings.

For other platforms there are only a few essential tasks that must be completed:

-   Copy all the SSF C and H source files, except main.c, into your project sources and add them to your build environment.
-   In ssfport.h make sure SSF_TICKS_PER_SEC is set to the number of system ticks per second on your platform.
-   Map SSFPortGetTick64() to an existing function that returns the number of system ticks since boot, or
    implement SSFPortGetTick64() in ssfport.c if a simple mapping is not possible.
-   In ssfport.h make sure to follow the instructions for the byte order macros.
-   Run the unit tests.

Only a few modules in the framework use system ticks, so you can stub out SSFPortGetTick64() if it is not needed.
When the finite state machine framework runs in a multi-threaded environment some OS synchronization primitives must be implemented.

### Heap and Stack Memory

Only the memory pool and finite state machine use dynamic memory, aka heap. The memory pool only does so when a pool is created. The finite state machine only uses malloc when an event has data whose size is bigger than the sizeof a pointer.

The framework is fairly stack friendly, although the JSON/UBJSON parsers will recursively call functions for nested JSON objects and arrays. SSF\_[UB]JSON_CONFIG_MAX_IN_DEPTH in ssfport.h can be used to control the maximum depth the parser will recurse to prevent the stack from blowing up due to bad inputs. If the unit test for the JSON/UBJSON interface is failing weirdly then increase your system stack.

The most important step is to run the unit tests for the interfaces you intend to use on your platform. This will detect porting problems very quickly and avoid many future debugging headaches.

### SSFPortAssert()

For a production ready embedded system you should probably do something additional with SSFPortAssert() besides nothing.

First, I recommend that it should somehow safely record the file and line number where the assertion occurred so that it can be reported on the next boot.

Second, the system should be automatically reset rather than sitting forever in a loop.

Third, the system should have a safe boot mode that kicks in if the system reboots quickly many times in a row.

## Design Principles

### No Dependencies 

When you use the SSF, you just need the SSF and not a single other external dependency except for a few C standard library calls.

### No Error Codes

Too often API error codes are ignored in part or in whole, or improperly handled due to overloaded encodings (ex. <0=error, 0=ignored, >0=length)

Either a SSF API call will always succeed (void return), or it will return a boolean: true on success and false on failure.
That's it. Any function outputs are handled via the parameter list.
This makes application error handling simple to implement, and much less prone to errors.

### Militant Buffer and C String Overrun Protection

All SSF interfaces require the total allocated size of buffers and C strings to be passed as arguments.
The SSF API will never write beyond the end of a buffer or C string.
All C strings returned by a successful SSF API call are guaranteed to be NULL terminated.

Safe C string SSF API to replace crash inducing strlen(), strcat(), strcpy(), and strcmp(), and other "safe" C library calls that don't always ensure NULL termination like strncpy().

### Design by Contract

To help ensure correctness the framework uses Design by Contract techniques to immediately catch common errors that tend to creep into systems and cause problems at the worst possible times.

Design by Contract uses assertions, conditional code that ensures that the state of the system at runtime is operating within the allowable tolerances. The assertion interface uses several macros that hint at the assertions purpose. SSF_REQUIRE() is used to check function input parameters. SSF_ENSURE() is used to check the return result of a function. SSF_ASSERT() is used to check any other system state. SSF_ERROR() always forces an assertion.

The framework goes to great lengths to minimize and detect the potential for buffer overruns and prevent problems with unterminated C strings.

The framework will also detect common errors like using interfaces before they have been properly initialized.

### RTOS Support

You may have heard the terms bare-metal or superloop to describe single thread of execution systems that lack an OS.
This library is designed to primarily* run in a single thread of execution which avoids much of the overhead and pitfalls associated with RTOSes.
(*See Byte FIFO Interface for an explanation of how to deal with interrupts.)

Very few small memory systems need to have a threaded/tasked/real-time capable OS.
RTOSes introduce significant complexity, and in particular a dizzying amount of opportunity for introducing subtle race conditions (BUGS) that are easy to create and difficult to find and fix.

That said this framework can run perfectly fine with an RTOS, Windows, or Linux, so long as some precautions are taken.

Excepting the finite state machine framework, RTC interface, and heap, all interfaces are reentrant.
This means that calls into those interfaces from different execution contexts will not interfere with each other.

For example, you can have linked list object A in task 1 and linked list object B in task 2 and they will be managed independently and correctly, so long as they are only accessed from the context of their respective task.

To properly run the finite state machine framework in a multi-threaded system SSF_SM_CONFIG_ENABLE_THREAD_SUPPORT must be enabled and synchronization macros must be implemented. For more details see below.

### Deinitialization

This library has added support to deinitialize interfaces that have initialization functions. Primarily deinitialization was added to allow the library to better integrate with unit test frameworks.

## Conclusion

I built this framework for primarily myself, although I hope you can find a good use for it.

Special thanks to my son, Calvin, for researching, implementing, and debugging the AES Block and AES-GCM interfaces!

Drop me a line if you have a question or comment.

Jim Higgins

President

Supurloop Software

jim@supurloop.com
