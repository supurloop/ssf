# ssfport — Platform Port

[SSF](README.md)

Platform adaptation layer: tick type, tick rate, byte-order macros, heap allocators, assertion
handler, and optional mutex primitives. All other SSF modules depend on `ssfport.h`.

Porting SSF to a new target requires editing only `ssfport.h` and `ssfport.c`. Once
`SSFPortGetTick64()` and `SSFPortAssert()` are implemented and the configuration constants are
set, all SSF modules build and run without further modification.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Examples](#examples)

<a id="dependencies"></a>

## [↑](#ssfport--platform-port) Dependencies

None — `ssfport` is the foundation layer on which all other SSF modules depend.

<a id="notes"></a>

## [↑](#ssfport--platform-port) Notes

- Only `ssfport.h` and `ssfport.c` need to be modified when porting to a new target.
- `SSFPortAssert()` must **never return** in production; it should record the fault location and
  reset the system. Returning from `SSFPortAssert()` produces undefined behaviour in SSF modules.
- `SSFPortGetTick64()` must return a monotonically increasing value at the rate defined by
  `SSF_TICKS_PER_SEC`. Wrap-around is handled internally by SSF time modules.
- Set `SSF_CONFIG_BYTE_ORDER_MACROS` to `0` and include the platform header (e.g.,
  `<arpa/inet.h>`) when the target already provides `htons`, `htonl`, and `htonll`. Set to `1`
  and configure `SSF_CONFIG_LITTLE_ENDIAN` when the port must define them.
- The mutex macros (`SSF_MUTEX_*`) are only required when
  `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`.
- All `SSF_CONFIG_*_UNIT_TEST` enables can be set to `0` in a production build to exclude unit
  test code.
- `SSF_REQUIRE()` documents input-parameter assertions; `SSF_ENSURE()` documents return-value
  assertions; `SSF_ASSERT()` is for all other state checks; `SSF_ERROR()` fires unconditionally.
  All four resolve to the same underlying check and call `SSFPortAssert()` on failure.

<a id="configuration"></a>

## [↑](#ssfport--platform-port) Configuration

All settings are made directly in `ssfport.h`.

### Core Port Settings

| Setting | Example Default | Description |
|---------|-----------------|-------------|
| `SSFPortTick_t` | `uint64_t` | Typedef for the tick counter type; must hold a 64-bit unsigned value |
| `SSF_TICKS_PER_SEC` | `1000` | Number of ticks returned by `SSFPortGetTick64()` per second; must match the platform tick rate |
| `SSF_MALLOC` | `malloc` | Heap allocation function; replace with a custom allocator if required |
| `SSF_FREE` | `free` | Heap deallocation function; must pair with `SSF_MALLOC` |
| `SSF_CONFIG_BYTE_ORDER_MACROS` | `1` | `1` to have ssfport.h define `htons/htonl/htonll`; `0` to use platform-provided macros |
| `SSF_CONFIG_LITTLE_ENDIAN` | `1` | `1` for little-endian targets; `0` for big-endian (only used when `SSF_CONFIG_BYTE_ORDER_MACROS == 1`) |
| `SSF_CONFIG_ENABLE_THREAD_SUPPORT` | `1` | `1` to compile and require `SSF_MUTEX_*` macros; `0` for single-threaded builds |

### Unit Test Enables

Each SSF module has a corresponding unit test enable in `ssfport.h`. Set to `1` to include the
unit test, `0` to exclude it. The aggregate `SSF_CONFIG_UNIT_TEST` is automatically derived.

| Setting | Example Default | Description |
|---------|-----------------|-------------|
| `SSF_CONFIG_BFIFO_UNIT_TEST` | `1` | Enable Byte FIFO unit test |
| `SSF_CONFIG_JSON_UNIT_TEST` | `1` | Enable JSON unit test |
| `SSF_CONFIG_SHA2_UNIT_TEST` | `1` | Enable SHA-2 unit test |
| `SSF_CONFIG_<MODULE>_UNIT_TEST` | `1` | Enable/disable unit test for any SSF module |
| `SSF_CONFIG_UNIT_TEST` | (derived) | `1` if any module unit test is enabled; `0` otherwise — do not set manually |

### Mutex Macros

Required when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`. Implement these five macros in
`ssfport.h` using the RTOS or OS synchronization primitive appropriate for the target.

| Macro | Description |
|-------|-------------|
| `SSF_MUTEX_DECLARATION(mutex)` | Declare a mutex variable of the platform-specific type |
| `SSF_MUTEX_INIT(mutex)` | Initialize the mutex; call once before first use |
| `SSF_MUTEX_DEINIT(mutex)` | Destroy the mutex; call when the mutex is no longer needed |
| `SSF_MUTEX_ACQUIRE(mutex)` | Lock the mutex; blocks until the lock is obtained |
| `SSF_MUTEX_RELEASE(mutex)` | Unlock the mutex; must be called from the same context that acquired it |

<a id="api-summary"></a>

## [↑](#ssfport--platform-port) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssfporttick-t"></a>`SSFPortTick_t` | Typedef (`uint64_t`) | Tick counter type returned by [`SSFPortGetTick64()`](#ssfportgettick64) |
| `SSF_TICKS_PER_SEC` | Constant | Number of ticks per second; used by time modules to convert between ticks and real time |
| `SSF_MALLOC` | Macro | Heap allocation function mapped to `malloc` or a custom allocator |
| `SSF_FREE` | Macro | Heap deallocation function mapped to `free` or a custom deallocator |
| <a id="ssfcstrin-t"></a>`SSFCStrIn_t` | Typedef (`const char *`) | Type for null-terminated input C strings passed to SSF functions |
| <a id="ssfcstrout-t"></a>`SSFCStrOut_t` | Typedef (`char *`) | Type for null-terminated output C string buffers returned by SSF functions |
| `SSFVoidFn_t` | Typedef (`void (*)(void)`) | Generic function pointer type used by the state machine module |
| `SSF_MAX(x, y)` | Macro | Returns the larger of two values |
| `SSF_MIN(x, y)` | Macro | Returns the smaller of two values |
| `SSFIsDigit(c)` | Macro | Non-zero if `c` is an ASCII decimal digit (`'0'`–`'9'`) |
| `SSF_UNUSED(x)` | Macro | Suppresses unused-variable or unused-parameter compiler warnings |

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-portassert) | [`SSFPortAssert(file, line)`](#ssfportassert) | Assertion handler — implement in `ssfport.c`; never returns in production |
| [e.g.](#ex-gettick64) | [`SSFPortGetTick64()`](#ssfportgettick64) | Return the 64-bit monotonic tick counter — implement in `ssfport.c` |
| [e.g.](#ex-assert-macros) | [`SSF_ASSERT(x)` / `SSF_REQUIRE(x)` / `SSF_ENSURE(x)` / `SSF_ERROR()`](#ssf-assert) | Design-by-contract assertion macros |
| [e.g.](#ex-htons) | [`htons(x)` / `ntohs(x)`](#htons) | 16-bit host↔network byte order conversion |
| [e.g.](#ex-htonl) | [`htonl(x)` / `ntohl(x)`](#htonl) | 32-bit host↔network byte order conversion |
| [e.g.](#ex-htonll) | [`htonll(x)` / `ntohll(x)`](#htonll) | 64-bit host↔network byte order conversion |
| [e.g.](#ex-mutex) | [`SSF_MUTEX_DECLARATION(m)` / `SSF_MUTEX_INIT(m)` / `SSF_MUTEX_DEINIT(m)` / `SSF_MUTEX_ACQUIRE(m)` / `SSF_MUTEX_RELEASE(m)`](#ssf-mutex-declaration) | Mutex primitives (requires `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`) |

<a id="function-reference"></a>

## [↑](#ssfport--platform-port) Function Reference

<a id="ssfportassert"></a>

### [↑](#ssfport--platform-port) [`SSFPortAssert()`](#ex-portassert)

```c
void SSFPortAssert(const char *file, unsigned int line);
```

Assertion failure handler. Called by [`SSF_ASSERT()`](#ssf-assert) and all its aliases whenever a
contract check fails. Implement in `ssfport.c`. In production this function must not return;
recommended behaviour is to log the fault location to non-volatile memory and reset the system.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `file` | in | `const char *` | Source file path string from `__FILE__`. |
| `line` | in | `unsigned int` | Source line number from `__LINE__`. |

**Returns:** Never (in production). In unit-test builds the default implementation calls
`longjmp()` to allow assertion-triggering tests to continue.

---

<a id="ssfportgettick64"></a>

### [↑](#ssfport--platform-port) [`SSFPortGetTick64()`](#ex-gettick64)

```c
SSFPortTick_t SSFPortGetTick64(void);
```

Returns the number of system ticks elapsed since boot. The rate of the counter must match
[`SSF_TICKS_PER_SEC`](#api-summary). Implement in `ssfport.c`, or map to an existing platform
function via a macro in `ssfport.h`. The value must be monotonically increasing; wrap-around
every ~585 million years at 1000 ticks/s.

On Windows the default port defines `SSFPortGetTick64()` as a macro:

```c
#define SSFPortGetTick64() GetTickCount64()
```

On POSIX the default port implements it in `ssfport.c` using `clock_gettime(CLOCK_MONOTONIC)`.

**Returns:** [`SSFPortTick_t`](#ssfporttick-t) — current tick count.

---

<a id="ssf-assert"></a>

### [↑](#ssfport--platform-port) [`SSF_ASSERT()` / `SSF_REQUIRE()` / `SSF_ENSURE()` / `SSF_ERROR()`](#ex-assert-macros)

```c
#define SSF_ASSERT(x)  do { if (!(x)) SSFPortAssert(__FILE__, (uint32_t)__LINE__); } while (0)
#define SSF_REQUIRE(x) SSF_ASSERT(x)
#define SSF_ENSURE(x)  SSF_ASSERT(x)
#define SSF_ERROR()    SSF_ASSERT(0)
```

Design-by-contract assertion macros. All four call [`SSFPortAssert()`](#ssfportassert) when the
condition fails. They are semantically equivalent but carry intent:

| Macro | Intended use |
|-------|-------------|
| `SSF_REQUIRE(x)` | Validate function input parameters |
| `SSF_ENSURE(x)` | Validate a function's return value or post-condition |
| `SSF_ASSERT(x)` | Validate any other internal state |
| `SSF_ERROR()` | Mark unreachable code paths; always fires |

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `x` | in | expression | Condition that must be non-zero. If zero, `SSFPortAssert()` is called with the current `__FILE__` and `__LINE__`. |

**Returns:** Nothing. Does not return to the caller if the condition is false.

---

<a id="htons"></a>

### [↑](#ssfport--platform-port) [`htons()` / `ntohs()`](#ex-htons)

```c
uint16_t htons(uint16_t x);   /* host to network (big-endian) byte order, 16-bit */
uint16_t ntohs(uint16_t x);   /* network to host byte order, 16-bit */
```

Convert a 16-bit value between host byte order and network (big-endian) byte order. On
little-endian targets (`SSF_CONFIG_LITTLE_ENDIAN == 1`) the bytes are swapped; on big-endian
targets both macros are no-ops. `ntohs` is an alias for `htons` — the operation is its own
inverse.

These macros are defined by `ssfport.h` when `SSF_CONFIG_BYTE_ORDER_MACROS == 1`. When the
platform already provides them (e.g., via `<arpa/inet.h>`), set
`SSF_CONFIG_BYTE_ORDER_MACROS == 0` and include the appropriate header instead.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `x` | in | `uint16_t` | Value to convert. |

**Returns:** `uint16_t` — byte-swapped value on little-endian; unchanged value on big-endian.

---

<a id="htonl"></a>

### [↑](#ssfport--platform-port) [`htonl()` / `ntohl()`](#ex-htonl)

```c
uint32_t htonl(uint32_t x);   /* host to network byte order, 32-bit */
uint32_t ntohl(uint32_t x);   /* network to host byte order, 32-bit */
```

Convert a 32-bit value between host byte order and network (big-endian) byte order. `ntohl` is
an alias for `htonl`. Defined by `ssfport.h` when `SSF_CONFIG_BYTE_ORDER_MACROS == 1`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `x` | in | `uint32_t` | Value to convert. |

**Returns:** `uint32_t` — byte-swapped value on little-endian; unchanged value on big-endian.

---

<a id="htonll"></a>

### [↑](#ssfport--platform-port) [`htonll()` / `ntohll()`](#ex-htonll)

```c
uint64_t htonll(uint64_t x);  /* host to network byte order, 64-bit */
uint64_t ntohll(uint64_t x);  /* network to host byte order, 64-bit */
```

Convert a 64-bit value between host byte order and network (big-endian) byte order. `ntohll` is
an alias for `htonll`. Defined by `ssfport.h` when `SSF_CONFIG_BYTE_ORDER_MACROS == 1`. Note
that `htonll`/`ntohll` are SSF extensions — they are not part of the POSIX standard.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `x` | in | `uint64_t` | Value to convert. |

**Returns:** `uint64_t` — byte-swapped value on little-endian; unchanged value on big-endian.

---

<a id="ssf-mutex-declaration"></a>

### [↑](#ssfport--platform-port) [`SSF_MUTEX_DECLARATION()` / `SSF_MUTEX_INIT()` / `SSF_MUTEX_DEINIT()` / `SSF_MUTEX_ACQUIRE()` / `SSF_MUTEX_RELEASE()`](#ex-mutex)

```c
/* Requires SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1 */
#define SSF_MUTEX_DECLARATION(mutex)  /* declare mutex variable */
#define SSF_MUTEX_INIT(mutex)         /* initialize mutex */
#define SSF_MUTEX_DEINIT(mutex)       /* destroy mutex */
#define SSF_MUTEX_ACQUIRE(mutex)      /* lock mutex — blocks until acquired */
#define SSF_MUTEX_RELEASE(mutex)      /* unlock mutex */
```

Five macros that adapt SSF's locking requirements to the platform's synchronization primitive.
Only compiled and required when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`. Implement all five in
`ssfport.h` using the mutex, semaphore, or critical section appropriate for the target RTOS or OS.

The mutex used by SSF modules must support **recursive acquisition** — the same thread may lock
it more than once without deadlocking. On pthreads platforms use
`PTHREAD_MUTEX_RECURSIVE`; on FreeRTOS use a recursive mutex.

| Macro | Parameter | Description |
|-------|-----------|-------------|
| `SSF_MUTEX_DECLARATION(mutex)` | `mutex` — variable name | Expands to the mutex variable declaration, e.g., `HANDLE mutex` or `pthread_mutex_t mutex`. |
| `SSF_MUTEX_INIT(mutex)` | `mutex` — declared variable | Initialize the mutex before first use. Assert internally on failure. |
| `SSF_MUTEX_DEINIT(mutex)` | `mutex` — initialized variable | Destroy the mutex when it is no longer needed. |
| `SSF_MUTEX_ACQUIRE(mutex)` | `mutex` — initialized variable | Lock the mutex; block until acquired. Assert internally on failure. |
| `SSF_MUTEX_RELEASE(mutex)` | `mutex` — acquired variable | Unlock the mutex. Assert internally on failure. |

**Returns:** Nothing. All macros assert internally on failure rather than returning an error code.

<a id="examples"></a>

## [↑](#ssfport--platform-port) Examples

<a id="ex-portassert"></a>

### [↑](#ssfport--platform-port) [SSFPortAssert()](#ssfportassert)

```c
/* ssfport.c — minimal production implementation */
void SSFPortAssert(const char *file, unsigned int line)
{
    /* Log fault location to NV memory so it survives the reset */
    MyNVLog(file, line);

    /* Reset the system — this function must not return */
    MySystemReset();

    /* Unreachable; prevents compiler warning on platforms that don't know MySystemReset noreturn */
    for (;;) {}
}
```

<a id="ex-gettick64"></a>

### [↑](#ssfport--platform-port) [SSFPortGetTick64()](#ssfportgettick64)

```c
/* ssfport.c — POSIX implementation using clock_gettime (SSF_TICKS_PER_SEC == 1000) */
SSFPortTick_t SSFPortGetTick64(void)
{
    struct timespec ticks;
    clock_gettime(CLOCK_MONOTONIC, &ticks);
    return (SSFPortTick_t)((((SSFPortTick_t)ticks.tv_sec) * 1000u) +
                           (ticks.tv_nsec / 1000000u));
}

/* Usage in application code */
SSFPortTick_t start = SSFPortGetTick64();
/* ... do work ... */
SSFPortTick_t elapsed = SSFPortGetTick64() - start;
/* elapsed is in ticks; divide by SSF_TICKS_PER_SEC for seconds */
```

<a id="ex-assert-macros"></a>

### [↑](#ssfport--platform-port) [SSF_ASSERT() / SSF_REQUIRE() / SSF_ENSURE() / SSF_ERROR()](#ssf-assert)

```c
/* SSF_REQUIRE — validate input parameters at function entry */
bool MyFunc(const uint8_t *buf, size_t len)
{
    SSF_REQUIRE(buf != NULL);
    SSF_REQUIRE(len > 0u);

    /* SSF_ASSERT — validate internal state */
    size_t computed = ComputeLen(buf, len);
    SSF_ASSERT(computed <= len);

    bool ok = DoWork(buf, len);

    /* SSF_ENSURE — validate return value / post-condition */
    SSF_ENSURE(ok == true || ok == false); /* always true; illustrates intent */
    return ok;
}

/* SSF_ERROR — mark an unreachable branch */
switch (state)
{
    case STATE_A: HandleA(); break;
    case STATE_B: HandleB(); break;
    default:      SSF_ERROR(); break;  /* fires if state is unexpected */
}
```

<a id="ex-htons"></a>

### [↑](#ssfport--platform-port) [htons() / ntohs()](#htons)

```c
uint16_t hostVal = 0x1234u;

/* Convert to network byte order before sending */
uint16_t netVal = htons(hostVal);
/* On little-endian: netVal == 0x3412 */

/* Convert back after receiving */
uint16_t recovered = ntohs(netVal);
/* recovered == 0x1234 */
```

<a id="ex-htonl"></a>

### [↑](#ssfport--platform-port) [htonl() / ntohl()](#htonl)

```c
uint32_t hostVal = 0x12345678u;

uint32_t netVal  = htonl(hostVal);
/* On little-endian: netVal == 0x78563412 */

uint32_t recovered = ntohl(netVal);
/* recovered == 0x12345678 */
```

<a id="ex-htonll"></a>

### [↑](#ssfport--platform-port) [htonll() / ntohll()](#htonll)

```c
uint64_t hostVal = 0x0102030405060708ull;

uint64_t netVal  = htonll(hostVal);
/* On little-endian: netVal == 0x0807060504030201 */

uint64_t recovered = ntohll(netVal);
/* recovered == 0x0102030405060708 */
```

<a id="ex-mutex"></a>

### [↑](#ssfport--platform-port) [SSF_MUTEX_DECLARATION() / SSF_MUTEX_INIT() / SSF_MUTEX_DEINIT() / SSF_MUTEX_ACQUIRE() / SSF_MUTEX_RELEASE()](#ssf-mutex-declaration)

```c
/* ssfport.h — pthreads implementation example */
#define SSF_MUTEX_DECLARATION(mutex) pthread_mutex_t mutex
#define SSF_MUTEX_INIT(mutex)    { \
    pthread_mutexattr_t attr; \
    SSF_ASSERT(pthread_mutexattr_init(&attr) == 0); \
    SSF_ASSERT(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0); \
    SSF_ASSERT(pthread_mutex_init(&mutex, &attr) == 0); \
}
#define SSF_MUTEX_DEINIT(mutex)  { SSF_ASSERT(pthread_mutex_destroy(&mutex) == 0); }
#define SSF_MUTEX_ACQUIRE(mutex) { SSF_ASSERT(pthread_mutex_lock(&mutex)    == 0); }
#define SSF_MUTEX_RELEASE(mutex) { SSF_ASSERT(pthread_mutex_unlock(&mutex)  == 0); }

/* Usage — SSF modules call these macros internally; direct use is rare */
SSF_MUTEX_DECLARATION(myMutex);

SSF_MUTEX_INIT(myMutex);

SSF_MUTEX_ACQUIRE(myMutex);
/* ... access shared resource ... */
SSF_MUTEX_RELEASE(myMutex);

SSF_MUTEX_DEINIT(myMutex);
```
