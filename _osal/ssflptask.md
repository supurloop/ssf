# ssflptask — Low-Priority Task Queue

[SSF](../README.md) | [OS Abstraction](README.md)

Singleton FIFO queue that offloads blocking or CPU-intensive work from the main loop to a
background thread. Callers `Queue()` a work function with an opaque context; a single
worker thread drains the queue in insertion order, calling each work function and then its
optional completion callback. The completion callback runs in the worker thread, not the
main loop — main-loop integration is done by waking the main loop on a self-pipe (POSIX) or
event handle (Windows) that the opt file exposes.

The whole module is one process-wide queue. There is no per-instance handle on the public
API: `Init()` / `DeInit()` initialize a static singleton, and `Queue()` returns a token
that is meaningful only to `Cancel()`.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssflptask--low-priority-task-queue) Dependencies

- [`ssfport.h`](../ssfport.h) — pulls in `SSF_CONFIG_ENABLE_THREAD_SUPPORT` and the
  `SSF_MUTEX_*` family used to protect the queue.
- [`ssfll`](../_struct/ssfll.md) — the work queue and the free-entry pool are both
  `SSFLL_t` linked lists.
- POSIX `pthread` (macOS / Linux) or Windows semaphores / event handles for the worker
  thread and wake mechanism. Selected at compile time by the platform; both are wired up
  via macros in [`_opt/ssflptask_opt.h`](../_opt/ssflptask_opt.h).

<a id="notes"></a>

## [↑](#ssflptask--low-priority-task-queue) Notes

- **Threading is required.** The module is gated on
  `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`. When threading is disabled at build time the
  public functions exist but trip `SSF_ERROR()` if called — a guard against linking the
  module into a single-threaded build by accident. Verify-only / non-threaded targets
  should leave `ssflptask.c` out of the build entirely.
- **Singleton.** All state is module-private (static). [`SSFLPTaskInit()`](#ssflptaskinit)
  asserts if the module is already initialized; [`SSFLPTaskDeInit()`](#ssflptaskdeinit)
  asserts if it is not. There is no second instance to support multiple priority queues —
  if multiple priorities are needed, run multiple background threads at the application
  layer, each with its own [`ssfll`](../_struct/ssfll.md)-based queue.
- **Caller MUST NOT touch `ctx` until the completion callback fires.** The work function
  reads and may write `*ctx` from the worker thread; if the caller touches `*ctx`
  concurrently the worker may observe torn state. The completion callback fires after
  `workFn(ctx)` returns and is the synchronization edge that releases `*ctx` back to the
  caller. If no completion callback is provided (`completeFn == NULL`), the caller has no
  signal that the work is done — provide one whenever the caller intends to read the
  context after the work is complete.
- **Completion callbacks run in the worker thread.** They do **not** run on the main
  loop. If a completion needs to do main-loop work (update UI, post to a select()-based
  event loop), the callback should enqueue a notification through whatever main-loop
  signalling primitive the application uses. The opt file exposes
  `SSF_MAIN_THREAD_WAKE_*` macros (a self-pipe on POSIX, an event handle on Windows) that
  the worker uses internally — applications driving a `select()`-style main loop can read
  the same self-pipe FD via `SSF_MAIN_THREAD_WAKE_FD()` and drain it via
  `SSF_MAIN_THREAD_WAKE_DRAIN()` after each select wake to detect "completions are
  pending."
- **FIFO order.** Work items run in the order they were queued. There is no priority
  band, no preemption between work items, and no parallelism — one item runs to
  completion before the next starts.
- **Bounded queue.** The queue holds at most
  [`SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH`](#cfg-max-queue) items (default 8). When full,
  [`SSFLPTaskQueue()`](#ssflptaskqueue) returns
  [`SSF_LPTASK_HANDLE_INVALID`](#ssf-lptask-handle-invalid) instead of asserting; callers
  should handle that return as a "try again later" signal rather than a fatal error.
- **Cancel only catches queued work.** [`SSFLPTaskCancel()`](#ssflptaskcancel) walks the
  pending queue under lock and returns `true` only if the handle is still queued. Once
  the worker has popped an item and started its work function, the handle is no longer
  cancellable — `Cancel` returns `false` and the work runs to completion. There is no
  way to interrupt a running work function from this module.
- **Handles are non-zero `uint32_t` values that wrap.** The next-handle counter starts at
  `1`, increments on every successful queue, and wraps from
  [`SSF_LPTASK_HANDLE_INVALID − 1`](#ssf-lptask-handle-invalid) back to `1`. Two queued
  items can therefore share a handle if the queue stays non-empty for `2³² − 1` queue
  operations — vanishingly unlikely, but applications with an extremely long-lived queue
  shouldn't equate handles directly to "this specific work."
- **DeInit drains, then waits.** [`SSFLPTaskDeInit()`](#ssflptaskdeinit) sets the running
  flag false, posts a wake, joins the worker thread, and only then tears down state.
  In-flight work is allowed to complete; pending (not-yet-started) work is silently
  dropped. After `DeInit` returns, `Init` may be called again on a fresh state.
- **Trace output is opt-in.** When
  [`SSF_LPTASK_CONFIG_ENABLE_TRACE`](#cfg-enable-trace) is `1`, queue operations with a
  non-`NULL` `description` print `[LPTask] QUEUED:` / `START:` / `DONE:` lines to
  `stdout`. Pass `NULL` for `description` to suppress trace for a particular item even
  with the global flag on. Set the macro to `0` to remove the trace code from the build.

<a id="configuration"></a>

## [↑](#ssflptask--low-priority-task-queue) Configuration

Options live in [`_opt/ssflptask_opt.h`](../_opt/ssflptask_opt.h). The thread-support
macros (`SSF_LPTASK_THREAD_SYNC_*`, `SSF_LPTASK_THREAD_WAKE_*`,
`SSF_MAIN_THREAD_WAKE_*`) are also defined there but are infrastructure for the module
itself; they are documented inline in the opt file rather than here.

| Macro | Default | Description |
|-------|---------|-------------|
| <a id="cfg-max-queue"></a>`SSF_LPTASK_CONFIG_MAX_QUEUE_DEPTH` | `8` | Maximum number of work items that can be queued at once. The free-entry pool is sized to this and is consumed by every `Queue()` call until the matching item completes (or is cancelled). |
| <a id="cfg-enable-trace"></a>`SSF_LPTASK_CONFIG_ENABLE_TRACE` | `1` | Set to `1` to emit `[LPTask] QUEUED / START / DONE` lifecycle lines to `stdout` for items with non-`NULL` description. Set to `0` to remove the trace code at build time. |

The module also reads `SSF_CONFIG_ENABLE_THREAD_SUPPORT` from `ssfport.h`; threading must
be enabled or the module's public functions degrade to `SSF_ERROR()` stubs.

The unit-test entry point is gated by `SSF_CONFIG_LPTASK_UNIT_TEST` in `ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssflptask--low-priority-task-queue) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-workfn"></a>`SSFLPTaskWorkFn_t` | Typedef | `void (*)(void *ctx)` — the work function executed in the worker thread. |
| <a id="type-completefn"></a>`SSFLPTaskCompleteFn_t` | Typedef | `void (*)(void *ctx)` — optional completion callback invoked after `workFn` returns, also in the worker thread. |
| <a id="type-handle"></a>`SSFLPTaskHandle_t` | Typedef | `uint32_t` queue-entry handle; used by [`SSFLPTaskCancel()`](#ssflptaskcancel). |
| <a id="ssf-lptask-handle-invalid"></a>`SSF_LPTASK_HANDLE_INVALID` | Constant | `0xFFFFFFFF` — sentinel returned by [`SSFLPTaskQueue()`](#ssflptaskqueue) when the queue is full. |
| <a id="type-status"></a>`SSFLPTaskStatus_t` | Struct | Snapshot returned by [`SSFLPTaskGetStatus()`](#ssflptaskgetstatus): `queueDepth`, `maxQueueDepth`, `totalQueued`, `totalCompleted`, `threadRunning`. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`void SSFLPTaskInit(void)`](#ssflptaskinit) | Initialize the singleton and start the worker thread |
| [e.g.](#ex-deinit) | [`void SSFLPTaskDeInit(void)`](#ssflptaskdeinit) | Drain in-flight work and stop the worker thread |
| [e.g.](#ex-isinited) | [`bool SSFLPTaskIsInited(void)`](#ssflptaskisinited) | Returns true if the module is initialized and the worker is running |
| [e.g.](#ex-queue) | [`SSFLPTaskHandle_t SSFLPTaskQueue(workFn, completeFn, ctx, description)`](#ssflptaskqueue) | Queue a work item; returns the handle or `SSF_LPTASK_HANDLE_INVALID` |
| [e.g.](#ex-cancel) | [`bool SSFLPTaskCancel(handle)`](#ssflptaskcancel) | Remove a queued item that hasn't started executing |
| [e.g.](#ex-status) | [`bool SSFLPTaskGetStatus(statusOut)`](#ssflptaskgetstatus) | Snapshot queue depth and counters |

<a id="function-reference"></a>

## [↑](#ssflptask--low-priority-task-queue) Function Reference

<a id="ssflptaskinit"></a>

### [↑](#functions) [`void SSFLPTaskInit()`](#functions)

```c
void SSFLPTaskInit(void);
```

Initializes the module: zeroes the entry pool, primes the free list, creates the queue
mutex and wake primitive, and starts the background worker thread. Asserts if the module
is already initialized.

Calling `SSFLPTaskInit()` in a build with `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 0` trips
`SSF_ERROR()` immediately — the module has no fallback for single-threaded targets.

**Returns:** Nothing.

<a id="ex-init"></a>

**Example:**

```c
SSFLPTaskInit();
/* Worker thread is running; SSFLPTaskQueue() may now be called. */
```

---

<a id="ssflptaskdeinit"></a>

### [↑](#functions) [`void SSFLPTaskDeInit()`](#functions)

```c
void SSFLPTaskDeInit(void);
```

Stops the worker thread and tears down module state. Sets the internal `_running` flag
false, posts a wake so a thread waiting on the wake primitive returns, joins the worker,
drains both the work queue and the free pool, then de-initializes the underlying
[`ssfll`](../_struct/ssfll.md) lists. Asserts if the module is not initialized.

In-flight work (the item the worker is currently executing) is allowed to finish;
pending items still in the queue at the time of `DeInit` are silently dropped — their
work and completion functions are **not** invoked. Callers that need every queued item to
run must drain the queue (e.g., poll [`SSFLPTaskGetStatus()`](#ssflptaskgetstatus) until
`queueDepth == 0` and `totalCompleted == totalQueued`) before calling `DeInit`.

**Returns:** Nothing.

<a id="ex-deinit"></a>

**Example:**

```c
SSFLPTaskInit();
/* ... queue and run work ... */
SSFLPTaskDeInit();
/* Worker thread joined; the singleton may be Init-ed again. */
```

---

<a id="ssflptaskisinited"></a>

### [↑](#functions) [`bool SSFLPTaskIsInited()`](#functions)

```c
bool SSFLPTaskIsInited(void);
```

Returns whether the module is initialized **and** the worker thread is currently running.
Returns `false` between `DeInit()` (which clears `_running`) and the next `Init()`. Safe
to call before the first `Init()` — returns `false`.

**Returns:** `true` if the module is initialized and the worker is running; `false`
otherwise.

<a id="ex-isinited"></a>

**Example:**

```c
SSFLPTaskIsInited();   /* false */
SSFLPTaskInit();
SSFLPTaskIsInited();   /* true */
SSFLPTaskDeInit();
SSFLPTaskIsInited();   /* false */
```

---

<a id="ssflptaskqueue"></a>

### [↑](#functions) [`SSFLPTaskHandle_t SSFLPTaskQueue()`](#functions)

```c
SSFLPTaskHandle_t SSFLPTaskQueue(SSFLPTaskWorkFn_t workFn, SSFLPTaskCompleteFn_t completeFn,
                                 void *ctx, const char *description);
```

Adds a work item to the back of the FIFO queue and wakes the worker thread. The worker
will eventually call `workFn(ctx)`, then (if non-`NULL`) `completeFn(ctx)`. Both
callbacks run in the worker thread.

**The caller must not access `*ctx` between the call to `Queue()` and the moment the
completion callback fires.** The work function may read or modify `*ctx` from the worker
thread; concurrent main-thread access is a data race. If the application has no use for
the result and no need to free `*ctx` afterward, `completeFn` can be `NULL` — but the
caller still must not touch `*ctx` once it has been queued, since the worker thread may
still hold a pointer to it after `workFn` returns.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `workFn` | in | [`SSFLPTaskWorkFn_t`](#type-workfn) | Function to execute on the worker thread. Must not be `NULL`. |
| `completeFn` | in | [`SSFLPTaskCompleteFn_t`](#type-completefn) | Optional completion callback fired after `workFn` returns. May be `NULL`. |
| `ctx` | in-out | `void *` | Opaque pointer passed to both callbacks. May be `NULL`. Lifetime is the caller's responsibility. |
| `description` | in | `const char *` | Optional label for lifecycle trace. May be `NULL` to suppress trace for this item even when `SSF_LPTASK_CONFIG_ENABLE_TRACE == 1`. The pointer is stored verbatim — must remain valid until the work completes. Typically a string literal. |

**Returns:** A non-zero [`SSFLPTaskHandle_t`](#type-handle) on success, or
[`SSF_LPTASK_HANDLE_INVALID`](#ssf-lptask-handle-invalid) when the queue is full.

<a id="ex-queue"></a>

**Example:**

```c
typedef struct
{
    int input;
    int output;
} MyJob_t;

static void doMyWork(void *ctx)
{
    MyJob_t *job = (MyJob_t *)ctx;

    /* Worker thread context. ctx is owned by us until completeFn returns. */
    job->output = expensive_computation(job->input);
}

static void doMyComplete(void *ctx)
{
    MyJob_t *job = (MyJob_t *)ctx;

    /* Still on the worker thread. Hand the result off to the main loop. */
    post_to_main_loop(job);
}

MyJob_t job = { .input = 42 };
SSFLPTaskHandle_t h = SSFLPTaskQueue(doMyWork, doMyComplete, &job, "compute-42");

if (h == SSF_LPTASK_HANDLE_INVALID)
{
    /* Queue full -- retry later. */
}
```

---

<a id="ssflptaskcancel"></a>

### [↑](#functions) [`bool SSFLPTaskCancel()`](#functions)

```c
bool SSFLPTaskCancel(SSFLPTaskHandle_t handle);
```

Walks the pending queue under lock and removes the entry whose handle equals `handle` if
it is still queued. Returns `true` if the entry was removed (in which case neither
`workFn` nor `completeFn` will run). Returns `false` if the worker has already popped the
matching entry (i.e., the work is in-flight or already complete) or if the handle never
matched a queued entry.

`handle` must not be [`SSF_LPTASK_HANDLE_INVALID`](#ssf-lptask-handle-invalid); asserting
otherwise. The module must be initialized; asserting otherwise.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `handle` | in | [`SSFLPTaskHandle_t`](#type-handle) | A handle returned from a previous `SSFLPTaskQueue()` call. Must not be `SSF_LPTASK_HANDLE_INVALID`. |

**Returns:** `true` if a queued entry matching `handle` was removed; `false` otherwise.

<a id="ex-cancel"></a>

**Example:**

```c
SSFLPTaskHandle_t h = SSFLPTaskQueue(doMyWork, doMyComplete, &job, "compute-42");

if (SSFLPTaskCancel(h))
{
    /* Removed before it ran. Caller still owns &job. */
}
else
{
    /* Either already running / done, or handle never matched.
       The completion callback (if any) is the only safe way to know
       which case applies. */
}
```

---

<a id="ssflptaskgetstatus"></a>

### [↑](#functions) [`bool SSFLPTaskGetStatus()`](#functions)

```c
bool SSFLPTaskGetStatus(SSFLPTaskStatus_t *statusOut);
```

Snapshots the current queue depth, the configured maximum depth, the total number of
items ever queued, the total number ever completed, and the worker-thread running flag,
into `*statusOut`. Always returns `true` when the module is initialized; the bool return
exists for symmetry with the other queue ops and for forward compatibility.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `statusOut` | out | [`SSFLPTaskStatus_t *`](#type-status) | Receives the snapshot. Must not be `NULL`. |

**Returns:** `true` on success.

<a id="ex-status"></a>

**Example:**

```c
SSFLPTaskStatus_t s;

if (SSFLPTaskGetStatus(&s))
{
    /* s.queueDepth, s.totalQueued - s.totalCompleted, etc. */
    /* Useful for backpressure: stop submitting new work when
       queueDepth approaches maxQueueDepth. */
}
```
