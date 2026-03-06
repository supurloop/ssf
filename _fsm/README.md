# ssfsm — Finite State Machine Framework

[SSF](../README.md)

Event-driven finite state machine framework with timer support and optional hierarchical states.

Each state machine is a function (`SSFSMHandler_t`) that receives events via a `switch` on
`SSFSMEventId_t`. The framework delivers `SSF_SM_EVENT_ENTRY` and `SSF_SM_EVENT_EXIT`
automatically on state transitions triggered by `SSFSMTran()`. Timers post events after a
configurable delay. One level of state hierarchy is supported: a child handler names its parent
with `SSF_SM_SUPER()` in its `default` case, and unhandled events are forwarded automatically.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfsm--finite-state-machine-framework) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfoptions.h`](../ssfoptions.h)
- [`ssf.h`](../ssf.h)

<a id="notes"></a>

## [↑](#ssfsm--finite-state-machine-framework) Notes

- `SSFSMInit()`, `SSFSMDeInit()`, `SSFSMInitHandler()`, `SSFSMDeInitHandler()`, and
  `SSFSMTask()` must all be called from the same single thread of execution unless
  `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`.
- `SSFSMPutEventData()` and `SSFSMPutEvent()` may be called from any execution context
  (including ISRs) when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1` and the OS primitives support
  it; otherwise they must be called from the same single-threaded context as the other functions.
- `SSFSMTran()`, `SSFSMStartTimerData()`, `SSFSMStartTimer()`, `SSFSMStopTimer()`,
  `SSF_SM_SUPER()`, and `SSF_SM_EVENT_DATA_ALIGN()` are only valid when called from within a
  state handler during event processing.
- `SSF_SM_SUPER()` must appear only in the `default` case of a child state handler; parent
  (super) state handlers must not name a further parent.
- A state transition automatically stops all running timers for that state machine before
  delivering `SSF_SM_EVENT_EXIT` to the current state and `SSF_SM_EVENT_ENTRY` to the new state.
- `SSFSMStartTimer()` with `interval == 0` fires the event at the next `SSFSMTask()` call,
  making it useful as a deferred self-post.
- `SSFSMTask()` returns `true` when there are still pending events to process; call it again
  immediately in that case rather than waiting on the wake primitive.
- In multi-threaded builds, `SSFSMTask()` is typically run in a dedicated high-priority thread
  that blocks using `SSF_SM_THREAD_WAKE_WAIT()` between calls.
- `SSFSMList_t` and `SSFSMEventList_t` enumerations are mandatory and must be defined in
  `ssfoptions.h`.

<a id="configuration"></a>

## [↑](#ssfsm--finite-state-machine-framework) Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_SM_MAX_ACTIVE_EVENTS` | `3` | Maximum number of simultaneously queued events across all state machines; increase if events are dropped under peak load |
| `SSF_SM_MAX_ACTIVE_TIMERS` | `3` | Maximum number of simultaneously running timers across all state machines |

The following enumerations are **required** in `ssfoptions.h`:

```c
/* State machine identifiers — one entry per state machine instance */
typedef enum
{
    SSF_SM_MIN = -1,     /* Required sentinel; must be first */
    SSF_SM_MY_APP_1,     /* User-defined state machines */
    SSF_SM_MY_APP_2,
    SSF_SM_MAX           /* Required sentinel; must be last */
} SSFSMList_t;

/* Event identifiers — shared across all state machines */
typedef enum
{
    SSF_SM_EVENT_MIN = -1,      /* Required sentinel; must be first */
    SSF_SM_EVENT_ENTRY,         /* Required: delivered on state entry */
    SSF_SM_EVENT_EXIT,          /* Required: delivered on state exit */
    SSF_SM_EVENT_SUPER,         /* Required: used internally for hierarchy probing */
    /* User-defined events follow */
    SSF_SM_EVENT_MY_DATA_RX,
    SSF_SM_EVENT_MY_TIMER,
    SSF_SM_EVENT_MAX            /* Required sentinel; must be last */
} SSFSMEventList_t;
```

**Thread sync macros** (required when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`):

| Macro | Description |
|-------|-------------|
| `SSF_SM_THREAD_SYNC_DECLARATION` | Declare the mutex object |
| `SSF_SM_THREAD_SYNC_INIT()` | Initialize the mutex |
| `SSF_SM_THREAD_SYNC_DEINIT()` | De-initialize the mutex |
| `SSF_SM_THREAD_SYNC_ACQUIRE()` | Acquire the mutex |
| `SSF_SM_THREAD_SYNC_RELEASE()` | Release the mutex |

**Thread wake macros** (required when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`); implement with
a counting semaphore capped at 1:

| Macro | Description |
|-------|-------------|
| `SSF_SM_THREAD_WAKE_DECLARATION` | Declare the wake semaphore |
| `SSF_SM_THREAD_WAKE_INIT()` | Initialize the wake semaphore |
| `SSF_SM_THREAD_WAKE_DEINIT()` | De-initialize the wake semaphore |
| `SSF_SM_THREAD_WAKE_POST()` | Signal the FSM thread that an event is ready |
| `SSF_SM_THREAD_WAKE_WAIT(timeout)` | Block the FSM thread until an event arrives or `timeout` elapses |

<a id="api-summary"></a>

## [↑](#ssfsm--finite-state-machine-framework) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssfsmid-t"></a>`SSFSMId_t` | Type (`int8_t`) | Identifies a state machine instance; values come from `SSFSMList_t` |
| <a id="ssfsmeventid-t"></a>`SSFSMEventId_t` | Type (`int16_t`) | Identifies an event; values come from `SSFSMEventList_t` |
| <a id="ssfsmdata-t"></a>`SSFSMData_t` | Type (`uint8_t`) | Element type for event data payloads |
| <a id="ssfsmdatalen-t"></a>`SSFSMDataLen_t` | Type (`uint16_t`) | Length in bytes of an event data payload |
| <a id="ssfsmtimeout-t"></a>`SSFSMTimeout_t` | Type (`SSFPortTick_t`) | Timer interval in system ticks; `0` fires at the next `SSFSMTask()` call |
| <a id="ssfsmhandler-t"></a>`SSFSMHandler_t` | Function pointer | State handler signature: `void fn(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler)` |
| <a id="ssf-sm-max-timeout"></a>`SSF_SM_MAX_TIMEOUT` | Constant | Maximum valid timer interval (`(SSFSMTimeout_t)(-1)`) |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`void SSFSMInit(maxEvents, maxTimers)`](#ssfsminit) | Initialize the framework; must be called before any other ssfsm function |
| [e.g.](#ex-deinit) | [`void SSFSMDeInit()`](#ssfsmdeinit) | De-initialize the framework and release all resources |
| [e.g.](#ex-init-handler) | [`void SSFSMInitHandler(smid, initial)`](#ssfsminithandler) | Register a state machine and deliver `SSF_SM_EVENT_ENTRY` to the initial state |
| [e.g.](#ex-deinit-handler) | [`void SSFSMDeInitHandler(smid)`](#ssfsmdeinithandler) | Unregister a state machine |
| [e.g.](#ex-task) | [`bool SSFSMTask(nextTimeout)`](#ssfsmtask) | Process all pending events and expired timers; returns time until next timer |
| [e.g.](#ex-put-event-data) | [`void SSFSMPutEventData(smid, eid, data, dataLen)`](#ssfsmputeventdata) | Post an event with a data payload to a state machine |
| [e.g.](#ex-put-event) | [`void SSFSMPutEvent(smid, eid)`](#ssfsmputevent) | Post an event without data (expands to `SSFSMPutEventData` with `NULL`/`0`) |
| [e.g.](#ex-tran) | [`void SSFSMTran(next)`](#ssfsmtran) | Trigger a state transition; valid only inside a state handler |
| [e.g.](#ex-start-timer-data) | [`void SSFSMStartTimerData(eid, interval, data, dataLen)`](#ssfsmstarttimerddata) | Start a timer that posts an event with data; valid only inside a state handler |
| [e.g.](#ex-start-timer) | [`void SSFSMStartTimer(eid, to)`](#ssfsmstarttimer) | Start a timer without data (expands to `SSFSMStartTimerData` with `NULL`/`0`) |
| [e.g.](#ex-stop-timer) | [`void SSFSMStopTimer(eid)`](#ssfsmstoptimer) | Cancel a running timer; valid only inside a state handler |
| [e.g.](#ex-super) | [`void SSF_SM_SUPER(super)`](#ssf-sm-super) | Name the parent state handler; place in the `default` case of a child handler |
| [e.g.](#ex-event-data-align) | [`void SSF_SM_EVENT_DATA_ALIGN(v)`](#ssf-sm-event-data-align) | Copy event data into a typed variable; valid only inside a state handler |

<a id="function-reference"></a>

## [↑](#ssfsm--finite-state-machine-framework) Function Reference

<a id="ssfsminit"></a>

### [↑](#functions) [`void SSFSMInit()`](#functions)

```c
void SSFSMInit(uint32_t maxEvents, uint32_t maxTimers);
```

Initializes the framework, allocating the internal event queue and timer table. Must be called
once before `SSFSMInitHandler()`, `SSFSMTask()`, or any event-posting function. Pass values
that match `SSF_SM_MAX_ACTIVE_EVENTS` and `SSF_SM_MAX_ACTIVE_TIMERS` from `ssfoptions.h`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `maxEvents` | in | `uint32_t` | Maximum simultaneously queued events. Must equal `SSF_SM_MAX_ACTIVE_EVENTS`. |
| `maxTimers` | in | `uint32_t` | Maximum simultaneously running timers. Must equal `SSF_SM_MAX_ACTIVE_TIMERS`. |

**Returns:** Nothing.

<a id="ex-init"></a>

**Example:**

```c
/* Initialize framework — values must match ssfoptions.h constants */
SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
/* Framework ready; call SSFSMInitHandler() for each state machine */
```

---

<a id="ssfsmdeinit"></a>

### [↑](#functions) [`void SSFSMDeInit()`](#functions)

```c
void SSFSMDeInit(void);
```

De-initializes the framework and frees internal resources. After this call, no other ssfsm
function may be used until `SSFSMInit()` is called again.

**Returns:** Nothing.

<a id="ex-deinit"></a>

**Example:**

```c
SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);
/* ... initialize handlers and run ... */
SSFSMDeInit();
/* Internal resources freed; SSFSMInit() required before further use */
```

---

<a id="ssfsminithandler"></a>

### [↑](#functions) [`void SSFSMInitHandler()`](#functions)

```c
void SSFSMInitHandler(SSFSMId_t smid, SSFSMHandler_t initial);
```

Registers a state machine identified by `smid` and sets `initial` as the current state.
Immediately delivers `SSF_SM_EVENT_ENTRY` to `initial`. If `initial` has a parent state
(established through `SSF_SM_SUPER()`), `SSF_SM_EVENT_ENTRY` is delivered to the parent first,
then to `initial`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `smid` | in | `SSFSMId_t` | State machine identifier from `SSFSMList_t`. Must be between `SSF_SM_MIN+1` and `SSF_SM_MAX-1`. |
| `initial` | in | `SSFSMHandler_t` | Pointer to the initial state handler function. Must not be `NULL`. |

**Returns:** Nothing.

<a id="ex-init-handler"></a>

**Example:**

```c
static void IdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                        SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler);

SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);

/* Register state machine; SSF_SM_EVENT_ENTRY is delivered to IdleHandler() immediately */
SSFSMInitHandler(SSF_SM_STATUS_LED, IdleHandler);

/* Superloop */
while (true)
{
    SSFSMTask(NULL);
}
```

---

<a id="ssfsmdeinithandler"></a>

### [↑](#functions) [`void SSFSMDeInitHandler()`](#functions)

```c
void SSFSMDeInitHandler(SSFSMId_t smid);
```

Unregisters the state machine identified by `smid` and cancels all its pending timers and
events. After this call the slot may be re-registered with `SSFSMInitHandler()`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `smid` | in | `SSFSMId_t` | State machine identifier to unregister. |

**Returns:** Nothing.

<a id="ex-deinit-handler"></a>

**Example:**

```c
static void IdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                        SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler);

SSFSMInitHandler(SSF_SM_STATUS_LED, IdleHandler);
/* ... */
SSFSMDeInitHandler(SSF_SM_STATUS_LED);
/* State machine unregistered; pending timers and events cancelled */
```

---

<a id="ssfsmtask"></a>

### [↑](#functions) [`bool SSFSMTask()`](#functions)

```c
bool SSFSMTask(SSFSMTimeout_t *nextTimeout);
```

Processes all pending events and fires any expired timers by invoking the appropriate state
handlers. Must be called repeatedly from the framework's execution context.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `nextTimeout` | out | `SSFSMTimeout_t *` | Receives the number of system ticks until the next timer expires, or `SSF_SM_MAX_TIMEOUT` if no timers are running. Pass `NULL` in single-threaded superloop builds. |

**Returns:** `true` if there are additional pending events that should be processed immediately
(call `SSFSMTask()` again without waiting); `false` when no more events are queued and the
caller may safely block for up to `*nextTimeout` ticks.

<a id="ex-task"></a>

**Example:**

```c
/* Single-threaded superloop */
while (true)
{
    SSFSMTask(NULL);
}

/* Multi-threaded: FSM thread blocks between calls using the wake primitive */
SSFSMTimeout_t to;
while (true)
{
    if (SSFSMTask(&to) == false)
    {
        /* No more pending events — block until next timer or SSFSMPutEvent() wakes us */
        SSF_SM_THREAD_WAKE_WAIT(to);
    }
}
```

---

<a id="ssfsmputeventdata"></a>

### [↑](#functions) [`void SSFSMPutEventData()`](#functions)

```c
void SSFSMPutEventData(SSFSMId_t smid, SSFSMEventId_t eid, const SSFSMData_t *data,
                       SSFSMDataLen_t dataLen);
```

Enqueues an event for state machine `smid`. If `data` is non-`NULL`, up to `dataLen` bytes are
copied into the event queue entry and delivered to the handler as the `data`/`dataLen`
parameters. May be called from any context when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `smid` | in | `SSFSMId_t` | Target state machine identifier. |
| `eid` | in | `SSFSMEventId_t` | Event identifier from `SSFSMEventList_t`. Must not be `SSF_SM_EVENT_ENTRY`, `SSF_SM_EVENT_EXIT`, or `SSF_SM_EVENT_SUPER`. |
| `data` | in | `const SSFSMData_t *` | Pointer to the event data payload. Pass `NULL` when there is no data. |
| `dataLen` | in | `SSFSMDataLen_t` | Number of bytes of event data. Must be `0` when `data` is `NULL`. |

**Returns:** Nothing.

<a id="ex-put-event-data"></a>

**Example:**

```c
/* Post an event carrying a 16-bit received-length payload */
uint16_t rxLen = 42u;
SSFSMPutEventData(SSF_SM_STATUS_LED, SSF_SM_EVENT_RX_DATA,
                  (SSFSMData_t *)&rxLen, (SSFSMDataLen_t)sizeof(rxLen));
```

---

<a id="ssfsmputevent"></a>

### [↑](#functions) [`void SSFSMPutEvent()`](#functions)

```c
#define SSFSMPutEvent(smid, eid) SSFSMPutEventData(smid, eid, NULL, 0)
```

Convenience macro for posting an event without a data payload. Expands to
[`SSFSMPutEventData()`](#ssfsmputeventdata) with `NULL` and `0` for the data parameters. All
threading constraints of `SSFSMPutEventData()` apply.

<a id="ex-put-event"></a>

**Example:**

```c
/* Post an event without a data payload */
SSFSMPutEvent(SSF_SM_STATUS_LED, SSF_SM_EVENT_RX_DATA);
```

---

<a id="ssfsmtran"></a>

### [↑](#functions) [`void SSFSMTran()`](#functions)

```c
void SSFSMTran(SSFSMHandler_t next);
```

Requests a transition to the state handler `next`. Valid only when called from within a state
handler during event processing. The framework delivers `SSF_SM_EVENT_EXIT` to the current
state (and its parent if applicable), stops all running timers for the machine, then delivers
`SSF_SM_EVENT_ENTRY` to `next` (and its parent if applicable). Must not be called from within
the `SSF_SM_EVENT_ENTRY` or `SSF_SM_EVENT_EXIT` event cases.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `next` | in | `SSFSMHandler_t` | Pointer to the target state handler function. Must not be `NULL`. |

**Returns:** Nothing.

<a id="ex-tran"></a>

**Example:**

```c
static void BlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                         SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler);

static void IdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                        SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        /* Turn LED off on entry */
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_RX_DATA:
        /* Transition: EXIT fires for IdleHandler, ENTRY fires for BlinkHandler */
        SSFSMTran(BlinkHandler);
        break;
    default:
        break;
    }
}
```

---

<a id="ssfsmstarttimerddata"></a>

### [↑](#functions) [`void SSFSMStartTimerData()`](#functions)

```c
void SSFSMStartTimerData(SSFSMEventId_t eid, SSFSMTimeout_t interval,
                         const SSFSMData_t *data, SSFSMDataLen_t dataLen);
```

Starts or restarts a timer that posts event `eid` to the owning state machine after `interval`
system ticks. If a timer for `eid` is already running, it is restarted with the new interval
and data. An `interval` of `0` posts the event at the next `SSFSMTask()` call. Valid only
when called from within a state handler.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `eid` | in | `SSFSMEventId_t` | Event to post when the timer expires. Must be a user-defined event from `SSFSMEventList_t`. |
| `interval` | in | `SSFSMTimeout_t` | Delay in system ticks. `0` fires at the next `SSFSMTask()` call; `SSF_SM_MAX_TIMEOUT` is the maximum. |
| `data` | in | `const SSFSMData_t *` | Data payload to deliver with the timer event. Pass `NULL` when there is no data. |
| `dataLen` | in | `SSFSMDataLen_t` | Number of bytes of data. Must be `0` when `data` is `NULL`. |

**Returns:** Nothing.

<a id="ex-start-timer-data"></a>

**Example:**

```c
static void BlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                         SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
    {
        /* Start a 1-second timer carrying a blink-count payload */
        uint8_t count = 5u;
        SSFSMStartTimerData(SSF_SM_EVENT_BLINK_TIMER, SSF_TICKS_PER_SEC,
                            (SSFSMData_t *)&count, (SSFSMDataLen_t)sizeof(count));
        break;
    }
    default:
        break;
    }
}
```

---

<a id="ssfsmstarttimer"></a>

### [↑](#functions) [`void SSFSMStartTimer()`](#functions)

```c
#define SSFSMStartTimer(eid, to) SSFSMStartTimerData(eid, to, NULL, 0)
```

Convenience macro for starting a timer without a data payload. Expands to
[`SSFSMStartTimerData()`](#ssfsmstarttimerddata) with `NULL` and `0` for the data parameters.
Valid only when called from within a state handler.

<a id="ex-start-timer"></a>

**Example:**

```c
static void IdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                        SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler);

static void BlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                         SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        /* Fire immediately at next SSFSMTask(); idle timeout after 10 seconds */
        SSFSMStartTimer(SSF_SM_EVENT_BLINK_TIMER, 0);
        SSFSMStartTimer(SSF_SM_EVENT_IDLE_TIMER,  SSF_TICKS_PER_SEC * 10u);
        break;
    case SSF_SM_EVENT_BLINK_TIMER:
        /* Toggle LED and reschedule for 1-second repeat */
        SSFSMStartTimer(SSF_SM_EVENT_BLINK_TIMER, SSF_TICKS_PER_SEC);
        break;
    case SSF_SM_EVENT_IDLE_TIMER:
        SSFSMTran(IdleHandler);
        break;
    default:
        break;
    }
}
```

---

<a id="ssfsmstoptimer"></a>

### [↑](#functions) [`void SSFSMStopTimer()`](#functions)

```c
void SSFSMStopTimer(SSFSMEventId_t eid);
```

Cancels the timer for event `eid` on the owning state machine if it is running. Has no effect
if no timer for `eid` is active. Valid only when called from within a state handler. Note that
`SSFSMTran()` automatically stops all running timers, so explicit cancellation is only needed
when stopping a timer without transitioning.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `eid` | in | `SSFSMEventId_t` | Event identifier of the timer to cancel. |

**Returns:** Nothing.

<a id="ex-stop-timer"></a>

**Example:**

```c
static void BlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                         SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_RX_DATA:
        /* Cancel the idle timeout; keep blinking */
        SSFSMStopTimer(SSF_SM_EVENT_IDLE_TIMER);
        /* Note: SSFSMTran() would cancel all timers automatically */
        break;
    default:
        break;
    }
}
```

---

<a id="ssf-sm-super"></a>

### [↑](#functions) [`void SSF_SM_SUPER()`](#functions)

```c
#define SSF_SM_SUPER(super) *superHandler = (SSFVoidFn_t)super;
```

Names the parent (super) state handler for the current child state. Must appear in the
`default` case of a child state handler; writes `super` into the `superHandler` output
parameter of the handler function. When an event is not handled by the child, the framework
re-delivers it to the parent. Parent handlers must not call `SSF_SM_SUPER()`. Valid only when
called from within a state handler.

| Parameter | Description |
|-----------|-------------|
| `super` | The parent state handler function (`SSFSMHandler_t`). The framework will route unhandled events to this handler. |

<a id="ex-super"></a>

**Example:**

```c
static void IdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                        SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler);

static void ChildHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                         SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_RX_DATA:
        /* Handle event specific to this child state */
        break;
    default:
        /* Route all other events to ParentHandler for processing */
        SSF_SM_SUPER(ParentHandler);
        break;
    }
}

static void ParentHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                          SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_BLINK_TIMER:
        /* Shared behavior: handled for any child that names ParentHandler as super */
        SSFSMTran(IdleHandler);
        break;
    default:
        /* Parent handlers must NOT call SSF_SM_SUPER() */
        break;
    }
}
```

---

<a id="ssf-sm-event-data-align"></a>

### [↑](#functions) [`void SSF_SM_EVENT_DATA_ALIGN()`](#functions)

```c
#define SSF_SM_EVENT_DATA_ALIGN(v) { \
    SSF_ASSERT((sizeof(v) >= dataLen) && (data != NULL)); \
    memcpy(&(v), data, dataLen); }
```

Safely copies the event data payload into a typed variable `v`. Asserts that `sizeof(v) >=
dataLen` and that `data` is non-`NULL`. Accesses `data` and `dataLen` from the enclosing state
handler's parameter scope; valid only when called from within a state handler.

| Parameter | Description |
|-----------|-------------|
| `v` | A variable whose address receives the event data via `memcpy`. Must be large enough to hold `dataLen` bytes. |

<a id="ex-event-data-align"></a>

**Example:**

```c
static void BlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                         SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler);

static void IdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data,
                        SSFSMDataLen_t dataLen, SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_RX_DATA:
    {
        uint16_t rxLen;
        /* Safely copy the event data payload into a typed variable */
        SSF_SM_EVENT_DATA_ALIGN(rxLen);
        /* rxLen now holds the value posted via SSFSMPutEventData() */
        SSFSMTran(BlinkHandler);
        break;
    }
    default:
        break;
    }
}
```
