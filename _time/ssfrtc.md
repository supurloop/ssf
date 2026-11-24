# ssfrtc — Unix Time RTC Interface

[SSF](../README.md) | [Time](README.md)

Tracks Unix time by combining a hardware RTC read at startup with the system tick counter,
eliminating repeated slow RTC hardware accesses.

`SSFRTCInit()` reads the hardware RTC once and records the corresponding system tick value.
All subsequent calls to `SSFRTCGetUnixNow()` derive the current time from the elapsed tick
count without touching hardware. `SSFRTCSet()` writes a new time through to the hardware RTC
and resets the tick baseline.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfrtc--unix-time-rtc-interface) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`_opt/ssfrtc_opt.h`](../_opt/ssfrtc_opt.h) (aggregated through `ssfoptions.h`)

<a id="notes"></a>

## [↑](#ssfrtc--unix-time-rtc-interface) Notes

- Call `SSFRTCInit()` once at startup before any call to `SSFRTCGetUnixNow()` or `SSFRTCSet()`.
  Calling either before `SSFRTCInit()`, or after `SSFRTCDeInit()`, is a programming error and
  asserts, as do `SSFRTCInit()` twice without `SSFRTCDeInit()` and `SSFRTCDeInit()` when not
  initialized. There is deliberately no "is initialized" query.
- **Initialized is not the same as time valid.** `SSFRTCInit()` initializes the interface even
  when its RTC read fails or returns an out-of-range value; it then returns `false`, and
  `SSFRTCGetUnixNow()` returns `false` (no assert) until a successful `SSFRTCSet()`. A failed
  `SSFRTCSet()` also leaves the time not valid.
- **A valid read is not a plausible time.** Any value from `0` to `SSFDTIME_UNIX_EPOCH_SEC_MAX`
  is accepted: the simulated RTC starts at `0`, so after `SSFRTCInit()` it reports
  1970-01-01 as a valid time until `SSFRTCSet()`, and a hardware RTC that lost power typically
  does the same. A caller that needs a trusted time applies its own floor; the TLS client
  refuses times before `SSF_TLSC_CONFIG_MIN_TRUSTED_UNIX_SEC`.
- `SSFRTCGetUnixNow()` returns time in system ticks (`SSFPortTick_t`); divide by
  `SSF_TICKS_PER_SEC` to obtain whole seconds.
- When [`SSF_RTC_ENABLE_SIM`](#opt-sim) is `0`, implement the `SSF_RTC_WRITE(unixSec)` and
  `SSF_RTC_READ(unixSecPtr)` macros in [`_opt/ssfrtc_opt.h`](../_opt/ssfrtc_opt.h) to map to the
  target hardware RTC driver.
- The interface is thread-safe when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1` and the
  `SSF_RTC_THREAD_SYNC_*` macros are implemented in [`_opt/ssfrtc_opt.h`](../_opt/ssfrtc_opt.h).
- The supported time range is `1970-01-01T00:00:00Z` through `2199-12-31T23:59:59Z`.

<a id="configuration"></a>

## [↑](#ssfrtc--unix-time-rtc-interface) Configuration

Options live in [`_opt/ssfrtc_opt.h`](../_opt/ssfrtc_opt.h) (aggregated into the build via `ssfoptions.h`).

| Option | Default | Description |
|--------|---------|-------------|
| <a id="opt-sim"></a>`SSF_RTC_ENABLE_SIM` | `1` | `1` to use a RAM-based simulated RTC (suitable for unit tests and platforms without hardware RTC); `0` to use real hardware via `SSF_RTC_WRITE` and `SSF_RTC_READ` macros |

<a id="api-summary"></a>

## [↑](#ssfrtc--unix-time-rtc-interface) API Summary

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`bool SSFRTCInit()`](#ssfrtcinit) | Initialize the RTC interface; reads hardware RTC and begins tick-based tracking |
| [e.g.](#ex-deinit) | [`void SSFRTCDeInit()`](#ssfrtcdeinit) | De-initialize the RTC interface |
| [e.g.](#ex-set) | [`bool SSFRTCSet(unixSec)`](#ssfrtcset) | Set the current Unix time and write to the hardware RTC |
| [e.g.](#ex-getunixnow) | [`bool SSFRTCGetUnixNow(unixSys)`](#ssfrtcgetunixnow) | Get the current Unix time in system ticks |

<a id="function-reference"></a>

## [↑](#ssfrtc--unix-time-rtc-interface) Function Reference

<a id="ssfrtcinit"></a>

### [↑](#functions) [`bool SSFRTCInit()`](#functions)

```c
bool SSFRTCInit(void);
```

Initializes the RTC interface. Reads the current time from the hardware RTC (or the simulated
RTC when [`SSF_RTC_ENABLE_SIM`](#opt-sim) is `1`) and records the corresponding system tick
value. After a successful call, `SSFRTCGetUnixNow()` derives the current time from the elapsed
tick count without re-reading hardware.

**Returns:** `true` if the RTC was read and its value is in range, so the time is valid; `false` if the read failed or the value is out of range. Either way the interface is initialized and `SSFRTCDeInit()` must precede another `SSFRTCInit()` (a second call asserts).

<a id="ex-init"></a>

**Example:**

```c
if (SSFRTCInit())
{
    /* RTC interface initialized; SSFRTCGetUnixNow() is now available */
}
```

---

<a id="ssfrtcdeinit"></a>

### [↑](#functions) [`void SSFRTCDeInit()`](#functions)

```c
void SSFRTCDeInit(void);
```

De-initializes the RTC interface, clearing its initialized state. Asserts if the interface is
not initialized. After this call `SSFRTCGetUnixNow()` and `SSFRTCSet()` must not be called (they
assert) until `SSFRTCInit()` is called again.

**Returns:** Nothing.

<a id="ex-deinit"></a>

**Example:**

```c
SSFRTCInit();
/* ... use RTC ... */
SSFRTCDeInit();
/* SSFRTCGetUnixNow() and SSFRTCSet() now assert until SSFRTCInit() is called again */
```

---

<a id="ssfrtcset"></a>

### [↑](#functions) [`bool SSFRTCSet()`](#functions)

```c
bool SSFRTCSet(uint64_t unixSec);
```

Sets the current Unix time to `unixSec` whole seconds, writes the new value to the hardware RTC,
and resets the internal tick baseline so that `SSFRTCGetUnixNow()` immediately reflects the
updated time.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `unixSec` | in | `uint64_t` | New Unix time in whole seconds since the Unix epoch (`1970-01-01T00:00:00Z`). Valid range: `0`–`7258118399` (covers up to `2199-12-31T23:59:59Z`). |

**Returns:** `true` if the hardware RTC write succeeded and internal tracking was updated; `false` if the RTC write failed or `unixSec` is out of range, after which the time is not valid until a later successful call. Asserts if the interface is not initialized.

<a id="ex-set"></a>

**Example:**

```c
SSFRTCInit();

/* Set time to 2024-03-15T10:30:45Z */
uint64_t unixSec = 1710498645ull;

if (SSFRTCSet(unixSec))
{
    /* Hardware RTC updated; SSFRTCGetUnixNow() now reflects the new time */
}
```

---

<a id="ssfrtcgetunixnow"></a>

### [↑](#functions) [`bool SSFRTCGetUnixNow()`](#functions)

```c
bool SSFRTCGetUnixNow(SSFPortTick_t *unixSys);
```

Returns the current Unix time expressed in system ticks, derived from the last RTC read plus
elapsed system ticks since that read. Does not access the hardware RTC. Divide `*unixSys` by
`SSF_TICKS_PER_SEC` to obtain whole seconds, or use directly with
[`ssfdtime`](ssfdtime.md) and [`ssfiso8601`](ssfiso8601.md) conversion functions.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `unixSys` | out | `SSFPortTick_t *` | Receives the current Unix time in system ticks. Divide by `SSF_TICKS_PER_SEC` for whole seconds. Must not be `NULL`. |

**Returns:** `true` if the time is valid; `false` if it is not (the `SSFRTCInit()` read failed or was out of range, or the last `SSFRTCSet()` failed, and no `SSFRTCSet()` has succeeded since). `*unixSys` is written either way and is meaningful only on `true`. Asserts if the interface is not initialized: never before `SSFRTCInit()` or after `SSFRTCDeInit()`.

<a id="ex-getunixnow"></a>

**Example:**

```c
SSFRTCInit();

SSFPortTick_t unixSys;

if (SSFRTCGetUnixNow(&unixSys))
{
    uint64_t unixSec = unixSys / SSF_TICKS_PER_SEC;
    /* unixSec == seconds since 1970-01-01T00:00:00Z */
}

/* Pass directly to ssfdtime / ssfiso8601 */
char iso[SSFISO8601_MAX_SIZE];
SSFRTCGetUnixNow(&unixSys);
SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0,
                    iso, sizeof(iso));
/* iso == "2024-03-15T10:30:45Z" */
```
