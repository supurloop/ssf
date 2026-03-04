# ssfrtc — Unix Time RTC Interface

[Back to Time README](README.md) | [Back to ssf README](../README.md)

Tracks Unix time by combining a hardware RTC read at startup with the system tick counter,
eliminating repeated RTC accesses.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_RTC_ENABLE_SIM` | `1` | `1` to use a RAM-simulated RTC (for unit tests and platforms without hardware RTC); `0` to map `SSF_RTC_WRITE` and `SSF_RTC_READ` to real hardware functions |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFRTCInit()` | Initialize the RTC; reads hardware RTC and begins tick-based tracking |
| `SSFRTCDeInit()` | De-initialize the RTC interface |
| `SSFRTCSet(unixSec)` | Set the current Unix time (seconds) and write to hardware RTC |
| `SSFRTCGetUnixNow(unixSys)` | Get current Unix time in system ticks |

## Function Reference

### `SSFRTCInit`

```c
bool SSFRTCInit(void);
```

Initializes the RTC interface. Reads the current time from the hardware RTC (or simulated RTC when
`SSF_RTC_ENABLE_SIM == 1`) and records it together with the current system tick count. Subsequent
calls to `SSFRTCGetUnixNow()` derive the current time from the tick counter without re-reading the
hardware.

**Returns:** `true` if the RTC was successfully read and the interface initialized; `false` if the
RTC read failed.

---

### `SSFRTCDeInit`

```c
void SSFRTCDeInit(void);
```

De-initializes the RTC interface, releasing its initialized state. Called primarily in unit test
teardown scenarios. No parameters. No return value.

---

### `SSFRTCSet`

```c
bool SSFRTCSet(uint64_t unixSec);
```

Sets the current Unix time and writes the new value to the hardware RTC. Also updates the
internal tick-based tracking so that `SSFRTCGetUnixNow()` immediately reflects the new time.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `unixSec` | in | `uint64_t` | New Unix time in whole seconds since the Unix epoch (1970-01-01T00:00:00Z). Valid range: 0 – 7258118399 (covers up to 2199-12-31T23:59:59Z). |

**Returns:** `true` if the hardware RTC write succeeded and the interface was updated; `false` if the RTC write failed.

---

### `SSFRTCGetUnixNow`

```c
bool SSFRTCGetUnixNow(SSFPortTick_t *unixSys);
```

Returns the current Unix time in system ticks (`SSFPortTick_t`), derived from the last RTC read
plus elapsed system ticks since that read. Does not access the hardware RTC.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `unixSys` | out | `SSFPortTick_t *` | Receives the current Unix time expressed in system ticks. Divide by `SSF_TICKS_PER_SEC` to obtain whole seconds. Must not be `NULL`. |

**Returns:** `true` if the interface is initialized and the time was written; `false` if the
interface has not been initialized.

## Usage

Many embedded systems use I2C RTC devices that are slow to query. This interface reads the RTC
once at initialization and tracks elapsed time using the faster system tick counter. When the
time is updated (e.g., by NTP), `SSFRTCSet()` writes through to the hardware RTC.

```c
SSFRTCInit();

while (true)
{
    SSFPortTick_t unixSys;
    uint64_t newUnixSec;

    SSF_ASSERT(SSFRTCGetUnixNow(&unixSys));
    /* unixSys / SSF_TICKS_PER_SEC == seconds since Unix epoch */

    if (NTPUpdated(&newUnixSec))
    {
        SSFRTCSet(newUnixSec);
        /* RTC has been updated with the new time */
    }
}
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- When `SSF_RTC_ENABLE_SIM == 0`, implement `SSF_RTC_WRITE(unixSec)` and
  `SSF_RTC_READ(unixSec)` macros in `ssfoptions.h` to map to your hardware RTC driver.
- The RTC interface is thread-safe when `SSF_CONFIG_ENABLE_THREAD_SUPPORT == 1` and the
  `SSF_RTC_THREAD_SYNC_*` macros are implemented.
- `SSFRTCGetUnixNow()` returns time in system ticks (not raw seconds); divide by
  `SSF_TICKS_PER_SEC` to get seconds.
