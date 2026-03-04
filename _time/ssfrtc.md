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
| `SSFRTCGetUnixNow(unixSys)` | Get current Unix time in system ticks |
| `SSFRTCSet(unixSec)` | Set the current Unix time (seconds) and write to hardware RTC |

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
