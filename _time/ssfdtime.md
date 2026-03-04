# ssfdtime — Date/Time Struct Conversion

[Back to Time README](README.md) | [Back to ssf README](../README.md)

Converts between Unix time in system ticks and a calendar date/time struct.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_DTIME_STRUCT_STRICT_CHECK` | `1` | `1` to detect unauthorized modifications to `SSFDTimeStruct_t` fields by application code |
| `SSF_DTIME_EXHAUSTIVE_UNIT_TEST` | `0` | `1` to run an exhaustive unit test over every possible second (slow) |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFDTimeStructInit(ts, year, month, day, hour, min, sec, fsec)` | Initialize a date/time struct from components |
| `SSFDTimeStructToUnix(ts, unixSys)` | Convert a date/time struct to Unix time in system ticks |
| `SSFDTimeUnixToStruct(unixSys, ts, tsSize)` | Convert Unix time in system ticks to a date/time struct |

## Usage

Unix time in this framework is always UTC and measured in system ticks (seconds scaled by
`SSF_TICKS_PER_SEC`, which must be 1000, 1,000,000, or 1,000,000,000).

```c
SSFDTimeStruct_t ts;
SSFPortTick_t unixSys;
SSFDTimeStruct_t tsOut;

/* Initialize from date components */
SSFDTimeStructInit(&ts, year, month, day, hour, min, sec, fsec);

/* Convert to Unix time */
SSFDTimeStructToUnix(&ts, &unixSys);

/* Convert back to struct */
SSFDTimeUnixToStruct(unixSys, &tsOut, sizeof(tsOut));
/* tsOut fields match ts fields */
```

Supported date range: `1970-01-01T00:00:00.000000000Z` — `2199-12-31T23:59:59.999999999Z`.

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- Unix time does not account for leap seconds; only leap years are handled.
- `SSF_TICKS_PER_SEC` must be 1000, 1,000,000, or 1,000,000,000.
- When `SSF_DTIME_STRUCT_STRICT_CHECK == 1`, an assertion fires if struct fields are modified
  outside of the provided API functions.
- All inputs are strictly validated; an invalid calendar date causes a function to return `false`
  or trigger an assertion.
