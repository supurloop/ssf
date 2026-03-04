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
| `SSFDTimeStructInit(ts, year, month, day, hour, min, sec, fsec)` | Initialize a date/time struct from calendar components |
| `SSFDTimeUnixToStruct(unixSys, ts, tsSize)` | Convert Unix time in system ticks to a date/time struct |
| `SSFDTimeStructToUnix(ts, unixSys)` | Convert a date/time struct to Unix time in system ticks |
| `SSFDTimeIsLeapYear(year)` | Returns true if the given year is a leap year |
| `SSFDTimeDaysInMonth(year, month)` | Returns the number of days in the given month |

## Function Reference

### `SSFDTimeStructInit`

```c
bool SSFDTimeStructInit(SSFDTimeStruct_t *ts, uint16_t year, uint8_t month, uint8_t day,
                        uint8_t hour, uint8_t min, uint8_t sec, uint32_t fsec);
```

Initializes an `SSFDTimeStruct_t` from individual calendar components. All fields are validated
before being written. The `wday` (day of week) and `yday` (day of year) fields are computed and
set automatically.

Note: all fields use **0-based offsets** where applicable. `year` is the offset from 1970;
`month` is 0 for January through 11 for December; `day` is 0 for the 1st of the month.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ts` | out | `SSFDTimeStruct_t *` | Pointer to the struct to initialize. Must not be `NULL`. |
| `year` | in | `uint16_t` | Year offset from 1970. Valid range: 0 (= year 1970) to 229 (= year 2199). |
| `month` | in | `uint8_t` | Month (0-based). `0` = January, `11` = December. Valid range: 0–11. |
| `day` | in | `uint8_t` | Day of month (0-based). `0` = 1st. Valid range: 0–27/28/29/30 depending on month and year. |
| `hour` | in | `uint8_t` | Hour of day. Valid range: 0–23. |
| `min` | in | `uint8_t` | Minute of hour. Valid range: 0–59. |
| `sec` | in | `uint8_t` | Second of minute. Valid range: 0–59. |
| `fsec` | in | `uint32_t` | Fractional seconds in system tick units. Valid range: 0–`SSF_TS_FSEC_MAX` (999 for ms, 999999 for µs, 999999999 for ns precision). |

**Returns:** `true` if all components are valid and the struct was initialized; `false` if any component is out of range.

---

### `SSFDTimeUnixToStruct`

```c
bool SSFDTimeUnixToStruct(SSFPortTick_t unixSys, SSFDTimeStruct_t *ts, size_t tsSize);
```

Converts a Unix time value expressed in system ticks to a calendar date/time struct. The tick
value encodes both whole seconds and sub-second precision; the result struct includes all fields
including `wday`, `yday`, and `fsec`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `unixSys` | in | `SSFPortTick_t` | Unix time in system ticks. Valid range: 0 to `SSFDTIME_UNIX_EPOCH_SYS_MAX` (covers 1970-01-01 through 2199-12-31). |
| `ts` | out | `SSFDTimeStruct_t *` | Pointer to the struct to fill. Must not be `NULL`. |
| `tsSize` | in | `size_t` | `sizeof(SSFDTimeStruct_t)`. Used to detect struct size mismatches across compilation units. |

**Returns:** `true` if the conversion succeeded; `false` if `unixSys` is outside the supported range.

---

### `SSFDTimeStructToUnix`

```c
bool SSFDTimeStructToUnix(const SSFDTimeStruct_t *ts, SSFPortTick_t *unixSys);
```

Converts a previously initialized `SSFDTimeStruct_t` to a Unix time value in system ticks.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ts` | in | `const SSFDTimeStruct_t *` | Pointer to a valid, initialized date/time struct. Must not be `NULL`. Must have been initialized by `SSFDTimeStructInit` or `SSFDTimeUnixToStruct` (not modified directly by the application). |
| `unixSys` | out | `SSFPortTick_t *` | Receives the Unix time in system ticks. Must not be `NULL`. |

**Returns:** `true` if the conversion succeeded; `false` if the struct is invalid or the date is out of range.

---

### `SSFDTimeIsLeapYear`

```c
bool SSFDTimeIsLeapYear(uint16_t year);
```

Determines whether a calendar year is a leap year using the standard Gregorian algorithm
(divisible by 4, except centuries unless also divisible by 400).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `year` | in | `uint16_t` | The full calendar year (e.g., `2024`), not an offset. Valid range: any year representable by `uint16_t`. |

**Returns:** `true` if `year` is a leap year; `false` otherwise.

---

### `SSFDTimeDaysInMonth`

```c
uint8_t SSFDTimeDaysInMonth(uint16_t year, uint8_t month);
```

Returns the number of days in the specified month of the given year, accounting for leap years
in February.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `year` | in | `uint16_t` | Full calendar year (e.g., `2024`). Used to determine leap year status for February. |
| `month` | in | `uint8_t` | Month (0-based). `0` = January through `11` = December. |

**Returns:** Number of days in the month: 28, 29, 30, or 31.

## Usage

Unix time in this framework is always UTC and measured in system ticks (seconds scaled by
`SSF_TICKS_PER_SEC`, which must be 1000, 1,000,000, or 1,000,000,000).

```c
SSFDTimeStruct_t ts;
SSFPortTick_t unixSys;
SSFDTimeStruct_t tsOut;

/* Initialize from date components (2024-03-15T10:30:00.000Z) */
/* year=54 (2024-1970), month=2 (March, 0-based), day=14 (15th, 0-based) */
SSFDTimeStructInit(&ts, 54, 2, 14, 10, 30, 0, 0);

/* Convert to Unix time */
SSFDTimeStructToUnix(&ts, &unixSys);

/* Convert back to struct */
SSFDTimeUnixToStruct(unixSys, &tsOut, sizeof(tsOut));
/* tsOut fields match ts fields */

/* Leap year queries */
SSFDTimeIsLeapYear(2024);  /* returns true */
SSFDTimeIsLeapYear(2023);  /* returns false */

/* Days in month */
SSFDTimeDaysInMonth(2024, 1);  /* returns 29 (Feb 2024, leap year) */
SSFDTimeDaysInMonth(2023, 1);  /* returns 28 (Feb 2023) */
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
- All date/time fields in `SSFDTimeStruct_t` use **0-based offsets**: year from 1970, month
  from January, day from the 1st of the month.
