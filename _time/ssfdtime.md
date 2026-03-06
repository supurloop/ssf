# ssfdtime — Date/Time Struct Conversion

[SSF](../README.md) | [Time](README.md)

Converts between Unix time in system ticks and a calendar date/time struct.

All time values are UTC. System ticks are whole seconds scaled by `SSF_TICKS_PER_SEC`
(milliseconds, microseconds, or nanoseconds depending on the port). The supported date range is
`1970-01-01T00:00:00Z` through `2199-12-31T23:59:59Z`.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Examples](#examples)

<a id="dependencies"></a>

## [↑](#ssfdtime--datetime-struct-conversion) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfoptions.h`](../ssfoptions.h)

<a id="notes"></a>

## [↑](#ssfdtime--datetime-struct-conversion) Notes

- All `SSFDTimeStruct_t` fields use **0-based offsets**: `year` is offset from 1970; `month` is
  0 for January through 11 for December; `day` is 0 for the 1st of the month.
- [`SSFDTimeIsLeapYear()`](#ssfdtimeisleapyear) and [`SSFDTimeDaysInMonth()`](#ssfdtimedaysinmonth)
  take the **full calendar year** (e.g., `2024`), not the 0-based year offset.
- The `wday` and `yday` fields of `SSFDTimeStruct_t` are computed automatically by
  [`SSFDTimeStructInit()`](#ssfdtimestructinit) and [`SSFDTimeUnixToStruct()`](#ssfdtimeunixtostruct);
  do not set them directly.
- When [`SSF_DTIME_STRUCT_STRICT_CHECK`](#opt-strict-check) is `1`, an assertion fires if any
  struct field is modified outside of the provided API functions.
- Unix time in this framework does not account for leap seconds; only leap years are handled.
- `SSF_TICKS_PER_SEC` must be exactly `1000`, `1000000`, or `1000000000`.

<a id="configuration"></a>

## [↑](#ssfdtime--datetime-struct-conversion) Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| <a id="opt-strict-check"></a>`SSF_DTIME_STRUCT_STRICT_CHECK` | `1` | `1` to detect unauthorised direct modifications to `SSFDTimeStruct_t` fields |
| `SSF_DTIME_EXHAUSTIVE_UNIT_TEST` | `0` | `1` to run an exhaustive unit test over every possible second (slow) |

<a id="api-summary"></a>

## [↑](#ssfdtime--datetime-struct-conversion) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssfdtimestruct-t"></a>`SSFDTimeStruct_t` | Struct | Calendar date/time. Fields are 0-based (see Notes). Read fields freely; write only through API functions |
| `SSFDTimeStruct_t.fsec` | Field | Fractional seconds in system tick units; range `0`–[`SSF_TS_FSEC_MAX`](#const-fsec-max) |
| `SSFDTimeStruct_t.sec` | Field | Second of minute; range `0`–`59` |
| `SSFDTimeStruct_t.min` | Field | Minute of hour; range `0`–`59` |
| `SSFDTimeStruct_t.hour` | Field | Hour of day; range `0`–`23` |
| `SSFDTimeStruct_t.day` | Field | Day of month, 0-based (`0` = 1st); range `0`–`30` |
| `SSFDTimeStruct_t.month` | Field | Month, 0-based (`0` = January); range `0`–`11`; compare with [`SSFDTimeStructMonth_t`](#type-ssfdtimestructmonth-t) |
| `SSFDTimeStruct_t.year` | Field | Year offset from 1970 (`0` = 1970); range `0`–`229`; add `1970` for calendar year |
| `SSFDTimeStruct_t.wday` | Field | Day of week; compare with [`SSFDTimeStructWday_t`](#type-ssfdtimestructwday-t) — computed automatically |
| `SSFDTimeStruct_t.yday` | Field | Day of year, 0-based (`0` = Jan 1st); `0`–`364` (non-leap) or `0`–`365` (leap) — computed automatically |
| <a id="type-ssfdtimestructwday-t"></a>`SSFDTimeStructWday_t` | Enum | Day-of-week constants for `SSFDTimeStruct_t.wday` |
| `SSF_DTIME_WDAY_SUN` | Enum value | Sunday (`0`) |
| `SSF_DTIME_WDAY_MON` | Enum value | Monday (`1`) |
| `SSF_DTIME_WDAY_TUE` | Enum value | Tuesday (`2`) |
| `SSF_DTIME_WDAY_WED` | Enum value | Wednesday (`3`) |
| `SSF_DTIME_WDAY_THU` | Enum value | Thursday (`4`) |
| `SSF_DTIME_WDAY_FRI` | Enum value | Friday (`5`) |
| `SSF_DTIME_WDAY_SAT` | Enum value | Saturday (`6`) |
| <a id="type-ssfdtimestructmonth-t"></a>`SSFDTimeStructMonth_t` | Enum | Month constants for `SSFDTimeStruct_t.month` and [`SSFDTimeDaysInMonth()`](#ssfdtimedaysinmonth) |
| `SSF_DTIME_MONTH_JAN` | Enum value | January (`0`) |
| `SSF_DTIME_MONTH_FEB` | Enum value | February (`1`) |
| `SSF_DTIME_MONTH_MAR` | Enum value | March (`2`) |
| `SSF_DTIME_MONTH_APR` | Enum value | April (`3`) |
| `SSF_DTIME_MONTH_MAY` | Enum value | May (`4`) |
| `SSF_DTIME_MONTH_JUN` | Enum value | June (`5`) |
| `SSF_DTIME_MONTH_JUL` | Enum value | July (`6`) |
| `SSF_DTIME_MONTH_AUG` | Enum value | August (`7`) |
| `SSF_DTIME_MONTH_SEP` | Enum value | September (`8`) |
| `SSF_DTIME_MONTH_OCT` | Enum value | October (`9`) |
| `SSF_DTIME_MONTH_NOV` | Enum value | November (`10`) |
| `SSF_DTIME_MONTH_DEC` | Enum value | December (`11`) |
| <a id="const-fsec-max"></a>`SSF_TS_FSEC_MAX` | Constant | Maximum fractional-seconds value: `999` (ms), `999999` (µs), or `999999999` (ns), depending on `SSF_TICKS_PER_SEC` |
| `SSFDTIME_UNIX_EPOCH_SYS_MAX` | Constant | Maximum valid `unixSys` tick value, corresponding to `2199-12-31T23:59:59Z` plus `SSF_TS_FSEC_MAX` sub-second ticks |
| `SSF_TS_YEAR_MAX` | Constant | Maximum year offset from 1970 accepted by [`SSFDTimeStructInit()`](#ssfdtimestructinit): `229` (= year 2199) |

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-structinit) | [`SSFDTimeStructInit(ts, year, month, day, hour, min, sec, fsec)`](#ssfdtimestructinit) | Initialize a date/time struct from calendar components |
| [e.g.](#ex-unixtostruct) | [`SSFDTimeUnixToStruct(unixSys, ts, tsSize)`](#ssfdtimeunixtostruct) | Convert Unix time in system ticks to a date/time struct |
| [e.g.](#ex-structtounix) | [`SSFDTimeStructToUnix(ts, unixSys)`](#ssfdtimestructtounix) | Convert a date/time struct to Unix time in system ticks |
| [e.g.](#ex-isleapyear) | [`SSFDTimeIsLeapYear(year)`](#ssfdtimeisleapyear) | Return true if a calendar year is a leap year |
| [e.g.](#ex-daysinmonth) | [`SSFDTimeDaysInMonth(year, month)`](#ssfdtimedaysinmonth) | Return the number of days in a given month |

<a id="function-reference"></a>

## [↑](#ssfdtime--datetime-struct-conversion) Function Reference

<a id="ssfdtimestructinit"></a>

### [↑](#ssfdtime--datetime-struct-conversion) [`SSFDTimeStructInit()`](#ex-structinit)

```c
bool SSFDTimeStructInit(SSFDTimeStruct_t *ts, uint16_t year, uint8_t month, uint8_t day,
                        uint8_t hour, uint8_t min, uint8_t sec, uint32_t fsec);
```

Initializes an `SSFDTimeStruct_t` from individual calendar components after validating every
field. The derived fields `wday` (day of week) and `yday` (day of year) are computed and set
automatically. All calendar fields use 0-based offsets: `year` is offset from 1970, `month`
from January, and `day` from the 1st of the month.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ts` | out | [`SSFDTimeStruct_t *`](#type-ssfdtimestruct-t) | Pointer to the struct to initialize. Must not be `NULL`. |
| `year` | in | `uint16_t` | Year offset from 1970. `0` = 1970, `54` = 2024. Valid range: `0`–[`SSF_TS_YEAR_MAX`](#const-fsec-max) (`229`). |
| `month` | in | `uint8_t` | Month, 0-based. `0` = January, `11` = December. Use [`SSFDTimeStructMonth_t`](#type-ssfdtimestructmonth-t) constants. Valid range: `0`–`11`. |
| `day` | in | `uint8_t` | Day of month, 0-based. `0` = 1st, `30` = 31st. Valid range: `0`–27/28/29/30 depending on month and year. |
| `hour` | in | `uint8_t` | Hour of day. Valid range: `0`–`23`. |
| `min` | in | `uint8_t` | Minute of hour. Valid range: `0`–`59`. |
| `sec` | in | `uint8_t` | Second of minute. Valid range: `0`–`59`. |
| `fsec` | in | `uint32_t` | Fractional seconds in system tick units. Valid range: `0`–[`SSF_TS_FSEC_MAX`](#const-fsec-max). |

**Returns:** `true` if all components are valid and the struct was initialized; `false` if any component is out of range.

---

<a id="ssfdtimeunixtostruct"></a>

### [↑](#ssfdtime--datetime-struct-conversion) [`SSFDTimeUnixToStruct()`](#ex-unixtostruct)

```c
bool SSFDTimeUnixToStruct(SSFPortTick_t unixSys, SSFDTimeStruct_t *ts, size_t tsSize);
```

Converts a Unix time value expressed in system ticks to a fully-populated calendar date/time
struct, including `wday`, `yday`, and `fsec`. The `unixSys` value encodes whole seconds in its
upper portion and sub-second ticks in its lower portion, as determined by `SSF_TICKS_PER_SEC`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `unixSys` | in | `SSFPortTick_t` | Unix time in system ticks. Valid range: `0` (= `1970-01-01T00:00:00Z`) to `SSFDTIME_UNIX_EPOCH_SYS_MAX` (= `2199-12-31T23:59:59Z` + max fsec). |
| `ts` | out | [`SSFDTimeStruct_t *`](#type-ssfdtimestruct-t) | Pointer to the struct to fill. Must not be `NULL`. |
| `tsSize` | in | `size_t` | Must be `sizeof(SSFDTimeStruct_t)`. Guards against struct-size mismatches across compilation units. |

**Returns:** `true` if the conversion succeeded and `*ts` was populated; `false` if `unixSys` is outside the supported range.

---

<a id="ssfdtimestructtounix"></a>

### [↑](#ssfdtime--datetime-struct-conversion) [`SSFDTimeStructToUnix()`](#ex-structtounix)

```c
bool SSFDTimeStructToUnix(const SSFDTimeStruct_t *ts, SSFPortTick_t *unixSys);
```

Converts a previously initialized `SSFDTimeStruct_t` to a Unix time value in system ticks. The
struct must have been populated by [`SSFDTimeStructInit()`](#ssfdtimestructinit) or
[`SSFDTimeUnixToStruct()`](#ssfdtimeunixtostruct); direct field writes are detected as invalid
when [`SSF_DTIME_STRUCT_STRICT_CHECK`](#opt-strict-check) is `1`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ts` | in | [`const SSFDTimeStruct_t *`](#type-ssfdtimestruct-t) | Pointer to a valid, API-initialized date/time struct. Must not be `NULL`. |
| `unixSys` | out | `SSFPortTick_t *` | Receives the Unix time in system ticks. Must not be `NULL`. |

**Returns:** `true` if the conversion succeeded and `*unixSys` was set; `false` if the struct is invalid or the encoded date is out of range.

---

<a id="ssfdtimeisleapyear"></a>

### [↑](#ssfdtime--datetime-struct-conversion) [`SSFDTimeIsLeapYear()`](#ex-isleapyear)

```c
bool SSFDTimeIsLeapYear(uint16_t year);
```

Determines whether a calendar year is a leap year using the Gregorian algorithm: divisible by 4,
except century years unless also divisible by 400. Takes the **full calendar year**, not the
0-based year offset stored in `SSFDTimeStruct_t`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `year` | in | `uint16_t` | Full calendar year (e.g., `2024`). Not the 0-based offset from 1970. |

**Returns:** `true` if `year` is a leap year; `false` otherwise.

---

<a id="ssfdtimedaysinmonth"></a>

### [↑](#ssfdtime--datetime-struct-conversion) [`SSFDTimeDaysInMonth()`](#ex-daysinmonth)

```c
uint8_t SSFDTimeDaysInMonth(uint16_t year, uint8_t month);
```

Returns the number of days in the specified month of the given year, correctly handling February
in leap years. Takes the **full calendar year** and a **0-based month**.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `year` | in | `uint16_t` | Full calendar year (e.g., `2024`). Used to determine leap year status for February. |
| `month` | in | `uint8_t` | Month, 0-based (`0` = January, `11` = December). Use [`SSFDTimeStructMonth_t`](#type-ssfdtimestructmonth-t) constants. |

**Returns:** Number of days in the month: `28`, `29`, `30`, or `31`.

<a id="examples"></a>

## [↑](#ssfdtime--datetime-struct-conversion) Examples

<a id="ex-structinit"></a>

### [↑](#ssfdtime--datetime-struct-conversion) [SSFDTimeStructInit()](#ssfdtimestructinit)

```c
SSFDTimeStruct_t ts;

/* 2024-03-15T10:30:45Z */
/* year = 2024 - 1970 = 54; month = SSF_DTIME_MONTH_MAR (2, 0-based); day = 14 (15th, 0-based) */
if (SSFDTimeStructInit(&ts, 54, SSF_DTIME_MONTH_MAR, 14, 10, 30, 45, 0))
{
    /* ts.year == 54, ts.month == 2, ts.day == 14 */
    /* ts.hour == 10, ts.min == 30, ts.sec == 45, ts.fsec == 0 */
    /* ts.wday and ts.yday computed automatically */
}

/* Invalid: month 12 is out of range (valid 0-11) */
if (SSFDTimeStructInit(&ts, 54, 12, 0, 0, 0, 0, 0) == false)
{
    /* Initialization rejected */
}
```

<a id="ex-unixtostruct"></a>

### [↑](#ssfdtime--datetime-struct-conversion) [SSFDTimeUnixToStruct()](#ssfdtimeunixtostruct)

```c
SSFDTimeStruct_t ts;

/* Unix timestamp for 2024-03-15T10:30:45Z in milliseconds (SSF_TICKS_PER_SEC == 1000) */
SSFPortTick_t unixSys = 1710498645000ull;

if (SSFDTimeUnixToStruct(unixSys, &ts, sizeof(ts)))
{
    /* ts.year == 54 (2024), ts.month == 2 (March), ts.day == 14 (15th) */
    /* ts.hour == 10, ts.min == 30, ts.sec == 45, ts.fsec == 0 */
    /* ts.wday == SSF_DTIME_WDAY_FRI, ts.yday == 74 */
}

/* Epoch origin: unixSys == 0 -> 1970-01-01T00:00:00Z */
if (SSFDTimeUnixToStruct(0, &ts, sizeof(ts)))
{
    /* ts.year == 0, ts.month == 0, ts.day == 0 */
    /* ts.wday == SSF_DTIME_WDAY_THU */
}
```

<a id="ex-structtounix"></a>

### [↑](#ssfdtime--datetime-struct-conversion) [SSFDTimeStructToUnix()](#ssfdtimestructtounix)

```c
SSFDTimeStruct_t ts;
SSFPortTick_t    unixSys;

SSFDTimeStructInit(&ts, 54, SSF_DTIME_MONTH_MAR, 14, 10, 30, 45, 0);

if (SSFDTimeStructToUnix(&ts, &unixSys))
{
    /* unixSys == 1710498645000 (ms ticks when SSF_TICKS_PER_SEC == 1000) */
}

/* Round-trip: convert to Unix then back to struct */
SSFDTimeStruct_t ts2;
SSFDTimeUnixToStruct(unixSys, &ts2, sizeof(ts2));
/* ts2 fields are identical to ts fields */
```

<a id="ex-isleapyear"></a>

### [↑](#ssfdtime--datetime-struct-conversion) [SSFDTimeIsLeapYear()](#ssfdtimeisleapyear)

```c
/* Takes the full calendar year — NOT the 0-based year offset */
SSFDTimeIsLeapYear(2024);   /* returns true  — divisible by 4 */
SSFDTimeIsLeapYear(2023);   /* returns false */
SSFDTimeIsLeapYear(2100);   /* returns false — century year, not divisible by 400 */
SSFDTimeIsLeapYear(2000);   /* returns true  — divisible by 400 */

/* Accessing the calendar year from a struct */
SSFDTimeStruct_t ts;
SSFDTimeStructInit(&ts, 54, SSF_DTIME_MONTH_JAN, 0, 0, 0, 0, 0);
SSFDTimeIsLeapYear((uint16_t)(1970u + ts.year));   /* returns true (2024) */
```

<a id="ex-daysinmonth"></a>

### [↑](#ssfdtime--datetime-struct-conversion) [SSFDTimeDaysInMonth()](#ssfdtimedaysinmonth)

```c
/* Takes the full calendar year and a 0-based month */
SSFDTimeDaysInMonth(2024, SSF_DTIME_MONTH_FEB);   /* returns 29 — leap year */
SSFDTimeDaysInMonth(2023, SSF_DTIME_MONTH_FEB);   /* returns 28 */
SSFDTimeDaysInMonth(2024, SSF_DTIME_MONTH_JAN);   /* returns 31 */
SSFDTimeDaysInMonth(2024, SSF_DTIME_MONTH_APR);   /* returns 30 */

/* Using a struct's calendar year to find days remaining in the current month */
SSFDTimeStruct_t ts;
SSFDTimeStructInit(&ts, 54, SSF_DTIME_MONTH_MAR, 14, 0, 0, 0, 0);
uint8_t daysLeft = SSFDTimeDaysInMonth((uint16_t)(1970u + ts.year), ts.month) - ts.day - 1u;
/* daysLeft == 16 (days after the 15th in March 2024) */
```
