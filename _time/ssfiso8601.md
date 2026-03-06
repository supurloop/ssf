# ssfiso8601 — ISO 8601 Date/Time String Interface

[SSF](../README.md) | [Time](README.md)

Converts between Unix time in system ticks and ISO 8601 extended date/time strings, with full
timezone offset support.

The supported string format is:

```
YYYY-MM-DDTHH:MM:SS[.FFF|.FFFFFF|.FFFFFFFFF][Z|+HH|+HH:MM|-HH|-HH:MM|(absent)]
```

The fractional-seconds field width is determined by `SSF_TICKS_PER_SEC` (3 digits for ms,
6 for µs, 9 for ns). This is the only SSF time interface that handles local time zones.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Examples](#examples)

<a id="dependencies"></a>

## [↑](#ssfiso8601--iso-8601-datetime-string-interface) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfoptions.h`](../ssfoptions.h)
- [`ssfdtime`](ssfdtime.md) — date/time struct used internally

<a id="notes"></a>

## [↑](#ssfiso8601--iso-8601-datetime-string-interface) Notes

- When conversion fails, [`SSF_ISO8601_ERR_STR`](#opt-err-str) is written to the output buffer
  and `false` is returned; the buffer is always null-terminated.
- Always allocate at least [`SSFISO8601_MAX_SIZE`](#const-max-size) bytes for the output buffer
  to guarantee all format combinations fit.
- When a timezone is present in the parsed string, the returned `unixSys` is adjusted to UTC.
  When no timezone is present and [`SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX`](#opt-no-zone) is `1`,
  `unixSys` is returned unadjusted and `*zoneOffsetMin` is set to
  [`SSFISO8601_INVALID_ZONE_OFFSET`](#const-invalid-zone).
- Daylight saving time is not handled automatically; adjust `zoneOffsetMin` in the application.
- `SSF_TICKS_PER_SEC` must be exactly `1000`, `1000000`, or `1000000000`.
- All date/time values are validated; out-of-range inputs return `false`.

<a id="configuration"></a>

## [↑](#ssfiso8601--iso-8601-datetime-string-interface) Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| <a id="opt-err-str"></a>`SSF_ISO8601_ERR_STR` | `"0000-00-00T00:00:00"` | String written to the output buffer when a conversion fails |
| <a id="opt-fsec-trunc"></a>`SSF_ISO8601_ALLOW_FSEC_TRUNC` | `1` | `1` to truncate fractional seconds silently when the ISO string precision exceeds the system tick precision; `0` to return `false` instead |
| <a id="opt-no-zone"></a>`SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX` | `1` | `1` to accept ISO strings that have no timezone field; `0` to return `false` for such strings |
| `SSF_ISO8601_EXHAUSTIVE_UNIT_TEST` | `0` | `1` to run an exhaustive unit test over every possible second (slow) |

<a id="api-summary"></a>

## [↑](#ssfiso8601--iso-8601-datetime-string-interface) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="const-min-size"></a>`SSFISO8601_MIN_SIZE` | Constant | `20` — minimum output buffer size; fits `YYYY-MM-DDTHH:MM:SS` with no fractional seconds and no timezone |
| <a id="const-max-size"></a>`SSFISO8601_MAX_SIZE` | Constant | `36` — maximum output buffer size; fits `YYYY-MM-DDTHH:MM:SS.FFFFFFFFF+HH:MM` (9-digit fsec, full zone) |
| <a id="const-invalid-zone"></a>`SSFISO8601_INVALID_ZONE_OFFSET` | Constant | `1441` — sentinel value written to `*zoneOffsetMin` by [`SSFISO8601ISOToUnix()`](#ssfiso8601isotounix) when no timezone field is present in the source string |
| <a id="type-ssfiso8601zone-t"></a>`SSFISO8601Zone_t` | Enum | Timezone representation for the output string; passed as `zone` to [`SSFISO8601UnixToISO()`](#ssfiso8601unixtoiso) |
| `SSF_ISO8601_ZONE_UTC` | Enum value | Append `Z` to the output string (UTC) |
| `SSF_ISO8601_ZONE_OFFSET_HH` | Enum value | Append `±HH` hour-only offset to the output string |
| `SSF_ISO8601_ZONE_OFFSET_HHMM` | Enum value | Append `±HH:MM` hour-and-minute offset to the output string |
| `SSF_ISO8601_ZONE_LOCAL` | Enum value | Omit the timezone field entirely |

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-unixtoiso) | [`SSFISO8601UnixToISO(unixSys, secPrecision, secPseudoPrecision, pseudoSecs, zone, zoneOffsetMin, outStr, outStrSize)`](#ssfiso8601unixtoiso) | Convert Unix time in system ticks to an ISO 8601 string |
| [e.g.](#ex-isotounix) | [`SSFISO8601ISOToUnix(inStr, unixSys, zoneOffsetMin)`](#ssfiso8601isotounix) | Parse an ISO 8601 string to Unix time in system ticks |

<a id="function-reference"></a>

## [↑](#ssfiso8601--iso-8601-datetime-string-interface) Function Reference

<a id="ssfiso8601unixtoiso"></a>

### [↑](#ssfiso8601--iso-8601-datetime-string-interface) [`SSFISO8601UnixToISO()`](#ex-unixtoiso)

```c
bool SSFISO8601UnixToISO(SSFPortTick_t unixSys, bool secPrecision, bool secPseudoPrecision,
                         uint16_t pseudoSecs, SSFISO8601Zone_t zone, int16_t zoneOffsetMin,
                         SSFCStrOut_t outStr, size_t outStrSize);
```

Converts a Unix time value in system ticks to a null-terminated ISO 8601 extended datetime
string. The caller controls whether fractional seconds appear and which timezone representation
is used.

The three fractional-second modes are mutually exclusive in priority order:

| `secPrecision` | `secPseudoPrecision` | Fractional-second field |
|:-:|:-:|---|
| `true` | any | Real sub-second ticks from `unixSys`, width set by `SSF_TICKS_PER_SEC` |
| `false` | `true` | `pseudoSecs` value, same field width |
| `false` | `false` | Omitted — second-level precision only |

On failure [`SSF_ISO8601_ERR_STR`](#opt-err-str) is written to `outStr` and `false` is returned.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `unixSys` | in | `SSFPortTick_t` | Unix time in system ticks. Must be within the supported range (`0`–`SSFDTIME_UNIX_EPOCH_SYS_MAX`). |
| `secPrecision` | in | `bool` | `true` to include the real sub-second fractional field derived from `unixSys`; `false` to omit or use pseudo value. |
| `secPseudoPrecision` | in | `bool` | `true` to include a fixed fractional field using `pseudoSecs` instead of the real tick sub-second. Ignored when `secPrecision` is `true`. |
| `pseudoSecs` | in | `uint16_t` | Pseudo fractional-seconds value used when `secPseudoPrecision` is `true`. Must be in range `0`–`SSF_TS_FSEC_MAX`. Ignored otherwise. |
| `zone` | in | [`SSFISO8601Zone_t`](#type-ssfiso8601zone-t) | Timezone representation: `SSF_ISO8601_ZONE_UTC` appends `Z`; `SSF_ISO8601_ZONE_OFFSET_HH` appends `±HH`; `SSF_ISO8601_ZONE_OFFSET_HHMM` appends `±HH:MM`; `SSF_ISO8601_ZONE_LOCAL` omits the timezone field. |
| `zoneOffsetMin` | in | `int16_t` | Timezone offset in minutes east of UTC. `+330` = India (+05:30), `-300` = US Eastern (−05:00). Valid range: `−1439`–`+1439`. Ignored when `zone` is `SSF_ISO8601_ZONE_UTC` or `SSF_ISO8601_ZONE_LOCAL`. |
| `outStr` | out | `char *` | Buffer receiving the null-terminated ISO 8601 string. Must not be `NULL`. |
| `outStrSize` | in | `size_t` | Allocated size of `outStr`. Must be at least [`SSFISO8601_MAX_SIZE`](#const-max-size) (`36`) to guarantee all format combinations fit. |

**Returns:** `true` if the conversion succeeded and `outStr` contains a valid ISO 8601 string; `false` if any argument is invalid or `unixSys` is out of range.

---

<a id="ssfiso8601isotounix"></a>

### [↑](#ssfiso8601--iso-8601-datetime-string-interface) [`SSFISO8601ISOToUnix()`](#ex-isotounix)

```c
bool SSFISO8601ISOToUnix(SSFCStrIn_t inStr, SSFPortTick_t *unixSys, int16_t *zoneOffsetMin);
```

Parses a null-terminated ISO 8601 extended datetime string and converts it to a Unix time value
in system ticks. All of the following optional fields are accepted:

```
YYYY-MM-DDTHH:MM:SS[.FFF|.FFFFFF|.FFFFFFFFF][Z|+HH|+HH:MM|-HH|-HH:MM|(absent)]
```

When a timezone is present, `*unixSys` is adjusted to UTC and `*zoneOffsetMin` receives the
parsed offset. When no timezone is present, behaviour is controlled by
[`SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX`](#opt-no-zone): if `1`, `*unixSys` is returned
unadjusted and `*zoneOffsetMin` is set to [`SSFISO8601_INVALID_ZONE_OFFSET`](#const-invalid-zone);
if `0`, the call returns `false`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `inStr` | in | `const char *` | Null-terminated ISO 8601 string to parse. Must not be `NULL`. |
| `unixSys` | out | `SSFPortTick_t *` | Receives the parsed Unix time in system ticks, adjusted to UTC when a timezone is present. Must not be `NULL`. |
| `zoneOffsetMin` | out | `int16_t *` | Receives the timezone offset in minutes: `0` for UTC (`Z`), the parsed signed value for `±HH`/`±HH:MM`, or [`SSFISO8601_INVALID_ZONE_OFFSET`](#const-invalid-zone) when no timezone field is present. Must not be `NULL`. |

**Returns:** `true` if parsing succeeded and `*unixSys` was set; `false` if the string is malformed, out of range, or has no timezone when [`SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX`](#opt-no-zone) is `0`.

<a id="examples"></a>

## [↑](#ssfiso8601--iso-8601-datetime-string-interface) Examples

The examples below use this Unix timestamp (ms ticks, `SSF_TICKS_PER_SEC == 1000`):

```c
/* 2024-03-15T10:30:45Z expressed in milliseconds */
SSFPortTick_t unixSys = 1710498645000ull;
char          iso[SSFISO8601_MAX_SIZE];
```

<a id="ex-unixtoiso"></a>

### [↑](#ssfiso8601--iso-8601-datetime-string-interface) [SSFISO8601UnixToISO()](#ssfiso8601unixtoiso)

```c
/* UTC, no fractional seconds */
if (SSFISO8601UnixToISO(unixSys, false, false, 0,
                        SSF_ISO8601_ZONE_UTC, 0,
                        iso, sizeof(iso)))
{
    /* iso == "2024-03-15T10:30:45Z" */
}

/* UTC, real fractional seconds from system tick (SSF_TICKS_PER_SEC == 1000) */
SSFPortTick_t unixSysFrac = 1710498645750ull; /* .750 ms sub-second */
if (SSFISO8601UnixToISO(unixSysFrac, true, false, 0,
                        SSF_ISO8601_ZONE_UTC, 0,
                        iso, sizeof(iso)))
{
    /* iso == "2024-03-15T10:30:45.750Z" */
}

/* UTC, pseudo fractional seconds (e.g. RTC only provides whole seconds) */
if (SSFISO8601UnixToISO(unixSys, false, true, 500,
                        SSF_ISO8601_ZONE_UTC, 0,
                        iso, sizeof(iso)))
{
    /* iso == "2024-03-15T10:30:45.500Z" */
}

/* Local time with +05:30 offset (India), ±HH:MM format */
if (SSFISO8601UnixToISO(unixSys, false, false, 0,
                        SSF_ISO8601_ZONE_OFFSET_HHMM, 330,
                        iso, sizeof(iso)))
{
    /* iso == "2024-03-15T16:00:45+05:30"  (10:30:45 UTC + 5h30m) */
}

/* Local time with -05:00 offset (US Eastern), ±HH format */
if (SSFISO8601UnixToISO(unixSys, false, false, 0,
                        SSF_ISO8601_ZONE_OFFSET_HH, -300,
                        iso, sizeof(iso)))
{
    /* iso == "2024-03-15T05:30:45-05" */
}

/* No timezone field */
if (SSFISO8601UnixToISO(unixSys, false, false, 0,
                        SSF_ISO8601_ZONE_LOCAL, 0,
                        iso, sizeof(iso)))
{
    /* iso == "2024-03-15T10:30:45" */
}
```

<a id="ex-isotounix"></a>

### [↑](#ssfiso8601--iso-8601-datetime-string-interface) [SSFISO8601ISOToUnix()](#ssfiso8601isotounix)

```c
SSFPortTick_t parsedUnix;
int16_t       zone;

/* UTC string — zoneOffsetMin == 0 */
if (SSFISO8601ISOToUnix("2024-03-15T10:30:45Z", &parsedUnix, &zone))
{
    /* parsedUnix == 1710498645000, zone == 0 */
}

/* UTC string with fractional seconds */
if (SSFISO8601ISOToUnix("2024-03-15T10:30:45.750Z", &parsedUnix, &zone))
{
    /* parsedUnix == 1710498645750, zone == 0 */
}

/* Offset string — unixSys returned as UTC, zoneOffsetMin carries the offset */
if (SSFISO8601ISOToUnix("2024-03-15T16:00:45+05:30", &parsedUnix, &zone))
{
    /* parsedUnix == 1710498645000 (adjusted to UTC), zone == 330 */
}

/* Negative offset */
if (SSFISO8601ISOToUnix("2024-03-15T05:30:45-05:00", &parsedUnix, &zone))
{
    /* parsedUnix == 1710498645000 (adjusted to UTC), zone == -300 */
}

/* No timezone field — requires SSF_ISO8601_ALLOW_NO_ZONE_ISO_TO_UNIX == 1 */
if (SSFISO8601ISOToUnix("2024-03-15T10:30:45", &parsedUnix, &zone))
{
    /* parsedUnix == 1710498645000 (no UTC adjustment), zone == SSFISO8601_INVALID_ZONE_OFFSET */
}

/* Round-trip: generate then parse */
SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, iso, sizeof(iso));
SSFISO8601ISOToUnix(iso, &parsedUnix, &zone);
/* parsedUnix == unixSys, zone == 0 */
```
