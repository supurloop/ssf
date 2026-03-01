# Time

[Back to ssf README](../README.md)

Time management interfaces.

## Unix Time RTC Interface

This interface keeps Unix time, as initialized from an RTC, by using the system tick counter. When time is changed, the RTC is written to keep it in sync.

Since many embedded systems use I2C RTC devices, accessing the RTC everytime Unix time is required is time-intensive. This interface eliminates all unnecessary RTC reads.

```
    /* Reads the RTC and tracks Unix time based on the system tick */
    SSFRTCInit();

    while (true)
    {
        SSFPortTick_t unixSys;
        uint64_t newUnixSec;

        /* Returns Unix time in system ticks */
        SSF_ASSERT(SSFRTCGetUnixNow(&unixSys));
        /* unixSys / SSF_TICKS_PER_SEC == Seconds since Unix Epoch */

        if (NTPUpdated(&newUnixSec))
        {
            /* NTP returned a new seconds since Unix Epoch */
            SSFRTCSet(newUnixSec);
            /* ...RTC has been written with new time */
        }
    }
```

## Date Time Interface

This interface converts Unix time in system ticks into a date time struct and vice versa.

```
    /* Supported date range: 1970-01-01T00:00:00.000000000Z - 2199-12-31T23:59:59.999999999Z         */
    /* Unix time is measured in system ticks (unixSys is seconds scaled by SSF_TICKS_PER_SEC)        */
    /* Unix time is always UTC (Z) time zone, other zones are handled by the ssfios8601 interface.   */
    /* Unix time does not account for leap seconds, it only accounts for leap years.                 */
    /* It is assumed that the RTC is periodically updated from an external time source, such as NTP. */
    /* Inputs are strictly checked to ensure they represent valid calendar dates.                    */
    /* System ticks (SSF_TICKS_PER_SEC) must be 1000, 1000000, or 1000000000.                        */

    SSFDTimeStruct_t ts;
    SSFPortTick_t unixSys;
    SSFDTimeStruct_t tsOut;

    /* Initialize a date time struct from basic date information */
    SSFDTimeStructInit(&ts, year, month, day, hour, min, sec, fsec);

    /* Convert the date time struct to Unix time in system ticks */
    SSFDTimeStructToUnix(&ts, &unixSys);
    /* unixSys == system ticks since epoch for year/month/day hour/min/sec/fsec */

    /* Convert unixSys back to a date time struct */
    SSFDTimeUnixToStruct(unixSys, &tsOut, sizeof(tsOut));
    /* tsOut struct fields == ts struct fields */
```

## ISO8601 Date Time Interface

This interface converts Unix time in system ticks into an ISO8601 extended date time string and vice versa. This is the only time interface in the framework that handles "local time".

```
    /* Supported date range: 1970-01-01T00:00:00.000000000Z - 2199-12-31T23:59:59.999999999Z         */
    /* Unix time is measured in system ticks (unixSys is seconds is scaled by SSF_TICKS_PER_SEC)     */
    /* Unix time is always UTC (Z) time zone.                                                        */
    /* Inputs are strictly checked to ensure they represent valid calendar dates.                    */
    /*                                                                                               */
    /* Only ISO8601 extended format is supported, and only with the following ordered fields:        */
    /*   Required Date & Time Field:      YYYY-MM-DDTHH:MM:SS                                        */
    /*   Optional Second Precision Field:                    .FFF                                    */
    /*                                                       .FFFFFF                                 */
    /*                                                       .FFFFFFFFF                              */
    /*   Optional Time Zone Field :                                    Z                             */
    /*                                                                 +HH                           */
    /*                                                                 -HH                           */
    /*                                                                 +HH:MM                        */
    /*                                                                 -HH:MM                        */
    /*                                                                 (no TZ field == local time)   */
    /*                                                                                               */
    /* The Date and Time field is always in local time, subtracting offset yields UTC time.          */
    /* The default fractional second precision is determined by SSF_TICKS_PER_SEC.                   */
    /* Fractional seconds may be optionally added when generating an ISO string.                     */
    /* 3 digits of pseudo-fractional seconds precision may be added when generating an ISO string.   */
    /* Daylight savings is handled by application code adjusting the zoneOffsetMin input as needed.  */

    SSFPortTick_t unixSys;
    SSFPortTick_t unixSysOut;
    int16_t zoneOffsetMin;
    char isoStr[SSFISO8601_MAX_SIZE];

    SSF_ASSERT(SSFRTCGetUnixNow(&unixSys));
    SSFISO8601UnixToISO(unixSys, false, false, 0, SSF_ISO8601_ZONE_UTC, 0, isoStr, sizeof(isoStr));
    /* isoStr looks something like "2022-11-23T13:00:12Z" */

    SSFISO8601ISOToUnix(isoStr, &unixSysOut, &zoneOffsetMin);
    /* unixSys == unixSysOut, zoneOffsetMin == 0 */
```
