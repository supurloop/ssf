# Storage

[Back to ssf README](../README.md)

Non-volatile storage interfaces.

## Version Controlled Configuration Storage Interface

Most embedded systems need to read and write configuration data to non-volatile memory such as NOR flash. This cfg interface handles all the details of reliably storing versioned data to the flash and prevents redundant writes.

```
#define MY_CONFIG_ID (0u) /* 32-bit number uniquely each type of config in the system */
#define MY_CONFIG_VER_1 (1u) /* Version number 1 of my config data */
#define MY_CONFIG_VER_2 (2u) /* Version number 2 of my config data */

uint8_t myConfigData[SSF_MAX_CFG_DATA_SIZE_LIMIT]; /* Can be any arbitrary data or structure */
uint16_t myConfigDataLen;

/* Bootstrap config */
if (SSFCfgRead(myConfigData, &myConfigDataLen, sizeof(myConfigData), MY_CONFIG_ID) == MY_CONFIG_VER_1)
{
    /* Successfully read version 1 of my config data, myConfigDataLen is actual config data len */
    ...
}
if (SSFCfgRead(myConfigData, &myConfigDataLen, sizeof(myConfigData), MY_CONFIG_ID) == MY_CONFIG_VER_2)
{
    /* Successfully read version 2 of my config data, myConfigDataLen is actual config data len */
    ...
}
else
{
    /* Set my config to defaults */
    memset(myConfigData, 0, sizeof(myConfigData));
    SSFCfgWrite(myConfigData, 5, MY_CONFIG_ID, MY_CONFIG_VER_2);
}
```
