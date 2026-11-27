/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfawsprov configuration                                            */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_AWSPROV_OPT_H_INCLUDE
#define SSF_AWSPROV_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes include the NUL terminator */

/* Size of the NUL-terminated copy of one response payload, 2..65536 */
#ifndef SSF_AWSPROV_CONFIG_RX_SIZE
#define SSF_AWSPROV_CONFIG_RX_SIZE         (4096u)
#endif

/* Maximum thingName size accepted from RegisterThing, 2..129 */
#ifndef SSF_AWSPROV_CONFIG_THING_NAME_SIZE
#define SSF_AWSPROV_CONFIG_THING_NAME_SIZE (129u)
#endif

#if (SSF_AWSPROV_CONFIG_RX_SIZE < 2u) || (SSF_AWSPROV_CONFIG_RX_SIZE > 65536ul)
#error SSF_AWSPROV_CONFIG_RX_SIZE must be 2..65536.
#endif
#if (SSF_AWSPROV_CONFIG_THING_NAME_SIZE < 2u) || (SSF_AWSPROV_CONFIG_THING_NAME_SIZE > 129u)
#error SSF_AWSPROV_CONFIG_THING_NAME_SIZE must be 2..129.
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSF_AWSPROV_OPT_H_INCLUDE */
