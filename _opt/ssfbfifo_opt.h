/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfbfifo configuration                                              */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_BFIFO_OPT_H_INCLUDE
#define SSF_BFIFO_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Define the maximum fifo size. */
#define SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE (255UL)

#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY         (0u)
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255         (1u)
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1 (2u)

/* Define the allowed runtime fifo size. */
/* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_ANY allows any fifo size up to
   SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE. */
/* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255 allows only fifo sizes of 255. */
/* SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_POW2_MINUS1 allows fifo sizes that are power of 2 minus 1
   up to SSF_BFIFO_CONFIG_MAX_BFIFO_SIZE. */
#define SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE (SSF_BFIFO_CONFIG_RUNTIME_BFIFO_SIZE_255)

/* Enable or disable the multi-byte fifo interface. */
#define SSF_BFIFO_MULTI_BYTE_ENABLE                     (1u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_BFIFO_OPT_H_INCLUDE */
