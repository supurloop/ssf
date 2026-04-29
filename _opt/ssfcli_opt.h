/* --------------------------------------------------------------------------------------------- */
/* Small System Framework -- ssfcli configuration                                                */
/* --------------------------------------------------------------------------------------------- */
#ifndef SSF_CLI_OPT_H_INCLUDE
#define SSF_CLI_OPT_H_INCLUDE

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of option fields supplied to a single CLI command */
#define SSF_CLI_MAX_OPTS (5u)

/* Maximum number of argument fields supplied to a single CLI command */
#define SSF_CLI_MAX_ARGS (5u)

/* Maximum size of CLI's command line string, including NULL terminator */
#define SSF_CLI_MAX_CMD_LINE_SIZE (80u)

/* Maximum number of cmds that can be registered in the CLI */
#define SSF_CLI_MAX_CMDS (10u)

/* Maximum number of cmds in the CLI history buffer */
#define SSF_CLI_MAX_CMD_HIST (6u)

#ifdef __cplusplus
}
#endif

#endif /* SSF_CLI_OPT_H_INCLUDE */
