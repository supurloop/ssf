#!/bin/sh
gcc main.c ssfbase64.c ssfbfifo.c ssffcsum.c ssfhex.c ssfjson.c ssfbase64_ut.c ssffcsum_ut.c ssfhex_ut.c ssfport.c ssfmpool.c ssfmpool_ut.c ssfbfifo_ut.c ssfsm.c ssfsm_ut.c ssfjson_ut.c ssfll.c ssfll_ut.c ssfrs.c ssfrs_ut.c ssfcrc16.c ssfcrc16_ut.c ssfcrc32.c ssfcrc32_ut.c -lm -g -o ssf
