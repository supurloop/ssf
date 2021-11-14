#!/bin/sh
gcc main.c ssfbase64.c ssfbfifo.c ssffcsum.c ssfhex.c ssfjson.c ssfbase64_ut.c ssffcsum_ut.c ssfhex_ut.c ssfport.c ssfmpool.c ssfmpool_ut.c ssfbfifo_ut.c ssfsm.c ssfsm_ut.c ssfjson_ut.c ssfll.c ssfll_ut.c ssfrs.c ssfrs_ut.c ssfcrc16.c ssfcrc16_ut.c ssfcrc32.c ssfcrc32_ut.c ssfsha2.c ssfsha2_ut.c ssftlv.c ssftlv_ut.c ssfaes.c ssfaes_ut.c ssfaesgcm.c ssfaesgcm_ut.c -Wall -Wextra -pedantic -Wcast-align -Wno-parentheses -Wno-unused -Wdisabled-optimization -fdiagnostics-show-option -Wstrict-overflow=5 -Wformat=2 -lm -g -o ssf