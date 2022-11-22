#!/bin/sh
gcc main.c _codec/ssfbase64.c _struct/ssfbfifo.c _edc/ssffcsum.c _codec/ssfhex.c _codec/ssfjson.c _codec/ssfbase64_ut.c _edc/ssffcsum_ut.c _codec/ssfhex_ut.c ssfport.c _struct/ssfmpool.c _struct/ssfmpool_ut.c _struct/ssfbfifo_ut.c _fsm/ssfsm.c _fsm/ssfsm_ut.c _codec/ssfjson_ut.c _struct/ssfll.c _struct/ssfll_ut.c _ecc/ssfrs.c _ecc/ssfrs_ut.c _edc/ssfcrc16.c _edc/ssfcrc16_ut.c _edc/ssfcrc32.c _edc/ssfcrc32_ut.c _crypto/ssfsha2.c _crypto/ssfsha2_ut.c _codec/ssftlv.c _codec/ssftlv_ut.c _crypto/ssfaes.c _crypto/ssfaes_ut.c _crypto/ssfaesgcm.c _crypto/ssfaesgcm_ut.c _storage/ssfcfg.c _storage/ssfcfg_ut.c _crypto/ssfprng.c _crypto/ssfprng_ut.c _codec/ssfini.c _codec/ssfini_ut.c _codec/ssfubjson.c _codec/ssfubjson_ut.c _time/ssfdtime.c _time/ssfdtime_ut.c _time/ssfrtc.c _time/ssfrtc_ut.c _time/ssfiso8601.c _time/ssfiso8601_ut.c -Wall -Wextra -pedantic -Wcast-align -Wno-parentheses -Wno-unused -Wdisabled-optimization -fdiagnostics-show-option -Wstrict-overflow=5 -Wformat=2 -I./ -I_time -I_codec -I_crypto -I_ecc -I_edc -I_fsm -I_storage -I_struct -lm -O3 -o ssf