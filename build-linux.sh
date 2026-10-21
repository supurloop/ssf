#!/bin/sh
# Build SSF on Linux via ninja (uses build-linux.ninja which adds -Wlogical-op
# and -lpthread compared to the macOS configuration).
# Pass any ninja flags as arguments (e.g. -j 4, -t clean, -t targets).
exec ninja -f build-linux.ninja "$@"
