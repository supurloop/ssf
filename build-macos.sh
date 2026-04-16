#!/bin/sh
# Build SSF on macOS via ninja.
# Pass any ninja flags as arguments (e.g. -j 4, -t clean, -t targets).
exec ninja "$@"
