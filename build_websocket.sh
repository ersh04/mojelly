#!/bin/sh
set -eu

# Resolve source paths independently of the directory from which this script was called
WS_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WS_OUT=${WS_BUILD_DIR:-"$WS_ROOT/build/websocket"}
WS_CC=${CC:-cc}
WS_MODE=${1:-c}
if [ "$WS_MODE" != c ] && [ "$WS_MODE" != --mojo ]; then
    printf 'Usage: sh build_websocket.sh [--mojo]\n' >&2
    exit 1
fi
if [ "${WS_SANITIZE:-0}" = 1 ] && [ "$WS_MODE" = --mojo ]; then
    printf 'Run C sanitizers and Mojo tests separately.\n' >&2
    exit 1
fi
# Apply strict C diagnostics to every translation unit in both build modes
WS_FLAGS="-std=c11 -Wall -Wextra -Werror -Wpedantic -pthread -fPIC"
if [ "${WS_SANITIZE:-0}" = 1 ]; then
    WS_FLAGS="$WS_FLAGS -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"
else
    WS_FLAGS="$WS_FLAGS -O2"
fi
mkdir -p "$WS_OUT"
for WS_NAME in bridge protocol connection server mojo_adapter; do
    "$WS_CC" $WS_FLAGS -c "$WS_ROOT/src_c/websocket/$WS_NAME.c" -o "$WS_OUT/ws_$WS_NAME.o"
done
# Keep the Mojo adapter in a separate archive member so C applications need no Mojo exports
ar rcs "$WS_OUT/libmojelly_ws.a" "$WS_OUT/ws_bridge.o" "$WS_OUT/ws_protocol.o" \
    "$WS_OUT/ws_connection.o" "$WS_OUT/ws_server.o" "$WS_OUT/ws_mojo_adapter.o"
"$WS_CC" $WS_FLAGS -I "$WS_ROOT/src_c/websocket" "$WS_ROOT/examples/websocket_echo.c" \
    "$WS_OUT/libmojelly_ws.a" -o "$WS_OUT/websocket_echo"
printf 'WebSocket library: %s/libmojelly_ws.a\nEcho server: %s/websocket_echo\n' "$WS_OUT" "$WS_OUT"

# Build Mojo only when requested and use the configured compiler or project environment
if [ "$WS_MODE" = --mojo ]; then
    set --
    if [ -n "${WS_MOJO_STDLIB:-}" ]; then
        set -- -I "$WS_MOJO_STDLIB"
    fi
    if [ -n "${MOJO:-}" ]; then
        "$MOJO" build "$@" -I "$WS_ROOT" "$WS_ROOT/examples/websocket_echo.mojo" \
            -Xlinker "$WS_OUT/libmojelly_ws.a" -Xlinker -lpthread -o "$WS_OUT/websocket_echo_mojo"
    elif command -v mojo >/dev/null 2>&1; then
        mojo build "$@" -I "$WS_ROOT" "$WS_ROOT/examples/websocket_echo.mojo" \
            -Xlinker "$WS_OUT/libmojelly_ws.a" -Xlinker -lpthread -o "$WS_OUT/websocket_echo_mojo"
    else
        pixi run mojo build "$@" -I "$WS_ROOT" "$WS_ROOT/examples/websocket_echo.mojo" \
            -Xlinker "$WS_OUT/libmojelly_ws.a" -Xlinker -lpthread -o "$WS_OUT/websocket_echo_mojo"
    fi
    printf 'Mojo echo server: %s/websocket_echo_mojo\n' "$WS_OUT"
fi
