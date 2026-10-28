from std.ffi import external_call
from std.sys import argv
from mojelly.websocket.server import (
    WebSocketHandle,
    WebSocketBytes,
    WS_EVENT_MESSAGE,
    WS_EVENT_ERROR,
    WS_TEXT,
    create,
    listen,
    port,
    run,
    send,
    stop,
    destroy,
)


# Match the native adapter ABI exactly and never let exceptions escape this callback
# Message data is borrowed and must be copied if the application retains it
@export
def mojo_ws_event(
    server: WebSocketHandle,
    event: Int32,
    connection_id: UInt64,
    detail: Int64,
    data: Optional[WebSocketBytes],
    length: UInt64,
) abi("C") -> None:
    if event == WS_EVENT_MESSAGE:
        # Return the borrowed event payload to the copying native send API before the parser can reuse that storage
        var status = send(server, connection_id, data, length, Int32(detail))
        if status != 0:
            # If echo admission fails, request bounded shutdown rather than trying to retain an extra application queue
            _ = stop(server)
        # Echo first so the queued response precedes the shutdown Close frame
        elif detail == WS_TEXT and length == 4 and data:
            # Unwrap only after checking that a four-byte text payload has a non-NULL data pointer
            var bytes = data.value()
            if (
                bytes[] == 115
                and bytes.unsafe_offset(1)[] == 116
                and bytes.unsafe_offset(2)[] == 111
                and bytes.unsafe_offset(3)[] == 112
            ):
                _ = stop(server)
    elif event == WS_EVENT_ERROR:
        print("WebSocket error:", detail)


# Own the server on the main thread and release it only after graceful shutdown finishes
# Port zero is useful for tests because the operating system selects an available listener
def main() raises:
    # Read the optional port before allocating any native resources so argument errors need no server cleanup
    var args = argv()
    var requested_port: UInt32 = 9001
    if len(args) > 2:
        raise Error("Usage: websocket_echo_mojo [port]")
    if len(args) == 2:
        var bytes = args[1].as_bytes()
        if len(bytes) == 0:
            raise Error("Port cannot be empty")
        requested_port = 0
        for byte in bytes:
            if byte < 48 or byte > 57:
                raise Error("Invalid port")
            requested_port = requested_port * 10 + UInt32(byte - 48)
            if requested_port > 65535:
                raise Error("Invalid port")
    # Allocate the native server and check the nullable result before extracting its live handle
    var created = create()
    if not created:
        raise Error("Cannot create WebSocket server")
    var server = created.value()
    # Bind the configured port and destroy the still-idle handle if listener setup fails
    if listen(server, requested_port) != 0:
        _ = destroy(server)
        raise Error("Cannot listen on WebSocket port")
    # Query the actual bound port because a requested zero is replaced by an operating-system-selected value
    print("ws://127.0.0.1:" + String(port(server)) + "/ws")
    # Flush the startup address so pipe-based clients can discover an ephemeral port
    _ = external_call["fflush", Int32, Optional[WebSocketHandle]](None)
    # Keep this thread inside the native loop until the stop command and peer Close acknowledgements have been processed
    var status = run(server)
    # Release the adapter after run returns, then check both statuses so a shutdown or lifetime failure is not hidden
    var destroyed = destroy(server)
    if status != 0 or destroyed != 0:
        raise Error("WebSocket server failed")
