from std.ffi import external_call
from std.memory import Pointer

comptime WebSocketHandle = Pointer[NoneType, MutUntrackedOrigin]
comptime WebSocketBytes = Pointer[UInt8, MutUntrackedOrigin]

comptime WS_OK = 0
comptime WS_TEXT = 1
comptime WS_BINARY = 2
comptime WS_EVENT_OPEN = 1
comptime WS_EVENT_MESSAGE = 2
comptime WS_EVENT_CLOSE = 3
comptime WS_EVENT_ERROR = 4


# Create a default-configured native server on the current thread
# Optional models a C NULL allocation result without creating an invalid nonnull Pointer
def create() -> Optional[WebSocketHandle]:
    # Receive the native handle as Optional so a C allocation failure remains a valid nullable result
    return external_call["ws_mojo_create", Optional[WebSocketHandle]]()


# Bind a numeric address and exact route while the temporary String buffers remain alive
# Native code copies the path before this call returns and port zero requests an available port
def listen(
    server: WebSocketHandle,
    port: UInt32 = 9001,
    address: String = "127.0.0.1",
    path: String = "/ws",
) -> Int32:
    # Borrow byte views of both strings while their owning String arguments remain alive for the entire native call
    var address_bytes = address.as_bytes()
    var path_bytes = path.as_bytes()
    # Adapt pointer origins and mutability to the ABI pointer type without transferring ownership
    # Native code uses these arguments as const strings and retains its own route copy
    return external_call[
        "ws_mojo_listen", Int32, WebSocketHandle, WebSocketBytes, UInt32, WebSocketBytes
    ](
        server,
        address_bytes.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutUntrackedOrigin](),
        port,
        path_bytes.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutUntrackedOrigin](),
    )


# Return the actual bound port from the owner thread or zero for an invalid access
def port(server: WebSocketHandle) -> UInt32:
    # Ask the native owner-thread accessor for the bound port rather than inferring it from the requested port
    return external_call["ws_mojo_port", UInt32, WebSocketHandle](server)


# Run one owner-thread iteration and allow native deadlines to shorten the requested wait
# A stopped loop returns WS_STOPPED and callbacks must not recursively enter the loop
def poll(server: WebSocketHandle, timeout_ms: Int32 = 100) -> Int32:
    # Forward the wait budget and native status unchanged so the application can distinguish stopped and busy loops
    return external_call["ws_mojo_poll", Int32, WebSocketHandle, Int32](server, timeout_ms)


# Keep polling until stop has drained all native connections
def run(server: WebSocketHandle) -> Int32:
    # Enter native polling on this thread and continue receiving synchronous Mojo events until shutdown completes
    return external_call["ws_mojo_run", Int32, WebSocketHandle](server)


# Borrow the payload only until return because native code keeps its own copy
# Optional represents empty payloads passed as NULL across the C ABI
# Cross-thread success means queue acceptance and later failures arrive as error events
def send(
    server: WebSocketHandle, connection_id: UInt64,
    data: Optional[WebSocketBytes], length: UInt64, kind: Int32,
) -> Int32:
    # Pass a borrowed optional pointer and explicit byte count instead of assuming a NUL-terminated string
    # The native copy makes the original buffer reusable after this call, even for queued cross-thread sends
    return external_call[
        "ws_mojo_send", Int32, WebSocketHandle, UInt64, Optional[WebSocketBytes], UInt64, Int32
    ](server, connection_id, data, length, kind)


# Request an ordered Close handshake with an optional borrowed UTF-8 reason
# An absent reason and zero length produce a Close frame containing only the code
def close(
    server: WebSocketHandle, connection_id: UInt64, code: UInt32,
    reason: Optional[WebSocketBytes] = None, length: UInt64 = 0,
) -> Int32:
    # Let the native API validate the code and reason before either direct dispatch or an ordered queued Close command
    return external_call[
        "ws_mojo_close", Int32, WebSocketHandle, UInt64, UInt32, Optional[WebSocketBytes], UInt64
    ](server, connection_id, code, reason, length)


# Publish a thread-safe graceful shutdown request and wake the native polling loop
def stop(server: WebSocketHandle) -> Int32:
    # Wake native polling without releasing the handle because shutdown can still generate final event callbacks
    return external_call["ws_mojo_stop", Int32, WebSocketHandle](server)


# Release the opaque handle only after run or poll finishes and all producers have joined
# BUSY and WRONG_THREAD leave the handle valid and must not be treated as successful cleanup
def destroy(server: WebSocketHandle) -> Int32:
    # Release only a fully stopped native server and adapter
    # On a nonzero result the handle remains live and must not be discarded as though destruction succeeded
    return external_call["ws_mojo_destroy", Int32, WebSocketHandle](server)
