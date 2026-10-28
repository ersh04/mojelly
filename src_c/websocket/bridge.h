#ifndef WS_BRIDGE_H
#define WS_BRIDGE_H

#include <stdint.h>

#include "events.h"

/* Opaque owner-thread bridge between application callbacks and native transport */
typedef struct ws_bridge ws_bridge_t;

/* Status values cross the C ABI as int32_t and are distinct from WebSocket Close codes */
enum {
    WS_OK = 0,
    WS_INVALID_ARGUMENT = -1,
    WS_NO_MEMORY = -2,
    WS_NOT_FOUND = -3,
    WS_CLOSING = -4,
    WS_TOO_LARGE = -5,
    WS_BACKPRESSURE = -6,
    WS_WRONG_THREAD = -7,
    WS_STOPPED = -8,
    WS_BUSY = -9,
    WS_IO_ERROR = -10,
    WS_PROTOCOL_ERROR = -11,
    WS_TIMED_OUT = -12
};

/* Transport operations execute on the bridge owner thread
 * WS_OK transfers ownership of the malloc buffer to the transport
 * Any other result leaves the buffer owned by the bridge, which frees it
 * Empty payloads may use NULL and accepted buffers must eventually be freed with free()
 * The transport checks connection state, queue limits, close codes and UTF-8
 * Acceptance into the transport does not acknowledge delivery to the remote application */
typedef struct {
    int32_t (*send)(void* context, uint64_t connection_id, uint8_t* data,
                    uint64_t length, int32_t kind);
    int32_t (*close)(void* context, uint64_t connection_id, uint32_t code,
                     uint8_t* reason, uint64_t reason_length);
} ws_transport_t;

/* Bind a bridge to the calling thread and copy both function tables
 * Both transport operations are required while callbacks may be NULL
 * External contexts are borrowed and must outlive the bridge
 * The message limit must be nonzero and representable by size_t
 * Failure initializes out_bridge to NULL when the output argument itself is valid */
int32_t ws_bridge_create(
    void* transport_context, const ws_transport_t* transport,
    void* application_context, const ws_callbacks_t* callbacks,
    uint64_t max_message_size, ws_bridge_t** out_bridge);

/* Reject new commands and open/message events while allowing final close/error events
 * Stopping the bridge does not stop sockets or drain asynchronous transport operations */
int32_t ws_bridge_stop(ws_bridge_t* bridge);

/* Destroy only after stop and after all transport work has completed
 * Destruction from a callback or transport operation returns WS_BUSY
 * All other bridge calls require a valid handle and must not race with destruction */
int32_t ws_bridge_destroy(ws_bridge_t* bridge);

/* Copy borrowed data before dispatch so the caller may immediately reuse its buffer
 * Connection ID zero is reserved and kinds must be WS_TEXT or WS_BINARY
 * Empty messages are valid and a success result means acceptance into the transport */
int32_t ws_send(ws_bridge_t* bridge, uint64_t connection_id,
                const uint8_t* data, uint64_t length, int32_t kind);

/* Copy a close reason of at most 123 bytes and request an ordered Close handshake
 * The transport performs the final validation of the close code and UTF-8 reason */
int32_t ws_close(ws_bridge_t* bridge, uint64_t connection_id,
                 uint32_t code, const uint8_t* reason, uint64_t reason_length);

/* Internal synchronous event entry points used by the native connection layer
 * The native layer preserves ordering and emits open and final close at most once
 * Message and diagnostic buffers are borrowed until the callback returns
 * A callback may send, close or stop but must not destroy the active bridge */
int32_t ws_emit_open(ws_bridge_t* bridge, uint64_t connection_id, uint64_t route_id);
int32_t ws_emit_message(ws_bridge_t* bridge, uint64_t connection_id,
                        const uint8_t* data, uint64_t length, int32_t kind);
int32_t ws_emit_close(ws_bridge_t* bridge, uint64_t connection_id,
                      uint32_t code, const uint8_t* reason, uint64_t reason_length);
int32_t ws_emit_error(ws_bridge_t* bridge, uint64_t connection_id,
                      int32_t error, const uint8_t* message, uint64_t message_length);

#endif
