#include "bridge.h"

#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* The bridge belongs to its creating thread and borrows both external contexts
 * Function tables are copied so callers may release their temporary tables
 * Dispatch depth prevents callbacks from destroying a bridge still on the stack */
struct ws_bridge {
    pthread_t owner;
    void* transport_context;
    void* application_context;
    ws_transport_t transport;
    ws_callbacks_t callbacks;
    uint64_t max_message_size;
    size_t dispatch_depth;
    int stopped;
};

/* Validate the bridge and its thread before accessing mutable state
 * Shutdown may reject new commands while still allowing final close and error events */
static int32_t check_bridge(const ws_bridge_t* bridge,
                            int require_running) {
    if (bridge == NULL) return WS_INVALID_ARGUMENT;
    /* Compare pthread identifiers through pthread_equal rather than treating their representation as an integer
     * A foreign caller must not read or change the owner-thread state */
    if (!pthread_equal(bridge->owner, pthread_self())) {
        return WS_WRONG_THREAD;
    }
    if (require_running && bridge->stopped) return WS_STOPPED;
    return WS_OK;
}
/* Accept NULL only for an empty buffer and reject lengths that cannot fit size_t
 * The caller remains responsible for providing readable memory of the stated length */
static int32_t check_bytes(const uint8_t* data, uint64_t length) {
    if (data == NULL && length != 0) return WS_INVALID_ARGUMENT;
    if (length > SIZE_MAX) return WS_TOO_LARGE;
    return WS_OK;
}
/* Validate message kind, connection ID and application payload limit
 * Connection existence, closing state and protocol-specific checks belong to the transport */
static int32_t check_message(const ws_bridge_t* bridge,
                             uint64_t connection_id, const uint8_t* data,
                             uint64_t length, int32_t kind) {
    if (connection_id == 0 ||
        (kind != WS_TEXT && kind != WS_BINARY)) {
        return WS_INVALID_ARGUMENT;
    }
    /* Check pointer and length compatibility before later copies or protocol validation can access the buffer */
    int32_t status = check_bytes(data, length);
    if (status != WS_OK) return status;
    if (length > bridge->max_message_size) return WS_TOO_LARGE;
    return WS_OK;
}
/* Make an independent malloc-owned copy before returning control to Mojo
 * Empty payloads use NULL and still represent valid WebSocket messages */
static int32_t copy_bytes(const uint8_t* data, uint64_t length,
                          uint8_t** out_copy) {
    *out_copy = NULL;
    if (length == 0) return WS_OK;
    /* Allocate native storage separately from Mojo memory so asynchronous output does not borrow a temporary object */
    uint8_t* copy = malloc((size_t)length);
    if (copy == NULL) return WS_NO_MEMORY;
    /* Copy the exact byte count rather than a string length so embedded NUL bytes remain part of binary messages */
    memcpy(copy, data, (size_t)length);
    *out_copy = copy;
    return WS_OK;
}
/* Capture the current thread, copy callback tables and borrow external contexts
 * Initialize the output to NULL so failed creation never exposes a partial bridge */
int32_t ws_bridge_create(
    void* transport_context, const ws_transport_t* transport,
    void* application_context, const ws_callbacks_t* callbacks,
    uint64_t max_message_size, ws_bridge_t** out_bridge) {
    if (out_bridge == NULL) return WS_INVALID_ARGUMENT;
    *out_bridge = NULL;
    if (transport == NULL || transport->send == NULL ||
        transport->close == NULL || max_message_size == 0 ||
        max_message_size > SIZE_MAX) {
        return WS_INVALID_ARGUMENT;
    }
    /* Allocate zero-initialized state so absent optional callbacks and the initial dispatch depth are safe */
    ws_bridge_t* bridge = calloc(1, sizeof(*bridge));
    if (bridge == NULL) return WS_NO_MEMORY;
    /* Record the creator as owner and copy only the function tables
     * The pointed-to transport and application contexts remain borrowed */
    bridge->owner = pthread_self();
    bridge->transport_context = transport_context;
    bridge->application_context = application_context;
    bridge->transport = *transport;
    if (callbacks != NULL) bridge->callbacks = *callbacks;
    bridge->max_message_size = max_message_size;
    *out_bridge = bridge;
    return WS_OK;
}

/* Reject subsequent send, close, open and message operations
 * Existing transport work must drain separately and may still emit close or error events */
int32_t ws_bridge_stop(ws_bridge_t* bridge) {
    /* Allow an already stopped bridge so repeated stop requests stay harmless while callbacks drain */
    int32_t status = check_bridge(bridge, 0);
    if (status != WS_OK) return status;
    bridge->stopped = 1;
    return WS_OK;
}

/* Release only a stopped bridge outside every callback and transport invocation
 * The caller must first guarantee that no asynchronous transport callbacks remain */
int32_t ws_bridge_destroy(ws_bridge_t* bridge) {
    int32_t status = check_bridge(bridge, 0);
    if (status != WS_OK) return status;
    /* Reject destruction until stop has been requested and every synchronous external call has returned */
    if (!bridge->stopped || bridge->dispatch_depth != 0) {
        return WS_BUSY;
    }
    /* Release only bridge-owned metadata because neither borrowed context belongs to this allocation */
    free(bridge);
    return WS_OK;
}

/* Copy the borrowed application buffer and pass ownership to the transport on success
 * On rejection the bridge frees the copy and forwards the transport status unchanged */
int32_t ws_send(ws_bridge_t* bridge, uint64_t connection_id,
                       const uint8_t* data, uint64_t length, int32_t kind) {
    /* Check owner-thread access and running state before validating the application command */
    int32_t status = check_bridge(bridge, 1);
    if (status != WS_OK) return status;
    /* Validate the ID, message kind and complete payload size before allocating any transport storage */
    status = check_message(bridge, connection_id, data, length, kind);
    if (status != WS_OK) return status;
    uint8_t* copy;
    /* Detach the payload from caller-owned memory before handing it to potentially asynchronous transport code */
    status = copy_bytes(data, length, &copy);
    if (status != WS_OK) return status;

    /* Protect the bridge while transport.send runs because the transport may synchronously invoke application callbacks */
    bridge->dispatch_depth++;
    status = bridge->transport.send(bridge->transport_context, connection_id,
                                    copy, length, kind);
    bridge->dispatch_depth--;
    /* An accepted buffer belongs to the transport
     * Free it here only when the transport rejected ownership */
    if (status != WS_OK) free(copy);
    return status;
}

/* Copy the close reason and delegate protocol validation to the transport
 * The Close control payload allows at most 123 reason bytes after its two-byte code */
int32_t ws_close(ws_bridge_t* bridge, uint64_t connection_id,
                        uint32_t code, const uint8_t* reason,
                        uint64_t reason_length) {
    int32_t status = check_bridge(bridge, 1);
    if (status != WS_OK) return status;
    if (connection_id == 0 || code > UINT16_MAX) {
        return WS_INVALID_ARGUMENT;
    }
    /* Validate the borrowed reason before copying it and leave valid wire code and UTF-8 checks to the transport */
    status = check_bytes(reason, reason_length);
    if (status != WS_OK) return status;

    if (reason_length > 123) return WS_TOO_LARGE;
    uint8_t* copy;
    /* Retain a native reason buffer because the caller may release its original memory as soon as this function returns */
    status = copy_bytes(reason, reason_length, &copy);
    if (status != WS_OK) return status;
    /* Keep the bridge alive across transport.close and any application callbacks triggered by that call */
    bridge->dispatch_depth++;
    status = bridge->transport.close(bridge->transport_context, connection_id,
                                     code, copy, reason_length);
    bridge->dispatch_depth--;
    /* Preserve the same transfer-on-success contract as message sending to avoid leaks or double frees */
    if (status != WS_OK) free(copy);
    return status;
}

/* Synchronously report a completed upgrade using a nonzero connection ID
 * The transport is responsible for emitting this event only once per connection */
int32_t ws_emit_open(ws_bridge_t* bridge,
                            uint64_t connection_id, uint64_t route_id) {
    int32_t status = check_bridge(bridge, 1);
    if (status != WS_OK) return status;
    if (connection_id == 0) return WS_INVALID_ARGUMENT;
    /* Invoke only a registered callback and protect the bridge until the notification returns
     * This notification means the native layer has already accepted the Upgrade */
    if (bridge->callbacks.on_open != NULL) {
        bridge->dispatch_depth++;
        bridge->callbacks.on_open(bridge->application_context, connection_id,
                                  route_id);
        bridge->dispatch_depth--;
    }
    return WS_OK;
}

/* Deliver a complete validated message without copying its borrowed payload
 * The callback may send a response but must copy data it wants to retain */
int32_t ws_emit_message(ws_bridge_t* bridge,
                               uint64_t connection_id, const uint8_t* data,
                               uint64_t length, int32_t kind) {
    int32_t status = check_bridge(bridge, 1);
    if (status != WS_OK) return status;
    /* Apply bridge-level size and kind checks even though the native parser has already checked frame syntax */
    status = check_message(bridge, connection_id, data, length, kind);
    if (status != WS_OK) return status;
    /* Borrow the completed parser buffer for one synchronous callback
     * A callback that sends a reply goes through ws_send and receives its own output copy */
    if (bridge->callbacks.on_message != NULL) {
        bridge->dispatch_depth++;
        bridge->callbacks.on_message(bridge->application_context, connection_id,
                                     data, length, kind);
        bridge->dispatch_depth--;
    }
    return WS_OK;
}

/* Deliver the final close event even after the bridge has stopped
 * Code and reason may describe a local abnormal closure rather than a wire Close frame */
int32_t ws_emit_close(ws_bridge_t* bridge,
                             uint64_t connection_id, uint32_t code,
                             const uint8_t* reason, uint64_t reason_length) {
    /* Skip the running-state requirement because final close notifications must survive a shutdown request */
    int32_t status = check_bridge(bridge, 0);
    if (status != WS_OK) return status;
    if (connection_id == 0) return WS_INVALID_ARGUMENT;
    status = check_bytes(reason, reason_length);
    if (status != WS_OK) return status;
    /* Deliver the reason while its connection storage is still alive
     * The native layer may release that storage immediately after this function returns */
    if (bridge->callbacks.on_close != NULL) {
        bridge->dispatch_depth++;
        bridge->callbacks.on_close(bridge->application_context, connection_id,
                                   code, reason, reason_length);
        bridge->dispatch_depth--;
    }
    return WS_OK;
}

/* Report an operation or connection failure without assuming it closes the connection
 * The diagnostic buffer is valid only for the duration of this callback */
int32_t ws_emit_error(ws_bridge_t* bridge,
                             uint64_t connection_id, int32_t error,
                             const uint8_t* message, uint64_t message_length) {
    /* Permit diagnostics during shutdown while still enforcing owner-thread delivery */
    int32_t status = check_bridge(bridge, 0);
    if (status != WS_OK) return status;
    if (connection_id == 0) return WS_INVALID_ARGUMENT;
    status = check_bytes(message, message_length);
    if (status != WS_OK) return status;
    /* Borrow the diagnostic bytes for this call without promising that the connection is still open */
    if (bridge->callbacks.on_error != NULL) {
        bridge->dispatch_depth++;
        bridge->callbacks.on_error(bridge->application_context, connection_id,
                                   error, message, message_length);
        bridge->dispatch_depth--;
    }
    return WS_OK;
}
