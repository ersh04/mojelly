#include "mojo_adapter.h"

#include <stdlib.h>

/* Keep the Mojo-visible handle stable while borrowing it as the native callback context
 * This object is freed only after the underlying server has stopped */
struct ws_mojo_server {
    server_context_t* server;
};

/* Forward the configured route ID through the shared Mojo event entry point */
static void on_open(void* context, uint64_t id, uint64_t route) {
    /* Map the native route ID to the signed detail slot and use an empty optional payload for this lifecycle event */
    mojo_ws_event(context, WS_EVENT_OPEN, id, (int64_t)route, NULL, 0);
}

/* Forward a borrowed complete message whose data remains valid until Mojo returns */
static void on_message(void* context, uint64_t id, const uint8_t* data,
                        uint64_t length, int32_t kind) {
    /* Pass the parser buffer straight through the C ABI for synchronous handling
     * Mojo must copy bytes it retains beyond the event, while replying through send obtains a native copy */
    mojo_ws_event(context, WS_EVENT_MESSAGE, id, kind, data, length);
}

/* Forward the final peer close code and borrowed reason without allocating another copy */
static void on_close(void* context, uint64_t id, uint32_t code,
                      const uint8_t* reason, uint64_t length) {
    /* Keep the wire or local close code in detail and borrow the reason only while the connection still owns it */
    mojo_ws_event(context, WS_EVENT_CLOSE, id, code, reason, length);
}

/* Preserve negative native status values in the signed detail argument */
static void on_error(void* context, uint64_t id, int32_t error,
                      const uint8_t* message, uint64_t length) {
    /* Sign-extend the native error into detail so a negative status is not confused with a positive Close code */
    mojo_ws_event(context, WS_EVENT_ERROR, id, error, message, length);
}

/* Build the optional Mojo callback adapter using the default native configuration
 * The application must export mojo_ws_event with exactly the declared C ABI */
ws_mojo_server_t* ws_mojo_create(void) {
    /* Allocate the stable callback context before constructing a native server that will borrow its address */
    ws_mojo_server_t* adapter = calloc(1, sizeof(*adapter));
    if (adapter == NULL) return NULL;
    /* Translate four native callbacks into one exported Mojo dispatcher
     * The native constructor copies this temporary table, so the local table need not outlive the call */
    ws_callbacks_t callbacks = {.on_open = on_open, .on_message = on_message,
        .on_close = on_close, .on_error = on_error};
    /* Use default limits and install the adapter as application context
     * If native construction fails, it cleans its own partial state and this function frees only the wrapper */
    if (ws_server_create(NULL, &callbacks, adapter, &adapter->server) != WS_OK) {
        free(adapter); return NULL;
    }
    return adapter;
}

/* Delegate listener creation while validating the opaque adapter handle */
int32_t ws_mojo_listen(ws_mojo_server_t* server, const char* address,
                       uint32_t port, const char* path) {
    /* Unwrap the native handle only after the NULL check and let the native listener enforce thread and lifecycle rules */
    return server == NULL ? WS_INVALID_ARGUMENT :
        ws_server_listen(server->server, address, port, path);
}

/* Expose the bound native port without exposing the native server structure to Mojo */
uint32_t ws_mojo_port(ws_mojo_server_t* server) {
    /* Read the actual bound port through the native owner-thread accessor rather than exposing private server fields to Mojo */
    return server == NULL ? 0 : ws_server_port(server->server);
}

/* Drive one owner-thread event-loop iteration from Mojo */
int32_t ws_mojo_poll(ws_mojo_server_t* server, int32_t timeout_ms) {
    /* Forward the wait limit unchanged so native connection deadlines and wakeups still control the actual poll duration */
    return server == NULL ? WS_INVALID_ARGUMENT : ws_server_poll(server->server, timeout_ms);
}

/* Drive the owner-thread loop until the native server finishes shutting down */
int32_t ws_mojo_run(ws_mojo_server_t* server) {
    /* Keep callback routing attached to this wrapper throughout the native run loop and its shutdown callbacks */
    return server == NULL ? WS_INVALID_ARGUMENT : ws_server_run(server->server);
}

/* Pass borrowed Mojo data to the native copying send API */
int32_t ws_mojo_send(ws_mojo_server_t* server, uint64_t id,
                     const uint8_t* data, uint64_t length, int32_t kind) {
    /* Delegate copying and cross-thread enqueueing to the native send API
     * The adapter itself never takes ownership of borrowed Mojo memory */
    return server == NULL ? WS_INVALID_ARGUMENT :
        ws_server_send(server->server, id, data, length, kind);
}

/* Pass a borrowed reason to the native copying close API */
int32_t ws_mojo_close(ws_mojo_server_t* server, uint64_t id, uint32_t code,
                      const uint8_t* reason, uint64_t length) {
    /* Let the native close path validate and copy the reason before returning across the ABI boundary */
    return server == NULL ? WS_INVALID_ARGUMENT :
        ws_server_close(server->server, id, code, reason, length);
}

/* Request shutdown without destroying an adapter still used by callbacks */
int32_t ws_mojo_stop(ws_mojo_server_t* server) {
    /* Publish a native stop request while retaining the wrapper because final events still need its callback context */
    return server == NULL ? WS_INVALID_ARGUMENT : ws_server_request_stop(server->server);
}

/* Free the adapter only after native destruction succeeds
 * BUSY and WRONG_THREAD leave the handle valid for a later attempt */
int32_t ws_mojo_destroy(ws_mojo_server_t* server) {
    if (server == NULL) return WS_INVALID_ARGUMENT;
    /* Ask the native server to confirm that no active loop or connection can call back through this wrapper */
    int32_t status = ws_server_destroy(server->server);
    /* Free the callback context only after successful native destruction
     * Any failure must leave the handle intact for a later valid cleanup attempt */
    if (status == WS_OK) free(server);
    return status;
}
