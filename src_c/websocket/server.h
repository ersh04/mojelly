#ifndef MOJELLY_WS_SERVER_H
#define MOJELLY_WS_SERVER_H

#include <stdint.h>

#include "bridge.h"

/* Heap-allocated server context whose internals remain private to the socket backend */
typedef struct server_context server_context_t;

/* Resource limits are copied at creation and remain immutable while the server runs
 * max_message_size applies to the entire reassembled message, not each fragment
 * max_queued_bytes limits retained output allocations per connection and the command queue
 * A separate fixed reserve permits control frames under application backpressure
 * All durations use monotonic milliseconds and only read_timeout_ms accepts zero */
typedef struct {
    uint64_t max_message_size;
    uint64_t max_queued_bytes;
    uint32_t max_connections;
    uint32_t max_header_size;
    uint64_t handshake_timeout_ms;
    uint64_t read_timeout_ms;
    uint64_t write_timeout_ms;
    uint64_t close_timeout_ms;
    /* NULL allows any Origin and a non-NULL value requires an exact match
     * The origin policy is copied and does not authenticate the remote client */
    const char* allowed_origin;
} ws_server_config_t;

/* Initialize every configuration field to the documented standalone defaults */
void ws_server_config_default(ws_server_config_t* config);

/* Create a server on the calling thread, copying configuration and callback tables
 * Passing NULL configuration selects defaults and passing NULL callbacks is allowed
 * The application context is borrowed until destruction and must remain valid
 * Creation, listening, polling, running and destruction belong to this same thread */
int32_t ws_server_create(const ws_server_config_t* config,
                         const ws_callbacks_t* callbacks, void* application_context,
                         server_context_t** out_server);

/* Start a nonblocking listener on one numeric address and one exact path
 * NULL address selects loopback and port zero selects an available port
 * Query strings do not change path matching and this listener uses route ID 1 */
int32_t ws_server_listen(server_context_t* server, const char* address,
                         uint32_t port, const char* path);

/* Return the actual bound port or zero if called with an invalid handle or thread */
uint32_t ws_server_port(const server_context_t* server);

/* Process one event-loop iteration with a maximum wait, shortened by pending deadlines
 * A timeout of -1 permits an indefinite wait when no deadline is pending
 * Reentrant calls return WS_BUSY and a fully stopped loop returns WS_STOPPED */
int32_t ws_server_poll(server_context_t* server, int32_t timeout_ms);

/* Run until a requested shutdown drains all connections or an unrecoverable error occurs */
int32_t ws_server_run(server_context_t* server);

/* Submit a message from either the owner thread or another producer thread
 * Data is copied before return and may immediately be changed or released by the caller
 * Owner-thread success means transport acceptance and cross-thread success means enqueueing
 * Later failures of queued commands are reported through on_error */
int32_t ws_server_send(server_context_t* server, uint64_t connection_id,
                       const uint8_t* data, uint64_t length, int32_t kind);

/* Request a valid Close frame using the same thread and ownership rules as send
 * The UTF-8 reason may be NULL only when reason_length is zero */
int32_t ws_server_close(server_context_t* server, uint64_t connection_id,
                        uint32_t code, const uint8_t* reason, uint64_t reason_length);

/* Request graceful shutdown from any thread and wake the polling thread
 * This operation acquires a mutex and is not safe to call from a signal handler */
int32_t ws_server_request_stop(server_context_t* server);

/* Destroy before listening or after run/poll has completed shutdown
 * Stop and join all producer threads first and make no further calls with the handle
 * Destruction from inside any active event-loop callback returns WS_BUSY */
int32_t ws_server_destroy(server_context_t* server);

#endif
