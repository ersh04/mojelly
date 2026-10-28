#ifndef WS_EVENTS_H
#define WS_EVENTS_H

#include <stdint.h>

/* Application message kinds use the corresponding WebSocket data opcodes */
enum {
    WS_TEXT = 1,
    WS_BINARY = 2
};

/* Every callback executes synchronously on the creating event-loop thread
 * The context and all payload pointers are borrowed and must not be freed here
 * A payload pointer may be NULL when its length is zero
 * Copy any message or reason that must survive beyond the callback
 * Any callback may be NULL and exceptions must never cross the C ABI boundary
 * An error notification does not necessarily imply that the connection has closed */
typedef struct {
    void (*on_open)(void* context, uint64_t connection_id, uint64_t route_id);
    void (*on_message)(void* context, uint64_t connection_id,
                       const uint8_t* data, uint64_t length, int32_t kind);
    void (*on_close)(void* context, uint64_t connection_id, uint32_t code,
                     const uint8_t* reason, uint64_t reason_length);
    void (*on_error)(void* context, uint64_t connection_id, int32_t error,
                     const uint8_t* message, uint64_t message_length);
} ws_callbacks_t;

#endif
