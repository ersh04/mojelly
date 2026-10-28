#ifndef WS_MOJO_ADAPTER_H
#define WS_MOJO_ADAPTER_H

#include "server.h"

/* Stable opaque handle that owns the native server and its callback routing */
typedef struct ws_mojo_server ws_mojo_server_t;

enum { WS_EVENT_OPEN = 1, WS_EVENT_MESSAGE = 2, WS_EVENT_CLOSE = 3, WS_EVENT_ERROR = 4 };

/* The application exports mojo_ws_event using exactly this C ABI
 * Event data is read-only and borrowed until the callback returns
 * detail carries the route ID, message kind, Close code or signed native error
 * This optional adapter is linked only when a Mojo application references it */
void mojo_ws_event(ws_mojo_server_t* server, int32_t event, uint64_t connection_id,
                   int64_t detail, const uint8_t* data, uint64_t length);

/* Mirror the native server API with a default-configuration constructor
 * Thread restrictions and buffer ownership follow server.h */
ws_mojo_server_t* ws_mojo_create(void);
int32_t ws_mojo_listen(ws_mojo_server_t* server, const char* address,
                       uint32_t port, const char* path);
uint32_t ws_mojo_port(ws_mojo_server_t* server);
int32_t ws_mojo_poll(ws_mojo_server_t* server, int32_t timeout_ms);
int32_t ws_mojo_run(ws_mojo_server_t* server);
int32_t ws_mojo_send(ws_mojo_server_t* server, uint64_t id,
                     const uint8_t* data, uint64_t length, int32_t kind);
int32_t ws_mojo_close(ws_mojo_server_t* server, uint64_t id, uint32_t code,
                      const uint8_t* reason, uint64_t length);
int32_t ws_mojo_stop(ws_mojo_server_t* server);
int32_t ws_mojo_destroy(ws_mojo_server_t* server);

#endif
