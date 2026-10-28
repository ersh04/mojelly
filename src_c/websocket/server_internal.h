#ifndef WS_SERVER_INTERNAL_H
#define WS_SERVER_INTERNAL_H

#include <poll.h>
#include <pthread.h>
#include <stddef.h>

#include "connection.h"

/* State transitions are performed only by the event-loop owner thread */
typedef enum { ST_INIT, ST_OPEN, ST_CLOSING, ST_CLOSED } server_state_t;

/* Cross-thread command nodes own copies of their payloads until the loop consumes them
 * The mutex protects queue links, accounting and shutdown publication */
typedef struct ws_command {
    struct ws_command* next;
    uint64_t connection_id;
    uint8_t* data;
    uint64_t length;
    int32_t kind;
    uint32_t close_code;
    int close_command;
} ws_command_t;

/* Most fields are owner-thread-only and immutable configuration is safe for producers to read
 * Producer threads may touch command fields only while holding command_mutex
 * No thread may race with final destruction of this context */
struct server_context {
    pthread_t owner;
    server_state_t state;
    ws_server_config_t config;
    char* allowed_origin;
    char* path;
    int listen_fd;
    uint32_t port;
    /* The pipe transports wakeups only and complete commands stay in the protected queue */
    int wake_read_fd;
    int wake_write_fd;
    pthread_mutex_t command_mutex;
    ws_command_t* command_head;
    ws_command_t* command_tail;
    uint64_t command_bytes;
    int stop_requested;
    int accepting_commands;
    int in_poll;
    ws_bridge_t* bridge;
    ws_connection_t* connections;
    uint32_t connection_count;
    uint64_t next_connection_id;
    /* Preallocate poll storage to the connection limit and retain a parallel object snapshot */
    struct pollfd* poll_fds;
    ws_connection_t** poll_connections;
};

uint64_t ws_now_ms(void);
void ws_connection_error(ws_connection_t* connection, int32_t status,
                          const char* message);

#endif
