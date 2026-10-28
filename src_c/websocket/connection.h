#ifndef WS_CONNECTION_H
#define WS_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

#include "protocol.h"
#include "server.h"

/* One owned output buffer with independent header and payload progress
 * Keeping the buffers separate avoids copying an entire message to prepend a frame header */
typedef struct ws_write_item {
    struct ws_write_item* next;
    uint8_t header[10];
    size_t header_length;
    size_t header_offset;
    uint8_t* data;
    size_t length;
    size_t offset;
} ws_write_item_t;

/* Owner-thread state for an accepted TCP connection before and after upgrade
 * Objects remain stable until the server finishes processing its current poll snapshot */
typedef struct ws_connection {
    struct ws_connection* next;
    server_context_t* server;
    int fd;
    uint64_t id;
    int opened;
    int closing;
    int close_after_write;
    int dead;
    int peer_closed;
    uint32_t reported_code;
    uint8_t reported_reason[123];
    size_t reported_reason_length;
    uint64_t created_ms;
    uint64_t last_read_ms;
    uint64_t last_write_ms;
    uint64_t close_started_ms;
    char* handshake;
    size_t handshake_length;
    size_t handshake_capacity;
    ws_frame_parser_t parser;
    ws_write_item_t* write_head;
    ws_write_item_t* write_tail;
    /* Wire bytes remaining and total retained allocation cost serve different purposes */
    uint64_t queued_bytes;
    uint64_t buffered_bytes;
} ws_connection_t;

/* Internal lifecycle entry points owned by the server, including the accepted descriptor */
ws_connection_t* ws_connection_create(server_context_t* server, int fd,
                                      uint64_t id, uint64_t now);
void ws_connection_destroy(ws_connection_t* connection);
/* send takes ownership only on success while close always borrows its input reason */
int32_t ws_connection_send(ws_connection_t* connection, uint8_t* data,
                           uint64_t length, int32_t kind);
int32_t ws_connection_close(ws_connection_t* connection, uint32_t code,
                            const uint8_t* reason, size_t length);
/* Service readiness with bounded I/O work so one client cannot monopolize the loop */
void ws_connection_read(ws_connection_t* connection, uint64_t now);
void ws_connection_write(ws_connection_t* connection, uint64_t now);
/* Timeouts use monotonic milliseconds and UINT64_MAX represents no active deadline */
void ws_connection_tick(ws_connection_t* connection, uint64_t now);
uint64_t ws_connection_deadline(const ws_connection_t* connection);

#endif
