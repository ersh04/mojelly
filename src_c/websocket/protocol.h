#ifndef WS_PROTOCOL_H
#define WS_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include "bridge.h"

/* Incremental parser state for exactly one connection
 * The base header, extended length and mask may arrive in different TCP reads
 * Application fragments share a bounded reusable buffer while control frames use fixed storage */
typedef struct {
    uint8_t header[14];
    size_t header_length;
    size_t header_needed;
    int header_ready;
    uint64_t payload_length;
    uint64_t payload_read;
    uint8_t mask[4];
    uint8_t opcode;
    int final;
    uint8_t control[125];
    uint8_t* message;
    size_t message_length;
    size_t message_capacity;
    uint8_t fragment_kind;
    uint64_t max_message_size;
} ws_frame_parser_t;

/* The handler borrows parser storage until return and can stop consumption with WS_CLOSING */
typedef int32_t (*ws_frame_handler_t)(void* context, uint8_t opcode,
                                     const uint8_t* data, size_t length);

/* Initialize and eventually release all connection-local parser allocations */
void ws_frame_init(ws_frame_parser_t* parser, uint64_t max_message_size);
void ws_frame_destroy(ws_frame_parser_t* parser);
/* Feed arbitrary TCP chunks and return a local status plus a protocol Close code on failure */
int32_t ws_frame_feed(ws_frame_parser_t* parser, const uint8_t* data,
                      size_t length, ws_frame_handler_t handler, void* context,
                      uint32_t* close_code);
/* Write an unmasked final server header into an output buffer of at least ten bytes */
size_t ws_frame_header(uint8_t output[10], uint8_t opcode, uint64_t length);
/* Validate whole strings and distinguish sendable Close codes from local reporting codes */
int ws_valid_utf8(const uint8_t* data, size_t length);
int ws_valid_close_code(uint32_t code);

/* Parse and mutate a bounded complete HTTP opening header
 * The request buffer needs one writable terminator byte after length
 * Return an HTTP status and populate accept_value only for a successful 101 */
int ws_handshake(char* request, size_t length, const char* path,
                 const char* allowed_origin, char accept_value[29]);

#endif
