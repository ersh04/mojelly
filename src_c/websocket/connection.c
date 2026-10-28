#define _POSIX_C_SOURCE 200809L
#include "server_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define WS_IO_BUDGET (64 * 1024)

/* Report failures only for upgraded connections known to the application
 * Handshake failures are reported through HTTP responses instead of WebSocket events */
void ws_connection_error(ws_connection_t* connection, int32_t status,
                          const char* message) {
    if (connection->opened) {
        /* Forward only a borrowed diagnostic view and its byte length
         * The bridge delivers it synchronously while this string is still available */
        (void)ws_emit_error(connection->server->bridge, connection->id, status,
                            (const uint8_t*)message, strlen(message));
    }
}

/* Create connection-local parser and timing state without taking any shared locks
 * The caller retains the accepted descriptor if allocation fails */
ws_connection_t* ws_connection_create(server_context_t* server, int fd,
                                      uint64_t id, uint64_t now) {
    /* Allocate connection-local state before taking responsibility for the accepted descriptor */
    ws_connection_t* connection = calloc(1, sizeof(*connection));
    if (connection == NULL) return NULL;
    connection->fd = fd;
    connection->id = id;
    connection->server = server;
    connection->created_ms = now;
    connection->last_read_ms = now;
    connection->last_write_ms = now;
    connection->reported_code = 1006;
    /* Initialize an incremental parser with the complete-message limit
     * It will retain partial headers and fragmented payloads across future recv calls */
    ws_frame_init(&connection->parser, server->config.max_message_size);
    return connection;
}

/* Close the descriptor and release every pending owned output buffer and parser allocation
 * The server must emit the final close event before entering this function */
void ws_connection_destroy(ws_connection_t* connection) {
    /* Release the socket before discarding queued work because this connection will never perform more I/O */
    close(connection->fd);
    ws_write_item_t* item = connection->write_head;
    /* Walk every unsent or partially sent output node and free the buffers whose ownership was accepted during enqueueing */
    while (item != NULL) {
        ws_write_item_t* next = item->next;
        free(item->data);
        free(item);
        item = next;
    }
    /* Release the parser buffer separately from the opening HTTP header because they have independent allocation lifetimes */
    ws_frame_destroy(&connection->parser);
    free(connection->handshake);
    free(connection);
}

/* Queue an owned buffer without flattening the frame header and payload into another copy
 * Account for retained allocations as well as wire bytes to bound tiny-message queues
 * Reserve a fixed extra budget for control frames under application backpressure */
static int32_t enqueue_owned(ws_connection_t* connection, uint8_t* data,
                              size_t length, uint8_t opcode, int raw) {
    uint8_t header[10];
    /* Build a frame header for WebSocket data and control messages
     * Raw HTTP responses already contain their wire header and must not receive a WebSocket prefix */
    size_t header_length = raw ? 0 : ws_frame_header(header, opcode, length);
    uint64_t bytes = (uint64_t)length + header_length;
    uint64_t limit = connection->server->config.max_queued_bytes;

    /* Allow a fixed control-frame reserve while charging both payload storage and node overhead against buffering limits */
    if (!raw && opcode >= 8) limit += 512;
    uint64_t cost = bytes + sizeof(ws_write_item_t);
    if (cost > limit || connection->buffered_bytes > limit - cost) {
        return WS_BACKPRESSURE;
    }
    /* Allocate metadata before taking ownership so any rejection leaves the original buffer with its caller */
    ws_write_item_t* item = calloc(1, sizeof(*item));
    if (item == NULL) return WS_NO_MEMORY;
    if (header_length != 0) memcpy(item->header, header, header_length);
    item->header_length = header_length;
    item->data = data;
    item->length = length;
    /* Append one complete write operation to preserve HTTP response and frame order
     * When an empty queue becomes active, start its write-progress timeout at the current monotonic time */
    if (connection->write_tail != NULL) connection->write_tail->next = item;
    else {
        connection->write_head = item;
        connection->last_write_ms = ws_now_ms();
    }
    connection->write_tail = item;
    connection->queued_bytes += bytes;
    connection->buffered_bytes += cost;
    return WS_OK;
}

/* Copy temporary handshake or control data before it leaves the current stack frame
 * Transfer the copy only after enqueue_owned succeeds */
static int32_t enqueue_copy(ws_connection_t* connection, const uint8_t* data,
                             size_t length, uint8_t opcode, int raw) {
    uint8_t* copy = NULL;
    /* Retain bytes that may come from a stack response or the parser scratch buffer
     * A zero-length payload needs no allocation */
    if (length != 0) {
        copy = malloc(length);
        if (copy == NULL) return WS_NO_MEMORY;
        memcpy(copy, data, length);
    }
    /* Transfer the new copy only if queue admission succeeds
     * Otherwise release it here because no transport node owns it */
    int32_t status = enqueue_owned(connection, copy, length, opcode, raw);
    if (status != WS_OK) free(copy);
    return status;
}

/* Accept application data only after upgrade and before closing begins
 * Text payloads must be valid UTF-8 before they can appear on the wire */
int32_t ws_connection_send(ws_connection_t* connection, uint8_t* data,
                           uint64_t length, int32_t kind) {
    if (connection->dead || !connection->opened) return WS_NOT_FOUND;
    if (connection->closing) return WS_CLOSING;
    /* Validate a complete outgoing text message after connection-state checks
     * Binary payloads intentionally bypass UTF-8 validation */
    if (kind == WS_TEXT && !ws_valid_utf8(data, (size_t)length)) {
        return WS_INVALID_ARGUMENT;
    }
    /* Accept the bridge-owned buffer directly to avoid another full-message copy in the socket layer */
    return enqueue_owned(connection, data, (size_t)length, (uint8_t)kind, 0);
}

/* Start an ordered Close handshake without freeing the connection immediately
 * Earlier queued frames retain their order and the close deadline bounds peer cooperation */
int32_t ws_connection_close(ws_connection_t* connection, uint32_t code,
                            const uint8_t* reason, size_t length) {
    if (connection->dead || !connection->opened) return WS_NOT_FOUND;
    if (connection->closing) return WS_CLOSING;
    /* Check the wire close code and reason together before constructing an otherwise valid control frame */
    if (!ws_valid_close_code(code) || length > 123 ||
        !ws_valid_utf8(reason, length)) return WS_INVALID_ARGUMENT;
    /* Prefix the UTF-8 reason with the two-byte close code in network byte order */
    uint8_t payload[125];
    payload[0] = (uint8_t)(code >> 8);
    payload[1] = (uint8_t)code;
    if (length != 0) memcpy(payload + 2, reason, length);
    /* Copy this stack payload into the ordered output queue before publishing the closing state */
    int32_t status = enqueue_copy(connection, payload, length + 2, 8, 0);
    if (status == WS_OK) {
        connection->closing = 1;
        /* Start the peer acknowledgement deadline only after the Close frame has actually been accepted into the queue */
        connection->close_started_ms = ws_now_ms();
    }
    return status;
}

/* Translate parser events into bridge messages or protocol control responses
 * A received Close stops parsing this read batch and is acknowledged at most once
 * When our Close was already flushed, its acknowledgement can finish immediately */
static int32_t handle_frame(void* context, uint8_t opcode,
                             const uint8_t* data, size_t length) {
    ws_connection_t* connection = context;
    if (opcode == 8) {
        connection->peer_closed = 1;
        /* Decode the peer status for the final application callback
         * An empty Close carries no code, so 1005 is a local reporting value and is not sent on the wire */
        connection->reported_code = length == 0 ? 1005 :
            ((uint32_t)data[0] << 8) | data[1];
        connection->reported_reason_length = length >= 2 ? length - 2 : 0;
        if (length > 2) memcpy(connection->reported_reason, data + 2, length - 2);
        if (!connection->closing) {
            /* Acknowledge an unsolicited Close using a copy of the already validated control payload */
            int32_t status = enqueue_copy(connection, data, length, 8, 0);
            if (status != WS_OK) connection->dead = 1;
            connection->closing = 1;
            connection->close_started_ms = ws_now_ms();
        }
        /* Stop consuming this read batch after Close and finish once pending output drains
         * If our own Close was already flushed, no extra write event is needed to complete the connection */
        connection->close_after_write = 1;
        if (connection->write_head == NULL) connection->dead = 1;
        return WS_CLOSING;
    }
    if (opcode == 9) {
        /* Answer Ping with an identical Pong payload without disturbing any unfinished application message */
        int32_t status = enqueue_copy(connection, data, length, 10, 0);
        if (status != WS_OK) {
            ws_connection_error(connection, status, "Cannot queue Pong");
            connection->dead = 1;
            return status;
        }
    } else if (opcode != 10 && !connection->closing) {
        /* Deliver only complete application messages while parser-owned bytes are still valid
         * After closing begins, incoming data messages are not passed to application handlers */
        (void)ws_emit_message(connection->server->bridge, connection->id,
                              data, length, opcode);
    }
    return connection->dead ? WS_CLOSING : WS_OK;
}

/* Queue either the opening 101 response or a bounded HTTP rejection without a body
 * Upgrade headers precede application frames because both use the same output queue */
static void http_response(ws_connection_t* connection, int status,
                           const char* accept_value) {
    char response[512];
    int length;
    if (status == 101) {
        /* Format the negotiated accept value into the opening response that precedes all queued WebSocket frames */
        length = snprintf(response, sizeof(response),
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept_value);
    } else {
        /* Select a bounded rejection response and advertise version 13 when the client offered an unsupported version */
        const char* phrase = status == 403 ? "Forbidden" : status == 404 ? "Not Found" :
            status == 408 ? "Request Timeout" : status == 426 ? "Upgrade Required" :
            status == 431 ? "Request Header Fields Too Large" : "Bad Request";
        length = snprintf(response, sizeof(response),
            "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n%s\r\n",
            status, phrase, status == 426 ? "Sec-WebSocket-Version: 13\r\n" : "");
        connection->close_after_write = 1;
    }
    /* Reject formatting failure or truncation before enqueue_copy reads the temporary buffer
     * Queue the HTTP response as raw bytes and terminate the connection if even that cannot be retained */
    if (length < 0 || (size_t)length >= sizeof(response) ||
        enqueue_copy(connection, (const uint8_t*)response, (size_t)length, 0, 1) != WS_OK) {
        connection->dead = 1;
    }
}

/* Accumulate a bounded HTTP header until its CRLF delimiter is complete
 * After upgrading, pass any bytes left in the same TCP read directly to the frame parser
 * Protocol failures queue a Close response and stop parsing untrusted trailing bytes */
static void feed_bytes(ws_connection_t* connection, const uint8_t* data, size_t length) {
    size_t offset = 0;
    while (!connection->opened && offset < length && !connection->close_after_write) {
        size_t maximum = connection->server->config.max_header_size;
        /* Enforce the opening-header budget before consuming another incoming byte or growing its allocation */
        if (connection->handshake_length == maximum) {
            http_response(connection, 431, NULL);
            return;
        }
        if (connection->handshake_length + 1 >= connection->handshake_capacity) {
            size_t capacity = connection->handshake_capacity == 0 ? 512 :
                connection->handshake_capacity * 2;
            if (capacity > maximum + 1) capacity = maximum + 1;
            /* Grow geometrically but retain one spare terminator byte for the in-place HTTP parser
             * A failed realloc leaves the old buffer available for final connection cleanup */
            char* buffer = realloc(connection->handshake, capacity);
            if (buffer == NULL) { connection->dead = 1; return; }
            connection->handshake = buffer;
            connection->handshake_capacity = capacity;
        }
        connection->handshake[connection->handshake_length++] = (char)data[offset++];
        size_t count = connection->handshake_length;
        /* Look for the complete HTTP header delimiter before calling any string-based parsing helper */
        if (count >= 4 && memcmp(connection->handshake + count - 4, "\r\n\r\n", 4) == 0) {
            char accept_value[29];
            /* Validate the completed request and derive its accept value, then queue either Upgrade or rejection */
            int status = ws_handshake(connection->handshake, count,
                connection->server->path, connection->server->allowed_origin, accept_value);
            http_response(connection, status, accept_value);
            /* The response owns its own bytes, so release the now-consumed request before notifying the application */
            free(connection->handshake);
            connection->handshake = NULL;
            connection->handshake_capacity = 0;
            if (status != 101 || connection->dead) return;
            connection->opened = 1;
            /* Publish the connection only after its Upgrade response is queued
             * Any frame sent by the callback will therefore appear after the HTTP header */
            (void)ws_emit_open(connection->server->bridge, connection->id, 1);
        } else if (count == maximum) {
            http_response(connection, 431, NULL);
            return;
        }
    }
    if (connection->opened && !connection->close_after_write && !connection->dead) {
        uint32_t close_code;
        /* Pass the unread suffix of this same TCP chunk to the frame parser
         * This preserves clients that send their first frame together with the opening request */
        int32_t status = ws_frame_feed(&connection->parser, data + offset, length - offset,
                                       handle_frame, connection, &close_code);
        if (status != WS_OK && status != WS_CLOSING) {
            /* Report local parsing failure separately from the protocol Close code chosen by the parser
             * Queue the failure response when possible and stop interpreting trailing untrusted bytes */
            ws_connection_error(connection, status, "Invalid WebSocket frame");
            if (connection->closing ||
                ws_connection_close(connection, close_code, NULL, 0) != WS_OK) {
                connection->dead = 1;
            }
            connection->close_after_write = 1;
        }
    }
}

/* Consume nonblocking reads with a per-iteration fairness budget
 * EINTR retries, EAGAIN yields to poll and EOF or hard errors terminate the connection */
void ws_connection_read(ws_connection_t* connection, uint64_t now) {
    uint8_t buffer[16384];
    size_t budget = WS_IO_BUDGET;
    while (budget != 0 && !connection->dead && !connection->close_after_write) {
        /* Read only as much as this iteration can fairly process without blocking the event loop */
        ssize_t count = recv(connection->fd, buffer,
                             budget < sizeof(buffer) ? budget : sizeof(buffer), 0);
        if (count > 0) {
            connection->last_read_ms = now;
            /* Feed exactly the bytes returned by recv because TCP chunks do not correspond to HTTP headers or WebSocket frame boundaries */
            feed_bytes(connection, buffer, (size_t)count);
            budget -= (size_t)count;
        } else if (count == 0) {
            connection->dead = 1;
        } else if (errno == EINTR) continue;
        else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        else {
            /* Report a hard receive failure before marking the object for deferred server-side removal */
            ws_connection_error(connection, WS_IO_ERROR, "Socket receive failed");
            connection->dead = 1;
        }
    }
}

/* Resume partial header and payload writes using independent offsets
 * Retain each complete allocation until its queue node is removed
 * MSG_NOSIGNAL keeps a disconnected client from terminating the process with SIGPIPE */
void ws_connection_write(ws_connection_t* connection, uint64_t now) {
    size_t budget = WS_IO_BUDGET;
    while (connection->write_head != NULL && budget != 0 && !connection->dead) {
        ws_write_item_t* item = connection->write_head;
        /* Resume the frame header first and then the payload using separate offsets
         * HTTP response nodes have no extra frame header and naturally enter the payload path */
        int writing_header = item->header_offset < item->header_length;
        size_t remaining = writing_header ? item->header_length - item->header_offset :
            item->length - item->offset;
        /* Remove a node only after both parts are fully written
         * Release its complete retained-allocation charge here rather than when individual bytes are sent */
        if (remaining == 0) {
            connection->write_head = item->next;
            if (connection->write_head == NULL) connection->write_tail = NULL;
            connection->buffered_bytes -= sizeof(*item) + item->length + item->header_length;
            free(item->data);
            free(item);
            continue;
        }
        const uint8_t* data = writing_header ? item->header + item->header_offset :
            item->data + item->offset;
        if (remaining > budget) remaining = budget;
        /* Attempt one nonblocking slice and suppress SIGPIPE if the peer has disconnected */
        ssize_t count = send(connection->fd, data, remaining, MSG_NOSIGNAL);
        if (count > 0) {
            if (writing_header) item->header_offset += (size_t)count;
            else item->offset += (size_t)count;
            /* Advance only by the actual send result and refresh the progress deadline
             * The remaining bytes stay queued when the kernel accepts less than requested */
            connection->queued_bytes -= (size_t)count;
            connection->last_write_ms = now;
            budget -= (size_t)count;
        } else if (count < 0 && errno == EINTR) continue;
        else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        else {
            /* Treat only hard errors as fatal while interrupted or temporarily blocked writes leave offsets intact */
            ws_connection_error(connection, WS_IO_ERROR, "Socket send failed");
            connection->dead = 1;
        }
    }
    /* Complete HTTP rejections and acknowledged Close handshakes only after their final queued bytes are gone */
    if (connection->close_after_write && connection->write_head == NULL) {
        connection->dead = 1;
    }
}

/* Represent disabled or overflowing deadlines as the largest possible timestamp */
static uint64_t deadline(uint64_t start, uint64_t timeout) {
    if (timeout == 0 || timeout > UINT64_MAX - start) return UINT64_MAX;
    return start + timeout;
}

/* Choose the earliest handshake, idle, close or write-progress deadline
 * A pending write must have a deadline even while an HTTP rejection is being drained */
uint64_t ws_connection_deadline(const ws_connection_t* connection) {
    const ws_server_config_t* config = &connection->server->config;
    uint64_t result = UINT64_MAX;
    /* Choose the lifecycle deadline appropriate to the current handshake, active or closing phase */
    if (!connection->opened && !connection->close_after_write) {
        result = deadline(connection->created_ms, config->handshake_timeout_ms);
    } else if (connection->closing) {
        result = deadline(connection->close_started_ms, config->close_timeout_ms);
    } else if (!connection->close_after_write) {
        result = deadline(connection->last_read_ms, config->read_timeout_ms);
    }
    /* Combine the lifecycle deadline with the next output-progress deadline so blocked writes are bounded in every phase */
    if (connection->write_head != NULL) {
        uint64_t write_deadline = deadline(connection->last_write_ms, config->write_timeout_ms);
        if (write_deadline < result) result = write_deadline;
    }
    return result;
}

/* Reject stalled handshakes, initiate idle closes and abort stalled writes or close handshakes
 * Timeout errors remain distinct from the close code observed from the peer */
void ws_connection_tick(ws_connection_t* connection, uint64_t now) {
    /* Avoid timeout side effects until the earliest deadline has actually expired */
    if (connection->dead || now < ws_connection_deadline(connection)) return;
    const ws_server_config_t* config = &connection->server->config;
    if (!connection->opened && !connection->close_after_write) {
        /* An incomplete HTTP request still needs an HTTP timeout response because no WebSocket session exists yet */
        http_response(connection, 408, NULL);
    } else if (connection->closing || connection->close_after_write ||
               (connection->write_head != NULL && config->write_timeout_ms != 0 &&
                now >= deadline(connection->last_write_ms, config->write_timeout_ms))) {
        /* Abort a stalled close or write instead of recursively starting another handshake that would also be unable to finish */
        ws_connection_error(connection, WS_TIMED_OUT, "Connection timed out");
        connection->dead = 1;
    } else {
        /* For a merely idle upgraded peer, report the timeout and attempt an orderly going-away Close before forced cleanup */
        ws_connection_error(connection, WS_TIMED_OUT, "Connection idle timeout");
        if (ws_connection_close(connection, 1001, NULL, 0) != WS_OK) connection->dead = 1;
    }
}
