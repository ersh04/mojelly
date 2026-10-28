#define _POSIX_C_SOURCE 200809L
#include "server_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Use a monotonic clock so wall-clock corrections cannot change timeout durations */
uint64_t ws_now_ms(void) {
    struct timespec now;
    /* Read the monotonic clock used by connection deadlines and convert its seconds and nanoseconds to milliseconds */
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

/* Preserve existing descriptor flags while enabling nonblocking I/O and close-on-exec
 * Any failure leaves cleanup to the caller that owns the descriptor */
static int set_nonblocking(int fd) {
    /* Read status flags and descriptor flags separately because nonblocking mode and close-on-exec use different flag sets */
    int flags = fcntl(fd, F_GETFL, 0);
    int descriptor_flags = fcntl(fd, F_GETFD, 0);
    return flags >= 0 && descriptor_flags >= 0 &&
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 &&
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0;
}

/* Restrict event-loop and lifetime operations to the creating thread
 * The command submission APIs intentionally use a separate thread-safe path */
static int32_t check_owner(const server_context_t* server) {
    if (server == NULL) return WS_INVALID_ARGUMENT;
    return pthread_equal(server->owner, pthread_self()) ? WS_OK : WS_WRONG_THREAD;
}

/* Resolve stable connection IDs only on the owner thread
 * Removed IDs are never reused during this server lifetime */
static ws_connection_t* find_connection(server_context_t* server, uint64_t id) {
    for (ws_connection_t* c = server->connections; c != NULL; c = c->next) {
        if (c->id == id && !c->dead) return c;
    }
    return NULL;
}

/* Adapt the bridge transport contract to a live connection queue
 * The connection takes the malloc buffer only when it accepts the complete message */
static int32_t transport_send(void* context, uint64_t id, uint8_t* data,
                               uint64_t length, int32_t kind) {
    /* Resolve the ID immediately before dispatch so a stale queued command cannot address a removed connection */
    ws_connection_t* connection = find_connection(context, id);
    return connection == NULL ? WS_NOT_FOUND :
        ws_connection_send(connection, data, length, kind);
}

/* Queue the Close frame and consume the bridge-owned reason only on success
 * On failure the bridge remains responsible for freeing the original reason */
static int32_t transport_close(void* context, uint64_t id, uint32_t code,
                                uint8_t* reason, uint64_t length) {
    ws_connection_t* connection = find_connection(context, id);
    /* Ask the connection to build and retain a complete Close payload before accepting the bridge reason buffer */
    int32_t status = connection == NULL ? WS_NOT_FOUND :
        ws_connection_close(connection, code, reason, (size_t)length);
    /* The connection retained its own control payload, so accepted bridge storage can be released
     * On rejection the bridge must remain responsible for this buffer */
    if (status == WS_OK) free(reason);
    return status;
}

/* Provide finite resource and progress limits for a standalone listener
 * Only the read inactivity timeout may be disabled with zero */
void ws_server_config_default(ws_server_config_t* config) {
    if (config == NULL) return;
    /* Clear optional policy pointers together with scalar fields before assigning explicit finite defaults */
    memset(config, 0, sizeof(*config));
    config->max_message_size = 1024 * 1024;
    config->max_queued_bytes = 4 * 1024 * 1024;
    config->max_connections = 1024;
    config->max_header_size = 16384;
    config->handshake_timeout_ms = 5000;
    config->read_timeout_ms = 60000;
    config->write_timeout_ms = 30000;
    config->close_timeout_ms = 1000;
}

/* Allocate the owner-thread context, poll storage, command mutex and wakeup pipe
 * Copy configuration and Origin policy, then create a bridge on the same thread
 * Every failure unwinds only resources that were initialized successfully */
int32_t ws_server_create(const ws_server_config_t* config,
                         const ws_callbacks_t* callbacks, void* application_context,
                         server_context_t** out_server) {
    if (out_server == NULL) return WS_INVALID_ARGUMENT;
    *out_server = NULL;
    ws_server_config_t defaults;
    /* Use local defaults when no configuration was supplied and check all limits before allocating storage */
    if (config == NULL) { ws_server_config_default(&defaults); config = &defaults; }
    if (config->max_message_size == 0 || config->max_message_size > SIZE_MAX - 512 ||
        config->max_queued_bytes < 512 || config->max_queued_bytes > SIZE_MAX - 512 ||
        config->max_connections == 0 || config->max_connections > 65535 ||
        config->max_header_size < 256 || config->max_header_size > 1024 * 1024 ||
        config->handshake_timeout_ms == 0 || config->write_timeout_ms == 0 ||
        config->close_timeout_ms == 0) return WS_INVALID_ARGUMENT;
    /* Create private zeroed state and invalid descriptor sentinels for safe constructor error cleanup */
    server_context_t* server = calloc(1, sizeof(*server));
    if (server == NULL) return WS_NO_MEMORY;
    server->owner = pthread_self();
    server->config = *config;
    server->listen_fd = server->wake_read_fd = server->wake_write_fd = -1;
    server->next_connection_id = 1;
    /* Reserve readiness entries and parallel connection pointers once
     * Two additional slots belong to the listening socket and wakeup pipe */
    server->poll_fds = calloc((size_t)config->max_connections + 2, sizeof(*server->poll_fds));
    server->poll_connections = calloc((size_t)config->max_connections + 2,
                                      sizeof(*server->poll_connections));
    /* Copy Origin policy because the caller may release its configuration after this call returns */
    if (config->allowed_origin != NULL) server->allowed_origin = strdup(config->allowed_origin);
    if (server->poll_fds == NULL || server->poll_connections == NULL ||
        (config->allowed_origin != NULL && server->allowed_origin == NULL)) {
        free(server->poll_fds); free(server->poll_connections);
        free(server->allowed_origin); free(server);
        return WS_NO_MEMORY;
    }
    server->config.allowed_origin = server->allowed_origin;
    /* Initialize synchronization before any producer can publish commands
     * Earlier failures use direct cleanup because there was no initialized mutex to destroy */
    if (pthread_mutex_init(&server->command_mutex, NULL) != 0) {
        free(server->poll_fds); free(server->poll_connections);
        free(server->allowed_origin); free(server);
        return WS_IO_ERROR;
    }
    int fds[2];
    /* Create a nonblocking notification channel
     * From this point the normal destroy path can safely unwind constructor failures */
    if (pipe(fds) != 0) { (void)ws_server_destroy(server); return WS_IO_ERROR; }
    server->wake_read_fd = fds[0]; server->wake_write_fd = fds[1];
    if (!set_nonblocking(fds[0]) || !set_nonblocking(fds[1])) {
        (void)ws_server_destroy(server); return WS_IO_ERROR;
    }
    /* Bind socket operations to a bridge created on the same owner thread as the event loop */
    ws_transport_t transport = {.send = transport_send, .close = transport_close};
    int32_t status = ws_bridge_create(server, &transport, application_context,
                                      callbacks, config->max_message_size, &server->bridge);
    if (status != WS_OK) { (void)ws_server_destroy(server); return status; }
    *out_server = server;
    return WS_OK;
}

/* Bind one numeric IPv4 or IPv6 address and one exact WebSocket path
 * Port zero requests an ephemeral port that ws_server_port reports after binding
 * The listener remains nonblocking and accepts upgrades independently of the HTTP backend */
int32_t ws_server_listen(server_context_t* server, const char* address,
                         uint32_t port, const char* path) {
    /* Validate lifecycle and ownership before allocating or publishing listener resources */
    int32_t status = check_owner(server);
    if (status != WS_OK) return status;
    if (server->in_poll || server->state != ST_INIT) return WS_BUSY;
    if (port > 65535 || path == NULL || path[0] != '/' ||
        strlen(path) >= server->config.max_header_size) return WS_INVALID_ARGUMENT;
    for (const unsigned char* p = (const unsigned char*)path; *p; p++) {
        if (*p <= 32 || *p >= 127 || *p == '?' || *p == '#') return WS_INVALID_ARGUMENT;
    }
    /* Retain the route independently of the temporary String or buffer supplied by the application */
    char* path_copy = strdup(path);
    if (path_copy == NULL) return WS_NO_MEMORY;
    char service[6];
    (void)snprintf(service, sizeof(service), "%u", port);
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
    /* Convert the numeric address and service into IPv4 or IPv6 socket addresses without performing DNS lookup */
    if (getaddrinfo(address == NULL ? "127.0.0.1" : address, service,
                    &hints, &addresses) != 0) {
        free(path_copy); return WS_INVALID_ARGUMENT;
    }
    int fd = -1;
    for (struct addrinfo* item = addresses; item != NULL; item = item->ai_next) {
        /* Try each returned address and discard its descriptor if configuration, binding or listening fails */
        fd = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (fd < 0) continue;
        int enabled = 1;
        /* Permit rebinding after a previous listener exits and keep descriptor setup on the nonblocking path */
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
        if (set_nonblocking(fd) && bind(fd, item->ai_addr, item->ai_addrlen) == 0 &&
            listen(fd, 128) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd < 0) { free(path_copy); return WS_IO_ERROR; }
    struct sockaddr_storage bound;
    socklen_t bound_length = sizeof(bound);
    /* Read the actual bound port so a port-zero caller can discover the selected listener address */
    if (getsockname(fd, (struct sockaddr*)&bound, &bound_length) != 0) {
        close(fd); free(path_copy); return WS_IO_ERROR;
    }
    server->port = bound.ss_family == AF_INET ?
        ntohs(((struct sockaddr_in*)&bound)->sin_port) :
        ntohs(((struct sockaddr_in6*)&bound)->sin6_port);
    server->path = path_copy;
    server->listen_fd = fd;
    server->state = ST_OPEN;
    /* Publish producer acceptance under the command mutex without overriding a concurrent stop request */
    pthread_mutex_lock(&server->command_mutex);
    server->accepting_commands = !server->stop_requested;
    pthread_mutex_unlock(&server->command_mutex);
    return WS_OK;
}

/* Expose the actual bound port to the owner thread, returning zero for invalid access */
uint32_t ws_server_port(const server_context_t* server) {
    return check_owner(server) == WS_OK ? server->port : 0;
}

/* Wake poll without holding the command mutex or sending application data through the pipe
 * EAGAIN means an existing wakeup is already pending, so no notification is lost */
static void wake_server(server_context_t* server) {
    const uint8_t value = 1;
    ssize_t result;
    /* Retry interrupted writes only
     * A full nonblocking pipe already contains a notification that will wake the polling thread */
    do { result = write(server->wake_write_fd, &value, 1); }
    while (result < 0 && errno == EINTR);

}

/* Bound cross-thread buffering by both payload size and command-node overhead
 * Copy caller data under the queue lock and wake the loop after publishing the node
 * A successful enqueue does not guarantee that the target connection still exists */
static int32_t enqueue_command(server_context_t* server, uint64_t id,
                                const uint8_t* data, uint64_t length,
                                int32_t kind, uint32_t code, int close_command) {
    uint64_t cost = sizeof(ws_command_t) + length;
    /* Serialize shutdown checks, memory-budget accounting and command publication as one queue operation */
    pthread_mutex_lock(&server->command_mutex);
    if (!server->accepting_commands || server->stop_requested) {
        pthread_mutex_unlock(&server->command_mutex); return WS_STOPPED;
    }
    uint64_t limit = server->config.max_queued_bytes;
    if (cost > limit || server->command_bytes > limit - cost) {
        pthread_mutex_unlock(&server->command_mutex); return WS_BACKPRESSURE;
    }
    /* Allocate both the command node and copied payload while holding the queue budget
     * On failure release temporary allocations before making the queue available to another producer */
    ws_command_t* command = calloc(1, sizeof(*command));
    uint8_t* copy = length == 0 ? NULL : malloc((size_t)length);
    if (command == NULL || (length != 0 && copy == NULL)) {
        free(command); free(copy);
        pthread_mutex_unlock(&server->command_mutex); return WS_NO_MEMORY;
    }
    if (length != 0) memcpy(copy, data, (size_t)length);
    command->data = copy; command->length = length;
    command->connection_id = id; command->kind = kind;
    command->close_code = code; command->close_command = close_command;
    /* Append to the FIFO in constant time to preserve each producer thread command order */
    if (server->command_tail != NULL) server->command_tail->next = command;
    else server->command_head = command;
    server->command_tail = command;
    server->command_bytes += cost;
    pthread_mutex_unlock(&server->command_mutex);
    /* Notify after unlocking and publishing the complete node
     * The pipe carries wakeups while the protected queue carries the actual commands */
    wake_server(server);
    return WS_OK;
}

/* Validate payload arguments before copying or examining text data
 * Owner-thread calls return the transport result directly
 * Other threads submit copied commands whose later failures become error events */
int32_t ws_server_send(server_context_t* server, uint64_t connection_id,
                       const uint8_t* data, uint64_t length, int32_t kind) {
    if (server == NULL || connection_id == 0 || (data == NULL && length != 0) ||
        (kind != WS_TEXT && kind != WS_BINARY)) return WS_INVALID_ARGUMENT;
    if (length > server->config.max_message_size || length > SIZE_MAX - 512) return WS_TOO_LARGE;
    /* Reject invalid text before either a synchronous transport call or an asynchronous handoff */
    if (kind == WS_TEXT && !ws_valid_utf8(data, (size_t)length)) return WS_INVALID_ARGUMENT;
    /* Owner-thread callers can use the bridge directly and receive the immediate connection lookup result */
    if (pthread_equal(server->owner, pthread_self())) {
        if (server->state != ST_OPEN) return WS_STOPPED;
        return ws_send(server->bridge, connection_id, data, length, kind);
    }
    /* Foreign callers must not inspect connections or write sockets
     * Queue an independent copy for later owner-thread lookup and execution */
    return enqueue_command(server, connection_id, data, length, kind, 0, 0);
}

/* Reject reserved close codes, oversized reasons and malformed UTF-8 before enqueueing
 * The same owner-thread versus queued-command distinction applies as for send */
int32_t ws_server_close(server_context_t* server, uint64_t connection_id,
                        uint32_t code, const uint8_t* reason, uint64_t reason_length) {
    if (server == NULL || connection_id == 0 || (reason == NULL && reason_length != 0) ||
        !ws_valid_close_code(code)) return WS_INVALID_ARGUMENT;
    if (reason_length > 123) return WS_TOO_LARGE;
    /* Validate the complete reason before any asynchronous handoff so invalid UTF-8 fails in the calling thread */
    if (!ws_valid_utf8(reason, (size_t)reason_length)) return WS_INVALID_ARGUMENT;
    /* Use the bridge directly only when already running on the event-loop thread */
    if (pthread_equal(server->owner, pthread_self())) {
        if (server->state != ST_OPEN) return WS_STOPPED;
        return ws_close(server->bridge, connection_id, code, reason, reason_length);
    }
    /* Represent a foreign-thread Close as an ordered command with a retained copy of its reason */
    return enqueue_command(server, connection_id, reason, reason_length, 0, code, 1);
}

/* Publish an idempotent shutdown request under the queue mutex and wake poll
 * This does not join producers or destroy descriptors and must not run in a signal handler */
int32_t ws_server_request_stop(server_context_t* server) {
    if (server == NULL) return WS_INVALID_ARGUMENT;
    /* Disable producer acceptance atomically with publication of the shutdown request */
    pthread_mutex_lock(&server->command_mutex);
    server->stop_requested = 1;
    server->accepting_commands = 0;
    pthread_mutex_unlock(&server->command_mutex);
    /* Interrupt an otherwise indefinite poll so the owner begins shutdown promptly */
    wake_server(server);
    return WS_OK;
}

/* Drain wakeup bytes, detach a bounded command batch and release the lock before callbacks
 * Callbacks may submit more work without deadlocking the queue
 * On shutdown discard pending application commands, stop accepting and close live peers */
static void drain_commands(server_context_t* server) {
    uint8_t bytes[256];
    ssize_t count;
    /* Empty accumulated notifications without assuming one wakeup byte corresponds to one command */
    do { count = read(server->wake_read_fd, bytes, sizeof(bytes)); }
    while (count > 0 || (count < 0 && errno == EINTR));
    /* Detach a complete FIFO batch under the mutex and unlock before dispatching callbacks or transport work */
    pthread_mutex_lock(&server->command_mutex);
    ws_command_t* command = server->command_head;
    server->command_head = server->command_tail = NULL;
    server->command_bytes = 0;
    int stopping = server->stop_requested;
    pthread_mutex_unlock(&server->command_mutex);
    while (command != NULL) {
        ws_command_t* next = command->next;
        if (!stopping && server->state == ST_OPEN) {
            /* Execute the retained command on the owner thread
             * The bridge makes a separate transport copy, allowing command storage to be released after dispatch */
            int32_t status = command->close_command ?
                ws_close(server->bridge, command->connection_id, command->close_code,
                          command->data, command->length) :
                ws_send(server->bridge, command->connection_id, command->data,
                         command->length, command->kind);
            if (status != WS_OK) {
                static const uint8_t message[] = "Queued WebSocket command failed";
                /* Report delayed execution failures through events because the producer has already received enqueue success */
                (void)ws_emit_error(server->bridge, command->connection_id, status,
                                    message, sizeof(message) - 1);
            }
        }
        /* Release detached command storage after either execution or cancellation without touching accepted transport buffers */
        free(command->data); free(command); command = next;
    }
    /* Check shutdown again because a callback may have requested stop while the detached batch was being processed */
    pthread_mutex_lock(&server->command_mutex);
    stopping = server->stop_requested;
    pthread_mutex_unlock(&server->command_mutex);
    if (stopping && server->state == ST_OPEN) {
        server->state = ST_CLOSING;
        /* Stop new accepts immediately while existing peers retain their descriptors for protocol shutdown */
        close(server->listen_fd); server->listen_fd = -1;
        /* Reject application commands but preserve final close and error notifications during draining */
        (void)ws_bridge_stop(server->bridge);
        /* Initiate server Close frames directly because the application bridge is now stopped
         * Unupgraded peers have no WebSocket handshake to complete and can be discarded immediately */
        for (ws_connection_t* c = server->connections; c != NULL; c = c->next) {
            if (!c->opened || (!c->closing && ws_connection_close(c, 1001, NULL, 0) != WS_OK)) {
                c->dead = 1;
            }
        }
    }
}

/* Unlink dead connections before notifying the application so stale IDs cannot resolve
 * Deliver the close event while its reason buffer is alive, then release all connection storage */
static void reap_connections(server_context_t* server) {
    ws_connection_t** cursor = &server->connections;
    while (*cursor != NULL) {
        ws_connection_t* connection = *cursor;
        if (!connection->dead) { cursor = &connection->next; continue; }
        /* Remove the ID from lookup before notifying application code so callbacks cannot send through a dead connection */
        *cursor = connection->next;
        server->connection_count--;
        if (connection->opened) {
            /* Keep the stored reason alive until the synchronous callback returns */
            (void)ws_emit_close(server->bridge, connection->id, connection->reported_code,
                                connection->reported_reason, connection->reported_reason_length);
        }
        /* Release descriptor, output buffers and parser state only after the final application notification */
        ws_connection_destroy(connection);
    }
    if (server->state == ST_CLOSING && server->connections == NULL) server->state = ST_CLOSED;
}

/* Limit accepts per iteration so a connection flood cannot starve existing peers
 * Apply descriptor flags and connection limits before adding a client to the owner list */
static void accept_connections(server_context_t* server, uint64_t now) {
    for (size_t budget = 0; budget < 64; budget++) {
        /* Accept only a bounded batch so a busy listener does not starve established clients */
        int fd = accept(server->listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        /* Enforce the descriptor limit and nonblocking setup before allocating per-connection storage */
        if (server->connection_count >= server->config.max_connections ||
            server->next_connection_id == 0 || !set_nonblocking(fd)) {
            close(fd); continue;
        }
        int enabled = 1;
        /* Disable Nagle buffering for interactive frames and initialize parser state with a never-reused connection ID */
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        ws_connection_t* connection = ws_connection_create(server, fd,
            server->next_connection_id++, now);
        /* Close the accepted descriptor here because failed allocation never transferred its ownership to a connection object */
        if (connection == NULL) { close(fd); continue; }
        connection->next = server->connections;
        server->connections = connection;
        server->connection_count++;
    }
}

/* Process commands and deadlines, then wait for descriptor readiness
 * Never recurse into the loop from an application callback
 * Keep connection objects alive until every entry in this poll snapshot has been processed */
int32_t ws_server_poll(server_context_t* server, int32_t timeout_ms) {
    /* Reject foreign-thread and recursive loop entries before mutating the poll snapshot */
    int32_t status = check_owner(server);
    if (status != WS_OK) return status;
    if (timeout_ms < -1) return WS_INVALID_ARGUMENT;
    if (server->in_poll || server->state == ST_INIT) return WS_BUSY;
    if (server->state == ST_CLOSED) return WS_STOPPED;
    server->in_poll = 1;
    /* Apply queued commands and expired deadlines before sleeping
     * Remove dead peers now so the readiness snapshot contains only live descriptors */
    drain_commands(server);
    uint64_t now = ws_now_ms();
    for (ws_connection_t* c = server->connections; c != NULL; c = c->next) ws_connection_tick(c, now);
    reap_connections(server);
    if (server->state == ST_CLOSED) { server->in_poll = 0; return WS_OK; }
    /* Reserve the first readiness entries for listener events and cross-thread notifications */
    size_t size = 2;
    server->poll_fds[0] = (struct pollfd){.fd = server->listen_fd, .events = POLLIN};
    server->poll_fds[1] = (struct pollfd){.fd = server->wake_read_fd, .events = POLLIN};
    int wait_ms = timeout_ms;
    for (ws_connection_t* c = server->connections; c != NULL; c = c->next) {
        /* Request write readiness only while output is queued so normally writable sockets cannot cause a busy loop */
        short events = c->close_after_write ? 0 : POLLIN;
        if (c->write_head != NULL) events |= POLLOUT;
        server->poll_fds[size] = (struct pollfd){.fd = c->fd, .events = events};
        server->poll_connections[size++] = c;
        /* Shorten the caller wait to the earliest deadline so timers still run when no socket traffic arrives */
        uint64_t due = ws_connection_deadline(c);
        uint64_t remaining = due > now ? due - now : 0;
        if (remaining < INT_MAX && (wait_ms < 0 || remaining < (uint64_t)wait_ms)) {
            wait_ms = (int)remaining;
        }
    }
    /* Wait for readiness or a deadline and refresh monotonic time before servicing the resulting batch */
    int result = poll(server->poll_fds, (nfds_t)size, wait_ms);
    now = ws_now_ms();
    if (result < 0 && errno != EINTR) {
        (void)ws_server_request_stop(server);
        status = WS_IO_ERROR;
    }
    if (result > 0) {
        /* Process wakeups first because a concurrent shutdown may invalidate the listener before its readiness is handled */
        if ((server->poll_fds[1].revents & POLLIN) != 0) drain_commands(server);
        if (server->state == ST_OPEN && (server->poll_fds[0].revents & POLLIN) != 0) {
            accept_connections(server, now);
        }
        /* Walk saved pointers instead of a connection list that callbacks or accepts may have changed
         * Connection objects are freed only after all snapshot entries have been examined */
        for (size_t i = 2; i < size; i++) {
            ws_connection_t* c = server->poll_connections[i];
            short events = server->poll_fds[i].revents;
            if (!c->dead && (events & POLLIN) != 0) ws_connection_read(c, now);
            if (!c->dead && (events & POLLOUT) != 0) ws_connection_write(c, now);
            if (!c->dead && (events & (POLLERR | POLLNVAL | POLLHUP)) != 0) c->dead = 1;
        }
    }
    /* Apply deadlines again after I/O and reap peers only when the readiness snapshot is no longer being used */
    for (ws_connection_t* c = server->connections; c != NULL; c = c->next) ws_connection_tick(c, now);
    reap_connections(server);
    server->in_poll = 0;
    return status;
}

/* Drive poll until all connections have drained after a stop request
 * Remember an I/O failure while allowing the normal shutdown cleanup path to finish */
int32_t ws_server_run(server_context_t* server) {
    int32_t status = check_owner(server);
    if (status != WS_OK) return status;
    if (server->in_poll || server->state == ST_INIT) return WS_BUSY;
    int32_t result = WS_OK;
    while (server->state != ST_CLOSED) {
        /* Let the polling helper calculate timer-aware waits instead of imposing an artificial polling interval */
        status = ws_server_poll(server, -1);
        if (status != WS_OK && status != WS_IO_ERROR) return status;
        /* Retain an I/O failure while allowing the stop request from poll to drain descriptors on subsequent iterations */
        if (status != WS_OK) result = status;
    }
    return result;
}

/* Release server resources only before listening or after the loop reaches its closed state
 * The application must join all command-producing threads before calling this function */
int32_t ws_server_destroy(server_context_t* server) {
    int32_t status = check_owner(server);
    if (status != WS_OK) return status;
    if (server->in_poll || (server->state != ST_INIT && server->state != ST_CLOSED)) return WS_BUSY;
    /* Destroy the bridge only after the lifecycle check guarantees there is no active event-loop callback */
    if (server->bridge != NULL) {
        (void)ws_bridge_stop(server->bridge);
        (void)ws_bridge_destroy(server->bridge);
    }
    /* Close initialized descriptors only so cleanup also works for a constructor that failed partway through setup */
    if (server->listen_fd >= 0) close(server->listen_fd);
    if (server->wake_read_fd >= 0) close(server->wake_read_fd);
    if (server->wake_write_fd >= 0) close(server->wake_write_fd);
    /* Free commands that never reached transport execution before destroying their mutex and private server allocations */
    ws_command_t* command = server->command_head;
    while (command != NULL) {
        ws_command_t* next = command->next;
        free(command->data); free(command); command = next;
    }
    pthread_mutex_destroy(&server->command_mutex);
    free(server->path); free(server->allowed_origin);
    free(server->poll_fds); free(server->poll_connections); free(server);
    return WS_OK;
}
