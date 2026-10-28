#include "server.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

/* Signal handlers only publish this flag and never lock a mutex or invoke server APIs */
static volatile sig_atomic_t stop_requested;

/* Defer shutdown work to the main loop because server shutdown itself is not signal-safe */
static void stop_signal(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

/* Echo the borrowed event buffer through the copying send API
 * A rejected echo starts a Close handshake instead of growing an unbounded application queue */
static void on_message(void* context, uint64_t id, const uint8_t* data,
                        uint64_t length, int32_t kind) {
    server_context_t* server = *(server_context_t**)context;
    /* Send while the event bytes are still borrowed and valid
     * The native send function copies them before this callback returns */
    int32_t status = ws_server_send(server, id, data, length, kind);
    /* Start a bounded protocol close if echo admission fails instead of silently retaining data outside the server queue */
    if (status != WS_OK) (void)ws_server_close(server, id, 1011, NULL, 0);
}

/* Create and drive the native server on one thread with a bounded polling wait
 * The address of the local server handle remains a valid callback context until destruction */
int main(int argc, char** argv) {
    char* end = NULL;
    /* Parse the optional command-line port and retain the end pointer so trailing nonnumeric characters can be rejected */
    unsigned long port = argc > 1 ? strtoul(argv[1], &end, 10) : 9001;
    if (argc > 2 || port > 65535 || (argc > 1 && (*argv[1] == '\0' || *end != '\0'))) {
        fprintf(stderr, "Usage: %s [port]\n", argv[0]);
        return 1;
    }
    server_context_t* server = NULL;
    ws_callbacks_t callbacks = {.on_message = on_message};
    /* Create callbacks and event-loop state on the main thread
     * Use the address of the local handle as context so callbacks see the initialized server pointer */
    if (ws_server_create(NULL, &callbacks, &server, &server) != WS_OK) return 1;
    /* Bind the route only after construction succeeds and destroy the still-idle server if listening fails */
    if (ws_server_listen(server, "127.0.0.1", (uint32_t)port, "/ws") != WS_OK) {
        (void)ws_server_destroy(server);
        return 1;
    }
    /* Register flag-only signal handlers because the real stop request takes a mutex and belongs in normal control flow */
    (void)signal(SIGINT, stop_signal);
    (void)signal(SIGTERM, stop_signal);
    /* Discover the actual bound port and flush the address so a parent process can connect even when stdout is a pipe */
    printf("ws://127.0.0.1:%u/ws\n", ws_server_port(server));
    fflush(stdout);
    int32_t status;
    do {
        /* Convert a pending signal into a normal stop request, then keep polling until protocol shutdown has drained */
        if (stop_requested) (void)ws_server_request_stop(server);
        status = ws_server_poll(server, 100);
    } while (status == WS_OK);
    /* Release native resources after polling finishes and preserve both polling and cleanup failures in the process exit status */
    int32_t destroyed = ws_server_destroy(server);
    return status == WS_STOPPED && destroyed == WS_OK ? 0 : 1;
}
