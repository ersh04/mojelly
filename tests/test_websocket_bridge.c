#include "../src_c/websocket/bridge.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ws_bridge_t* bridge;
    uint8_t* pending;
    uint64_t pending_length;
    int32_t transport_status;
    int send_calls;
    int close_calls;
    int open_events;
    int message_events;
    int close_events;
    int error_events;
    int stop_in_callback;
    int stop_in_transport;
} test_state_t;

static int32_t send_message(void* context, uint64_t id, uint8_t* data,
                             uint64_t length, int32_t kind) {
    test_state_t* state = context;
    assert(id == 42);
    assert(kind == WS_BINARY || kind == WS_TEXT);
    state->send_calls++;
    if (state->stop_in_transport) {
        assert(ws_bridge_stop(state->bridge) == WS_OK);
        assert(ws_bridge_destroy(state->bridge) == WS_BUSY);
    }
    if (state->transport_status != WS_OK) {
        return state->transport_status;
    }
    assert(state->pending == NULL);
    state->pending = data;
    state->pending_length = length;
    return WS_OK;
}

static int32_t close_connection(void* context, uint64_t id, uint32_t code,
                                uint8_t* reason, uint64_t length) {
    test_state_t* state = context;
    assert(id == 42 && code == 1000);
    state->close_calls++;
    if (state->transport_status != WS_OK) {
        return state->transport_status;
    }
    assert(state->pending == NULL);
    state->pending = reason;
    state->pending_length = length;
    return WS_OK;
}

static void on_open(void* context, uint64_t id, uint64_t route) {
    test_state_t* state = context;
    assert(id == 42 && route == 7);
    state->open_events++;
}

static void on_message(void* context, uint64_t id, const uint8_t* data,
                        uint64_t length, int32_t kind) {
    test_state_t* state = context;
    state->message_events++;
    /* Ответ из обработчика проверяет повторный вход и копирование
     * заимствованного входящего сообщения, включая нулевые байты. */
    assert(ws_send(state->bridge, id, data, length, kind) ==
           WS_OK);
    if (state->stop_in_callback) {
        assert(ws_bridge_stop(state->bridge) == WS_OK);
        assert(ws_bridge_destroy(state->bridge) == WS_BUSY);
    }
}

static void on_close(void* context, uint64_t id, uint32_t code,
                      const uint8_t* reason, uint64_t length) {
    test_state_t* state = context;
    assert(id == 42 && code == 1006 && reason == NULL && length == 0);
    state->close_events++;
}

static void on_error(void* context, uint64_t id, int32_t error,
                      const uint8_t* message, uint64_t length) {
    test_state_t* state = context;
    assert(id == 42 && error == -123 && message == NULL && length == 0);
    state->error_events++;
}

static void release_pending(test_state_t* state) {
    free(state->pending);
    state->pending = NULL;
    state->pending_length = 0;
}

static void* check_wrong_thread(void* context) {
    test_state_t* state = context;
    assert(ws_send(state->bridge, 42, NULL, 0, WS_TEXT) ==
           WS_WRONG_THREAD);
    assert(ws_close(state->bridge, 42, 1000, NULL, 0) ==
           WS_WRONG_THREAD);
    assert(ws_emit_open(state->bridge, 42, 7) == WS_WRONG_THREAD);
    assert(ws_emit_message(state->bridge, 42, NULL, 0,
                                   WS_BINARY) == WS_WRONG_THREAD);
    assert(ws_emit_close(state->bridge, 42, 1006, NULL, 0) ==
           WS_WRONG_THREAD);
    assert(ws_emit_error(state->bridge, 42, -123, NULL, 0) ==
           WS_WRONG_THREAD);
    assert(ws_bridge_stop(state->bridge) == WS_WRONG_THREAD);
    assert(ws_bridge_destroy(state->bridge) == WS_WRONG_THREAD);
    return NULL;
}

int main(void) {
    test_state_t state = {0};
    mojelly_ws_transport_t transport = {
        .send = send_message,
        .close = close_connection
    };
    mojelly_ws_callbacks_t callbacks = {
        .on_open = on_open,
        .on_message = on_message,
        .on_close = on_close,
        .on_error = on_error
    };
    assert(ws_bridge_create(&state, NULL, &state, &callbacks, 16,
                                     &state.bridge) == WS_INVALID_ARGUMENT);
    assert(state.bridge == NULL);
    assert(ws_bridge_create(&state, &transport, &state, &callbacks, 0,
                                     &state.bridge) == WS_INVALID_ARGUMENT);
    assert(ws_bridge_create(&state, &transport, &state, &callbacks, 16,
                                     NULL) == WS_INVALID_ARGUMENT);
    assert(ws_send(NULL, 42, NULL, 0, WS_TEXT) ==
           WS_INVALID_ARGUMENT);
    assert(ws_bridge_create(&state, &transport, &state, &callbacks, 16,
                                     &state.bridge) == WS_OK);
    /* Изменение исходных таблиц не должно менять уже созданный мост. */
    transport.send = NULL;
    callbacks.on_message = NULL;
    assert(ws_bridge_destroy(state.bridge) == WS_BUSY);

    uint8_t payload[] = {'a', 0, 'b'};
    assert(ws_send(state.bridge, 0, payload, 3, WS_BINARY) ==
           WS_INVALID_ARGUMENT);
    assert(ws_send(state.bridge, 42, NULL, 1, WS_BINARY) ==
           WS_INVALID_ARGUMENT);
    assert(ws_send(state.bridge, 42, payload, 3, 99) ==
           WS_INVALID_ARGUMENT);
    assert(ws_send(state.bridge, 42, payload, 17, WS_BINARY) ==
           WS_TOO_LARGE);
    assert(ws_close(state.bridge, 42, 65536, NULL, 0) ==
           WS_INVALID_ARGUMENT);
    assert(ws_close(state.bridge, 42, 1000, payload, 124) ==
           WS_TOO_LARGE);
    assert(state.send_calls == 0 && state.close_calls == 0);

    assert(ws_send(state.bridge, 42, payload, 3, WS_BINARY) ==
           WS_OK);
    assert(state.pending != payload && state.pending_length == 3);
    payload[0] = 'z';
    assert(memcmp(state.pending, "a\0b", 3) == 0);
    release_pending(&state);
    assert(ws_send(state.bridge, 42, NULL, 0, WS_TEXT) ==
           WS_OK);
    assert(state.pending == NULL && state.pending_length == 0);

    state.transport_status = WS_BACKPRESSURE;
    assert(ws_send(state.bridge, 42, payload, 3, WS_BINARY) ==
           WS_BACKPRESSURE);
    state.transport_status = WS_NOT_FOUND;
    assert(ws_close(state.bridge, 42, 1000, payload, 3) ==
           WS_NOT_FOUND);
    state.transport_status = WS_OK;
    assert(ws_close(state.bridge, 42, 1000, payload, 3) == WS_OK);
    payload[0] = 'x';
    assert(state.pending != payload && state.pending_length == 3);
    assert(memcmp(state.pending, "z\0b", 3) == 0);
    release_pending(&state);

    pthread_t worker;
    assert(pthread_create(&worker, NULL, check_wrong_thread, &state) == 0);
    assert(pthread_join(worker, NULL) == 0);
    assert(ws_emit_open(state.bridge, 42, 7) == WS_OK);
    assert(state.open_events == 1);
    state.stop_in_callback = 1;
    assert(ws_emit_message(state.bridge, 42, payload, 3,
                                   WS_BINARY) == WS_OK);
    assert(state.message_events == 1);
    payload[0] = 'y';
    assert(memcmp(state.pending, "x\0b", 3) == 0);
    release_pending(&state);
    assert(ws_send(state.bridge, 42, NULL, 0, WS_TEXT) ==
           WS_STOPPED);
    assert(ws_close(state.bridge, 42, 1000, NULL, 0) == WS_STOPPED);
    assert(ws_emit_open(state.bridge, 42, 7) == WS_STOPPED);
    assert(ws_emit_message(state.bridge, 42, NULL, 0,
                                   WS_TEXT) == WS_STOPPED);
    assert(ws_emit_error(state.bridge, 42, -123, NULL, 0) == WS_OK);
    assert(ws_emit_close(state.bridge, 42, 1006, NULL, 0) == WS_OK);
    assert(state.error_events == 1 && state.close_events == 1);
    assert(ws_bridge_stop(state.bridge) == WS_OK);
    assert(ws_bridge_destroy(state.bridge) == WS_OK);

    /* Без обработчиков мост остаётся пригоден для транспорта; защита
     * времени жизни действует и внутри самого транспортного вызова. */
    transport.send = send_message;
    state.stop_in_transport = 1;
    assert(ws_bridge_create(&state, &transport, &state, NULL, 16,
                                     &state.bridge) == WS_OK);
    assert(ws_emit_open(state.bridge, 42, 7) == WS_OK);
    assert(ws_emit_message(state.bridge, 42, payload, 3,
                                   WS_BINARY) == WS_OK);
    assert(ws_send(state.bridge, 42, payload, 3, WS_BINARY) ==
           WS_OK);
    release_pending(&state);
    assert(ws_bridge_destroy(state.bridge) == WS_OK);
    puts("Проверки WebSocket-моста пройдены.");
    return 0;
}
