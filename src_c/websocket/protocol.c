#include "protocol.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Rotate a 32-bit SHA-1 word using shifts strictly between zero and the word width */
static uint32_t rotate_left(uint32_t value, unsigned int bits) {
    return (value << bits) | (value >> (32 - bits));
}

/* Hash the fixed 60-byte concatenation of the 24-character client key and 36-character GUID
 * SHA-1 padding expands this handshake input to exactly two 64-byte blocks
 * This helper exists only for the WebSocket opening protocol, not as a general crypto API */
static void handshake_digest(const char key[24], uint8_t digest[20]) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t input[128] = {0};
    uint32_t state[5] = {0x67452301, 0xefcdab89, 0x98badcfe,
                         0x10325476, 0xc3d2e1f0};
    /* Hash the original Base64 key text together with the protocol GUID
     * Decoding the client key first would produce a different accept value */
    memcpy(input, key, 24);
    memcpy(input + 24, guid, 36);
    /* Append SHA-1 padding and the original 480-bit length as a big-endian integer
     * The final two bytes encode 0x01e0 while the earlier length bytes remain zero */
    input[60] = 0x80;
    input[126] = 1;
    input[127] = 0xe0;
    for (size_t block = 0; block < 2; block++) {
        uint32_t words[80];
        /* Load each input block as sixteen big-endian words, independently of the host byte order */
        for (size_t i = 0; i < 16; i++) {
            const uint8_t* p = input + block * 64 + i * 4;
            words[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                       ((uint32_t)p[2] << 8) | p[3];
        }
        /* Expand the message schedule using the SHA-1 XOR and rotation recurrence before the compression rounds */
        for (size_t i = 16; i < 80; i++) {
            words[i] = rotate_left(words[i-3] ^ words[i-8] ^ words[i-14] ^
                                    words[i-16], 1);
        }
        uint32_t a = state[0], b = state[1], c = state[2];
        uint32_t d = state[3], e = state[4];
        /* Select the Boolean function and additive constant for each twenty-round phase
         * Unsigned word arithmetic supplies the required modulo-2^32 wrapping */
        for (size_t i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | (~b & d); k = 0x5a827999;
            } else if (i < 40) {
                f = b ^ c ^ d; k = 0x6ed9eba1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc;
            } else {
                f = b ^ c ^ d; k = 0xca62c1d6;
            }
            uint32_t next = rotate_left(a, 5) + f + e + k + words[i];
            e = d; d = c; c = rotate_left(b, 30); b = a; a = next;
        }
        /* Fold this block back into the running digest so the second block continues the first block state */
        state[0] += a; state[1] += b; state[2] += c;
        state[3] += d; state[4] += e;
    }
    /* Serialize the five state words as raw digest bytes rather than hexadecimal characters */
    for (size_t i = 0; i < 20; i++) {
        digest[i] = (uint8_t)(state[i / 4] >> (24 - (i % 4) * 8));
    }
}

static const char base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Decode one Base64 alphabet character while excluding padding and the string terminator */
static int base64_digit(char c) {
    if (c == '\0') return -1;
    /* Locate the character in the fixed alphabet and turn its position into the corresponding six-bit value */
    const char* p = strchr(base64, c);
    return p == NULL ? -1 : (int)(p - base64);
}

/* Require a canonical Base64 encoding of exactly 16 bytes
 * The final two padding characters and zero padding bits prevent ambiguous key encodings */
static int valid_key(const char* key) {
    /* Require the exact encoded width and padding expected for the sixteen-byte opening nonce */
    if (strlen(key) != 24 || key[22] != '=' || key[23] != '=') return 0;
    /* Reject characters outside the alphabet before relying on their numeric six-bit values */
    for (size_t i = 0; i < 22; i++) {
        if (base64_digit(key[i]) < 0) return 0;
    }
    /* Only two significant bits remain in the last encoded character
     * Its four unused low bits must therefore be zero */
    return (base64_digit(key[21]) & 15) == 0;
}

/* Encode the raw 20-byte digest as a 28-character Base64 value plus its terminator
 * The hexadecimal representation of SHA-1 must never be used for this response */
static void accept_key(const char* key, char output[29]) {
    uint8_t digest[20];
    /* Compute the raw SHA-1 digest that becomes Sec-WebSocket-Accept after Base64 encoding */
    handshake_digest(key, digest);
    size_t offset = 0;
    /* Convert each group of at most three digest bytes to four alphabet characters
     * Use padding for the final incomplete group and append a C terminator after the encoded value */
    for (size_t i = 0; i < 20; i += 3) {
        size_t remaining = 20 - i;
        uint32_t value = (uint32_t)digest[i] << 16;
        if (remaining > 1) value |= (uint32_t)digest[i + 1] << 8;
        if (remaining > 2) value |= digest[i + 2];
        output[offset++] = base64[(value >> 18) & 63];
        output[offset++] = base64[(value >> 12) & 63];
        output[offset++] = remaining > 1 ? base64[(value >> 6) & 63] : '=';
        output[offset++] = remaining > 2 ? base64[value & 63] : '=';
    }
    output[offset] = '\0';
}

/* Recognize ASCII HTTP field-name token characters without locale-dependent classification */
static int token_character(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           (c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

/* Match an HTTP comma-separated token case-insensitively after trimming optional whitespace */
static int has_token(const char* value, const char* token) {
    size_t token_length = strlen(token);
    while (*value != '\0') {
        /* Isolate one comma-delimited candidate and trim only optional HTTP whitespace around its boundaries */
        const char* end = strchr(value, ',');
        if (end == NULL) end = value + strlen(value);
        const char* start = value;
        while (start < end && (*start == ' ' || *start == '\t')) start++;
        const char* trimmed = end;
        while (trimmed > start && (trimmed[-1] == ' ' || trimmed[-1] == '\t')) {
            trimmed--;
        }
        /* Compare exact token lengths before the case-insensitive match so prefixes such as upgrade-extra are not accepted */
        if ((size_t)(trimmed - start) == token_length &&
            strncasecmp(start, token, token_length) == 0) return 1;
        value = *end == ',' ? end + 1 : end;
    }
    return 0;
}

/* Parse only a complete bounded HTTP/1.1 upgrade request and mutate its temporary buffer
 * Reject duplicate singleton headers, invalid framing and requests carrying an HTTP body
 * Negotiate no extensions or subprotocols and optionally enforce one exact Origin value */
int ws_handshake(char* request, size_t length, const char* path,
                 const char* allowed_origin, char accept_value[29]) {
    /* Verify the complete header delimiter and reject embedded NUL bytes before using any C string helper */
    if (length < 4 || memcmp(request + length - 4, "\r\n\r\n", 4) != 0 ||
        memchr(request, '\0', length) != NULL) return 400;
    request[length] = '\0';
    /* Split the request line into method, target and version in the owned temporary buffer
     * Replacing separators in place avoids allocating separate strings for each field */
    char* line_end = strstr(request, "\r\n");
    if (line_end == NULL) return 400;
    *line_end = '\0';
    char* target = strchr(request, ' ');
    if (target == NULL) return 400;
    *target++ = '\0';
    char* version = strchr(target, ' ');
    if (version == NULL) return 400;
    *version++ = '\0';
    if (strcmp(request, "GET") != 0 || strcmp(version, "HTTP/1.1") != 0 ||
        target[0] != '/') return 400;
    for (const unsigned char* p = (const unsigned char*)target; *p; p++) {
        if (*p <= 32 || *p >= 127 || *p == '#') return 400;
    }

    // Exclude the query suffix from exact route matching while leaving request validation separate
    char* query = strchr(target, '?');
    if (query != NULL) *query = '\0';


    /* Remember the route result but finish validating the opening request before choosing its HTTP response status */
    int matched_path = strcmp(target, path) == 0;
    char *key = NULL, *ws_version = NULL, *host = NULL, *origin = NULL;
    int connection_upgrade = 0, upgrade = 0, content_length_seen = 0;
    char* line = line_end + 2;
    while (*line != '\r') {
        /* Isolate a complete header field and validate its name as an HTTP token before interpreting the value */
        line_end = strstr(line, "\r\n");
        if (line_end == NULL) return 400;
        *line_end = '\0';
        char* colon = strchr(line, ':');
        if (colon == NULL || colon == line) return 400;
        for (char* p = line; p < colon; p++) {
            if (!token_character((unsigned char)*p)) return 400;
        }
        *colon = '\0';
        /* Trim surrounding optional whitespace and reject forbidden control characters before header-specific comparisons */
        char* value = colon + 1;
        while (*value == ' ' || *value == '\t') value++;
        char* end = line_end;
        while (end > value && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
        for (unsigned char* p = (unsigned char*)value; *p; p++) {
            if ((*p < 32 && *p != '\t') || *p == 127) return 400;
        }
        /* Recognize field names case-insensitively and reject duplicate singleton fields
         * Connection and Upgrade are token lists, while HTTP body framing is rejected for this opening request */
        if (strcasecmp(line, "Host") == 0) {
            if (host != NULL || *value == '\0') return 400;
            host = value;
        } else if (strcasecmp(line, "Connection") == 0) {
            connection_upgrade |= has_token(value, "upgrade");
        } else if (strcasecmp(line, "Upgrade") == 0) {
            upgrade |= has_token(value, "websocket");
        } else if (strcasecmp(line, "Sec-WebSocket-Key") == 0) {
            if (key != NULL) return 400;
            key = value;
        } else if (strcasecmp(line, "Sec-WebSocket-Version") == 0) {
            if (ws_version != NULL) return 400;
            ws_version = value;
        } else if (strcasecmp(line, "Origin") == 0) {
            if (origin != NULL) return 400;
            origin = value;
        } else if (strcasecmp(line, "Transfer-Encoding") == 0) {
            return 400;
        } else if (strcasecmp(line, "Content-Length") == 0) {
            if (content_length_seen || strcmp(value, "0") != 0) return 400;
            content_length_seen = 1;
        }
        line = line_end + 2;
    }
    /* Validate all required fields together and check the nonce shape before deriving any protocol response */
    if (host == NULL || !connection_upgrade || !upgrade || key == NULL ||
        !valid_key(key) || ws_version == NULL) return 400;
    if (strcmp(ws_version, "13") != 0) return 426;
    if (!matched_path) return 404;
    /* Apply the optional exact Origin policy after request validity, version and path checks have succeeded */
    if (allowed_origin != NULL &&
        (origin == NULL || strcmp(origin, allowed_origin) != 0)) return 403;
    /* Derive the accept value only for an otherwise accepted request
     * The caller will queue the 101 response before exposing the connection to application callbacks */
    accept_key(key, accept_value);
    return 101;
}

/* Validate a complete UTF-8 string including overlong encodings, surrogates and range limits
 * Fragmented text is assembled before this check so a code point may cross frame boundaries */
int ws_valid_utf8(const uint8_t* data, size_t length) {
    size_t i = 0;
    while (i < length) {
        uint32_t c = data[i++], minimum;
        size_t extra;
        if (c < 0x80) continue;
        /* Use the leading byte to choose the continuation count and minimum legal code point for this encoded width */
        if (c >= 0xc2 && c <= 0xdf) {
            c &= 0x1f; extra = 1; minimum = 0x80;
        } else if (c >= 0xe0 && c <= 0xef) {
            c &= 0x0f; extra = 2; minimum = 0x800;
        } else if (c >= 0xf0 && c <= 0xf4) {
            c &= 7; extra = 3; minimum = 0x10000;
        } else return 0;
        if (extra > length - i) return 0;
        /* Consume only continuation bytes after checking enough input remains for the complete sequence */
        while (extra-- != 0) {
            uint8_t next = data[i++];
            if ((next & 0xc0) != 0x80) return 0;
            c = (c << 6) | (next & 63);
        }
        /* Reject overlong forms, UTF-16 surrogate values and code points beyond the Unicode maximum */
        if (c < minimum || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) return 0;
    }
    return 1;
}

/* Allow defined protocol close codes and application or private-use codes
 * Local-only reporting codes such as 1005 and 1006 must never be sent on the wire */
int ws_valid_close_code(uint32_t code) {
    return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014) ||
           (code >= 3000 && code <= 4999);
}

/* Initialize a parser that starts by reading the two-byte base header
 * All parser state belongs to one connection and one event-loop thread */
void ws_frame_init(ws_frame_parser_t* parser, uint64_t max_message_size) {
    /* Clear partial-frame state and leave message storage unallocated until a validated frame needs it */
    memset(parser, 0, sizeof(*parser));
    parser->header_needed = 2;
    parser->max_message_size = max_message_size;
}

/* Release the reusable message buffer and invalidate all accumulated parser state */
void ws_frame_destroy(ws_frame_parser_t* parser) {
    /* Release the reusable assembly buffer once and reset pointers so no stale partial message remains visible */
    free(parser->message);
    memset(parser, 0, sizeof(*parser));
}

/* Encode a final, unmasked server frame with the shortest valid payload length encoding */
size_t ws_frame_header(uint8_t output[10], uint8_t opcode, uint64_t length) {
    /* Mark one final server frame and keep the mask bit clear because only client-to-server frames are masked */
    output[0] = (uint8_t)(0x80 | opcode);
    if (length < 126) {
        output[1] = (uint8_t)length;
        return 2;
    }
    /* Choose the shortest extended-length representation and write it most-significant byte first */
    size_t bytes = length <= 65535 ? 2 : 8;
    output[1] = bytes == 2 ? 126 : 127;
    for (size_t i = 0; i < bytes; i++) {
        output[2 + i] = (uint8_t)(length >> ((bytes - i - 1) * 8));
    }
    return 2 + bytes;
}

/* Keep the local operation status separate from the protocol Close code sent to the peer */
static int32_t frame_failure(uint32_t* code, uint32_t value) {
    *code = value;
    return WS_PROTOCOL_ERROR;
}

/* Reject unmasked client frames, reserved bits, unsupported opcodes and invalid fragmentation
 * Run as soon as two header bytes arrive rather than waiting for a mask or payload */
static int32_t check_frame_start(ws_frame_parser_t* parser, uint32_t* close_code) {
    uint8_t first = parser->header[0], second = parser->header[1];
    parser->opcode = first & 15;
    parser->final = (first & 0x80) != 0;
    int control = parser->opcode >= 8;
    /* Check reserved bits and client masking before accepting a payload
     * Control frames must be final and small, while data opcodes must agree with the current continuation state */
    if ((first & 0x70) != 0 || (second & 0x80) == 0 ||
        !(parser->opcode == 0 || parser->opcode == 1 || parser->opcode == 2 ||
          parser->opcode == 8 || parser->opcode == 9 || parser->opcode == 10) ||
        (control && (!parser->final || (second & 127) > 125)) ||
        (!control && ((parser->opcode == 0 && parser->fragment_kind == 0) ||
                      (parser->opcode != 0 && parser->fragment_kind != 0)))) {
        return frame_failure(close_code, 1002);
    }
    return WS_OK;
}

/* Decode extended lengths and reject nonminimal or signed 64-bit encodings
 * Check the whole fragmented-message limit before allocating payload storage
 * Control frames use a fixed 125-byte buffer and may interrupt a fragmented message */
static int32_t prepare_payload(ws_frame_parser_t* parser, uint32_t* close_code) {
    /* Reuse base-header validation once the complete header is available, then decode its extended length */
    int32_t status = check_frame_start(parser, close_code);
    if (status != WS_OK) return status;
    uint8_t second = parser->header[1];
    int control = parser->opcode >= 8;
    size_t extended = (second & 127) == 126 ? 2 : (second & 127) == 127 ? 8 : 0;
    uint64_t length = extended == 0 ? second & 127 : 0;
    for (size_t i = 0; i < extended; i++) length = (length << 8) | parser->header[2 + i];
    /* Reject longer-than-necessary encodings and the forbidden high bit of a 64-bit length before converting or allocating */
    if ((extended == 2 && length < 126) ||
        (extended == 8 && (length < 65536 || (length >> 63) != 0))) {
        return frame_failure(close_code, 1002);
    }
    /* Retain the frame-specific mask because its bytes may not be available in later TCP reads */
    memcpy(parser->mask, parser->header + 2 + extended, 4);
    if (!control) {
        /* Charge this fragment against the remaining complete-message budget, not merely its individual frame size */
        if (length > parser->max_message_size - parser->message_length ||
            length > SIZE_MAX - parser->message_length) {
            return frame_failure(close_code, 1009);
        }
        size_t needed = parser->message_length + (size_t)length;
        if (needed > parser->message_capacity) {
            size_t capacity = parser->message_capacity;
            if (capacity == 0) capacity = 256;
            while (capacity < needed) {
                if (capacity > SIZE_MAX / 2) { capacity = needed; break; }
                capacity *= 2;
            }
            if (capacity > parser->max_message_size) capacity = needed;
            /* Grow reusable message storage only after all length checks
             * On allocation failure preserve the old buffer for connection cleanup and report an internal-error Close code */
            uint8_t* message = realloc(parser->message, capacity);
            if (message == NULL) {
                *close_code = 1011;
                return WS_NO_MEMORY;
            }
            parser->message = message;
            parser->message_capacity = capacity;
        }
        /* Remember the first fragmented data opcode so continuation frames retain their text or binary interpretation */
        if (parser->opcode != 0 && !parser->final) parser->fragment_kind = parser->opcode;
    }
    parser->payload_length = length;
    parser->payload_read = 0;
    parser->header_ready = 1;
    return WS_OK;
}

/* Validate control payloads or deliver a complete application message
 * Preserve fragment state across Ping and Pong, then reset it only after the final data frame */
static int32_t finish_frame(ws_frame_parser_t* parser, ws_frame_handler_t handler,
                            void* context, uint32_t* close_code) {
    int32_t status = WS_OK;
    if (parser->opcode >= 8) {
        size_t length = (size_t)parser->payload_length;
        if (parser->opcode == 8) {
            if (length == 1) return frame_failure(close_code, 1002);
            if (length >= 2) {
                uint32_t code = ((uint32_t)parser->control[0] << 8) | parser->control[1];
                /* Validate the decoded wire status separately from the UTF-8 reason
                 * Reserved reporting codes cause a protocol error and malformed reasons cause invalid-payload closure */
                if (!ws_valid_close_code(code)) return frame_failure(close_code, 1002);
                if (!ws_valid_utf8(parser->control + 2, length - 2)) {
                    return frame_failure(close_code, 1007);
                }
            }
        }
        /* Borrow fixed control storage for synchronous Ping, Pong or Close handling without disturbing data-fragment accumulation */
        status = handler(context, parser->opcode, parser->control, length);
    } else if (parser->final) {
        uint8_t kind = parser->opcode == 0 ? parser->fragment_kind : parser->opcode;
        /* Validate text only after final reassembly because one Unicode code point may span multiple frames */
        if (kind == WS_TEXT && !ws_valid_utf8(parser->message, parser->message_length)) {
            return frame_failure(close_code, 1007);
        }
        /* Deliver the completed borrowed message before resetting its length
         * A response must be copied by the bridge before this buffer is reused */
        status = handler(context, kind, parser->message, parser->message_length);
        parser->message_length = 0;
        parser->fragment_kind = 0;
    }
    /* Return to base-header collection for the next frame while keeping the reusable allocation */
    parser->header_length = 0;
    parser->header_needed = 2;
    parser->header_ready = 0;
    return status;
}

/* Consume any TCP chunk while retaining incomplete headers, masks and payloads
 * Unmask with the absolute payload offset so masks stay aligned across reads
 * A callback may stop consumption after a Close without treating remaining bytes as a new frame */
int32_t ws_frame_feed(ws_frame_parser_t* parser, const uint8_t* data,
                      size_t length, ws_frame_handler_t handler, void* context,
                      uint32_t* close_code) {
    *close_code = 1002;
    size_t offset = 0;
    while (offset < length || (parser->header_ready &&
                               parser->payload_read == parser->payload_length)) {
        if (!parser->header_ready) {
            size_t count = parser->header_needed - parser->header_length;
            if (count > length - offset) count = length - offset;
            /* Retain just the missing header bytes and stop if this TCP chunk does not complete the current header stage */
            memcpy(parser->header + parser->header_length, data + offset, count);
            parser->header_length += count;
            offset += count;
            if (parser->header_length < parser->header_needed) break;
            if (parser->header_needed == 2) {
                /* Reject a malformed two-byte prefix immediately instead of waiting for an impossible mask or payload */
                int32_t status = check_frame_start(parser, close_code);
                if (status != WS_OK) return status;
                uint8_t size = parser->header[1] & 127;
                parser->header_needed = 2 + (size == 126 ? 2 : size == 127 ? 8 : 0) + 4;
                continue;
            }
            /* Once extended length and mask are present, validate the size and reserve bounded assembly storage */
            int32_t status = prepare_payload(parser, close_code);
            if (status != WS_OK) return status;
        }
        uint64_t remaining = parser->payload_length - parser->payload_read;
        size_t count = length - offset;
        if (remaining < count) count = (size_t)remaining;
        /* Unmask using this frame payload offset rather than the overall message offset
         * Control bytes go to fixed scratch storage while data fragments append to the shared message buffer */
        for (size_t i = 0; i < count; i++) {
            uint8_t value = data[offset + i] ^ parser->mask[(parser->payload_read + i) % 4];
            if (parser->opcode >= 8) parser->control[parser->payload_read + i] = value;
            else parser->message[parser->message_length + i] = value;
        }
        if (parser->opcode < 8) parser->message_length += count;
        parser->payload_read += count;
        offset += count;
        /* Finish both empty and nonempty frames as soon as all their payload bytes are consumed
         * Propagate callback stop results so trailing bytes after Close are not parsed as another message */
        if (parser->payload_read == parser->payload_length) {
            int32_t status = finish_frame(parser, handler, context, close_code);
            if (status != WS_OK) return status;
        }
    }
    return WS_OK;
}
