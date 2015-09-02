/*
 * The MIT License (MIT)
 *
 * Copyright 2015 Sony Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/** @file */
#ifndef WS_HANDSHAKE_H_
#define WS_HANDSHAKE_H_

#include <stdint.h>

#include "http_parser.h"
#include "websocket/buffer.h"

/*
 * Header Fields
 * ref: http://en.wikipedia.org/wiki/List_of_HTTP_header_fields
 * ref: https://tools.ietf.org/html/rfc6455
 */
#define WSHS_HF_ACCEPT_CHARSET		"Accept-Charset"
#define WSHS_HF_ACCEPT_ENCODING		"Accept-Encoding"
#define WSHS_HF_ACCEPT_LANGUAGE		"Accept-Language"
#define WSHS_HF_AUTHORIZATION		"Authorization"
#define WSHS_HF_CONNECTION		"Connection"
#define WSHS_HF_COOKIE			"Cookie"
#define WSHS_HF_DATA			"Date"
#define WSHS_HF_HOST			"Host"
#define WSHS_HF_ORIGIN			"Origin"
#define WSHS_HF_REFERER			"Referer"
#define WSHS_HF_SEC_WEBSOCKET_ACCEPT	"Sec-WebSocket-Accept"
#define WSHS_HF_SEC_WEBSOCKET_KEY	"Sec-WebSocket-Key"
#define WSHS_HF_SEC_WEBSOCKET_PROTOCOL	"Sec-WebSocket-Protocol"
#define WSHS_HF_SEC_WEBSOCKET_VERSION	"Sec-WebSocket-Version"
#define WSHS_HF_SET_COOKIE		"Set-Cookie"
#define WSHS_HF_SERVER			"Server"
#define WSHS_HF_USER_AGENT		"User-Agent"
#define WSHS_HF_UPGRADE			"Upgrade"
#define WSHS_HF_WWW_AUTHENTICATE	"WWW-Authenticate"

#define WSHS_RESPONSE_MAP(XX)                              \
  XX(101, SUCCESS,               "Switching Protocols")    \
  XX(400, BAD_REQUEST,           "Bad Request")            \
  XX(401, UNAUTHORIZED,          "Unauthorized")           \
  XX(403, FORBIDDEN,             "Forbidden")              \
  XX(404, NOT_FOUND,             "Not Found")              \
  XX(405, METHOD_NOT_ALLOWED,    "Method Not Allowed")     \
  XX(500, INTERNAL_SERVER_ERROR, "Internal Server Error")  \
  XX(503, SERVICE_UNAVAILABLE,   "Service UnAvailable")

#ifdef __cplusplus
extern "C" {
#endif

enum ws_handshake_response_code {
#define XX(num, name, string) WSHS_##name = num,
  WSHS_RESPONSE_MAP(XX)
#undef XX
  WSHS_RESPONSE_MAX
};

typedef struct _ws_handshake_url {
  buffer raw;
  uint16_t port;
  uint16_t field_set;
  buffer field_value[UF_MAX];
} ws_handshake_url;

typedef struct _ws_handshake_request {
  ws_handshake_url url;
  buffer_kvs headers;
} ws_handshake_request;

typedef struct _ws_handshake_response {
  enum ws_handshake_response_code code;
  buffer_kvs headers;
} ws_handshake_response;

enum ws_handshake_state {
  WSHS_COMPLETE =  0,
  WSHS_CONTINUE =  1
};

enum ws_handshake_type {
  WSHS_CLIENT = 0,
  WSHS_SERVER = 1
};

typedef struct _ws_handshake {
  enum ws_handshake_state state;
  enum ws_handshake_type type;
  ws_handshake_request request;
  ws_handshake_response response;
  int err;
  http_parser parser;
  void *data;
} ws_handshake;

typedef void (*ws_handshake_cb)(ws_handshake *handshake);

typedef struct _ws_handshake_settings {
  ws_handshake_cb on_complete;
  ws_handshake_cb on_error;
} ws_handshake_settings;

WS_EXTERN int ws_handshake_is_ipv6(const char *s);
WS_EXTERN void ws_handshake_init(ws_handshake *handshake, enum ws_handshake_type type);
WS_EXTERN void ws_handshake_fin(ws_handshake *handshake);
WS_EXTERN size_t ws_handshake_execute(ws_handshake *handshake, ws_handshake_settings *settings,
                                      const char *p, size_t siz);
WS_EXTERN int ws_handshake_create_request(ws_handshake *handshake, buffer *request);
WS_EXTERN int ws_handshake_create_response(ws_handshake *handshake, buffer *response);

#ifdef __cplusplus
}
#endif

#endif  /* WS_HANDSHAKE_H_ */
