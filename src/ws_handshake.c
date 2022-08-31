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

#include <assert.h>
#include <string.h>

#if defined(_WIN32)
# include <winsock2.h>
# include <Ws2tcpip.h>
#else
# include <sys/time.h>
# include <arpa/inet.h>
#endif

#ifdef WITH_SSL
# include <openssl/sha.h>
#else
# include "sha1.h"
# define SHA_DIGEST_LENGTH SHA1_DIGEST_LENGTH
#endif

#include "websocket/ws_handshake.h"

static int on_url(http_parser *p, const char *at, size_t length);
static int on_header_field(http_parser *p, const char *at, size_t length);
static int on_header_value(http_parser *p, const char *at, size_t length);
static int on_headers_complete(http_parser *p);
static int on_message_complete(http_parser *p);
static int create_accept_field_value(buffer *accept, const buffer *key);

static http_parser_settings http_settings;

int ws_handshake_is_ipv6(const char *s) {
  unsigned char buf[16]; /* 128bit */
#if defined(_WIN32)
  return (InetPton(AF_INET6, s, buf) == 1);
#else
  return (inet_pton(AF_INET6, s, buf) == 1);
#endif
}

int on_url(http_parser *p, const char *at, size_t length) {
  ws_handshake *handshake = (ws_handshake *)(p->data);
  ws_handshake_url *url = &handshake->request.url;
  if (buffer_append(&(url->raw), at, length) < 0) {
    handshake->err = WSHS_INTERNAL_SERVER_ERROR;
    return -1;
  }
  return 0;
}

int on_header_field(http_parser *p, const char *at, size_t length) {
  ws_handshake *handshake;
  buffer_kvs *headers;
  buffer_kv *kv;
  handshake = (ws_handshake *)(p->data);
  if (handshake->type == WSHS_SERVER) {
    headers = &handshake->request.headers;
  } else {
    headers = &handshake->response.headers;
  }
  kv = SLIST_GET_FIRST(headers, slist);
  if (SLIST_IS_EMPTY(headers, slist) || kv->val.len > 0) {
    buffer_kv new_kv;
    buffer_kv_init(&new_kv);
    if (buffer_kvs_insert(headers, &new_kv)) {
      handshake->err = WSHS_INTERNAL_SERVER_ERROR;
      return -1;
    }
    kv = SLIST_GET_FIRST(headers, slist);
  }
  if (buffer_append(&kv->key, at, length)) {
    handshake->err = WSHS_INTERNAL_SERVER_ERROR;
    return -1;
  }
  return 0;
}

int on_header_value(http_parser *p, const char *at, size_t length) {
  ws_handshake *handshake;
  buffer_kvs *headers;
  buffer_kv *kv;
  handshake = (ws_handshake *)(p->data);
  if (handshake->type == WSHS_SERVER) {
    headers = &handshake->request.headers;
  } else {
    headers = &handshake->response.headers;
  }
  kv = SLIST_GET_FIRST(headers, slist);
  if (buffer_append(&kv->val, at, length)) {
    handshake->err = WSHS_INTERNAL_SERVER_ERROR;
    return -1;
  }
  return 0;
}

static int create_request_url(ws_handshake_url *url) {
  struct http_parser_url u;
  enum http_parser_url_fields i;
  if (url->raw.len == 0) {
    return -1;
  }
  if (http_parser_parse_url(url->raw.ptr, url->raw.len, 0, &u)) {
    return -1;
  }
  for (i = UF_SCHEMA; i < UF_MAX; i = (enum http_parser_url_fields)(i + 1)) {
    if (u.field_set & (1 << i)) {
      url->field_set |= (1 << i);
      if (buffer_append(&url->field_value[i],
                        url->raw.ptr + u.field_data[i].off,
                        u.field_data[i].len) < 0) {
        return -1;
      }
    }
  }
  url->port = u.port;
  return 0;
}

int on_headers_complete(http_parser *p) {
  ws_handshake *handshake = (ws_handshake *)(p->data);
  if (handshake->type == WSHS_SERVER) {
    if (create_request_url(&handshake->request.url)) {
      handshake->err = WSHS_BAD_REQUEST;
      return -1;
    }
  } else {
    handshake->response.code = (enum ws_handshake_response_code)p->status_code;
    if (handshake->response.code != WSHS_SUCCESS) {
      return -1;
    }
  }
  return 0;
}

int on_message_complete(http_parser *p) {
  ws_handshake *handshake;
  buffer_kvs *headers;
  const buffer *value;
  handshake = (ws_handshake *)(p->data);
  if (handshake->type == WSHS_SERVER) {
    if (p->method != HTTP_GET) {
      handshake->err = WSHS_METHOD_NOT_ALLOWED;
      return -1;
    }
    headers = &handshake->request.headers;
    if (!buffer_kvs_case_find(headers, CONST_STRING(WSHS_HF_HOST))) {
      handshake->err = WSHS_BAD_REQUEST;
      return -1;
    }
    if (!buffer_kvs_case_find(headers, CONST_STRING(WSHS_HF_SEC_WEBSOCKET_KEY))) {
      handshake->err = WSHS_BAD_REQUEST;
      return -1;
    }
  } else {
    const buffer *key;
    buffer verify;
    headers = &handshake->response.headers;
    value = buffer_kvs_case_find(headers, CONST_STRING(WSHS_HF_SEC_WEBSOCKET_ACCEPT));
    if (!value) {
      handshake->err = WSHS_BAD_REQUEST;
      return -1;
    }
    key = buffer_kvs_case_find(&handshake->request.headers, CONST_STRING(WSHS_HF_SEC_WEBSOCKET_KEY));
    if (!key) {
      handshake->err = WSHS_INTERNAL_SERVER_ERROR;
      return -1;
    }
    buffer_init(&verify);
    if (create_accept_field_value(&verify, key)) {
      buffer_fin(&verify);
      handshake->err = WSHS_BAD_REQUEST;
      return -1;
    }
    if (value->len != verify.len || memcmp(value->ptr, verify.ptr, verify.len)) {
      buffer_fin(&verify);
      handshake->err = WSHS_BAD_REQUEST;
      return -1;
    }
    buffer_fin(&verify);
  }
  if (p->http_major != 1 || p->http_minor != 1) {
    handshake->err = WSHS_BAD_REQUEST;
    return -1;
  } 
  value = buffer_kvs_case_find(headers, CONST_STRING(WSHS_HF_CONNECTION));
  if (!value) {
    handshake->err = WSHS_BAD_REQUEST;
    return -1;
  }
  buffer_to_lower((buffer *)value); /* tolower(orig_header_val) */
  if (strstr(value->ptr, "upgrade") == NULL) { /* Connection: keep-alive, Upgrade */
    handshake->err = WSHS_BAD_REQUEST;
    return -1;
  }
  value = buffer_kvs_case_find(headers, CONST_STRING(WSHS_HF_UPGRADE));
  if (!value) {
    handshake->err = WSHS_BAD_REQUEST;
    return -1;
  }
  
#if defined(_WIN32)
  if (_stricmp(value->ptr, "websocket") != 0) { /* Upgrade: websocket */
#else
  if (strcasecmp(value->ptr, "websocket") != 0) {
#endif

    handshake->err = WSHS_BAD_REQUEST;
    return -1;
  }
  handshake->err = WSHS_SUCCESS;
  http_parser_pause(p, 1);
  return 0;
}

static void ws_handshake_url_init(ws_handshake_url *url) {
  enum http_parser_url_fields i;
  buffer_init(&url->raw);
  url->field_set = 0;
  url->port = 0;
  for (i = UF_SCHEMA; i < UF_MAX; i = (enum http_parser_url_fields)(i + 1)) {
    buffer_init(&url->field_value[i]);
  }
}

static void ws_handshake_url_fin(ws_handshake_url *url) {
  enum http_parser_url_fields i;
  buffer_fin(&url->raw);
  url->field_set = 0;
  url->port = 0;
  for (i = UF_SCHEMA; i < UF_MAX; i = (enum http_parser_url_fields)(i + 1)) {
    buffer_fin(&url->field_value[i]);
  }
}

static void ws_handshake_request_init(ws_handshake_request *request) {
  ws_handshake_url_init(&request->url);
  buffer_kvs_init(&request->headers);
}

static void ws_handshake_request_fin(ws_handshake_request *request) {
  ws_handshake_url_fin(&request->url);
  buffer_kvs_fin(&request->headers);
}

static void ws_handshake_response_init(ws_handshake_response *response) {
  response->code = WSHS_SERVICE_UNAVAILABLE;
  buffer_kvs_init(&response->headers);
}

static void ws_handshake_response_fin(ws_handshake_response *response) {
  buffer_kvs_fin(&response->headers);
}

void ws_handshake_init(ws_handshake *handshake, enum ws_handshake_type type) {
  assert(handshake);
  handshake->state = WSHS_CONTINUE;
  handshake->type = type;
  ws_handshake_request_init(&handshake->request);
  ws_handshake_response_init(&handshake->response);
  handshake->err = WSHS_BAD_REQUEST;
  if (type == WSHS_SERVER) {
    http_parser_init(&handshake->parser, HTTP_REQUEST);
  } else {
    http_parser_init(&handshake->parser, HTTP_RESPONSE);
  }
  handshake->parser.data = handshake;
  handshake->data = NULL;
  http_settings.on_message_begin = NULL;
  http_settings.on_url = on_url;
  http_settings.on_status = NULL;
  http_settings.on_header_field = on_header_field;
  http_settings.on_header_value = on_header_value;
  http_settings.on_headers_complete = on_headers_complete;
  http_settings.on_body = NULL;
  http_settings.on_message_complete = on_message_complete;
}

void ws_handshake_fin(ws_handshake *handshake) {
  assert(handshake);
  ws_handshake_request_fin(&handshake->request);
  ws_handshake_response_fin(&handshake->response);
  handshake->data = NULL;
}

size_t ws_handshake_execute(ws_handshake *handshake, ws_handshake_settings *settings,
                            const char *p, size_t siz) {
  size_t nparsed;
  assert(handshake && settings && p);
  if (handshake->state == WSHS_COMPLETE) {
    if (handshake->err == WSHS_SUCCESS) {
      settings->on_complete(handshake);
    } else {
      settings->on_error(handshake);
    }
    return 0;
  }
  nparsed = http_parser_execute(&handshake->parser, &http_settings, p, siz);
  if (HTTP_PARSER_ERRNO(&handshake->parser) != HPE_OK) {
    handshake->state = WSHS_COMPLETE;
  }
  if (handshake->state == WSHS_COMPLETE) {
    if (handshake->err == WSHS_SUCCESS) {
      settings->on_complete(handshake);
    } else {
      settings->on_error(handshake);
    }
  }
  return nparsed;
}

STATIC_INLINE int create_key_field_value(buffer *s) {
  if (buffer_fill_random(s, 16) != 0) {
    return -1;
  }
  return buffer_to_base64(s);
}

static int create_request_headers(ws_handshake_request *request) {
  enum header_flags {
    SEC_WEBSOCKET_VERSION = 0,
    SEC_WEBSOCKET_KEY = 1,
    CONNECTION = 2,
    UPGRADE = 3
  };
  uint16_t field_set = 0;
  buffer_kv kv;
  buffer_kvs *headers = &request->headers;

  buffer_kv_init(&kv);
  /* Sec-WebSocket-Version */
  if (!buffer_kvs_case_find(headers, CONST_STRING(WSHS_HF_SEC_WEBSOCKET_VERSION))) {
    field_set |= (1 << SEC_WEBSOCKET_VERSION);
  }
  if (!buffer_kvs_case_find(headers, CONST_STRING(WSHS_HF_SEC_WEBSOCKET_KEY))) {
    field_set |= (1 << SEC_WEBSOCKET_KEY);
  }
  if (!buffer_kvs_case_find(headers, CONST_STRING(WSHS_HF_CONNECTION))) {
    field_set |= (1 << CONNECTION);
  }
  if (!buffer_kvs_case_find(headers, CONST_STRING(WSHS_HF_UPGRADE))) {
    field_set |= (1 << UPGRADE);
  }
  if (field_set & (1 << SEC_WEBSOCKET_VERSION)) {
    if (buffer_append(&kv.key, CONST_STRING(WSHS_HF_SEC_WEBSOCKET_VERSION))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (buffer_append(&kv.val, "13", 2)) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (buffer_kvs_insert(headers, &kv)) {
      buffer_kv_fin(&kv);
      return -1;
    }
  }
  /* Sec-WebSocket-Key */
  if (field_set & (1 << SEC_WEBSOCKET_KEY)) {
    buffer_kv_reset(&kv);
    if (buffer_append(&kv.key, CONST_STRING(WSHS_HF_SEC_WEBSOCKET_KEY))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (create_key_field_value(&kv.val)) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (buffer_kvs_insert(headers, &kv)) {
      buffer_kv_fin(&kv);
      return -1;
    }
  }
  /* Connection */
  if (field_set & (1 << CONNECTION)) {
    buffer_kv_reset(&kv);
    if (buffer_append(&kv.key, CONST_STRING(WSHS_HF_CONNECTION))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (buffer_append(&kv.val, CONST_STRING("Upgrade"))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (buffer_kvs_insert(headers, &kv)) {
      buffer_kv_fin(&kv);
      return -1;
    }
  }
  /* Upgrade */
  if (field_set & (1 << UPGRADE)) {
    buffer_kv_reset(&kv);
    if (buffer_append(&kv.key, CONST_STRING(WSHS_HF_UPGRADE))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (buffer_append(&kv.val, CONST_STRING("websocket"))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (buffer_kvs_insert(headers, &kv)) {
      buffer_kv_fin(&kv);
      return -1;
    }
  }
  buffer_kv_fin(&kv);
  return 0;
}

int ws_handshake_create_request(ws_handshake *handshake, buffer *request) {
  buffer_kv *kv;
  assert(handshake && request);
  if (handshake->type == WSHS_CLIENT) {
    if (create_request_url(&handshake->request.url)) {
      return -1;
    }
    if (create_request_headers(&handshake->request)) {
      return -1;
    }
  }
  buffer_reset(request);
  if (buffer_append(request, CONST_STRING("GET "))) {
    return -1;
  }
  if (handshake->request.url.field_set & (1 << UF_PATH)) {
    if (buffer_append(request,
                      handshake->request.url.field_value[UF_PATH].ptr,
                      handshake->request.url.field_value[UF_PATH].len)) {
      return -1;
    }
  } else {
    if (buffer_append(request, CONST_STRING("/"))) {
      return -1;
    }
  }
  if (handshake->request.url.field_set & (1 << UF_QUERY)) {
    if (buffer_append(request, CONST_STRING("?"))) {
      return -1;
    }
    if (buffer_append(request,
                      handshake->request.url.field_value[UF_QUERY].ptr,
                      handshake->request.url.field_value[UF_QUERY].len)) {
      return -1;
    }
  }
  if (buffer_append(request, CONST_STRING(" HTTP/1.1\r\n"))) {
    return -1;
  }
  for (kv = SLIST_GET_FIRST(&handshake->request.headers, slist);
       kv;
       kv = SLIST_GET_NEXT(kv, entry)) {
    if (buffer_append(request, kv->key.ptr, kv->key.len)) {
      return -1;
    }
    if (buffer_append(request, CONST_STRING(": "))) {
      return -1;
    }
    if (buffer_append(request, kv->val.ptr, kv->val.len)) {
      return -1;
    }
    if (buffer_append(request, CONST_STRING("\r\n"))) {
      return -1;
    }
  }
  if (buffer_append(request, CONST_STRING("\r\n"))) {
    return -1;
  }
  return 0;
}

static int create_accept_field_value(buffer *accept, const buffer *key) {
  buffer tmp;
  SHA_CTX sha;
  unsigned char sha_digest[SHA_DIGEST_LENGTH];

  buffer_init(&tmp);
  if (buffer_append(&tmp, key->ptr, key->len)) {
    buffer_fin(&tmp);
    return -1;
  }

/* ref: https://tools.ietf.org/html/rfc6455 Sec.1.3 Opening Handshake */
#define	GUID	"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  if (buffer_append(&tmp, CONST_STRING(GUID))) {
    buffer_fin(&tmp);
    return -1;
  }
#undef GUID
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  SHA1_Init(&sha);
  SHA1_Update(&sha, (unsigned char*)tmp.ptr, tmp.len);
  SHA1_Final(sha_digest, &sha);
#pragma GCC diagnostic warning "-Wdeprecated-declarations"
  buffer_fin(&tmp);
  buffer_reset(accept);
  if (buffer_append(accept, (char*)&sha_digest[0], SHA_DIGEST_LENGTH)) {
    return -1;
  }
  return buffer_to_base64(accept);
}

static int create_response_headers(ws_handshake *handshake) {
  buffer_kv kv;
  buffer_kv_init(&kv);
  if (!buffer_kvs_case_find(&handshake->response.headers, CONST_STRING(WSHS_HF_SEC_WEBSOCKET_ACCEPT))) {
    const buffer *key;
    key = buffer_kvs_case_find(&handshake->request.headers, CONST_STRING(WSHS_HF_SEC_WEBSOCKET_KEY));
    if (!key) {
      buffer_kv_fin(&kv);
      return -1;
    }
    buffer_reset(&kv.key);
    if (buffer_append(&kv.key, CONST_STRING(WSHS_HF_SEC_WEBSOCKET_ACCEPT))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    buffer_reset(&kv.val);
    if (create_accept_field_value(&kv.val, key)) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (buffer_kvs_insert(&handshake->response.headers, &kv)) {
      buffer_kv_fin(&kv);
      return -1;
    }
  }
  if (!buffer_kvs_case_find(&handshake->response.headers, CONST_STRING(WSHS_HF_CONNECTION))) {
    buffer_reset(&kv.key);
    if (buffer_append(&kv.key, CONST_STRING(WSHS_HF_CONNECTION))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    buffer_reset(&kv.val);
    if (buffer_append(&kv.val, CONST_STRING("Upgrade"))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (buffer_kvs_insert(&handshake->response.headers, &kv)) {
      buffer_kv_fin(&kv);
      return -1;
    }
  }
  if (!buffer_kvs_case_find(&handshake->response.headers, CONST_STRING(WSHS_HF_UPGRADE))) {
    buffer_reset(&kv.key);
    if (buffer_append(&kv.key, CONST_STRING(WSHS_HF_UPGRADE))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    buffer_reset(&kv.val);
    if (buffer_append(&kv.val, CONST_STRING("websocket"))) {
      buffer_kv_fin(&kv);
      return -1;
    }
    if (buffer_kvs_insert(&handshake->response.headers, &kv)) {
      buffer_kv_fin(&kv);
      return -1;
    }
  }
  buffer_kv_fin(&kv);
  return 0;
}

int ws_handshake_create_response(ws_handshake *handshake, buffer *response) {
  const char *cptr;
  buffer_kv *kv;
  buffer_kv err;
  assert(handshake && response);
  buffer_reset(response);
  if (handshake->type == WSHS_SERVER) {
    if (handshake->response.code == WSHS_SUCCESS) {
      if (create_response_headers(handshake)) {
        return -1;
      }
    } else if (!buffer_kvs_case_find(&handshake->response.headers, CONST_STRING(WSHS_HF_CONNECTION))) {
      buffer_kv_init(&err);
      if (buffer_append(&err.key, CONST_STRING(WSHS_HF_CONNECTION))) {
        buffer_kv_fin(&err);
        return -1;
      }
      if (buffer_append(&err.val, CONST_STRING("close"))) {
        buffer_kv_fin(&err);
        return -1;
      }
      if (buffer_kvs_insert(&handshake->response.headers, &err)) {
        buffer_kv_fin(&err);
        return -1;
      }
      buffer_kv_fin(&err);
    }
  }

  if (buffer_append(response, CONST_STRING("HTTP/1.1 "))) {
    return -1;
  }

#define STATUS_TO_STRING(num, name, string)  case WSHS_##name : cptr = #num; break;
  switch(handshake->response.code) {
    WSHS_RESPONSE_MAP(STATUS_TO_STRING)
  default:
    cptr = "400";
    break;
  }
  if (buffer_append(response, cptr, strlen(cptr))) {
    return -1;
  }
#undef STATUS_TO_STRING

  if (buffer_append(response, CONST_STRING(" "))) {
    return -1;
  }

#define GET_STATUS_STRING(num, name, string) case WSHS_##name : cptr = string; break;
  switch(handshake->response.code) {
    WSHS_RESPONSE_MAP(GET_STATUS_STRING)
  default:
    cptr = "Bad Request";
    break;
  }
  if (buffer_append(response, cptr, strlen(cptr))) {
    return -1;
  }
#undef GET_STATUS_STRING

  if (buffer_append(response, CONST_STRING("\r\n"))) {
    return -1;
  }
  for (kv = SLIST_GET_FIRST(&handshake->response.headers, slist);
       kv;
       kv = SLIST_GET_NEXT(kv, entry)) {
    if (buffer_append(response, kv->key.ptr, kv->key.len)) {
      return -1;
    }
    if (buffer_append(response, CONST_STRING(": "))) {
      return -1;
    }
    if (buffer_append(response, kv->val.ptr, kv->val.len)) {
      return -1;
    }
    if (buffer_append(response, CONST_STRING("\r\n"))) {
      return -1;
    }
  }
  if (buffer_append(response, CONST_STRING("\r\n"))) {
    return -1;
  }
  return 0;
}
