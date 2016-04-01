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

#include "tv.h"
#include "internal.h"

static void tv__wss_start_client_handshake(tv_stream_t* ssl_handle, int status);
static void tv__wss_start_server_handshake(tv_stream_t* server, tv_stream_t* client, int status);
static void tv__wss_handshake_write_cb(tv_write_t* ssl_req, int status);
static void tv__wss_read_cb(tv_stream_t* ssl_handle, ssize_t nread, const tv_buf_t* buf);
static void tv__wss_write_cb(tv_write_t* ssl_req, int status);
static void tv__wss_timer_close_cb(tv_handle_t* handle);
static void tv__wss_close_cb(tv_handle_t* handle);
static void tv__wss_close_cb2(tv_handle_t* handle);
static void tv__wss_handle_error(tv_wss_t* handle, int err);

static void on_handshake_complete(ws_handshake* handshake) {
  tv_wss_t* handle = (tv_wss_t *)handshake->data;
  if (handle->is_server) {
    buffer response;
    tv_buf_t buf;
    tv_write_t* ssl_req;
    handle->is_accepted = 1;
    ssl_req = (tv_write_t *)malloc(sizeof(*ssl_req));
    if (ssl_req == NULL) {
      tv__ssl_close(handle->ssl_handle, tv__wss_close_cb2);
      tv__timer_close(handle->timer, tv__wss_timer_close_cb);
      return;
    }
    handle->listen_handle->handshake.response.code = (enum ws_handshake_response_code)handshake->err;
    handshake->response.code = (enum ws_handshake_response_code)handshake->err;
    if (handle->connection_cb != NULL) {
      handle->connection_cb((tv_stream_t*) handle->listen_handle, (tv_stream_t*) handle,
                            (handshake->response.code == WSHS_SUCCESS) ? 0 : TV_EWS);
    }
    if (uv_is_closing((uv_handle_t*) handle->ssl_handle->tv_handle->tcp_handle)) {
      free(ssl_req);
      return;
    }
    buffer_init(&response);
    if (ws_handshake_create_response(handshake, &response) != 0) {
      buffer_fin(&response);
      free(ssl_req);
      tv__wss_handle_error(handle, TV_ENOMEM);
      return;
    }
    buf.base = response.ptr; /* swap */
    buf.len = response.len;
    /* NOTE: no need to buffer_fin(&response); */
    ssl_req->data = handle;
    tv__ssl_write(ssl_req, handle->ssl_handle, buf, tv__wss_handshake_write_cb);
    if (handshake->response.code != WSHS_SUCCESS) {
      tv__wss_handle_error(handle, TV_EWS);
    }
  } else {
    handle->is_connected = (handshake->response.code == WSHS_SUCCESS);
    if (handle->connect_cb) {
      handle->connect_cb((tv_stream_t*) handle, (handle->is_connected) ? 0 : TV_EWS);
    }
  }
}
static ws_handshake_settings handshake_settings;
static void on_frame_complete(ws_frame* frame) {
  tv_wss_t* handle = (tv_wss_t *)frame->data;
  tv_buf_t buf;
  if (frame->err != WSFRM_NORMAL) {
    if (!handle->is_server) {
      buffer cls;
      tv_write_t* ssl_req = (tv_write_t*)malloc(sizeof(tv_write_t));
      if (ssl_req == NULL) {
        tv__wss_handle_error(handle, TV_EWS);
        return;
      }
      buffer_init(&cls);
      if (ws_frame_create(&cls, NULL, 0, WSFRM_CLOSE, (handle->is_server != 1))) {
        buffer_fin(&cls);
        free(ssl_req);
        tv__wss_handle_error(handle, TV_EWS);
        return;
      }
      buf.base = cls.ptr; /* swap */
      buf.len = cls.len;
      /* NOTE: no need to buffer_fin(&cls); */
      tv__ssl_write(ssl_req, handle->ssl_handle, buf, NULL);
    }
    tv__wss_handle_error(handle, TV_EWS);
    return;
  }
  switch(frame->header.type) {
  case WSFRM_TEXT:
  case WSFRM_BINARY:
    if (handle->read_cb != NULL && frame->payload.len > 0) {
      buf.base = (char *)malloc(frame->payload.len);
      if (buf.base == NULL) {
        tv__wss_handle_error(handle, TV_ENOMEM);
        break;
      }
      memcpy(buf.base, frame->payload.ptr, frame->payload.len);
      buf.len = frame->payload.len;
      handle->read_cb((tv_stream_t*) handle, frame->payload.len, &buf);
    }
    break;
  case WSFRM_PING: {
    buffer pong;
    tv_write_t* ssl_req = (tv_write_t*)malloc(sizeof(tv_write_t));
    if (ssl_req == NULL) {
      break; /* try next time */
    }
    buffer_init(&pong);
    if (ws_frame_create(&pong, frame->payload.ptr, frame->payload.len, WSFRM_PONG, (handle->is_server != 1))) {
      buffer_fin(&pong);
      free(ssl_req);
      break; /* try next time */
    }
    buf.base = pong.ptr; /* swap */
    buf.len = pong.len;
    /* NOTE: no need to buffer_fin(&pong); */
    tv__ssl_write(ssl_req, handle->ssl_handle, buf, NULL);
    break;
  }
  case WSFRM_PONG: {
    handle->drop_pong = 0;
    break;
  }
  case WSFRM_CLOSE:
    if (handle->read_cb != NULL) {
      handle->read_cb((tv_stream_t*) handle, TV_EWS, &buf);
    } else {
      tv__ssl_close(handle->ssl_handle, tv__wss_close_cb2);
      tv__timer_close(handle->timer, tv__wss_timer_close_cb);
    }
    break;
  }
}
static ws_frame_settings frame_settings;

int tv_wss_init(tv_loop_t* loop, tv_wss_t* handle, SSL_CTX* ssl_ctx) {
  int ret = 0;
  if ((loop == NULL) || (handle == NULL)) {
    return TV_EINVAL;
  }
  ret = tv_stream_init(TV_WSS, loop, (tv_stream_t*) handle);
  if (ret) {
    return ret;
  }
  handshake_settings.on_complete = on_handshake_complete;
  handshake_settings.on_error = on_handshake_complete;
  frame_settings.on_complete = on_frame_complete;
  frame_settings.on_error = on_frame_complete;
  ws_handshake_init(&handle->handshake, WSHS_CLIENT);
  ws_frame_init(&handle->frame, WSFRM_CLIENT);
  handle->timer = (tv_timer_t*)malloc(sizeof(tv_timer_t));
  ret = tv_timer_init(loop, handle->timer);
  if (ret) {
    tv_stream_destroy((tv_stream_t*) handle);
    return ret;
  }
  handle->is_timer_started = 0;
  handle->retry = 0;
  handle->drop_pong = 0;
  handle->listen_handle = NULL;
  handle->ssl_handle = NULL;
  handle->is_server = 0;
  handle->ssl_ctx = ssl_ctx;
  handle->handshake_complete_cb = NULL;
  return 0;
}
void tv__wss_connect(tv_wss_t* handle, const char* host, const char* port, tv_connect_cb connect_cb) {
  int ret = 0;
  tv_ssl_t* ssl_handle = NULL;
  buffer host_header_value;
  buffer origin_header_value;
  buffer_kv kv;
  int ipv6_flag = 0;
  handle->connect_cb = connect_cb;
  if (handle->is_connected) {
    tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_EISCONN);
    return;
  }
  ssl_handle = (tv_ssl_t*)malloc(sizeof(*ssl_handle));
  if (ssl_handle == NULL) {
    tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
    return;
  }
  ret = tv_ssl_init(handle->loop, ssl_handle, handle->ssl_ctx);
  assert(ret == 0);
  TV_UNUSED(ret);
  if (handle->handshake.request.url.raw.len == 0) {
    if (buffer_append(&handle->handshake.request.url.raw, CONST_STRING("/"))) {
      free(ssl_handle);
      tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
      return;
    }
  } else {
    ipv6_flag = ws_handshake_is_ipv6(host);
  }
  buffer_kv_init(&kv);
  if (!buffer_kvs_case_find(&handle->handshake.request.headers, CONST_STRING("Host"))) {
    buffer_init(&host_header_value);
    if (ipv6_flag) {
      if (buffer_append(&host_header_value, CONST_STRING("["))) {
        buffer_fin(&host_header_value);
        buffer_kv_fin(&kv);
        free(ssl_handle);
        tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
        return;
      }
    }
    if (buffer_append(&host_header_value, host, strlen(host))) {
      buffer_fin(&host_header_value);
      buffer_kv_fin(&kv);
      free(ssl_handle);
      tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
      return;
    }
    if (ipv6_flag) {
      if (buffer_append(&host_header_value, CONST_STRING("]"))) {
        buffer_fin(&host_header_value);
        buffer_kv_fin(&kv);
        free(ssl_handle);
        tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
        return;
      }
    }
    if (buffer_append(&host_header_value, CONST_STRING(":")) ||
        buffer_append(&host_header_value, port, strlen(port))) {
      buffer_fin(&host_header_value);
      buffer_kv_fin(&kv);
      free(ssl_handle);
      tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
      return;
    }
    if (buffer_append(&kv.key, CONST_STRING("Host")) ||
        buffer_append(&kv.val, host_header_value.ptr, host_header_value.len) ||
        buffer_kvs_insert(&handle->handshake.request.headers, &kv)) {
      buffer_fin(&host_header_value);
      buffer_kv_fin(&kv);
      free(ssl_handle);
      tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
      return;
    }
    buffer_fin(&host_header_value);
  }
  buffer_kv_reset(&kv);
  if (!buffer_kvs_case_find(&handle->handshake.request.headers, CONST_STRING("Origin"))) {
    buffer_init(&origin_header_value);
    if (buffer_append(&origin_header_value, CONST_STRING("https://"))) {
      buffer_fin(&origin_header_value);
      buffer_kv_fin(&kv);
      free(ssl_handle);
      tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
      return;
    }
    if (ipv6_flag) {
      if (buffer_append(&origin_header_value, CONST_STRING("["))) {
        buffer_fin(&origin_header_value);
        buffer_kv_fin(&kv);
        free(ssl_handle);
        tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
        return;
      }
    }
    if (buffer_append(&origin_header_value, host, strlen(host))) {
      buffer_fin(&origin_header_value);
      buffer_kv_fin(&kv);
      free(ssl_handle);
      tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
      return;
    }
    if (ipv6_flag) {
      if (buffer_append(&origin_header_value, CONST_STRING("]"))) {
        buffer_fin(&origin_header_value);
        buffer_kv_fin(&kv);
        free(ssl_handle);
        tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
        return;
      }
    }
    if (buffer_append(&origin_header_value, CONST_STRING(":")) ||
        buffer_append(&origin_header_value, port, strlen(port))) {
      buffer_fin(&origin_header_value);
      buffer_kv_fin(&kv);
      free(ssl_handle);
      tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
      return;
    }
    if (buffer_append(&kv.key, CONST_STRING("Origin")) ||
        buffer_append(&kv.val, origin_header_value.ptr, origin_header_value.len) ||
        buffer_kvs_insert(&handle->handshake.request.headers, &kv)) {
      buffer_fin(&origin_header_value);
      buffer_kv_fin(&kv);
      free(ssl_handle);
      tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
      return;
    }
    buffer_fin(&origin_header_value);
  }
  buffer_kv_fin(&kv);
  ssl_handle->data = handle;

  /* Copy handle->devname to lower transport */
  if (handle->devname != NULL) {
    size_t len;
   
    len = strlen(handle->devname) + 1;
    ssl_handle->devname = (char*)malloc(len);
    memset(ssl_handle->devname, 0, len);
    strncpy(ssl_handle->devname, handle->devname, len - 1);
  }

  handle->handshake.data = handle;
  handle->frame.data = handle;
  handle->ssl_handle = ssl_handle;
  tv__ssl_connect(ssl_handle, host, port, tv__wss_start_client_handshake);
}
static void tv__wss_start_client_handshake(tv_stream_t* ssl_handle, int status) {
  int ret = 0;
  tv_wss_t* wss_handle = (tv_wss_t*) ssl_handle->data;
  buffer request;
  tv_buf_t buf;
  tv_write_t* ssl_req;
  if (status) {
    tv__wss_handle_error(wss_handle, status);
    return;
  }
  ssl_req = (tv_write_t*)malloc(sizeof(*ssl_req));
  if (ssl_req == NULL) {
    tv__wss_handle_error(wss_handle, TV_ENOMEM);
    return;
  }
  buffer_init(&request);
  if (ws_handshake_create_request(&wss_handle->handshake, &request) != 0) {
    buffer_fin(&request);
    free(ssl_req);
    tv__wss_handle_error(wss_handle, TV_ENOMEM);
    return;
  }
  buf.base = request.ptr; /* swap */
  buf.len = request.len;
  /* NOTE: no need to buffer_fin(&request); */
  ssl_req->data = wss_handle;
  ret = tv_read_start(ssl_handle, tv__wss_read_cb);
  assert(ret == 0);
  TV_UNUSED(ret);
  tv__ssl_write(ssl_req, wss_handle->ssl_handle, buf, tv__wss_handshake_write_cb);
}
void tv__wss_listen(tv_wss_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb) {
  int ret = 0;
  tv_ssl_t* ssl_handle = NULL;
  handle->connection_cb = connection_cb;
  handle->is_server = 1;
  if (handle->is_listened) {
    handle->last_err = TV_EISCONN;
    return;
  }
  ssl_handle = (tv_ssl_t*)malloc(sizeof(*ssl_handle));
  if (ssl_handle == NULL) {
    handle->last_err= TV_ENOMEM;
    return;
  }
  ret = tv_ssl_init(handle->loop, ssl_handle, handle->ssl_ctx);
  assert(ret == 0);
  TV_UNUSED(ret);
  ssl_handle->data = handle;

  tv__ssl_listen(ssl_handle, host, port, backlog, tv__wss_start_server_handshake);
  if (!ssl_handle->is_listened) {
    handle->last_err = ssl_handle->last_err;
    tv__ssl_close(ssl_handle, tv__handle_free_handle); /* TODO: callback is valid? */
  } else {
    handle->ssl_handle = ssl_handle;
    handle->is_listened = ssl_handle->is_listened;
    handle->last_err = ssl_handle->last_err;
  }
}
static void tv__wss_start_server_handshake(tv_stream_t* server, tv_stream_t* client, int status) {
  int ret = 0;
  tv_wss_t* wss_server = (tv_wss_t*) server->data;
  tv_wss_t* wss_client = NULL;
  if (status) {
    if (wss_server->connection_cb != NULL) {
      wss_server->connection_cb((tv_stream_t*) wss_server, NULL, status);
    }
    return;
  }
  wss_client = (tv_wss_t*)malloc(sizeof(*wss_client));
  if (wss_client == NULL) {
    tv__ssl_close((tv_ssl_t*) client, tv__handle_free_handle); /* TODO: callback is valid? */
    if (wss_server->connection_cb != NULL) {
      wss_server->connection_cb((tv_stream_t*) wss_server, NULL, status);
    }
    return;
  }
  ret = tv_wss_init(wss_server->loop, wss_client, wss_server->ssl_ctx);
  assert(ret == 0);
  TV_UNUSED(ret);
  wss_client->connection_cb = wss_server->connection_cb;
  ws_handshake_init(&wss_client->handshake, WSHS_SERVER);
  wss_client->handshake.data = wss_client;
  ws_frame_init(&wss_client->frame, WSFRM_SERVER);
  wss_client->frame.data = wss_client;
  wss_client->listen_handle = wss_server;
  wss_client->ssl_handle = (tv_ssl_t*) client;
  wss_client->is_server = 1;
  wss_client->handshake_complete_cb = wss_server->handshake_complete_cb;
  client->data = wss_client;
  ret = tv_read_start(client, tv__wss_read_cb);
  assert(ret == 0);
}
static void tv__wss_handshake_write_cb(tv_write_t* ssl_req, int status) {
  tv_wss_t* wss_handle = (tv_wss_t*)ssl_req->data;
  if (status) {
    tv__wss_handle_error(wss_handle, status);
  } else {
    if (wss_handle->is_accepted && wss_handle->handshake_complete_cb) {
      wss_handle->handshake_complete_cb((tv_stream_t*) wss_handle,
                                       (wss_handle->handshake.response.code == WSHS_SUCCESS) ? 0 : wss_handle->handshake.response.code);
    } else if (wss_handle->is_accepted && wss_handle->handshake.response.code != WSHS_SUCCESS) {
      tv__ssl_close(wss_handle->ssl_handle, tv__wss_close_cb2);
      tv__timer_close(wss_handle->timer, tv__wss_timer_close_cb);
    }
  }
  free(ssl_req->buf.base);
  free(ssl_req);
}
void tv__wss_read_start(tv_wss_t* handle, tv_read_cb read_cb) {
  handle->read_cb = read_cb;
}
void tv__wss_read_stop(tv_wss_t* handle) {
  int ret = 0;
  handle->read_cb = NULL;
  ret = tv_read_stop((tv_stream_t*) handle->ssl_handle);
  assert(ret == 0);
  TV_UNUSED(ret);
}
static void tv__wss_read_cb(tv_stream_t* ssl_handle, ssize_t nread, const tv_buf_t* buf) {
  tv_wss_t* wss_handle = NULL;
  assert(nread != 0);
  wss_handle = (tv_wss_t*) ssl_handle->data;
  if (nread > 0) {
    size_t nparsed = 0;
    do {
      if (wss_handle->handshake.state == WSHS_CONTINUE) {
        nparsed += ws_handshake_execute(&wss_handle->handshake, &handshake_settings, &buf->base[nparsed], nread - nparsed);
        if (wss_handle->handshake.err != WSHS_SUCCESS) {
          break;
        }
      } else {
        nparsed += ws_frame_execute(&wss_handle->frame, &frame_settings, &buf->base[nparsed], nread - nparsed);
        if (wss_handle->frame.err != WSFRM_NORMAL) {
          break;
        }
      }
    } while (nparsed < (size_t)nread);
    free(buf->base);
  } else {
    tv__timer_stop(wss_handle->timer);
    if (wss_handle->is_server && wss_handle->handshake.state == WSHS_CONTINUE) {
      tv__ssl_close(wss_handle->ssl_handle, tv__wss_close_cb2);
      tv__timer_close(wss_handle->timer, tv__wss_timer_close_cb);
    } else if (nread == TV_EOF) {
      tv__wss_handle_error(wss_handle, TV_ECONNRESET);
    } else {
      tv__wss_handle_error(wss_handle, nread);
    }
  }
}
void tv__wss_write(tv_write_t* tv_req, tv_wss_t* handle, tv_buf_t buf, tv_write_cb write_cb) {
  buffer frame;
  tv_buf_t ws_buf;
  tv_write_t* ssl_req = NULL;
  tv_write_init(tv_req, (tv_stream_t*) handle, buf, write_cb);
  if (!(handle->is_connected || handle->is_accepted)) {
    tv__stream_delayed_write_cb(tv_req, TV_ENOTCONN);
    return;
  }
  ssl_req = (tv_write_t*)malloc(sizeof(*ssl_req));
  if (ssl_req == NULL) {
    tv__stream_delayed_write_cb(tv_req, TV_ENOMEM);
    return;
  }
  ssl_req->data = tv_req;
  buffer_init(&frame);
  if (ws_frame_create(&frame, buf.base, buf.len, WSFRM_BINARY, (handle->is_server != 1))) {
    free(ssl_req);
    buffer_fin(&frame);
    tv__stream_delayed_write_cb(tv_req, TV_ENOMEM);
    return;
  }
  ws_buf.base = frame.ptr; /* swap */
  ws_buf.len = frame.len;
  /* NOTE: no need to buffer_fin(&frame); */
  tv__ssl_write(ssl_req, handle->ssl_handle, ws_buf, tv__wss_write_cb);
}
static void tv__wss_write_cb(tv_write_t* ssl_req, int status) {
  tv_write_t* tv_req = (tv_write_t*) ssl_req->data;
  if (tv_req->write_cb != NULL) {
    tv_req->write_cb(tv_req, status);
  }
  free(ssl_req->buf.base);
  free(ssl_req);
}
void tv__wss_close(tv_wss_t* handle, tv_close_cb close_cb) {
  if (handle->ssl_handle != NULL) {
    handle->close_cb = close_cb;
    tv__ssl_close(handle->ssl_handle, tv__wss_close_cb);
    tv__timer_close(handle->timer, tv__wss_timer_close_cb);
  } else {
    if (close_cb != NULL) {
      close_cb((tv_handle_t*) handle);
    }
  }
}
static void tv__wss_timer_close_cb(tv_handle_t* handle) {
  free(handle);
}
static void tv__wss_close_cb(tv_handle_t* handle) {
  tv_wss_t* wss_handle = (tv_wss_t*) handle->data;
  tv__req_queue_erase(wss_handle->loop, (tv_handle_t*) wss_handle);
  tv_stream_destroy((tv_stream_t*) wss_handle);
  ws_handshake_fin(&wss_handle->handshake);
  ws_frame_fin(&wss_handle->frame);
  if (wss_handle->close_cb != NULL) {
    wss_handle->close_cb((tv_handle_t*) wss_handle);
  }
  free(handle);
}
static void tv__wss_close_cb2(tv_handle_t* handle) {
  tv_wss_t* wss_handle = (tv_wss_t*) handle->data;
  tv__req_queue_erase(wss_handle->loop, (tv_handle_t*) wss_handle);
  tv_stream_destroy((tv_stream_t*) wss_handle);
  ws_handshake_fin(&wss_handle->handshake);
  ws_frame_fin(&wss_handle->frame);
  free(wss_handle);
  free(handle);
}
static void tv__wss_handle_error(tv_wss_t* handle, int err) {
  if (handle->is_accepted || handle->is_connected) {
    if (handle->read_cb) {
      tv_buf_t buf;
      handle->read_cb((tv_stream_t*)handle, err, &buf);
    }
  } else {
    if (handle->is_server) {
      if (handle->connection_cb) {
        handle->connection_cb((tv_stream_t*) handle->listen_handle, NULL, err);
      }
    } else {
      if (handle->connect_cb) {
        handle->connect_cb((tv_stream_t*) handle, err);
      }
    }
  }
}
void tv__wss_timer_cb(tv_timer_t* timer) {
  tv_wss_t* handle = (tv_wss_t *)timer->data;
  handle->drop_pong++;
  if (handle->drop_pong > handle->retry) {
    tv__timer_stop(handle->timer);
    tv__wss_handle_error(handle, TV_ETIMEDOUT);
    return;
  }
  {
    tv_buf_t buf;
    buffer ping;
    tv_write_t* ssl_req = (tv_write_t*)malloc(sizeof(tv_write_t));
    if (ssl_req == NULL) {
      return; /* try next time */
    }
    buffer_init(&ping);
    if (ws_frame_create(&ping, "ping", strlen("ping"), WSFRM_PING, (handle->is_server != 1))) {
      buffer_fin(&ping);
      free(ssl_req);
      return; /* try next time */
    }
    buf.base = ping.ptr; /* swap */
    buf.len = ping.len;
    /* NOTE: no need to buffer_fin(&ping); */
    tv__ssl_write(ssl_req, handle->ssl_handle, buf, NULL);
  }
}
