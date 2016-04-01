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
#include <stdlib.h>

#include "uv.h"

#include "tv.h"
#include "internal.h"

#if defined(WITH_SSL)
# include <openssl/err.h>
# include <openssl/x509.h>
#endif

const char* tv_strerror(tv_handle_t* handle, int err) {
  ws_handshake* handshake;
  ws_frame* frame;
  int is_conn = ((tv_stream_t*)handle)->is_connected | ((tv_stream_t*)handle)->is_accepted;

#if defined(WITH_SSL)
  if (err == TV_EX509) {
    if (handle->type == TV_WSS) {
      return X509_verify_cert_error_string((long) ((tv_wss_t*)handle)->ssl_handle->ssl_err);
    } else {
      return X509_verify_cert_error_string((long) handle->ssl_err);
    }
  } else if (err == TV_ESSL) {
    if (handle->type == TV_WSS) {
      return ERR_error_string(((tv_wss_t*)handle)->ssl_handle->ssl_err, NULL);
    } else {
      return ERR_error_string(handle->ssl_err, NULL);
    }
  }
#else
  if ((err == TV_EX509) || (err == TV_ESSL)) {
    return uv_strerror(UV_UNKNOWN);
  }
#endif

  if (err == TV_EWS) {
    if (handle->type == TV_WS) {
      handshake = &(((tv_ws_t *)handle)->handshake);
      frame = &(((tv_ws_t *)handle)->frame);

#if defined(WITH_SSL)
    } else if (handle->type == TV_WSS) {
      handshake = &(((tv_wss_t *)handle)->handshake);
      frame = &(((tv_wss_t *)handle)->frame);
#endif

    } else {
      return uv_strerror(UV_UNKNOWN);
    }
    if (!is_conn) {
      switch(handshake->response.code) {
      case WSHS_BAD_REQUEST:
        return "400 Bad Request";
      case WSHS_UNAUTHORIZED:
        return "401 Unauthorized";
      case WSHS_FORBIDDEN:
        return "403 Forbidden";
      case WSHS_NOT_FOUND:
        return "404 Not Found";
      case WSHS_METHOD_NOT_ALLOWED:
        return "405 Method Not Allowed";
      case WSHS_SERVICE_UNAVAILABLE:
        return "503 Service UnAvailable";
      case WSHS_INTERNAL_SERVER_ERROR:
      default:
        return "500 Internal Server Error";
      }
    } else {
      switch(frame->err) {
      case WSFRM_NORMAL:
        return "1000:Normal Close";
      case WSFRM_GOAWAY:
        return "1001:Go Away";
      case WSFRM_EPROTO:
        return "1002:Invalid Protocol";
      case WSFRM_EDATA:
        return "1003:Invalid Data";
      case WSFRM_ETYPE:
        return "1007:Invalid Message Type";
      case WSFRM_ESIZE:
        return "1009:Payload Size Too Big";
      case WSFRM_EINTERNAL:
        return "1011:Internal Server Error";
      }
    }
  }

  return uv_strerror(err);
}

int tv_handle_init(tv_handle_type type, tv_loop_t* loop, tv_handle_t* handle) {
  handle->type = type;
  handle->loop = loop;
  /* handle->data = NULL; */
  handle->close_cb = NULL;
  handle->last_err = 0;
  handle->ssl_err = 0;
  return 0;
}

int tv_close(tv_handle_t* handle, tv_close_cb close_cb) {
  uv_thread_t current_thread = uv_thread_self();
  if (uv_thread_equal(&handle->loop->thread, &current_thread)) {
    tv__close(handle, close_cb);
    return 0;
  } else {
    tv_close_req_t* tv_req = NULL;

    tv_req = (tv_close_req_t*)malloc(sizeof(*tv_req));
    if (tv_req == NULL) {
      return TV_ENOMEM;
    }
    tv_req_init((tv_req_t*) tv_req, handle, TV_CLOSE);
    tv_req->close_cb = close_cb;

    tv_req_queue_push(handle->loop, (tv_req_t*) tv_req);
    tv_req_queue_flush(handle->loop);
    return 0;
  }
}

void tv__close(tv_handle_t* handle, tv_close_cb close_cb) {
  switch (handle->type) {
  case TV_TCP:
    tv__tcp_close((tv_tcp_t*) handle, close_cb);
    break;
  case TV_WS:
    tv__ws_close((tv_ws_t*) handle, close_cb);
    break;
#if defined(WITH_SSL)
  case TV_SSL:
    tv__ssl_close((tv_ssl_t*) handle, close_cb);
    break;
  case TV_WSS:
    tv__wss_close((tv_wss_t*) handle, close_cb);
    break;
#endif
  case TV_PIPE:
    tv__pipe_close((tv_pipe_t*) handle, close_cb);
    break;
  case TV_TIMER:
    tv__timer_close((tv_timer_t*) handle, close_cb);
    break;
  default:
    assert(0);
  }
}

void tv__handle_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
  buf->base = (char*)malloc(suggested_size);
  buf->len = (buf->base != NULL) ? suggested_size : 0;
}
void tv__handle_free_handle(tv_handle_t* handle) {
  free(handle);
}
