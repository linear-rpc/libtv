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

#ifndef INTERNAL_H_
#define INTERNAL_H_

#include "tv.h"

#define TV_UNUSED(x) ((void) (x))

typedef struct {
  uv_tcp_t* handle;
  void*     queue[2];
} tv_tcp_node_t;

typedef enum {
  TV_CONNECT,
  TV_LISTEN,
  TV_READ_START,
  TV_READ_STOP,
  TV_WRITE,
  TV_CLOSE,
  TV_TIMER_START,
  TV_TIMER_STOP,
  TV_PIPE_CONNECT,
  TV_PIPE_LISTEN,
  TV_LOOP_CLOSE,
  TV_REQ_TYPE_MAX
} tv_req_type;

typedef struct tv_addrinfo_s tv_addrinfo_t;
typedef struct tv_req_s tv_req_t;

struct tv_addrinfo_s {
  struct addrinfo* res;
  struct addrinfo* ai;
};

#define TV_REQ_FIELDS  \
  void*  queue[2];     \
  tv_req_type  type;   \
  tv_handle_t* handle; \

struct tv_req_s {
  TV_REQ_FIELDS
};

typedef struct {
  TV_REQ_FIELDS
  char* host;
  char* port;
  tv_connect_cb connect_cb;
} tv_connect_req_t;

typedef struct {
  TV_REQ_FIELDS
  char* host;
  char* port;
  int backlog;
  tv_connection_cb connection_cb;
} tv_listen_req_t;

typedef struct {
  TV_REQ_FIELDS
  tv_read_cb read_cb;
} tv_read_start_req_t;

typedef struct {
  TV_REQ_FIELDS
} tv_read_stop_req_t;

typedef struct {
  TV_REQ_FIELDS
  tv_write_t* req;
  tv_buf_t buf;
  tv_write_cb write_cb;
} tv_write_req_t;

typedef struct {
  TV_REQ_FIELDS
  tv_close_cb close_cb;
} tv_close_req_t;

typedef struct {
  TV_REQ_FIELDS
  tv_timer_cb timer_cb;
  uint64_t timeout;
  uint64_t repeat;
} tv_timer_start_req_t;

typedef struct {
  TV_REQ_FIELDS
} tv_timer_stop_req_t;

typedef struct {
  TV_REQ_FIELDS
  char* name;
  tv_connect_cb connect_cb;
} tv_pipe_connect_req_t;

typedef struct {
  TV_REQ_FIELDS
  char* name;
  int backlog;
  tv_connection_cb connection_cb;
} tv_pipe_listen_req_t;

typedef struct {
  TV_REQ_FIELDS
  tv_loop_t* loop;
} tv_loop_close_req_t;

/* common */

/* loop */
void tv_req_init(tv_req_t* req, tv_handle_t* handle, tv_req_type type);
void tv_req_queue_push(tv_loop_t* loop, tv_req_t* req);
void tv_req_queue_flush(tv_loop_t* loop);

void tv__req_queue_erase(tv_loop_t* loop, tv_handle_t* handle);

void tv__loop_close(tv_loop_t* loop);

/* handle */
int tv_handle_init(tv_handle_type type, tv_loop_t* loop, tv_handle_t* handle);

void tv__close(tv_handle_t* handle, tv_close_cb close_cb);

void tv__handle_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);

void tv__handle_free_handle(tv_handle_t* handle);

/* stream */
int tv_stream_init(tv_handle_type type, tv_loop_t* loop, tv_stream_t* stream);
void tv_stream_destroy(tv_stream_t* stream);

#define tv_write_init(req_, handle_, buf_, write_cb_) \
  (req_)->handle = (handle_); \
  (req_)->buf = (buf_); \
  (req_)->write_cb = (write_cb_);

void tv__connect(tv_stream_t* handle, const char* host, const char* port, tv_connect_cb connect_cb);
void tv__listen(tv_stream_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb);
void tv__read_start(tv_stream_t* handle, tv_read_cb read_cb);
void tv__read_stop(tv_stream_t* handle);
void tv__write(tv_write_t* req, tv_stream_t* handle, tv_buf_t buf, tv_write_cb write_cb);

void tv__write_cancel(tv_write_req_t* req);

void tv__stream_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void tv__stream_write_cb(uv_write_t* write_req, int status);

void tv__stream_delayed_write_cb(tv_write_t* req, int status);
void tv__stream_delayed_connect_cb(tv_stream_t* handle, int status);

/* tcp */
int tv__tcp_connect2(tv_tcp_t* handle, tv_addrinfo_t* addr);
void tv__tcp_connect(tv_tcp_t* handle, const char* host, const char* port, tv_connect_cb connect_cb);
void tv__tcp_listen(tv_tcp_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb);
void tv__tcp_read_start(tv_tcp_t* handle, tv_read_cb read_cb);
void tv__tcp_read_stop(tv_tcp_t* handle);
void tv__tcp_write(tv_write_t* req, tv_tcp_t* handle, tv_buf_t buf, tv_write_cb write_cb);
void tv__tcp_close(tv_tcp_t* handle, tv_close_cb close_cb);

int tv_getaddrinfo_translate_error(int sys_err);

#if defined(WITH_SSL)
/*
 * Premise that errno of libuv is greater than -5000.
 * see UV__EOF in uv-errno.h
 */
# define TV_SSL_X509_ERRNO_BASE (-5000)
/*
 * Premise that the number of errno of X509 is less than 1000.
 * see X509_V_OK, X509_V_ERR_* in openssl/x509_vfy.h
 */
# define TV_SSL_BIO_ERRNO_BASE  (-6000)
/* ssl */
void tv__ssl_connect(tv_ssl_t* handle, const char* host, const char* port, tv_connect_cb connect_cb);
void tv__ssl_listen(tv_ssl_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb);
void tv__ssl_read_start(tv_ssl_t* handle, tv_read_cb read_cb);
void tv__ssl_read_stop(tv_ssl_t* handle);
void tv__ssl_write(tv_write_t* tv_req, tv_ssl_t* handle, tv_buf_t buf, tv_write_cb write_cb);
void tv__ssl_close(tv_ssl_t* handle, tv_close_cb close_cb);
#endif

/* ws */
void tv__ws_connect(tv_ws_t* handle, const char* host, const char* port, tv_connect_cb connect_cb);
void tv__ws_listen(tv_ws_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb);
void tv__ws_read_start(tv_ws_t* handle, tv_read_cb read_cb);
void tv__ws_read_stop(tv_ws_t* handle);
void tv__ws_write(tv_write_t* tv_req, tv_ws_t* handle, tv_buf_t buf, tv_write_cb write_cb);
void tv__ws_close(tv_ws_t* handle, tv_close_cb close_cb);

#if defined(WITH_SSL)
/* ws */
void tv__wss_connect(tv_wss_t* handle, const char* host, const char* port, tv_connect_cb connect_cb);
void tv__wss_listen(tv_wss_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb);
void tv__wss_read_start(tv_wss_t* handle, tv_read_cb read_cb);
void tv__wss_read_stop(tv_wss_t* handle);
void tv__wss_write(tv_write_t* tv_req, tv_wss_t* handle, tv_buf_t buf, tv_write_cb write_cb);
void tv__wss_close(tv_wss_t* handle, tv_close_cb close_cb);
#endif

/* pipe */
void tv__pipe_connect(tv_pipe_t* handle, const char* name, tv_connect_cb connect_cb);
void tv__pipe_listen(tv_pipe_t* handle, const char* name, int backlog, tv_connection_cb connection_cb);
void tv__pipe_read_start(tv_pipe_t* handle, tv_read_cb read_cb);
void tv__pipe_read_stop(tv_pipe_t* handle);
void tv__pipe_write(tv_write_t* req, tv_pipe_t* handle, tv_buf_t buf, tv_write_cb write_cb);
void tv__pipe_close(tv_pipe_t* handle, tv_close_cb close_cb);

/* timer */
void tv__timer_start(tv_timer_t* timer, tv_timer_cb timer_cb, uint64_t timeout, uint64_t repeat);
void tv__timer_stop(tv_timer_t* timer);
void tv__timer_close(tv_timer_t* handle, tv_close_cb close_cb);

#endif  /* INTERNAL_H_ */
