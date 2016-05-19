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
#include <string.h>

#include "uv.h"

#include "tv.h"
#include "internal.h"

#if defined (_WIN32)
# include <mstcpip.h>
#endif

int tv_fileno(const tv_stream_t* handle, uv_os_fd_t* fd) {
  switch (handle->type) {
  case TV_TCP: {
    const tv_tcp_t* tcp_handle = (const tv_tcp_t*) handle;
    return uv_fileno((uv_handle_t*) tcp_handle->tcp_handle, fd);
  }
  case TV_WS: {
    const tv_ws_t* ws_handle = (const tv_ws_t*)handle;
    return uv_fileno((uv_handle_t*) ws_handle->tv_handle->tcp_handle, fd);
  }
#if defined(WITH_SSL)
  case TV_SSL: {
    const tv_ssl_t* ssl_handle = (const tv_ssl_t*) handle;
    return uv_fileno((uv_handle_t*) ssl_handle->tv_handle->tcp_handle, fd);
  }
  case TV_WSS: {
    const tv_wss_t* wss_handle = (const tv_wss_t*) handle;
    return uv_fileno((uv_handle_t*) wss_handle->ssl_handle->tv_handle->tcp_handle, fd);
  }
#endif
  default:
    return TV_EINVAL;
  }
}

void tv_set_max_sendbuf(tv_stream_t* handle, size_t siz) {
  handle->max_sendbuf = siz;
}

int tv_setsockopt(tv_stream_t* handle, int level, int optname, const void* optval, size_t optlen) {
  int ret = 0;
  uv_os_fd_t sockfd;

  ret = tv_fileno(handle, &sockfd);
  if (ret) {
    return ret;
  }

#if defined(_WIN32)
  ret = setsockopt((uv_os_sock_t) sockfd, level,
                   optname, (const char*) optval, optlen);
  if (ret) {
    return WSAGetLastError();
  }
#else
  ret = setsockopt(sockfd, level,
                   optname, (const void*) optval, optlen);
  if (ret) {
    return -errno;
  }
#endif

  return 0;
}
int tv_bindtodevice(tv_stream_t* handle, const char* devname) {
#if !defined(_WIN32) && !defined(__APPLE__)
  size_t len;
 
  if (handle->devname != NULL) {
    free(handle->devname);
  }
  len = strlen(devname) + 1;
  handle->devname = (char*)malloc(len);
  memset(handle->devname, 0, len);
  strncpy(handle->devname, devname, len - 1);
  return 0;
#else
  return TV_EINVAL;
#endif
}
int tv_keepalive(tv_stream_t* handle, int enable, unsigned int idle, unsigned int interval, unsigned int retry) {
  int ret = 0;
  uv_os_fd_t sockfd;
#if defined(_WIN32)
  BOOL b = enable ? TRUE : FALSE;
  struct tcp_keepalive ka;
  DWORD retBytes;
#endif

  if ((handle->type != TV_TCP) && (handle->type != TV_SSL) &&
      (handle->type != TV_WS) && (handle->type != TV_WSS)) {
    return TV_EINVAL;
  }

  ret = tv_fileno(handle, &sockfd);
  if (ret) {
    return ret;
  }

#if defined(_WIN32)
  if ((uv_os_sock_t) sockfd == INVALID_SOCKET) {
    return TV_EINVAL;
  }
  ret = setsockopt((uv_os_sock_t) sockfd, SOL_SOCKET,
                   SO_KEEPALIVE, (char*) &b, sizeof(b));
  if (ret) {
    return WSAGetLastError();
  }

  ka.onoff = enable;
  ka.keepalivetime = idle * 1000;
  ka.keepaliveinterval = interval * 1000;
  ret = WSAIoctl((uv_os_sock_t) sockfd, SIO_KEEPALIVE_VALS, &ka, sizeof(ka),
                 NULL, 0, &retBytes, NULL, NULL);
  if (ret) {
    return WSAGetLastError();
  }
#else
  if (sockfd == -1) {
    return TV_EINVAL;
  }
  ret = setsockopt(sockfd, SOL_SOCKET,
                   SO_KEEPALIVE, (void*) &enable, sizeof(enable));
  if (ret) {
    return -errno;
  }
# if defined(TCP_KEEPIDLE)  /* Unix */
  ret = setsockopt(sockfd, IPPROTO_TCP,
                   TCP_KEEPIDLE, (void*) &idle, sizeof(idle));
  if (ret) {
    return -errno;
  }
# elif defined(TCP_KEEPALIVE)  /* Mac */
  ret = setsockopt(sockfd, IPPROTO_TCP,
                   TCP_KEEPALIVE, (void*) &idle, sizeof(idle));
  if (ret) {
    return -errno;
  }
# endif

# if defined(TCP_KEEPINTVL)
  ret = setsockopt(sockfd, IPPROTO_TCP,
                   TCP_KEEPINTVL, (void*) &interval, sizeof(interval));
  if (ret) {
    return -errno;
  }
# endif

# if defined(TCP_KEEPCNT)
  ret = setsockopt(sockfd, IPPROTO_TCP,
                   TCP_KEEPCNT, (void*) &retry, sizeof(retry));
  if (ret) {
    return -errno;
  }
# endif

#endif

  return 0;
}

int tv_ws_keepalive(tv_stream_t* handle, int enable, unsigned int interval, unsigned int retry) {
  if (!handle->is_connected && !handle->is_accepted) {
    return TV_ENOTCONN;
  }
  interval = (interval == 0) ? 1 : interval;
  if (handle->type == TV_WS) {
    tv_ws_t* ws_handle = (tv_ws_t*)handle;
    if (!enable) {
      if (ws_handle->is_timer_started == 0) {
        return 0;
      }
      ws_handle->is_timer_started = 0;
      return tv_timer_stop(ws_handle->timer);
    }
    if (ws_handle->is_timer_started != 0) {
      return TV_EALREADY;
    }
    ws_handle->is_timer_started = 1;
    ws_handle->retry = retry;
    ws_handle->timer->data = ws_handle;
    return tv_timer_start(ws_handle->timer, tv__ws_timer_cb, 0, interval * 1000);

#if defined(WITH_SSL)
  } else if (handle->type == TV_WSS) {
    tv_wss_t* wss_handle = (tv_wss_t*)handle;
    if (!enable) {
      if (wss_handle->is_timer_started == 0) {
        return 0;
      }
      wss_handle->is_timer_started = 0;
      return tv_timer_stop(wss_handle->timer);
    }
    if (wss_handle->is_timer_started != 0) {
      return TV_EALREADY;
    }
    wss_handle->is_timer_started = 1;
    wss_handle->retry = retry;
    wss_handle->timer->data = wss_handle;
    return tv_timer_start(wss_handle->timer, tv__wss_timer_cb, 0, interval * 1000);
#endif

  }
  return TV_EINVAL;
}

int tv_getsockname(const tv_stream_t* handle, struct sockaddr* name, int* namelen) {
  switch (handle->type) {
  case TV_TCP: {
    const tv_tcp_t* tcp_handle = (const tv_tcp_t*) handle;
    if (tcp_handle->is_connected || tcp_handle->is_accepted) {
      return uv_tcp_getsockname(tcp_handle->tcp_handle, name, namelen);
    } else {
      return TV_ENOTCONN;
    }
  }
  case TV_WS: {
    const tv_ws_t* ws_handle = (const tv_ws_t*) handle;
    if (ws_handle->is_connected || ws_handle->is_accepted) {
      return uv_tcp_getsockname(ws_handle->tv_handle->tcp_handle, name, namelen);
    } else {
      return TV_ENOTCONN;
    }
    break;
  }
#if defined(WITH_SSL)
  case TV_SSL: {
    const tv_ssl_t* ssl_handle = (const tv_ssl_t*) handle;
    if (ssl_handle->is_connected || ssl_handle->is_accepted) {
      return uv_tcp_getsockname(ssl_handle->tv_handle->tcp_handle, name, namelen);
    } else {
      return TV_ENOTCONN;
    }
  }
  case TV_WSS: {
    const tv_wss_t* wss_handle = (const tv_wss_t*) handle;
    if (wss_handle->is_connected || wss_handle->is_accepted) {
      return uv_tcp_getsockname(wss_handle->ssl_handle->tv_handle->tcp_handle, name, namelen);
    } else {
      return TV_ENOTCONN;
    }
    break;
  }
#endif
  default:
    return TV_EINVAL;
  }

  return 0;
}
int tv_getpeername(const tv_stream_t* handle, struct sockaddr* name, int* namelen) {
  switch (handle->type) {
  case TV_TCP: {
    const tv_tcp_t* tcp_handle = (const tv_tcp_t*) handle;
    if (tcp_handle->is_connected || tcp_handle->is_accepted) {
      return uv_tcp_getpeername(tcp_handle->tcp_handle, name, namelen);
    } else {
      return TV_ENOTCONN;
    }
  }
  case TV_WS: {
    const tv_ws_t* ws_handle = (const tv_ws_t*) handle;
    if (ws_handle->is_connected || ws_handle->is_accepted) {
      return uv_tcp_getpeername(ws_handle->tv_handle->tcp_handle, name, namelen);
    } else {
      return TV_ENOTCONN;
    }
    break;
  }
#if defined(WITH_SSL)
  case TV_SSL: {
    const tv_ssl_t* ssl_handle = (const tv_ssl_t*) handle;
    if (ssl_handle->is_connected || ssl_handle->is_accepted) {
      return uv_tcp_getpeername(ssl_handle->tv_handle->tcp_handle, name, namelen);
    } else {
      return TV_ENOTCONN;
    }
  }
  case TV_WSS: {
    const tv_wss_t* wss_handle = (const tv_wss_t*) handle;
    if (wss_handle->is_connected || wss_handle->is_accepted) {
      return uv_tcp_getpeername(wss_handle->ssl_handle->tv_handle->tcp_handle, name, namelen);
    } else {
      return TV_ENOTCONN;
    }
    break;
  }
#endif
  default:
    return TV_EINVAL;
  }

  return 0;
}

int tv_stream_init(tv_handle_type type, tv_loop_t* loop, tv_stream_t* stream) {
  int ret = 0;

  ret = tv_handle_init(type, loop, (tv_handle_t*) stream);
  assert(ret == 0);

  stream->is_accepted = 0;
  stream->is_connected = 0;
  stream->is_listened = 0;
  stream->connect_cb = NULL;
  stream->connection_cb = NULL;
  stream->read_cb = NULL;
  stream->devname = NULL;
  stream->max_sendbuf = 0;

  stream->pending_timer.data = NULL;

  ret = uv_cond_init(&stream->sync_cond);
  if (ret) {
    return ret;
  }
  ret = uv_mutex_init(&stream->sync_mutex);
  if (ret) {
    uv_cond_destroy(&stream->sync_cond);
    return ret;
  }

  return 0;
}
void tv_stream_destroy(tv_stream_t* stream) {
  uv_mutex_destroy(&stream->sync_mutex);
  uv_cond_destroy(&stream->sync_cond);
  stream->pending_timer.data = NULL;
  if (stream->devname != NULL) {
    free(stream->devname);
    stream->devname = NULL;
  }
  stream->is_listened = 0;
  stream->is_connected = 0;
  stream->is_accepted = 0;
}

int tv_connect(tv_stream_t* handle, const char* host, const char* port, tv_connect_cb connect_cb) {
  uv_thread_t current_thread = uv_thread_self();
  if (uv_thread_equal(&handle->loop->thread, &current_thread)) {
    tv__connect(handle, host, port, connect_cb);
    return 0;
  } else {
    size_t req_len = 0;
    size_t host_len = 0;
    size_t port_len = 0;
    void* mem = NULL;
    tv_connect_req_t* tv_req = NULL;

    if ((host == NULL) && (port == NULL)) {
      return TV_EINVAL;
    }

    req_len = sizeof(*tv_req);
    host_len = (host == NULL) ? 0 : strlen(host) + 1;
    port_len = (port == NULL) ? 0 : strlen(port) + 1;

    mem = malloc(req_len + host_len + port_len);
    if (mem == NULL) {
      return TV_ENOMEM;
    }

    tv_req = (tv_connect_req_t*)mem;
    tv_req_init((tv_req_t*) tv_req, (tv_handle_t*) handle, TV_CONNECT);
    tv_req->host = (host == NULL) ? NULL : (char*) memcpy(((char*) mem) + req_len, host, host_len);
    tv_req->port = (port == NULL) ? NULL : (char*) memcpy(((char*) mem) + req_len + host_len, port, port_len);
    tv_req->connect_cb = connect_cb;

    tv_req_queue_push(handle->loop, (tv_req_t*) tv_req);
    tv_req_queue_flush(handle->loop);
    return 0;
  }
}
int tv_listen(tv_stream_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb) {
  uv_thread_t current_thread = uv_thread_self();
  if (uv_thread_equal(&handle->loop->thread, &current_thread)) {
    tv__listen(handle, host, port, backlog, connection_cb);
    return handle->last_err;  /* handle->last_err is updated in loop thread only. */
  } else {
    size_t req_len = 0;
    size_t host_len = 0;
    size_t port_len = 0;
    void* mem = NULL;
    tv_listen_req_t* tv_req = NULL;

    if ((host == NULL) && (port == NULL)) {
      return TV_EINVAL;
    }

    req_len = sizeof(*tv_req);
    host_len = (host == NULL) ? 0 : strlen(host) + 1;
    port_len = (port == NULL) ? 0 : strlen(port) + 1;

    mem = malloc(req_len + host_len + port_len);
    if (mem == NULL) {
      return TV_ENOMEM;
    }

    tv_req = (tv_listen_req_t*)mem;
    tv_req_init((tv_req_t*) tv_req, (tv_handle_t*) handle, TV_LISTEN);
    tv_req->host = (host == NULL) ? NULL : (char*) memcpy(((char*) mem) + req_len, host, host_len);
    tv_req->port = (port == NULL) ? NULL : (char*) memcpy(((char*) mem) + req_len + host_len, port, port_len);
    tv_req->backlog = backlog;
    tv_req->connection_cb = connection_cb;

    tv_req_queue_push(handle->loop, (tv_req_t*) tv_req);
    uv_mutex_lock(&handle->sync_mutex);
    tv_req_queue_flush(handle->loop);

    uv_cond_wait(&handle->sync_cond, &handle->sync_mutex);
    uv_mutex_unlock(&handle->sync_mutex);
    return handle->last_err;  /* handle->last_err is updated in loop thread only. */
  }
}

int tv_read_start(tv_stream_t* handle, tv_read_cb read_cb) {
  uv_thread_t current_thread = uv_thread_self();
  if (uv_thread_equal(&handle->loop->thread, &current_thread)) {
    tv__read_start(handle, read_cb);
    return 0;
  } else {
    tv_read_start_req_t* tv_req = NULL;

    tv_req = (tv_read_start_req_t*)malloc(sizeof(*tv_req));
    if (tv_req == NULL) {
      return TV_ENOMEM;
    }
    tv_req_init((tv_req_t*) tv_req, (tv_handle_t*) handle, TV_READ_START);
    tv_req->read_cb = read_cb;

    tv_req_queue_push(handle->loop, (tv_req_t*) tv_req);
    tv_req_queue_flush(handle->loop);
    return 0;
  }
}
int tv_read_stop(tv_stream_t* handle) {
  uv_thread_t current_thread = uv_thread_self();
  if (uv_thread_equal(&handle->loop->thread, &current_thread)) {
    tv__read_stop(handle);
    return 0;
  } else {
    tv_read_stop_req_t* tv_req = NULL;

    tv_req = (tv_read_stop_req_t*)malloc(sizeof(*tv_req));
    if (tv_req == NULL) {
      return TV_ENOMEM;
    }
    tv_req_init((tv_req_t*) tv_req, (tv_handle_t*) handle, TV_READ_STOP);

    tv_req_queue_push(handle->loop, (tv_req_t*) tv_req);
    tv_req_queue_flush(handle->loop);
    return 0;
  }
}

int tv_write(tv_write_t* req, tv_stream_t* handle, tv_buf_t buf, tv_write_cb write_cb) {
  uv_thread_t current_thread = uv_thread_self();

  if (handle->max_sendbuf > 0) {
    uv_stream_t* uv_stream = NULL;
    switch (handle->type) {
    case TV_TCP:
      uv_stream = (uv_stream_t*)((tv_tcp_t*)handle)->tcp_handle;
      break;
    case TV_WS:
      uv_stream = (uv_stream_t*)((tv_ws_t*)handle)->tv_handle->tcp_handle;
      break;
#if defined(WITH_SSL)
    case TV_SSL:
      uv_stream = (uv_stream_t*)((tv_ssl_t*)handle)->tv_handle->tcp_handle;
      break;
    case TV_WSS:
      uv_stream = (uv_stream_t*)((tv_wss_t*)handle)->ssl_handle->tv_handle->tcp_handle;
      break;
#endif
    case TV_PIPE:
      uv_stream = (uv_stream_t*)&(((tv_pipe_t*)handle)->pipe_handle);
      break;
    default:
      return TV_EINVAL;
    }
    if (uv_stream->write_queue_size > handle->max_sendbuf) {
      return TV_EBUSY;
    }
  }
  if (uv_thread_equal(&handle->loop->thread, &current_thread)) {
    tv__write(req, handle, buf, write_cb);
    return 0;
  } else {
    tv_write_req_t* tv_req = NULL;

    tv_req = (tv_write_req_t*)malloc(sizeof(*tv_req));
    if (tv_req == NULL) {
      return TV_ENOMEM;
    }
    tv_req_init((tv_req_t*) tv_req, (tv_handle_t*) handle, TV_WRITE);
    tv_req->req = req;
    tv_req->buf = buf;
    tv_req->write_cb = write_cb;

    tv_req_queue_push(handle->loop, (tv_req_t*) tv_req);
    tv_req_queue_flush(handle->loop);
    return 0;
  }
}

void tv__connect(tv_stream_t* handle, const char* host, const char* port, tv_connect_cb connect_cb) {
  switch (handle->type) {
  case TV_TCP:
    tv__tcp_connect((tv_tcp_t*) handle, host, port, connect_cb);
    break;
  case TV_WS:
    tv__ws_connect((tv_ws_t*) handle, host, port, connect_cb);
    break;
#if defined(WITH_SSL)
  case TV_SSL:
    tv__ssl_connect((tv_ssl_t*) handle, host, port, connect_cb);
    break;
  case TV_WSS:
    tv__wss_connect((tv_wss_t*) handle, host, port, connect_cb);
    break;
#endif
  default:
    assert(0);
  }
}
void tv__listen(tv_stream_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb) {
  handle->last_err = 0;

  switch (handle->type) {
  case TV_TCP:
    tv__tcp_listen((tv_tcp_t*) handle, host, port, backlog, connection_cb);
    break;
  case TV_WS:
    tv__ws_listen((tv_ws_t*) handle, host, port, backlog, connection_cb);
    break;
#if defined(WITH_SSL)
  case TV_SSL:
    tv__ssl_listen((tv_ssl_t*) handle, host, port, backlog, connection_cb);
    break;
  case TV_WSS:
    tv__wss_listen((tv_wss_t*) handle, host, port, backlog, connection_cb);
    break;
#endif
  default:
    assert(0);
  }
}
void tv__read_start(tv_stream_t* handle, tv_read_cb read_cb) {
  switch (handle->type) {
  case TV_TCP:
    tv__tcp_read_start((tv_tcp_t*) handle, read_cb);
    break;
  case TV_WS:
    tv__ws_read_start((tv_ws_t*) handle, read_cb);
    break;
#if defined(WITH_SSL)
  case TV_SSL:
    tv__ssl_read_start((tv_ssl_t*) handle, read_cb);
    break;
  case TV_WSS:
    tv__wss_read_start((tv_wss_t*) handle, read_cb);
    break;
#endif
  case TV_PIPE:
    tv__pipe_read_start((tv_pipe_t*) handle, read_cb);
    break;
  default:
    assert(0);
  }
}
void tv__read_stop(tv_stream_t* handle) {
  switch (handle->type) {
  case TV_TCP:
    tv__tcp_read_stop((tv_tcp_t*) handle);
    break;
  case TV_WS:
    tv__ws_read_stop((tv_ws_t*) handle);
    break;
#if defined(WITH_SSL)
  case TV_SSL:
    tv__ssl_read_stop((tv_ssl_t*) handle);
    break;
  case TV_WSS:
    tv__wss_read_stop((tv_wss_t*) handle);
    break;
#endif
  case TV_PIPE:
    tv__pipe_read_stop((tv_pipe_t*) handle);
    break;
  default:
    assert(0);
  }
}
void tv__write(tv_write_t* req, tv_stream_t* handle, tv_buf_t buf, tv_write_cb write_cb) {
  switch (handle->type) {
  case TV_TCP:
    tv__tcp_write(req, (tv_tcp_t*) handle, buf, write_cb);
    break;
  case TV_WS:
    tv__ws_write(req, (tv_ws_t*) handle, buf, write_cb);
    break;
#if defined(WITH_SSL)
  case TV_SSL:
    tv__ssl_write(req, (tv_ssl_t*) handle, buf, write_cb);
    break;
  case TV_WSS:
    tv__wss_write(req, (tv_wss_t*) handle, buf, write_cb);
    break;
#endif
  case TV_PIPE:
    tv__pipe_write(req, (tv_pipe_t*) handle, buf, write_cb);
    break;
  default:
    assert(0);
  }
}
void tv__write_cancel(tv_write_req_t* req) {
  req->req->handle = (tv_stream_t*) req->handle;
  req->req->buf = req->buf;
  req->req->write_cb = req->write_cb;

  if (req->write_cb != NULL) {
    req->write_cb(req->req, TV_ECANCELED);
  }
  free(req);
}

void tv__stream_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
  tv_stream_t* handle = NULL;

  handle = (tv_stream_t*) stream->data;
  if (nread > 0) {
    if (handle->read_cb != NULL) {
      handle->read_cb(handle, nread, buf);
    }
  } else if (nread == 0) {
    free(buf->base);
  } else {
    free(buf->base);
    if (handle->read_cb != NULL) {
      handle->read_cb(handle, nread, buf);
    }
  }
}
void tv__stream_write_cb(uv_write_t* uv_req, int status) {
  tv_write_t* tv_req = NULL;

  tv_req = (tv_write_t*) uv_req->data;
  free(uv_req);
  if (tv_req->write_cb != NULL) {
    tv_req->write_cb(tv_req, status);
  }
}

static void tv__stream_call_pending_write_cb(uv_handle_t* uv_handle) {
  tv_write_t* req = NULL;

  req = (tv_write_t*) uv_handle->data;
  if (req->write_cb != NULL) {
    req->write_cb(req, req->handle->last_err);
  }
}
void tv__stream_delayed_write_cb(tv_write_t* req, int status) {
  int ret = 0;

  req->handle->last_err = status;
  ret = uv_check_init(&req->handle->loop->loop, &req->check_handle);
  assert(ret == 0);  /* uv_check_init always return 0 in version 0.11.13. */
  TV_UNUSED(ret);
  req->check_handle.data = req;
  uv_close((uv_handle_t*) &req->check_handle, tv__stream_call_pending_write_cb);
}

static void tv__stream_call_pending_connect_cb(uv_timer_t* uv_handle) {
  int ret = 0;
  tv_stream_t* handle = NULL;

  handle = (tv_stream_t*) uv_handle->data;

  ret = uv_timer_stop(uv_handle);
  assert(ret == 0);  /* uv_timer_stop always return 0 in version 0.11.26. */
  TV_UNUSED(ret);
  if (handle->connect_cb != NULL) {
    handle->connect_cb(handle, handle->last_err);
  }
}
void tv__stream_delayed_connect_cb(tv_stream_t* handle, int status) {
  int ret = 0;

  handle->last_err = status;

  if (handle->pending_timer.data == NULL) {
    ret = uv_timer_init(&handle->loop->loop, &handle->pending_timer);
    assert(ret == 0);  /* uv_timer_init always return 0 in version 0.11.26. */
    handle->pending_timer.data = handle;
  }

  uv_update_time(&handle->loop->loop);
  ret = uv_timer_start(&handle->pending_timer, tv__stream_call_pending_connect_cb, 0, 0);
  assert(ret == 0);  /* uv_timer_start always return 0 in version 0.11.26. */
  TV_UNUSED(ret);
}
