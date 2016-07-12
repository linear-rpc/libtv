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

#ifndef _WIN32
/* Expose glibc-specific EAI_* error codes. Needs to be defined before we
 * include any headers.
 */
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
/* EAI_* constants. */
# include <netdb.h>
#endif

#include "uv.h"

#include "tv.h"
#include "internal.h"
#include "queue.h"

static void tv__tcp_queue_push(tv_tcp_t* handle, tv_tcp_node_t* tcp_node);
static void tv__tcp_queue_erase(tv_tcp_t* handle, uv_tcp_t* uv_handle);
static int tv__tcp_queue_empty(tv_tcp_t* handle);

static void tv__tcp_call_connect_cb(uv_connect_t* connect_req, int status);
static void tv__tcp_call_connection_cb(uv_stream_t* uv_server, int status);
static void tv__tcp_close_connect_handle(uv_handle_t* uv_handle);
static void tv__tcp_close_handle(uv_handle_t* uv_handle);
static void tv__tcp_close_listen_handle(uv_handle_t* uv_handle);


static void tv__handle_free_uv_handle(uv_handle_t* uv_handle) {
  free(uv_handle);
}

static void tv__tcp_queue_push(tv_tcp_t* handle, tv_tcp_node_t* tcp_node) {
  QUEUE_INIT(&tcp_node->queue);
  QUEUE_INSERT_TAIL(&handle->tcp_queue, &tcp_node->queue);
}
static void tv__tcp_queue_erase(tv_tcp_t* handle, uv_tcp_t* uv_handle) {
  QUEUE* q = NULL;
  tv_tcp_node_t* node = NULL;

  QUEUE_FOREACH(q, &handle->tcp_queue) {
    node = QUEUE_DATA(q, tv_tcp_node_t, queue);
    if (node->handle == uv_handle) {
      QUEUE_REMOVE(q);
      free(node);
      return;
    }
  }
}
static int tv__tcp_queue_empty(tv_tcp_t* handle) {
  return QUEUE_EMPTY(&handle->tcp_queue);
}

int tv_tcp_init(tv_loop_t* loop, tv_tcp_t* handle) {
  int ret = 0;

  if ((loop == NULL) || (handle == NULL)) {
    return TV_EINVAL;
  }

  ret = tv_stream_init(TV_TCP, loop, (tv_stream_t*) handle);
  if (ret) {
    return ret;
  }

  handle->tcp_handle = NULL;

  QUEUE_INIT(&handle->tcp_queue);

  return 0;
}

#if defined(_WIN32)
int tv_translate_sys_error(int sys_errno) {
  if (sys_errno <= 0) {
    return sys_errno;  /* If < 0 then it's already a libuv error. */
  }

  switch (sys_errno) {
    case ERROR_NOACCESS:                    return UV_EACCES;
    case WSAEACCES:                         return UV_EACCES;
    case ERROR_ADDRESS_ALREADY_ASSOCIATED:  return UV_EADDRINUSE;
    case WSAEADDRINUSE:                     return UV_EADDRINUSE;
    case WSAEADDRNOTAVAIL:                  return UV_EADDRNOTAVAIL;
    case WSAEAFNOSUPPORT:                   return UV_EAFNOSUPPORT;
    case WSAEWOULDBLOCK:                    return UV_EAGAIN;
    case WSAEALREADY:                       return UV_EALREADY;
    case ERROR_INVALID_FLAGS:               return UV_EBADF;
    case ERROR_INVALID_HANDLE:              return UV_EBADF;
    case ERROR_LOCK_VIOLATION:              return UV_EBUSY;
    case ERROR_PIPE_BUSY:                   return UV_EBUSY;
    case ERROR_SHARING_VIOLATION:           return UV_EBUSY;
    case ERROR_OPERATION_ABORTED:           return UV_ECANCELED;
    case WSAEINTR:                          return UV_ECANCELED;
    case ERROR_NO_UNICODE_TRANSLATION:      return UV_ECHARSET;
    case ERROR_CONNECTION_ABORTED:          return UV_ECONNABORTED;
    case WSAECONNABORTED:                   return UV_ECONNABORTED;
    case ERROR_CONNECTION_REFUSED:          return UV_ECONNREFUSED;
    case WSAECONNREFUSED:                   return UV_ECONNREFUSED;
    case ERROR_NETNAME_DELETED:             return UV_ECONNRESET;
    case WSAECONNRESET:                     return UV_ECONNRESET;
    case ERROR_ALREADY_EXISTS:              return UV_EEXIST;
    case ERROR_FILE_EXISTS:                 return UV_EEXIST;
    case ERROR_BUFFER_OVERFLOW:             return UV_EFAULT;
    case WSAEFAULT:                         return UV_EFAULT;
    case ERROR_HOST_UNREACHABLE:            return UV_EHOSTUNREACH;
    case WSAEHOSTUNREACH:                   return UV_EHOSTUNREACH;
    case ERROR_INSUFFICIENT_BUFFER:         return UV_EINVAL;
    case ERROR_INVALID_DATA:                return UV_EINVAL;
    case ERROR_INVALID_PARAMETER:           return UV_EINVAL;
    case ERROR_SYMLINK_NOT_SUPPORTED:       return UV_EINVAL;
    case WSAEINVAL:                         return UV_EINVAL;
    case WSAEPFNOSUPPORT:                   return UV_EINVAL;
    case WSAESOCKTNOSUPPORT:                return UV_EINVAL;
    case ERROR_BEGINNING_OF_MEDIA:          return UV_EIO;
    case ERROR_BUS_RESET:                   return UV_EIO;
    case ERROR_CRC:                         return UV_EIO;
    case ERROR_DEVICE_DOOR_OPEN:            return UV_EIO;
    case ERROR_DEVICE_REQUIRES_CLEANING:    return UV_EIO;
    case ERROR_DISK_CORRUPT:                return UV_EIO;
    case ERROR_EOM_OVERFLOW:                return UV_EIO;
    case ERROR_FILEMARK_DETECTED:           return UV_EIO;
    case ERROR_GEN_FAILURE:                 return UV_EIO;
    case ERROR_INVALID_BLOCK_LENGTH:        return UV_EIO;
    case ERROR_IO_DEVICE:                   return UV_EIO;
    case ERROR_NO_DATA_DETECTED:            return UV_EIO;
    case ERROR_NO_SIGNAL_SENT:              return UV_EIO;
    case ERROR_OPEN_FAILED:                 return UV_EIO;
    case ERROR_SETMARK_DETECTED:            return UV_EIO;
    case ERROR_SIGNAL_REFUSED:              return UV_EIO;
    case WSAEISCONN:                        return UV_EISCONN;
    case ERROR_CANT_RESOLVE_FILENAME:       return UV_ELOOP;
    case ERROR_TOO_MANY_OPEN_FILES:         return UV_EMFILE;
    case WSAEMFILE:                         return UV_EMFILE;
    case WSAEMSGSIZE:                       return UV_EMSGSIZE;
    case ERROR_FILENAME_EXCED_RANGE:        return UV_ENAMETOOLONG;
    case ERROR_NETWORK_UNREACHABLE:         return UV_ENETUNREACH;
    case WSAENETUNREACH:                    return UV_ENETUNREACH;
    case WSAENOBUFS:                        return UV_ENOBUFS;
    case ERROR_DIRECTORY:                   return UV_ENOENT;
    case ERROR_FILE_NOT_FOUND:              return UV_ENOENT;
    case ERROR_INVALID_NAME:                return UV_ENOENT;
    case ERROR_INVALID_DRIVE:               return UV_ENOENT;
    case ERROR_INVALID_REPARSE_DATA:        return UV_ENOENT;
    case ERROR_MOD_NOT_FOUND:               return UV_ENOENT;
    case ERROR_PATH_NOT_FOUND:              return UV_ENOENT;
    case WSAHOST_NOT_FOUND:                 return UV_ENOENT;
    case WSANO_DATA:                        return UV_ENOENT;
    case ERROR_NOT_ENOUGH_MEMORY:           return UV_ENOMEM;
    case ERROR_OUTOFMEMORY:                 return UV_ENOMEM;
    case ERROR_CANNOT_MAKE:                 return UV_ENOSPC;
    case ERROR_DISK_FULL:                   return UV_ENOSPC;
    case ERROR_EA_TABLE_FULL:               return UV_ENOSPC;
    case ERROR_END_OF_MEDIA:                return UV_ENOSPC;
    case ERROR_HANDLE_DISK_FULL:            return UV_ENOSPC;
    case ERROR_NOT_CONNECTED:               return UV_ENOTCONN;
    case WSAENOTCONN:                       return UV_ENOTCONN;
    case ERROR_DIR_NOT_EMPTY:               return UV_ENOTEMPTY;
    case WSAENOTSOCK:                       return UV_ENOTSOCK;
    case ERROR_NOT_SUPPORTED:               return UV_ENOTSUP;
    case ERROR_BROKEN_PIPE:                 return UV_EOF;
    case ERROR_ACCESS_DENIED:               return UV_EPERM;
    case ERROR_PRIVILEGE_NOT_HELD:          return UV_EPERM;
    case ERROR_BAD_PIPE:                    return UV_EPIPE;
    case ERROR_NO_DATA:                     return UV_EPIPE;
    case ERROR_PIPE_NOT_CONNECTED:          return UV_EPIPE;
    case WSAESHUTDOWN:                      return UV_EPIPE;
    case WSAEPROTONOSUPPORT:                return UV_EPROTONOSUPPORT;
    case ERROR_WRITE_PROTECT:               return UV_EROFS;
    case ERROR_SEM_TIMEOUT:                 return UV_ETIMEDOUT;
    case WSAETIMEDOUT:                      return UV_ETIMEDOUT;
    case ERROR_NOT_SAME_DEVICE:             return UV_EXDEV;
    case ERROR_INVALID_FUNCTION:            return UV_EISDIR;
    case ERROR_META_EXPANSION_TOO_LONG:     return UV_E2BIG;
    default:                                return UV_UNKNOWN;
  }
}
int tv_getaddrinfo_translate_error(int sys_err) {
  switch (sys_err) {
    case 0:                       return 0;
    case WSATRY_AGAIN:            return UV_EAI_AGAIN;
    case WSAEINVAL:               return UV_EAI_BADFLAGS;
    case WSANO_RECOVERY:          return UV_EAI_FAIL;
    case WSAEAFNOSUPPORT:         return UV_EAI_FAMILY;
    case WSA_NOT_ENOUGH_MEMORY:   return UV_EAI_MEMORY;
    case WSAHOST_NOT_FOUND:       return UV_EAI_NONAME;
    case WSATYPE_NOT_FOUND:       return UV_EAI_SERVICE;
    case WSAESOCKTNOSUPPORT:      return UV_EAI_SOCKTYPE;
    default:                      return tv_translate_sys_error(sys_err);
  }
}
#else
int tv_getaddrinfo_translate_error(int sys_err) {
  switch (sys_err) {
  case 0:
    return 0;
#if defined(EAI_ADDRFAMILY)
  case EAI_ADDRFAMILY:
    return UV_EAI_ADDRFAMILY;
#endif
#if defined(EAI_AGAIN)
  case EAI_AGAIN:
    return UV_EAI_AGAIN;
#endif
#if defined(EAI_BADFLAGS)
  case EAI_BADFLAGS:
    return UV_EAI_BADFLAGS;
#endif
#if defined(EAI_BADHINTS)
  case EAI_BADHINTS: return UV_EAI_BADHINTS;
#endif
#if defined(EAI_CANCELED)
  case EAI_CANCELED:
    return UV_EAI_CANCELED;
#endif
#if defined(EAI_FAIL)
  case EAI_FAIL:
    return UV_EAI_FAIL;
#endif
#if defined(EAI_FAMILY)
  case EAI_FAMILY:
    return UV_EAI_FAMILY;
#endif
#if defined(EAI_MEMORY)
  case EAI_MEMORY:
    return UV_EAI_MEMORY;
#endif
#if defined(EAI_NODATA)
  case EAI_NODATA:
    return UV_EAI_NODATA;
#endif
#if defined(EAI_NONAME)
# if !defined(EAI_NODATA) || EAI_NODATA != EAI_NONAME
  case EAI_NONAME:
    return UV_EAI_NONAME;
# endif
#endif
#if defined(EAI_OVERFLOW)
  case EAI_OVERFLOW: return UV_EAI_OVERFLOW;
#endif
#if defined(EAI_PROTOCOL)
  case EAI_PROTOCOL: return UV_EAI_PROTOCOL;
#endif
#if defined(EAI_SERVICE)
  case EAI_SERVICE:
    return UV_EAI_SERVICE;
#endif
#if defined(EAI_SOCKTYPE)
  case EAI_SOCKTYPE:
    return UV_EAI_SOCKTYPE;
#endif
#if defined(EAI_SYSTEM)
  case EAI_SYSTEM:
    return -errno;
#endif
  default:
    return UV_UNKNOWN;
  }
}
#endif
int tv__tcp_connect2(tv_tcp_t* handle, tv_addrinfo_t* addr) {
  int ret = 0;
  uv_connect_t* connect_req = NULL;
  uv_tcp_t* uv_handle = NULL;
#if !defined(_WIN32) && !defined(__APPLE__)
  uv_os_sock_t sock;
#endif

  connect_req = (uv_connect_t*)malloc(sizeof(*connect_req));
  if (connect_req == NULL) {
    return TV_ENOMEM;
  }
  connect_req->data = addr;

  uv_handle = (uv_tcp_t*)malloc(sizeof(*uv_handle));
  if (uv_handle == NULL) {
    free(connect_req);
    return TV_ENOMEM;
  }
  ret = uv_tcp_init(&handle->loop->loop, uv_handle);
  assert(ret == 0);  /* uv_tcp_init always return 0 in version 0.11.13. */

  handle->tcp_handle = uv_handle;

#if !defined(_WIN32) && !defined(__APPLE__)  /* for SO_BINDTODEVICE */
  sock = socket(addr->ai->ai_addr->sa_family, SOCK_STREAM, 0);
  if (sock < 0) {
    free(connect_req);
    free(uv_handle);
    handle->tcp_handle = NULL;
    return sock;
  }
  ret = uv_tcp_open(uv_handle, sock);
  if (ret) {
    uv_close((uv_handle_t*) uv_handle, tv__handle_free_uv_handle);
    free(connect_req);
    handle->tcp_handle = NULL;
    return ret;
  }
  if (handle->devname != NULL) {
    ret = tv_setsockopt((tv_stream_t*) handle, SOL_SOCKET, SO_BINDTODEVICE, (void*) handle->devname, strlen(handle->devname) + 1);
    if (ret) {
      uv_close((uv_handle_t*) uv_handle, tv__handle_free_uv_handle);
      free(connect_req);
      handle->tcp_handle = NULL;
      return ret;
    }
  }
#endif

  uv_handle->data = handle;

  ret = uv_tcp_connect(connect_req, uv_handle, addr->ai->ai_addr, tv__tcp_call_connect_cb);
  if (ret) {
    /* failure */
    if (!uv_is_closing((uv_handle_t*) uv_handle)) {
      uv_close((uv_handle_t*) uv_handle, tv__handle_free_uv_handle);
    }
    free(connect_req);
    handle->tcp_handle = NULL;
  }
  return ret;
}
void tv__tcp_connect(tv_tcp_t* handle, const char* host, const char* port, tv_connect_cb connect_cb) {
  int ret = 0;
  struct addrinfo hints;
  tv_addrinfo_t* addr = NULL;

  handle->connect_cb = connect_cb;

  if (handle->is_connected) {
    /* Unless it becomes possible that tv_tcp_connect returns false using state corresponded to multi-thread. */
    tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_EISCONN);
    return;
  }

  addr = (tv_addrinfo_t*)malloc(sizeof(*addr));
  if (addr == NULL) {
    tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
    return;
  }
  addr->res = NULL;
  addr->ai = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  ret = getaddrinfo(host, port, &hints, &addr->res);
  if (ret) {
    free(addr);
    tv__stream_delayed_connect_cb((tv_stream_t*) handle, tv_getaddrinfo_translate_error(ret));
    return;
  }

  for (addr->ai = addr->res; addr->ai != NULL; addr->ai = addr->ai->ai_next) {
    ret = tv__tcp_connect2(handle, addr);
    if ((ret == TV_ENOMEM) || (ret && (addr->ai->ai_next == NULL))) {
      /* fatal failure or all addrinfo fail to connect -> call connect_cb with error */
      freeaddrinfo(addr->res);
      free(addr);
      tv__stream_delayed_connect_cb((tv_stream_t*) handle, ret);
      return;
    } else if (ret == 0) {
      /* success -> break this loop */
      break;
    }
    /* failure -> reconnect */
  }
}
void tv__tcp_listen(tv_tcp_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb) {
  int ret = 0;
  int err = 0;
  struct addrinfo hints;
  struct addrinfo* res = NULL;
  struct addrinfo* ai = NULL;

  handle->connection_cb = connection_cb;

  if (handle->is_listened) {
    handle->last_err = TV_EISCONN;
    return;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_socktype = SOCK_STREAM;
  ret = getaddrinfo(host, port, &hints, &res);
  if (ret) {
    handle->last_err = tv_getaddrinfo_translate_error(ret);
    return;
  }

  for (ai = res; ai != NULL; ai = ai->ai_next) {
    tv_tcp_node_t* tcp_node = NULL;
    uv_tcp_t* uv_handle = NULL;

    tcp_node = (tv_tcp_node_t*)malloc(sizeof(*tcp_node));
    if (tcp_node == NULL) {
      freeaddrinfo(res);
      handle->last_err = TV_ENOMEM;
      return;
    }

    uv_handle = (uv_tcp_t*)malloc(sizeof(*uv_handle));
    if (uv_handle == NULL) {
      free(tcp_node);
      freeaddrinfo(res);
      handle->last_err = TV_ENOMEM;
      return;
    }
    ret = uv_tcp_init(&handle->loop->loop, uv_handle);
    assert(ret == 0);  /* uv_tcp_init always return 0 in version 0.11.13. */
    uv_handle->data = handle;

    ret = uv_tcp_bind(uv_handle, ai->ai_addr, 0);
    if (ret) {
      err = ret;
      free(tcp_node);
      if (!uv_is_closing((uv_handle_t*) uv_handle)) {
        uv_close((uv_handle_t*) uv_handle, tv__handle_free_uv_handle);
      }
      continue;
    }

    ret = uv_listen((uv_stream_t*) uv_handle, backlog, tv__tcp_call_connection_cb);
    if (ret) {
      err = ret;
      free(tcp_node);
      if (!uv_is_closing((uv_handle_t*) uv_handle)) {
        uv_close((uv_handle_t*) uv_handle, tv__handle_free_uv_handle);
      }
      continue;
    }

    tcp_node->handle = uv_handle;
    tv__tcp_queue_push(handle, tcp_node);
  }
  freeaddrinfo(res);

  if (tv__tcp_queue_empty(handle)) {
    /* all addrinfo fail to listen */
    handle->last_err = err;
  } else {
    /* listen success more than one addrinfo */
    handle->is_listened = 1;
    handle->last_err = 0;
  }
}
void tv__tcp_read_start(tv_tcp_t* handle, tv_read_cb read_cb) {
  int ret = 0;

  handle->read_cb = read_cb;

  ret = uv_read_start((uv_stream_t*) handle->tcp_handle, tv__handle_alloc_cb, tv__stream_read_cb);
  assert(ret == 0);  /* in version 0.11.13, uv_read_start always return 0 if immediately after connect_cb called with status = 0. */
  TV_UNUSED(ret);
}
void tv__tcp_read_stop(tv_tcp_t* handle) {
  int ret = 0;

  handle->read_cb = NULL;

  ret = uv_read_stop((uv_stream_t*) handle->tcp_handle);
  assert(ret == 0);  /* in version 0.11.13, uv_read_stop always return 0 unless type is tty. */
  TV_UNUSED(ret);
}
void tv__tcp_write(tv_write_t* req, tv_tcp_t* handle, tv_buf_t buf, tv_write_cb write_cb) {
  int ret = 0;
  uv_write_t* uv_req = NULL;

  tv_write_init(req, (tv_stream_t*) handle, buf, write_cb);

  if (!(handle->is_connected || handle->is_accepted)) {
    tv__stream_delayed_write_cb(req, TV_ENOTCONN);
    return;
  }
  if (handle->max_sendbuf > 0 && handle->cur_sendbuf > handle->max_sendbuf) {
    tv__stream_delayed_write_cb(req, TV_EBUSY);
    return;
  }
  uv_req = (uv_write_t*)malloc(sizeof(*uv_req));
  if (uv_req == NULL) {
    tv__stream_delayed_write_cb(req, TV_ENOMEM);
    return;
  }
  uv_req->data = req;

  ret = uv_write(uv_req, (uv_stream_t*) handle->tcp_handle, &buf, 1, tv__stream_write_cb);
  if (ret) {
    free(uv_req);
    tv__stream_delayed_write_cb(req, ret);
  }
  handle->cur_sendbuf += buf.len;
}
void tv__tcp_close(tv_tcp_t* handle, tv_close_cb close_cb) {
  handle->close_cb = close_cb;

  if (handle->is_listened) {
    QUEUE* q = NULL;
    tv_tcp_node_t* node = NULL;

    /* uv_close_cb is called LIFO in version 0.11.13, so uv_close is called this order */
    QUEUE_FOREACH(q, &handle->tcp_queue) {
      node = QUEUE_DATA(q, tv_tcp_node_t, queue);
      if (!uv_is_closing((uv_handle_t*) node->handle)) {
        uv_close((uv_handle_t*) node->handle, tv__tcp_close_listen_handle);
      }
    }
    if ((handle->pending_timer.data != NULL) && !uv_is_closing((uv_handle_t*) &handle->pending_timer)) {
      uv_close((uv_handle_t*) &handle->pending_timer, NULL);
    }
  } else if (handle->is_connected || handle->is_accepted) {
    /* uv_close_cb is called LIFO in version 0.11.13, so uv_close is called this order */
    if (!uv_is_closing((uv_handle_t*) handle->tcp_handle)) {
      uv_close((uv_handle_t*) handle->tcp_handle, tv__tcp_close_connect_handle);
    }
    if ((handle->pending_timer.data != NULL) && !uv_is_closing((uv_handle_t*) &handle->pending_timer)) {
      uv_close((uv_handle_t*) &handle->pending_timer, NULL);
    }
  } else {
    if (handle->tcp_handle == NULL) {
      /* connecting or initialized */
      if (handle->pending_timer.data == NULL) {
        int ret = 0;

        ret = uv_timer_init(&handle->loop->loop, &handle->pending_timer);
        assert(ret == 0);  /* uv_timer_init always return 0 in version 0.11.13. */
	TV_UNUSED(ret);
        handle->pending_timer.data = handle;
      }
      if (!uv_is_closing((uv_handle_t*) &handle->pending_timer)) {
        uv_close((uv_handle_t*) &handle->pending_timer, tv__tcp_close_handle);
      }
    } else {
      /* uv_close_cb is called LIFO in version 0.11.13, so uv_close is called this order */
      if (!uv_is_closing((uv_handle_t*) handle->tcp_handle)) {
        uv_close((uv_handle_t*) handle->tcp_handle, tv__tcp_close_connect_handle);
      }
      if ((handle->pending_timer.data != NULL) && !uv_is_closing((uv_handle_t*) &handle->pending_timer)) {
        uv_close((uv_handle_t*) &handle->pending_timer, NULL);
      }
    }
  }
}
static void tv__tcp_call_connect_cb(uv_connect_t* connect_req, int status) {
  int ret = 0;
  tv_addrinfo_t* addr = NULL;
  tv_tcp_t* handle = NULL;
  uv_tcp_t* uv_handle = NULL;

  addr = (tv_addrinfo_t*) connect_req->data;
  handle = (tv_tcp_t*) connect_req->handle->data;
  uv_handle = (uv_tcp_t*) connect_req->handle;

  free(connect_req);
  if ((status == UV_ECANCELED) || (status == UV_ENOMEM) ||
      (status && (addr->ai->ai_next == NULL))) {
    /* fatal failure or all addrinfo fail to connect -> call connect_cb with error */
    freeaddrinfo(addr->res);
    free(addr);
    handle->last_err = status;
    if (handle->connect_cb != NULL) {
      handle->connect_cb((tv_stream_t*) handle, handle->last_err);
    }
  } else if (status) {
    /* failure -> reconnect */
    for (addr->ai = addr->ai->ai_next; addr->ai != NULL; addr->ai = addr->ai->ai_next) {
      ret = tv__tcp_connect2(handle, addr);
      if ((ret == TV_ENOMEM) || (ret && (addr->ai->ai_next == NULL))) {
        /* fatal failure or all addrinfo fail to connect -> call connect_cb with error */
        freeaddrinfo(addr->res);
        free(addr);
        handle->last_err = ret;
        if (handle->connect_cb != NULL) {
          handle->connect_cb((tv_stream_t*) handle, handle->last_err);
        }
        return;
      } else if (ret == 0) {
        /* success -> break this loop */
        break;
      }
      /* failure -> reconnect */
    }
  } else {
    /* success */
    ret = uv_tcp_nodelay(uv_handle, 1);
    handle->is_connected = 1;
    freeaddrinfo(addr->res);
    free(addr);
    if (handle->connect_cb != NULL) {
      handle->connect_cb((tv_stream_t*) handle, 0);
    }
  }
}
static void tv__tcp_call_connection_cb(uv_stream_t* uv_server, int status) {
  int ret = 0;
  tv_tcp_t* tv_server = NULL;
  tv_tcp_t* tv_client = NULL;
  uv_tcp_t* uv_client = NULL;

  tv_server = (tv_tcp_t*) uv_server->data;

  if (status) {
    /* in version 0.11.13, when status != 0, accepted fd were closed. */
    if (tv_server->connection_cb != NULL) {
      tv_server->connection_cb((tv_stream_t*) tv_server, NULL, status);
    }
    return;
  }

  tv_client = (tv_tcp_t*)malloc(sizeof(*tv_client));
  assert(tv_client != NULL);  /* do not remove unless it becomes possible to close accepted fd. */
  if (tv_client == NULL) {
    /* TODO: accepted fd close. */
    if (tv_server->connection_cb != NULL) {
      tv_server->connection_cb((tv_stream_t*) tv_server, NULL, TV_ENOMEM);
    }
    return;
  }
  ret = tv_tcp_init(tv_server->loop, tv_client);
  assert(ret == 0);

  uv_client = (uv_tcp_t*)malloc(sizeof(*uv_client));
  assert(uv_client != NULL);  /* do not remove unless it becomes possible to close accepted fd. */
  if (uv_client == NULL) {
    /* TODO: accepted fd close. */
    free(tv_client);
    if (tv_server->connection_cb != NULL) {
      tv_server->connection_cb((tv_stream_t*) tv_server, NULL, TV_ENOMEM);
    }
    return;
  }
  ret = uv_tcp_init(&tv_client->loop->loop, uv_client);
  assert(ret == 0);  /* uv_tcp_init always return 0 in version 0.11.13. */
  uv_client->data = tv_client;

  ret = uv_accept(uv_server, (uv_stream_t*) uv_client);
  if (ret) {
    free(uv_client);
    free(tv_client);
    if (tv_server->connection_cb != NULL) {
      tv_server->connection_cb((tv_stream_t*) tv_server, NULL, ret);
    }
    return;
  }

  ret = uv_tcp_nodelay(uv_client, 1);  /* ignore return value */

  tv_client->tcp_handle = uv_client;
  tv_client->is_accepted = 1;
  if (tv_server->connection_cb != NULL) {
    tv_server->connection_cb((tv_stream_t*) tv_server, (tv_stream_t*) tv_client, 0);
  }
}
static void tv__tcp_close_connect_handle(uv_handle_t* uv_handle) {
  tv_tcp_t* handle = NULL;

  handle = (tv_tcp_t*) uv_handle->data;

  tv__req_queue_erase(handle->loop, (tv_handle_t*) handle);

  tv_stream_destroy((tv_stream_t*) handle);
  if (handle->close_cb != NULL) {
    handle->close_cb((tv_handle_t*) handle);
  }

  free(uv_handle);
}
static void tv__tcp_close_handle(uv_handle_t* uv_handle) {
  tv_tcp_t* handle = NULL;

  handle = (tv_tcp_t*) uv_handle->data;

  tv__req_queue_erase(handle->loop, (tv_handle_t*) handle);

  tv_stream_destroy((tv_stream_t*) handle);
  if (handle->close_cb != NULL) {
    handle->close_cb((tv_handle_t*) handle);
  }
}
static void tv__tcp_close_listen_handle(uv_handle_t* uv_handle) {
  tv_tcp_t* handle = NULL;

  handle = (tv_tcp_t*) uv_handle->data;

  tv__req_queue_erase(handle->loop, (tv_handle_t*) handle);

  tv__tcp_queue_erase(handle, (uv_tcp_t*) uv_handle);
  if (tv__tcp_queue_empty(handle)) {
    tv_stream_destroy((tv_stream_t*) handle);
    if (handle->close_cb != NULL) {
      handle->close_cb((tv_handle_t*) handle);
    }
  }

  free(uv_handle);
}
