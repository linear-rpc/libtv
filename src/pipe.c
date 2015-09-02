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
#include "queue.h"

int tv_pipe_init(tv_loop_t* loop, tv_pipe_t* handle, int ipc) {
  int ret = 0;

  if ((loop == NULL) || (handle == NULL)) {
    return TV_EINVAL;
  }

  ret = tv_stream_init(TV_PIPE, loop, (tv_stream_t*) handle);
  if (ret) {
    return ret;
  }

  handle->pipe_handle.data = NULL;
  handle->ipc = ipc;

  return 0;
}
int tv_pipe_connect(tv_pipe_t* handle, const char* name, tv_connect_cb connect_cb) {
  uv_thread_t current_thread = uv_thread_self();
  if (uv_thread_equal(&handle->loop->thread, &current_thread)) {
    tv__pipe_connect(handle, name, connect_cb);
    return 0;
  } else {
    size_t req_len = 0;
    size_t name_len = 0;
    void* mem = NULL;
    tv_pipe_connect_req_t* tv_req = NULL;

    if (name == NULL) {
      return TV_EINVAL;
    }

    req_len = sizeof(*tv_req);
    name_len = strlen(name) + 1;

    mem = malloc(req_len + name_len);
    if (mem == NULL) {
      return TV_ENOMEM;
    }

    tv_req = mem;
    tv_req_init((tv_req_t*) tv_req, (tv_handle_t*) handle, TV_PIPE_CONNECT);
    tv_req->name = (char*) memcpy(((char*) mem) + req_len, name, name_len);
    tv_req->connect_cb = connect_cb;

    tv_req_queue_push(handle->loop, (tv_req_t*) tv_req);
    tv_req_queue_flush(handle->loop);
    return 0;
  }
}
int tv_pipe_listen(tv_pipe_t* handle, const char* name, int backlog, tv_connection_cb connection_cb) {
  uv_thread_t current_thread = uv_thread_self();
  if (uv_thread_equal(&handle->loop->thread, &current_thread)) {
    tv__pipe_listen(handle, name, backlog, connection_cb);
    return handle->last_err;  /* handle->last_err is updated in loop thread only. */
  } else {
    size_t req_len = 0;
    size_t name_len = 0;
    void* mem = NULL;
    tv_pipe_listen_req_t* tv_req = NULL;

    if (name == NULL) {
      return TV_EINVAL;
    }

    req_len = sizeof(*tv_req);
    name_len = strlen(name) + 1;

    mem = malloc(req_len + name_len);
    if (mem == NULL) {
      return TV_ENOMEM;
    }

    tv_req = mem;
    tv_req_init((tv_req_t*) tv_req, (tv_handle_t*) handle, TV_PIPE_LISTEN);
    tv_req->name = (char*) memcpy(((char*) mem) + req_len, name, name_len);
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

static void tv__pipe_connect_cb(uv_connect_t* connect_req, int status) {
  tv_pipe_t* handle = NULL;

  handle = (tv_pipe_t*) connect_req->handle->data;

  if (status == 0) {
    handle->is_connected = 1;
  }

  free(connect_req);
  if (handle->connect_cb != NULL) {
    handle->connect_cb((tv_stream_t*) handle, status);
  }
}
void tv__pipe_connect(tv_pipe_t* handle, const char* name, tv_connect_cb connect_cb) {
  int ret = 0;
  uv_connect_t* connect_req = NULL;

  handle->connect_cb = connect_cb;

  if (handle->is_connected) {
    /* Unless it becomes possible that tv_pipe_connect returns false using state corresponded to multi-thread. */
    tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_EISCONN);
    return;
  }

  connect_req = malloc(sizeof(*connect_req));
  if (connect_req == NULL) {
    tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
    return;
  }

  if (handle->pipe_handle.data == NULL) {
    ret = uv_pipe_init(&handle->loop->loop, &handle->pipe_handle, handle->ipc);
    assert(ret == 0);  /* uv_pipe_init always return 0 in version 0.11.26. */
    TV_UNUSED(ret);
    handle->pipe_handle.data = handle;
  }

  uv_pipe_connect(connect_req, &handle->pipe_handle, name, tv__pipe_connect_cb);
}

static void tv__pipe_connection_cb(uv_stream_t* uv_server, int status) {
  int ret = 0;
  tv_pipe_t* tv_server = NULL;
  tv_pipe_t* tv_client = NULL;

  tv_server = (tv_pipe_t*) uv_server->data;

  if (status) {
    if (tv_server->connection_cb != NULL) {
      tv_server->connection_cb((tv_stream_t*) tv_server, NULL, status);
    }
    return;
  }

  tv_client = malloc(sizeof(*tv_client));
  assert(tv_client != NULL);  /* Unless it becomes possible to close accepted fd. */
  if (tv_client == NULL) {
    /* TODO: accepted fd close. */
    if (tv_server->connection_cb != NULL) {
      tv_server->connection_cb((tv_stream_t*) tv_server, NULL, UV_ENOMEM);
    }
    return;
  }
  ret = tv_pipe_init(tv_server->loop, tv_client, tv_server->ipc);
  assert(ret == 0);

  ret = uv_pipe_init(&tv_client->loop->loop, &tv_client->pipe_handle, tv_client->ipc);
  assert(ret == 0);  /* uv_pipe_init always return 0 in version 0.11.26. */
  tv_client->pipe_handle.data = tv_client;

  ret = uv_accept(uv_server, (uv_stream_t*) &tv_client->pipe_handle);
  if (ret) {
    tv__pipe_close(tv_client, tv__handle_free_handle);
    if (tv_server->connection_cb != NULL) {
      tv_server->connection_cb((tv_stream_t*) tv_server, NULL, ret);
    }
    return;
  }

  tv_client->is_accepted = 1;
  if (tv_server->connection_cb != NULL) {
    tv_server->connection_cb((tv_stream_t*) tv_server, (tv_stream_t*) tv_client, 0);
  }
}
void tv__pipe_listen(tv_pipe_t* handle, const char* name, int backlog, tv_connection_cb connection_cb) {
  int ret = 0;

  handle->connection_cb = connection_cb;

  if (handle->is_listened) {
    handle->last_err = TV_EISCONN;
    return;
  }

  if (handle->pipe_handle.data == NULL) {
    ret = uv_pipe_init(&handle->loop->loop, &handle->pipe_handle, handle->ipc);
    assert(ret == 0);  /* uv_pipe_init always return 0 in version 0.11.26. */
    handle->pipe_handle.data = handle;
  }

  ret = uv_pipe_bind(&handle->pipe_handle, name);
  if (ret) {
    if (!uv_is_closing((uv_handle_t*) &handle->pipe_handle)) {
      uv_close((uv_handle_t*) &handle->pipe_handle, NULL);
    }
    handle->last_err = ret;
    return;
  }
  ret = uv_listen((uv_stream_t*) &handle->pipe_handle, backlog, tv__pipe_connection_cb);
  if (ret) {
    if (!uv_is_closing((uv_handle_t*) &handle->pipe_handle)) {
      uv_close((uv_handle_t*) &handle->pipe_handle, NULL);
    }
    handle->last_err = ret;
    return;
  }
  handle->is_listened = 1;
  handle->last_err = 0;
}
void tv__pipe_read_start(tv_pipe_t* handle, tv_read_cb read_cb) {
  int ret = 0;

  handle->read_cb = read_cb;

  ret = uv_read_start((uv_stream_t*) &handle->pipe_handle, tv__handle_alloc_cb, tv__stream_read_cb);
  assert(ret == 0);  /* in version 0.11.13, uv_read_start always return 0 if immediately after connect_cb called with status = 0. */
  TV_UNUSED(ret);
}
void tv__pipe_read_stop(tv_pipe_t* handle) {
  int ret = 0;

  handle->read_cb = NULL;

  ret = uv_read_stop((uv_stream_t*) &handle->pipe_handle);
  assert(ret == 0);  /* in version 0.11.13, uv_read_stop always return 0 unless type is tty. */
  TV_UNUSED(ret);
}
void tv__pipe_write(tv_write_t* req, tv_pipe_t* handle, tv_buf_t buf, tv_write_cb write_cb) {
  int ret = 0;
  uv_write_t* uv_req = NULL;

  tv_write_init(req, (tv_stream_t*) handle, buf, write_cb);

  if (!(handle->is_connected || handle->is_accepted)) {
    tv__stream_delayed_write_cb(req, TV_ENOTCONN);
    return;
  }

  uv_req = malloc(sizeof(*uv_req));
  if (uv_req == NULL) {
    tv__stream_delayed_write_cb(req, TV_ENOMEM);
    return;
  }
  uv_req->data = req;

  ret = uv_write(uv_req, (uv_stream_t*) &handle->pipe_handle, &buf, 1, tv__stream_write_cb);
  if (ret) {
    free(uv_req);
    tv__stream_delayed_write_cb(req, ret);
    return;
  }
}
static void tv_pipe_destroy(tv_pipe_t* handle) {
  handle->pipe_handle.data = NULL;
  tv_stream_destroy((tv_stream_t*) handle);
}
static void tv__pipe_close_handle(uv_handle_t* uv_handle) {
  tv_pipe_t* handle = NULL;

  handle = (tv_pipe_t*) uv_handle->data;

  tv__req_queue_erase(handle->loop, (tv_handle_t*) handle);

  tv_pipe_destroy(handle);
  if (handle->close_cb != NULL) {
    handle->close_cb((tv_handle_t*) handle);
  }
}
void tv__pipe_close(tv_pipe_t* handle, tv_close_cb close_cb) {
  int ret = 0;
  handle->close_cb = close_cb;

  if (handle->pipe_handle.data == NULL) {
    ret = uv_pipe_init(&handle->loop->loop, &handle->pipe_handle, handle->ipc);
    assert(ret == 0);  /* uv_pipe_init always return 0 in version 0.11.26. */
    TV_UNUSED(ret);
    handle->pipe_handle.data = handle;
  }
  /* uv_close_cb is called LIFO in version 0.11.13, so uv_close is called this order */
  if (!uv_is_closing((uv_handle_t*) &handle->pipe_handle)) {
    uv_close((uv_handle_t*) &handle->pipe_handle, tv__pipe_close_handle);
  }
  if ((handle->pending_timer.data != NULL) && !uv_is_closing((uv_handle_t*) &handle->pending_timer)) {
    uv_close((uv_handle_t*) &handle->pending_timer, NULL);
  }
}
