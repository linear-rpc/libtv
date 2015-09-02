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
#include "queue.h"

#if defined(WITH_SSL)
# include <openssl/err.h>
#endif

static void tv__req_queue_flush(tv_loop_t* loop) {
  QUEUE* q = NULL;
  tv_req_t* req = NULL;

  uv_mutex_lock(&loop->mutex);
  while (!QUEUE_EMPTY(&loop->req_queue)) {
    q = QUEUE_HEAD(&loop->req_queue);
    req = QUEUE_DATA(q, tv_req_t, queue);
    QUEUE_REMOVE(q);

    switch (req->type) {
    case TV_CONNECT: {
      tv_connect_req_t* connect_req = (tv_connect_req_t*) req;
      tv_stream_t* stream = (tv_stream_t*) connect_req->handle;

      tv__connect(stream, connect_req->host, connect_req->port, connect_req->connect_cb);
      break;
    }
    case TV_LISTEN: {
      tv_listen_req_t* listen_req = (tv_listen_req_t*) req;
      tv_stream_t* stream = (tv_stream_t*) listen_req->handle;

      tv__listen(stream, listen_req->host, listen_req->port, listen_req->backlog, listen_req->connection_cb);

      uv_mutex_lock(&stream->sync_mutex);
      uv_cond_signal(&stream->sync_cond);
      uv_mutex_unlock(&stream->sync_mutex);
      break;
    }
    case TV_READ_START: {
      tv_read_start_req_t* read_start_req = (tv_read_start_req_t*) req;
      tv_stream_t* stream = (tv_stream_t*) read_start_req->handle;

      tv__read_start(stream, read_start_req->read_cb);
      break;
    }
    case TV_READ_STOP: {
      tv_read_stop_req_t* read_stop_req = (tv_read_stop_req_t*) req;
      tv_stream_t* stream = (tv_stream_t*) read_stop_req->handle;

      tv__read_stop(stream);
      break;
    }
    case TV_WRITE: {
      tv_write_req_t* write_req = (tv_write_req_t*) req;
      tv_stream_t* stream = (tv_stream_t*) write_req->handle;

      tv__write(write_req->req, stream, write_req->buf, write_req->write_cb);
      break;
    }
    case TV_CLOSE: {
      tv_close_req_t* close_req = (tv_close_req_t*) req;

      tv__close(close_req->handle, close_req->close_cb);
      break;
    }
    case TV_TIMER_START: {
      tv_timer_start_req_t* timer_start_req = (tv_timer_start_req_t*) req;
      tv_timer_t* timer = (tv_timer_t*) timer_start_req->handle;

      tv__timer_start(timer, timer_start_req->timer_cb, timer_start_req->timeout, timer_start_req->repeat);
      break;
    }
    case TV_TIMER_STOP: {
      tv_timer_stop_req_t* timer_stop_req = (tv_timer_stop_req_t*) req;
      tv_timer_t* timer = (tv_timer_t*) timer_stop_req->handle;

      tv__timer_stop(timer);
      break;
    }
    case TV_PIPE_CONNECT: {
      tv_pipe_connect_req_t* connect_req = (tv_pipe_connect_req_t*) req;
      tv_pipe_t *handle = (tv_pipe_t*) connect_req->handle;

      tv__pipe_connect(handle, connect_req->name, connect_req->connect_cb);
      break;
    }
    case TV_PIPE_LISTEN: {
      tv_pipe_listen_req_t* listen_req = (tv_pipe_listen_req_t*)req;
      tv_pipe_t *handle = (tv_pipe_t*) listen_req->handle;
      tv__pipe_listen(handle, listen_req->name, listen_req->backlog, listen_req->connection_cb);

      uv_mutex_lock(&handle->sync_mutex);
      uv_cond_signal(&handle->sync_cond);
      uv_mutex_unlock(&handle->sync_mutex);
      break;
    }
    case TV_LOOP_CLOSE: {
      tv_loop_close_req_t* loop_close_req = (tv_loop_close_req_t*) req;

      tv__loop_close(loop_close_req->loop);
      break;
    }
    default:
      assert(0);
    }

    free(req);
  }
  uv_mutex_unlock(&loop->mutex);
}
static void tv__loop_async_cb(uv_async_t* async) {
  tv_loop_t* loop = NULL;
  
  loop = (tv_loop_t*) async->data;
  tv__req_queue_flush(loop);
}

static void tv__loop_thread_cb(void* arg) {
  tv_loop_t* loop = NULL;
  
  loop = (tv_loop_t*) arg;

  uv_run(&loop->loop, UV_RUN_DEFAULT);
#if defined(WITH_SSL)
  ERR_remove_thread_state(NULL);
#endif
}

void tv_req_init(tv_req_t* req, tv_handle_t* handle, tv_req_type type) {
  QUEUE_INIT(&req->queue);
  req->type = type;
  req->handle = handle;
}
void tv_req_queue_push(tv_loop_t* loop, tv_req_t* req) {
  uv_mutex_lock(&loop->mutex);
  QUEUE_INSERT_TAIL(&loop->req_queue, &req->queue);
  uv_mutex_unlock(&loop->mutex);
}
void tv_req_queue_flush(tv_loop_t* loop) {
  int ret = 0;

  ret = uv_async_send(&loop->async);
  assert(ret == 0);  /* uv_async_send always return 0 in version 0.11.26. */
  TV_UNUSED(ret);
}

static void tv__req_queue_drain(tv_loop_t* loop, QUEUE* dst, tv_handle_t* handle) {
  QUEUE* q = NULL;
  tv_req_t* req = NULL;

  uv_mutex_lock(&loop->mutex);
  QUEUE_FOREACH(q, &loop->req_queue) {
    req = QUEUE_DATA(q, tv_req_t, queue);
    if (req->handle == handle) {
      QUEUE* prev_q = QUEUE_PREV(q);
      QUEUE_REMOVE(q);
      q = prev_q;

      QUEUE_INIT(&req->queue);
      QUEUE_INSERT_TAIL(dst, &req->queue);
    }
  }
  uv_mutex_unlock(&loop->mutex);
}
void tv__req_queue_erase(tv_loop_t* loop, tv_handle_t* handle) {
  QUEUE tmp_queue;
  QUEUE* q = NULL;
  QUEUE* prev_q = NULL;
  tv_req_t* req = NULL;

  QUEUE_INIT(&tmp_queue);
  tv__req_queue_drain(loop, &tmp_queue, handle);

  QUEUE_FOREACH(q, &tmp_queue) {
    req = QUEUE_DATA(q, tv_req_t, queue);

    prev_q = QUEUE_PREV(q);
    QUEUE_REMOVE(q);
    q = prev_q;

    switch (req->type) {
    case TV_CONNECT:
    case TV_LISTEN:
    case TV_READ_START:
    case TV_READ_STOP:
    case TV_CLOSE:
    case TV_TIMER_START:
    case TV_TIMER_STOP:
      free(req);
      break;
    case TV_WRITE:
      tv__write_cancel((tv_write_req_t*) req);
      break;
    case TV_LOOP_CLOSE:
      /* fprintf(stderr, "must not come here.\n"); */
      break;
    default:
      /* fprintf(stderr, "unknown type\n"); */
      ;
    }
  }
}

int tv_loop_init(tv_loop_t* loop) {
  int ret = 0;

  ret = uv_loop_init(&loop->loop);
  if (ret) {
    return ret;
  }

  ret = uv_mutex_init(&loop->mutex);
  if (ret) {
    uv_loop_close(&loop->loop);  /* no check return value */
    return ret;
  }

  QUEUE_INIT(&loop->req_queue);

  ret = uv_async_init(&loop->loop, &loop->async, tv__loop_async_cb);
  if (ret) {
    uv_mutex_destroy(&loop->mutex);
    uv_loop_close(&loop->loop);  /* no check return value */
    return ret;
  }
  loop->async.data = loop;

  ret = uv_thread_create(&loop->thread, tv__loop_thread_cb, loop);
  if (ret) {
    uv_close((uv_handle_t*) &loop->async, NULL);
    uv_mutex_destroy(&loop->mutex);
    uv_loop_close(&loop->loop);  /* no check return value */
    return ret;
  }

  return 0;
}
int tv_loop_close(tv_loop_t* loop) {
  int ret = 0;
  tv_loop_close_req_t* tv_req = NULL;

  tv_req = malloc(sizeof(*tv_req));
  if (tv_req == NULL) {
    return TV_ENOMEM;
  }
  tv_req_init((tv_req_t*) tv_req, NULL, TV_LOOP_CLOSE);
  tv_req->loop = loop;

  tv_req_queue_push(loop, (tv_req_t*) tv_req);
  tv_req_queue_flush(loop);

  uv_thread_join(&loop->thread);
  uv_mutex_destroy(&loop->mutex);
  ret = uv_loop_close(&loop->loop);
  if (ret) {
    return ret;
  }

  return 0;
}

tv_loop_t* tv_loop_new(void) {
  int ret = 0;
  tv_loop_t* loop = NULL;

  loop = malloc(sizeof(*loop));
  if (loop == NULL) {
    return NULL;
  }

  ret = tv_loop_init(loop);
  if (ret) {
    free(loop);
    return NULL;
  }

  return loop;
}
int tv_loop_delete(tv_loop_t* loop) {
  int ret = 0;

  ret = tv_loop_close(loop);
  if (ret) {
    return ret;
  }

  free(loop);

  return 0;
}

static void tv__loop_close_uv_handle(uv_handle_t* handle, void* arg) {
  if (!uv_is_closing(handle)) {
    uv_close(handle, NULL);
  }
}
void tv__loop_close(tv_loop_t* loop) {
  uv_walk(&loop->loop, tv__loop_close_uv_handle, NULL);
}
