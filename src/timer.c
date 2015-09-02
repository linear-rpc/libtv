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

int tv_timer_init(tv_loop_t* loop, tv_timer_t* timer) {
  int ret = 0;

  if ((loop == NULL) || (timer == NULL)) {
    return TV_EINVAL;
  }

  ret = tv_handle_init(TV_TIMER, loop, (tv_handle_t*) timer);
  assert(ret == 0);

  timer->timer.data = NULL;
  timer->timer_cb = NULL;

  return ret;
}
int tv_timer_start(tv_timer_t* timer, tv_timer_cb timer_cb, uint64_t timeout, uint64_t repeat) {
  uv_thread_t current_thread = uv_thread_self();
  if (uv_thread_equal(&timer->loop->thread, &current_thread)) {
    tv__timer_start(timer, timer_cb, timeout, repeat);
    return 0;
  } else {
    tv_timer_start_req_t* tv_req = NULL;

    tv_req = malloc(sizeof(*tv_req));
    if (tv_req == NULL) {
      return TV_ENOMEM;
    }
    tv_req_init((tv_req_t*) tv_req, (tv_handle_t*) timer, TV_TIMER_START);
    tv_req->timer_cb = timer_cb;
    tv_req->timeout  = timeout;
    tv_req->repeat   = repeat;

    tv_req_queue_push(timer->loop, (tv_req_t*) tv_req);
    tv_req_queue_flush(timer->loop);
    return 0;
  }
}
int tv_timer_stop(tv_timer_t* timer) {
  uv_thread_t current_thread = uv_thread_self();
  if (uv_thread_equal(&timer->loop->thread, &current_thread)) {
    tv__timer_stop(timer);
    tv__req_queue_erase(timer->loop, (tv_handle_t *)timer);
    return 0;
  } else {
    tv_timer_stop_req_t* tv_req = NULL;

    tv_req = malloc(sizeof(*tv_req));
    if (tv_req == NULL) {
      return TV_ENOMEM;
    }
    tv_req_init((tv_req_t*) tv_req, (tv_handle_t*) timer, TV_TIMER_STOP);

    tv_req_queue_push(timer->loop, (tv_req_t*) tv_req);
    tv_req_queue_flush(timer->loop);
    return 0;
  }
}

static void tv__timer_timer_cb(uv_timer_t* uv_handle) {
  tv_timer_t* timer = NULL;
 
  timer = (tv_timer_t*) uv_handle->data;
  if (timer->timer_cb != NULL) {
    timer->timer_cb(timer);
  }
}
void tv__timer_start(tv_timer_t* timer, tv_timer_cb timer_cb, uint64_t timeout, uint64_t repeat) {
  int ret = 0;

  timer->timer_cb = timer_cb;

  if (timer->timer.data == NULL) {
    ret = uv_timer_init(&timer->loop->loop, &timer->timer);
    assert(ret == 0);  /* uv_timer_init always return 0 in version 0.11.26. */
    timer->timer.data = timer;
  }

  uv_update_time(&timer->loop->loop);
  ret = uv_timer_start(&timer->timer, tv__timer_timer_cb, timeout, repeat);
  assert(ret == 0);  /* uv_timer_start always return 0 in version 0.11.26. */
  TV_UNUSED(ret);
}

void tv__timer_stop(tv_timer_t* timer) {
  int ret = 0;

  if (timer->timer.data == NULL) {
    ret = uv_timer_init(&timer->loop->loop, &timer->timer);
    assert(ret == 0);  /* uv_timer_init always return 0 in version 0.11.26. */
    timer->timer.data = timer;
  }

  ret = uv_timer_stop(&timer->timer);
  assert(ret == 0);  /* uv_timer_start always return 0 in version 0.11.26. */
  TV_UNUSED(ret);
}

static void tv__timer_close_cb(uv_handle_t* uv_handle) {
  tv_timer_t* timer = NULL;
  
  timer = (tv_timer_t*) uv_handle->data;

  tv__req_queue_erase(timer->loop, (tv_handle_t*) timer);

  if (timer->close_cb != NULL) {
    timer->close_cb((tv_handle_t*) timer);
  }
}
void tv__timer_close(tv_timer_t* handle, tv_close_cb close_cb) {
  int ret = 0;

  handle->close_cb = close_cb;

  if (handle->timer.data == NULL) {
    ret = uv_timer_init(&handle->loop->loop, &handle->timer);
    assert(ret == 0);  /* uv_timer_init always return 0 in version 0.11.26. */
    TV_UNUSED(ret);
    handle->timer.data = handle;
  }

  if (!uv_is_closing((uv_handle_t*) &handle->timer)) {
    uv_close((uv_handle_t*) &handle->timer, tv__timer_close_cb);
  }
}
