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
#ifndef WS_FRAME_H_
#define WS_FRAME_H_

#include <stdint.h>

#include "websocket/buffer.h"

#define WSFRM_NORMAL    (1000)
#define WSFRM_GOAWAY    (1001)
#define WSFRM_EPROTO    (1002)
#define WSFRM_EDATA     (1003)
#define WSFRM_ETYPE     (1007)
#define WSFRM_ESIZE     (1009)
#define WSFRM_EINTERNAL (1011)

#ifdef __cplusplus
extern "C" {
#endif

enum ws_frame_state {
  WSFRM_INIT,
  WSFRM_LENGTH,
  WSFRM_EXLENGTH,
  WSFRM_MASK,
  WSFRM_PAYLOAD
};

enum ws_frame_type {
  WSFRM_TEXT,
  WSFRM_BINARY,
  WSFRM_CLOSE,
  WSFRM_PING,
  WSFRM_PONG
};

typedef struct _ws_frame_header {
  unsigned char flags[2];
  unsigned char lencnt;
  enum ws_frame_type type;
  uint64_t len;
  buffer mask;
} ws_frame_header;

enum ws_frame_mode {
  WSFRM_CLIENT = 0,
  WSFRM_SERVER = 1
};

typedef struct _ws_frame {
  enum ws_frame_state state;
  enum ws_frame_mode mode;
  int err;
  ws_frame_header header;
  buffer payload;
  void *data;
} ws_frame;

typedef void (*ws_frame_cb)(ws_frame *frame);

typedef struct _ws_frame_settings {
  ws_frame_cb on_complete;
  ws_frame_cb on_error;
} ws_frame_settings;

WS_EXTERN void ws_frame_init(ws_frame *frame, enum ws_frame_mode mode);
WS_EXTERN void ws_frame_fin(ws_frame *frame);
WS_EXTERN void ws_frame_reset(ws_frame *frame);
WS_EXTERN size_t ws_frame_execute(ws_frame *frame, ws_frame_settings *settings, const char *p, size_t siz);
WS_EXTERN int ws_frame_create(buffer *frame_data, const char *p, size_t siz, enum ws_frame_type type, int do_mask);

#ifdef __cplusplus
}
#endif

#endif  /* WS_FRAME_H_ */
