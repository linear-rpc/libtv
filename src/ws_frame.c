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

#include "websocket/ws_frame.h"

void ws_frame_init(ws_frame *frame, enum ws_frame_mode mode) {
  assert(frame);
  frame->state = WSFRM_INIT;
  frame->mode = mode;
  frame->err = WSFRM_NORMAL;
  frame->header.flags[0] = 0;
  frame->header.flags[1] = 0;
  frame->header.type = WSFRM_TEXT;
  frame->header.len = 0;
  buffer_init(&frame->header.mask);
  buffer_init(&frame->payload);
  frame->data = NULL;
}

void ws_frame_fin(ws_frame *frame) {
  assert(frame);
  buffer_fin(&frame->header.mask);
  buffer_fin(&frame->payload);
  frame->data = NULL;
}

void ws_frame_reset(ws_frame *frame) {
  assert(frame);
  frame->state = WSFRM_INIT;
  frame->err = WSFRM_NORMAL;
  frame->header.flags[0] = 0;
  frame->header.flags[1] = 0;
  frame->header.type = WSFRM_TEXT;
  frame->header.len = 0;
  buffer_reset(&frame->header.mask);
  buffer_reset(&frame->payload);
}

STATIC_INLINE void unmask_payload(ws_frame *frame) {
  size_t i;
  for (i = 0; i < frame->payload.len; i++) {
    frame->payload.ptr[i] = frame->payload.ptr[i] ^ frame->header.mask.ptr[i % 4];
  }
}

size_t ws_frame_execute(ws_frame *frame, ws_frame_settings *settings, const char *p, size_t siz) {
  size_t i;
  uint64_t rest, toread;
  unsigned char _len, _mask;
  assert(frame && settings && p);
  for (i = 0; i < siz; i++) {
    switch(frame->state) {
    case WSFRM_INIT:
      frame->header.lencnt = 0;
      frame->header.len = 0;
      buffer_reset(&frame->header.mask);
      buffer_reset(&frame->payload);
      frame->header.flags[0] = (unsigned char)p[i];
      switch(frame->header.flags[0] & 0x0f) {
      case 0x00:
        break;
      case 0x01:
        frame->header.type = WSFRM_TEXT;
        break;
      case 0x02:
        frame->header.type = WSFRM_BINARY;
        break;
      case 0x08:
        frame->header.type = WSFRM_CLOSE;
        break;
      case 0x09:
        frame->header.type = WSFRM_PING;
        break;
      case 0x0a:
        frame->header.type = WSFRM_PONG;
        break;
      default:
        frame->err = WSFRM_EPROTO;
        settings->on_error(frame);
        return 0;
      }
      frame->state = WSFRM_LENGTH;
      break;
    case WSFRM_LENGTH:
      frame->header.flags[1] = (unsigned char)p[i];
      _mask = frame->header.flags[1] & 0x80;
      if (frame->mode == WSFRM_SERVER && _mask != 0x80) {
        frame->err = WSFRM_EPROTO;
        settings->on_error(frame);
        frame->state = WSFRM_INIT;
        return 0;
      }
      _len = frame->header.flags[1] & 0x7f;
      if (_len < 0x7e) {
        frame->header.len = (uint64_t)_len;
        if (_mask == 0x80) {
          frame->state = WSFRM_MASK;
        } else {
          if (_len == 0) {
            settings->on_complete(frame);
            frame->state = WSFRM_INIT;
          } else {
            frame->state = WSFRM_PAYLOAD;
          }
        }
      } else {
        frame->state = WSFRM_EXLENGTH;
      }
      break;
    case WSFRM_EXLENGTH:
      frame->header.lencnt++;
      _mask = frame->header.flags[1] & 0x80;
      _len = frame->header.flags[1] & 0x7f;
      frame->header.len = (frame->header.len << 8) + (uint64_t)(p[i] & 0xff);
      if ((_len == 0x7e && frame->header.lencnt == 2) ||
          (_len == 0x7f && frame->header.lencnt == 8)) {
        if (_mask == 0x80) {
          frame->state = WSFRM_MASK;
        } else {
          if (frame->header.len == 0) {
            settings->on_complete(frame);
            frame->state = WSFRM_INIT;
          } else {
            frame->state = WSFRM_PAYLOAD;
          }
        }
      }
      break;
    case WSFRM_MASK:
      if (buffer_append(&frame->header.mask, &p[i], 1)) {
        frame->err = WSFRM_EINTERNAL;
        settings->on_error(frame);
        frame->state = WSFRM_INIT;
        return 0;
      }
      if (frame->header.mask.len == 4) {
        if ((frame->header.flags[1] & 0x7f) == 0) {
          settings->on_complete(frame);
          frame->state = WSFRM_INIT;
        } else {
          frame->state = WSFRM_PAYLOAD;
        }
      }
      break;
    case WSFRM_PAYLOAD:
      if (frame->header.len >= (uint64_t)((size_t)-1)) {
        frame->err = WSFRM_ESIZE;
        settings->on_error(frame);
        frame->state = WSFRM_INIT;
        return 0;
      }
      rest = (frame->header.len - frame->payload.len);
      toread = ((siz - i) <= rest) ? (siz - i) : rest;
      if (buffer_append(&frame->payload, &p[i], (size_t)toread)) {
        frame->err = WSFRM_EINTERNAL;
        settings->on_error(frame);
        frame->state = WSFRM_INIT;
        return 0;
      }
      if (frame->payload.len == frame->header.len) {
        if ((frame->header.flags[1] & 0x80) == 0x80) {
          unmask_payload(frame);
        }
        settings->on_complete(frame);
        frame->state = WSFRM_INIT;
      }
      i += (size_t)toread - 1;
      break;
    default:
      frame->err = WSFRM_EINTERNAL;
      settings->on_error(frame);
      frame->state = WSFRM_INIT;
      return 0;
    }
  }
  return i;
}

STATIC_INLINE void mask_payload(buffer *payload, buffer *mask) {
  size_t i;
  for (i = 0; i < payload->len; i++) {
    payload->ptr[i] = payload->ptr[i] ^ mask->ptr[i % 4];
  }
}

int ws_frame_create(buffer *buf, const char *p, size_t siz, enum ws_frame_type type, int do_mask) {
  char flags[2];
  char len16[2];
  char len64[8];
  buffer mask, payload;
  assert(buf);
  flags[0] = (char)0x80;
  switch(type) {
  case WSFRM_TEXT:
    flags[0] |= 0x01;
    break;
  case WSFRM_BINARY:
    flags[0] |= 0x02;
    break;
  case WSFRM_CLOSE:
    flags[0] |= 0x08;
    break;
  case WSFRM_PING:
    flags[0] |= 0x09;
    break;
  case WSFRM_PONG:
    flags[0] |= 0x0A;
    break;
  default: /* not reach*/
    assert(0);
    return -1;
  }
  if (siz < 0x7e) {
    flags[1] = (char)(siz & 0x7f);
  } else if (siz < (size_t)((uint16_t)-1)) {
    flags[1] = 0x7e;
    len16[0] = (siz >> 8) & 0xff;
    len16[1] =  siz       & 0xff;
  } else {
    flags[1] = 0x7f;

#if __WORDSIZE == 64
    len64[0] = (siz >> 56) & 0x7f;
    len64[1] = (siz >> 48) & 0xff;
    len64[2] = (siz >> 40) & 0xff;
    len64[3] = (siz >> 32) & 0xff;
#else
    len64[0] = 0;
    len64[1] = 0;
    len64[2] = 0;
    len64[3] = 0;
#endif

    len64[4] = (siz >> 24) & 0xff;
    len64[5] = (siz >> 16) & 0xff;
    len64[6] = (siz >>  8) & 0xff;
    len64[7] =  siz        & 0xff;
  }
  flags[1] = (do_mask) ? (flags[1] | 0x80) : flags[1];
  buffer_reset(buf);
  if (buffer_append(buf, flags, 2)) {
    return -1;
  }
  if ((flags[1] & 0x7f) == 0x7f) {
    if (buffer_append(buf, len64, 8)) {
      return -1;
    }
  } else if ((flags[1] & 0x7e) == 0x7e) {
    if (buffer_append(buf, len16, 2)) {
      return -1;
    }
  }
  if (do_mask) {
    buffer_init(&mask);
    if (buffer_fill_random(&mask, 4)) {
      buffer_fin(&mask);
      return -1;
    }
    if (buffer_append(buf, mask.ptr, mask.len)) {
      buffer_fin(&mask);
      return -1;
    }
    buffer_init(&payload);
    if (buffer_append(&payload, p, siz)) {
      buffer_fin(&payload);
      buffer_fin(&mask);
      return -1;
    }
    mask_payload(&payload, &mask);
    buffer_fin(&mask);
    if (buffer_append(buf, payload.ptr, payload.len)) {
      buffer_fin(&payload);
      return -1;
    }
    buffer_fin(&payload);
  } else {
    if (buffer_append(buf, p, siz)) {
      return -1;
    }
  }
  return 0;
}
