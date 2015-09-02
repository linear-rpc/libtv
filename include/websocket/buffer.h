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
#ifndef BUFFER_H_
#define BUFFER_H_

#include <stdlib.h>

#include "websocket/slist.h"

#if defined(_WIN32)
# define STATIC_INLINE static __inline
  /* Windows - set up dll import/export decorators. */
# if defined(BUILDING_WS_SHARED)
   /* Building shared library. */
#  define WS_EXTERN __declspec(dllexport)
# elif defined(USING_WS_SHARED)
   /* Using shared library. */
#  define WS_EXTERN __declspec(dllimport)
# else
   /* Building static library. */
#  define WS_EXTERN /* nothing */
# endif
#elif __GNUC__ >= 4
# define STATIC_INLINE static inline
# define WS_EXTERN __attribute__((visibility("default")))
#else
# define STATIC_INLINE static inline
# define WS_EXTERN /* nothing */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CONST_STRING(s) s, (sizeof(s) - 1)

/**
 * buffer.
 */
typedef struct buffer {
  char *ptr;  /* NUL termination is guaranteed */
  size_t len;
  size_t siz;
} buffer;

STATIC_INLINE void buffer_init(buffer *b) {
  b->ptr = NULL; b->len = 0; b->siz = 0;
}
STATIC_INLINE void buffer_fin(buffer *b) {
  if (b->ptr) { free(b->ptr); b->ptr = NULL; }
}
STATIC_INLINE void buffer_reset(buffer *b) {
  b->len = 0;
}
WS_EXTERN int buffer_append(buffer *b, const char *p, size_t len);
WS_EXTERN void buffer_to_lower(buffer *b);
WS_EXTERN int buffer_from_base64(buffer *b);
WS_EXTERN int buffer_to_base64(buffer *b);
WS_EXTERN int buffer_to_md5sum(buffer *b);
WS_EXTERN int buffer_fill_random(buffer *b, size_t len);

/**
 * buffer_kv.
 */
typedef struct buffer_kv {
  buffer key;
  buffer val;
  SLIST_ENTRY(buffer_kv, entry);
} buffer_kv;

STATIC_INLINE void buffer_kv_init(buffer_kv *kv) {
  buffer_init(&kv->key);
  buffer_init(&kv->val);
  SLIST_ENTRY_INIT(kv, entry);
}
STATIC_INLINE void buffer_kv_fin(buffer_kv *kv) {
  buffer_fin(&kv->key);
  buffer_fin(&kv->val);
}
STATIC_INLINE void buffer_kv_reset(buffer_kv *kv) {
  buffer_reset(&kv->key);
  buffer_reset(&kv->val);
}
STATIC_INLINE int buffer_kv_set_key(buffer_kv *kv, const buffer *key) {
  buffer_reset(&kv->key);
  return buffer_append(&kv->key, key->ptr, key->len);
}
STATIC_INLINE int buffer_kv_set_value(buffer_kv *kv, const buffer *val) {
  buffer_reset(&kv->val);
  return buffer_append(&kv->val, val->ptr, val->len);
}
STATIC_INLINE int buffer_kv_set(buffer_kv *kv, const buffer *key, const buffer *val) {
  int ret = buffer_kv_set_key(kv, key);
  return (ret == 0) ? buffer_kv_set_value(kv, val) : ret;
}

/**
 * buffer_kvs.
 */
typedef struct buffer_kvs {
  SLIST(buffer_kv, slist);
} buffer_kvs;

STATIC_INLINE void buffer_kvs_init(buffer_kvs *kvs) {
  SLIST_INIT(kvs, slist);
}
WS_EXTERN void buffer_kvs_fin(buffer_kvs *kvs);
WS_EXTERN int buffer_kvs_insert(buffer_kvs *kvs, const buffer_kv *kv);
STATIC_INLINE const buffer_kv *buffer_kvs_get_first(const buffer_kvs *kvs) {
  return SLIST_GET_FIRST(kvs, slist);
}
STATIC_INLINE const buffer_kv *buffer_kvs_get_next(const buffer_kv *kv) {
  return SLIST_GET_NEXT(kv, entry);
}
WS_EXTERN const buffer *buffer_kvs_find(const buffer_kvs *kvs, const char *key, size_t len);
WS_EXTERN const buffer *buffer_kvs_case_find(const buffer_kvs *kvs, const char *key, size_t len);

#ifdef __cplusplus
}
#endif

#endif  /* BUFFER_H_ */
