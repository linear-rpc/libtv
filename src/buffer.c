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

#define _DOTEST 0
#if _DOTEST
#include <assert.h>
#include <stdio.h>
#endif

#if defined(_WIN32)
# include <stdint.h>
# include <winsock2.h>
#else
# include <sys/time.h>
#endif

#include <string.h>

#include "websocket/buffer.h"
#include "md5.h"

#if defined(_WIN32)
int gettimeofday(struct timeval *tp, struct timezone *tzp) {
  static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);
  SYSTEMTIME  system_time;
  FILETIME    file_time;
  uint64_t    time;

  GetSystemTime( &system_time );
  SystemTimeToFileTime( &system_time, &file_time );
  time =  ((uint64_t)file_time.dwLowDateTime )      ;
  time += ((uint64_t)file_time.dwHighDateTime) << 32;

  tp->tv_sec  = (long) ((time - EPOCH) / 10000000L);
  tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
  return 0;
}
#endif

int buffer_append(buffer *b, const char *ptr, size_t len) {
  char *tmp = NULL;
  if (!ptr || len == 0) {
    return 0;
  }
  if (b->siz < b->len + len + 1) {
    tmp = (char *)realloc(b->ptr, b->len + len + 1);
    if (!tmp) {
      return -1;
    }
    b->siz = b->len + len + 1;
    b->ptr = tmp;
  }
  memcpy(&b->ptr[b->len], ptr, len);
  b->ptr[b->len + len] = '\0';
  b->len += len;
  return 0;
}

void buffer_to_lower(buffer *b) {
  char *p;
  if (b->len == 0) {
    return;
  }
  for (p = b->ptr; *p; p++) {
    if (*p >= 'A' && *p <= 'Z') {
      *p |= 32;
    }
  }
}

int buffer_from_base64(buffer *b) {
  const signed char base64_decode_chars[] = {
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1,  62, - 1, - 1, - 1,  63,
     52,  53,  54,  55,  56,  57,  58,  59,
     60,  61, - 1, - 1, - 1,   0, - 1, - 1,
    - 1,   0,   1,   2,   3,   4,   5,   6,
      7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,
     23,  24,  25, - 1, - 1, - 1, - 1, - 1,
    - 1,  26,  27,  28,  29,  30,  31,  32,
     33,  34,  35,  36,  37,  38,  39,  40,
     41,  42,  43,  44,  45,  46,  47,  48,
     49,  50,  51, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1,
    - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1};
  union {
    unsigned long x;
    char c[4];
  } base64;
  unsigned char *src_ptr = (unsigned char *)b->ptr;
  size_t src_siz = b->len;
  unsigned char *base64_decoded;
  unsigned char *dst_ptr;
  int i, j = 0, ret = -1;

  if ((b->len % 4) != 0) {
    return -1;
  }
  base64.x = 0UL;
  base64_decoded = (unsigned char *)malloc(b->len);
  if (!base64_decoded) {
    return -1;
  }
  dst_ptr = base64_decoded;
  for (; src_siz > 0; src_ptr+=4, src_siz-=4) {
    for (i = 0; i < 4; i++) {
      if (base64_decode_chars[src_ptr[i]] == -1) {
        free(base64_decoded);
        return -1;
      }
      base64.x = base64.x << 6 | base64_decode_chars[src_ptr[i]];
      j += (src_ptr[i] == '=');
    }
    for (i = 3; i > j; i--) {
      *dst_ptr++ = base64.c[i - 1];
    }
  }
  *dst_ptr = '\0';
  buffer_reset(b);
  ret = buffer_append(b, (char *)base64_decoded, strlen((char *)base64_decoded));
  free(base64_decoded);
  return ret;
}

int buffer_to_base64(buffer *b) {
  const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "abcdefghijklmnopqrstuvwxyz"
                              "0123456789+/";
  unsigned long x = 0UL;
  int i = 0, l = 0, ret = -1;
  unsigned char *src_ptr = (unsigned char *)b->ptr;
  size_t src_len = b->len;
  unsigned char *base64_encoded;
  unsigned char *base64_ptr;

  base64_encoded = (unsigned char *)malloc(src_len * 2);
  if (!base64_encoded) {
    return -1;
  }
  base64_ptr = base64_encoded;
  for (; src_len > 0; src_ptr++, src_len--) {
    x = x << 8 | *src_ptr;
    for (l += 8; l >= 6; l -= 6) {
      base64_ptr[i++] = base64_chars[(x >> (l - 6)) & 0x3f];
    }
  }
  if (l > 0) {
    x <<= 6 - l;
    base64_ptr[i++] = base64_chars[x & 0x3f];
  }
  for (; i % 4;) {
    base64_ptr[i++] = '=';
  }
  buffer_reset(b);
  ret = buffer_append(b, (char *)base64_encoded, i);
  free(base64_encoded);
  return ret;
}

int buffer_fill_random(buffer *b, size_t len) {
#define BYTES (4)
  size_t copy_len;
  struct timeval tv;
  char c[BYTES]; /* 32bit */
  long l;
  buffer_reset(b);
  gettimeofday(&tv, NULL);
  srand(tv.tv_sec * 1000 + tv.tv_usec);
  do {
    l = rand();
    copy_len = (BYTES < len) ? BYTES : len;
    memcpy(c, &l, copy_len);
    if (buffer_append(b, c, copy_len)) {
      return -1;
    }
    len -= copy_len;
  } while (len > 0);
  return 0;
#undef BYTES
}

int buffer_to_md5sum(buffer *b) {
  int ret;
  char *digest = md5_sum(b->ptr, b->len);
  if (digest == NULL) {
    return -1;
  }
  buffer_reset(b);
  ret = buffer_append(b, digest, strlen(digest));
  free(digest);
  return ret;
}

void buffer_kvs_fin(buffer_kvs *kvs) {
  buffer_kv *kv;
  while ((kv = SLIST_GET_FIRST(kvs, slist))) {
    SLIST_REMOVE_FIRST(kvs, slist, entry);
    buffer_kv_fin(kv);
    free(kv);
  }
}

int buffer_kvs_insert(buffer_kvs *kvs, const buffer_kv *kv) {
  int ret;
  buffer_kv *new_kv = (buffer_kv *)malloc(sizeof(buffer_kv));
  if (!new_kv) {
    return -1;
  }
  buffer_kv_init(new_kv);
  ret = buffer_append(&new_kv->key, kv->key.ptr, kv->key.len);
  if (ret) {
    free(new_kv);
    return ret;
  }
  ret = buffer_append(&new_kv->val, kv->val.ptr, kv->val.len);
  if (ret) {
    free(new_kv);
    return ret;
  }
  SLIST_INSERT_FIRST(kvs, slist, new_kv, entry);
  return 0;
}

const buffer *buffer_kvs_find(const buffer_kvs *kvs, const char *key, size_t len) {
  buffer_kv *kv;
  for (kv = SLIST_GET_FIRST(kvs, slist);
       kv;
       kv = SLIST_GET_NEXT(kv, entry)) {
    if (kv->key.len == len && memcmp(kv->key.ptr, key, len) == 0) {
      return &kv->val;
    }
  }
  return NULL;
}

const buffer *buffer_kvs_case_find(const buffer_kvs *kvs, const char *key, size_t len) {
  buffer s1;
  buffer s2;
  buffer_kv *kv;
  buffer_init(&s1);
  buffer_init(&s2);
  if (buffer_append(&s1, key, len)) {
    buffer_fin(&s1);
    buffer_fin(&s2);
    return NULL;
  }
  buffer_to_lower(&s1);
  for (kv = SLIST_GET_FIRST(kvs, slist);
       kv;
       kv = SLIST_GET_NEXT(kv, entry)) {
    if (kv->key.len == len) {
      if (buffer_append(&s2, kv->key.ptr, kv->key.len)) {
        break;
      }
      buffer_to_lower(&s2);
      if (memcmp(s1.ptr, s2.ptr, s1.len) == 0) {
        buffer_fin(&s1);
        buffer_fin(&s2);
        return &kv->val;
      }
      buffer_reset(&s2);
    }
  }
  buffer_fin(&s1);
  buffer_fin(&s2);
  return NULL;
}

#if _DOTEST
void buffer_test() {
  const char bin_1 = 0;
  const char bin_2[] = {0, 1};
  const char bin_3[] = {0, 1, 2};
  char bin_4[256];
  const char b64_1[] = "AA==";
  const char b64_2[] = "AAE=";
  const char b64_3[] = "AAEC";
  const char b64_4[] =
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v"
    "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f"
    "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P"
    "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/"
    "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v"
    "8PHy8/T19vf4+fr7/P3+/w==";
  int r, i;
  buffer s;

  buffer_init(&s);
  /* string */
  r = buffer_append(&s, CONST_STRING("Foo"));
  assert(0 == r);
  assert(3 == s.len);
  assert(4 == s.siz);
  assert(memcmp(s.ptr, "Foo", sizeof("Foo") - 1) == 0);
  /* binary */
  r = buffer_append(&s, "\0\r\n", 3);
  assert(0 == r);
  assert(6 == s.len);
  assert(7 == s.siz);
  assert(memcmp(s.ptr, "Foo\0\r\n", sizeof("Foo\0\r\n") - 1) == 0);
  /* lower */
  buffer_to_lower(&s);
  assert(6 == s.len);
  assert(memcmp(s.ptr, "foo\0\r\n", sizeof("foo\0\r\n") - 1) == 0);
  /* reset */
  buffer_reset(&s);
  assert(0 == s.len);
  /* base64 */
  buffer_reset(&s);
  r = buffer_append(&s, &bin_1, 1);
  r = buffer_to_base64(&s);
  assert(0 == r);
  assert(4 == s.len);
  assert(memcmp(s.ptr, b64_1, 4) == 0);
  buffer_reset(&s);
  r = buffer_append(&s, bin_2, 2);
  r = buffer_to_base64(&s);
  assert(0 == r);
  assert(4 == s.len);
  assert(memcmp(s.ptr, b64_2, 4) == 0);
  buffer_reset(&s);
  r = buffer_append(&s, bin_3, 3);
  r = buffer_to_base64(&s);
  assert(0 == r);
  assert(4 == s.len);
  assert(memcmp(s.ptr, b64_3, 4) == 0);
  buffer_reset(&s);
  for (i = 0; i < 256; i++) {
    bin_4[i] = (char)i;
  }
  r = buffer_append(&s, bin_4, 256);
  r = buffer_to_base64(&s);
  assert(0 == r);
  assert((sizeof(b64_4) - 1) == s.len);
  assert(memcmp(s.ptr, b64_4, sizeof(b64_4) - 1) == 0);
  buffer_fin(&s);
}

void buffer_kv_test() {
  int r;
  buffer key, val;
  buffer_kv kv;

  buffer_init(&key);
  buffer_init(&val);
  buffer_append(&key, "Key", 3);
  buffer_append(&val, "Val", 3);

  /* set key */
  buffer_kv_init(&kv);
  r = buffer_kv_set_key(&kv, &key);
  assert(0 == r);
  assert(strcmp(kv.key.ptr, "Key") == 0);
  assert(0 == kv.val.len);
  /* set val */
  buffer_kv_reset(&kv);
  r = buffer_kv_set_value(&kv, &val);
  assert(0 == r);
  assert(strcmp(kv.val.ptr, "Val") == 0);
  assert(0 == kv.key.len);
  /* set */
  buffer_kv_reset(&kv);
  r = buffer_kv_set(&kv, &val, &key);
  assert(0 == r);
  assert(strcmp(kv.key.ptr, "Val") == 0);
  assert(3 == kv.key.len);
  assert(strcmp(kv.val.ptr, "Key") == 0);
  assert(3 == kv.val.len);

  buffer_kv_fin(&kv);
  buffer_fin(&key);
  buffer_fin(&val);
}

void buffer_kvs_test() {
  int r;
  buffer key, val;
  const buffer *ref;
  buffer_kv kv1, kv2, *tmp;
  buffer_kvs kvs;

  /* append string key */
  buffer_init(&key);
  buffer_append(&key, "Key", 3);
  buffer_init(&val);
  buffer_append(&val, "Val", 3);
  buffer_kv_init(&kv1);
  buffer_kv_set(&kv1, &key, &val);
  buffer_kvs_init(&kvs);
  assert(SLIST_IS_EMPTY(&kvs, slist));
  r = buffer_kvs_insert(&kvs, &kv1);
  assert(0 == r);
  assert(!SLIST_IS_EMPTY(&kvs, slist));
  tmp = (buffer_kv *)buffer_kvs_get_first(&kvs);
  assert(kv1.key.len == tmp->key.len);
  assert(strcmp(kv1.key.ptr, tmp->key.ptr) == 0);
  assert(kv1.val.len == tmp->val.len);
  assert(strcmp(kv1.val.ptr, tmp->val.ptr) == 0);
  tmp = (buffer_kv *)buffer_kvs_get_next(tmp);
  assert(tmp == NULL);
  /* append binary key */
  buffer_reset(&key);
  buffer_append(&key, "Key\0\r\n", 6);
  buffer_reset(&val);
  buffer_append(&val, "Val\0\r\n", 6);
  buffer_kv_init(&kv2);
  buffer_kv_set(&kv2, &key, &val);
  r = buffer_kvs_insert(&kvs, &kv2);
  assert(0 == r);
  tmp = (buffer_kv *)buffer_kvs_get_first(&kvs);
  assert(kv2.key.len == tmp->key.len);
  assert(strcmp(kv2.key.ptr, tmp->key.ptr) == 0);
  assert(kv2.val.len == tmp->val.len);
  assert(strcmp(kv2.val.ptr, tmp->val.ptr) == 0);
  tmp = (buffer_kv *)buffer_kvs_get_next(tmp);
  assert(kv1.key.len == tmp->key.len);
  assert(strcmp(kv1.key.ptr, tmp->key.ptr) == 0);
  assert(kv1.val.len == tmp->val.len);
  assert(strcmp(kv1.val.ptr, tmp->val.ptr) == 0);
  tmp = (buffer_kv *)buffer_kvs_get_next(tmp);
  assert(tmp == NULL);
  /* not found : case sensitive */
  ref = buffer_kvs_find(&kvs, CONST_STRING("key"));
  assert(NULL == ref);
  /* found string key */
  ref = buffer_kvs_find(&kvs, CONST_STRING("Key"));
  assert(3 == ref->len);
  assert(memcmp(ref->ptr, "Val", 3) == 0);
  /* found binary key */
  ref = buffer_kvs_find(&kvs, "Key\0\r\n", 6);
  assert(6 == ref->len);
  assert(memcmp(ref->ptr, "Val\0\r\n", 6) == 0);
  buffer_kvs_fin(&kvs);
  buffer_fin(&key);
  buffer_fin(&val);
  buffer_kv_fin(&kv1);
  buffer_kv_fin(&kv2);
}

int main() {
  buffer_test();
  buffer_kv_test();
  buffer_kvs_test();
}
#endif
