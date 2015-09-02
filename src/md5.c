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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "md5.h"

typedef struct{
  uint32_t word[4];
  uint8_t data[64];
  char pad_start;
} md5_t;

#define DIGEST_SIZE (32)

#define Func_F( x, y, z ) ( ( (x) & (y) ) | ( (~x) & (z) ) ) 
#define Func_G( x, y, z ) ( ( (x) & (z) ) | ( (y) & (~z) ) )
#define Func_H( x, y, z ) ( (x) ^ (y) ^ (z) )
#define Func_I( x, y, z ) ( (y) ^ ( (x) | (~z) ) )
#define RotateLeftShift( x , s ) ( ((x) << (s)) | ((x) >> (32-(s))) )

#define Calc_ROUND1( a,b,c,d,k,s,i ) ( (a) = (b) + RotateLeftShift( ( (a) + Func_F( (b),(c),(d) ) + __getblock(md5,(k)) + Table[(i)] ) , (s) ) )
#define Calc_ROUND2( a,b,c,d,k,s,i ) ( (a) = (b) + RotateLeftShift( ( (a) + Func_G( (b),(c),(d) ) + __getblock(md5,(k)) + Table[(i)] ) , (s) ) )
#define Calc_ROUND3( a,b,c,d,k,s,i ) ( (a) = (b) + RotateLeftShift( ( (a) + Func_H( (b),(c),(d) ) + __getblock(md5,(k)) + Table[(i)] ) , (s) ) )
#define Calc_ROUND4( a,b,c,d,k,s,i ) ( (a) = (b) + RotateLeftShift( ( (a) + Func_I( (b),(c),(d) ) + __getblock(md5,(k)) + Table[(i)] ) , (s) ) )


static uint32_t Table[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static void md5_init(md5_t *md5) {
  md5->word[0] = 0x67452301;
  md5->word[1] = 0xefcdab89;
  md5->word[2] = 0x98badcfe;
  md5->word[3] = 0x10325476;
  *(md5->data) = '\0';
  md5->pad_start = 0;
}

static uint32_t __getblock(md5_t *md5, int bn) {
    int i;
    uint32_t tmp;

    tmp = 0x00000000;
    for (i = bn * 4; i < (bn + 1) * 4; i++) {
      tmp = tmp | ((uint32_t)md5->data[i] << ((i % 4) * 8));
    }
    return tmp;
}

static size_t md5_get_next64byte(md5_t *md5, const char *ptr, size_t left, uint64_t total) {
  size_t i, pad;
  size_t parsed;
  uint32_t siz;

  if (left >= 64) { 
    memcpy(md5->data, ptr, 64);
    parsed = 64;
  } else {
    if (left != 0) {
      memcpy(md5->data, ptr, left);
    }
    pad = left;
    if (md5->pad_start == 0) {
      *(md5->data + left) = 0x80;
      md5->pad_start = 1;
      pad++;
    }
    if (left >= 56) {
      for (i = pad; i < 64; i++){
        *(md5->data + i) = 0x00;
      }
    } else {
      for (i = pad; i < 56; i++) {
        *(md5->data + i) = 0x00;
      }
      siz = (uint32_t) (total & 0xffffffff);
      for (i = 56; i < 60; i++) {
        *(md5->data + i) = ((siz >> ((i - 56) * 8)) & 0xff);
      }
      siz = (uint32_t)((total >> 32) & 0xffffffff);
      for (i = 60; i < 64; i++) {
        *(md5->data + i) = ((siz >> ((i - 60) * 8)) & 0xff);
      }
    }
    parsed = left;
  }
  return parsed;
}

static void md5_compute(md5_t *md5) {
  int i;
  uint32_t A, B, C, D;

  A = md5->word[0];
  B = md5->word[1];
  C = md5->word[2];
  D = md5->word[3];
  for (i = 0; i < 4; i++) {
    Calc_ROUND1(A, B, C, D, ((i * 4)     % 16),  7, (i * 4));
    Calc_ROUND1(D, A, B, C, ((i * 4 + 1) % 16), 12, (i * 4 + 1));
    Calc_ROUND1(C, D, A, B, ((i * 4 + 2) % 16), 17, (i * 4 + 2));
    Calc_ROUND1(B, C, D, A, ((i * 4 + 3) % 16), 22, (i * 4 + 3));
  }
  for (i = 0; i < 4; i++) {
    Calc_ROUND2(A, B, C, D, ((i * 4 +  1) % 16),  5, (i * 4 + 16));
    Calc_ROUND2(D, A, B, C, ((i * 4 +  6) % 16),  9, (i * 4 + 17));
    Calc_ROUND2(C, D, A, B, ((i * 4 + 11) % 16), 14, (i * 4 + 18));
    Calc_ROUND2(B, C, D, A, ((i * 4)      % 16), 20, (i * 4 + 19));
  }
  for (i = 0; i < 4; i++) {
    Calc_ROUND3(A, B, C, D, ((21 - i * 4) % 16),  4, (i * 4 + 32));
    Calc_ROUND3(D, A, B, C, ((24 - i * 4) % 16), 11, (i * 4 + 33));
    Calc_ROUND3(C, D, A, B, ((27 - i * 4) % 16), 16, (i * 4 + 34));
    Calc_ROUND3(B, C, D, A, ((30 - i * 4) % 16), 23, (i * 4 + 35));
  }
  for (i = 0; i < 4; i++) {
    Calc_ROUND4(A, B, C, D, ((32 - i * 4) % 16),  6, (i * 4 + 48));
    Calc_ROUND4(D, A, B, C, ((23 - i * 4) % 16), 10, (i * 4 + 49));
    Calc_ROUND4(C, D, A, B, ((30 - i * 4) % 16), 15, (i * 4 + 50));
    Calc_ROUND4(B, C, D, A, ((21 - i * 4) % 16), 21, (i * 4 + 51));
  }
  md5->word[0] += A;
  md5->word[1] += B;
  md5->word[2] += C;
  md5->word[3] += D;
}

static void md5_update(md5_t *md5, const char *src, size_t siz) {
  int do_loop = 1;
  size_t left = siz;
  size_t total = siz * 8;
  const char *ptr = src;
  size_t parsed = 0;

  while (do_loop) {
    if (left < 56) {
      do_loop = 0;
    }
    parsed = md5_get_next64byte(md5, ptr, left, total);
    md5_compute(md5);
    ptr += parsed;
    left -= parsed;
  }
}

static char __bin2hexchar(uint32_t data) {
  return (char)((data < 10) ? '0' + data : 'a' + data - 10);
}

static char *md5_final(md5_t *md5) {
  int i, j;
  uint32_t tmp;
  char *digest = (char*)malloc(DIGEST_SIZE + 1);
  char *ptr = digest;

  if (ptr == NULL) {
    return ptr;
  }
  for (i = 0; i < 4; i++) {
    for(j = 0; j < 4; j++) {
      tmp = (md5->word[i] >> (j * 8));
      *ptr = __bin2hexchar((tmp >> 4) & 0x0f);
      *(ptr + 1) = __bin2hexchar(tmp & 0x0f);
      ptr += 2;
    }
  }
  *ptr = '\0';
  return digest;
}

char *md5_sum(const char *src, size_t siz) {
  md5_t md5;
  md5_init(&md5);
  md5_update(&md5, src, siz);
  return md5_final(&md5);
}
