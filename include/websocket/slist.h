/* based on sys/queue.h */

/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)queue.h	8.5 (Berkeley) 8/20/94
 */

/** @file */
#ifndef SLIST_H_
#define SLIST_H_

#ifdef __cplusplus
extern "C" {
#endif

#define SLIST(type, listname)    \
  struct {                       \
    struct type *sl_first;       \
  } listname

#define SLIST_ENTRY(type, entryname)    \
  struct {                              \
    struct type *sle_next;              \
  } entryname

#define SLIST_INIT(slist, listname)		((slist)->listname.sl_first = NULL)

#define SLIST_ENTRY_INIT(sle, entryname)	((sle)->entryname.sle_next = NULL)

#define SLIST_GET_FIRST(slist, listname)	((slist)->listname.sl_first)

#define SLIST_GET_NEXT(sle, entryname)		((sle)->entryname.sle_next)

#define SLIST_IS_FIRST(slist, listname, sle)	((sle) == (slist)->listname.sl_first)

#define SLIST_IS_LAST(sle, entryname)		((sle)->entryname.sle_next == NULL)

#define SLIST_IS_EMPTY(slist, listname)		((slist)->listname.sl_first == NULL)

#define SLIST_REMOVE_FIRST(slist, listname, entryname)                  \
  (slist)->listname.sl_first = SLIST_GET_NEXT((slist)->listname.sl_first, entryname)

#define SLIST_REMOVE_AFTER(sle, entryname)                              \
  ((sle)->entryname.sle_next = SLIST_GET_NEXT(SLIST_GET_NEXT(sle, entryname),entryname))

#define SLIST_REMOVE(slist, listname, entrytype, sle, entryname)        \
  do {                                                                  \
    if (SLIST_IS_FIRST(slist, listname, sle)) {                         \
      SLIST_REMOVE_FIRST(slist, listname, entryname);                   \
    } else {                                                            \
      entrytype *sle_pre = (slist)->listname.sl_first;                  \
      while (!(SLIST_GET_NEXT(sle_pre, entryname) == sle)) {            \
        sle_pre=SLIST_GET_NEXT(sle_pre, entryname);                     \
      }                                                                 \
      SLIST_REMOVE_AFTER(sle_pre, entryname);                           \
    }                                                                   \
  } while(0)

#define SLIST_INSERT_FIRST(slist, listname, sle, entryname)          \
  do {                                                               \
    (sle)->entryname.sle_next = SLIST_GET_FIRST(slist, listname);    \
    (slist)->listname.sl_first = sle;                                \
  } while(0)

#define SLIST_INSERT_AFTER(sle_pos, sle_new, entryname)                 \
  do {                                                                  \
    (sle_new)->entryname.sle_next = (sle_pos)->entryname.sle_next;      \
    (sle_pos)->entryname.sle_next = sle_new;                            \
  } while(0)

#ifdef __cplusplus
}
#endif

#endif  /* SLIST_H_ */
