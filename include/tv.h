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
#ifndef TV_H_
#define TV_H_

#include "uv.h"

#if defined(WITH_SSL)
# include <openssl/bio.h>
# include <openssl/ssl.h>
# include <openssl/x509.h>
#endif

#include "websocket/ws_handshake.h"
#include "websocket/ws_frame.h"

#if defined(_WIN32)
  /* Windows - set up dll import/export decorators. */
# if defined(BUILDING_TV_SHARED)
   /* Building shared library. */
#  define TV_EXTERN __declspec(dllexport)
# elif defined(USING_TV_SHARED)
   /* Using shared library. */
#  define TV_EXTERN __declspec(dllimport)
# else
   /* Building static library. */
#  define TV_EXTERN /* nothing */
# endif
#elif __GNUC__ >= 4
# define TV_EXTERN __attribute__((visibility("default")))
#else
# define TV_EXTERN /* nothing */
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
#define XX(code, _) TV_ ## code = UV__ ## code,
  UV_ERRNO_MAP(XX)
#undef XX
  TV_EX509     = -5000,
  TV_ESSL      = -5001,
  TV_EWS       = -5002,
  TV_ERRNO_MAX = -5003
} tv_errno_t;

/**
 * tv handle type.
 */
typedef enum {
  TV_TCP,   /**< TCP */
  TV_SSL,   /**< SSL */
  TV_WS,    /**< WebSocket */
  /** @cond */
  TV_WSS,   /**< WebSocket over TLS */
  /** @endcond */
  TV_PIPE,  /**< PIPE */
  TV_TIMER  /**< Timer */
} tv_handle_type;

/**
 * @struct tv_buf_t
 * @brief Data structure which libtv handles.
 */
typedef uv_buf_t tv_buf_t;

typedef struct tv_loop_s tv_loop_t;

typedef struct tv_handle_s tv_handle_t;
typedef struct tv_stream_s tv_stream_t;
typedef struct tv_tcp_s tv_tcp_t;
typedef struct tv_ws_s tv_ws_t;
#if defined(WITH_SSL)
typedef struct tv_ssl_s tv_ssl_t;
typedef struct tv_wss_s tv_wss_t;
#endif
typedef struct tv_pipe_s tv_pipe_t;
typedef struct tv_timer_s tv_timer_t;

typedef struct tv_write_s tv_write_t;

/**
 * Callback called when close operation completed.
 *
 * @param handle handle
 */
typedef void (*tv_close_cb)(tv_handle_t* handle);
/**
 * Callback called when connected or failed to connect in TCP, SSL.
 *
 * if 'status' is 0, connect succeeded.
 * if 'status' is others, connect failed.
 * @param stream handle
 * @param status connect result
 */
typedef void (*tv_connect_cb)(tv_stream_t* stream, int status);
/**
 * Callback called when client connected in TCP, SSL.
 *
 * @param server listening handle
 * @param client accepted handle
 * @param status accept result
 */
typedef void (*tv_connection_cb)(tv_stream_t* server, tv_stream_t* client, int status);
/**
 * Callback called when received data from peer in TCP, SSL.
 *
 * @warning MUST free buf.base if (nread > 0).
 *
 * @param stream handle
 * @param nread  data length
 * @param buf    data
 */
typedef void (*tv_read_cb)(tv_stream_t* stream, ssize_t nread, const tv_buf_t* buf);
/**
 * Callback called when write operation completed in TCP, SSL.
 *
 * @param req    write identifier
 * @param status write result
 */
typedef void (*tv_write_cb)(tv_write_t* req, int status);
/**
 * Callback called when timer fired.
 *
 * @param timer timer handle
 */
typedef void (*tv_timer_cb)(tv_timer_t* timer);

#define TV_LOOP_FIELDS \
  void* data;  /**< user data */ \

#define TV_LOOP_PRIVATE_FIELDS \
  uv_loop_t     loop;          /**< @private */ \
  uv_async_t    async;         /**< @private */ \
  uv_mutex_t    mutex;         /**< @private */ \
  void*         req_queue[2];  /**< @private */ \
  uv_thread_t   thread;        /**< @private */ \

/**
 * Event loop.
 */
struct tv_loop_s {
  TV_LOOP_FIELDS
  TV_LOOP_PRIVATE_FIELDS
};

#define TV_HANDLE_FIELDS \
  tv_handle_type type;  /**< handle type */ \
  tv_loop_t*     loop;  /**< event loop */ \
  void*          data;  /**< user data */ \

#define TV_HANDLE_PRIVATE_FIELDS \
  tv_close_cb   close_cb;  /**< @private */ \
  int           last_err;  /**< @private */ \
  unsigned long ssl_err;   /**< @private */ \

/**
 * Handle which all handles are based on.
 */
struct tv_handle_s {
  TV_HANDLE_FIELDS
  TV_HANDLE_PRIVATE_FIELDS
};

#define TV_STREAM_FIELDS \
  int is_connected;  /**< whether handle is connected. this field only used in client mode. */ \
  int is_accepted;   /**< whether handle is accepted. this field only used in server mode. */ \
  int is_listened;   /**< whether handle is listened. this field only used in server mode. */ \

#define TV_STREAM_PRIVATE_FIELDS \
  uv_timer_t       pending_timer;  /**< @private */ \
  uv_mutex_t       sync_mutex;     /**< @private */ \
  uv_cond_t        sync_cond;      /**< @private */ \
  tv_connect_cb    connect_cb;     /**< @private */ \
  tv_connection_cb connection_cb;  /**< @private */ \
  tv_read_cb       read_cb;        /**< @private */ \
  char*            devname;        /**< @private */ \
  size_t           max_sendbuf;    /**< @private */ \
  size_t           cur_sendbuf;    /**< @private */ \

/**
 * Handle which all streams are based on, like TCP, SSL.
 */
struct tv_stream_s {
  TV_HANDLE_FIELDS
  TV_HANDLE_PRIVATE_FIELDS
  TV_STREAM_FIELDS
  TV_STREAM_PRIVATE_FIELDS
};

#define TV_TCP_PRIVATE_FIELDS \
  uv_tcp_t* tcp_handle;    /**< @private */ \
  void*     tcp_queue[2];  /**< @private */ \

/**
 * TCP handle.
 */
struct tv_tcp_s {
  TV_HANDLE_FIELDS
  TV_HANDLE_PRIVATE_FIELDS
  TV_STREAM_FIELDS
  TV_STREAM_PRIVATE_FIELDS
  TV_TCP_PRIVATE_FIELDS
};

#if defined(WITH_SSL)
#define TV_SSL_PRIVATE_FIELDS \
  void*     queue[2];           /**< @private */ \
  tv_ssl_t* listen_handle;      /**< @private */ \
  tv_tcp_t* tv_handle;          /**< @private */ \
  BIO*      bio_int;            /**< @private */ \
  BIO*      bio_net;            /**< @private */ \
  SSL*      ssl;                /**< @private */ \
  SSL_CTX*  ssl_ctx;            /**< @private */ \
  int       is_server;          /**< @private */ \
  int       close_immediately;  /**< @private */ \

/**
 * SSL handle.
 */
struct tv_ssl_s {
  TV_HANDLE_FIELDS
  TV_HANDLE_PRIVATE_FIELDS
  TV_STREAM_FIELDS
  TV_STREAM_PRIVATE_FIELDS
  TV_SSL_PRIVATE_FIELDS
};
#endif

#define TV_WS_FIELDS                               \
  ws_handshake   handshake;                        \
  ws_frame       frame;                            \
  tv_timer_t*    timer;                            \
  unsigned int   retry;                            \
  int            is_timer_started;                 \
  uint64_t       drop_pong;                        \

#define TV_WS_PRIVATE_FIELDS                                 \
  void*         queue[2];              /**< @private */      \
  tv_ws_t*      listen_handle;         /**< @private */      \
  tv_tcp_t*     tv_handle;             /**< @private */      \
  int           is_server;             /**< @private */      \
  tv_connect_cb handshake_complete_cb; /**< @private */      \

/**
 * WS handle
 */
struct tv_ws_s {
  TV_HANDLE_FIELDS
  TV_HANDLE_PRIVATE_FIELDS
  TV_STREAM_FIELDS
  TV_STREAM_PRIVATE_FIELDS
  TV_WS_FIELDS
  TV_WS_PRIVATE_FIELDS
};

#if defined(WITH_SSL)
#define TV_WSS_PRIVATE_FIELDS                                \
  void*         queue[2];              /**< @private */      \
  tv_wss_t*     listen_handle;         /**< @private */      \
  tv_ssl_t*     ssl_handle;            /**< @private */      \
  int           is_server;             /**< @private */      \
  SSL_CTX*      ssl_ctx;               /**< @private */      \
  tv_connect_cb handshake_complete_cb; /**< @private */      \

/**
 * WSS handle
 */
struct tv_wss_s {
  TV_HANDLE_FIELDS
  TV_HANDLE_PRIVATE_FIELDS
  TV_STREAM_FIELDS
  TV_STREAM_PRIVATE_FIELDS
  TV_WS_FIELDS
  TV_WSS_PRIVATE_FIELDS
};
#endif /* defined(WITH_SSL) */

#define TV_PIPE_PRIVATE_FIELDS \
  uv_pipe_t pipe_handle;  /**< @private */ \
  int       ipc;          /**< @private */ \

/**
 * PIPE handle.
 */
struct tv_pipe_s {
  TV_HANDLE_FIELDS
  TV_HANDLE_PRIVATE_FIELDS
  TV_STREAM_FIELDS
  TV_STREAM_PRIVATE_FIELDS
  TV_PIPE_PRIVATE_FIELDS
};

/**
 * Action to multicast group.
 */
typedef enum {
  TV_LEAVE_GROUP = 0,  /**< Leave multicast group */
  TV_JOIN_GROUP        /**< Join multicast group */
} tv_membership;

#define TV_TIMER_PRIVATE_FIELDS \
  uv_timer_t  timer;     /**< @private */ \
  tv_timer_cb timer_cb;  /**< @private */ \

/**
 * Timer handle.
 */
struct tv_timer_s {
  TV_HANDLE_FIELDS
  TV_HANDLE_PRIVATE_FIELDS
  TV_TIMER_PRIVATE_FIELDS
};

#define TV_WRITE_FIELDS \
  void*        data;      /**< user data */ \
  tv_stream_t* handle;    /**< handle associated with this */ \
  tv_buf_t     buf;       /**< write data. free this field when write_cb is called. */ \
  tv_write_cb  write_cb;  /**< callback called when write operation completed */ \

#define TV_WRITE_PRIVATE_FIELDS \
  uv_check_t check_handle;  /**< @private */ \

/**
 * Write identifier handle.
 */
struct tv_write_s {
  TV_WRITE_FIELDS
  TV_WRITE_PRIVATE_FIELDS
};

/**
 * Return string which explain error.
 *
 * @param  handle tv handle
 * @param  err    error
 * @return string which explain error.
 */
TV_EXTERN const char* tv_strerror(tv_handle_t* handle, int err);

/**
 * Initialize event loop handle.
 *
 * @param  loop event loop
 * @return result.
 */
TV_EXTERN int tv_loop_init(tv_loop_t* loop);
/**
 * Close event loop handle.
 *
 * After this function returns the user shall free the memory allocated for the loop.
 *
 * @param  loop event loop
 * @return result.
 */
TV_EXTERN int tv_loop_close(tv_loop_t* loop);
/**
 * Create new event loop.
 *
 * @deprecated this function is DEPRECATED (to be removed next version),
 *             users should allocate the loop manually and use tv_loop_init instread.
 * @return event loop address. if NULL, creation failed.
 */
TV_EXTERN tv_loop_t* tv_loop_new(void);
/**
 * Delete event loop.
 *
 * @deprecated this function is DEPRECATED (to be removed next version),
 *             users should use tv_loop_close and free the memory manually instread.
 * @param loop event loop
 * @return result.
 */
TV_EXTERN int tv_loop_delete(tv_loop_t* loop);

/**
 * Initialize tcp handle.
 *
 * @param  loop   event loop
 * @param  handle tcp handle
 * @return result.
 */
TV_EXTERN int tv_tcp_init(tv_loop_t* loop, tv_tcp_t* handle);

#if defined(WITH_SSL)
/**
 * Initialize ssl library.
 */
TV_EXTERN void tv_ssl_library_init(void);
/**
 * Initialize ssl handle.
 *
 * @param  loop    event loop
 * @param  handle  ssl handle
 * @param  ssl_ctx ssl context
 * @return result.
 */
TV_EXTERN int tv_ssl_init(tv_loop_t* loop, tv_ssl_t* handle, SSL_CTX* ssl_ctx);
/**
 * Get result of peer certificate verification.
 *
 * @param  handle ssl handle
 * @return result. If not zero, verify failed.
 */
TV_EXTERN int tv_ssl_get_verify_result(tv_ssl_t* handle);
/**
 * Get peer certificate.
 *
 * @param  handle ssl handle
 * @return X509 certificate. if NULL, no certificate got.
 */
TV_EXTERN X509* tv_ssl_get_peer_certificate(tv_ssl_t* handle);
/**
 * Get peer certificate chain.
 *
 * @param  handle ssl handle
 * @return STACK_OF(X509) certificates. if NULL, no certificate got.
 */
TV_EXTERN STACK_OF(X509*) tv_ssl_get_peer_certificate_chain(tv_ssl_t* handle);
/**
 * Get ssl cipher of a connection.
 *
 * @param  handle ssl handle
 * @return SSL cipher. if NULL, no session has been established.
 */
TV_EXTERN const SSL_CIPHER* tv_ssl_get_current_cipher(tv_ssl_t* handle);
#endif

TV_EXTERN int tv_ws_init(tv_loop_t* loop, tv_ws_t* handle);

#if defined(WITH_SSL)
TV_EXTERN int tv_wss_init(tv_loop_t* loop, tv_wss_t* handle, SSL_CTX* ssl_ctx);
#endif

/**
 * Close handle.
 *
 * @param  handle   tv handle
 * @param  close_cb callback called when close operation completed.
 * @return result.
 */
TV_EXTERN int tv_close(tv_handle_t* handle, tv_close_cb close_cb);

/**
 * Connect to specific server.
 *
 * @param  handle     tv handle
 * @param  host       destination IP address or FQDN
 * @param  port       destination port number
 * @param  connect_cb callback called when connected.
 * @return result.
 */
TV_EXTERN int tv_connect(tv_stream_t* handle, const char* host, const char* port, tv_connect_cb connect_cb);
/**
 * Listen with specific address.
 *
 * This function is blocked while listen completed.
 *
 * @param  handle        tv handle
 * @param  host          listening IPAddr or FQDN name
 * @param  port          listening port number
 * @param  backlog       listen backlog
 * @param  connection_cb callback called when client connected.
 * @return result.
 */
TV_EXTERN int tv_listen(tv_stream_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb);
/**
 * Start read operation from peer.
 *
 * @param  handle  tv handle
 * @param  read_cb callback called when received data from peer.
 * @return result.
 */
TV_EXTERN int tv_read_start(tv_stream_t* handle, tv_read_cb read_cb);
/**
 * Stop read operation from peer.
 *
 * @param  handle  tv handle
 * @return result.
 */
TV_EXTERN int tv_read_stop(tv_stream_t* handle);

/**
 * Write data to peer.
 *
 * @param  req      write operation identifier
 * @param  handle   tv handle
 * @param  buf      write data
 * @param  write_cb callback called when write operation completed.
 * @return result.
 */
TV_EXTERN int tv_write(tv_write_t* req, tv_stream_t* handle, tv_buf_t buf, tv_write_cb write_cb);
/**
 * Gets the transport dependent file descriptor equivalent.
 *
 * @param handle tv handle
 * @param fd     file descriptor
 * @return result.
 */
TV_EXTERN int tv_fileno(const tv_stream_t* handle, uv_os_fd_t* fd);
/**
 * Sets max send buffer size.
 *
 * @param handle tv handle
 * @param siz    max buffer size
 */
TV_EXTERN void tv_set_max_sendbuf(tv_stream_t* handle, size_t siz);
/**
 * Set an socket option.
 *
 * @param  handle  tv handle
 * @param  level   level
 * @param  optname option name
 * @param  optval  option value
 * @param  optlen  length of option value
 * @return result.
 */
TV_EXTERN int tv_setsockopt(tv_stream_t* handle, int level, int optname, const void* optval, size_t optlen);
/**
 * Bind to a particular device.
 *
 * @attention
 * This function is enabled Linux only.
 *
 * @param  handle   tv handle
 * @param  devname  device name to bind.
 * @return result.
 */
TV_EXTERN int tv_bindtodevice(tv_stream_t* handle, const char* devname);
/**
 * Enable/disable TCP keep-alive.
 *
 * @attention
 * Windows Vista and later, 'retry' is set to 10 and cannot be changed.<br />
 * Mac OS X Lion and before, 'interval' and 'retry' cannot be changed from this API.<br />
 * See http://msdn.microsoft.com/en-us/library/windows/desktop/dd877220(v=vs.85).aspx
 *
 * @param  handle   tv handle
 * @param  enable   0: disable, 1: enable
 * @param  idle     keep-alive idle time(sec), ignored when 'enable' is 0
 * @param  interval keep-alive interval time(sec), ignored when 'enable' is 0
 * @param  retry    keep-alive retry count, ignored when 'enable' is 0
 * @return result.
 */
TV_EXTERN int tv_keepalive(tv_stream_t* handle, int enable, unsigned int idle, unsigned int interval, unsigned int retry);
/**
 * Enable/disable WebSocket keep-alive.
 *
 * @param  handle   tv_ws handle or tv_wss handle
 * @param  enable   0: disable, 1: enable
 * @param  interval keep-alive interval time(sec), ignored when 'enable' is 0
 * @param  retry    keep-alive retry count, ignored when 'enable' is 0
 * @return result.
 */
TV_EXTERN int tv_ws_keepalive(tv_stream_t* handle, int enable, unsigned int interval, unsigned int retry);
/**
 * Set address information corresponded to tv handle to sockaddr.
 *
 * @param  handle  tv handle
 * @param  name    sockaddr's address
 * @param  namelen sockaddr's size
 * @return result.
 */
TV_EXTERN int tv_getsockname(const tv_stream_t* handle, struct sockaddr* name, int* namelen);
/**
 * Set peer address information corresponded to tv handle connected to sockaddr.
 *
 * @param  handle  tv handle
 * @param  name    sockaddr's address
 * @param  namelen sockaddr's size
 * @return result.
 */
TV_EXTERN int tv_getpeername(const tv_stream_t* handle, struct sockaddr* name, int* namelen);

/**
 * Initialize pipe handle.
 *
 * On Windows this is a Named Pipe.
 * On Unix this is a UNIX domain socket.
 *
 * @param  loop   event loop
 * @param  handle pipe handle
 * @param  ipc    ipc
 * @return result.
 */
TV_EXTERN int tv_pipe_init(tv_loop_t* loop, tv_pipe_t* handle, int ipc);

/**
 * Connect to specific server.
 *
 * @param  handle     tv handle
 * @param  name       UNIX domain socket name or pipe name
 * @param  connect_cb callback called when connected.
 * @return result.
 */
TV_EXTERN int tv_pipe_connect(tv_pipe_t* handle, const char* name, tv_connect_cb connect_cb);
/**
 * Listen with specific address.
 *
 * This function is blocked while listen completed.
 *
 * @param  handle        tv handle
 * @param  name          listening UNIX domain socket name or pipe name
 * @param  backlog       listen backlog
 * @param  connection_cb callback called when client connected.
 * @return result.
 */
TV_EXTERN int tv_pipe_listen(tv_pipe_t* handle, const char* name, int backlog, tv_connection_cb connection_cb);

/**
 * Initialize timer handle.
 *
 * @param  loop  event loop
 * @param  timer timer handle
 * @return result.
 */
TV_EXTERN int tv_timer_init(tv_loop_t* loop, tv_timer_t* timer);
/**
 * Start timer.
 *
 * @param  timer    timer handle
 * @param  timer_cb callback called when timer fired.
 * @param  timeout  time which timer fires first.
 *                  If timeout is zero, the callback fires on the next tick of the event loop.
 *                  The unit is milliseconds.
 * @param  repeat   repeat interval. The unit is milliseconds.
 * @return result.
 */
TV_EXTERN int tv_timer_start(tv_timer_t* timer, tv_timer_cb timer_cb, uint64_t timeout, uint64_t repeat);
/**
 * Stop timer.
 *
 * @param  timer timer handle
 * @return result.
 */
TV_EXTERN int tv_timer_stop(tv_timer_t* timer);

#ifdef __cplusplus
}
#endif

#endif  /* TV_H_ */
