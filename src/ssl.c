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

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define TV_SSL_MAX_RECORD_SIZE (16384)
#define TV_BIO_DEFAULT_BUFFER_SIZE (17408)
#define TV_SSL_DEFAULT_BUFFER_SIZE (4096)

static void tv_ssl_library_destroy(void);
static void tv_ssl_library_init_once(void);

static int tv__ssl_init_bio(tv_ssl_t* handle, int is_server);
static void tv__ssl_close_bio(tv_ssl_t* handle);

static void tv__ssl_handle_error(tv_ssl_t* handle, int err);
static void tv__ssl_handshake_complete(tv_ssl_t* handle);
static void tv__ssl_handshake(tv_ssl_t* handle);

static int tv__ssl_read(tv_ssl_t* handle);

static void tv__ssl_start_client_handshake(tv_stream_t* tcp_handle, int status);
static void tv__ssl_start_server_handshake(tv_stream_t* server, tv_stream_t* client, int status);
static void tv__ssl_read_cb(tv_stream_t* tcp_handle, ssize_t nread, const tv_buf_t* buf);
static void tv__ssl_handshake_write_cb(tv_write_t* tcp_req, int status);
static void tv__ssl_call_write_cb(tv_write_t* tcp_req, int status);
static void tv__ssl_close_write_cb(tv_write_t* tcp_req, int status);
static void tv__ssl_close_handle(tv_handle_t* handle);
static void tv__ssl_close_handle2(uv_handle_t* handle);


static void tv_ssl_library_destroy(void) {
  /* Thread-local cleanup functions */
  ERR_remove_thread_state(NULL);
  /* Application-global cleanup functions that are aware of usage (and therefore thread-safe) */
  ENGINE_cleanup();
  CONF_modules_unload(0);
  /* "Brutal" (thread-unsafe) Application-global cleanup functions */
  ERR_free_strings();
  EVP_cleanup();
#if 0 // TODO: cause SEGV when calling atexit(front thread) and close_cb(child thread) same time.
  CRYPTO_cleanup_all_ex_data();
#endif
  /* NEW! */
  sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
}
static void tv_ssl_library_init_once(void) {
  SSL_load_error_strings();
  SSL_library_init();
  atexit(tv_ssl_library_destroy);
}
void tv_ssl_library_init(void) {
  static uv_once_t init_once = UV_ONCE_INIT;
  uv_once(&init_once, tv_ssl_library_init_once);
}

static int tv__ssl_init_bio(tv_ssl_t* handle, int is_server) {
  int ret = 0;

  handle->ssl = SSL_new(handle->ssl_ctx);
  if (handle->ssl == NULL) {
    handle->ssl_err = ERR_get_error();
    return TV_ESSL;
  }
  if (is_server) {
    SSL_set_accept_state(handle->ssl);
  } else {
    SSL_set_connect_state(handle->ssl);
  }
  ret = BIO_new_bio_pair(&handle->bio_int, 0, &handle->bio_net, 0);  /* BIO default buffer size(17408) is set */
  if (ret != 1) {
    SSL_free(handle->ssl);
    handle->ssl = NULL;
    handle->ssl_err = ERR_get_error();
    return TV_ESSL;
  }
  SSL_set_bio(handle->ssl, handle->bio_int, handle->bio_int);
  handle->is_server = is_server;

  return 0;
}
static void tv__ssl_close_bio(tv_ssl_t* handle) {
  /*
   * No NULL check because SSL_free and BIO_free checks NULL internally.
   */
  SSL_free(handle->ssl);  /* implicitly frees handle->bio_int */
  BIO_free(handle->bio_net);
  handle->ssl = NULL;
}
int tv_ssl_init(tv_loop_t* loop, tv_ssl_t* handle, SSL_CTX* ssl_ctx) {
  int ret = 0;

  if ((loop == NULL) || (handle == NULL) || (ssl_ctx == NULL)) {
    return TV_EINVAL;
  }

  ret = tv_stream_init(TV_SSL, loop, (tv_stream_t*) handle);
  if (ret) {
    return ret;
  }

  handle->listen_handle = NULL;
  handle->ssl_ctx = ssl_ctx;
  handle->tv_handle = NULL;
  handle->bio_int = NULL;
  handle->bio_net = NULL;
  handle->ssl = NULL;
  handle->is_server = 0;
  handle->close_immediately = 0;

  return 0;
}

int tv_ssl_get_verify_result(tv_ssl_t* handle) {
  X509* peer_cert = NULL;
  long result = 0;

  if (!(handle->is_connected || handle->is_accepted)) {
    return TV_ENOTCONN;
  }

  peer_cert = SSL_get_peer_certificate(handle->ssl);
  if (peer_cert == NULL) {
    handle->ssl_err = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
    return TV_EX509;
  }
  X509_free(peer_cert);

  result = SSL_get_verify_result(handle->ssl);
  if (result != X509_V_OK) {
    handle->ssl_err = result;
    return TV_EX509;
  }

  return 0;
}
X509* tv_ssl_get_peer_certificate(tv_ssl_t* handle) {
  if (!(handle->is_connected || handle->is_accepted)) {
    return NULL;
  }

  return SSL_get_peer_certificate(handle->ssl);
}
STACK_OF(X509*) tv_ssl_get_peer_certificate_chain(tv_ssl_t* handle) {
  if (!(handle->is_connected || handle->is_accepted)) {
    return NULL;
  }

  return SSL_get_peer_cert_chain(handle->ssl);
}
const SSL_CIPHER* tv_ssl_get_current_cipher(tv_ssl_t* handle) {
  if (!(handle->is_connected || handle->is_accepted)) {
    return NULL;
  }

  return SSL_get_current_cipher(handle->ssl);
}

static void tv__ssl_handle_error(tv_ssl_t* handle, int err) {
  if (handle->is_accepted || handle->is_connected) {
    /* handshake complete */
    if (handle->read_cb != NULL) {
      tv_buf_t buf;
      handle->read_cb((tv_stream_t*) handle, err, &buf);
    }
  } else {
    /* handshake incomplete => accepted handle is not ready */
    if (handle->is_server) {
      tv_stream_t* listen_handle = (tv_stream_t*) handle->listen_handle;
      tv__ssl_close(handle, tv__handle_free_handle);
      if (listen_handle->connection_cb != NULL) {
        listen_handle->connection_cb(listen_handle, NULL, err);
      }
    } else {
      if (handle->connect_cb != NULL) {
        handle->connect_cb((tv_stream_t*) handle, err);
      }
    }
  }
}
static void tv__ssl_handshake_complete(tv_ssl_t* handle) {
  if (handle->is_server) {
    /* handshake complete in accept */
    handle->is_accepted = 1;
    if (handle->connection_cb != NULL) {
      handle->connection_cb((tv_stream_t*) handle->listen_handle, (tv_stream_t*) handle, 0);
    }
  } else {
    /* handshake complete in connect */
    int ret = 0;

    handle->is_connected = 1;
    if (handle->connect_cb != NULL) {
      handle->connect_cb((tv_stream_t*) handle, 0);
    }

    /* ClearOut */
    ret = tv__ssl_read(handle);
    if (ret) {
      tv__ssl_handle_error(handle, ret);
    }
  }
}
static void tv__ssl_handshake(tv_ssl_t* handle) {
  int ret = SSL_do_handshake(handle->ssl);
  if (ret <= 0) {
    int err = SSL_get_error(handle->ssl, ret);
    if ((err != SSL_ERROR_WANT_READ) && (err != SSL_ERROR_WANT_WRITE)) {
      /* fatal error */
      if (handle->is_server) {
        /* handshake not completed, so available handle is listen handle only. */
        handle->listen_handle->ssl_err = ERR_get_error();
        tv__ssl_handle_error(handle, TV_ESSL);
      } else {
        handle->ssl_err = ERR_get_error();
        tv__ssl_handle_error(handle, TV_ESSL);
      }
      return;
    }
  }

  ret = BIO_pending(handle->bio_net);
  assert(ret >= 0);
  if (ret == 0) {
    if (SSL_is_init_finished(handle->ssl)) {
      tv__ssl_handshake_complete(handle);
    }
  } else if (ret > 0) {
    tv_write_t* tcp_req = NULL;
    tv_buf_t enc_buf = uv_buf_init(malloc(ret), ret);

    if (enc_buf.base == NULL) {
      tv__ssl_handle_error(handle, TV_ENOMEM);
      return;
    }

    tcp_req = malloc(sizeof(*tcp_req));
    if (tcp_req == NULL) {
      free(enc_buf.base);
      tv__ssl_handle_error(handle, TV_ENOMEM);
      return;
    }

    ret = BIO_read(handle->bio_net, enc_buf.base, enc_buf.len);
    /* assert(ret == (int) enc_buf.len); */

    tv__tcp_write(tcp_req, handle->tv_handle, enc_buf, tv__ssl_handshake_write_cb);
  }
}
static int tv__ssl_read(tv_ssl_t* handle) {
  int nread = 0;
  int total = 0;
  tv_buf_t dec_buf = uv_buf_init(malloc(TV_SSL_DEFAULT_BUFFER_SIZE), TV_SSL_DEFAULT_BUFFER_SIZE);

  if (dec_buf.base == NULL) {
    return TV_ENOMEM;
  }

  do {
    nread = SSL_read(handle->ssl, dec_buf.base + total, dec_buf.len - total);
    if (nread > 0) {
      total += nread;
      if (dec_buf.len < (total + TV_SSL_DEFAULT_BUFFER_SIZE)) {
        char* tmp = realloc(dec_buf.base, dec_buf.len + TV_SSL_DEFAULT_BUFFER_SIZE);
        if (tmp == NULL) {
          free(dec_buf.base);
          return TV_ENOMEM;
        }
        dec_buf.base = tmp;
        dec_buf.len += TV_SSL_DEFAULT_BUFFER_SIZE;
      }
    }
  } while (nread > 0);

  if (total > 0) {
    if (handle->read_cb != NULL) {
      handle->read_cb((tv_stream_t*) handle, total, &dec_buf);
    } else {
      free(dec_buf.base);
      dec_buf.base = NULL;
    }
  } else {
    free(dec_buf.base);
    dec_buf.base = NULL;
  }

  if (nread == 0) {
    int flags = SSL_get_shutdown(handle->ssl);
    /* TODO: check flags */
    if ((flags & (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN))
        == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) {
      tv__tcp_close(handle->tv_handle, tv__ssl_close_handle);
    } else if (flags & SSL_RECEIVED_SHUTDOWN) {
      if (handle->read_cb != NULL) {
        handle->read_cb((tv_stream_t*) handle, TV_EOF, &dec_buf);
      }
    }
  } else if (nread < 0) {
    int err = SSL_get_error(handle->ssl, nread);
    if (err == SSL_ERROR_SYSCALL) {
      unsigned long ssl_err = ERR_get_error();
      /*
       * If ssl_err == 0, then EOF that is not an error.
       * http://stackoverflow.com/questions/13686398/ssl-read-failing-with-ssl-error-syscall-error
       */
      if (ssl_err != 0) {
        handle->ssl_err = ssl_err;
        return TV_ESSL;
      }
    /* TODO: check err */
    } else if ((err != SSL_ERROR_WANT_READ) && (err != SSL_ERROR_WANT_WRITE)) {
      handle->ssl_err = ERR_get_error();
      return TV_ESSL;
    }
  }

  return 0;
}
void tv__ssl_connect(tv_ssl_t* handle, const char* host, const char* port, tv_connect_cb connect_cb) {
  int ret = 0;
  tv_tcp_t* tcp_handle = NULL;

  handle->connect_cb = connect_cb;

  if (handle->is_connected) {
    /* Unless it becomes possible that tv_tcp_connect returns false using state corresponded to multi-thread. */
    tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_EISCONN);
    return;
  }

  tcp_handle = malloc(sizeof(*tcp_handle));
  if (tcp_handle == NULL) {
    tv__stream_delayed_connect_cb((tv_stream_t*) handle, TV_ENOMEM);
    return;
  }
  ret = tv_tcp_init(handle->loop, tcp_handle);
  assert(ret == 0);
  TV_UNUSED(ret);
  tcp_handle->data = handle;

  /* Copy handle->devname to lower transport */
  if (handle->devname != NULL) {
    size_t len = strlen(handle->devname) + 1;
    tcp_handle->devname = malloc(len);
    memset(tcp_handle->devname, 0, len);
    strncpy(tcp_handle->devname, handle->devname, len - 1);
  }

  tv__tcp_connect(tcp_handle, host, port, tv__ssl_start_client_handshake);

  handle->tv_handle = tcp_handle;
}
void tv__ssl_listen(tv_ssl_t* handle, const char* host, const char* port, int backlog, tv_connection_cb connection_cb) {
  int ret = 0;
  tv_tcp_t* tcp_handle = NULL;

  handle->connection_cb = connection_cb;
  handle->is_server = 1;

  if (handle->is_listened) {
    handle->last_err = TV_EISCONN;
    return;
  }

  tcp_handle = malloc(sizeof(*tcp_handle));
  if (tcp_handle == NULL) {
    handle->last_err= TV_ENOMEM;
    return;
  }
  ret = tv_tcp_init(handle->loop, tcp_handle);
  assert(ret == 0);
  TV_UNUSED(ret);
  tcp_handle->data = handle;

  tv__tcp_listen(tcp_handle, host, port, backlog, tv__ssl_start_server_handshake);
  if (!tcp_handle->is_listened) {
    handle->last_err = tcp_handle->last_err;
    tv__tcp_close(tcp_handle, tv__handle_free_handle);
  } else {
    handle->tv_handle = tcp_handle;
    handle->is_listened = tcp_handle->is_listened;
    handle->last_err = tcp_handle->last_err;
  }
}

void tv__ssl_read_start(tv_ssl_t* handle, tv_read_cb read_cb) {
  handle->read_cb = read_cb;
}
void tv__ssl_read_stop(tv_ssl_t* handle) {
  int ret = 0;

  handle->read_cb = NULL;

  ret = tv_read_stop((tv_stream_t*) handle->tv_handle);
  assert(ret == 0);
  TV_UNUSED(ret);
}

void tv__ssl_write(tv_write_t* tv_req, tv_ssl_t* handle, tv_buf_t buf, tv_write_cb write_cb) {
  int ret = 0;
  size_t remain = buf.len;
  size_t written = 0;
  tv_write_t* tcp_req = NULL;
  tv_buf_t enc_buf = uv_buf_init(NULL, 0);

  tv_write_init(tv_req, (tv_stream_t*) handle, buf, write_cb);

  if (!(handle->is_connected || handle->is_accepted)) {
    tv__stream_delayed_write_cb(tv_req, TV_ENOTCONN);
    return;
  }

  while (remain > 0) {
    size_t write_size = (remain > TV_SSL_MAX_RECORD_SIZE) ? TV_SSL_MAX_RECORD_SIZE : remain;

    /* ClearIn */
    ret = SSL_write(handle->ssl, (buf.base + written), write_size);
    if (ret <= 0) {
      int err = SSL_get_error(handle->ssl, ret);
      if ((err != SSL_ERROR_WANT_READ) && (err != SSL_ERROR_WANT_WRITE)) {
        free(enc_buf.base);
        handle->ssl_err = ERR_get_error();
        tv__stream_delayed_write_cb(tv_req, TV_ESSL);
        return;
      }
    }
    remain -= write_size;
    written += write_size;

    /* EncOut */
    ret = BIO_pending(handle->bio_net);
    if (ret > 0) {
      char* tmp = realloc(enc_buf.base, enc_buf.len + ret);
      if (tmp == NULL) {
        free(enc_buf.base);
        tv__stream_delayed_write_cb(tv_req, TV_ENOMEM);
        return;
      }
      enc_buf.base = tmp;
      ret = BIO_read(handle->bio_net, enc_buf.base + enc_buf.len, ret);
      enc_buf.len += ret;
    }
  }

  /* Send */
  tcp_req = malloc(sizeof(*tcp_req));
  if (tcp_req == NULL) {
    free(enc_buf.base);
    tv__stream_delayed_write_cb(tv_req, TV_ENOMEM);
    return;
  }
  tcp_req->data = tv_req;
  tv__tcp_write(tcp_req, handle->tv_handle, enc_buf, tv__ssl_call_write_cb);
}
void tv__ssl_close(tv_ssl_t* handle, tv_close_cb close_cb) {
  handle->close_cb = close_cb;

  if (handle->is_listened) {
    tv__tcp_close(handle->tv_handle, tv__ssl_close_handle);
  } else if (handle->is_connected || handle->is_accepted) {
    int ret = 0;

    if (handle->close_immediately) {
      tv__tcp_close(handle->tv_handle, tv__ssl_close_handle);
      return;
    }

    ret = SSL_shutdown(handle->ssl);
    if (ret == 1) {
      /* shutdown complete */
      ret = BIO_pending(handle->bio_net);
      if (ret > 0) {
        tv_buf_t enc_buf;
        tv_write_t* tcp_req = NULL;

        enc_buf.base = malloc(ret);
        if (enc_buf.base == NULL) {
          tv__tcp_close(handle->tv_handle, tv__ssl_close_handle);
          return;
        }
        enc_buf.len = ret;

        tcp_req = malloc(sizeof(*tcp_req));
        if (tcp_req == NULL) {
          free(enc_buf.base);
          tv__tcp_close(handle->tv_handle, tv__ssl_close_handle);
          return;
        }

        ret = BIO_read(handle->bio_net, enc_buf.base, enc_buf.len);
        assert(ret == (int)enc_buf.len);

        tv__tcp_write(tcp_req, handle->tv_handle, enc_buf, tv__ssl_close_write_cb);
      } else {
        /* already shutdown completely */
        tv__tcp_close(handle->tv_handle, tv__ssl_close_handle);
        return;
      }
    } else if (ret == 0) {
      /* shutdown incomplete */
      ret = BIO_pending(handle->bio_net);
      if (ret > 0) {
        tv_buf_t enc_buf;
        tv_write_t* tcp_req = NULL;

        enc_buf.base = malloc(ret);
        if (enc_buf.base == NULL) {
          tv__tcp_close(handle->tv_handle, tv__ssl_close_handle);
          return;
        }
        enc_buf.len = ret;

        tcp_req = malloc(sizeof(*tcp_req)); assert(tcp_req != NULL);
        if (tcp_req == NULL) {
          free(enc_buf.base);
          tv__tcp_close(handle->tv_handle, tv__ssl_close_handle);
          return;
        }

        ret = BIO_read(handle->bio_net, enc_buf.base, enc_buf.len);
        assert(ret == (int)enc_buf.len);

        tv__tcp_write(tcp_req, handle->tv_handle, enc_buf, tv__ssl_close_write_cb);
      }
    } else {
      assert(ret == -1);
      handle->ssl_err = ERR_get_error();
      tv__tcp_close(handle->tv_handle, tv__ssl_close_handle);
    }
  } else {
    if (handle->tv_handle == NULL) {
      /* connecting or initialized */
      if (handle->pending_timer.data == NULL) {
        int ret = uv_timer_init(&handle->loop->loop, &handle->pending_timer);
        assert(ret == 0);  /* uv_timer_init always return 0 in version 0.11.13. */
        TV_UNUSED(ret);
        handle->pending_timer.data = handle;
      }
      if (!uv_is_closing((uv_handle_t*) &handle->pending_timer)) {
        uv_close((uv_handle_t*) &handle->pending_timer, tv__ssl_close_handle2);
      }
    } else {
      tv__tcp_close(handle->tv_handle, tv__ssl_close_handle);
    }
  }
}

static void tv__ssl_start_client_handshake(tv_stream_t* tcp_handle, int status) {
  int ret = 0;
  tv_ssl_t* ssl_handle = (tv_ssl_t*) tcp_handle->data;

  ret = tv__ssl_init_bio(ssl_handle, 0);
  if (ret) {
    if (ssl_handle->connect_cb != NULL) {
      ssl_handle->connect_cb((tv_stream_t*) ssl_handle, ret);
    }
    return;
  }

  if (status) {
    if (ssl_handle->connect_cb != NULL) {
      ssl_handle->connect_cb((tv_stream_t*) ssl_handle, status);
    }
    return;
  }

  ret = tv_read_start(tcp_handle, tv__ssl_read_cb);
  assert(ret == 0);

  tv__ssl_handshake(ssl_handle);
}
static void tv__ssl_start_server_handshake(tv_stream_t* server, tv_stream_t* client, int status) {
  int ret = 0;
  tv_ssl_t* ssl_server = NULL;
  tv_ssl_t* ssl_client = NULL;

  ssl_server = (tv_ssl_t*) server->data;

  if (status) {
    if (ssl_server->connection_cb != NULL) {
      ssl_server->connection_cb((tv_stream_t*) ssl_server, NULL, status);
    }
    return;
  }

  ssl_client = malloc(sizeof(*ssl_client));
  if (ssl_client == NULL) {
    tv__tcp_close((tv_tcp_t*) client, tv__handle_free_handle);
    if (ssl_server->connection_cb != NULL) {
      ssl_server->connection_cb((tv_stream_t*) ssl_server, NULL, TV_ENOMEM);
    }
    return;
  }
  ret = tv_ssl_init(ssl_server->loop, ssl_client, ssl_server->ssl_ctx);
  assert(ret == 0);
  ssl_client->listen_handle = ssl_server;
  ssl_client->tv_handle = (tv_tcp_t*) client;
  ssl_client->connection_cb = ssl_server->connection_cb;
  client->data = ssl_client;

  ret = tv__ssl_init_bio(ssl_client, 1);
  if (ret) {
    free(ssl_client);
    tv__tcp_close((tv_tcp_t*) client, tv__handle_free_handle);
    if (ssl_server->connection_cb != NULL) {
      ssl_server->connection_cb((tv_stream_t*) ssl_server, NULL, ret);
    }
    return;
  }

  ret = tv_read_start(client, tv__ssl_read_cb);
  assert(ret == 0);

  tv__ssl_handshake(ssl_client);
}
static void tv__ssl_read_cb(tv_stream_t* tcp_handle, ssize_t nread, const tv_buf_t* buf) {
  int ret = 0;
  size_t remain = 0;
  size_t written = 0;
  tv_ssl_t* ssl_handle = (tv_ssl_t*) tcp_handle->data;

  assert(nread != 0);  /* tv_read_cb not return nread = 0. */
  if (nread <= 0) {
    ssl_handle->close_immediately = 1;
    tv__ssl_handle_error(ssl_handle, nread);
    return;
  }

  remain = nread;
  while (remain > 0) {
    size_t write_size = (remain > TV_BIO_DEFAULT_BUFFER_SIZE) ? TV_BIO_DEFAULT_BUFFER_SIZE : remain;

    /* EncIn */
    ret = BIO_write(ssl_handle->bio_net, (buf->base + written), write_size);
    if ((ret <= 0) && !BIO_should_retry(ssl_handle->bio_net)) {
      /* fatal error */
      free(buf->base);
      ssl_handle->ssl_err = ERR_get_error();
      tv__ssl_handle_error(ssl_handle, TV_ESSL);
      return;
    }
    remain -= write_size;
    written += write_size;

    /* ClearOut */
    if (!SSL_is_init_finished(ssl_handle->ssl)) {
      tv__ssl_handshake(ssl_handle);
    } else {
      ret = tv__ssl_read(ssl_handle);
      if (ret) {
        tv__ssl_handle_error(ssl_handle, ret);
      }
    }
  }
  free(buf->base);
}
static void tv__ssl_handshake_write_cb(tv_write_t* tcp_req, int status) {
  tv_ssl_t* ssl_handle = (tv_ssl_t*) tcp_req->handle->data;
  if (status) {
    /* failure */
    tv__ssl_handle_error(ssl_handle, status);
  } else {
    /* success */
    if (SSL_is_init_finished(ssl_handle->ssl)) {
      tv__ssl_handshake_complete(ssl_handle);
    }
    /* !SSL_is_init_finished => wait to receive from peer */
  }

  free(tcp_req->buf.base);
  free(tcp_req);
}
static void tv__ssl_call_write_cb(tv_write_t* tcp_req, int status) {
  tv_write_t* tv_req = (tv_write_t*) tcp_req->data;
  if (tv_req->write_cb != NULL) {
    tv_req->write_cb(tv_req, status);
  }

  free(tcp_req->buf.base);
  free(tcp_req);
}
static void tv__ssl_close_write_cb(tv_write_t* tcp_req, int status) {
  tv_ssl_t* ssl_handle = (tv_ssl_t*) tcp_req->handle->data;

  /* even if write failed, socket close */
  TV_UNUSED(status);

  tv__tcp_close(ssl_handle->tv_handle, tv__ssl_close_handle);

  free(tcp_req->buf.base);
  free(tcp_req);
}
static void tv__ssl_close_handle(tv_handle_t* handle) {
  tv_ssl_t* ssl_handle = (tv_ssl_t*) handle->data;

  tv__req_queue_erase(ssl_handle->loop, (tv_handle_t*) ssl_handle);

  if (!ssl_handle->is_listened) {
    tv__ssl_close_bio(ssl_handle);
  }
  tv_stream_destroy((tv_stream_t*) ssl_handle);
  if (ssl_handle->close_cb != NULL) {
    ssl_handle->close_cb((tv_handle_t*) ssl_handle);
  }

  free(handle);
}
static void tv__ssl_close_handle2(uv_handle_t* handle) {
  tv_ssl_t* ssl_handle = (tv_ssl_t*) handle->data;

  tv__req_queue_erase(ssl_handle->loop, (tv_handle_t*) ssl_handle);

  tv_stream_destroy((tv_stream_t*) ssl_handle);
  if (ssl_handle->close_cb != NULL) {
    ssl_handle->close_cb((tv_handle_t*) ssl_handle);
  }
}
