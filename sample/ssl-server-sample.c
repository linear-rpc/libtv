#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "tv.h"

#define MAX_SIZE (256)

#define SERVER_CERT "../certs/valid/server.pem"
#define SERVER_PKEY "../certs/valid/server.key"
#define CA_CERT     "../certs/valid/ca.pem"

static int count;

void print_sock_addr(tv_stream_t* peer) {
  int ret;
  struct sockaddr_storage peername;
  int namelen = sizeof(peername);

  ret = tv_getsockname(peer, (struct sockaddr*) &peername, &namelen);
  if (ret) {
    fprintf(stderr, "getsockname fail\n");
  }
  switch (peername.ss_family) {
  case AF_INET: {
    char ip_str[INET_ADDRSTRLEN];
    int port;
    struct sockaddr_in* src = (struct sockaddr_in*) &peername;
    ret = uv_inet_ntop(AF_INET, &src->sin_addr, ip_str, sizeof(ip_str));
    if (ret) {
      fprintf(stderr, "getsockname fail\n");
    }
    port = ntohs(src->sin_port);
    fprintf(stderr, "SockAddress: %s, %d\n", ip_str, port);
    break;
  }
  case AF_INET6: {
    char ip_str[INET6_ADDRSTRLEN];
    int port;
    struct sockaddr_in6* src = (struct sockaddr_in6*) &peername;
    ret = uv_inet_ntop(AF_INET6, &src->sin6_addr, ip_str, sizeof(ip_str));
    if (ret) {
      fprintf(stderr, "getsockname fail\n");
    }
    port = ntohs(src->sin6_port);
    fprintf(stderr, "SockAddress: %s, %d\n", ip_str, port);
    break;
  }
  default:
    break;
  }
}
void print_peer_addr(tv_stream_t* peer) {
  int ret;
  struct sockaddr_storage peername;
  int namelen = sizeof(peername);

  ret = tv_getpeername(peer, (struct sockaddr*) &peername, &namelen);
  if (ret) {
    fprintf(stderr, "getpeername fail\n");
  }
  switch (peername.ss_family) {
  case AF_INET: {
    char ip_str[INET_ADDRSTRLEN];
    int port;
    struct sockaddr_in* src = (struct sockaddr_in*) &peername;
    ret = uv_inet_ntop(AF_INET, &src->sin_addr, ip_str, sizeof(ip_str));
    if (ret) {
      fprintf(stderr, "getpeername fail\n");
    }
    port = ntohs(src->sin_port);
    fprintf(stderr, "Address: %s, %d\n", ip_str, port);
    break;
  }
  case AF_INET6: {
    char ip_str[INET6_ADDRSTRLEN];
    int port;
    struct sockaddr_in6* src = (struct sockaddr_in6*) &peername;
    ret = uv_inet_ntop(AF_INET6, &src->sin6_addr, ip_str, sizeof(ip_str));
    if (ret) {
      fprintf(stderr, "getpeername fail\n");
    }
    port = ntohs(src->sin6_port);
    fprintf(stderr, "Address: %s, %d\n", ip_str, port);
    break;
  }
  default:
    break;
  }
}
void close_cb(tv_handle_t* handle) {
  fprintf(stdout, "closed, count = %d\n", --count);
  free(handle);
}
void write_cb(tv_write_t* req, int status) {
  if (status) {
    fprintf(stderr, "write error: %s\n", tv_strerror((tv_handle_t*) req->handle, status));
    tv_close((tv_handle_t*) req->handle, close_cb);
  }
  free(req->buf.base);
  free(req);
}
void read_cb(tv_stream_t* handle, ssize_t nread, const tv_buf_t* buf) {
  assert(nread != 0);
  if (nread < 0) {
    fprintf(stderr, "read error: %s\n", tv_strerror((tv_handle_t*) handle, nread));
    tv_close((tv_handle_t*) handle, close_cb);
    /* if nread < 0 then libtv frees buf.base internally */
  } else {
    int i;
    tv_write_t* req;
    tv_buf_t buf_out;

    fprintf(stdout, "recv and echo-back: ");
    for (i = 0; i < nread; i++) {
      fprintf(stdout, "%c", buf->base[i]);
    }
    req = (tv_write_t*) malloc(sizeof(tv_write_t));
    buf_out.base = (char*) malloc(nread);
    buf_out.len = nread;
    memcpy(buf_out.base, buf->base, nread);
    tv_write(req, handle, buf_out, write_cb);
    free(buf->base);
  }
}
void connection_cb(tv_stream_t* server, tv_stream_t* client, int status) {
  char buf[256];
  X509* cert = NULL;
  X509_NAME* xname = NULL;
  const SSL_CIPHER* cipher;

  if (status) {
    assert(client == NULL);
    fprintf(stderr, "connection_cb error: %s\n", tv_strerror((tv_handle_t*) server, status));
    return;
  }
  if (tv_ssl_get_verify_result((tv_ssl_t*) client)) {
    fprintf(stderr, "verify failed\n");
    tv_close((tv_handle_t*) client, close_cb);
    return;
  }
  cert = tv_ssl_get_peer_certificate((tv_ssl_t*) client);
  xname = X509_get_subject_name(cert);
  X509_NAME_get_text_by_NID(xname, NID_commonName, buf, sizeof(buf));
  fprintf(stderr, "Subject: CN=%s\n", buf);
  cipher = tv_ssl_get_current_cipher((tv_ssl_t*) client);
  fprintf(stderr, "Cipher: Name=%s, Version=%s\n", SSL_CIPHER_get_name(cipher), SSL_CIPHER_get_version(cipher));
  X509_free(cert);
  fprintf(stdout, "connected, count = %d\n", ++count);
  print_sock_addr(client);
  print_peer_addr(client);
  tv_read_start(client, read_cb);
}

int init_ssl_ctx(SSL_CTX* ssl_ctx) {
  FILE* fp;
  EVP_PKEY* key;

  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE, NULL);
  if (SSL_CTX_use_certificate_chain_file(ssl_ctx, SERVER_CERT) != 1) {
    fprintf(stderr, "use_certificate error\n");
    return -1;
  }
  if ((fp = fopen(SERVER_PKEY, "r")) == NULL) {
    fprintf(stderr, "fopen error\n");
    return -1;
  }
  if ((key = PEM_read_PrivateKey(fp, NULL, NULL, "netmedia")) == NULL) {
    fprintf(stderr, "PEM_read_PrivateKey error\n");
    return -1;
  }
  if (SSL_CTX_use_PrivateKey(ssl_ctx, key) != 1) {
    fprintf(stderr, "use_PrivateKey error\n");
    return -1;
  }
  EVP_PKEY_free(key);
  if (fclose(fp) != 0) {
    fprintf(stderr, "fclose error\n");
    return -1;
  }
  if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
    fprintf(stderr, "check_private_key error\n");
    return -1;
  }
  if (SSL_CTX_load_verify_locations(ssl_ctx, CA_CERT, NULL) != 1) {
    fprintf(stderr, "load_verify_locations error\n");
    return -1;
  }
  return 0;
}

int main() {
  int ret;
  SSL_CTX* ssl_ctx;
  tv_loop_t* loop;
  tv_ssl_t handle;
  char input[MAX_SIZE + 1];

  signal(SIGPIPE, SIG_IGN);
  tv_ssl_library_init();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  ssl_ctx = SSL_CTX_new(TLSv1_1_server_method());
#else
  ssl_ctx = SSL_CTX_new(TLS_server_method());
#endif
  assert(ssl_ctx != NULL);
  ret = init_ssl_ctx(ssl_ctx);
  if (ret) {
    SSL_CTX_free(ssl_ctx);
    return -1;
  }
  loop = tv_loop_new();
  tv_ssl_init(loop, &handle, ssl_ctx);
  ret = tv_listen((tv_stream_t*) &handle, "0.0.0.0", "11600", 10, connection_cb);
  if (ret) {
    fprintf(stderr, "tv_listen error: %s\n", tv_strerror((tv_handle_t*) &handle, ret));
    ret = tv_close((tv_handle_t*) &handle, NULL);
    SSL_CTX_free(ssl_ctx);
    tv_loop_delete(loop);
    return -1;
  }
  printf("press any key to exit.\n");
  fgets(input, MAX_SIZE, stdin);
  ret = tv_close((tv_handle_t*) &handle, NULL);
  SSL_CTX_free(ssl_ctx);
  tv_loop_delete(loop);
  return 0;
}
