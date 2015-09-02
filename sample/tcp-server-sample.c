#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "tv.h"

#define MAX_SIZE (256)

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
    fprintf(stderr, "PeerAddress: %s, %d\n", ip_str, port);
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
    fprintf(stderr, "PeerAddress: %s, %d\n", ip_str, port);
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
  if (status) {
    fprintf(stderr, "connection_cb error: %s\n", tv_strerror((tv_handle_t*) server, status));
    return;
  }
  fprintf(stdout, "connected, count = %d\n", ++count);
  print_sock_addr(client);
  print_peer_addr(client);
  tv_read_start(client, read_cb);
}

int main() {
  int ret;
  tv_loop_t* loop;
  tv_tcp_t handle;
  char input[MAX_SIZE + 1];

  signal(SIGPIPE, SIG_IGN);
  loop = tv_loop_new();
  tv_tcp_init(loop, &handle);
  ret = tv_listen((tv_stream_t*) &handle, "0.0.0.0", "11600", 10, connection_cb);
  if (ret) {
    fprintf(stderr, "error %s\n", tv_strerror((tv_handle_t*) &handle, ret));
    ret = tv_close((tv_handle_t*) &handle, NULL);
    tv_loop_delete(loop);
    return -1;
  }
  printf("press any key to exit.\n");
  fgets(input, MAX_SIZE, stdin);
  ret = tv_close((tv_handle_t*) &handle, NULL);
  tv_loop_delete(loop);
  return 0;
}
