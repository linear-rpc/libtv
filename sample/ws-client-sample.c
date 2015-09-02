#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "tv.h"

static int is_connected;
static int is_written;
static int is_read;

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
  fprintf(stdout, "closed\n");
  is_connected = 0;
}
void write_cb(tv_write_t* req, int status) {
  if (status) {
    fprintf(stderr, "write error: %s\n", tv_strerror((tv_handle_t*) req->handle, status));
    tv_close((tv_handle_t*) req->handle, close_cb);
  } else {
    is_written = 1;
  }
  free(req);
}
void read_cb(tv_stream_t* handle, ssize_t nread, const tv_buf_t* buf) {
  if (nread < 0) {
    fprintf(stderr, "read error: %s\n", tv_strerror((tv_handle_t*) handle, nread));
    tv_close((tv_handle_t*) handle, close_cb);
    /* if nread < 0 then libtv frees buf.base internally */
  } else {
    int i;
    fprintf(stdout, "recv: ");
    for (i = 0; i < nread; i++) {
      fprintf(stdout, "%c", buf->base[i]);
    }
    is_read = 1;
    free(buf->base);
  }
}
void connect_cb(tv_stream_t* handle, int status) {
  if (status) {
    fprintf(stdout, "connect error %s\n", tv_strerror((tv_handle_t*) handle, status));
    tv_close((tv_handle_t*) handle, close_cb);
  } else {
    fprintf(stdout, "connected\n");
    print_sock_addr(handle);
    print_peer_addr(handle);
    tv_read_start(handle, read_cb);
    is_connected = 1;
  }
}

int main() {
  is_connected = 0;
  is_written = 0;
  is_read = 0;

  int ret;
  tv_loop_t* loop;
  tv_ws_t handle;
  tv_write_t* req;

  signal(SIGPIPE, SIG_IGN);
  loop = tv_loop_new();
  tv_ws_init(loop, &handle);
  ret = tv_connect((tv_stream_t*) &handle, "localhost", "11600", connect_cb);
  if (ret) {
    fprintf(stderr, "error %s\n", tv_strerror((tv_handle_t*) &handle, ret));
    tv_close((tv_handle_t*) &handle, close_cb);
    tv_loop_delete(loop);
    return -1;
  }
  while (!is_connected) {
    usleep(10);
  }
  while (1) {
    char input[65536];
    char* p;
    p = fgets(input, sizeof(input) - 1, stdin);
    if (strncmp(p, "quit", 4) == 0) {
      break;
    }
    fprintf(stdout, "send: %s", p);
    req = (tv_write_t*) malloc(sizeof(tv_write_t));
    uv_buf_t buf;
    buf.base = p;
    buf.len = strlen(p);
    ret = tv_write(req, (tv_stream_t*) &handle, buf, write_cb);
    if (ret) {
      fprintf(stderr, "tv_write error: %s\n", tv_strerror((tv_handle_t*) &handle, ret));
      return -1;
    }
    while (!is_written) {
      usleep(10);
    }
  }
  ret = tv_close((tv_handle_t*) &handle, close_cb);
  if (ret) {
    fprintf(stderr, "tv_close error: %s\n", tv_strerror((tv_handle_t*) &handle, ret));
    return -1;
  }
  while (is_connected) {
    usleep(10);
  }
  tv_loop_delete(loop);
  return 0;
}
