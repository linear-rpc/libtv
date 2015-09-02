#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "tv.h"

#define MAX_SIZE (256)

static int count;

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
  tv_read_start(client, read_cb);
}

int main() {
  int ret;
  tv_loop_t* loop;
  tv_pipe_t handle;
  char input[MAX_SIZE];
  int ipc = 1;

  signal(SIGPIPE, SIG_IGN);
  loop = tv_loop_new();
  tv_pipe_init(loop, &handle, ipc);
  ret = tv_pipe_listen(&handle, "/tmp/tv_sock", 10, connection_cb);
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
