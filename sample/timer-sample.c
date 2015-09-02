#include <stdio.h>
#include <unistd.h>

#include "tv.h"

#define MAX_SIZE (256)

static int count;

void close_cb(tv_handle_t* handle) {
  fprintf(stdout, "closed\n");
}
void timer_cb(tv_timer_t* timer) {
  fprintf(stderr, "%d\n", ++count);
  /* timer stop in loop thread */
  // if (count == 5) {
  //   tv_err_t err;
  //   fprintf(stderr, "timer stop\n");
  //   err = tv_timer_stop(timer);
  //   if (err.code != TV_OK) {
  //     fprintf(stderr, "tv_timer_stop failed\n");
  //   }
  //   fprintf(stderr, "timer close\n");
  //   err = tv_close((tv_handle_t*) timer);
  //   if (err.code != TV_OK) {
  //     fprintf(stderr, "tv_close failed\n");
  //   }
  // }
}

int main() {
  int ret;
  tv_loop_t* loop;
  tv_timer_t timer;
  char input[MAX_SIZE];
  char* p;

  count = 0;
  loop = tv_loop_new();
  ret = tv_timer_init(loop, &timer);
  if (ret) {
    fprintf(stderr, "tv_timer_init failed\n");
    return -1;
  }
  ret = tv_timer_start(&timer, timer_cb, 1000, 1000);
  if (ret) {
    fprintf(stderr, "tv_timer_start failed\n");
    return -1;
  }

  printf("press any key to stop timer.\n");
  p = fgets(input, MAX_SIZE, stdin);
  printf("%s\n", p);

  /* timer stop in main thread */
  fprintf(stderr, "timer stop\n");
  ret = tv_timer_stop(&timer);
  if (ret) {
    fprintf(stderr, "tv_timer_stop failed\n");
  }

  printf("press any key to start timer.\n");
  p = fgets(input, MAX_SIZE, stdin);
  printf("%s\n", p);

  ret = tv_timer_start(&timer, timer_cb, 1000, 1000);
  if (ret) {
    fprintf(stderr, "tv_timer_start failed\n");
    return -1;
  }

  printf("press any key to exit.\n");
  p = fgets(input, MAX_SIZE, stdin);
  printf("%s\n", p);

  fprintf(stderr, "timer stop\n");
  ret = tv_timer_stop(&timer);
  if (ret) {
    fprintf(stderr, "tv_timer_stop failed\n");
  }

  fprintf(stderr, "timer close\n");
  ret = tv_close((tv_handle_t*) &timer, close_cb);
  if (ret) {
    fprintf(stderr, "tv_close failed\n");
  }

  tv_loop_delete(loop);

  return 0;
}
