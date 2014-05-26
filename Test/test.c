/* Test code for IFRit */

#include "stdio.h"
#include "pthread.h"

int x;

void *thread(void *data) {
  for (int i = 0; i < 1000; i++) {
    x += 1;
  }
}

int main() {
  printf("Hello world\n");
  x = 0;
  pthread_t t1, t2;
  pthread_create(&t1, NULL, thread, NULL);
  pthread_create(&t2, NULL, thread, NULL);
  pthread_join(t1, NULL);
  pthread_join(t2, NULL);
  printf("Final value of x: %d\n", x);
}
