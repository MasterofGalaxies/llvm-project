// RUN: %clangxx_asan -O0 -g %s -o %t && ASAN_OPTIONS=handle_ioctl=1 %t 2>&1 | %symbolize | FileCheck %s
// RUN: %clangxx_asan -O3 -g %s -o %t && ASAN_OPTIONS=handle_ioctl=1 %t 2>&1 | %symbolize | FileCheck %s

// RUN: %clangxx_asan -O0 -g %s -o %t && %t
// RUN: %clangxx_asan -O3 -g %s -o %t && %t

#include <assert.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  int nonblock;
  int res = ioctl(fd, FIONBIO, &nonblock + 1);
  // CHECK: AddressSanitizer: stack-buffer-overflow
  // CHECK: READ of size 4 at
  // CHECK: {{#.* in _?main .*ioctl.cc:}}[[@LINE-3]]
  assert(res == 0);
  close(fd);
  return 0;
}
