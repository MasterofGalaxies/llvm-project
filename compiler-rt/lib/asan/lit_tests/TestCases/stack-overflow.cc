// RUN: %clangxx_asan -O0 %s -o %t && %t 2>&1 | %symbolize | FileCheck %s
// RUN: %clangxx_asan -O1 %s -o %t && %t 2>&1 | %symbolize | FileCheck %s
// RUN: %clangxx_asan -O2 %s -o %t && %t 2>&1 | %symbolize | FileCheck %s
// RUN: %clangxx_asan -O3 %s -o %t && %t 2>&1 | %symbolize | FileCheck %s

#include <string.h>
int main(int argc, char **argv) {
  char x[10];
  memset(x, 0, 10);
  int res = x[argc * 10];  // BOOOM
  // CHECK: {{READ of size 1 at 0x.* thread T0}}
  // CHECK: {{    #0 0x.* in _?main .*stack-overflow.cc:}}[[@LINE-2]]
  // CHECK: {{Address 0x.* is located in stack of thread T0 at offset}}
  // CHECK-NEXT: in{{.*}}main{{.*}}stack-overflow.cc
  return res;
}
