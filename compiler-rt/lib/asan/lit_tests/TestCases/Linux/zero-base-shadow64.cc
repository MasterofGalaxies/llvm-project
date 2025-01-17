// RUN: %clangxx_asan -O0 -fsanitize-address-zero-base-shadow -fPIE -pie %s -o %t
// RUN: %t 2>&1 | %symbolize | FileCheck %s
// RUN: %clangxx_asan -O1 -fsanitize-address-zero-base-shadow -fPIE -pie %s -o %t
// RUN: %t 2>&1 | %symbolize | FileCheck %s
// RUN: %clangxx_asan -O2 -fsanitize-address-zero-base-shadow -fPIE -pie %s -o %t
// RUN: %t 2>&1 | %symbolize | FileCheck %s

// Zero-base shadow only works on x86_64 and i386.
// REQUIRES: x86_64-supported-target, asan-64-bits

#include <string.h>
int main(int argc, char **argv) {
  char x[10];
  memset(x, 0, 10);
  int res = x[argc * 10];  // BOOOM
  // CHECK: {{READ of size 1 at 0x.* thread T0}}
  // CHECK: {{    #0 0x.* in _?main .*zero-base-shadow64.cc:}}[[@LINE-2]]
  // CHECK: {{Address 0x.* is .* frame}}
  // CHECK: main

  // Check that shadow for stack memory occupies lower part of address space.
  // CHECK: =>0x0f
  return res;
}
