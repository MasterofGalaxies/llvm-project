// RUN: %clangxx_asan -O0 %s -o %t && %t 2>&1 | %symbolize | FileCheck %s
// RUN: %clangxx_asan -O3 %s -o %t && %t 2>&1 | %symbolize | FileCheck %s

#include <assert.h>
#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <string.h>

#include <sanitizer/linux_syscall_hooks.h>

/* Test the presence of __sanitizer_syscall_ in the tool runtime, and general
   sanity of their behaviour. */

int main(int argc, char *argv[]) {
  char buf[1000];
  __sanitizer_syscall_pre_recvmsg(0, buf - 1, 0);
  // CHECK: AddressSanitizer: stack-buffer-{{.*}}erflow
  // CHECK: READ of size {{.*}} at {{.*}} thread T0
  // CHECK: #0 {{.*}} in __sanitizer_syscall_pre_recvmsg
  return 0;
}
