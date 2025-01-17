// Test that gcc-toolchain option is working correctly
//
// RUN: %clangxx -no-canonical-prefixes %s -### -o %t 2>&1 \
// RUN:     --target=i386-unknown-linux \
// RUN:     --gcc-toolchain=%S/Inputs/ubuntu_11.04_multiarch_tree/usr \
// RUN:   | FileCheck %s
//
// Additionally check that the legacy spelling of the flag works.
// RUN: %clangxx -no-canonical-prefixes %s -### -o %t 2>&1 \
// RUN:     --target=i386-unknown-linux \
// RUN:     -gcc-toolchain %S/Inputs/ubuntu_11.04_multiarch_tree/usr \
// RUN:   | FileCheck %s
//
// Test for header search toolchain detection.
// CHECK: "-internal-isystem"
// CHECK: "[[TOOLCHAIN:[^"]+]]/usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5/../../../../../include/c++/4.5"
// CHECK: "-internal-isystem"
// CHECK: "[[TOOLCHAIN]]/usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5/../../../../../include/c++/4.5/i686-linux-gnu"
// CHECK: "-internal-isystem"
// CHECK: "[[TOOLCHAIN]]/usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5/../../../../../include/c++/4.5/backward"
// CHECK: "-internal-isystem" "/usr/local/include"
//
// Test for linker toolchain detection. Note that only the '-L' flags will use
// the same precise formatting of the path as the '-internal-system' flags
// above, so we just blanket wildcard match the 'crtbegin.o'.
// CHECK: "{{[^"]*}}ld{{(.exe)?}}"
// CHECK: "{{[^"]*}}/usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5/crtbegin.o"
// CHECK: "-L[[TOOLCHAIN]]/usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5"
// CHECK: "-L[[TOOLCHAIN]]/usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5/../../../.."
