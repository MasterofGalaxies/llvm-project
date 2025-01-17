// General tests that ld invocations on Linux targets sane. Note that we use
// sysroot to make these tests independent of the host system.
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-unknown-linux \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-LD-32 %s
// CHECK-LD-32-NOT: warning:
// CHECK-LD-32: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-LD-32: "{{.*}}/usr/lib/gcc/i386-unknown-linux/4.6.0/crtbegin.o"
// CHECK-LD-32: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0"
// CHECK-LD-32: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/../../../../i386-unknown-linux/lib"
// CHECK-LD-32: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/../../.."
// CHECK-LD-32: "-L[[SYSROOT]]/lib"
// CHECK-LD-32: "-L[[SYSROOT]]/usr/lib"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=x86_64-unknown-linux \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-LD-64 %s
// CHECK-LD-64-NOT: warning:
// CHECK-LD-64: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-LD-64: "--eh-frame-hdr"
// CHECK-LD-64: "-m" "elf_x86_64"
// CHECK-LD-64: "-dynamic-linker"
// CHECK-LD-64: "{{.*}}/usr/lib/gcc/x86_64-unknown-linux/4.6.0/crtbegin.o"
// CHECK-LD-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0"
// CHECK-LD-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../../../x86_64-unknown-linux/lib"
// CHECK-LD-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../.."
// CHECK-LD-64: "-L[[SYSROOT]]/lib"
// CHECK-LD-64: "-L[[SYSROOT]]/usr/lib"
// CHECK-LD-64: "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed"
// CHECK-LD-64: "-lc"
// CHECK-LD-64: "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=x86_64-unknown-linux \
// RUN:     -static-libgcc \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-LD-64-STATIC-LIBGCC %s
// CHECK-LD-64-STATIC-LIBGCC-NOT: warning:
// CHECK-LD-64-STATIC-LIBGCC: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-LD-64-STATIC-LIBGCC: "--eh-frame-hdr"
// CHECK-LD-64-STATIC-LIBGCC: "-m" "elf_x86_64"
// CHECK-LD-64-STATIC-LIBGCC: "-dynamic-linker"
// CHECK-LD-64-STATIC-LIBGCC: "{{.*}}/usr/lib/gcc/x86_64-unknown-linux/4.6.0/crtbegin.o"
// CHECK-LD-64-STATIC-LIBGCC: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0"
// CHECK-LD-64-STATIC-LIBGCC: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../../../x86_64-unknown-linux/lib"
// CHECK-LD-64-STATIC-LIBGCC: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../.."
// CHECK-LD-64-STATIC-LIBGCC: "-L[[SYSROOT]]/lib"
// CHECK-LD-64-STATIC-LIBGCC: "-L[[SYSROOT]]/usr/lib"
// CHECK-LD-64-STATIC-LIBGCC: "-lgcc" "-lgcc_eh"
// CHECK-LD-64-STATIC-LIBGCC: "-lc"
// CHECK-LD-64-STATIC-LIBGCC: "-lgcc" "-lgcc_eh"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=x86_64-unknown-linux \
// RUN:     -static \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-LD-64-STATIC %s
// CHECK-LD-64-STATIC-NOT: warning:
// CHECK-LD-64-STATIC: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-LD-64-STATIC-NOT: "--eh-frame-hdr"
// CHECK-LD-64-STATIC: "-m" "elf_x86_64"
// CHECK-LD-64-STATIC-NOT: "-dynamic-linker"
// CHECK-LD-64-STATIC: "-static"
// CHECK-LD-64-STATIC: "{{.*}}/usr/lib/gcc/x86_64-unknown-linux/4.6.0/crtbeginT.o"
// CHECK-LD-64-STATIC: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0"
// CHECK-LD-64-STATIC: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../../../x86_64-unknown-linux/lib"
// CHECK-LD-64-STATIC: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../.."
// CHECK-LD-64-STATIC: "-L[[SYSROOT]]/lib"
// CHECK-LD-64-STATIC: "-L[[SYSROOT]]/usr/lib"
// CHECK-LD-64-STATIC: "--start-group" "-lgcc" "-lgcc_eh" "-lc" "--end-group"
//
// Check that flags can be combined. The -static dominates.
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=x86_64-unknown-linux \
// RUN:     -static-libgcc -static \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-LD-64-STATIC %s
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-unknown-linux -m32 \
// RUN:     --sysroot=%S/Inputs/multilib_32bit_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-32-TO-32 %s
// CHECK-32-TO-32: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-32-TO-32: "{{.*}}/usr/lib/gcc/i386-unknown-linux/4.6.0/crtbegin.o"
// CHECK-32-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0"
// CHECK-32-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/../../../../i386-unknown-linux/lib/../lib32"
// CHECK-32-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/../../../../lib32"
// CHECK-32-TO-32: "-L[[SYSROOT]]/lib/../lib32"
// CHECK-32-TO-32: "-L[[SYSROOT]]/usr/lib/../lib32"
// CHECK-32-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/../../../../i386-unknown-linux/lib"
// CHECK-32-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/../../.."
// CHECK-32-TO-32: "-L[[SYSROOT]]/lib"
// CHECK-32-TO-32: "-L[[SYSROOT]]/usr/lib"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-unknown-linux -m64 \
// RUN:     --sysroot=%S/Inputs/multilib_32bit_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-32-TO-64 %s
// CHECK-32-TO-64: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-32-TO-64: "{{.*}}/usr/lib/gcc/i386-unknown-linux/4.6.0/64/crtbegin.o"
// CHECK-32-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/64"
// CHECK-32-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/../../../../i386-unknown-linux/lib/../lib64"
// CHECK-32-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/../../../../lib64"
// CHECK-32-TO-64: "-L[[SYSROOT]]/lib/../lib64"
// CHECK-32-TO-64: "-L[[SYSROOT]]/usr/lib/../lib64"
// CHECK-32-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0"
// CHECK-32-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/../../../../i386-unknown-linux/lib"
// CHECK-32-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/i386-unknown-linux/4.6.0/../../.."
// CHECK-32-TO-64: "-L[[SYSROOT]]/lib"
// CHECK-32-TO-64: "-L[[SYSROOT]]/usr/lib"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=x86_64-unknown-linux -m64 \
// RUN:     --sysroot=%S/Inputs/multilib_64bit_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-64-TO-64 %s
// CHECK-64-TO-64: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-64-TO-64: "{{.*}}/usr/lib/gcc/x86_64-unknown-linux/4.6.0/crtbegin.o"
// CHECK-64-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0"
// CHECK-64-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../../../x86_64-unknown-linux/lib/../lib64"
// CHECK-64-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../../../lib64"
// CHECK-64-TO-64: "-L[[SYSROOT]]/lib/../lib64"
// CHECK-64-TO-64: "-L[[SYSROOT]]/usr/lib/../lib64"
// CHECK-64-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../../../x86_64-unknown-linux/lib"
// CHECK-64-TO-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../.."
// CHECK-64-TO-64: "-L[[SYSROOT]]/lib"
// CHECK-64-TO-64: "-L[[SYSROOT]]/usr/lib"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=x86_64-unknown-linux -m32 \
// RUN:     --sysroot=%S/Inputs/multilib_64bit_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-64-TO-32 %s
// CHECK-64-TO-32: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-64-TO-32: "{{.*}}/usr/lib/gcc/x86_64-unknown-linux/4.6.0/32/crtbegin.o"
// CHECK-64-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/32"
// CHECK-64-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../../../x86_64-unknown-linux/lib/../lib32"
// CHECK-64-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../../../lib32"
// CHECK-64-TO-32: "-L[[SYSROOT]]/lib/../lib32"
// CHECK-64-TO-32: "-L[[SYSROOT]]/usr/lib/../lib32"
// CHECK-64-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0"
// CHECK-64-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../../../x86_64-unknown-linux/lib"
// CHECK-64-TO-32: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0/../../.."
// CHECK-64-TO-32: "-L[[SYSROOT]]/lib"
// CHECK-64-TO-32: "-L[[SYSROOT]]/usr/lib"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=x86_64-unknown-linux -m32 \
// RUN:     --gcc-toolchain=%S/Inputs/multilib_64bit_linux_tree/usr \
// RUN:     --sysroot=%S/Inputs/multilib_32bit_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-64-TO-32-SYSROOT %s
// CHECK-64-TO-32-SYSROOT: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-64-TO-32-SYSROOT: "{{.*}}/usr/lib/gcc/x86_64-unknown-linux/4.6.0/32/crtbegin.o"
// CHECK-64-TO-32-SYSROOT: "-L{{[^"]*}}/Inputs/multilib_64bit_linux_tree/usr/lib/gcc/x86_64-unknown-linux/4.6.0/32"
// CHECK-64-TO-32-SYSROOT: "-L[[SYSROOT]]/lib/../lib32"
// CHECK-64-TO-32-SYSROOT: "-L[[SYSROOT]]/usr/lib/../lib32"
// CHECK-64-TO-32-SYSROOT: "-L{{[^"]*}}/Inputs/multilib_64bit_linux_tree/usr/lib/gcc/x86_64-unknown-linux/4.6.0"
// CHECK-64-TO-32-SYSROOT: "-L[[SYSROOT]]/lib"
// CHECK-64-TO-32-SYSROOT: "-L[[SYSROOT]]/usr/lib"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-unknown-linux -m32 \
// RUN:     -ccc-install-dir %S/Inputs/fake_install_tree/bin \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-INSTALL-DIR-32 %s
// CHECK-INSTALL-DIR-32: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-INSTALL-DIR-32: "{{.*}}/Inputs/fake_install_tree/bin/../lib/gcc/i386-unknown-linux/4.7.0/crtbegin.o"
// CHECK-INSTALL-DIR-32: "-L{{.*}}/Inputs/fake_install_tree/bin/../lib/gcc/i386-unknown-linux/4.7.0"
//
// Check that with 64-bit builds, we don't actually use the install directory
// as its version of GCC is lower than our sysrooted version.
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=x86_64-unknown-linux -m64 \
// RUN:     -ccc-install-dir %S/Inputs/fake_install_tree/bin \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-INSTALL-DIR-64 %s
// CHECK-INSTALL-DIR-64: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-INSTALL-DIR-64: "{{.*}}/usr/lib/gcc/x86_64-unknown-linux/4.6.0/crtbegin.o"
// CHECK-INSTALL-DIR-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-unknown-linux/4.6.0"
//
// Check that we support unusual patch version formats, including missing that
// component.
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-unknown-linux -m32 \
// RUN:     -ccc-install-dir %S/Inputs/gcc_version_parsing1/bin \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-GCC-VERSION1 %s
// CHECK-GCC-VERSION1: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-GCC-VERSION1: "{{.*}}/Inputs/gcc_version_parsing1/bin/../lib/gcc/i386-unknown-linux/4.7/crtbegin.o"
// CHECK-GCC-VERSION1: "-L{{.*}}/Inputs/gcc_version_parsing1/bin/../lib/gcc/i386-unknown-linux/4.7"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-unknown-linux -m32 \
// RUN:     -ccc-install-dir %S/Inputs/gcc_version_parsing2/bin \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-GCC-VERSION2 %s
// CHECK-GCC-VERSION2: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-GCC-VERSION2: "{{.*}}/Inputs/gcc_version_parsing2/bin/../lib/gcc/i386-unknown-linux/4.7.x/crtbegin.o"
// CHECK-GCC-VERSION2: "-L{{.*}}/Inputs/gcc_version_parsing2/bin/../lib/gcc/i386-unknown-linux/4.7.x"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-unknown-linux -m32 \
// RUN:     -ccc-install-dir %S/Inputs/gcc_version_parsing3/bin \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-GCC-VERSION3 %s
// CHECK-GCC-VERSION3: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-GCC-VERSION3: "{{.*}}/Inputs/gcc_version_parsing3/bin/../lib/gcc/i386-unknown-linux/4.7.99-rc5/crtbegin.o"
// CHECK-GCC-VERSION3: "-L{{.*}}/Inputs/gcc_version_parsing3/bin/../lib/gcc/i386-unknown-linux/4.7.99-rc5"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-unknown-linux -m32 \
// RUN:     -ccc-install-dir %S/Inputs/gcc_version_parsing4/bin \
// RUN:     --sysroot=%S/Inputs/basic_linux_tree \
// RUN:   | FileCheck --check-prefix=CHECK-GCC-VERSION4 %s
// CHECK-GCC-VERSION4: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-GCC-VERSION4: "{{.*}}/Inputs/gcc_version_parsing4/bin/../lib/gcc/i386-unknown-linux/4.7.99/crtbegin.o"
// CHECK-GCC-VERSION4: "-L{{.*}}/Inputs/gcc_version_parsing4/bin/../lib/gcc/i386-unknown-linux/4.7.99"
//
// Test a very broken version of multiarch that shipped in Ubuntu 11.04.
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-unknown-linux \
// RUN:     --sysroot=%S/Inputs/ubuntu_11.04_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-UBUNTU-11-04 %s
// CHECK-UBUNTU-11-04: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-UBUNTU-11-04: "{{.*}}/usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5/crtbegin.o"
// CHECK-UBUNTU-11-04: "-L[[SYSROOT]]/usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5"
// CHECK-UBUNTU-11-04: "-L[[SYSROOT]]/usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5/../../../../i386-linux-gnu"
// CHECK-UBUNTU-11-04: "-L[[SYSROOT]]/usr/lib/i386-linux-gnu"
// CHECK-UBUNTU-11-04: "-L[[SYSROOT]]/usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5/../../../.."
// CHECK-UBUNTU-11-04: "-L[[SYSROOT]]/lib"
// CHECK-UBUNTU-11-04: "-L[[SYSROOT]]/usr/lib"
//
// Check multi arch support on Ubuntu 12.04 LTS.
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-unknown-linux-gnueabihf \
// RUN:     --sysroot=%S/Inputs/ubuntu_12.04_LTS_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-UBUNTU-12-04-ARM-HF %s
// CHECK-UBUNTU-12-04-ARM-HF: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-UBUNTU-12-04-ARM-HF: "{{.*}}/usr/lib/gcc/arm-linux-gnueabihf/4.6.3/../../../arm-linux-gnueabihf/crt1.o"
// CHECK-UBUNTU-12-04-ARM-HF: "{{.*}}/usr/lib/gcc/arm-linux-gnueabihf/4.6.3/../../../arm-linux-gnueabihf/crti.o"
// CHECK-UBUNTU-12-04-ARM-HF: "{{.*}}/usr/lib/gcc/arm-linux-gnueabihf/4.6.3/crtbegin.o"
// CHECK-UBUNTU-12-04-ARM-HF: "-L[[SYSROOT]]/usr/lib/gcc/arm-linux-gnueabihf/4.6.3"
// CHECK-UBUNTU-12-04-ARM-HF: "-L[[SYSROOT]]/usr/lib/gcc/arm-linux-gnueabihf/4.6.3/../../../arm-linux-gnueabihf"
// CHECK-UBUNTU-12-04-ARM-HF: "-L[[SYSROOT]]/lib/arm-linux-gnueabihf"
// CHECK-UBUNTU-12-04-ARM-HF: "-L[[SYSROOT]]/usr/lib/arm-linux-gnueabihf"
// CHECK-UBUNTU-12-04-ARM-HF: "-L[[SYSROOT]]/usr/lib/gcc/arm-linux-gnueabihf/4.6.3/../../.."
// CHECK-UBUNTU-12-04-ARM-HF: "{{.*}}/usr/lib/gcc/arm-linux-gnueabihf/4.6.3/crtend.o"
// CHECK-UBUNTU-12-04-ARM-HF: "{{.*}}/usr/lib/gcc/arm-linux-gnueabihf/4.6.3/../../../arm-linux-gnueabihf/crtn.o"
//
// Check fedora 18 on arm.
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=armv7-unknown-linux-gnueabihf \
// RUN:     --sysroot=%S/Inputs/fedora_18_tree \
// RUN:   | FileCheck --check-prefix=CHECK-FEDORA-18-ARM-HF %s
// CHECK-FEDORA-18-ARM-HF: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-FEDORA-18-ARM-HF: "{{.*}}/usr/lib/gcc/armv7hl-redhat-linux-gnueabi/4.7.2/../../../crt1.o"
// CHECK-FEDORA-18-ARM-HF: "{{.*}}/usr/lib/gcc/armv7hl-redhat-linux-gnueabi/4.7.2/../../../crti.o"
// CHECK-FEDORA-18-ARM-HF: "{{.*}}/usr/lib/gcc/armv7hl-redhat-linux-gnueabi/4.7.2/crtbegin.o"
// CHECK-FEDORA-18-ARM-HF: "-L[[SYSROOT]]/usr/lib/gcc/armv7hl-redhat-linux-gnueabi/4.7.2"
// CHECK-FEDORA-18-ARM-HF: "-L[[SYSROOT]]/usr/lib/gcc/armv7hl-redhat-linux-gnueabi/4.7.2/../../.."
// CHECK-FEDORA-18-ARM-HF: "-L[[SYSROOT]]/lib"
// CHECK-FEDORA-18-ARM-HF: "-L[[SYSROOT]]/usr/lib"
// CHECK-FEDORA-18-ARM-HF: "{{.*}}/usr/lib/gcc/armv7hl-redhat-linux-gnueabi/4.7.2/crtend.o"
// CHECK-FEDORA-18-ARM-HF: "{{.*}}/usr/lib/gcc/armv7hl-redhat-linux-gnueabi/4.7.2/../../../crtn.o"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-unknown-linux-gnueabi \
// RUN:     --sysroot=%S/Inputs/ubuntu_12.04_LTS_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-UBUNTU-12-04-ARM %s
// CHECK-UBUNTU-12-04-ARM: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-UBUNTU-12-04-ARM: "{{.*}}/usr/lib/gcc/arm-linux-gnueabi/4.6.1/../../../arm-linux-gnueabi/crt1.o"
// CHECK-UBUNTU-12-04-ARM: "{{.*}}/usr/lib/gcc/arm-linux-gnueabi/4.6.1/../../../arm-linux-gnueabi/crti.o"
// CHECK-UBUNTU-12-04-ARM: "{{.*}}/usr/lib/gcc/arm-linux-gnueabi/4.6.1/crtbegin.o"
// CHECK-UBUNTU-12-04-ARM: "-L[[SYSROOT]]/usr/lib/gcc/arm-linux-gnueabi/4.6.1"
// CHECK-UBUNTU-12-04-ARM: "-L[[SYSROOT]]/usr/lib/gcc/arm-linux-gnueabi/4.6.1/../../../arm-linux-gnueabi"
// CHECK-UBUNTU-12-04-ARM: "-L[[SYSROOT]]/lib/arm-linux-gnueabi"
// CHECK-UBUNTU-12-04-ARM: "-L[[SYSROOT]]/usr/lib/arm-linux-gnueabi"
// CHECK-UBUNTU-12-04-ARM: "-L[[SYSROOT]]/usr/lib/gcc/arm-linux-gnueabi/4.6.1/../../.."
// CHECK-UBUNTU-12-04-ARM: "{{.*}}/usr/lib/gcc/arm-linux-gnueabi/4.6.1/crtend.o"
// CHECK-UBUNTU-12-04-ARM: "{{.*}}/usr/lib/gcc/arm-linux-gnueabi/4.6.1/../../../arm-linux-gnueabi/crtn.o"
//
// Test the setup that shipped in SUSE 10.3 on ppc64.
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=powerpc64-suse-linux \
// RUN:     --sysroot=%S/Inputs/suse_10.3_ppc64_tree \
// RUN:   | FileCheck --check-prefix=CHECK-SUSE-10-3-PPC64 %s
// CHECK-SUSE-10-3-PPC64: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-SUSE-10-3-PPC64: "{{.*}}/usr/lib/gcc/powerpc64-suse-linux/4.1.2/64/crtbegin.o"
// CHECK-SUSE-10-3-PPC64: "-L[[SYSROOT]]/usr/lib/gcc/powerpc64-suse-linux/4.1.2/64"
// CHECK-SUSE-10-3-PPC64: "-L[[SYSROOT]]/usr/lib/gcc/powerpc64-suse-linux/4.1.2/../../../../lib64"
// CHECK-SUSE-10-3-PPC64: "-L[[SYSROOT]]/lib/../lib64"
// CHECK-SUSE-10-3-PPC64: "-L[[SYSROOT]]/usr/lib/../lib64"
//
// Check dynamic-linker for different archs
// RUN: %clang %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-linux-gnueabi \
// RUN:   | FileCheck --check-prefix=CHECK-ARM %s
// CHECK-ARM: "{{.*}}ld{{(.exe)?}}"
// CHECK-ARM: "-m" "armelf_linux_eabi"
// CHECK-ARM: "-dynamic-linker" "{{.*}}/lib/ld-linux.so.3"
//
// RUN: %clang %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-linux-gnueabihf \
// RUN:   | FileCheck --check-prefix=CHECK-ARM-HF %s
// CHECK-ARM-HF: "{{.*}}ld{{(.exe)?}}"
// CHECK-ARM-HF: "-m" "armelf_linux_eabi"
// CHECK-ARM-HF: "-dynamic-linker" "{{.*}}/lib/ld-linux-armhf.so.3"
//
// Check that we do not pass --hash-style=gnu and --hash-style=both to linker
// and provide correct path to the dynamic linker and emulation mode when build
// for MIPS platforms.
// RUN: %clang %s -### -o %t.o 2>&1 \
// RUN:     --target=mips-linux-gnu \
// RUN:   | FileCheck --check-prefix=CHECK-MIPS %s
// CHECK-MIPS: "{{.*}}ld{{(.exe)?}}"
// CHECK-MIPS: "-m" "elf32btsmip"
// CHECK-MIPS: "-dynamic-linker" "{{.*}}/lib/ld.so.1"
// CHECK-MIPS-NOT: "--hash-style={{gnu|both}}"
// RUN: %clang %s -### -o %t.o 2>&1 \
// RUN:     --target=mipsel-linux-gnu \
// RUN:   | FileCheck --check-prefix=CHECK-MIPSEL %s
// CHECK-MIPSEL: "{{.*}}ld{{(.exe)?}}"
// CHECK-MIPSEL: "-m" "elf32ltsmip"
// CHECK-MIPSEL: "-dynamic-linker" "{{.*}}/lib/ld.so.1"
// CHECK-MIPSEL-NOT: "--hash-style={{gnu|both}}"
// RUN: %clang %s -### -o %t.o 2>&1 \
// RUN:     --target=mips64-linux-gnu \
// RUN:   | FileCheck --check-prefix=CHECK-MIPS64 %s
// CHECK-MIPS64: "{{.*}}ld{{(.exe)?}}"
// CHECK-MIPS64: "-m" "elf64btsmip"
// CHECK-MIPS64: "-dynamic-linker" "{{.*}}/lib64/ld.so.1"
// CHECK-MIPS64-NOT: "--hash-style={{gnu|both}}"
// RUN: %clang %s -### -o %t.o 2>&1 \
// RUN:     --target=mips64el-linux-gnu \
// RUN:   | FileCheck --check-prefix=CHECK-MIPS64EL %s
// CHECK-MIPS64EL: "{{.*}}ld{{(.exe)?}}"
// CHECK-MIPS64EL: "-m" "elf64ltsmip"
// CHECK-MIPS64EL: "-dynamic-linker" "{{.*}}/lib64/ld.so.1"
// CHECK-MIPS64EL-NOT: "--hash-style={{gnu|both}}"
// RUN: %clang %s -### -o %t.o 2>&1 \
// RUN:     --target=mips64-linux-gnu -mabi=n32 \
// RUN:   | FileCheck --check-prefix=CHECK-MIPS64-N32 %s
// CHECK-MIPS64-N32: "{{.*}}ld{{(.exe)?}}"
// CHECK-MIPS64-N32: "-m" "elf32btsmipn32"
// CHECK-MIPS64-N32: "-dynamic-linker" "{{.*}}/lib32/ld.so.1"
// CHECK-MIPS64-N32-NOT: "--hash-style={{gnu|both}}"
// RUN: %clang %s -### -o %t.o 2>&1 \
// RUN:     --target=mips64el-linux-gnu -mabi=n32 \
// RUN:   | FileCheck --check-prefix=CHECK-MIPS64EL-N32 %s
// CHECK-MIPS64EL-N32: "{{.*}}ld{{(.exe)?}}"
// CHECK-MIPS64EL-N32: "-m" "elf32ltsmipn32"
// CHECK-MIPS64EL-N32: "-dynamic-linker" "{{.*}}/lib32/ld.so.1"
// CHECK-MIPS64EL-N32-NOT: "--hash-style={{gnu|both}}"
//
// Thoroughly exercise the Debian multiarch environment.
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i686-linux-gnu \
// RUN:     --sysroot=%S/Inputs/debian_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-X86 %s
// CHECK-DEBIAN-X86: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-X86: "{{.*}}/usr/lib/gcc/i686-linux-gnu/4.5/crtbegin.o"
// CHECK-DEBIAN-X86: "-L[[SYSROOT]]/usr/lib/gcc/i686-linux-gnu/4.5"
// CHECK-DEBIAN-X86: "-L[[SYSROOT]]/usr/lib/gcc/i686-linux-gnu/4.5/../../../i386-linux-gnu"
// CHECK-DEBIAN-X86: "-L[[SYSROOT]]/usr/lib/i386-linux-gnu"
// CHECK-DEBIAN-X86: "-L[[SYSROOT]]/usr/lib/gcc/i686-linux-gnu/4.5/../../.."
// CHECK-DEBIAN-X86: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-X86: "-L[[SYSROOT]]/usr/lib"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=x86_64-linux-gnu \
// RUN:     --sysroot=%S/Inputs/debian_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-X86-64 %s
// CHECK-DEBIAN-X86-64: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-X86-64: "{{.*}}/usr/lib/gcc/x86_64-linux-gnu/4.5/crtbegin.o"
// CHECK-DEBIAN-X86-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-linux-gnu/4.5"
// CHECK-DEBIAN-X86-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-linux-gnu/4.5/../../../x86_64-linux-gnu"
// CHECK-DEBIAN-X86-64: "-L[[SYSROOT]]/usr/lib/x86_64-linux-gnu"
// CHECK-DEBIAN-X86-64: "-L[[SYSROOT]]/usr/lib/gcc/x86_64-linux-gnu/4.5/../../.."
// CHECK-DEBIAN-X86-64: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-X86-64: "-L[[SYSROOT]]/usr/lib"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=powerpc-linux-gnu \
// RUN:     --sysroot=%S/Inputs/debian_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-PPC %s
// CHECK-DEBIAN-PPC: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-PPC: "{{.*}}/usr/lib/gcc/powerpc-linux-gnu/4.5/crtbegin.o"
// CHECK-DEBIAN-PPC: "-L[[SYSROOT]]/usr/lib/gcc/powerpc-linux-gnu/4.5"
// CHECK-DEBIAN-PPC: "-L[[SYSROOT]]/usr/lib/gcc/powerpc-linux-gnu/4.5/../../../powerpc-linux-gnu"
// CHECK-DEBIAN-PPC: "-L[[SYSROOT]]/usr/lib/powerpc-linux-gnu"
// CHECK-DEBIAN-PPC: "-L[[SYSROOT]]/usr/lib/gcc/powerpc-linux-gnu/4.5/../../.."
// CHECK-DEBIAN-PPC: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-PPC: "-L[[SYSROOT]]/usr/lib"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=powerpc64-linux-gnu \
// RUN:     --sysroot=%S/Inputs/debian_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-PPC64 %s
// CHECK-DEBIAN-PPC64: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-PPC64: "{{.*}}/usr/lib/gcc/powerpc64-linux-gnu/4.5/crtbegin.o"
// CHECK-DEBIAN-PPC64: "-L[[SYSROOT]]/usr/lib/gcc/powerpc64-linux-gnu/4.5"
// CHECK-DEBIAN-PPC64: "-L[[SYSROOT]]/usr/lib/gcc/powerpc64-linux-gnu/4.5/../../../powerpc64-linux-gnu"
// CHECK-DEBIAN-PPC64: "-L[[SYSROOT]]/usr/lib/powerpc64-linux-gnu"
// CHECK-DEBIAN-PPC64: "-L[[SYSROOT]]/usr/lib/gcc/powerpc64-linux-gnu/4.5/../../.."
// CHECK-DEBIAN-PPC64: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-PPC64: "-L[[SYSROOT]]/usr/lib"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mips-linux-gnu \
// RUN:     --sysroot=%S/Inputs/debian_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-MIPS %s
// CHECK-DEBIAN-MIPS: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-MIPS: "{{.*}}/usr/lib/gcc/mips-linux-gnu/4.5/crtbegin.o"
// CHECK-DEBIAN-MIPS: "-L[[SYSROOT]]/usr/lib/gcc/mips-linux-gnu/4.5"
// CHECK-DEBIAN-MIPS: "-L[[SYSROOT]]/usr/lib/gcc/mips-linux-gnu/4.5/../../../mips-linux-gnu"
// CHECK-DEBIAN-MIPS: "-L[[SYSROOT]]/usr/lib/mips-linux-gnu"
// CHECK-DEBIAN-MIPS: "-L[[SYSROOT]]/usr/lib/gcc/mips-linux-gnu/4.5/../../.."
// CHECK-DEBIAN-MIPS: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-MIPS: "-L[[SYSROOT]]/usr/lib"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mipsel-linux-gnu \
// RUN:     --sysroot=%S/Inputs/debian_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-MIPSEL %s
// CHECK-DEBIAN-MIPSEL: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-MIPSEL: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.5/crtbegin.o"
// CHECK-DEBIAN-MIPSEL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.5"
// CHECK-DEBIAN-MIPSEL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.5/../../../mipsel-linux-gnu"
// CHECK-DEBIAN-MIPSEL: "-L[[SYSROOT]]/usr/lib/mipsel-linux-gnu"
// CHECK-DEBIAN-MIPSEL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.5/../../.."
// CHECK-DEBIAN-MIPSEL: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-MIPSEL: "-L[[SYSROOT]]/usr/lib"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mips64-linux-gnu \
// RUN:     --sysroot=%S/Inputs/debian_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-MIPS64 %s
// CHECK-DEBIAN-MIPS64: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-MIPS64: "{{.*}}/usr/lib/gcc/mips-linux-gnu/4.5/64/crtbegin.o"
// CHECK-DEBIAN-MIPS64: "-L[[SYSROOT]]/usr/lib/gcc/mips-linux-gnu/4.5/64"
// CHECK-DEBIAN-MIPS64: "-L[[SYSROOT]]/usr/lib/gcc/mips-linux-gnu/4.5"
// CHECK-DEBIAN-MIPS64: "-L[[SYSROOT]]/usr/lib/gcc/mips-linux-gnu/4.5/../../.."
// CHECK-DEBIAN-MIPS64: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-MIPS64: "-L[[SYSROOT]]/usr/lib"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mips64el-linux-gnu \
// RUN:     --sysroot=%S/Inputs/debian_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-MIPS64EL %s
// CHECK-DEBIAN-MIPS64EL: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-MIPS64EL: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.5/64/crtbegin.o"
// CHECK-DEBIAN-MIPS64EL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.5/64"
// CHECK-DEBIAN-MIPS64EL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.5"
// CHECK-DEBIAN-MIPS64EL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.5/../../.."
// CHECK-DEBIAN-MIPS64EL: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-MIPS64EL: "-L[[SYSROOT]]/usr/lib"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mips64-linux-gnu -mabi=n32 \
// RUN:     --sysroot=%S/Inputs/debian_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-MIPS64-N32 %s
// CHECK-DEBIAN-MIPS64-N32: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-MIPS64-N32: "{{.*}}/usr/lib/gcc/mips-linux-gnu/4.5/n32/crtbegin.o"
// CHECK-DEBIAN-MIPS64-N32: "-L[[SYSROOT]]/usr/lib/gcc/mips-linux-gnu/4.5/n32"
// CHECK-DEBIAN-MIPS64-N32: "-L[[SYSROOT]]/usr/lib/gcc/mips-linux-gnu/4.5"
// CHECK-DEBIAN-MIPS64-N32: "-L[[SYSROOT]]/usr/lib/gcc/mips-linux-gnu/4.5/../../.."
// CHECK-DEBIAN-MIPS64-N32: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-MIPS64-N32: "-L[[SYSROOT]]/usr/lib"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mips64el-linux-gnu -mabi=n32 \
// RUN:     --sysroot=%S/Inputs/debian_multiarch_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-MIPS64EL-N32 %s
// CHECK-DEBIAN-MIPS64EL-N32: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-MIPS64EL-N32: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.5/n32/crtbegin.o"
// CHECK-DEBIAN-MIPS64EL-N32: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.5/n32"
// CHECK-DEBIAN-MIPS64EL-N32: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.5"
// CHECK-DEBIAN-MIPS64EL-N32: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.5/../../.."
// CHECK-DEBIAN-MIPS64EL-N32: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-MIPS64EL-N32: "-L[[SYSROOT]]/usr/lib"
//
// Test linker invocation on Android.
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-linux-androideabi \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mipsel-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID %s
// CHECK-ANDROID: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-ANDROID: "{{.*}}/crtbegin_dynamic.o"
// CHECK-ANDROID: "-L[[SYSROOT]]/usr/lib"
// CHECK-ANDROID-NOT: "gcc_s"
// CHECK-ANDROID: "-lgcc"
// CHECK-ANDROID: "-ldl"
// CHECK-ANDROID-NOT: "gcc_s"
// CHECK-ANDROID: "{{.*}}/crtend_android.o"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-linux-androideabi \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -shared \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-SO %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -shared \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-SO %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mipsel-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -shared \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-SO %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -shared \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-SO %s
// CHECK-ANDROID-SO: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-ANDROID-SO: "-Bsymbolic"
// CHECK-ANDROID-SO: "{{.*}}/crtbegin_so.o"
// CHECK-ANDROID-SO: "-L[[SYSROOT]]/usr/lib"
// CHECK-ANDROID-SO-NOT: "gcc_s"
// CHECK-ANDROID-SO: "-lgcc"
// CHECK-ANDROID-SO: "-ldl"
// CHECK-ANDROID-SO-NOT: "gcc_s"
// CHECK-ANDROID-SO: "{{.*}}/crtend_so.o"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-linux-androideabi \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -static \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-STATIC %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -static \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-STATIC %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mipsel-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -static \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-STATIC %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -static \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-STATIC %s
// CHECK-ANDROID-STATIC: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-ANDROID-STATIC: "{{.*}}/crtbegin_static.o"
// CHECK-ANDROID-STATIC: "-L[[SYSROOT]]/usr/lib"
// CHECK-ANDROID-STATIC-NOT: "gcc_s"
// CHECK-ANDROID-STATIC: "-lgcc"
// CHECK-ANDROID-STATIC-NOT: "-ldl"
// CHECK-ANDROID-STATIC-NOT: "gcc_s"
// CHECK-ANDROID-STATIC: "{{.*}}/crtend_android.o"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-linux-androideabi \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot  \
// RUN:     -pie \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-PIE %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=arm-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -pie \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-PIE %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mipsel-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -pie \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-PIE %s
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=i386-linux-android \
// RUN:     --sysroot=%S/Inputs/basic_android_tree/sysroot \
// RUN:     -pie \
// RUN:   | FileCheck --check-prefix=CHECK-ANDROID-PIE %s
// CHECK-ANDROID-PIE: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-ANDROID-PIE: "{{.*}}/crtbegin_dynamic.o"
// CHECK-ANDROID-PIE: "-L[[SYSROOT]]/usr/lib"
// CHECK-ANDROID-PIE-NOT: "gcc_s"
// CHECK-ANDROID-PIE: "-lgcc"
// CHECK-ANDROID-PIE-NOT: "gcc_s"
// CHECK-ANDROID-PIE: "{{.*}}/crtend_android.o"
//
// Check linker invocation on Debian 6 MIPS 32/64-bit.
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mipsel-linux-gnu \
// RUN:     --sysroot=%S/Inputs/debian_6_mips_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-ML-MIPSEL %s
// CHECK-DEBIAN-ML-MIPSEL: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-ML-MIPSEL: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.4/../../../../lib/crt1.o"
// CHECK-DEBIAN-ML-MIPSEL: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.4/../../../../lib/crti.o"
// CHECK-DEBIAN-ML-MIPSEL: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.4/crtbegin.o"
// CHECK-DEBIAN-ML-MIPSEL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.4"
// CHECK-DEBIAN-ML-MIPSEL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.4/../../../../lib"
// CHECK-DEBIAN-ML-MIPSEL: "-L[[SYSROOT]]/lib/../lib"
// CHECK-DEBIAN-ML-MIPSEL: "-L[[SYSROOT]]/usr/lib/../lib"
// CHECK-DEBIAN-ML-MIPSEL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.4/../../.."
// CHECK-DEBIAN-ML-MIPSEL: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-ML-MIPSEL: "-L[[SYSROOT]]/usr/lib"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mips64el-linux-gnu \
// RUN:     --sysroot=%S/Inputs/debian_6_mips_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-ML-MIPS64EL %s
// CHECK-DEBIAN-ML-MIPS64EL: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-ML-MIPS64EL: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.4/../../../../lib64/crt1.o"
// CHECK-DEBIAN-ML-MIPS64EL: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.4/../../../../lib64/crti.o"
// CHECK-DEBIAN-ML-MIPS64EL: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.4/64/crtbegin.o"
// CHECK-DEBIAN-ML-MIPS64EL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.4/64"
// CHECK-DEBIAN-ML-MIPS64EL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.4/../../../../lib64"
// CHECK-DEBIAN-ML-MIPS64EL: "-L[[SYSROOT]]/lib/../lib64"
// CHECK-DEBIAN-ML-MIPS64EL: "-L[[SYSROOT]]/usr/lib/../lib64"
// CHECK-DEBIAN-ML-MIPS64EL: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.4/../../.."
// CHECK-DEBIAN-ML-MIPS64EL: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-ML-MIPS64EL: "-L[[SYSROOT]]/usr/lib"
//
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=mips64el-linux-gnu -mabi=n32 \
// RUN:     --sysroot=%S/Inputs/debian_6_mips_tree \
// RUN:   | FileCheck --check-prefix=CHECK-DEBIAN-ML-MIPS64EL-N32 %s
// CHECK-DEBIAN-ML-MIPS64EL-N32: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-DEBIAN-ML-MIPS64EL-N32: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.4/../../../../lib32/crt1.o"
// CHECK-DEBIAN-ML-MIPS64EL-N32: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.4/../../../../lib32/crti.o"
// CHECK-DEBIAN-ML-MIPS64EL-N32: "{{.*}}/usr/lib/gcc/mipsel-linux-gnu/4.4/n32/crtbegin.o"
// CHECK-DEBIAN-ML-MIPS64EL-N32: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.4/n32"
// CHECK-DEBIAN-ML-MIPS64EL-N32: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.4/../../../../lib32"
// CHECK-DEBIAN-ML-MIPS64EL-N32: "-L[[SYSROOT]]/lib/../lib32"
// CHECK-DEBIAN-ML-MIPS64EL-N32: "-L[[SYSROOT]]/usr/lib/../lib32"
// CHECK-DEBIAN-ML-MIPS64EL-N32: "-L[[SYSROOT]]/usr/lib/gcc/mipsel-linux-gnu/4.4/../../.."
// CHECK-DEBIAN-ML-MIPS64EL-N32: "-L[[SYSROOT]]/lib"
// CHECK-DEBIAN-ML-MIPS64EL-N32: "-L[[SYSROOT]]/usr/lib"
//
// Test linker invocation for Freescale SDK (OpenEmbedded).
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=powerpc-fsl-linux \
// RUN:     --sysroot=%S/Inputs/freescale_ppc_tree \
// RUN:   | FileCheck --check-prefix=CHECK-FSL-PPC %s
// CHECK-FSL-PPC: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-FSL-PPC: "-m" "elf32ppclinux"
// CHECK-FSL-PPC: "{{.*}}/crt1.o"
// CHECK-FSL-PPC: "{{.*}}/crtbegin.o"
// CHECK-FSL-PPC: "-L[[SYSROOT]]/usr/lib"
// RUN: %clang -no-canonical-prefixes %s -### -o %t.o 2>&1 \
// RUN:     --target=powerpc64-fsl-linux \
// RUN:     --sysroot=%S/Inputs/freescale_ppc64_tree \
// RUN:   | FileCheck --check-prefix=CHECK-FSL-PPC64 %s
// CHECK-FSL-PPC64: "{{.*}}ld{{(.exe)?}}" "--sysroot=[[SYSROOT:[^"]+]]"
// CHECK-FSL-PPC64: "-m" "elf64ppc"
// CHECK-FSL-PPC64: "{{.*}}/crt1.o"
// CHECK-FSL-PPC64: "{{.*}}/crtbegin.o"
// CHECK-FSL-PPC64: "-L[[SYSROOT]]/usr/lib64/powerpc64-fsl-linux/4.6.2/../.."
//
// Check that crtfastmath.o is linked with -ffast-math.
// RUN: %clang --target=x86_64-unknown-linux -### %s \
// RUN:        --sysroot=%S/Inputs/basic_linux_tree 2>&1 \
// RUN:   | FileCheck --check-prefix=CHECK-NOCRTFASTMATH %s
// RUN: %clang --target=x86_64-unknown-linux -### %s -ffast-math \
// RUN:        --sysroot=%S/Inputs/basic_linux_tree 2>&1 \
// RUN:   | FileCheck --check-prefix=CHECK-CRTFASTMATH %s
// RUN: %clang --target=x86_64-unknown-linux -### %s -funsafe-math-optimizations\
// RUN:        --sysroot=%S/Inputs/basic_linux_tree 2>&1 \
// RUN:   | FileCheck --check-prefix=CHECK-CRTFASTMATH %s
// RUN: %clang --target=x86_64-unknown-linux -### %s -ffast-math -fno-fast-math \
// RUN:        --sysroot=%S/Inputs/basic_linux_tree 2>&1 \
// RUN:   | FileCheck --check-prefix=CHECK-NOCRTFASTMATH %s
// We don't have crtfastmath.o in the i386 tree, use it to check that file
// detection works.
// RUN: %clang --target=i386-unknown-linux -### %s -ffast-math \
// RUN:        --sysroot=%S/Inputs/basic_linux_tree 2>&1 \
// RUN:   | FileCheck --check-prefix=CHECK-NOCRTFASTMATH %s
// CHECK-CRTFASTMATH: usr/lib/gcc/x86_64-unknown-linux/4.6.0/crtfastmath.o
// CHECK-NOCRTFASTMATH-NOT: crtfastmath.o

// Check that we link in gcrt1.o when compiling with -pg
// RUN: %clang -pg --target=x86_64-unknown-linux -### %s \
// RUN:        --sysroot=%S/Inputs/basic_linux_tree 2>& 1 \
// RUN:   | FileCheck --check-prefix=CHECK-PG %s
// CHECK-PG: gcrt1.o
