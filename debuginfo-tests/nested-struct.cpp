// RUN: %clangxx -O0 -g %s -c -o %t.o
// RUN: %test_debuginfo %s %t.o
// Radar 9440721
// If debug info for my_number() is emitted outside function foo's scope
// then a debugger may not be able to handle it. At least one version of
// gdb crashes in such cases.

// DEBUGGER: ptype foo
// CHECK: type = int (void)

int foo() {
  struct Local {
    static int my_number() {
      return 42;
    }
  };

  int i = 0;
  i = Local::my_number();
  return i + 1;
}
