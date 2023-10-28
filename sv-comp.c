#include <stdlib.h>
#include <time.h>
#include <unistd.h>

// can't srand at the beginning of main, so GCC constructor
__attribute__((constructor)) static void __sv_sanitizers_srand()  {
  // getpid to have different seeds for processes created during the same second
  srand(time(NULL) ^ getpid());
}

int __VERIFIER_nondet_int() {
  return rand() % 10;
}
