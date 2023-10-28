#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <stdbool.h>

// can't srand at the beginning of main, so GCC constructor
__attribute__((constructor)) static void __sv_sanitizers_srand()  {
  // getpid to have different seeds for processes created during the same second
  srand(time(NULL) ^ getpid());
}

__thread bool __sv_sanitizers_marsaglia_spare_available = false;
__thread double __sv_sanitizers_marsaglia_spare;

double __sv_sanitizers_marsaglia() {
  if (__sv_sanitizers_marsaglia_spare_available) {
    __sv_sanitizers_marsaglia_spare_available = false;
    return __sv_sanitizers_marsaglia_spare;
  }
  else {
    double x, y, r2;
    do {
      x = 2.0 * (rand() / ((double)RAND_MAX)) - 1.0;
      y = 2.0 * (rand() / ((double)RAND_MAX)) - 1.0;
      r2 = x * x + y * y;
    }
    while (r2 > 1.0 || r2 == 0.0);

    const double mult = sqrt(-2 * log(r2) / r2);
    __sv_sanitizers_marsaglia_spare = x * mult;
    __sv_sanitizers_marsaglia_spare_available = true;
    return y * mult;
  }
}

bool __VERIFIER_nondet_bool() {
  return rand() % 2;
}

char __VERIFIER_nondet_char() {
  return rand() % 256;
}

int __VERIFIER_nondet_int() {
  return __sv_sanitizers_marsaglia() * 10;
}

__int128 __VERIFIER_nondet_int128() {
  return __sv_sanitizers_marsaglia() * 100;
}

float __VERIFIER_nondet_float() {
  return __sv_sanitizers_marsaglia() * 10;
}

double __VERIFIER_nondet_double() {
  return __sv_sanitizers_marsaglia() * 20;
}

// loff_t

long __VERIFIER_nondet_long() {
  return __sv_sanitizers_marsaglia() * 20;
}
