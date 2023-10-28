#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <stdbool.h>
#include <pthread.h>

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

#ifdef __SIZEOF_INT128__
__int128 __VERIFIER_nondet_int128() {
  return __sv_sanitizers_marsaglia() * 40;
}
#endif

float __VERIFIER_nondet_float() {
  return __sv_sanitizers_marsaglia() * 10;
}

double __VERIFIER_nondet_double() {
  return __sv_sanitizers_marsaglia() * 20;
}

// TODO: loff_t

long __VERIFIER_nondet_long() {
  return __sv_sanitizers_marsaglia() * 20;
}

long long __VERIFIER_nondet_longlong() {
  return __sv_sanitizers_marsaglia() * 30;
}

// TODO: pchar
// TODO: pthread_t
// TODO: sector_t

short __VERIFIER_nondet_short() {
  return __sv_sanitizers_marsaglia() * 10;
}

size_t __VERIFIER_nondet_size_t() {
  return __sv_sanitizers_marsaglia() * 20;
}

// u32

unsigned char __VERIFIER_nondet_uchar() {
  return rand() % 256;
}

unsigned int __VERIFIER_nondet_uint() {
  return fabs(__sv_sanitizers_marsaglia() * 20);
}

#ifdef __SIZEOF_INT128__
__uint128_t __VERIFIER_nondet_uint128() {
  return fabs(__sv_sanitizers_marsaglia() * 80);
}
#endif

unsigned long __VERIFIER_nondet_ulong() {
  return fabs(__sv_sanitizers_marsaglia() * 40);
}

unsigned long long __VERIFIER_nondet_ulonglong() {
  return fabs(__sv_sanitizers_marsaglia() * 60);
}

unsigned __VERIFIER_nondet_unsigned() {
  return fabs(__sv_sanitizers_marsaglia() * 20);
}

unsigned short __VERIFIER_nondet_ushort() {
  return fabs(__sv_sanitizers_marsaglia() * 20);
}

pthread_mutex_t __sv_sanitizers_atomic = PTHREAD_MUTEX_INITIALIZER;

void __VERIFIER_atomic_begin() {
  pthread_mutex_lock(&__sv_sanitizers_atomic);
}

void __VERIFIER_atomic_end() {
  pthread_mutex_unlock(&__sv_sanitizers_atomic);
}
