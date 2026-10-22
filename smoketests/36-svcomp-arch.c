// CRAM
#include <limits.h>

int main() {
  long k = INT_MAX;
  long n = k * k;

  while (1) {} // infinite loop to test that halt_on_error works
  return 0;
}
