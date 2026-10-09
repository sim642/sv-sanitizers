#include <assert.h>

void reach_error() { assert(0); }

int main() {
    reach_error();
    return 0;
}
