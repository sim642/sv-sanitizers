#include <stdlib.h>

int main() {
    int *p = malloc(sizeof(int));
    free(p);
    free(p);

    while (1) {} // infinite loop to test that halt_on_error works
    return 0;
}
