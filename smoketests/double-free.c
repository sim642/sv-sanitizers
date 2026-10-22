#include <stdlib.h>

void* force_malloc(size_t size) {
    void *p;
    do {
        p = malloc(size);
    } while (p == NULL);
    return p;
}

int main() {
    int *p = force_malloc(sizeof(int));
    free(p);
    free(p);

    while (1) {} // infinite loop to test that halt_on_error works
    return 0;
}
