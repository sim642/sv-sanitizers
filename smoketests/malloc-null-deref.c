#include <stdlib.h>

int main() {
    int *p = malloc(sizeof(int));
    // p = realloc(p, sizeof(int));
    // int *p = calloc(1, sizeof(int));
    *p = 42;
    free(p);
    return 0;
}
