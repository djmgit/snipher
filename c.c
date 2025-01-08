#include <stdio.h>

typedef struct st
{
    char *c;
    int a;
} st_t;

int main() {
    st_t *s;
    s->a = 1;
    s->c = "hello";

    printf("a: %d, c: %s\n", s->a, s->c);
}
