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
    //int a=2;
    //int *b = &a;
    //*b = 1;


    printf("a: %d, c: %s\n", s->a, s->c);
    // /printf("%d \n", a);
}
