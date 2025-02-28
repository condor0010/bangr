#include <stdio.h>

int main() {
    int i;
    scanf("%d", &i);
    printf("%p\n", (&i+i));
}
