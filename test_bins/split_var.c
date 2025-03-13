#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int data = 0;
    int result = 0;
    if (argc > 2)
        data = 10;
    result = 100/data;
    printf("Result: %d\n", result);
    return 0;
}
