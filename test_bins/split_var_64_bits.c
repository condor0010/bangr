#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

int main(int argc, char **argv) {
    uint64_t data = 0;
    uint64_t result = 0;
    uint64_t dividend = 1;
    dividend = dividend << 33;
    if (argc > 2)
        data = 10;
    result = dividend/data;
    printf("Result: %d\n", result);
    return 0;
}
