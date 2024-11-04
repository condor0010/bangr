#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    // Check if a number is provided as a command-line argument
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <number>\n", argv[0]);
        return 1;
    }

    // Convert the command line argument to a long long integer
    long long number = atoll(argv[1]);

    // Check if the number is larger than 72
    if (number > 72) {
        number <<= 2; // Left shift by 2
        printf("Left shifted value: %lld\n", number);
    } 
    // Check if the number is even
    else if (number % 2 == 0) {
        number += 42; // Add 42
        printf("Even number adjusted value: %lld\n", number);
    } 
    // If the number is odd
    else {
        number += 43; // Add 43
        printf("Odd number adjusted value: %lld\n", number);
    }

    return 0;
}

