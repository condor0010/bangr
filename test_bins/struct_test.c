#include <stdio.h>

struct Ex {
    int number0;
    char* string;
    int number1;
};

int main() {
    char str[10];
    int a,b;
    scanf("%d %s %d", &a, &str, &b);
    struct Ex example = {a, str, b};
    printf("first number: %d\n", example.number0);
    printf("string: %s\n", example.string);
    printf("second number: %d\n", example.number1);
}
