#include <stdio.h>
#include <stdlib.h>

struct Ex {
    int number0;
    char* string;
    int number1;
};

int main() {
    struct Ex another_struct = {5, malloc(256), 10};
    scanf("%d %s %d", &another_struct.number0, another_struct.string, &another_struct.number1);
    printf("%s\n", another_struct.string);
    struct Ex* ex_ptr = malloc(sizeof(struct Ex));
    char * str_ptr = malloc(256);
    ex_ptr->string = str_ptr;
    scanf("%d %s %d", &ex_ptr->number0, str_ptr, &ex_ptr->number1);
    printf("first number: %d\n", ex_ptr->number0);
    printf("string: %s\n", ex_ptr->string);
    printf("second number: %d\n", ex_ptr->number1);
    printf("variable offset: %d\n", (int*)&ex_ptr[ex_ptr->number0]);
    unsigned long new_int = 0x7fff;
    new_int += another_struct.number0;
    new_int += (unsigned char)new_int;
    printf("%d\n", (unsigned char)new_int);
}
