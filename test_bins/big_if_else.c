#include <stdio.h>

int func (int choice) {
    int retval;
    if (choice == 0) {
        printf("You entered 0\n");
        retval = 0;
    } else if (choice == 1) {
        printf("You entered 1\n");
        retval = 1;
    } else if (choice == 2) {
        printf("You entered 2\n");
        retval = 2;
    } else if (choice == 3) {
        printf("You entered 3\n");
        retval = 3;
    } else if (choice == 4) {
        printf("You entered 4\n");
        retval = 4;
    } else {
        printf("Actually i dont care\n");
        retval = 5;
    }
    return retval;
}

int main() {
    int choice;
    scanf("%d", &choice);
    func(choice);
}
