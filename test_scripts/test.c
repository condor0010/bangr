#include <stdio.h>
#include <string.h>

int func(char* buf, int num) {
   int retval = 0;
   if (strcmp(buf, "abc") == 0) {
      if (num == 8) {
         printf("yea that's cool\n");
         retval = num;
      } else {
         printf("not as cool\n");
         retval = num;
      }
   } else {
      printf("%d is not cool at all!\n", num);
      retval = num;
   }
   return retval;
}

int main() {
   char buf[8];
   int num;
   scanf("%s %d", &buf, &num);
   printf("%s %d\n", &buf, num);
   func(buf, num);
   return num;
}
