#include <stdio.h>
int s_arr[] = {5,10,15,20};

int main() {
    for (int i=0; i<sizeof(s_arr)/sizeof(s_arr[0]); i++) {
        printf("%d", s_arr[i]);
        s_arr[i] = 0;
    }
    int index;
    scanf("%d", &index);
    int t_arr[] = {4,8,12,16};
    for (int i=index; i<sizeof(t_arr)/sizeof(t_arr[0]); i++) {
        printf("%d", t_arr[i]);
        t_arr[i] = 0;
    }
}
