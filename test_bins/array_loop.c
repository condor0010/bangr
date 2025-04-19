#include <stdio.h>
int arr[] = {5,10,15,20};

int func(int s_arr[], int pj, int pi) {
    for (int j=pj; j<10; j++) {
        s_arr[0] = s_arr[0]+1;
        for (int i=pi; i<sizeof(*s_arr)/sizeof(s_arr[0]); i++) {
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
}

int main() {
    func(arr, 3, 2);
}
