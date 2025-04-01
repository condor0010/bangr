int func(int arg1, char* arg2) {
    arg2[3] = arg2[3] + arg1;
    return arg1;
}

int main() {
    char * s = "string";
    int rval = func(1, s);
    return rval;
}
