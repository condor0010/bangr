int main(int argc, char *argv[]) {
  char c = argv[1][0];
  int num = c ^ 48;
  if (num > 5){
    num += 444;
  }
  return num;
}
