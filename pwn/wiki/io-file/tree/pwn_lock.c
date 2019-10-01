#include <stdio.h>
char buf[0x100] = {0};
FILE *fd;

int main() {
   fd = fopen("key.txt","rw");
   gets(buf);
   fclose(fd);
}
