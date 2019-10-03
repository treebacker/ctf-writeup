#include <stdio.h>
int main() {
   char buf[10] = "abcd";
   setbuf(stdout,buf);
   printf("treebacker");
   printf(buf);  
 return 0;
}
