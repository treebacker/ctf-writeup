//gcc str.c -m32 -o str
#include <stdio.h>

int main(void)
{
	int c = 0; 
	printf("%.100d%n", c, &c);
	printf("c = %d\n", c);
	return 0;
}
