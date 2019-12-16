#include <stdio.h>
#include <stdlib.h>

char tt[30]={0};
int main()
{
	char src[30] = {0}; 
	scanf("%s", src);
	snprintf(tt, 0x100, src);
	puts(tt);
	return 0;
}
