#include <stdio.h>
#include <stdlib.h>

int main()
{
	srand(1);
	int i;
	for(i=0; i<10; i++)
	{
		printf("%d, ", rand() % 0x1869F + 1);
	}
	return 0;
}