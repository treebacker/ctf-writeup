#include <stdio.h>
#include <time.h>

int main(int argc, int* args[])
{
	if(argc != 5)
	{
		printf("	useage -number0 (seed) -number1(mod base) - number2(want to produce count) -number3(add what)\n");
		printf("random 6 50");
		return 0;
	}
	int i;
	int sed = atoi(args[1]);
	int base = atoi(args[2]);
	int count = atoi(args[3]);
	int add = atoi(args[4]);

	printf("sed: %d, base: %d, count: %d, add: %d\n", sed, base, count, add);
	srand(sed);
	
	for(i=0; i<count; i++)
	{
		printf("%d, ", rand()%base + add);
	}

	return 0;
}
