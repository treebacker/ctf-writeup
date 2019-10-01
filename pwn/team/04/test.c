#include <stdio.h>
#include <stdlib.h>
int main()
{
	int fd_0 = open("/proc/self/mem", 0);
	printf("fd_0 is %d\n", fd_0);
	int fd_1 = open("proc/self/mem", 2);
	printf("fd_1 is %d\n", fd_1);
	close(fd_0);
	close(fd_1);
return 0;
}
