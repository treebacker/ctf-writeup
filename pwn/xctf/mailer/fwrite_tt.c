#include <stdio.h>

int main(void)
{
	FILE* fd;
	fd = fopen("./tmp", "a");
	fwrite("aaa", 1, 3, fd);
	fwrite("bbb", 1, 3, fd);
	fclose(fd);
}
