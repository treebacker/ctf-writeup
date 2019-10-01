#include <stdio.h>
int main(void)
{
	char buf[10];
	memset(buf, 0, 10);
	buf[0] = '1';
	printf(buf);
	setbuf(stdout, buf);
	printf("test");
	write(1, "\n====\n", 6);
	write(2, buf, 10);
}
