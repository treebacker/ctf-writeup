#include <stdio.h>
int main()
{
	char *msg = "treebacker";
	FILE* fp;
	char *buf = malloc(100);
	read(0, buf, 100);
	fp = fopen("key.txt", "rw");
	fp->_flags &= ~8;
	fp->_flags |= 0x800;
	fp->_IO_write_base = msg;
	fp->_IO_write_ptr = msg+10;
	fp->_IO_read_end = fp->_IO_write_base;
	fp->_fileno = 1;
	fwrite(buf, 1, 100, fp);/*leak msg*/
}