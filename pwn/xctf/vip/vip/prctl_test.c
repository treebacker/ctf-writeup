#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <linux/filter.h>

int main(void) {

	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	struct sock_filter sft[] = {
		{0x20, 0x00, 0x00, 0x00000004},
		{0x15, 0x00, 0x05, 0xc000003e},
		{0x20, 0x00, 0x00, 0x00000000},
		{0x35, 0x00, 0x01, 0x40000000},
		{0x15, 0x00, 0x02, 0xffffffff},
		{0x15, 0x01, 0x00, 0x0000003b},
		{0x06, 0x00, 0x00, 0x7fff0000},
		{0x06, 0x00, 0x00, 0x00000000}
	};

	struct sock_fprog sfp = {8, sft};
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sfp);
	char* filename = "/bin/sh";
	char *argv[] = {"/bin/sh", NULL};
	char *envp[] = {NULL};
	write(1, "i will give you a shell\n", 24);
	syscall(59, filename, argv, envp);	//execve

	return 0;
}