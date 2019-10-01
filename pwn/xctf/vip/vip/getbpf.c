#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <fcntl.h>

int main(void) {
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(0), SCMP_SYS(open), 1, SCMP_A0(SCMP_CMP_EQ, 0x40207E));
	seccomp_load(ctx);

	int fd = open("bpf.out",O_WRONLY);
	seccomp_export_bpf(ctx, fd);
	close(fd);
	char* filename = "/bin/sh";
	char *argv[] = {"/bin/sh", NULL};
	char *envp[] = {NULL};
	write(1, "i will give you a shell\n", 24);
	syscall(59, filename, argv, envp);	//execve

	return 0;
}