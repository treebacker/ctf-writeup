from Crypto.Cipher import AES
from Crypto import Random
from string import ascii_letters
from random import choice,randint
from pwn import *

def pad(s, block_size):
    return s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)

def gen_user(name,iv):
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    cipher_text = iv + cipher.encrypt(pad(name, AES.block_size))
    return cipher_text.encode("hex")

p = remote('183.129.189.62', 16406)
#ret = 'cbc6b42eeccf475ec83b8e944127732556993e2617236a1dcd7ba2fa361afae8'
ret = p.recvuntil('is ')
ret = ret.decode('utf-8')
name = 'Admin'
iv = ret[16:]
p.send(gen_user(name,iv))