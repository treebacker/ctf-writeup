def pviot32(offset_ebp, fake_ebp, func, ret, args):
  payload = 'a'*offset
  payload += p32(fake_ebp)
  payload += p32(func)
  payload += p32(ret)
  payload += args


#if ret is leave ret; esp will got to ebp+4
#the func if libc_func will be nice
