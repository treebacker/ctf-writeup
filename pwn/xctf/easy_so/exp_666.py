cmp = 'izwhroz""w"v.K".Ni'




def decode():
	flag = ""
	i = 0
	while(i < 0x12):
		tmp1 = (ord(cmp[i]) ^ 0x12) - 6
		tmp2 = (ord(cmp[i+1])^ 0x12) + 6
		tmp3 = (ord(cmp[i+2]) ^ 0x12) ^ 6

		flag += chr(tmp1) + chr(tmp2) + chr(tmp3)
		i += 3
	return flag

print "legth ==> " + hex(len(cmp))
print decode()