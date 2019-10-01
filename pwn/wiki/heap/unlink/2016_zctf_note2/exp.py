one = ['0'] * 26
one[0]='24_21'
one[1]='25_3'
one[2]='26_15'
one[3]='1_1'
one[4]='2_19'
one[5]='3_10'
one[6]='4_14'
one[7]='5_26'
one[8]='6_20'
one[9]='7_8'
one[10]='8_16'
one[11]='9_7'
one[12]='10_22'
one[13]='11_4'
one[14]='12_11'
one[15]='13_5'
one[16]='14_17'
one[17]='15_9'
one[18]='16_12'
one[19]='17_23'
one[20]='18_18'
one[21]='19_2'
one[22]='20_25'
one[23]='21_6'
one[24]='22_24'
one[25]='23_13'

two = ['0'] * 26
two[0]='26_20'
two[1]='1_1'
two[2]='2_6'
two[3]='3_4'
two[4]='4_15'
two[5]='5_3'
two[6]='6_14'
two[7]='7_12'
two[8]='8_23'
two[9]='9_5'
two[10]='10_16'
two[11]='11_2'
two[12]='12_22'
two[13]='13_19'
two[14]='14_11'
two[15]='15_18'
two[16]='16_25'
two[17]='17_24'
two[18]='18_13'
two[19]='19_7'
two[20]='20_10'
two[21]='21_8'
two[22]='22_21'
two[23]='23_9'
two[24]='24_26'
two[25]='25_17'

three = ['0'] * 26
three[0]='1_8'
three[1]='2_18'
three[2]='3_26'
three[3]='4_17'
three[4]='5_20'
three[5]='6_22'
three[6]='7_10'
three[7]='8_3'
three[8]='9_13'
three[9]='10_11'
three[10]='11_4'
three[11]='12_23'
three[12]='13_5'
three[13]='14_24'
three[14]='15_9'
three[15]='16_12'
three[16]='17_25'
three[17]='18_16'
three[18]='19_19'
three[19]='20_6'
three[20]='21_15'
three[21]='22_21'
three[22]='23_2'
three[23]='24_7'
three[24]='25_1'
three[25]='26_14'

##Init work
src1 = one[25]
src2 = two[25]
src3 = three[25]
alphabet = 'abcdefghijklmnopqrstuvwxyz'
compstr = "xvqxcnrankcowyxlre"

def getL(ttstr):
    ans = ttstr.split('_')[0]
    return ans
def getR(ttstr):
    ans = ttstr.split('_')[1]
    return ans

def tran_a_char(inchar):
    idxw = 0
    ans = 0
    idx = alphabet.index(inchar)

    for m in range(0, 26):
        if(getL(one[idx]) == getR(one[m])):
            idxw = m
            break
    for n in range(0, 26):
        if(getL(two[idxw]) == getR(two[n])):
            ans = n
            break
        
    for i in range(0, 26):
        if(getL(three[ans]) == getR(three[i])):
            ans = i
            break
    ans = alphabet[ans]
    return ans

def cycle1():
    tmp = one[25]
    for i in range(24, -1, -1):
        one[i+1] = one[i]
    one[0] = tmp

def cycle2():
    tmp = two[25]
    for i in range(24, -1, -1):
        two[i+1] = two[i]
    two[0] = tmp

def cycle3():
    tmp = three[25]
    for i in range(24, -1, -1):
        three[i+1] = three[i]
    three[0] = tmp 

if __name__ == '__main__':

    flag = ""
    len = len(compstr)
    cnt = 0
    for i, ans in enumerate(compstr):
        for g in alphabet:
                if(ans == tran_a_char(g)):
                    flag += g
                    break
        
        cnt += 1
        cycle3()

        if(cnt%6 == 0):
            cycle2()
        
        if(cnt%36 == 0):
            cycle1()
    print(flag)

