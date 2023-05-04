import gmpy2

'''
RSA Public-Key: (256 bit)
Modulus:
    00:c2:63:6a:e5:c3:d8:e4:3f:fb:97:ab:09:02:8f:
    1a:ac:6c:0b:f6:cd:3d:70:eb:ca:28:1b:ff:e9:7f:
    be:30:dd
Exponent: 65537 (0x10001)
Modulus=C2636AE5C3D8E43FFB97AB09028F1AAC6C0BF6CD3D70EBCA281BFFE97FBE30DD
writing RSA key
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMJjauXD2OQ/+5erCQKPGqxsC/bNPXDr
yigb/+l/vjDdAgMBAAE=
-----END PUBLIC KEY-----


e = 65537
n = 87924348264132406875276140514499937145050893665602592992418171647042491658461
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239

phi_n = 87924348264132406875276140514499937144456189488436765114374296308467862464924
d = 10866948760844599168252082612378495977388271279679231539839049698621994994673

'''

def bytes2num(b):
    s = '0x'
    for x in b:
        tmp = str(hex(x))[2:]
        if len(tmp)==2:
            pass
        else:
            tmp = '0' +tmp
        s += tmp
    num = int(s, 16)
    return num

def num2str(n):
    tmp = str(hex(n))[2:]
    if len(tmp)%2 == 0:
        pass
    else:
        tmp = '0' + tmp

    # PKCS#1 v1.5 padding 填充模式加密
    for i in range(0, len(tmp), 2):
        if tmp[i:i+2] == '00':
            tmp = tmp[i+2:]
            break

    s = ''
    for i in range(0, len(tmp), 2):
        temp = tmp[i] + tmp[i+1]
        s += chr(int(temp, 16))
    return s

e = 65537
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239
n = 87924348264132406875276140514499937145050893665602592992418171647042491658461

phi_n = (p - 1) * (q - 1)
# print(phi_n)
# phi_n = 87924348264132406875276140514499937144456189488436765114374296308467862464924
d = gmpy2.invert(e, phi_n)
# print(d)
# d = 10866948760844599168252082612378495977388271279679231539839049698621994994673

fi = open('secret.enc', 'rb')
cipher = fi.read()
cipher = bytes2num(cipher)
# print(cipher)
# cipher = 84905763485077958193641410886067237517896375906905759069003959545809446517649
fi.close()

plain = pow(cipher, d, n)
# print(plain)
# plain = 4503120026053466109536410913555064581389690482792472008743863915105959690   
plain = num2str(plain)
print(plain)
