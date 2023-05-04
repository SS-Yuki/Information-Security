import random
import os

def multiplicative_inverse(e, phi):
    '''
    extended Euclid's algorithm for finding the multiplicative inverse 
    '''
    # WRITE YOUR CODE HERE!
    # 拓展欧几里得算法
    def extended_euclid(a, b):
        if b == 0:
            return a, 1, 0
        else:
            # ax+by==a*y1+b*(x1-(a/b)*y1)
            # 上一深度的x等于下一深度的y1, 上一深度的y等于下一深度的x1-(a/b)*y1
            d, x, y = extended_euclid(b, a % b)
            return d, y, x - (a // b) * y

    d, x, _ = extended_euclid(e, phi)
    if d == 1:
        return x % phi
    return None


def key_generation(p, q):
    # WRITE YOUR CODE HERE!
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    d = multiplicative_inverse(e, phi)
    while d is None:
        e = random.randrange(1, phi)
        d = multiplicative_inverse(e, phi)
    return (n, e), (n, d)

'''
PKCS#1(v1.5)中规定, 如果使用PKCS1Padding进行填充, 当RSA的密钥长度是1024b, 则原文数据最多117B。若原数据不满足长度要求, 则需要在加密前进行填充, 填充公式为: 
EB = 00 || BT || PS || 00 || D: 
    EB: 填充后的数据
    D: 原消息数据
    BT: The block type 块类型, 取值为 00 or 01 （私钥运算时）, 取值为 02 （公钥运算时）
    PS: The padding string填充字符串, 长度为 Len(EB) - 3 - Len(D), 最少是 8字节。
    BT=00, PS为00
    BT=01, PS为FF
    BT=02, PS为伪随机生成, 非零
'''
def pkcs1v15_padding(bytes_, size):
    padding_len = size - len(bytes_) - 3
    padding = b""
    while len(padding) < padding_len:
        byte_ = os.urandom(1)
        if byte_ != b'\x00':
            padding += byte_
    return b"\x00\x02" + padding + b"\x00" + bytes_

def pkcs1v15_unpadding(bytes_):
    if bytes_[0:2] != b"\x00\x02":
        raise ValueError("The format is incorrect")
    padding_index = bytes_.find(b"\x00", 2)
    if padding_index == -1:
        raise ValueError("The format is incorrect")
    return bytes_[padding_index+1:]

'''
encrypt: string -> bytes(string -> bytes -> int -> bytes)
decrypt: bytes -> string(bytes -> int -> bytes -> string)
'''

def encrypt(pk, plaintext):
    n, e = pk
    plaintext_ = pkcs1v15_padding(plaintext.encode(), (n.bit_length()+7)//8 - 11)
    m = int.from_bytes(plaintext_, 'big')
    c = pow(m, e, n)
    ciphertext = c.to_bytes((n.bit_length()+7)//8, 'big')
    return ciphertext

def decrypt(sk, ciphertext):
    n, d = sk
    c = int.from_bytes(ciphertext, 'big')
    m = pow(c, d, n)
    plaintext_ = pkcs1v15_unpadding(m.to_bytes((n.bit_length()+7)//8-11, 'big'))
    plaintext = plaintext_.decode()
    return plaintext

text = "helloworld"
print("text: ", text)
p = 319576316814478949870590164193048041239
q = 232684764001698545563067004009755869717
pk, sk = key_generation(p, q)
plaintext = decrypt(sk, encrypt(pk, text))
print("plaintext: ", plaintext)
if text == plaintext:
    print("Test Pass")
