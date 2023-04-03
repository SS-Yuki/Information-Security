# Permutation tables and S-boxes
# 初始置换
IP = (
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
)
# 结尾置换
IP_INV = (
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
)

# 64->56
PC1 = (
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4
)

# 56->48
PC2 = (
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
)

# R的32->48
E  = (
    32, 1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9,  10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
)

# 异或后的结果48->32
Sboxes = {
    0: (
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
        0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
        4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
    ),
    1: (
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
        3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
        0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 
    ),
    2: (
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
        1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 
    ),
    3: (
        7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
        3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
    ),
    4: (
        2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
        4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
    ),
    5: (
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
        9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
        4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
    ),
    6: (
        4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
        1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
        6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
    ),
    7: (
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
        1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
        7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
        2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    )
}

# 从Sboxes输出后进入
P = (
    16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11, 4,  25
)

def permutation_by_table(block, block_len, table):
    '''block of length block_len permutated by table table'''
    # WRITE YOUR CODE HERE!
    permuted_block = 0
    for i, bit_index in enumerate(table):
        bit_index -= 1 
        # 将原块的第 bit_index 位设置为 permuted_block 的第 i 位
        if block & (1 << (block_len - bit_index - 1)):
            permuted_block |= (1 << (len(table) - i - 1))
    return permuted_block

def generate_round_keys(C0, D0):
    '''returns dict of 16 keys (one for each round)'''
    round_keys = dict.fromkeys(range(0,17))
    lrot_values = (1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1)
 
    # left-rotation function
    lrot = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
 
    # initial rotation
    C0 = lrot(C0, 0, 28)
    D0 = lrot(D0, 0, 28)
    round_keys[0] = (C0, D0)
 
    # create 16 more different key pairs
    # WRITE YOUR CODE HERE!
    for i, r_bits in enumerate(lrot_values):
        C0 = lrot(C0, r_bits, 28)
        D0 = lrot(D0, r_bits, 28)
        round_keys[i + 1] = (C0, D0)
 
    # round_keys[1] for first round
    #           [16] for 16th round
    # do not need round_keys[0] anymore, remove
    del round_keys[0]
 
    #form the keys from concatenated CiDi 1<=i<=16 and by apllying PC2
    # WRITE YOUR CODE HERE!
    for i, (Ci, Di) in round_keys.items():
        key = (Ci << 28) | Di
        round_keys[i] = permutation_by_table(key, 56, PC2)
 
    return round_keys

def round_function(Ri, Ki):
    # expand Ri from 32 to 48 bit using table E
    Ri = permutation_by_table(Ri, 32, E)
 
    # xor with round key
    # WRITE YOUR CODE HERE!
    Ri = Ri ^ Ki
 
    # split Ri into 8 groups of 6 bit
    # WRITE YOUR CODE HERE!
    blocks = [Ri >> (6 * i) & 0b111111 for i in range(7, -1, -1)]
 
    # interpret each block as address for the S-boxes
    # WRITE YOUR CODE HERE!
    sbox_blocks = []
    for i, block in enumerate(blocks):
        row = (block >> 4 & 0b10) | (block & 0b1)
        col = block >> 1 & 0b1111
        sbox_blocks.append(Sboxes[i][row * 16 + col])
 
    # pack the blocks together again by concatenating
    # WRITE YOUR CODE HERE!
    Ri = 0
    for i in range(8):
        Ri |= sbox_blocks[i] << (4 * (7 - i))
 
    # another permutation 32bit -> 32bit
    Ri = permutation_by_table(Ri, 32, P)
 
    return Ri

def encrypt(msg, key, decrypt=False):

    # permutate by table PC1
    key = permutation_by_table(key, 64, PC1) # 64bit -> PC1 -> 56bit
 
    # split up key in two halves
    # WRITE YOUR CODE HERE!
    C0 = key >> 28
    D0 = key & 0xFFFFFFF

    # generate the 16 round keys
    round_keys = generate_round_keys(C0, D0) # 56bit -> PC2 -> 48bit
 
    msg_block = permutation_by_table(msg, 64, IP)
    # WRITE YOUR CODE HERE!
    L0 = msg_block >> 32
    R0 = msg_block & 0xFFFFFFFF
 
    # apply round function 16 times (Feistel Network):
    L_last = L0
    R_last = R0
    # WRITE YOUR CODE HERE!
    for i in range(1, 17):
        key_index = 0
        if decrypt:
            key_index = 17 - i
        else:
            key_index = i
        temp = L_last
        L_last = R_last
        R_last = temp ^ round_function(R_last, round_keys[key_index])

    cipher_block = (R_last << 32) | L_last
    # final permutation
    cipher_block = permutation_by_table(cipher_block, 64, IP_INV)
 
    return cipher_block


def decrypt(cipher_text, key):
    plain_text = encrypt(cipher_text, key, decrypt=True)
    print('Plain Text: '+ bytearray.fromhex(hex(plain_text)[2:]).decode())

import binascii
key = int(binascii.hexlify(b'FudanNiu') , 16)
cipher_text_odd = 0x6be808c5976d0452
cipher_text_even = 0x3ca6d517b176768a

# decrypt(cipher_text_odd,key)
decrypt(cipher_text_even,key)