SBOX = [
    0x09, 0x04, 0x0A, 0x0B,
    0x0D, 0x01, 0x08, 0x05,
    0x06, 0x02, 0x00, 0x03,
    0x0C, 0x0E, 0x0F, 0x07
]

INV_SBOX = [
    0x0A, 0x05, 0x09, 0x0B,
    0x01, 0x07, 0x08, 0x0F,
    0x06, 0x00, 0x02, 0x03,
    0x0C, 0x04, 0x0D, 0x0E
]

MIX_COL = [
    [1, 4],
    [4, 1]
]

INV_MIX_COL = [
    [9, 2],
    [2, 9]
]

# Generated using http://www.ee.unb.ca/cgi-bin/tervo/galois3.pl?p=4&C=1&h=1&D=1&A=1
GF_MULT_TABLE = [
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
    [0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x03, 0x01, 0x07, 0x05, 0x0B, 0x09, 0x0F, 0x0D],
    [0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09, 0x0B, 0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02],
    [0x04, 0x08, 0x0C, 0x03, 0x07, 0x0B, 0x0F, 0x06, 0x02, 0x0E, 0x0A, 0x05, 0x01, 0x0D, 0x09],
    [0x05, 0x0A, 0x0F, 0x07, 0x02, 0x0D, 0x08, 0x0E, 0x0B, 0x04, 0x01, 0x09, 0x0C, 0x03, 0x06],
    [0x06, 0x0C, 0x0A, 0x0B, 0x0D, 0x07, 0x01, 0x05, 0x03, 0x09, 0x0F, 0x0E, 0x08, 0x02, 0x04],
    [0x07, 0x0E, 0x09, 0x0F, 0x08, 0x01, 0x06, 0x0D, 0x0A, 0x03, 0x04, 0x02, 0x05, 0x0C, 0x0B],
    [0x08, 0x03, 0x0B, 0x06, 0x0E, 0x05, 0x0D, 0x0C, 0x04, 0x0F, 0x07, 0x0A, 0x02, 0x09, 0x01],
    [0x09, 0x01, 0x08, 0x02, 0x0B, 0x03, 0x0A, 0x04, 0x0D, 0x05, 0x0C, 0x06, 0x0F, 0x07, 0x0E],
    [0x0A, 0x07, 0x0D, 0x0E, 0x04, 0x09, 0x03, 0x0F, 0x05, 0x08, 0x02, 0x01, 0x0B, 0x06, 0x0C],
    [0x0B, 0x05, 0x0E, 0x0A, 0x01, 0x0F, 0x04, 0x07, 0x0C, 0x02, 0x09, 0x0D, 0x06, 0x08, 0x03],
    [0x0C, 0x0B, 0x07, 0x05, 0x09, 0x0E, 0x02, 0x0A, 0x06, 0x01, 0x0D, 0x0F, 0x03, 0x04, 0x08],
    [0x0D, 0x09, 0x04, 0x01, 0x0C, 0x08, 0x05, 0x02, 0x0F, 0x0B, 0x06, 0x03, 0x0E, 0x0A, 0x07],
    [0x0E, 0x0F, 0x01, 0x0D, 0x03, 0x02, 0x0C, 0x09, 0x07, 0x06, 0x08, 0x04, 0x0A, 0x0B, 0x05],
    [0x0F, 0x0D, 0x02, 0x09, 0x06, 0x04, 0x0B, 0x01, 0x0E, 0x0C, 0x03, 0x08, 0x07, 0x05, 0x0A]
]


def to_hex(string):
    return int(("0x" + string), 16)


def rot_word(word):
    word = "0x{:02x}".format(word)
    return word[-1] + word[-2]


def sub_word(word):
    word = hex(word)[2:] if len(hex(word)[2:]) == 2 else "0" + hex(word)[2:]
    sub_word = ""
    for nibble in word:
        sub = SBOX[int(nibble, 16)]
        sub_word += str(sub) if len(str(sub)) == 1 else str(hex(sub))[2:]
    return to_hex(sub_word)


def key_expansion(key):
    keys = [None]*3
    words = [None]*6
    words[0] = ((key >> 12) & 0xF)*0x10 + ((key >> 8) & 0xF)
    words[1] = ((key >> 4) & 0xF)*0x10 + (key & 0xF)
    for i in range(2, 6):
        RCon = 0x80 if i < 4 else 0x30
        if (i % 2 == 0):
            words[i] = (sub_word(to_hex(rot_word(words[i-1])))
                        ^ RCon) ^ words[i-2]
        else:
            words[i] = words[i-1] ^ words[i-2]
    for i in range(3):
        keys[i] = (words[2*i])*0x100 + (words[2*i+1])
    return keys


def add_round_key(state, key):
    key_frags = [(key >> 12) & 0xF, (key >> 8) & 0xF, (key >> 4) & 0xF, key & 0xF]
    state = [state[i] ^ key_frags[i] for i in range(4)]
    return state

def sub_nibbles(state):
    return [SBOX[state[0]], SBOX[state[1]], SBOX[state[2]], SBOX[state[3]]]


def shift_rows(state):
    return [state[0], state[3], state[2], state[1]]

def gf_mult(num1, num2):
    return num1*num2 if num1*num2<16 else GF_MULT_TABLE[num1-1][num2-1]

def mix_columns(state):
    temp_state = [None]*4
    temp_state[0] = gf_mult(MIX_COL[0][0],state[0]) ^ gf_mult(MIX_COL[0][1],state[1])
    temp_state[1] = gf_mult(MIX_COL[1][0],state[0]) ^ gf_mult(MIX_COL[1][1],state[1])
    temp_state[2] = gf_mult(MIX_COL[0][0],state[2]) ^ gf_mult(MIX_COL[0][1],state[3])
    temp_state[3] = gf_mult(MIX_COL[1][0],state[2]) ^ gf_mult(MIX_COL[1][1],state[3])
    return temp_state


def saes_encrypt(block, keys):
    state = [(block >> 12) & 0xF, (block >> 8) &
             0xF, (block >> 4) & 0xF, block & 0xF]
    state = add_round_key(state, keys[0])
    # Round 1
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, keys[1])
    # Round 2
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = add_round_key(state, keys[2])

    return (state[0] << 12) | (state[1] << 8) | (state[2] << 4) | state[3]

"""Shifts nonce into 8-bit size"""
def shift_nonce(nonce):
    i = len(format(nonce,'04b'))
    return nonce << (8 - i)

def saes_ctr_encrypt(plaintext, key, nonce):
    ciphertext = []
    keys = key_expansion(key)
    counter = shift_nonce(nonce) << 8
    for i, byte in enumerate(plaintext):
        counter += i
        keystream_block = saes_encrypt(counter, keys)
        ciphertext.append(byte ^ ((keystream_block >> 8)))
    return bytes(ciphertext)

def saes_ctr_decrypt(ciphertext, key, nonce):
    bytes_cipher = bytes.fromhex(ciphertext)
    return saes_ctr_encrypt(bytes_cipher, key, nonce)

def brute_force_both(plaintext, ciphertext):
    for key in range(0x2473, 0xFFFF):
        print(key)
        for nonce in range(0xFF):
            cipher2 = saes_ctr_encrypt(plaintext, key, nonce)
            if cipher2.hex() == ciphertext:
                print(f"Key: {hex(key)}, Nonce: {hex(nonce)}")
                
key = 0x2475
nonce = 0x10


plaintext = b"Test String"
ciphertext = saes_ctr_encrypt(plaintext, key, nonce)
print(f"Ciphertext: {ciphertext.hex()}")

encrypted_message = "7637c166a2310e985aad2c"
decrypted_message = saes_ctr_decrypt(encrypted_message, key, nonce)
print(f"Decrypted Cipher: {decrypted_message.decode()}")

#brute_force_both(plaintext, encrypted_message)