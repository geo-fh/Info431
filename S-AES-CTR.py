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


def to_hex(string):
    return int(("0x" + string), 16)


def rot_word(word):
    word = hex(word)
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


def sub_nibbles(state):
    return [SBOX[state[0]], SBOX[state[1]], SBOX[state[2]], SBOX[state[3]]]


def shift_rows(state):
    return [state[0], state[3], state[2], state[1]]


def saes_encrypt(block, keys):
    state = [(block >> 12) & 0xF, (block >> 8) &
             0xF, (block >> 4) & 0xF, block & 0xF]

    state = [state[i] ^ keys[0] for i in range(4)]
    # Round 1
    return 0


key = 0x2475
keys = key_expansion(key)

for i in range(4):
    print(hex(sub_nibbles([2, 4, 7, 5])[i]))
