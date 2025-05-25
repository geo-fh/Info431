import tkinter as tk
from tkinter import ttk

# Substitution Box
SBOX = [
    0x09, 0x04, 0x0A, 0x0B,
    0x0D, 0x01, 0x08, 0x05,
    0x06, 0x02, 0x00, 0x03,
    0x0C, 0x0E, 0x0F, 0x07
]

# Inverse Substitution Box (Not needed with CTR)
INV_SBOX = [
    0x0A, 0x05, 0x09, 0x0B,
    0x01, 0x07, 0x08, 0x0F,
    0x06, 0x00, 0x02, 0x03,
    0x0C, 0x04, 0x0D, 0x0E
]

# Mix Columns Matrix
MIX_COL = [
    [1, 4],
    [4, 1]
]

# Inverse Mix Columns Matrix (Not Needed with CTR)
INV_MIX_COL = [
    [9, 2],
    [2, 9]
]

# GF(2^4) Multiplication Table, Generated using http://www.ee.unb.ca/cgi-bin/tervo/galois3.pl?p=4&C=1&h=1&D=1&A=1, for XORs whose values exceed 15
GF_MULT_TABLE = [
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
    [0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x03,
        0x01, 0x07, 0x05, 0x0B, 0x09, 0x0F, 0x0D],
    [0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09, 0x0B,
        0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02],
    [0x04, 0x08, 0x0C, 0x03, 0x07, 0x0B, 0x0F, 0x06,
        0x02, 0x0E, 0x0A, 0x05, 0x01, 0x0D, 0x09],
    [0x05, 0x0A, 0x0F, 0x07, 0x02, 0x0D, 0x08, 0x0E,
        0x0B, 0x04, 0x01, 0x09, 0x0C, 0x03, 0x06],
    [0x06, 0x0C, 0x0A, 0x0B, 0x0D, 0x07, 0x01, 0x05,
        0x03, 0x09, 0x0F, 0x0E, 0x08, 0x02, 0x04],
    [0x07, 0x0E, 0x09, 0x0F, 0x08, 0x01, 0x06, 0x0D,
        0x0A, 0x03, 0x04, 0x02, 0x05, 0x0C, 0x0B],
    [0x08, 0x03, 0x0B, 0x06, 0x0E, 0x05, 0x0D, 0x0C,
        0x04, 0x0F, 0x07, 0x0A, 0x02, 0x09, 0x01],
    [0x09, 0x01, 0x08, 0x02, 0x0B, 0x03, 0x0A, 0x04,
        0x0D, 0x05, 0x0C, 0x06, 0x0F, 0x07, 0x0E],
    [0x0A, 0x07, 0x0D, 0x0E, 0x04, 0x09, 0x03, 0x0F,
        0x05, 0x08, 0x02, 0x01, 0x0B, 0x06, 0x0C],
    [0x0B, 0x05, 0x0E, 0x0A, 0x01, 0x0F, 0x04, 0x07,
        0x0C, 0x02, 0x09, 0x0D, 0x06, 0x08, 0x03],
    [0x0C, 0x0B, 0x07, 0x05, 0x09, 0x0E, 0x02, 0x0A,
        0x06, 0x01, 0x0D, 0x0F, 0x03, 0x04, 0x08],
    [0x0D, 0x09, 0x04, 0x01, 0x0C, 0x08, 0x05, 0x02,
        0x0F, 0x0B, 0x06, 0x03, 0x0E, 0x0A, 0x07],
    [0x0E, 0x0F, 0x01, 0x0D, 0x03, 0x02, 0x0C, 0x09,
        0x07, 0x06, 0x08, 0x04, 0x0A, 0x0B, 0x05],
    [0x0F, 0x0D, 0x02, 0x09, 0x06, 0x04, 0x0B, 0x01,
        0x0E, 0x0C, 0x03, 0x08, 0x07, 0x05, 0x0A]
]


def to_hex(string):
    # Takes a string representation of a hex number (e.g: 24) and turns it into its hex value to be put in a variable (e.g: 0x24)
    return int(("0x" + string), 16)


def rot_word(word):
    # Adds a single digit padding of 0 if the number is <10 (e.g: 0xF -> 0x0F) to avoid errors when rotating the word
    word = "0x{:02x}".format(word)
    # Using negative indexes to skip the "0x" at the beginning of the number
    return word[-1] + word[-2]


def sub_word(word):
    # Check if the word length is 2 (the maximum) and if it's less pads it with a 0 at the start to prevent errors
    word = hex(word)[2:] if len(hex(word)[2:]) == 2 else "0" + hex(word)[2:]
    sub_word = ""
    # Substitutes each part of the word with its equivalent in the substitution table
    for nibble in word:
        # The substitution box is setup in a way that the value of the nibble is the index of its substitute
        sub = SBOX[int(nibble, 16)]
        sub_word += str(sub) if len(str(sub)) == 1 else str(hex(sub))[2:]
    return to_hex(sub_word)


def key_expansion(key):
    # Array to store k0, k1, k2 that will be used pre-round 1, round 1 and round 2 respectively
    keys = [None]*3
    # Array to store w0, w1, w2, w3, w4, w5 such as w0+w1=k0, w2+w3=k1, w4+w5=k2
    words = [None]*6
    # Forming w0 and w1 out of the first 8 bits and last 8 bits of the input key respectively
    words[0] = ((key >> 12) & 0xF)*0x10 + ((key >> 8) & 0xF)
    words[1] = ((key >> 4) & 0xF)*0x10 + (key & 0xF)
    for i in range(2, 6):
        # RCon is different for Round 1 and Round 2
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
    # Splits each key into 4 fragments of 4 bits each, for easy XORing
    key_frags = [(key >> 12) & 0xF, (key >> 8) &
                 0xF, (key >> 4) & 0xF, key & 0xF]
    state = [state[i] ^ key_frags[i] for i in range(4)]
    return state


def sub_nibbles(state):
    # Same as sub_word(word) earlier, but for the normal rounds instead of key expansion
    return [SBOX[state[0]], SBOX[state[1]], SBOX[state[2]], SBOX[state[3]]]


def shift_rows(state):
    # Row shifting for the rounds
    return [state[0], state[3], state[2], state[1]]


def gf_mult(num1, num2):
    # Handles the matrix multiplication in the Galois Field (2^4) in case a value outside the field is obtained, then it replaces with it's multiplication table equivalent
    return num1*num2 if num1*num2 < 16 else GF_MULT_TABLE[num1-1][num2-1]


def mix_columns(state):
    # Mixes the columns
    temp_state = [None]*4
    temp_state[0] = gf_mult(MIX_COL[0][0], state[0]) ^ gf_mult(
        MIX_COL[0][1], state[1])
    temp_state[1] = gf_mult(MIX_COL[1][0], state[0]) ^ gf_mult(
        MIX_COL[1][1], state[1])
    temp_state[2] = gf_mult(MIX_COL[0][0], state[2]) ^ gf_mult(
        MIX_COL[0][1], state[3])
    temp_state[3] = gf_mult(MIX_COL[1][0], state[2]) ^ gf_mult(
        MIX_COL[1][1], state[3])
    return temp_state


def saes_encrypt(block, keys):
    # Splits the 16-bit block into 4 4-bit pieces for easier handling
    state = [(block >> 12) & 0xF, (block >> 8) &
             0xF, (block >> 4) & 0xF, block & 0xF]
    # Standard S-AES transformation order, with 2 rounds
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

    # Merges the 4 fragments we split earlier back into a 16-bit encrypted block
    return (state[0] << 12) | (state[1] << 8) | (state[2] << 4) | state[3]


def shift_nonce(nonce):
    # Shifts the 8-bit nonce input so it occupies a full 8 bits with leading zeroes, to prevent errors
    i = len(format(nonce, '04b'))
    return nonce << (8 - i)


def saes_ctr_encrypt(plaintext, key, nonce):
    # Empty bytearray container ready to receive the blocks of encrypted message
    ciphertext = bytearray()
    keys = key_expansion(key)
    # Since the blocks are processed 2 bytes at a time, we pad the plaintext with an empty byte in case the plaintext has an odd number of bytes
    padded_plaintext = plaintext if len(
        plaintext) % 2 == 0 else plaintext + b'\x00'
    for i in range(0, len(padded_plaintext), 2):
        # The counter is 16-bits, formed by the concatenation of the 8-bit nonce and an 8-bit incrementing counter
        counter = (nonce << 8) | (i // 2)
        # In CTR mode, the plaintext itself is not encrypted by S-AES, but the counter variable
        keystream_block = saes_encrypt(counter, keys)
        # We select 2 bytes at a time from the padded plaintext for CTR mode encryption
        block = padded_plaintext[i:i+2]
        # The encrypted counter is XORed with the plaintext block to form the ciphertext
        encrypted_block = (int.from_bytes(block) ^ keystream_block).to_bytes(2)
        ciphertext.extend(encrypted_block)
    # We concatenate the bytearray back into a series of bytes and limit it to the original length of the plaintext, to remove the empty byte if any was added, and return the final value as the ciphertext
    return bytes(ciphertext[:len(plaintext)])


def saes_ctr_decrypt(ciphertext, key, nonce):
    # In CTR mode, decryption is equivalent to encrypting the ciphertext once more
    # All we have to do is transform the hex ciphertext into bytes and run it through the S-AES encryption one more time
    bytes_cipher = bytes.fromhex(ciphertext)
    return saes_ctr_encrypt(bytes_cipher, key, nonce)


def brute_force_both(plaintext, ciphertext):
    # To bruteforce the key and nonce, we input a capture plaintext and its encrypted equivalent ciphertext, and attempt to encrypt the plaintext with every key and nonce combination until the output matches the ciphertext
    # Tries all possible keys from 0x0000 to 0xFFFF
    for key in range(0xFFFF):
        print(key)
        # Tries all possible nonces in conjunction with the current key in the loop
        for nonce in range(0xFF):
            # Encrypts the plaintext with the current key and nonce and compares it to the ciphertext
            cipher2 = saes_ctr_encrypt(plaintext, key, nonce)
            if cipher2.hex() == ciphertext:
                print(f"Key: {hex(key)}, Nonce: {hex(nonce)}")
                return hex(key), hex(nonce)


def gui_encrypt():
    plaintext = e_plaintext.get().encode()
    key = int(e_key.get(), 16)
    nonce = int(e_nonce.get(), 16)
    ciphertext = saes_ctr_encrypt(plaintext, key, nonce)
    e_ciphertext.config(state='normal')
    e_ciphertext.delete(0, tk.END)
    e_ciphertext.insert(0, ciphertext.hex())
    e_ciphertext.config(state='readonly')


def gui_decrypt():
    ciphertext = d_ciphertext.get()
    key = int(d_key.get(), 16)
    nonce = int(d_nonce.get(), 16)
    plaintext = saes_ctr_decrypt(ciphertext, key, nonce)
    d_plaintext.config(state='normal')
    d_plaintext.delete(0, tk.END)
    d_plaintext.insert(0, plaintext)
    d_plaintext.config(state='readonly')


def gui_bruteforce():
    plaintext = bf_plaintext.get().encode()
    ciphertext = bf_ciphertext.get()
    key, nonce = brute_force_both(plaintext, ciphertext)
    bf_key.config(state='normal')
    bf_key.delete(0, tk.END)
    bf_key.insert(0, key)
    bf_key.config(state='readonly')
    bf_nonce.config(state='normal')
    bf_nonce.delete(0, tk.END)
    bf_nonce.insert(0, nonce)
    bf_nonce.config(state='readonly')


root = tk.Tk()
root.title("S-AES-CTR")
root.geometry("500x400")
root.resizable(False, False)

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

tab1 = ttk.Frame(notebook)
tab2 = ttk.Frame(notebook)
tab3 = ttk.Frame(notebook)

tab1.rowconfigure(0, weight=1, uniform='rows')
tab1.rowconfigure(1, weight=1, uniform='rows')
tab1.rowconfigure(2, weight=1, uniform='rows')
tab1.rowconfigure(3, weight=1, uniform='rows')
tab1.rowconfigure(4, weight=1, uniform='rows')
tab2.rowconfigure(0, weight=1, uniform='rows')
tab2.rowconfigure(1, weight=1, uniform='rows')
tab2.rowconfigure(2, weight=1, uniform='rows')
tab2.rowconfigure(3, weight=1, uniform='rows')
tab2.rowconfigure(4, weight=1, uniform='rows')
tab3.rowconfigure(0, weight=1, uniform='rows')
tab3.rowconfigure(1, weight=1, uniform='rows')
tab3.rowconfigure(2, weight=1, uniform='rows')
tab3.rowconfigure(3, weight=1, uniform='rows')
tab3.rowconfigure(4, weight=1, uniform='rows')
tab3.rowconfigure(5, weight=1, uniform='rows')
tab1.columnconfigure(0, weight=1, uniform='cols')
tab1.columnconfigure(1, weight=1, uniform='cols')
tab1.columnconfigure(2, weight=1, uniform='cols')
tab2.columnconfigure(0, weight=1, uniform='cols')
tab2.columnconfigure(1, weight=1, uniform='cols')
tab2.columnconfigure(2, weight=1, uniform='cols')
tab3.columnconfigure(0, weight=1, uniform='cols')
tab3.columnconfigure(1, weight=1, uniform='cols')
tab3.columnconfigure(2, weight=1, uniform='cols')

notebook.add(tab1, text="Encrypt")
notebook.add(tab2, text="Decrypt")
notebook.add(tab3, text="Brute Force")

style = ttk.Style()
style.configure("Label.TLabel", font=("Arial Bold", 10),
                anchor="center", padding=(10, 10))
style.configure("Entry.TEntry", font=("Arial", 10),
                anchor="center", padding=(10, 10))
style.configure("Button.TButton", font=("Arial", 10),
                anchor="center", padding=(10, 10))

ttk.Label(tab1, text="Plaintext:", style='Label.TLabel').grid(row=0, column=0)
e_plaintext = ttk.Entry(tab1, style='Entry.TEntry')
e_plaintext.grid(row=0, column=1, columnspan=2, sticky='ew', padx=(0, 30))
ttk.Label(tab1, text="Key:", style='Label.TLabel').grid(row=1, column=0)
e_key = ttk.Entry(tab1, style='Entry.TEntry')
e_key.grid(row=1, column=1, columnspan=2, sticky='ew', padx=(0, 30))
ttk.Label(tab1, text="Nonce (8-bit):",
          style='Label.TLabel').grid(row=2, column=0)
e_nonce = ttk.Entry(tab1, style='Entry.TEntry')
e_nonce.grid(row=2, column=1, columnspan=2, sticky='ew', padx=(0, 30))
ttk.Button(tab1, text="Encrypt", style='Button.TButton',
           command=gui_encrypt).grid(row=3, column=1)
e_error = ttk.Label(tab1, text="", style='Label.TLabel').grid(row=3, column=2)
ttk.Label(tab1, text="Ciphertext:", style='Label.TLabel').grid(row=4, column=0)
e_ciphertext = ttk.Entry(tab1, style='Entry.TEntry', state='readonly')
e_ciphertext.grid(row=4, column=1, columnspan=2, sticky='ew', padx=(0, 30))

ttk.Label(tab2, text="Ciphertext:", style='Label.TLabel').grid(row=0, column=0)
d_ciphertext = ttk.Entry(tab2, style='Entry.TEntry')
d_ciphertext.grid(row=0, column=1, columnspan=2, sticky='ew', padx=(0, 30))
ttk.Label(tab2, text="Key:", style='Label.TLabel').grid(row=1, column=0)
d_key = ttk.Entry(tab2, style='Entry.TEntry')
d_key.grid(row=1, column=1, columnspan=2, sticky='ew', padx=(0, 30))
ttk.Label(tab2, text="Nonce (8-bit):",
          style='Label.TLabel').grid(row=2, column=0)
d_nonce = ttk.Entry(tab2, style='Entry.TEntry')
d_nonce.grid(row=2, column=1, columnspan=2, sticky='ew', padx=(0, 30))
ttk.Button(tab2, text="Decrypt", style='Button.TButton',
           command=gui_decrypt).grid(row=3, column=1)
d_error = ttk.Label(tab2, text="", style='Label.TLabel').grid(row=3, column=2)
ttk.Label(tab2, text="Plaintext:", style='Label.TLabel').grid(row=4, column=0)
d_plaintext = ttk.Entry(tab2, style='Entry.TEntry', state='readonly')
d_plaintext.grid(row=4, column=1, columnspan=2, sticky='ew', padx=(0, 30))

ttk.Label(tab3, text="Plaintext:", style='Label.TLabel').grid(row=0, column=0)
bf_plaintext = ttk.Entry(tab3, style='Entry.TEntry')
bf_plaintext.grid(row=0, column=1, columnspan=2, sticky='ew', padx=(0, 30))
ttk.Label(tab3, text="Ciphertext:", style='Label.TLabel').grid(row=1, column=0)
bf_ciphertext = ttk.Entry(tab3, style='Entry.TEntry')
bf_ciphertext.grid(row=1, column=1, columnspan=2, sticky='ew', padx=(0, 30))
ttk.Button(tab3, text="Bruteforce", style='Button.TButton',
           command=gui_bruteforce).grid(row=2, column=1)
bf_error = ttk.Label(tab3, text="", style='Label.TLabel').grid(row=2, column=2)
"""
progress_bar = ttk.Progressbar(tab3, orient='horizontal', mode='determinate', maximum=0xFFFF)
progress_bar.grid(row=3, column=0, columnspan=2, sticky='ew', padx=(30, 0))
progress_label = ttk.Label(tab3, text="0000/FFFF", style='Label.TLabel')
progress_label.grid(row=3, column=2)
"""
ttk.Label(tab3, text="Key:", style='Label.TLabel').grid(row=4, column=0)
bf_key = ttk.Entry(tab3, style='Entry.TEntry', state='readonly')
bf_key.grid(row=4, column=1, columnspan=2, sticky='ew', padx=(0, 30))
ttk.Label(tab3, text="Nonce:", style='Label.TLabel').grid(row=5, column=0)
bf_nonce = ttk.Entry(tab3, style='Entry.TEntry', state='readonly')
bf_nonce.grid(row=5, column=1, columnspan=2, sticky='ew', padx=(0, 30))

root.mainloop()
