# Info431 S-AES-CTR Project


S-AES Encryption/Decryption: 16-bit block cipher with 16-bit key
CTR Mode: Converts block cipher to stream cipher
GUI Interface:
    Built with Tkinter
    Encryption Tab
    Decryption Tab
    Bruteforce Attack Tab


S-AES Implementation
    Key Expansion
    S-Box (Substitution Box): Predefined lookup table
    Galois Field (2^4) Multiplication Table: Constant once generated, calculated up to 2^4 in this case
    2 Round Transformations:
        Pre-Round 1:
            AddRoundKey
        Round 1:
            SubNibbles
            ShiftRows
            MixColumns
            AddRoundKey
        Round 2:
            SubNibbles
            ShiftRows
            AddRoundKey


CTR Mode
    Nonce: 8-bit in this implementation, concatenated with an 8-bit counter
    Keystream Generation: S-AES(nonce || counter)
    Counter Mode: Encryption and Decryption are identical, Encryption a ciphertext returns its decrypted plaintext


Installation:
    Prerequisites:
        Python 3.13+
        Tkinter (usually included with Python)
    Installation:
        git clone https://github.com/geo-fh/Info431.git
        cd Info431


GUI Mode:
    How to run the tkinter interface:
        python S-AES-CTR.py
    Interface guide:
        Encryption Mode:
            Plaintext Input: ASCII or hex input
            Key Input: 16-bit hex (e.g., 0x2475)
            Nonce Input: 8-bit hex (e.g., 0x10)
            Ciphertext Output: Hex, Encrypted Plaintext Input
        Decryption Mode:
            Ciphertext Input: Hex input
            Key Input: 16-bit hex (e.g., 0x2475)
            Nonce Input: 8-bit hex (e.g., 0x10)
            Plaintext Output: ASCII or hex output, Decrypted Ciphertext Input
        Bruteforce Mode:
            Plaintext Input: ASCII or hex input
            Ciphertext Input: Hex input
            Key Output: 16-bit hex
            Nonce Output: 8-bit hex


Limitations:
    Educational Use Only: Not secure for real-world applications
    Key Size: 16-bit keys are trivial to brute force
    Ciphertext Size: Ciphertext length is identical to Plaintext length