def pad(text, block_size):
    padding_length = block_size - len(text) % block_size
    padding = bytes([padding_length] * padding_length)
    return text + padding

def unpad(text):
    padding_length = text[-1]
    return text[:-padding_length]

def xor_bytes(byte_array1, byte_array2):
    return bytes(a ^ b for a, b in zip(byte_array1, byte_array2))

def split_into_blocks(text, block_size):
    return [text[i:i+block_size] for i in range(0, len(text), block_size)]

def cbc_encrypt(plaintext, key, iv):
    plaintext = pad(plaintext, len(key))
    blocks = split_into_blocks(plaintext, len(key))
    cipher_blocks = []
    prev_cipher_block = iv

    for block in blocks:
        xored_block = xor_bytes(block, prev_cipher_block)
        cipher_block = b''
        for i in range(len(key)):
            cipher_block += bytes([xored_block[i] ^ key[i]])
        cipher_blocks.append(cipher_block)
        prev_cipher_block = cipher_block

    return iv + b''.join(cipher_blocks)

def cbc_decrypt(ciphertext, key):
    iv = ciphertext[:len(key)]
    ciphertext = ciphertext[len(key):]
    blocks = split_into_blocks(ciphertext, len(key))
    plaintext_blocks = []
    prev_cipher_block = iv

    for block in blocks:
        decipher_block = b''
        for i in range(len(key)):
            decipher_block += bytes([block[i] ^ key[i]])
        plaintext_block = xor_bytes(decipher_block, prev_cipher_block)
        plaintext_blocks.append(plaintext_block)
        prev_cipher_block = block

    return unpad(b''.join(plaintext_blocks))

# Example usage
key = b'abcdefghijklmnop'
iv = b'1234567890123456'
plaintext = b'This is a secret message'

# Encrypt the plaintext
encrypted = cbc_encrypt(plaintext, key, iv)
print("Encrypted:", encrypted)

# Decrypt the ciphertext
decrypted = cbc_decrypt(encrypted, key)
print("Decrypted:", decrypted.decode('utf-8'))