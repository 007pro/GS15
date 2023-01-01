import os
from Cryptodome.Cipher import AES

def aes_encrypt(plaintext, key, iv) :
    # Encrypt the file using AES-256 in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = pkcs7_pad(plaintext, 16)
    print(plaintext[:16])
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext

def aes_decrypt(ciphertext, key, iv) :
    # Decrypt the file using AES-256 in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = pkcs7_unpad(plaintext, 16)
    print(plaintext[:16])

    return plaintext

def pkcs7_pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(padded_data, block_size):
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

