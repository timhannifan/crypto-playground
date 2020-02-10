"""
This code encrypts and decrypts a binary or text file.

Example:
    python filecrypt.py encrypt <input file> <output file>
    python filecrypt.py decrypt <input file> <output file>

Author: Tim Hannifan
"""

import sys
import os
import re
from hash import generate_sha256_hash
from genkeys import generate_credentials, get_private_key, get_keyhash, get_private_keys
from encrypt import write_ciphertext
from functools import partial

CREDENTIALS_STORE = 'credentials.txt'
USER = 'timhannifan'
PWD = 'password123'
BLOCK_SIZE = 32


def get_user_credentials(username, password, credentials_store):
    # generate keys if they don't exist
    if not os.path.exists(credentials_store):
        print('Generating credentials...')
        generate_credentials(username, password, credentials_store)

    creds = []
    with open(credentials_store, 'r') as credentials:
        creds = [line.strip() for line in credentials]

    msg_creds = re.split(':',creds[0])
    sig_creds = re.split(':',creds[0])

    # TODO: check username in creds is same as passed username
    msg_salt = msg_creds[3]
    private_key = get_private_key(password, msg_salt)
    print('msgcreds',private_key)
    print('keyhash', get_keyhash(private_key))

    return creds



def xor(message, key):
    if len(message) < len(key):
        diff = len(key) - len(message)
        message = message + b'\x00' * diff

    """xor two strings together."""
    if (isinstance(message, str)):
        return b"".join(chr(ord(a) ^ ord(b)) for a, b in zip(message, key))
    else:
        return bytes([a ^ b for a, b in zip(message, key)])

def write_output(data, fpath):
    print('Writing output...')
    with open(fpath, 'a') as file:
        file.write(data)

def sign_output(fpath, sig_key):
    print('Signing output...')
    signed_ciphertext_hash = generate_sha256_hash(fpath, sig_key)

    write_output(signed_ciphertext_hash, fpath)

def verify_ciphertext(fpath, sig_key):
    #TODO
    # signed_ciphertext_hash = generate_sha256_hash(fpath, sig_key)
    return True

def decrypt(input_file, msg_key, output_file):
    if os.path.exists(output_file):
        os.remove(output_file)
    with open(input_file, 'rb') as file:
        data = file.read()
        plaintext = xor(chunk, msg_key)
        print(plaintext.decode("utf8"))
        # for chunk in iter(partial(file.read, BLOCK_SIZE), b''):
        #     plaintext = xor(chunk, msg_key)

        #     print(plaintext.decode("utf8"))
            # print(type(plaintext))
            # print(plaintext.decode("utf8"))
            # write_output(ciphertext, output_file)

def run(command, input_file, output_file):
    """TODO

    Args:
      command: A string, either 'encrypt' or 'decrypt'.
      input_file: A filepath for the file to be encrypted or decrypted.
      output_file: A filepath where the output will be written 

    Returns:
      Nothing

    Raises:
      ModuleNotFoundError: If hashlib is not found
    """
    if command == 'encrypt':
        print('Encrypting file...')
        # credentials = get_user_credentials(USER, PWD, CREDENTIALS_STORE)
        msg_keys = get_private_keys(PWD)
        sig_keys = get_private_keys(PWD)
        print('msgkey:', msg_keys[1])

        with open(input_file, 'r') as file:
            message = file.read()
            message = message.encode('utf-8')

        key = msg_keys[0]
        cipher_text = xor(message, key)

        write_output(cipher_text.hex(), output_file)
        # message = 'This is a secret message'
        # key = msg_keys[0]
        # cipherText = xor_strings(message.encode('utf8'), key)
        # print('cipherText:', cipherText)
        # print('decrypted:', xor_strings(cipherText, key).decode('utf8'))
        # if os.path.exists(output_file):
        #     os.remove(output_file)
        # with open(input_file, 'rb') as file:
        #     for chunk in iter(partial(file.read, BLOCK_SIZE), b''):
        #         ciphertext = xor(chunk, msg_keys[0])
        #         write_output(ciphertext, output_file)

        # sign_output(output_file, sig_keys[0])

    elif command == 'decrypt':
        print('Decrypting file...')

        with open(input_file, 'r') as file:
            cipher_hex = file.read()
            cipher_text = bytes.fromhex(cipher_hex)

            key = bytes.fromhex('d4b438c6857a117c449caac3ea0621f3751390f63fd18e76bf07ac00b2696c5e')
            # print(type(key),type(cipher_text))
            decrypted = xor(cipher_text, key)
            print(decrypted)
            # print(decrypted.decode('utf8'))
            # print(decrypted.decode('utf-8', 'backslashreplace'))
# 
        # print('cipher_text:', cipher_text)
        # print('decrypted:', xor(cipher_text, key).decode('utf8'))


        # with open(input_file, 'r') as file:
        #     ciphertext = file.read()
        #     ciphertext = bytes.fromhex(ciphertext)
        #     k = '8bd35428e035b8435d8022755112b3d589dc26b68c802d67e12e72d9c8617ddd'
        #     k_b = bytes.fromhex(k)
        #     print(type(ciphertext))
        #     plain = xor(ciphertext, k_b)
        #     # print
        #     print(plain.decode('utf-8'))




        # with open(input_file, 'rb') as file:
        #     ciphertext = file.read()
        #     k = '8bd35428e035b8435d8022755112b3d589dc26b68c802d67e12e72d9c8617ddd'
        #     k_b = bytes.fromhex(k)
        #     plain = xor(ciphertext, k_b)
        #     print(plain.decode('utf-8'))
        # user_sig_key = input('Enter signature key: ')

        # if verify_ciphertext(input_file, user_sig_key):
        #     user_msg_key = input('Enter message key: ')
        #     key_bytes = bytes.fromhex(user_msg_key)
        #     # print(type(key_bytes))
        #     decrypt(input_file, key_bytes, output_file)
    elif command == 'test':
        print('TEST Encrypting file...')
        # credentials = get_user_credentials(USER, PWD, CREDENTIALS_STORE)
        msg_keys = get_private_keys(PWD)
        sig_keys = get_private_keys(PWD)

        # message = 'This is a secret message'
        with open(input_file, 'r') as file:
            message = file.read()
        key = msg_keys[0]
        cipher_text = xor(message.encode('utf8'), key)
        print('cipher_text:', cipher_text)
        print('decrypted:', xor(cipher_text, key).decode('utf8'))




if __name__ == '__main__':
    # Check passed arguments
    if len(sys.argv) < 4:
        sys.exit('CL error: Too few arguments.')
    elif len(sys.argv) > 4:
        sys.exit('CL error: Too many arguments supplied.')
    elif sys.argv[1] not in ['encrypt', 'decrypt', 'test']:
        sys.exit('CL error: The first argument can be encrypt or decrypt')
    elif not (os.path.isfile(sys.argv[2])):
        sys.exit('File error: Input file does not exist.')

    run(sys.argv[1], sys.argv[2], sys.argv[3])
