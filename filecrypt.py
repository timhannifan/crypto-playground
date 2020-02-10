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
import json
from hash import generate_sha256_hash
from genkeys import generate_credentials, get_private_key, get_keyhash, get_private_keys
from encrypt import write_ciphertext
from functools import partial

CREDENTIALS_STORE = 'credentials.txt'
USER = 'timhannifan'
PWD = 'password123'
BLOCK_SIZE = 32
HASH_RECORD = 'hashes.json'

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
    return creds



def xor(message, key):
    """Calculates the exclusive-or of a message and a key"""

    # Pad the message to length of key if necessary
    if len(message) < len(key):
        diff = len(key) - len(message)
        message = message + b'\x00' * diff

    # Comput xor
    if (isinstance(message, str)):
        return b"".join(chr(ord(x) ^ ord(y)) for x, y in zip(message, key))
    else:
        return bytes([x ^ y for x, y in zip(message, key)])


def write_output(data, fpath):
    """Writes output to a file"""
    print('Writing output...')
    with open(fpath, 'a') as file:
        file.write(data)


def verify_integrity(fname, sig_key):
    """Verifies the integrity of a file by checking the hash of the 
    ciphertext plus the signature key."""
    with open(HASH_RECORD) as json_file:
        data = json.load(json_file)

        if ((fname in data) and 
            (generate_sha256_hash(fname, sig_key ) == data[fname])):
            print('Integrity check successful')
            return True
        return False

def write_authentication_tag(output_file, sig_key):
    """Writes a hash of the cipertext and signature key to the hash
    record."""
    tag = generate_sha256_hash(output_file, sig_key)
    record = {}
    record[output_file] = tag

    with open(HASH_RECORD, 'w') as file:
        json.dump(record, file)


def run(command, input_file, output_file):
    """Main function for encryption and decryption. Produces ciphertext from a raw input in encrypt mode, and generates plaintext from ciphertext in decrypt mode.

    Args:
      command: A string, either 'encrypt' or 'decrypt'.
      input_file: A filepath for the file to be encrypted or decrypted.
      output_file: A filepath where the output will be written 

    Returns:
      Nothing
    """
    if command == 'encrypt':
        print('Encrypting file...')
        if os.path.exists(output_file):
            os.remove(output_file)

        msg_keys = get_private_keys(PWD)
        sig_keys = get_private_keys(PWD)
        print('Secret msg key:', msg_keys[1])
        print('Secret sig key:', sig_keys[1])

        with open(input_file, 'r') as file:
            message = file.read()
            message = message.encode('utf-8')

        key = msg_keys[0]
        cipher_text = xor(message, key)

        write_output(cipher_text.hex(), output_file)
        write_authentication_tag(output_file, sig_keys[1].encode('utf-8'))

    elif command == 'decrypt':
        print('Decrypting file...')
        user_sig_key = input('Enter secret signature key: ')
        
        if not verify_integrity(input_file, user_sig_key.encode('utf-8')):
            sys.exit('Decryption verification failed.')

        with open(input_file, 'r') as file:
            cipher_hex = file.read()
            cipher_text = bytes.fromhex(cipher_hex)
            key = bytes.fromhex(input('Secret message key: '))
            decrypted = xor(cipher_text, key).decode('utf-8')
            
            write_output(decrypted, output_file)

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
