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

CREDENTIALS_STORE = 'credentials.txt'
USER = 'timhannifan'
PWD = 'password123'


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

        write_ciphertext(msg_keys, input_file, output_file)



    elif command == 'decrypt':
        print('Decrypting file...')




if __name__ == '__main__':
    # Check passed arguments
    if len(sys.argv) < 4:
        sys.exit('CL error: Too few arguments.')
    elif len(sys.argv) > 4:
        sys.exit('CL error: Too many arguments supplied.')
    elif sys.argv[1] not in ['encrypt', 'decrypt']:
        sys.exit('CL error: The first argument can be encrypt or decrypt')
    elif not (os.path.isfile(sys.argv[2])):
        sys.exit('File error: Input file does not exist.')

    run(sys.argv[1], sys.argv[2], sys.argv[3])
