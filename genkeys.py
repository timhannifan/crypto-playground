import os
import hashlib
import sys
import secrets
from functools import partial

N_ITERATIONS = 10**5
SALT_SIZE = 128 // 8
BLOCK_SIZE = 48
NONCE_SIZE = 128 // 8
DEMO_U_NAME = 'timhannifan'
DEMO_PWD = 'password123'
TEST_FILE = 'testdata/small.txt'
CREDENTIALS_STORE = 'credentials.txt'

def generate_key(key_type, u_name, password):
    salt_b = bytes(key_type, 'utf-8') + os.urandom(SALT_SIZE)
    password_b = bytes(password, 'utf-8')
    dk = hashlib.pbkdf2_hmac('sha256', password_b, salt_b, N_ITERATIONS)

    return (u_name, key_type, dk, salt_b.hex())


def get_keyhash(val):
    hasher = hashlib.sha256()
    hasher.update(val)

    return hasher.hexdigest()


def write_credentials(credentials, fname):

    with open(fname, 'w') as file:
        for key_creds in credentials:
            print('keycred')
            user, key_type, dk, salt_hex = key_creds
            key_hash = get_keyhash(dk)
            line = ':'.join([user, key_type, key_hash, salt_hex]) + '\n'
            file.write(line)


msg_creds = generate_key('msg', DEMO_U_NAME, DEMO_PWD)
sig_creds = generate_key('sig', DEMO_U_NAME, DEMO_PWD)

write_credentials([msg_creds, sig_creds], CREDENTIALS_STORE)
