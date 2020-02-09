import os
import hashlib
import sys
import secrets
from functools import partial

N_ITERATIONS = 10**5
SALT_SIZE = 128 // 8
BLOCK_SIZE = 48
NONCE_SIZE = 128 // 8

TEST_FILE = 'testdata/small.txt'
# CREDENTIALS_STORE = 'credentials.txt'

def generate_key(key_type, u_name, password):
    password_b = bytes(password, 'utf-8')
    salt_b = bytes(key_type, 'utf-8') + os.urandom(SALT_SIZE)
    dk = hashlib.pbkdf2_hmac('sha256', password_b, salt_b, N_ITERATIONS)

    return (u_name, key_type, dk, salt_b.hex())

def get_private_keys(password):
    password_b = bytes(password, 'utf-8')
    salt_b = os.urandom(SALT_SIZE)
    dk = hashlib.pbkdf2_hmac('sha256', password_b, salt_b, N_ITERATIONS)

    return (dk, dk.hex())

def get_keyhash(val):
    hasher = hashlib.sha256()
    hasher.update(val)

    return hasher.hexdigest()

def get_private_key(password, salt):
    password_b = bytes(password, 'utf-8')
    salt_b = bytes(salt, 'utf-8')
    dk = hashlib.pbkdf2_hmac('sha256', password_b, salt_b, N_ITERATIONS)

    return dk


def write_credentials(credentials, fname):

    with open(fname, 'w') as file:
        for key_creds in credentials:   
            user, key_type, dk, salt_hex = key_creds
            key_hash = get_keyhash(dk)
            line = ':'.join([user, key_type, key_hash, salt_hex]) + '\n'
            file.write(line)

def generate_credentials(user, password, output_file):

    msg_creds = generate_key('msg', user, password)
    sig_creds = generate_key('sig', user, password)

    write_credentials([msg_creds, sig_creds], output_file)
