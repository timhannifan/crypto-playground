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
KEY_TYPE = 'encr_key'

def generate_key(key_type, u_name, password):
    salt_b = bytes(key_type, 'utf-8') + os.urandom(SALT_SIZE)
    password_b = bytes(password, 'utf-8')
    dk = hashlib.pbkdf2_hmac('sha256', password_b, salt_b, N_ITERATIONS)

    return (u_name, dk, salt_b)


def get_keyhash(val):
    hasher = hashlib.sha256()
    hasher.update(val)

    return hasher.hexdigest()


def write_credentials(u_name, salt, key_hash, key_type, fname):
    with open(fname, 'wa') as file:
        line = ':'.join([u_name, key_type, salt, key_hash])
        file.write(line)


key_type = 'msg'
creds = generate_key(key_type, DEMO_U_NAME, DEMO_PWD)
u_name, dk, salt = creds
write_credentials(u_name,  key_type, salt.hex(), get_keyhash(dk), 'creds.txt')

key_type = 'sig'
creds = generate_key(key_type, DEMO_U_NAME, DEMO_PWD)
u_name, dk, salt = creds
write_credentials(u_name,  key_type, salt.hex(), get_keyhash(dk), 'creds.txt')




# counter = 1
# with open('testdata/small.txt', 'rb') as file:
#     nonce = os.urandom(NONCE_SIZE)
#     for chunk in iter(partial(file.read, BLOCK_SIZE), b''):
#         print('ROUND')
#         # print((len(encr_key)))
#         print(len(nonce) + len(encr_key) + len(bytes(counter)))
#         print(bytes(counter))
#         print(len(bytes(chunk)))

#         # size_diff = (len(nonce) + len(encr_key)) - len(bytes(chunk))
#         # ks = generate_keystream(encr_key, nonce, counter)
#         counter += 1
