import os
from functools import partial

BLOCK_SIZE = 2048
NONCE_SIZE = 128 // 8

def write_block(fname, data):
    with open(fname, 'wb') as file:
        file.write(data)
            
def write_ciphertext(keys, input_path, output_file):
    b_key, h_key = keys
    nonce = os.urandom(NONCE_SIZE)
    print('writing ciphertext...')

    with open(input_path, 'rb') as file:
        ctr = 0
        for chunk in iter(partial(file.read, BLOCK_SIZE), b''):
            # fill_bytes = 
            ctr_bytes = ctr.to_bytes(100, 'big')
            ks = b_key + nonce + ctr_bytes
            # print('b_key',len(b_key))
            # print('nonce',len(nonce))
            # print('ctr_bytes',len(ctr_bytes))
            # print('len keystream', len(ks))
            
            # write_block(output_file, chunk)
            # print(bytearray(ks).hex())
            # print(nonce)
            ctr += 1


