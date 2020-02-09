from functools import partial

BLOCK_SIZE = 1024

def write_block(fname, data):
    with open(fname, 'wb') as file:
        file.write(data)
            
def write_ciphertext(keys, input_path, output_file):
    b_key, h_key = keys

    print('writing ciphertext...')

    with open(input_path, 'rb') as file:
        for chunk in iter(partial(file.read, BLOCK_SIZE), b''):
            write_block(output_file, chunk)



