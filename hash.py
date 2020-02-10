"""
This code produces a SHA-256 hash of a text or binary file.

Example:
    python hash.py /path/to/file

Author: Tim Hannifan
"""

import sys
import os
from functools import partial
# hashlib is imported in run()

BLOCK_SIZE = 1024

def generate_sha256_hash(fpath, sig_key=None):
    """Public function to generate SHA256 hash.
    Args:
      fpath: A filepath for the file to be hashed.

    Returns:
      tuple: (hexidecimal hash value, filename)
    """
    return run(fpath, sig_key)

def run(fpath, sig_key=None):
    """Prints the sha256 hexdigest of a file.

    Args:
      fpath: A filepath for the file to be hashed.

    Returns:
      TODO

    Raises:
      ModuleNotFoundError: If hashlib is not found
    """
    # Check that hashlib is available
    try:
        import hashlib
    except ModuleNotFoundError:
        sys.exit('Error: hashlib not found.')

    if not os.path.isfile(fpath):
        sys.exit('File Error: Supplied filepath does not refer a valid file.')
    
    # Initialize hasher and iterate through blocks of file
    hasher = hashlib.sha256()
    with open(fpath, 'rb') as file:
        for chunk in iter(partial(file.read, BLOCK_SIZE), b''):
            hasher.update(chunk)
    if sig_key is not None:
        hasher.update(sig_key)

    res = (hasher.hexdigest(), os.path.basename(fpath))
    # print('{}  {}'.format(res[0], res[1]))

    return hasher.hexdigest()


if __name__ == '__main__':
    # Check CLI arguments, correct command is "python3 hash.py <filepath>"
    if len(sys.argv) < 2:
        sys.exit('Error: No filepath supplied in arguments.')
    elif len(sys.argv) > 2:
        sys.exit('Error: Too many arguments supplied.')

    run(sys.argv[1])
