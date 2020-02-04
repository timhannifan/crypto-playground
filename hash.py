"""
This code produces a SHA-256 hash of a text or binary file.

Example:
    python hash.py /path/to/file

Author: Tim Hannifan
"""

import sys
import os
from functools import partial
# hashlib imported and checked in main

BLOCK_SIZE = 1024

def import_hashlib():
    # Check that hashlib can be imported
    try:
        import hashlib
    except ModuleNotFoundError:
        sys.exit('Error: hashlib not found.')

def generate_sha256(fpath):
    # import_hashlib()

    if not os.path.isfile(fpath):
        sys.exit('Error: Supplied filepath does not refer a valid file.')
    return run(fpath)

def run(fpath):
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

    # Initialize hasher and iterate through blocks of file
    hasher = hashlib.sha256()
    with open(fpath, 'rb') as file:
        for chunk in iter(partial(file.read, BLOCK_SIZE), b''):
            hasher.update(chunk)

    # print('{}  {}'.format(hasher.hexdigest(), os.path.basename(fpath)))
    return (hasher.hexdigest(), os.path.basename(fpath))

if __name__ == '__main__':
    # Check CLI arguments, correct command is "python3 hash.py <filepath>"
    if len(sys.argv) < 2:
        sys.exit('Error: No filepath supplied in arguments.')
    elif len(sys.argv) > 2:
        sys.exit('Error: Too many arguments supplied.')
    elif not os.path.isfile(sys.argv[1]):
        sys.exit('Error: Supplied filepath does not refer a valid file.')

    run(sys.argv[1])
