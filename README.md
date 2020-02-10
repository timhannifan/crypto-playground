## About
This repository contains Python code to demonstrate basic cryptographic principles. Do not use this code for production purposes.

## Contents
- `hash.py` generates the SHA-256 hash of any type of file
- `filecrypt.py` runs encryption and decription using symmetric encryption


## Usage
To use the encryption and decryption utilities, use the following commands:
```
python filecrypt.py encrypt <input file> <output file>
python filecrypt.py decrypt <input file> <output file>
```
## Construction
### Key generation/derivation
A weak password is hardcoded in filecrypt.py for demonstration purposes. When the encryption command is run, keys are derived using hashlib's `pbkdf2_hmac`. A strong password is created by adding a 128-bit salt generated from `os.urandom` (a cryptographically secure pseudorandom number generator) and then run through 100,000 iterations. The user's private keys are printed to the screen for transport out-of-band to the remote server. Two keys are generated: an encryption key and an authentication key.

### Encryption
When the encrypt command is run, the user's keys are generated and printed to the screen. Ciphertext is then created by x-or of the plaintext and the user's encryption key. The ciphertext is written to a file.

## Authentication
After the ciphertext is written, a SHA-256 hash of the ciphertext with the user's authentication appended to the end is created. The filename/hash combination are written to a JSON file. This structure repliates Encrypt-then-MAC, which generates the authentication tag from the ciphertext.

### Verification
When the decrypt command is run, the ciphertext file's integrity is checked by computing the SHA-256 hash of the ciphertext plus the user's authentication key. This hash should match the one computed and stored in the JSON file mentioned above. If these hashes do not match, either the wrong authentication key was provided or the ciphertext was modified.

## Decryption
If verification is passed, the users is prompted to enter their secret encryption key. This encryption key is then x-or'd with the ciphertext to arrive at the decrypted plaintext. This plaintext is then written to the specified output file.

## Generated Artifacts
- Authentication tags: stored in a JSON file, hashes.json
- Keys: printed to the screen, not stored on disk
- Ciphertext: text file with hexidecimal encoded contents


## Threat model
The decryption process protects against manipulation of the ciphertext through an encrypt-then-MAC schema. Alterations in the ciphertext or the use of an incorrect authentication key would will in failed verification, as the hash of these two values will have also changed. 

A root user on a remote server would be prevented from decrypting the ciphertext two ways. First, the user would need two private keys to verify/decrypt a message, and those are not stored anywhere in the clear. Second, the file verification would prevent unidentifiable maniuplation of the ciphertext; any changes made would result if verification failure.



## Bugs and Errors
The code currently supports text files. Some issues were encountered during the construction of a stream cipher in CTR mode.

## Requirements
- Python 3.6
