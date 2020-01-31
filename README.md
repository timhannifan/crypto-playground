## About
This repository contains Python code to demonstrate cryptographic principles and basic utilities. Do not use this code for production purposes.

## Contents
- `hash.py` generates the SHA-256 hash of a file and prints the hash followed by the filename to STDOUT

## File support
The code supports small and large files containing text or binary content. by iteratively adding chunks of the target file before digesting the hash.

## Error Handling
The following errors should be gracefully handled by the various utilities contained here: 
- Incorrect or non-existent filepaths
- command line arguments
- presence of hashlib

## Requirements
- Python 3.6

## Running the code

Example `hash.py` run command:
```
python hash.py <filename>
```