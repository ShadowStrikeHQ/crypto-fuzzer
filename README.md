# crypto-fuzzer
A targeted fuzzer specifically designed to test cryptographic libraries and implementations by generating semi-valid and malformed inputs to uncover edge cases and potential vulnerabilities. - Focused on Basic cryptographic operations

## Install
`git clone https://github.com/ShadowStrikeHQ/crypto-fuzzer`

## Usage
`./crypto-fuzzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--operation`: The cryptographic operation to fuzz.
- `--input`: The input string to fuzz.
- `--key`: The key to use for encryption/decryption.
- `--iv`: No description provided
- `--salt`: The salt to use for KDF.
- `--iterations`: The number of iterations for KDF. Default: 10000
- `--algorithm`: Hashing algorithm to use.  Options: SHA256, SHA512. Default: SHA256
- `--cipher`: Cipher algorithm to use. Options: AES, Blowfish. Default AES
- `--mode`: Cipher mode to use. Options: CBC, CFB, CTR. Default CBC
- `--tag`: No description provided

## License
Copyright (c) ShadowStrikeHQ
