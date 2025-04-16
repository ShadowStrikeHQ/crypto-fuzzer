import argparse
import logging
import secrets
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """Sets up the argument parser for the crypto-fuzzer."""
    parser = argparse.ArgumentParser(description="A targeted fuzzer for cryptographic libraries.")
    parser.add_argument("--operation", choices=["hash", "kdf", "encrypt", "decrypt"], required=True, help="The cryptographic operation to fuzz.")
    parser.add_argument("--input", type=str, help="The input string to fuzz.")
    parser.add_argument("--key", type=str, help="The key to use for encryption/decryption.")
    parser.add_argument("--iv", type=str, help="The Initialization Vector (IV) to use.")
    parser.add_argument("--salt", type=str, help="The salt to use for KDF.")
    parser.add_argument("--iterations", type=int, default=10000, help="The number of iterations for KDF. Default: 10000")
    parser.add_argument("--algorithm", type=str, default="SHA256", help="Hashing algorithm to use.  Options: SHA256, SHA512. Default: SHA256")
    parser.add_argument("--cipher", type=str, default="AES", help="Cipher algorithm to use. Options: AES, Blowfish. Default AES")
    parser.add_argument("--mode", type=str, default="CBC", help="Cipher mode to use. Options: CBC, CFB, CTR. Default CBC")
    parser.add_argument("--tag", type=str, help="The authentication tag for GCM mode (decryption)")
    return parser.parse_args()

def fuzz_hash(input_string, algorithm="SHA256"):
    """Fuzzes a hashing operation."""
    if not input_string:
        logging.error("Input string cannot be empty for hashing.")
        return

    try:
        if algorithm == "SHA256":
            hasher = hashes.SHA256()
        elif algorithm == "SHA512":
            hasher = hashes.SHA512()
        else:
            logging.error(f"Unsupported hashing algorithm: {algorithm}")
            return

        hasher.update(input_string.encode('utf-8'))
        digest = hasher.finalize()
        logging.info(f"Hashed input: {input_string} using {algorithm}")
        logging.info(f"Digest: {digest.hex()}")

        #Fuzzing by slightly changing the input
        for i in range(5): #Try 5 different fuzzes
            fuzzed_input = input_string + chr(ord('a') + i)
            hasher = hashes.SHA256() #reinitialize to ensure clean slate
            hasher.update(fuzzed_input.encode('utf-8'))
            fuzzed_digest = hasher.finalize()
            logging.info(f"Fuzzed input: {fuzzed_input}")
            logging.info(f"Fuzzed Digest: {fuzzed_digest.hex()}")


    except Exception as e:
        logging.error(f"Error during hashing: {e}")

def fuzz_kdf(password, salt, iterations=10000):
    """Fuzzes a Key Derivation Function (KDF)."""
    if not password or not salt:
        logging.error("Password and salt cannot be empty for KDF.")
        return

    try:
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8') if isinstance(salt, str) else salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password_bytes)
        logging.info(f"Derived key using PBKDF2HMAC with password: {password}, salt: {salt}, iterations: {iterations}")
        logging.info(f"Derived Key: {key.hex()}")

        # Fuzzing iterations
        for i in [iterations // 2, iterations * 2]:  #Try variations of the iteration count
            try:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt_bytes,
                    iterations=i,
                    backend=default_backend()
                )
                key = kdf.derive(password_bytes)
                logging.info(f"Fuzzed iterations: {i}, Derived Key: {key.hex()}")
            except Exception as e:
                logging.error(f"Error with fuzzed iterations {i}: {e}")


    except Exception as e:
        logging.error(f"Error during KDF: {e}")

def fuzz_encrypt(plaintext, key, iv, cipher_algorithm="AES", cipher_mode="CBC"):
    """Fuzzes encryption operation."""
    if not plaintext or not key or not iv:
        logging.error("Plaintext, key, and IV cannot be empty for encryption.")
        return

    try:
        key_bytes = key.encode('utf-8')[:32] #truncate if longer than 32
        iv_bytes = iv.encode('utf-8')[:16]  #truncate if longer than 16
        plaintext_bytes = plaintext.encode('utf-8')

        if cipher_algorithm == "AES":
            if cipher_mode == "CBC":
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
            elif cipher_mode == "CFB":
                 cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv_bytes), backend=default_backend())
            elif cipher_mode == "CTR":
                cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv_bytes), backend=default_backend())
            else:
                logging.error(f"Unsupported cipher mode: {cipher_mode}")
                return
        elif cipher_algorithm == "Blowfish":
            if cipher_mode == "CBC":
                cipher = Cipher(algorithms.Blowfish(key_bytes[:16]), modes.CBC(iv_bytes[:8]), backend=default_backend()) #blowfish key size is smaller
            elif cipher_mode == "CFB":
                cipher = Cipher(algorithms.Blowfish(key_bytes[:16]), modes.CFB(iv_bytes[:8]), backend=default_backend())
            elif cipher_mode == "CTR":
                cipher = Cipher(algorithms.Blowfish(key_bytes[:16]), modes.CTR(iv_bytes[:8]), backend=default_backend())
            else:
                logging.error(f"Unsupported cipher mode: {cipher_mode}")
                return
        else:
            logging.error(f"Unsupported cipher algorithm: {cipher_algorithm}")
            return

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        logging.info(f"Encrypted plaintext: {plaintext} using {cipher_algorithm} with {cipher_mode}")
        logging.info(f"Ciphertext: {ciphertext.hex()}")

        # Fuzzing the IV
        fuzzed_iv = os.urandom(len(iv_bytes)) #Random IV of same length
        if cipher_algorithm == "AES":
            if cipher_mode == "CBC":
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(fuzzed_iv), backend=default_backend())
            elif cipher_mode == "CFB":
                 cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(fuzzed_iv), backend=default_backend())
            elif cipher_mode == "CTR":
                cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(fuzzed_iv), backend=default_backend())
        elif cipher_algorithm == "Blowfish":
            if cipher_mode == "CBC":
                cipher = Cipher(algorithms.Blowfish(key_bytes[:16]), modes.CBC(fuzzed_iv[:8]), backend=default_backend()) #blowfish key size is smaller
            elif cipher_mode == "CFB":
                cipher = Cipher(algorithms.Blowfish(key_bytes[:16]), modes.CFB(fuzzed_iv[:8]), backend=default_backend())
            elif cipher_mode == "CTR":
                cipher = Cipher(algorithms.Blowfish(key_bytes[:16]), modes.CTR(fuzzed_iv[:8]), backend=default_backend())

        encryptor = cipher.encryptor()

        try:
            fuzzed_ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
            logging.info(f"Fuzzed IV, Ciphertext: {fuzzed_ciphertext.hex()}")
        except Exception as e:
            logging.error(f"Fuzz encrypt error with IV: {e}")

    except Exception as e:
        logging.error(f"Error during encryption: {e}")

def fuzz_decrypt(ciphertext, key, iv, cipher_algorithm="AES", cipher_mode="CBC", tag=None):
    """Fuzzes decryption operation."""
    if not ciphertext or not key or not iv:
        logging.error("Ciphertext, key, and IV cannot be empty for decryption.")
        return

    try:
        key_bytes = key.encode('utf-8')[:32] #truncate if longer than 32
        iv_bytes = iv.encode('utf-8')[:16]  #truncate if longer than 16
        ciphertext_bytes = bytes.fromhex(ciphertext)

        if cipher_algorithm == "AES":
            if cipher_mode == "CBC":
                cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
            elif cipher_mode == "CFB":
                 cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv_bytes), backend=default_backend())
            elif cipher_mode == "CTR":
                cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv_bytes), backend=default_backend())
            elif cipher_mode == "GCM":
                if tag is None:
                    logging.error("Tag must be provided for GCM mode")
                    return
                tag_bytes = bytes.fromhex(tag)
                cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv_bytes, tag_bytes), backend=default_backend())

            else:
                logging.error(f"Unsupported cipher mode: {cipher_mode}")
                return
        elif cipher_algorithm == "Blowfish":
            if cipher_mode == "CBC":
                cipher = Cipher(algorithms.Blowfish(key_bytes[:16]), modes.CBC(iv_bytes[:8]), backend=default_backend()) #blowfish key size is smaller
            elif cipher_mode == "CFB":
                cipher = Cipher(algorithms.Blowfish(key_bytes[:16]), modes.CFB(iv_bytes[:8]), backend=default_backend())
            elif cipher_mode == "CTR":
                cipher = Cipher(algorithms.Blowfish(key_bytes[:16]), modes.CTR(iv_bytes[:8]), backend=default_backend())

            else:
                logging.error(f"Unsupported cipher mode: {cipher_mode}")
                return

        else:
            logging.error(f"Unsupported cipher algorithm: {cipher_algorithm}")
            return

        decryptor = cipher.decryptor()
        try:
            plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
            logging.info(f"Decrypted ciphertext: {ciphertext} using {cipher_algorithm} with {cipher_mode}")
            logging.info(f"Plaintext: {plaintext.decode('utf-8')}")
        except InvalidTag:
             logging.error("Invalid Tag")


        #Fuzzing the Ciphertext
        fuzzed_ciphertext = bytearray(ciphertext_bytes)
        fuzzed_ciphertext[0] ^= 0x01  #Flip a bit in the first byte
        fuzzed_ciphertext_bytes = bytes(fuzzed_ciphertext)

        decryptor = cipher.decryptor()
        try:
            plaintext = decryptor.update(fuzzed_ciphertext_bytes) + decryptor.finalize()
            logging.info(f"Fuzzed Ciphertext, Plaintext: {plaintext.decode('utf-8')}")
        except Exception as e:
            logging.error(f"Error during decryption after fuzzing ciphertext: {e}")


    except Exception as e:
        logging.error(f"Error during decryption: {e}")


def main():
    """Main function to execute the crypto-fuzzer."""
    args = setup_argparse()

    if args.operation == "hash":
        fuzz_hash(args.input, args.algorithm)
    elif args.operation == "kdf":
        fuzz_kdf(args.input, args.salt, args.iterations)
    elif args.operation == "encrypt":
        fuzz_encrypt(args.input, args.key, args.iv, args.cipher, args.mode)
    elif args.operation == "decrypt":
        fuzz_decrypt(args.input, args.key, args.iv, args.cipher, args.mode, args.tag)
    else:
        logging.error("Invalid operation specified.")

if __name__ == "__main__":
    main()

# Example Usage:
# python main.py --operation hash --input "test_string"
# python main.py --operation kdf --input "password" --salt "salt" --iterations 20000
# python main.py --operation encrypt --input "plaintext" --key "secret_key" --iv "initialization_vector" --cipher AES --mode CBC
# python main.py --operation decrypt --input "fuzzed_ciphertext_hex" --key "secret_key" --iv "initialization_vector" --cipher AES --mode CBC
# Example with GCM
# python main.py --operation encrypt --input "plaintext" --key "secret_key" --iv "initialization_vector" --cipher AES --mode GCM
# The encryption run will give you the Ciphertext and Tag, then use these in the following:
# python main.py --operation decrypt --input "ciphertext_hex" --key "secret_key" --iv "initialization_vector" --cipher AES --mode GCM --tag "authentication_tag"