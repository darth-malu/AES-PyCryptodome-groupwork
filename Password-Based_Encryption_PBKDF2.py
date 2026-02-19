from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64


def encrypt_data(password, plaintext):
    # 1. Setup parameters
    password_bytes = password.encode() if isinstance(password, str) else password
    salt = get_random_bytes(16)

    # 2. Derive 32-byte key (for AES-256) using PBKDF2
    # We use SHA256 as the underlying HMAC function
    key = PBKDF2(password_bytes, salt, dkLen=32, count=200000, hmac_hash_module=SHA256)

    # 3. Encrypt using AES-GCM
    cipher = AES.new(key, AES.MODE_GCM)  # Nonce is auto-generated if not provided
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

    # 4. Combine and encode for storage: salt(16) + nonce(16) + tag(16) + ciphertext(var)
    # NOTE: PyCryptodome's GCM nonce defaults to 16 bytes unless specified
    combined = salt + cipher.nonce + tag + ciphertext
    return base64.b64encode(combined).decode()


def decrypt_data(password, encoded_bundle):
    # 1. Decode and unpack
    data = base64.b64decode(encoded_bundle)
    salt = data[:16]
    nonce = data[16:32]
    tag = data[32:48]
    ciphertext = data[48:]

    # 2. Re-derive the same key using the stored salt
    password_bytes = password.encode() if isinstance(password, str) else password
    key = PBKDF2(password_bytes, salt, dkLen=32, count=200000, hmac_hash_module=SHA256)

    # 3. Decrypt and Verify
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except ValueError:
        return "Decryption failed: Key incorrect or data corrupted."


# Testing the Lab Task
password = "my secret password"
secret_message = "Super secret IMPORTANT encrypted data 🐰"

encrypted_bundle = encrypt_data(password, secret_message)
print(f"Stored String (Base64):\n{encrypted_bundle}\n")

decrypted_message = decrypt_data(password, encrypted_bundle)
print(f"Decrypted Result: {decrypted_message}")
