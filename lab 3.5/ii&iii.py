import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def get_derived_key():
    """Derives a 32-byte (256-bit) key from environment variables."""
    # Fallbacks provided for demonstration
    passphrase = os.getenv("MEMBER_DATA_PASS", "super-secret-passphrase")
    salt = os.getenv("MEMBER_DATA_SALT", "static-salt-16-bytes")
    
    # PBKDF2: Password-Based Key Derivation Function 2
    key = PBKDF2(passphrase, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    return key

def encrypt_member_record(member_dict: dict) -> str:
    """Encrypts a dict and returns a base64 string containing nonce, tag, and ciphertext."""
    key = get_derived_key()
    cipher = AES.new(key, AES.MODE_GCM) # GCM handles padding internally
    
    # Serialize dict to JSON
    data_bytes = json.dumps(member_dict).encode('utf-8')
    
    # Encrypt and generate MAC tag for integrity
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    
    # Package: Nonce (16 bytes) + Tag (16 bytes) + Ciphertext
    combined_payload = cipher.nonce + tag + ciphertext
    return base64.b64encode(combined_payload).decode('utf-8')

def decrypt_member_record(b64_string: str) -> dict:
    """Decrypts the string and verifies integrity. Raises ValueError if tampered."""
    key = get_derived_key()
    raw_data = base64.b64decode(b64_string)
    
    # Split the payload based on standard GCM sizes
    nonce = raw_data[:16]
    tag = raw_data[16:32]
    ciphertext = raw_data[32:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # decrypt_and_verify will raise ValueError if the tag doesn't match
    decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(decrypted_bytes.decode('utf-8'))
