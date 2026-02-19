# lab3_1_aes_cbc.py
"""
AES-CBC Encryption/Decryption with PKCS7 Padding
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

BLOCK_SIZE = 16

def pkcs7_pad(data):
    """
    Apply PKCS7 padding to make data length a multiple of BLOCK_SIZE.
    
    Args:
        data (bytes): Data to pad
        
    Returns:
        bytes: Padded data
    """
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    # PKCS7 pads with the byte value equal to the padding length
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data):
    """
    Remove PKCS7 padding from data.
    
    Args:
        data (bytes): Padded data
        
    Returns:
        bytes: Unpadded data
        
    Raises:
        ValueError: If padding is invalid
    """
    if not data:
        raise ValueError("Empty data cannot be unpadded")
    
    pad_len = data[-1]
    
    # Validate padding (all padding bytes should have the same value)
    if pad_len > BLOCK_SIZE or pad_len == 0:
        raise ValueError("Invalid padding length")
    
    # Check if all padding bytes are correct
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    
    return data[:-pad_len]

def encrypt_cbc(plaintext, key=None):
    """
    Encrypt plaintext using AES-CBC mode.
    
    Args:
        plaintext (str or bytes): Data to encrypt
        key (bytes, optional): AES key (32 bytes for AES-256). If None, generate random key.
        
    Returns:
        tuple: (encoded_data, key) where encoded_data is base64 string of IV + ciphertext
    """
    # Convert string to bytes if necessary
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Generate key if not provided
    if key is None:
        key = get_random_bytes(32)  # AES-256
    elif len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256")
    
    # Generate random IV
    iv = get_random_bytes(BLOCK_SIZE)
    
    # Pad plaintext
    padded_data = pkcs7_pad(plaintext)
    
    # Encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_data)
    
    # Combine IV and ciphertext and encode as base64
    combined = iv + ciphertext
    encoded = base64.b64encode(combined).decode('utf-8')
    
    return encoded, key

def decrypt_cbc(encoded_data, key):
    """
    Decrypt data encrypted with AES-CBC mode.
    
    Args:
        encoded_data (str): Base64 string of IV + ciphertext
        key (bytes): AES key
        
    Returns:
        bytes: Decrypted plaintext
        
    Raises:
        ValueError: If decryption fails or padding is invalid
    """
    try:
        # Decode base64
        raw = base64.b64decode(encoded_data)
        
        # Extract IV and ciphertext
        iv = raw[:BLOCK_SIZE]
        ciphertext = raw[BLOCK_SIZE:]
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        plaintext = pkcs7_unpad(padded_plaintext)
        
        return plaintext
    
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def main():
    """Demonstrate AES-CBC encryption/decryption"""
    print("=" * 50)
    print("Lab3.1: AES-CBC Encryption/Decryption Demo")
    print("=" * 50)
    
    # Test data
    test_messages = [
        "Hello, AES CBC!",
        "Short",
        "This is a much longer message that will require multiple blocks of encryption because it exceeds 16 bytes significantly.",
        "1234567890123456"  # Exactly 16 bytes (no padding needed)
    ]
    
    for i, message in enumerate(test_messages, 1):
        print(f"\n--- Test {i}: '{message}' ---")
        
        # Encrypt
        encoded, key = encrypt_cbc(message)
        print(f"Encoded (base64): {encoded[:50]}..." if len(encoded) > 50 else f"Encoded: {encoded}")
        print(f"Key (hex): {key.hex()}")
        
        # Decrypt
        decrypted = decrypt_cbc(encoded, key).decode('utf-8')
        print(f"Decrypted: '{decrypted}'")
        
        # Verify
        assert message == decrypted, "Decryption failed: messages don't match"
        print("✓ Verification passed")
    
    print("\n" + "=" * 50)
    print("All tests passed successfully!")
    print("=" * 50)

if __name__ == "__main__":
    main()