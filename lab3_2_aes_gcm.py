# lab3_2_aes_gcm.py
"""
AES-GCM Authenticated Encryption with Tamper Detection

"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# GCM recommended nonce size
GCM_NONCE_SIZE = 12
# GCM tag size (16 bytes is standard)
GCM_TAG_SIZE = 16

def encrypt_gcm(plaintext, key=None, associated_data=None):
    """
    Encrypt and authenticate plaintext using AES-GCM mode.
    
    Args:
        plaintext (str or bytes): Data to encrypt
        key (bytes, optional): AES key (32 bytes for AES-256)
        associated_data (bytes, optional): Additional authenticated data (AAD)
        
    Returns:
        tuple: (encoded_data, key) where encoded_data is base64 string of nonce + tag + ciphertext
    """
    # Convert string to bytes if necessary
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    if associated_data and isinstance(associated_data, str):
        associated_data = associated_data.encode('utf-8')
    
    # Generate key if not provided
    if key is None:
        key = get_random_bytes(32)  # AES-256
    elif len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256")
    
    # Generate random nonce
    nonce = get_random_bytes(GCM_NONCE_SIZE)
    
    # Create cipher and encrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Add associated data if provided
    if associated_data:
        cipher.update(associated_data)
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Combine nonce, tag, and ciphertext, then encode as base64
    # Format: [nonce][tag][ciphertext]
    combined = nonce + tag + ciphertext
    encoded = base64.b64encode(combined).decode('utf-8')
    
    return encoded, key

def decrypt_gcm(encoded_data, key, associated_data=None):
    """
    Decrypt and verify data encrypted with AES-GCM mode.
    
    Args:
        encoded_data (str): Base64 string of nonce + tag + ciphertext
        key (bytes): AES key
        associated_data (bytes, optional): Additional authenticated data (must match encryption)
        
    Returns:
        bytes: Decrypted plaintext
        
    Raises:
        ValueError: If decryption fails or tampering is detected
    """
    try:
        # Decode base64
        raw = base64.b64decode(encoded_data)
        
        if len(raw) < GCM_NONCE_SIZE + GCM_TAG_SIZE:
            raise ValueError("Encoded data too short")
        
        # Extract components
        nonce = raw[:GCM_NONCE_SIZE]
        tag = raw[GCM_NONCE_SIZE:GCM_NONCE_SIZE + GCM_TAG_SIZE]
        ciphertext = raw[GCM_NONCE_SIZE + GCM_TAG_SIZE:]
        
        if associated_data and isinstance(associated_data, str):
            associated_data = associated_data.encode('utf-8')
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Add associated data if provided
        if associated_data:
            cipher.update(associated_data)
        
        # This will raise ValueError if tag verification fails
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext
    
    except ValueError as e:
        # Re-raise with more context
        raise ValueError(f"Tampering detected or decryption failed: {e}")
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def demonstrate_tampering():
    """Demonstrate that GCM detects tampering"""
    print("\n" + "=" * 50)
    print("Tamper Detection Demonstration")
    print("=" * 50)
    
    # Original encryption
    original_message = "This is a top secret message!"
    associated = "metadata:user=admin"
    
    print(f"Original message: '{original_message}'")
    
    # Encrypt
    encoded, key = encrypt_gcm(original_message, associated_data=associated)
    print(f"Encoded (first 20 chars): {encoded[:20]}...")
    
    # Successful decryption
    print("\n1. Normal decryption:")
    decrypted = decrypt_gcm(encoded, key, associated_data=associated).decode('utf-8')
    print(f"   Decrypted: '{decrypted}'")
    print("   ✓ Verification passed")
    
    # Tampering attempt 1: Modify ciphertext
    print("\n2. Tampering attempt - Modifying ciphertext:")
    try:
        raw = base64.b64decode(encoded)
        # Corrupt a byte in the ciphertext
        corrupted = bytearray(raw)
        corrupted[-5] ^= 0xFF  # Flip bits in last ciphertext byte
        corrupted_encoded = base64.b64encode(corrupted).decode('utf-8')
        
        decrypted = decrypt_gcm(corrupted_encoded, key, associated_data=associated)
        print(f"   Decrypted: '{decrypted.decode('utf-8')}'")  # This shouldn't execute
    except ValueError as e:
        print(f"   ✓ Detection successful: {e}")
    
    # Tampering attempt 2: Wrong associated data
    print("\n3. Tampering attempt - Wrong associated data:")
    try:
        wrong_associated = "metadata:user=hacker"
        decrypted = decrypt_gcm(encoded, key, associated_data=wrong_associated)
        print(f"   Decrypted: '{decrypted.decode('utf-8')}'")  # This shouldn't execute
    except ValueError as e:
        print(f"   ✓ Detection successful: {e}")
    
    # Tampering attempt 3: Wrong key
    print("\n4. Tampering attempt - Wrong key:")
    try:
        wrong_key = get_random_bytes(32)
        decrypted = decrypt_gcm(encoded, wrong_key, associated_data=associated)
        print(f"   Decrypted: '{decrypted.decode('utf-8')}'")  # This shouldn't execute
    except ValueError as e:
        print(f"   ✓ Detection successful: {e}")

def main():
    """Demonstrate AES-GCM encryption/decryption"""
    print("=" * 50)
    print("Lab3.2: AES-GCM Authenticated Encryption Demo")
    print("=" * 50)
    
    # Test with various messages
    test_messages = [
        "Sensitive message",
        "Another confidential data",
        "Short"
    ]
    
    for i, message in enumerate(test_messages, 1):
        print(f"\n--- Test {i}: '{message}' ---")
        
        # Encrypt with associated data
        associated = f"test_{i}:additional_data"
        encoded, key = encrypt_gcm(message, associated_data=associated)
        
        print(f"Encoded (base64): {encoded[:30]}...")
        print(f"Key (hex): {key.hex()[:16]}...")
        
        # Decrypt successfully
        decrypted = decrypt_gcm(encoded, key, associated_data=associated).decode('utf-8')
        print(f"Decrypted: '{decrypted}'")
        
        # Verify
        assert message == decrypted, "Decryption failed"
        print("✓ Verification passed")
    
    # Demonstrate tamper detection
    demonstrate_tampering()
    
    print("\n" + "=" * 50)
    print("All tests completed successfully!")
    print("=" * 50)

if __name__ == "__main__":
    main()