# lab3_3_file_encryption.py
"""
AES-GCM File Encryption with Streaming Support
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import argparse
import sys

# Constants
CHUNK_SIZE = 64 * 1024  # 64KB chunks for memory-efficient streaming
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16

class FileEncryptor:
    """AES-GCM file encryption/decryption utility with streaming support"""
    
    def __init__(self, key=None):
        """
        Initialize the file encryptor.
        
        Args:
            key (bytes, optional): AES key (32 bytes for AES-256). If None, generate new key.
        """
        if key is None:
            self.key = get_random_bytes(32)  # AES-256
        elif len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes")
        else:
            self.key = key
    
    def encrypt_file(self, input_file, output_file, associated_data=None):
        """
        Encrypt a file using AES-GCM with streaming.
        
        Args:
            input_file (str): Path to input file
            output_file (str): Path to output file (will be created/overwritten)
            associated_data (bytes, optional): Additional authenticated data
            
        Returns:
            tuple: (nonce, tag) used for encryption
            
        Raises:
            IOError: If file operations fail
        """
        # Generate random nonce
        nonce = get_random_bytes(GCM_NONCE_SIZE)
        
        # Create cipher
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        
        # Add associated data if provided
        if associated_data:
            if isinstance(associated_data, str):
                associated_data = associated_data.encode('utf-8')
            cipher.update(associated_data)
        
        # Process file in chunks
        file_size = 0
        try:
            with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                # Write nonce first (needed for decryption)
                f_out.write(nonce)
                
                # Encrypt and write file data in chunks
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    encrypted_chunk = cipher.encrypt(chunk)
                    f_out.write(encrypted_chunk)
                    file_size += len(chunk)
                
                # Get and write the authentication tag
                tag = cipher.digest()
                f_out.write(tag)
            
            print(f"File encrypted successfully: {file_size} bytes processed")
            return nonce, tag
            
        except Exception as e:
            # Clean up output file if encryption fails
            if os.path.exists(output_file):
                os.remove(output_file)
            raise IOError(f"Encryption failed: {e}")
    
    def decrypt_file(self, input_file, output_file, associated_data=None):
        """
        Decrypt a file encrypted with encrypt_file().
        
        Args:
            input_file (str): Path to encrypted input file
            output_file (str): Path to output file (will be created/overwritten)
            associated_data (bytes, optional): Additional authenticated data (must match encryption)
            
        Returns:
            int: Number of bytes decrypted
            
        Raises:
            ValueError: If authentication fails (tampering detected)
            IOError: If file operations fail
        """
        try:
            with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                # Read nonce
                nonce = f_in.read(GCM_NONCE_SIZE)
                if len(nonce) != GCM_NONCE_SIZE:
                    raise ValueError("Invalid file format: missing nonce")
                
                # Get file size for seeking to tag later
                f_in.seek(0, os.SEEK_END)
                file_size = f_in.tell()
                f_in.seek(GCM_NONCE_SIZE)
                
                # Read tag from the end
                f_in.seek(-GCM_TAG_SIZE, os.SEEK_END)
                tag = f_in.read(GCM_TAG_SIZE)
                
                # Reset to after nonce for decryption
                f_in.seek(GCM_NONCE_SIZE)
                
                # Calculate encrypted data size
                encrypted_size = file_size - GCM_NONCE_SIZE - GCM_TAG_SIZE
                
                # Create cipher
                cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
                
                # Add associated data if provided
                if associated_data:
                    if isinstance(associated_data, str):
                        associated_data = associated_data.encode('utf-8')
                    cipher.update(associated_data)
                
                # Decrypt and verify in chunks
                bytes_processed = 0
                while bytes_processed < encrypted_size:
                    # Read chunk (but don't read into the tag area)
                    chunk_size = min(CHUNK_SIZE, encrypted_size - bytes_processed)
                    chunk = f_in.read(chunk_size)
                    
                    if not chunk:
                        break
                    
                    decrypted_chunk = cipher.decrypt(chunk)
                    f_out.write(decrypted_chunk)
                    bytes_processed += len(chunk)
                
                # Verify tag
                try:
                    cipher.verify(tag)
                except ValueError:
                    raise ValueError("Authentication failed: file has been tampered with")
            
            print(f"File decrypted successfully: {bytes_processed} bytes processed")
            return bytes_processed
            
        except ValueError as e:
            # Clean up output file on authentication failure
            if os.path.exists(output_file):
                os.remove(output_file)
            raise
        except Exception as e:
            if os.path.exists(output_file):
                os.remove(output_file)
            raise IOError(f"Decryption failed: {e}")
    
    def encrypt_file_with_metadata(self, input_file, output_file, metadata=None):
        """
        Encrypt file with metadata as associated data.
        
        Args:
            input_file (str): Path to input file
            output_file (str): Path to output file
            metadata (dict, optional): Metadata to authenticate
        """
        # Convert metadata to bytes for AAD
        aad = None
        if metadata:
            import json
            aad = json.dumps(metadata, sort_keys=True).encode('utf-8')
        
        return self.encrypt_file(input_file, output_file, associated_data=aad)
    
    def get_key_hex(self):
        """Return key as hex string for storage"""
        return self.key.hex()
    
    @classmethod
    def from_key_hex(cls, key_hex):
        """Create FileEncryptor from hex key string"""
        key = bytes.fromhex(key_hex)
        return cls(key)

def create_test_file(filename, size_mb=1):
    """Create a test file with sample data"""
    with open(filename, 'wb') as f:
        # Write repeating pattern for easy verification
        pattern = b"Hello World! This is test data for AES-GCM file encryption.\n"
        repeats = (size_mb * 1024 * 1024) // len(pattern) + 1
        for _ in range(repeats):
            f.write(pattern)

def verify_files_equal(file1, file2):
    """Verify two files are identical"""
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        chunk1 = f1.read(CHUNK_SIZE)
        chunk2 = f2.read(CHUNK_SIZE)
        
        while chunk1 and chunk2:
            if chunk1 != chunk2:
                return False
            chunk1 = f1.read(CHUNK_SIZE)
            chunk2 = f2.read(CHUNK_SIZE)
        
        # Check if both files ended
        return not chunk1 and not chunk2

def main():
    """Demonstrate file encryption/decryption"""
    print("=" * 50)
    print("Lab3.3: AES-GCM File Encryption Demo")
    print("=" * 50)
    
    # Test files
    original_file = "test_original.dat"
    encrypted_file = "test_encrypted.bin"
    decrypted_file = "test_decrypted.dat"
    
    try:
        # Create test file (1MB)
        print("\n1. Creating test file...")
        create_test_file(original_file, size_mb=1)
        original_size = os.path.getsize(original_file)
        print(f"   Created {original_file} ({original_size:,} bytes)")
        
        # Create encryptor
        print("\n2. Initializing encryptor...")
        encryptor = FileEncryptor()
        print(f"   Key (hex): {encryptor.get_key_hex()}")
        
        # Encrypt file with metadata
        print("\n3. Encrypting file...")
        metadata = {
            "filename": original_file,
            "created_by": "AES-GCM Lab",
            "version": "1.0"
        }
        encryptor.encrypt_file_with_metadata(original_file, encrypted_file, metadata)
        encrypted_size = os.path.getsize(encrypted_file)
        print(f"   Encrypted to {encrypted_file} ({encrypted_size:,} bytes)")
        print(f"   Overhead: {encrypted_size - original_size:,} bytes (nonce + tag)")
        
        # Decrypt file
        print("\n4. Decrypting file...")
        encryptor.decrypt_file(encrypted_file, decrypted_file, 
                              associated_data=json.dumps(metadata, sort_keys=True).encode('utf-8'))
        decrypted_size = os.path.getsize(decrypted_file)
        print(f"   Decrypted to {decrypted_file} ({decrypted_size:,} bytes)")
        
        # Verify
        print("\n5. Verifying integrity...")
        if verify_files_equal(original_file, decrypted_file):
            print("   ✓ Verification passed: files are identical")
        else:
            print("   ✗ Verification failed: files differ")
        
        # Tampering demonstration
        print("\n6. Demonstrating tamper detection...")
        try:
            # Corrupt the encrypted file
            with open(encrypted_file, 'r+b') as f:
                f.seek(100)  # Go to position 100
                f.write(b'X')  # Corrupt one byte
            
            # Try to decrypt
            encryptor.decrypt_file(encrypted_file, "test_tampered.dat", 
                                  associated_data=json.dumps(metadata, sort_keys=True).encode('utf-8'))
            print("   ✗ Tampering not detected (this should not happen)")
        except ValueError as e:
            print(f"   ✓ Tampering detected: {e}")
        
    finally:
        # Clean up
        print("\n7. Cleaning up test files...")
        for f in [original_file, encrypted_file, decrypted_file, "test_tampered.dat"]:
            if os.path.exists(f):
                os.remove(f)
                print(f"   Removed {f}")

if __name__ == "__main__":
    import json
    main()