# AES Encryption Lab Report
**Course:** [APT 3090]  
**Date:** 02/20/26
**Authors:**
    - Timothy Obote 666548
    - Justin Malu 660955
    - Tevin
    

## Executive Summary
This lab implemented three AES encryption exercises using the PyCryptodome library in Python:
1. **Lab3.1**: AES-CBC mode with PKCS7 padding for text encryption
2. **Lab3.2**: AES-GCM authenticated encryption with tamper detection
3. **Lab3.3**: AES-GCM file encryption with streaming support

All implementations successfully demonstrate correct encryption/decryption and incorporate security best practices.

## Design Decisions

### Lab3.1: AES-CBC with PKCS7 Padding
**Key Features:**
- **AES-256**: Selected for strong security (256-bit keys)
- **Random IV**: Generated for each encryption using `get_random_bytes()`
- **PKCS7 Padding**: Standard padding scheme with validation
- **Base64 Encoding**: For safe storage/transmission

**Security Considerations:**
- IV is randomly generated and prepended to ciphertext
- Padding validation prevents padding oracle attacks
- No IV reuse with the same key

### Lab3.2: AES-GCM Authenticated Encryption
**Key Features:**
- **12-byte Nonce**: Recommended size for GCM mode
- **16-byte Authentication Tag**: Provides integrity verification
- **Associated Data (AAD)**: Optional metadata authentication
- **Tamper Detection**: Automatic verification on decryption

**Security Considerations:**
- Nonce uniqueness ensures semantic security
- Authentication tag prevents ciphertext manipulation
- AAD protects metadata integrity

### Lab3.3: File Encryption with Streaming
**Key Features:**
- **Chunk-based Processing**: 64KB chunks for memory efficiency
- **File Format**: [nonce][encrypted data][tag]
- **Metadata Authentication**: File properties as AAD
- **Error Handling**: Automatic cleanup on failure

**Security Considerations:**
- Streaming prevents loading entire files into memory
- Tag verification ensures file integrity
- Metadata authentication prevents filename tampering

## Test Results

### Lab3.1: AES-CBC Text Encryption
| Test Case | Input | Result | Verification |
|-----------|-------|--------|--------------|
| Normal text | "Hello, AES CBC!" | ✓ Success | Matches original |
| Short text | "Short" | ✓ Success | Matches original |
| Long text | Multi-block message | ✓ Success | Matches original |
| Exact block | 16 bytes | ✓ Success | Matches original |

### Lab3.2: AES-GCM Authenticated Encryption
| Test Case | Result | Notes |
|-----------|--------|-------|
| Normal encryption/decryption | ✓ Success | Message integrity preserved |
| Ciphertext tampering | ✓ Detected | ValueError raised |
| Wrong associated data | ✓ Detected | Authentication failed |
| Wrong key | ✓ Detected | Decryption failed |

### Lab3.3: File Encryption
| Test Case | Result | Notes |
|-----------|--------|-------|
| 1MB file encryption/decryption | ✓ Success | Files identical |
| With metadata authentication | ✓ Success | Metadata verified |
| Tampered file detection | ✓ Detected | Authentication failed |
| Memory efficiency | ✓ Success | 64KB chunks used |

## Security Analysis

### Strengths
1. **Key Generation**: Uses cryptographically secure random generator
2. **IV/Nonce Uniqueness**: Random generation prevents reuse
3. **Authenticated Encryption**: GCM provides both confidentiality and integrity
4. **Padding Validation**: Prevents oracle attacks
5. **Error Handling**: Secure failure modes with cleanup

### Potential Improvements
1. **Key Derivation**: Add PBKDF2 for password-based encryption
2. **Key Storage**: Implement secure key management
3. **Constant-time Operations**: For side-channel resistance
4. **Additional Modes**: Support for CCM, EAX for comparison

### Lab 3.4: PBKDF2 Key Derivation and AES-GCM Authentication
This implementation focuses on "Password-Based Encryption" (PBE), ensuring that even weak user passwords are transformed into high-entropy cryptographic keys before being used for AES-256.

**Key Features**:
-  **PBKDF2 Key Stretching**: Uses the PBKDF2 algorithm with 200,000 iterations. This "stretches" the password, making offline brute-force and dictionary attacks computationally expensive for an attacker.
-  **SHA-256 HMAC**: Employs SHA-256 as the underlying pseudorandom function for the key derivation process.
-  **Cryptographic Salt**: A random 16-byte salt is generated for every encryption. This ensures that two users with the same password will result in entirely different ciphertexts, preventing "rainbow table" attacks.
- **Authenticated Encryption (GCM)**: Unlike CBC mode, GCM provides built-in integrity. It generates a 16-byte MAC tag that is verified during decryption to ensure the data has not been tampered with.

**Security Considerations**:
- **Implicit Authentication**: The decrypt_and_verify method is used to catch any bit-level manipulation. If the ciphertext or the tag is altered by even a single bit, the system raises a ValueError rather than returning corrupted data.
- **Nonce Uniqueness**: A 16-byte nonce is auto-generated for each session. In GCM mode, reusing a nonce with the same key is a critical failure; this implementation avoids that by generating a fresh nonce per execution.
- **Data Packaging Format**: To ensure the ciphertext is portable, the implementation prepends all necessary metadata into a single byte-bundle before Base64 encoding:

### Lab 3.5
The design of this system relies on Key Derivation to turn a simple passphrase into a high-entropy 256-bit key. By using PBKDF2 with 100,000 iterations, we essentially "stretch" the password to make it much harder for a computer to guess. While this adds a tiny delay when the code first starts, it prevents "brute-force" attacks where a hacker tries to crack your password by testing millions of combinations every second.
For the actual encryption, we chose AES-GCM because it acts like a "security seal" for your data. Most encryption only hides information, but GCM also provides Integrity. It generates a unique mathematical "tag" for every record; if a single digit of a member?s balance is changed in the database, the decryption will fail immediately. This ensures that even if someone can't read the data, they also can't tamper with it without being caught.
To keep the system flexible and safe, we use Environment Variables instead of writing passwords directly in the code. This separation ensures that the "lock" (your Python script) and the "key" (the passphrase) are never stored in the same place. It adds a small step to the setup process, but it prevents the common mistake of accidentally sharing secret keys when uploading code to platforms like GitHub.

## Conclusion
All three exercises were successfully implemented and tested. The code demonstrates proper use of AES encryption with secure modes, correct padding implementation, and authenticated encryption. The file encryption utility efficiently handles large files while maintaining security properties through GCM mode.

## References
1. PyCryptodome Documentation: https://pycryptodome.readthedocs.io/
2. NIST Recommendations: SP 800-38A (CBC), SP 800-38D (GCM)
3. PKCS #7: Cryptographic Message Syntax Standard
