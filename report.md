# AES Encryption Lab Report
**Course:** [Your Course Name]  
**Date:** [Current Date]  
**Authors:** [Your Team Names]  

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

## Conclusion
All three exercises were successfully implemented and tested. The code demonstrates proper use of AES encryption with secure modes, correct padding implementation, and authenticated encryption. The file encryption utility efficiently handles large files while maintaining security properties through GCM mode.

## References
1. PyCryptodome Documentation: https://pycryptodome.readthedocs.io/
2. NIST Recommendations: SP 800-38A (CBC), SP 800-38D (GCM)
3. PKCS #7: Cryptographic Message Syntax Standard