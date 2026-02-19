import unittest

class TestMemberSecurity(unittest.TestCase):
    def setUp(self):
        self.member = {"name": "John Doe", "id": "12345", "balance": 500.00}

    def test_end_to_end(self):
        """Tests that a record can be encrypted and recovered perfectly."""
        encrypted = encrypt_member_record(self.member)
        decrypted = decrypt_member_record(encrypted)
        self.assertEqual(self.member, decrypted)

    def test_tamper_detection(self):
        """Tests that changing even one bit of the ciphertext causes failure."""
        encrypted_str = encrypt_member_record(self.member)
        encrypted_bytes = bytearray(base64.b64decode(encrypted_str))
        
        # Tamper: Flip a bit in the ciphertext portion
        encrypted_bytes[-1] = encrypted_bytes[-1] ^ 1
        tampered_str = base64.b64encode(encrypted_bytes).decode('utf-8')
        
        # PyCryptodome raises ValueError if the MAC tag verification fails
        with self.assertRaises(ValueError):
            decrypt_member_record(tampered_str)

if __name__ == "__main__":
    unittest.main()
