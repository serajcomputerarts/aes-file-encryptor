"""
Unit tests for AES File Encryptor
"""

import unittest
import os
import tempfile
from pathlib import Path
from src.encryptor import AESFileEncryptor


class TestAESFileEncryptor(unittest.TestCase):
    """Test cases for AESFileEncryptor"""
ECHO is off.
    def setUp(self):
        """Set up test fixtures"""
        self.password = "test_password_123"
        self.encryptor = AESFileEncryptor(self.password)
        self.test_dir = tempfile.mkdtemp()
ECHO is off.
    def tearDown(self):
        """Clean up test files"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)
ECHO is off.
    def test_encrypt_decrypt_data(self):
        """Test data encryption and decryption"""
        plaintext = b"Hello, World This is a test message."
ECHO is off.
        ciphertext = self.encryptor.encrypt_data(plaintext)
ECHO is off.
        self.assertNotEqual(plaintext, ciphertext)
ECHO is off.
        decrypted = self.encryptor.decrypt_data(ciphertext)
ECHO is off.
        self.assertEqual(plaintext, decrypted)
ECHO is off.
    def test_encrypt_decrypt_file(self):
        """Test file encryption and decryption"""
        test_file = Path(self.test_dir) / "test.txt"
        test_content = b"Test file content for encryption"
ECHO is off.
        with open(test_file, 'wb') as f:
            f.write(test_content)
ECHO is off.
        success, encrypted_path = self.encryptor.encrypt_file(str(test_file))
        self.assertTrue(success)
        self.assertTrue(Path(encrypted_path).exists())
ECHO is off.
        success, decrypted_path = self.encryptor.decrypt_file(encrypted_path)
        self.assertTrue(success)
        self.assertTrue(Path(decrypted_path).exists())
ECHO is off.
        with open(decrypted_path, 'rb') as f:
            decrypted_content = f.read()
ECHO is off.
        self.assertEqual(test_content, decrypted_content)
ECHO is off.
    def test_empty_password(self):
        """Test that empty password raises error"""
        with self.assertRaises(ValueError):
            AESFileEncryptor("")


if __name__ == '__main__':
    unittest.main()
