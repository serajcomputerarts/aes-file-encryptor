"""
Core encryption and decryption functionality using AES-256-CBC
"""

import os
from pathlib import Path
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class AESFileEncryptor:
    """
    AES-256-CBC file encryption and decryption handler
    
    Attributes:
        SALT_SIZE (int): Size of salt in bytes
        IV_SIZE (int): Size of initialization vector in bytes
        KEY_SIZE (int): Size of encryption key in bytes
        ITERATIONS (int): Number of PBKDF2 iterations
    """
    
    SALT_SIZE = 32
    IV_SIZE = 16
    KEY_SIZE = 32
    ITERATIONS = 100000
    ENCRYPTED_EXTENSION = '.encrypted'
    
    def __init__(self, password: str, salt: Optional[bytes] = None):
        """
        Initialize encryptor with password
        
        Args:
            password: Master password for encryption/decryption
            salt: Optional salt (will be generated if not provided)
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        self.password = password.encode('utf-8')
        self.salt = salt or os.urandom(self.SALT_SIZE)
        self.key = self._derive_key()
    
    def _derive_key(self) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Returns:
            Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=self.salt,
            iterations=self.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(self.password)
    
    @staticmethod
    def _pad_data(data: bytes) -> bytes:
        """
        Apply PKCS7 padding to data
        
        Args:
            data: Data to pad
            
        Returns:
            Padded data
        """
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def _unpad_data(data: bytes) -> bytes:
        """
        Remove PKCS7 padding from data
        
        Args:
            data: Padded data
            
        Returns:
            Unpadded data
        """
        padding_length = data[-1]
        return data[:-padding_length]
    
    def encrypt_data(self, plaintext: bytes) -> bytes:
        """
        Encrypt data using AES-256-CBC
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted data with IV prepended
        """
        # Generate random IV
        iv = os.urandom(self.IV_SIZE)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        padded_data = self._pad_data(plaintext)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def decrypt_data(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data using AES-256-CBC
        
        Args:
            ciphertext: Encrypted data with IV prepended
            
        Returns:
            Decrypted data
        """
        # Extract IV and ciphertext
        iv = ciphertext[:self.IV_SIZE]
        encrypted_data = ciphertext[self.IV_SIZE:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt data
        padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
        plaintext = self._unpad_data(padded_plaintext)
        
        return plaintext
    
    def encrypt_file(self, file_path: str, remove_original: bool = True) -> Tuple[bool, str]:
        """
        Encrypt a single file
        
        Args:
            file_path: Path to file to encrypt
            remove_original: Whether to remove original file after encryption
            
        Returns:
            Tuple of (success, result_path_or_error_message)
        """
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                return False, f"File not found: {file_path}"
            
            if not file_path.is_file():
                return False, f"Not a file: {file_path}"
            
            # Read file content
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Encrypt data
            encrypted_data = self.encrypt_data(plaintext)
            
            # Write encrypted file with salt
            encrypted_path = str(file_path) + self.ENCRYPTED_EXTENSION
            with open(encrypted_path, 'wb') as f:
                f.write(self.salt + encrypted_data)
            
            # Remove original file if requested
            if remove_original:
                file_path.unlink()
            
            return True, encrypted_path
            
        except Exception as e:
            return False, f"Encryption error: {str(e)}"
    
    def decrypt_file(self, file_path: str, remove_encrypted: bool = True) -> Tuple[bool, str]:
        """
        Decrypt a single file
        
        Args:
            file_path: Path to encrypted file
            remove_encrypted: Whether to remove encrypted file after decryption
            
        Returns:
            Tuple of (success, result_path_or_error_message)
        """
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                return False, f"File not found: {file_path}"
            
            if not str(file_path).endswith(self.ENCRYPTED_EXTENSION):
                return False, f"Not an encrypted file: {file_path}"
            
            # Read encrypted file
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Extract salt and verify
            file_salt = encrypted_data[:self.SALT_SIZE]
            ciphertext = encrypted_data[self.SALT_SIZE:]
            
            # Create new encryptor with file's salt
            temp_encryptor = AESFileEncryptor(self.password.decode('utf-8'), file_salt)
            
            # Decrypt data
            plaintext = temp_encryptor.decrypt_data(ciphertext)
            
            # Write decrypted file
            original_path = str(file_path).replace(self.ENCRYPTED_EXTENSION, '')
            with open(original_path, 'wb') as f:
                f.write(plaintext)
            
            # Remove encrypted file if requested
            if remove_encrypted:
                file_path.unlink()
            
            return True, original_path
            
        except Exception as e:
            return False, f"Decryption error: {str(e)}"
    
    def get_salt(self) -> bytes:
        """Get the salt used for key derivation"""
        return self.salt