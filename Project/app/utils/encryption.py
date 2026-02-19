import base64
import os
from cryptography.fernet import Fernet


def generate_key_from_password(master_password: str, salt: bytes = None) -> bytes:
    """
    Generate a Fernet key from the master password using simple key derivation.
    
    Args:
        master_password: The user's master password
        salt: Optional salt bytes. If not provided, generates a new one.
    
    Returns:
        bytes: The derived key
    """
    if salt is None:
        salt = os.urandom(16)
    
    # Use PBKDF2 with simple implementation
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for Fernet
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    return key


def encrypt_password(password: str, master_password: str, salt: str) -> str:
    """
    Encrypt a password using Fernet with the master password.
    
    Args:
        password: The password to encrypt
        master_password: The user's master password
        salt: The salt string (base64 encoded)
    
    Returns:
        str: The encrypted password (includes salt as prefix, format: salt:encrypted)
    """
    # Decode salt from base64
    salt_bytes = base64.b64decode(salt)
    
    # Generate key from master password and salt
    key = generate_key_from_password(master_password, salt_bytes)
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    
    # Return: salt:encrypted_password (both base64 encoded)
    return f"{salt}:{encrypted.decode()}"


def decrypt_password(encrypted_data: str, master_password: str, salt: str) -> str:
    """
    Decrypt a password using Fernet with the master password.
    
    Args:
        encrypted_data: The encrypted data (format: salt:encrypted)
        master_password: The user's master password
        salt: The salt string (base64 encoded)
    
    Returns:
        str: The decrypted password
    """
    # Decode salt from base64
    salt_bytes = base64.b64decode(salt)
    
    # Get the encrypted part (after the first colon which is the stored salt)
    parts = encrypted_data.split(':', 1)
    if len(parts) == 2:
        encrypted_password = parts[1]
    else:
        encrypted_password = encrypted_data
    
    # Generate key from master password and salt
    key = generate_key_from_password(master_password, salt_bytes)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_password.encode())
    
    return decrypted.decode()


def generate_salt() -> str:
    """Generate a random salt for key derivation."""
    return base64.b64encode(os.urandom(16)).decode()
