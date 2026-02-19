import base64
import os
from cryptography.fernet import Fernet


def generate_key_from_password(master_password: str, salt: bytes = None) -> bytes:
    if salt is None:
        salt = os.urandom(16)
    
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    return key


def encrypt_password(password: str, master_password: str, salt: str) -> str:
    salt_bytes = base64.b64decode(salt)
    key = generate_key_from_password(master_password, salt_bytes)
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    
    return f"{salt}:{encrypted.decode()}"


def decrypt_password(encrypted_data: str, master_password: str, salt: str) -> str:
    salt_bytes = base64.b64decode(salt)
    
    parts = encrypted_data.split(':', 1)
    if len(parts) == 2:
        encrypted_password = parts[1]
    else:
        encrypted_password = encrypted_data
    
    key = generate_key_from_password(master_password, salt_bytes)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_password.encode())
    
    return decrypted.decode()


def generate_salt() -> str:
    return base64.b64encode(os.urandom(16)).decode()
