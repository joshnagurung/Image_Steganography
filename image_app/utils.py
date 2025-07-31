import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

backend = default_backend()
ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=backend
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_text_with_password(text: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode())
    encrypted_data = base64.urlsafe_b64encode(salt + encrypted).decode()
    return encrypted_data

def decrypt_text_with_password(encrypted_data_b64: str, password: str) -> str:
    data = base64.urlsafe_b64decode(encrypted_data_b64)
    salt = data[:16]
    encrypted = data[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)
    return decrypted.decode()
