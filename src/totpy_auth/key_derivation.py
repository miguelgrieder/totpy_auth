import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class KeyDerivation:
    def __init__(self, salt=None):
        if salt is None:
            salt = os.urandom(16)  # Gera um salt aleatório
        self.__salt = salt

    def derive_pbkdf2_key(self, password, iterations=100):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.__salt,
            iterations=iterations,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode())
        return key

    def derive_scrypt_key(self, password, salt=None, length=32, n=2**14, r=8, p=1):
        if salt is None:
            salt = self.__salt
        kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p, backend=default_backend())
        key = kdf.derive(password.encode())
        return key

    def serialize_salt(self):
        return self.__salt.hex()

    @staticmethod
    def deserialize_salt(salt_hex):
        return bytes.fromhex(salt_hex)
