import getpass
import os

import pyotp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from totpy_auth.key_derivation import KeyDerivation


class Client:
    def __init__(self):
        self.username = input("Enter username: ")
        self.password = getpass.getpass("Enter password: ")
        self.token = None
        self.totp_secret = None
        self.session_key = None

    def derive_authentication_token(self):
        # Deriva token de autenticação usando PBKDF2
        key_derivation = KeyDerivation()
        self.token = key_derivation.derive_pbkdf2_key(self.password)

    def send_authentication_info(self, server):
        # Envia nome do usuário, token e horário para o servidor
        server.receive_authentication_info(self.username, self.token)

    def receive_totp_secret(self, totp_secret):
        # Recebe o segredo TOTP do servidor
        self.totp_secret = totp_secret

    def generate_totp_code(self):
        # Gera código TOTP usando o segredo TOTP
        totp = pyotp.TOTP(self.totp_secret)
        return totp.now()

    def send_totp_code(self, server):
        # Envia o código TOTP para o servidor
        totp_code = self.generate_totp_code()
        server.receive_totp_code(self.username, totp_code)

    def establish_session_key(self, server):
        # Deriva uma chave simétrica de sessão usando PBKDF2
        combined_code = self.token + self.totp_secret
        key_derivation = KeyDerivation()
        self.session_key = key_derivation.derive_pbkdf2_key(combined_code)
        server.receive_session_key(self.session_key)

    def encrypt_message(self, message):
        # Cifra a mensagem usando a chave simétrica de sessão e o modo GCM
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()
        return iv + encryptor.tag + encrypted_message

    def decrypt_message(self, encrypted_message):
        # Decifra a mensagem usando a chave simétrica de sessão e o modo GCM
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_message
