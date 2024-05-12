import getpass
import os

import pyotp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Client:
    def __init__(self, server):
        self.username = input("Client: Enter client username: ")
        self.password = getpass.getpass("Client: Enter client password: ")
        self.server = server
        self.token = None
        self.totp_secret = None
        self.session_key = None
        self.__salt = os.urandom(16)  # Gera um salt aleatório

        self.derive_authentication_token()

    def derive_pbkdf2_key(self, password, iterations=100):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.__salt,
            iterations=iterations,
            backend=default_backend(),
        )
        if isinstance(password, str) and not isinstance(password, bytes):
            password = password.encode("utf-8")
        key = kdf.derive(password)
        return key

    def derive_authentication_token(self):
        # Deriva token de autenticação usando PBKDF2
        self.token = self.derive_pbkdf2_key(self.password)

    def register_in_server(self):
        # Envia nome do usuário, token e horário para o servidor
        token_valid = self.server.register_client_authentication(self.username, self.token)
        return token_valid

    def generate_totp_secret_in_server_and_register(self):
        totp_secret = self.server.register_client_totp_secret(self.username)
        # Recebe o segredo TOTP do servidor
        self.totp_secret = totp_secret

    def generate_totp_code(self):
        # Gera código TOTP usando o segredo TOTP
        totp = pyotp.TOTP(self.totp_secret)
        return totp.now()

    def send_totp_code(self):
        # Envia o código TOTP para o servidor
        totp_code = self.generate_totp_code()
        totp_code_valid = self.server.receive_totp_code(self.username, totp_code)
        return totp_code_valid

    def establish_session_key(self):
        # Deriva uma chave simétrica de sessão usando PBKDF2
        combined_code = self.token + self.totp_secret.encode("utf-8")
        self.session_key = self.derive_pbkdf2_key(combined_code)
        self.server.receive_session_key(self.username, self.session_key)

    def send_encrypted_message_to_server(self):
        # Cifra a mensagem usando a chave simétrica de sessão e o modo GCM
        message_to_server = input("Client: Enter message to send to server: ").encode()
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message_to_server) + encryptor.finalize()
        full_encrypted_message = iv + encryptor.tag + encrypted_message
        print("Client: Encrypted message sent to server:", full_encrypted_message)
        success_decrypt_by_server = self.server.receive_encrypted_message(
            self.username, full_encrypted_message
        )
        return success_decrypt_by_server

    def receive_and_decrypt_message(self, encrypted_message):
        # Decifra a mensagem usando a chave simétrica de sessão e o modo GCM
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        print(
            f"Client: Message received from server decrypted: {decrypted_message.decode()}",
            end="\n\n",
        )
        return decrypted_message
