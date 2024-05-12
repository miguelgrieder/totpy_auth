import os

import pyotp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Server:
    def __init__(self):
        self.users = {}
        self.totp_secrets = {}
        self.session_keys = {}

    def receive_authentication_info(self, username, token):
        # Armazena o token de autenticação do usuário
        self.users[username] = token

    def compare_authentication_token(self, username, token):
        # Compara o token de autenticação recebido com o armazenado
        return self.users.get(username) == token

    def generate_totp_secret(self, username):
        # Gera e armazena o segredo TOTP para o usuário
        self.totp_secrets[username] = pyotp.random_base32()

    def receive_totp_code(self, username, totp_code):
        # Valida o código TOTP recebido
        totp = pyotp.TOTP(self.totp_secrets[username])
        return totp.verify(totp_code)

    def receive_session_key(self, username, session_key):
        # Armazena a chave de sessão do usuário
        self.session_keys[username] = session_key

    def receive_encrypted_message(self, username, encrypted_message):
        # Recebe e decifra mensagem cifrada do cliente
        if username in self.session_keys:
            session_key = self.session_keys[username]
            iv = encrypted_message[:12]
            tag = encrypted_message[12:28]
            ciphertext = encrypted_message[28:]
            cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted_message
        else:
            return b"Error: No session key established for the client."

    def encrypt_message(self, message, username):
        # Cifra mensagem usando a chave de sessão do usuário
        if username in self.session_keys:
            session_key = self.session_keys[username]
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(message) + encryptor.finalize()
            return iv + encryptor.tag + encrypted_message
        else:
            return b"Error: No session key established for the client."
