import os

import pyotp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Server:
    def __init__(self):
        self.users = {}
        self.totp_secrets = {}
        self.session_keys = {}

    def register_client_authentication(self, username, token):
        # Armazena o token de autenticação do usuário
        if self.users.__contains__(username):
            print("Server: User already registered!")
            token_valid = False
        else:
            self.users[username] = token
            token_valid = self.compare_authentication_token(username, token)
        return token_valid

    def compare_authentication_token(self, username, token):
        # Compara o token de autenticação recebido com o armazenado
        return self.users.get(username) == token

    def register_client_totp_secret(self, username):
        # Gera e armazena o segredo TOTP para o usuário
        if self.totp_secrets.__contains__(username):
            raise Exception("Server: User already have a totp_secret!")
        else:
            self.totp_secrets[username] = pyotp.random_base32()
        return self.totp_secrets[username]

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
            print(
                f"Server: Message received from client decrypted: {decrypted_message.decode()}",
                end="\n\n",
            )
            return True
        else:
            return False

    def send_encrypted_message_to_client(self, client):
        # Cifra mensagem usando a chave de sessão do usuário
        if client.username in self.session_keys:
            message_to_client = input("Server: Enter message to send to client: ").encode()
            session_key = self.session_keys[client.username]
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(message_to_client) + encryptor.finalize()
            full_encrypted_message = iv + encryptor.tag + encrypted_message
            print("Server: Encrypted message sent to client:", encrypted_message)
            success_decrypt_by_client = client.receive_and_decrypt_message(full_encrypted_message)
            return success_decrypt_by_client
        else:
            return False
