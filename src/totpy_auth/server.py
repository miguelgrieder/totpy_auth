import os

import pyotp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class Server:
    def __init__(self):
        self.users = {}
        self.totp_secrets = {}
        self.session_keys = {}
        self.__salt = os.urandom(16)

    def register_client_authentication(self, username, password_hash):
        # Deriva uma chave a partir do password_hash usando Scrypt
        key = self.derive_scrypt_key(password_hash)
        # Armazena a chave derivada do password_hash
        if username not in self.users:
            self.users[username] = key
            print(f"Server: {username} registered successfully!")
            return True
        else:
            print(f"Server: User {username} already registered!")
            return False

    def derive_scrypt_key(self, password_hash, salt=None, length=32, n=2**14, r=8, p=1):
        """
        Deriva uma chave usando o algoritmo Scrypt.

        Parâmetros:
        - password_hash: O hash da senha do usuário.
        - salt: Um valor aleatório usado para salgar o hash (padrão: novo salt gerado para o servidor).
        - length: O comprimento da chave derivada em bytes (padrão: 32 bytes).
        - n: O parâmetro N que afeta o uso de memória (padrão: 2^14).
        - r: O parâmetro r que afeta a computação da chave (padrão: 8).
        - p: O parâmetro p que afeta a computação da chave (padrão: 1).

        Retorna:
        - A chave derivada.
        """
        if salt is None:
            salt = self.__salt

        # Deriva a chave usando Scrypt
        kdf = Scrypt(
            salt=salt,
            length=length,  # Tamanho da chave de 32 bytes
            n=n,
            r=r,
            p=p,
            backend=default_backend(),
        )
        key = kdf.derive(password_hash)
        return key

    def compare_password_hash(self, username, token):
        # Compara o token de autenticação recebido com o armazenado
        return self.users.get(username) == token

    def generate_client_totp_secret_and_send(self, username):
        # Gera e armazena o segredo TOTP para o usuário
        if self.totp_secrets.__contains__(username):
            raise Exception("Server: User already have a totp_secret!")
        else:
            self.totp_secrets[username] = pyotp.random_base32()
            print(
                f"Server: debug - Generated totp_secret for {username} and sending {self.totp_secrets[username]}"
            )
        return self.totp_secrets[username]

    def receive_totp_code(self, username, totp_code):
        # Valida o código TOTP recebido
        totp = pyotp.TOTP(self.totp_secrets[username])
        totp_verification = totp.verify(totp_code)
        print(
            f"Server: debug - {username} totp_code {totp_code} verification: {totp_verification}",
            end="\n\n",
        )
        return totp_verification

    def receive_session_key(self, username, session_key):
        # Armazena a chave de sessão do usuário
        self.session_keys[username] = session_key
        print(f"Server: debug - {username} saved session key {self.session_keys[username]}")

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
                f"Server: Message received from {username} decrypted: {decrypted_message.decode()}",
                end="\n\n",
            )
            return True
        else:
            print(f"Server: {username} dont`t have any active session")
            return False

    def send_encrypted_message_to_client(self, client):
        # Cifra mensagem usando a chave de sessão do usuário
        if client.username in self.session_keys:
            message_to_client = input(
                f"Server: Enter message to send to {client.username}: "
            ).encode()
            session_key = self.session_keys[client.username]
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(message_to_client) + encryptor.finalize()
            full_encrypted_message = iv + encryptor.tag + encrypted_message
            print(
                f"Server - debug: Generated full encrypted message with [iv, tag, cipher(session_key, iv, message)]"
            )

            print(f"Server: Encrypted message sent to {client.username}:", encrypted_message)
            success_decrypt_by_client = client.receive_and_decrypt_message(full_encrypted_message)
            return success_decrypt_by_client
        else:
            return False
