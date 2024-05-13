import os

import pyotp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class Server:
    def __init__(self):
        self.__users_password_hash_with_scrypt = {}
        self.__users_totp_secrets = {}
        self.__session_keys = {}
        self.__salts = {}  # Dicionário para armazenar os salts únicos de cada cliente

    def register_client_authentication(self, username, password_hash):
        salt = os.urandom(16)
        # Deriva uma chave a partir do password_hash usando Scrypt
        scrypt_key = self.derive_scrypt_key(password_hash, salt)
        # Armazena a chave derivada do scrypt_key
        if username not in self.__users_password_hash_with_scrypt:
            self.__users_password_hash_with_scrypt[username] = scrypt_key
            self.__salts[username] = salt
            print(f"Server: {username} registered successfully!")
            return True
        else:
            print(f"Server: User {username} already registered!")
            return False

    def derive_scrypt_key(self, password_hash, salt, length=32, n=2**14, r=8, p=1):
        """Deriva uma chave usando o algoritmo Scrypt.

        Parâmetros:
        - password_hash: O hash da senha do usuário.
        - salt: Usado para randomizar o hash (padrão: novo salt gerado para o servidor).
        - length: O comprimento da chave derivada em bytes (padrão: 32 bytes).
        - n: O parâmetro N que afeta o uso de memória (padrão: 2^14).
        - r: O parâmetro r que afeta a computação da chave (padrão: 8).
        - p: O parâmetro p que afeta a computação da chave (padrão: 1).

        Retorna:
        - A chave derivada.
        """
        # Deriva a chave usando Scrypt
        kdf = Scrypt(
            salt=salt,
            length=length,
            n=n,
            r=r,
            p=p,
            backend=default_backend(),
        )
        key = kdf.derive(password_hash)
        return key

    def compare_password_hash(self, username, scrypt_key):
        # Compara o scrypt_key com o armazenado
        return self.__users_password_hash_with_scrypt.get(username) == scrypt_key

    def generate_client_totp_secret_and_send(self, username):
        # Gera e armazena o segredo TOTP para o usuário
        if self.__users_totp_secrets.__contains__(username):
            raise Exception("Server: User already have a totp_secret!")
        else:
            self.__users_totp_secrets[username] = pyotp.random_base32()
            print(
                f"Server: debug - Generated totp_secret for {username} and "
                f"sending {self.__users_totp_secrets[username]}"
            )
        return self.__users_totp_secrets[username]

    def receive_totp_code(self, username, totp_code):
        # Valida o código TOTP recebido
        totp = pyotp.TOTP(self.__users_totp_secrets[username])
        totp_verification = totp.verify(totp_code)
        print(
            f"Server: debug - {username} totp_code {totp_code} verification: {totp_verification}",
            end="\n\n",
        )
        return totp_verification

    def receive_session_key(self, username, session_key):
        # Armazena a chave de sessão do usuário
        self.__session_keys[username] = session_key
        print(f"Server: debug - {username} saved session key {self.__session_keys[username]}")

    def receive_encrypted_message(self, username, encrypted_message):
        # Recebe e decifra mensagem cifrada do cliente
        if username in self.__session_keys:
            session_key = self.__session_keys[username]
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
        if client.username in self.__session_keys:
            message_to_client = input(
                f"Server: Enter message to send to {client.username}: "
            ).encode()
            session_key = self.__session_keys[client.username]
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(message_to_client) + encryptor.finalize()
            full_encrypted_message = iv + encryptor.tag + encrypted_message
            print(
                f"Server - debug: Generated full encrypted message with "
                f"[iv, tag, cipher(session_key, iv, message)]"
            )

            print(f"Server: Encrypted message sent to {client.username}:", encrypted_message)
            success_decrypt_by_client = client.receive_and_decrypt_message(full_encrypted_message)
            return success_decrypt_by_client
        else:
            return False
