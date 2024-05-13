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
        self.__password = getpass.getpass(f"{self.username}: Enter client password: ")
        self.__server = server
        self.__password_hash = None
        self.__totp_secret = None
        self.__session_key = None
        self.__salt = os.urandom(16)  # Gera um salt aleatório
        print(f"{self.username} - debug: salt generated: {self.__salt}", end="\n\n")

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

    def derive_password_hash(self):
        # Deriva token de autenticação usando PBKDF2
        self.__password_hash = self.derive_pbkdf2_key(self.__password)
        print(f"{self.username} - debug: password_hash generated {self.__password_hash}")

    def register_in_server(self):
        # Envia nome do usuário e password_hash para o servidor
        self.derive_password_hash()
        totp_secret = self.__server.register_client_authentication(
            self.username, self.__password_hash
        )
        # Salva o segredo TOTP do servidor
        if totp_secret:
            self.__totp_secret = totp_secret
            print(f"{self.username} - debug: totp_secret saved {totp_secret}", end="\n\n")
            return True
        else:
            return False

    def generate_totp_code(self):
        # Gera código TOTP usando o segredo TOTP
        totp = pyotp.TOTP(self.__totp_secret)
        return totp.now()

    def send_2fa(self):
        password_hash_login_valid = self.__server.password_hash_login(
            self.username, self.__password_hash
        )
        if password_hash_login_valid:
            totp_code_valid = self.send_totp_code()
            if totp_code_valid:
                self.establish_session_key()
                print(f"{self.username}: Password hash login and totp validation succeeded")
                return True
            else:
                print(f"{self.username}: totp code INVALID!")
        else:
            print(f"{self.username}: Password login INVALID!")
        return False

    def send_totp_code(self):
        # Envia o código TOTP para o servidor
        totp_code = self.generate_totp_code()
        print(f"{self.username} - debug: Generated totp_code {totp_code} and sending to server")
        totp_code_valid = self.__server.receive_totp_code(self.username, totp_code)
        return totp_code_valid

    def establish_session_key(self):
        # Deriva uma chave simétrica de sessão usando PBKDF2
        combined_code = self.__password_hash + self.__totp_secret.encode("utf-8")
        self.__session_key = self.derive_pbkdf2_key(combined_code)
        print(
            f"{self.username} - debug: created session_key with password_hash and "
            f"totp_secret - {self.__session_key}"
        )
        self.__server.receive_session_key(self.username, self.__session_key)

    def send_encrypted_message_to_server(self):
        # Cifra a mensagem usando a chave simétrica de sessão e o modo GCM
        message_to_server = input(f"{self.username}: Enter message to send to server: ").encode()
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.__session_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message_to_server) + encryptor.finalize()
        full_encrypted_message = iv + encryptor.tag + encrypted_message
        print(
            f"{self.username} - debug: Generated full encrypted message with "
            f"[iv, tag, cipher(session_key, iv, message)]"
        )
        print(f"{self.username}: Encrypted message sent to server:", full_encrypted_message)
        success_decrypt_by_server = self.__server.receive_encrypted_message(
            self.username, full_encrypted_message
        )
        return success_decrypt_by_server

    def receive_and_decrypt_message(self, encrypted_message):
        # Decifra a mensagem usando a chave simétrica de sessão e o modo GCM
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]
        cipher = Cipher(algorithms.AES(self.__session_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        print(
            f"{self.username}: Message received from server "
            f"decrypted: {decrypted_message.decode()}",
            end="\n\n",
        )
        return decrypted_message
