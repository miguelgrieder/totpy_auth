from totpy_auth.client import Client
from totpy_auth.server import Server


def main():
    # Passo 1: Inicialização do cliente e servidor, usuário entra com login e senha
    client = Client()
    server = Server()

    # Passo 3: Cliente - envia nome do usuário, token e horário para servidor
    # Passo 4: Servidor - Token de autenticação é derivado de novo com Scrypt, compara com valor guardado no arquivo e valida

    token_valid = client.send_authentication_info(server)

    if token_valid:
        # Passo 5: Servidor – gera código TOTP e envia o QR Code para o cliente (2º fator de autenticação, simulando a necessidade de um celular)
        # Passo 8: Servidor - O cliente lê o QR Code e digita o código obtido na tela para enviar para o servidor
        client.auth_totp_secret(server)

        # Passo 9: Cliente - O cliente lê o QR Code e digita o código obtido na tela para enviar para o servidor
        totp_code_valid = client.send_totp_code(server)

        if totp_code_valid:
            # Passo 11: Cliente e Servidor - usam o código para derivar uma chave simétrica de sessão com o PBKDF2 para cifrar a comunicação simétrica entre ambos. Deve ser usada CRIPTOGRAFIA AUTENTICADA para cifragem e decifragem (modo GCM ou outro)
            client.establish_session_key(server)

            # Loop de troca de mensagens cifradas
            while True:
                message_to_server = input("Enter message to send to server: ").encode()
                encrypted_message = client.encrypt_message(message_to_server)
                print("Encrypted message sent to server:", encrypted_message)

                decrypted_message = server.receive_encrypted_message(
                    client.username, encrypted_message
                )
                print("Decrypted message received from server:", decrypted_message.decode())

                message_to_client = input("Enter message to send to client: ").encode()
                encrypted_message = server.encrypt_message(message_to_client, client.username)
                print("Encrypted message sent to client:", encrypted_message)

                decrypted_message = client.decrypt_message(encrypted_message)
                print("Decrypted message received from client:", decrypted_message.decode())
        else:
            print("Invalid TOTP code")
    else:
        print("Invalid authentication token")


if __name__ == "__main__":
    main()
