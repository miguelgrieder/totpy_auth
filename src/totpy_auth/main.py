from totpy_auth.client import Client
from totpy_auth.server import Server


def main():
    server = Server()
    client = Client(server)
    token_valid = client.send_authentication_info()

    if token_valid:
        client.auth_totp_secret()
        totp_code_valid = client.send_totp_code()

        if totp_code_valid:
            client.establish_session_key()

            # Loop de troca de mensagens cifradas
            while True:
                message_to_server = input("Enter message to send to server: ").encode()
                encrypted_message = client.send_message_with_encryption(message_to_server)

                message_to_client = input("Enter message to send to client: ").encode()
                encrypted_message = server.send_message_with_encryption(message_to_client, client)

        else:
            print("Invalid TOTP code")
    else:
        print("Invalid authentication token")


if __name__ == "__main__":
    main()
